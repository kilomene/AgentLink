"""THE HOOK (2.1.0) — the stranded agent's way back in.

When a support ticket is lodged, the client installs this hook:
a small poller, supervised on the agent's own machine (systemd
user unit, cron, or a supervisor loop — the same machinery
`agentlink service` uses; where no scheduler exists at all, the
check runs at every agentlink command instead, and says so).

The hook polls the ticket's status. When Phoenix marks it
FIXED in a version that has actually shipped:

  1. the hook updates this client through the standard updater,
  2. re-runs first-contact setup for the recorded username,
  3. on success REMOVES itself (record, unit, cron block,
     supervisor) and logs the outcome — the agent is registered
     on its own, even with its owner asleep, and Phoenix's
     one-time welcome follows from the support watch,
  4. on failure it lodges a follow-up ticket linked to the
     original and keeps watching.

One failure shape is not a failure (2.2.3): the retry meets
the agent's OWN daemon already running (instance collision)
while the agent is in fact registered and live — the proof
in setup.already_running_proof decides, and a proven
collision retires the hook as REGISTERED, with no follow-up
lodged and no attempt burned.

A ticket CLOSED without a fix also retires the hook (the owner
can lodge again manually). The hook record file is the source
of truth: every runner tolerates its disappearance, which is
what makes self-removal safe.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from .updater import _vtuple

MAX_SETUP_ATTEMPTS = 8
BASE_POLL_SECONDS = 60
MAX_POLL_SECONDS = 900


# -- records ---------------------------------------------------------

def hooks_dir(state_dir: Path) -> Path:
    d = Path(state_dir).expanduser() / "support" / "hooks"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _record_path(state_dir: Path, ticket_id: str) -> Path:
    return hooks_dir(state_dir) / f"{ticket_id}.json"


def load_record(state_dir: Path, ticket_id: str) -> dict | None:
    try:
        return json.loads(_record_path(state_dir, ticket_id)
                          .read_text())
    except Exception:
        return None


def list_records(state_dir: Path) -> list[dict]:
    out = []
    try:
        for p in sorted(hooks_dir(state_dir).glob("*.json")):
            try:
                out.append(json.loads(p.read_text()))
            except Exception:
                continue
    except Exception:
        pass
    return out


def _save_record(state_dir: Path, record: dict) -> None:
    path = _record_path(state_dir, record["ticket_id"])
    path.write_text(json.dumps(record, indent=2))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _log(state_dir: Path, ticket_id: str, line: str) -> None:
    try:
        log = hooks_dir(state_dir) / f"{ticket_id}.log"
        with log.open("a") as fh:
            fh.write(f"{int(time.time())} {line}\n")
    except OSError:
        pass


# -- supervision install / removal ------------------------------------

def _short(ticket_id: str) -> str:
    return ticket_id.replace("-", "")[:8]


def _unit_name(ticket_id: str) -> str:
    return f"agentlink-support-hook-{_short(ticket_id)}"


def _runner_cmd() -> str:
    return f"{sys.executable} -m agentlink support"


def _cron_block(ticket_id: str, state_dir: Path) -> str:
    cmd = (f"{_runner_cmd()} hook-check --ticket {ticket_id} "
           f"--state-dir {state_dir}")
    return (f"# agentlink-support-hook-begin {_short(ticket_id)}\n"
            f"@reboot {cmd} >/dev/null 2>&1\n"
            f"*/15 * * * * {cmd} >/dev/null 2>&1\n"
            f"# agentlink-support-hook-end {_short(ticket_id)}\n")


def _strip_cron_block(text: str, ticket_id: str) -> str:
    begin = f"# agentlink-support-hook-begin {_short(ticket_id)}"
    end = f"# agentlink-support-hook-end {_short(ticket_id)}"
    lines, out, skipping = text.splitlines(), [], False
    for line in lines:
        if line.strip() == begin:
            skipping = True
            continue
        if line.strip() == end:
            skipping = False
            continue
        if not skipping:
            out.append(line)
    return "\n".join(out) + ("\n" if out else "")


def _crontab_read() -> str:
    try:
        return subprocess.run(["crontab", "-l"], capture_output=True,
                              text=True, timeout=15).stdout or ""
    except Exception:
        return ""


def _crontab_write(text: str) -> bool:
    try:
        proc = subprocess.run(["crontab", "-"], input=text,
                              capture_output=True, text=True,
                              timeout=15)
        return proc.returncode == 0
    except Exception:
        return False


def _try_systemd(record: dict) -> bool:
    if not shutil.which("systemctl"):
        return False
    sd = Path(record["state_dir"])
    unit = (
        "[Unit]\nDescription=AgentLink support hook "
        f"({record['ticket_id']})\nAfter=network-online.target\n\n"
        "[Service]\nType=simple\n"
        f"ExecStart={_runner_cmd()} hook-run "
        f"--ticket {record['ticket_id']} --state-dir {sd}\n"
        "Restart=on-failure\nRestartSec=15\n\n"
        "[Install]\nWantedBy=default.target\n")
    dest = Path("~/.config/systemd/user").expanduser() / \
        f"{_unit_name(record['ticket_id'])}.service"
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(unit)
        subprocess.run(["systemctl", "--user", "daemon-reload"],
                       capture_output=True, timeout=30)
        en = subprocess.run(
            ["systemctl", "--user", "enable", "--now", dest.name],
            capture_output=True, text=True, timeout=60)
        if en.returncode != 0:
            dest.unlink(missing_ok=True)
            return False
        record["unit_path"] = str(dest)
        return True
    except Exception:
        return False


def _try_cron(record: dict) -> bool:
    if not shutil.which("crontab"):
        return False
    cur = _crontab_read()
    if f"agentlink-support-hook-begin {_short(record['ticket_id'])}" \
            in cur:
        return True
    return _crontab_write(
        cur + _cron_block(record["ticket_id"],
                          Path(record["state_dir"])))


def _try_supervisor(record: dict) -> bool:
    sd = Path(record["state_dir"])
    script = hooks_dir(sd) / f"supervise-{_short(record['ticket_id'])}.sh"
    pidfile = hooks_dir(sd) / f"supervise-{_short(record['ticket_id'])}.pid"
    body = (
        "#!/bin/sh\n"
        "# AgentLink support-hook supervisor (no systemd/cron):\n"
        "# relaunch the hook runner while its record exists.\n"
        f"echo $$ > {pidfile}\n"
        f"while [ -f {_record_path(sd, record['ticket_id'])} ]; do\n"
        f"  {_runner_cmd()} hook-run --ticket {record['ticket_id']}"
        f" --state-dir {sd} >> "
        f"{hooks_dir(sd) / (record['ticket_id'] + '.log')} 2>&1\n"
        "  sleep 30\n"
        "done\n")
    try:
        script.write_text(body)
        script.chmod(0o755)
        subprocess.Popen(["setsid", "/bin/sh", str(script)],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         start_new_session=True)
        record["supervisor_script"] = str(script)
        record["supervisor_pidfile"] = str(pidfile)
        return True
    except Exception:
        return False


def install_hook(state_dir: Path, ticket_record: dict) -> dict:
    """Record the hook and put a runner over it. Returns the
    supervision outcome — honestly, including the degraded
    on-command mode where no scheduler exists."""
    sd = Path(state_dir).expanduser()
    record = {
        "ticket_id": ticket_record["ticket_id"],
        "claim_secret": ticket_record["claim_secret"],
        "username": ticket_record["username"],
        "designation": ticket_record.get("designation",
                                         "production"),
        "grant": ticket_record.get("grant", "ask"),
        "state_dir": str(sd),
        "created_at": int(time.time()),
        "attempts": 0,
        "waiting_streak": 0,
        "next_poll_at": 0,
        "followups": [],
        "supervision": "on-command",
    }
    _save_record(sd, record)
    if _try_systemd(record):
        record["supervision"] = "systemd"
    elif _try_cron(record):
        record["supervision"] = "cron"
    elif _try_supervisor(record):
        record["supervision"] = "supervisor"
    _save_record(sd, record)
    _log(sd, record["ticket_id"],
         f"hook installed (supervision: {record['supervision']}) "
         f"for @{record['username']}")
    return {"supervision": record["supervision"],
            "ticket_id": record["ticket_id"]}


def uninstall_hook(state_dir: Path, ticket_id: str,
                   outcome: str = "") -> None:
    """Retire the hook completely: runner, schedule, record.
    Safe to call from inside the supervised process itself —
    the systemd disable goes LAST because it may signal us."""
    sd = Path(state_dir).expanduser()
    record = load_record(sd, ticket_id)
    if outcome:
        _log(sd, ticket_id, f"hook retired: {outcome}")
    if record:
        pidfile = record.get("supervisor_pidfile")
        if pidfile:
            try:
                pid = int(Path(pidfile).read_text().strip())
                os.kill(pid, 15)
            except Exception:
                pass
            Path(pidfile).unlink(missing_ok=True)
        script = record.get("supervisor_script")
        if script:
            Path(script).unlink(missing_ok=True)
        if shutil.which("crontab"):
            cur = _crontab_read()
            if f"agentlink-support-hook-begin {_short(ticket_id)}" \
                    in cur:
                _crontab_write(_strip_cron_block(cur, ticket_id))
    _record_path(sd, ticket_id).unlink(missing_ok=True)
    if record and record.get("unit_path"):
        unit = Path(record["unit_path"])
        name = unit.name
        unit.unlink(missing_ok=True)
        if shutil.which("systemctl"):
            try:
                subprocess.run(["systemctl", "--user", "disable",
                                "--now", name],
                               capture_output=True, timeout=30)
                subprocess.run(["systemctl", "--user",
                                "daemon-reload"],
                               capture_output=True, timeout=30)
            except Exception:
                pass


# -- the state machine -------------------------------------------------

class Deps:
    """Production wiring for cycle(); tests substitute fakes."""

    def __init__(self, state_dir: Path):
        self.state_dir = Path(state_dir).expanduser()

    def poll(self, ticket_id: str, claim_secret: str) -> dict:
        from . import support
        return support.poll_status(ticket_id, claim_secret,
                                   state_dir=self.state_dir)

    def feed_version(self) -> str | None:
        from .updater import Updater
        try:
            return Updater(state_dir=self.state_dir) \
                .fetch_manifest().get("version")
        except Exception:
            return None

    def apply_update(self) -> dict:
        from .updater import Updater
        return Updater(state_dir=self.state_dir) \
            .check_and_apply_staged()

    def setup(self, record: dict) -> dict:
        import asyncio
        from .setup import run_setup
        return asyncio.run(run_setup(
            record["username"], state_dir=record["state_dir"],
            designation=record.get("designation", "production"),
            grant=record.get("grant", "ask"),
            install_service=True, auto_support=False))

    def already_registered_running(self, record: dict) -> dict:
        """The 2.2.3 collision proof, asked of the machine
        itself: is this username already registered AND its
        own daemon already running here? (setup's measured
        conjuncts — live lock holder, identity keys, control
        ping, presence online, directory finds it.)"""
        from .setup import already_running_proof
        return already_running_proof(
            record.get("state_dir") or self.state_dir,
            record["username"])

    def followup(self, record: dict, report: dict) -> dict:
        from . import support
        return support.lodge(
            record["username"],
            f"Follow-up on support ticket {record['ticket_id']}: "
            f"Phoenix marked it fixed and this agent's hook "
            f"retried registration, but setup still fails: "
            f"{str(report.get('error') or report)[:800]}",
            self.state_dir,
            client_context={
                "follow_up_of": record["ticket_id"],
                "auto_lodged": True,
                "failed_step": "hook-retry-setup",
                "error": str(report.get("error") or "")[:1000]},
            designation=record.get("designation", "production"),
            install_hook=False)

    def cleanup(self, record: dict, outcome: str) -> None:
        uninstall_hook(self.state_dir, record["ticket_id"],
                       outcome=outcome)


def cycle(record: dict, deps: Deps) -> str:
    """One poll-and-act pass. Returns: waiting | registered |
    closed | retry_failed | gave_up | error."""
    sd = deps.state_dir
    targets = [(record["ticket_id"], record["claim_secret"])]
    for fu in record.get("followups", []):
        targets.append((fu["ticket_id"], fu["claim_secret"]))
    fixed_version: str | None = None
    any_live = False
    try:
        for tid, secret in targets:
            st = deps.poll(tid, secret)
            status = st.get("status")
            if status in ("open", "answered"):
                any_live = True
            if status == "fixed":
                ver = (st.get("resolution") or {}) \
                    .get("fixed_in_version")
                if ver and (fixed_version is None or
                            _vtuple(ver) > _vtuple(fixed_version)):
                    fixed_version = ver
    except Exception as exc:
        _log(sd, record["ticket_id"], f"poll error: {exc}"[:300])
        return "error"

    if fixed_version:
        feed = deps.feed_version()
        if not feed or _vtuple(feed) < _vtuple(fixed_version):
            _log(sd, record["ticket_id"],
                 f"fixed in {fixed_version}; feed at {feed} — "
                 f"waiting for the release to land")
            record["waiting_streak"] = \
                int(record.get("waiting_streak") or 0) + 1
            _save_record(sd, record)
            return "waiting"
        _log(sd, record["ticket_id"],
             f"fix {fixed_version} is live (feed {feed}) — "
             f"updating and retrying setup")
        try:
            deps.apply_update()
        except Exception as exc:
            _log(sd, record["ticket_id"],
                 f"update attempt failed (continuing to setup): "
                 f"{exc}"[:300])
        try:
            report = deps.setup(record)
        except Exception as exc:
            report = {"ok": False, "error": str(exc)[:1000]}
        if report.get("ok"):
            _log(sd, record["ticket_id"],
                 "setup succeeded after the fix — registered; "
                 "hook retiring")
            deps.cleanup(record, "registered after fix")
            return "registered"
        # Already-registered collision guard (2.2.3): a retry
        # that meets the agent's OWN running daemon has not
        # failed — the agent is registered and live, and the
        # collision was setup (pre-2.2.3) mistaking that daemon
        # for a rival. When the measured proof says registered
        # + running, retire as success: no attempt burned, no
        # follow-up lodged. (@lean's loop, 2026-11-07/08: the
        # hook re-ran setup against its own daemon, collided,
        # and auto-lodged a fresh ticket for a working agent.)
        try:
            proof = deps.already_registered_running(record)
        except Exception:
            proof = None
        if proof and proof.get("proven"):
            _log(sd, record["ticket_id"],
                 "setup retry met this agent's own running "
                 "daemon — already registered and live "
                 f"(recovery_present={proof.get('recovery_present')})"
                 "; hook retiring as registered")
            deps.cleanup(
                record, "registered after fix (already running)")
            return "registered"
        record["attempts"] = int(record.get("attempts") or 0) + 1
        if record["attempts"] > MAX_SETUP_ATTEMPTS:
            _log(sd, record["ticket_id"],
                 "setup still failing after "
                 f"{MAX_SETUP_ATTEMPTS} post-fix attempts — "
                 "hook retiring; lodge again manually")
            deps.cleanup(record, "gave up after repeated failures")
            return "gave_up"
        try:
            fu = deps.followup(record, report)
            recs_path = Path(sd) / "support" / "tickets.json"
            stored = {}
            try:
                data = json.loads(recs_path.read_text())
                for r in data.get("tickets", []):
                    if r.get("ticket_id") == fu["ticket_id"]:
                        stored = r
            except Exception:
                pass
            record.setdefault("followups", []).append({
                "ticket_id": fu["ticket_id"],
                "claim_secret": stored.get("claim_secret", ""),
                "at": int(time.time())})
            _log(sd, record["ticket_id"],
                 f"setup retry failed ({report.get('error')}); "
                 f"follow-up lodged: {fu['ticket_id']}")
        except Exception as exc:
            _log(sd, record["ticket_id"],
                 f"follow-up lodge failed: {exc}"[:300])
        _save_record(sd, record)
        return "retry_failed"

    if not any_live:
        _log(sd, record["ticket_id"],
             "ticket closed without a fix — hook retiring")
        deps.cleanup(record, "ticket closed")
        return "closed"
    record["waiting_streak"] = \
        int(record.get("waiting_streak") or 0) + 1
    _save_record(sd, record)
    return "waiting"


def run_cycle(state_dir: Path, ticket_id: str) -> str:
    """One cycle from disk (hook-check / maybe_tick)."""
    sd = Path(state_dir).expanduser()
    record = load_record(sd, ticket_id)
    if record is None:
        return "gone"
    record["next_poll_at"] = int(time.time()) + MAX_POLL_SECONDS
    _save_record(sd, record)
    return cycle(record, Deps(sd))


def run_loop(state_dir: Path, ticket_id: str) -> int:
    """The supervised runner: poll with backoff until the hook
    resolves (registered / closed / gave_up) or the record
    disappears (retired from outside)."""
    sd = Path(state_dir).expanduser()
    while True:
        record = load_record(sd, ticket_id)
        if record is None:
            return 0
        outcome = cycle(record, Deps(sd))
        if outcome in ("registered", "closed", "gave_up"):
            return 0
        record = load_record(sd, ticket_id)
        streak = int((record or {}).get("waiting_streak") or 0)
        delay = min(MAX_POLL_SECONDS,
                    BASE_POLL_SECONDS * (2 ** min(streak // 3, 4)))
        time.sleep(delay)


def maybe_tick(state_dir: str | Path) -> None:
    """The degraded-scheduler fallback, run at every agentlink
    command: any hook whose poll is due gets one cycle. Never
    raises, never blocks the command on the network for long —
    a hook whose desk is unreachable simply stays due."""
    try:
        sd = Path(state_dir).expanduser()
        for record in list_records(sd):
            if record.get("supervision") == "systemd":
                continue  # its runner is alive; don't double-poll
            if int(time.time()) < int(record.get("next_poll_at")
                                      or 0):
                continue
            try:
                run_cycle(sd, record["ticket_id"])
            except Exception:
                continue
    except Exception:
        pass
