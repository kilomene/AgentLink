"""v1.1.8 — in-daemon self-update, hostile-environment proofs.

The defect (owner-reported 2026-11-02): the 15-minute update check
was scheduled through the host's crontab; on a sandbox with NO
crontab binary it was never installed and the agent sat stranded on
its install version. The fix moves the check inside the agent.

(a) a daemon running with `crontab` REMOVED from PATH (an entirely
    empty PATH) self-updates from a local feed, re-execs (same PID),
    reconnects, and reports the new version; identity files are
    byte-identical before/after;
(b) a feed with a corrupted file hash -> no apply, old code
    untouched, error surfaced, no rollback backup created;
(c) a staged tree that fails the import smoke -> swap aborted, old
    code untouched, staging cleaned;
(d) a feed at the running version -> no-op, no churn (and the
    variant: newer version string, identical files -> no-op);
(e) UPDATE CONTINUITY: an agent with checkpointed work in progress,
    a queued unsent message, and a partially-uploaded chunked file
    self-updates -> after re-exec the work completes with a verified
    proof exactly once, the queued message arrives exactly once,
    and the upload finishes byte-exact;
(f) an update arriving mid-brain-call: the reply is still delivered
    (not lost, not duplicated) and the update applies right after;
(g) config pins (interval default = timing law, env overrides,
    disable switch) + the installer on a crontab-less host prints
    the in-daemon notice instead of silently skipping.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentlink import __version__ as RUNNING_VERSION  # noqa: E402
from agentlink.client import Agent  # noqa: E402
from agentlink.config import (resolve_update_check_seconds,  # noqa: E402
                              self_update_enabled)
from agentlink.relay import Relay  # noqa: E402
from agentlink.timing import (UPDATE_CHECK_SECONDS,  # noqa: E402
                              UPDATE_DRAIN_WAIT_SECONDS)
from agentlink.updater import (Updater, UpdateError,  # noqa: E402
                               self_clean_install)

_v = RUNNING_VERSION.split(".")
NEXT_VERSION = f"{_v[0]}.{_v[1]}.{int(_v[2]) + 1}"


# ------------------------------------------------------------------
# harness
# ------------------------------------------------------------------

def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _start_relay(tmp_path: Path):
    relay = Relay(host="127.0.0.1", port=0,
                  db_path=str(tmp_path / "relay.db"),
                  dashboard_port=0,
                  dashboard_password="self-update-tests")
    ready = threading.Event()

    def _thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _serve():
            await relay.start()
            ready.set()
            await asyncio.Future()

        try:
            loop.run_until_complete(_serve())
        except (RuntimeError, asyncio.CancelledError):
            pass

    threading.Thread(target=_thread, daemon=True).start()
    assert ready.wait(30), "relay did not start"
    return relay, f"ws://127.0.0.1:{relay.port}/ws"


async def _register(endpoint: str, state_dir: Path, username: str):
    agent = Agent(username, endpoint=endpoint, state_dir=state_dir)
    await agent.start()
    await agent.close()


def _identity_hashes(state_dir: Path, username: str) -> dict:
    out = {}
    for kind in ("secret", "keys", "groupkeys", "channelkeys",
                 "filekeys"):
        p = Path(state_dir) / f"{kind}-{username}.json"
        out[kind] = _sha(p.read_bytes()) if p.exists() else None
    return out


def _make_install(tmp_path: Path) -> Path:
    install = tmp_path / "install"
    shutil.copytree(ROOT / "agentlink", install / "agentlink",
                    ignore=shutil.ignore_patterns("__pycache__"))
    return install


def _make_feed(tmp_path: Path, version: str, *, corrupt: str = "",
               broken: str = "", bump_init: bool = True) -> Path:
    """A fake release feed: a copy of the real package (optionally
    version-bumped / corrupted / syntactically broken) + a manifest
    over it, served to the daemon via file://."""
    feed = tmp_path / "feed"
    pkg = feed / "agentlink"
    shutil.copytree(ROOT / "agentlink", pkg,
                    ignore=shutil.ignore_patterns("__pycache__"))
    if bump_init:
        init = pkg / "__init__.py"
        init.write_text(re.sub(
            r'__version__ = "[^"]+"', f'__version__ = "{version}"',
            init.read_text()))
    if broken:
        (pkg / broken).write_text("this is not python (\n")
    files = {}
    for f in sorted(pkg.glob("*.py")):
        rel = f"agentlink/{f.name}"
        files[rel] = "0" * 64 if corrupt == rel else _sha(f.read_bytes())
    (feed / "update-manifest.json").write_text(
        json.dumps({"version": version, "files": files}))
    return feed


def _tree_hashes(pkg: Path) -> dict:
    return {f.name: _sha(f.read_bytes())
            for f in sorted(pkg.glob("*.py"))}


class _Lines:
    """Thread-pumped stdout collector for a daemon subprocess."""

    def __init__(self, proc: subprocess.Popen):
        self._lines: list[str] = []
        self._lock = threading.Lock()
        threading.Thread(target=self._pump, args=(proc,),
                         daemon=True).start()

    def _pump(self, proc):
        for line in proc.stdout:
            with self._lock:
                self._lines.append(line.rstrip("\n"))

    def snapshot(self) -> list[str]:
        with self._lock:
            return list(self._lines)

    def count(self, needle: str) -> int:
        return sum(1 for l in self.snapshot() if needle in l)

    def wait_for(self, needle: str, timeout: float = 120) -> str:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for line in self.snapshot():
                if needle in line:
                    return line
            time.sleep(0.1)
        raise AssertionError(
            f"timed out waiting for {needle!r}; last lines:"
            f" {self.snapshot()[-25:]}")

    def wait_count(self, needle: str, n: int,
                   timeout: float = 120) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.count(needle) >= n:
                return
            time.sleep(0.1)
        raise AssertionError(
            f"timed out waiting for {n}x {needle!r} (saw"
            f" {self.count(needle)}); last lines:"
            f" {self.snapshot()[-25:]}")


def _seam_dir(tmp_path: Path) -> Path:
    """Test-harness seam for staged daemon subprocesses ONLY.

    HARDENED CORE (v1.2.0): the shipped library ignores the old
    AGENTLINK_SELF_UPDATE / AGENTLINK_UPDATE_CHECK_SECONDS env vars
    entirely — an agent's own environment can neither disable the
    checker nor move its 900s interval. The staged demos still need
    a 3-second tick, so the harness plants a sitecustomize.py on the
    child's PYTHONPATH that pins the timing CONSTANT in-process.
    That is the test reaching into the library's internals; it is
    not a configuration surface the product offers anyone."""
    seam = tmp_path / "testseam"
    seam.mkdir(exist_ok=True)
    (seam / "sitecustomize.py").write_text(
        "import os\n"
        "try:\n"
        "    import agentlink.timing as _t\n"
        "    _t.UPDATE_CHECK_SECONDS = float(\n"
        "        os.environ.get('TEST_UPDATE_CHECK_SECONDS', '3'))\n"
        "except Exception:\n"
        "    pass\n")
    return seam


def _child_env(tmp_path: Path, install: Path, feed: Path,
               state_dir: Path, endpoint: str, extra: dict) -> dict:
    shim = tmp_path / "shim"
    shim.mkdir(exist_ok=True)
    (tmp_path / "home").mkdir(exist_ok=True)
    env = {
        # An EMPTY bin dir as the whole PATH: no crontab, no
        # systemctl, no host tools of any kind. (HOME is inherited:
        # the interpreter's user site-packages live under it — the
        # hostility under test is missing host FACILITIES, not a
        # missing Python environment.)
        "PATH": str(shim),
        "HOME": os.environ.get("HOME", str(tmp_path / "home")),
        "PYTHONPATH": os.pathsep.join(
            [str(_seam_dir(tmp_path)), str(install)]),
        "PYTHONUNBUFFERED": "1",
        # Harness seam (see _seam_dir): the tick the staged daemon
        # runs at. The library's own env surface is dead by law.
        "TEST_UPDATE_CHECK_SECONDS": "3",
        "AGENTLINK_UPDATE_BASE": feed.as_uri(),
        "RUN_ENDPOINT": endpoint,
        "RUN_STATE": str(state_dir),
    }
    env.update(extra)
    return env


def _spawn(tmp_path: Path, script: str, env: dict):
    runner = tmp_path / "runner.py"
    runner.write_text(script)
    proc = subprocess.Popen(
        [sys.executable, str(runner)], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    return proc, _Lines(proc)


def _start_boss(endpoint: str, state_dir: Path, username: str):
    """A full agent running on its own loop in a thread (the
    assigner/recipient for the subprocess daemons)."""
    agent = Agent(username, endpoint=endpoint, state_dir=state_dir)
    box: dict = {}
    ready = threading.Event()

    def _thread():
        async def _main():
            box["loop"] = asyncio.get_running_loop()
            task = asyncio.create_task(agent.run())
            for _ in range(300):
                if agent.connection_state == "connected":
                    break
                await asyncio.sleep(0.1)
            ready.set()
            await task

        asyncio.run(_main())

    threading.Thread(target=_thread, daemon=True).start()
    assert ready.wait(30), "boss did not come online"
    return agent, box["loop"]


def _boss_call(loop, coro, timeout: float = 60):
    return asyncio.run_coroutine_threadsafe(coro, loop).result(timeout)


async def _wait_until(pred, timeout: float = 60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        await asyncio.sleep(0.2)
    return pred()


_RUNNER_PREAMBLE = '''
import asyncio, logging, os, sys
import agentlink
from agentlink.client import Agent

logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                    format="%(levelname)s %(name)s: %(message)s")
print(f"RUNNER_START version={agentlink.__version__}"
      f" pid={os.getpid()}", flush=True)


async def _boot(agent):
    """Start the daemon (reconnect loop) and wait for the first
    connection, so READY always means online + resume pass done."""
    task = asyncio.create_task(agent.run())
    for _ in range(300):
        if agent.connection_state == "connected":
            break
        await asyncio.sleep(0.1)
    return task
'''

RUNNER_BASIC = _RUNNER_PREAMBLE + '''

async def main():
    agent = Agent(os.environ["RUN_USER"],
                  endpoint=os.environ["RUN_ENDPOINT"],
                  state_dir=os.environ["RUN_STATE"])
    task = await _boot(agent)
    print("READY", flush=True)
    await task

asyncio.run(main())
'''

RUNNER_CONTINUITY = _RUNNER_PREAMBLE + '''
import hashlib, json
from pathlib import Path

STATE = Path(os.environ["RUN_STATE"])
BOSS = os.environ["RUN_BOSS"]
DATA = bytes(range(256)) * 800  # 204,800 deterministic bytes
CHUNK = 65536
GATE = Path(os.environ["RUN_GATE"])


async def main():
    agent = Agent(os.environ["RUN_USER"],
                  endpoint=os.environ["RUN_ENDPOINT"],
                  state_dir=os.environ["RUN_STATE"])

    @agent.on_work
    async def handle(work, ctx):
        wid = work["id"]
        if ctx.resumed:
            print(f"WORK_RESUMED checkpoint={ctx.checkpoint}",
                  flush=True)
            await agent.deliver_work(wid, "continuity delivery")
            print("WORK_DELIVERED", flush=True)
            return
        await agent.report_progress(wid, 50, "halfway")
        await agent.checkpoint(wid, {"stage": "halfway"})
        print("WORK_CHECKPOINTED", flush=True)
        # Block mid-work. The work is checkpointed, so the update
        # must proceed WITHOUT waiting for this handler — after the
        # re-exec the resume pass re-invokes it with the checkpoint.
        for _ in range(900):
            if GATE.exists():
                break
            await asyncio.sleep(0.2)
        await agent.deliver_work(wid, "continuity delivery")
        print("WORK_DELIVERED", flush=True)

    task = await _boot(agent)
    plan_p = STATE / "upload-plan.json"
    done_p = STATE / "upload-done.json"
    outbox_p = STATE / "outbox.json"
    sent_p = STATE / "outbox-sent.json"
    if not plan_p.exists():
        sid, cs = await agent.start_upload_session(
            DATA, for_user=BOSS, chunk_size=CHUNK)
        assert not str(sid).startswith("dedup:"), sid
        plan_p.write_text(json.dumps(
            {"session_id": sid, "chunk_size": cs,
             "sha256": hashlib.sha256(DATA).hexdigest()}))
        try:
            await agent.upload_blob(DATA, session_id=sid,
                                    chunk_size=cs, interrupt_after=1)
            raise RuntimeError("interrupt_after did not interrupt")
        except ConnectionError:
            print("UPLOAD_PARTIAL", flush=True)
        # The outbound queue: a message composed and durably queued
        # in the agent home, deliberately NOT sent before the update.
        outbox_p.write_text(json.dumps(
            {"body": "queued-note-survives-update"}))
        print("READY", flush=True)
    else:
        plan = json.loads(plan_p.read_text())
        if not done_p.exists():
            blob_id = await agent.upload_blob(
                DATA, session_id=plan["session_id"],
                chunk_size=plan["chunk_size"])
            done_p.write_text(json.dumps({"blob_id": blob_id}))
            print(f"UPLOAD_DONE blob={blob_id}", flush=True)
        if outbox_p.exists() and not sent_p.exists():
            await agent.send_message(
                BOSS, json.loads(outbox_p.read_text())["body"])
            sent_p.write_text("{}")
            print("OUTBOX_SENT", flush=True)
        print("READY", flush=True)
    await task

asyncio.run(main())
'''

RUNNER_BRAIN = _RUNNER_PREAMBLE + '''
from pathlib import Path

GATE = Path(os.environ["RUN_GATE"])


async def brain(ctx):
    if ctx.get("kind") != "message":
        return None
    print("BRAIN_START", flush=True)
    for _ in range(900):
        if GATE.exists():
            break
        await asyncio.sleep(0.2)
    print("BRAIN_END", flush=True)
    return "brain-reply:" + (ctx["message"].get("body") or "")


async def main():
    agent = Agent(os.environ["RUN_USER"],
                  endpoint=os.environ["RUN_ENDPOINT"],
                  state_dir=os.environ["RUN_STATE"],
                  brain=brain, mode="autonomous")
    task = await _boot(agent)
    print("READY", flush=True)
    await task

asyncio.run(main())
'''


# ------------------------------------------------------------------
# (a) no crontab in PATH: self-update + re-exec + reconnect
# ------------------------------------------------------------------

def test_a_daemon_self_updates_without_crontab(tmp_path):
    _, endpoint = _start_relay(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    asyncio.run(_register(endpoint, state, "upd-a"))
    before = _identity_hashes(state, "upd-a")
    assert before["secret"] and before["keys"]
    install = _make_install(tmp_path)
    feed = _make_feed(tmp_path, NEXT_VERSION)
    env = _child_env(tmp_path, install, feed, state, endpoint,
                     {"RUN_USER": "upd-a"})
    assert shutil.which("crontab", path=env["PATH"]) is None
    proc, lines = _spawn(tmp_path, RUNNER_BASIC, env)
    try:
        first = lines.wait_for(f"RUNNER_START version={RUNNING_VERSION}")
        lines.wait_for("in-daemon checker armed")
        lines.wait_for("next check in 3s")
        second = lines.wait_for(
            f"RUNNER_START version={NEXT_VERSION}", timeout=180)
        # Re-exec replaces the image: SAME pid, process still alive.
        assert _pid_of(first) == _pid_of(second) == proc.pid
        assert proc.poll() is None
        # The new process reconnected and finished its boot pass.
        lines.wait_count("READY", 2, timeout=60)
    finally:
        proc.terminate()
    assert (f'__version__ = "{NEXT_VERSION}"'
            in (install / "agentlink" / "__init__.py").read_text())
    backups = list((state / "update-backups").iterdir())
    assert backups, "no rollback backup was kept"
    assert (backups[0] / "VERSION").read_text() == RUNNING_VERSION
    assert _identity_hashes(state, "upd-a") == before


def _pid_of(line: str) -> int:
    return int(re.search(r"pid=(\d+)", line).group(1))


def test_a2_cli_module_daemon_self_updates(tmp_path):
    """The production entrypoint shape: `python -m agentlink agent`
    (what the systemd units run). Its sys.argv[0] is the package's
    __main__.py — a re-exec that re-runs that file as a plain
    script dies on relative imports, so the checker must reproduce
    the -m invocation (sys.orig_argv)."""
    import site as _site
    _, endpoint = _start_relay(tmp_path)
    install = _make_install(tmp_path)
    feed = _make_feed(tmp_path, NEXT_VERSION)
    shim = tmp_path / "shim"
    shim.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    deps = [p for p in (_site.getsitepackages()
                        + [_site.getusersitepackages()])
            if Path(p).exists()]
    env = {
        "PATH": str(shim),  # no crontab here either
        "HOME": str(home),  # fresh identity under the scrubbed HOME
        "PYTHONPATH": os.pathsep.join(
            [str(_seam_dir(tmp_path)), str(install), *deps]),
        "PYTHONUNBUFFERED": "1",
        "TEST_UPDATE_CHECK_SECONDS": "3",
        "AGENTLINK_UPDATE_BASE": feed.as_uri(),
        "AGENTLINK_ENDPOINT": endpoint,
    }
    assert shutil.which("crontab", path=env["PATH"]) is None
    proc = subprocess.Popen(
        [sys.executable, "-m", "agentlink", "agent",
         "--username", "upd-a2"],
        # cwd pinned AWAY from the repo root: for `-m`, sys.path[0]
        # is the CWD, which would otherwise shadow PYTHONPATH and
        # the daemon would import (and update!) the repo tree.
        cwd=str(tmp_path),
        env=env, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True)
    lines = _Lines(proc)
    try:
        lines.wait_for("online as upd-a2")
        lines.wait_for(
            f"installed {RUNNING_VERSION} -> {NEXT_VERSION}",
            timeout=180)
        # The re-exec'd process rejoins on the new code.
        lines.wait_count("online as upd-a2", 2, timeout=120)
        assert proc.poll() is None
    finally:
        proc.terminate()
    assert (f'__version__ = "{NEXT_VERSION}"'
            in (install / "agentlink" / "__init__.py").read_text())
    # The identity the daemon created lives in its own state dir
    # and survived the update.
    assert (home / ".agentlink" / "secret-upd-a2.json").exists()


# ------------------------------------------------------------------
# (b/c/d) staged apply gates, driven in-process
# ------------------------------------------------------------------

def _updater(tmp_path, feed, install, state) -> Updater:
    return Updater(base_url=feed.as_uri(), install_dir=install,
                   state_dir=state, current_version=RUNNING_VERSION)


def test_b_corrupt_hash_aborts_apply(tmp_path):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    feed = _make_feed(tmp_path, NEXT_VERSION,
                      corrupt="agentlink/client.py")
    before = _tree_hashes(install / "agentlink")
    outcome = _updater(tmp_path, feed, install, state) \
        .check_and_apply_staged()
    assert outcome["updated"] is False
    assert "sha256 mismatch" in outcome["error"]
    assert _tree_hashes(install / "agentlink") == before
    assert not (state / "update-backups").exists()
    assert _updater(tmp_path, feed, install, state) \
        ._import_check(install, RUNNING_VERSION)


def test_c_broken_staged_tree_aborts_swap(tmp_path):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    feed = _make_feed(tmp_path, NEXT_VERSION, broken="timing.py")
    before = _tree_hashes(install / "agentlink")
    outcome = _updater(tmp_path, feed, install, state) \
        .check_and_apply_staged()
    assert outcome["updated"] is False
    assert "import smoke" in outcome["error"]
    assert _tree_hashes(install / "agentlink") == before
    staging = state / "update-staging"
    assert not staging.exists() or not list(staging.iterdir())
    assert not (state / "update-backups").exists()


def test_d_feed_at_running_version_is_noop(tmp_path):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    feed = _make_feed(tmp_path, RUNNING_VERSION, bump_init=False)
    outcome = _updater(tmp_path, feed, install, state) \
        .check_and_apply_staged()
    assert outcome["updated"] is False
    assert outcome["reason"] == "already up to date"
    assert not (state / "update-backups").exists()
    assert not (state / "update-staging").exists()


def test_d2_newer_version_identical_files_is_noop(tmp_path):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    # Manifest claims NEXT but every file hash matches the install.
    feed = _make_feed(tmp_path, NEXT_VERSION, bump_init=False)
    outcome = _updater(tmp_path, feed, install, state) \
        .check_and_apply_staged()
    assert outcome["updated"] is False
    assert outcome["reason"] == "all files already match the manifest"
    assert not (state / "update-backups").exists()
    assert not (state / "update-staging").exists()


# ------------------------------------------------------------------
# (e) continuity: checkpointed work + queued message + partial
#     upload all survive a self-update, exactly once
# ------------------------------------------------------------------

def test_e_update_mid_work_preserves_everything(tmp_path):
    _, endpoint = _start_relay(tmp_path)
    boss_state = tmp_path / "boss-state"
    boss_state.mkdir()
    asyncio.run(_register(endpoint, boss_state, "upd-boss-e"))
    state = tmp_path / "state"
    state.mkdir()
    asyncio.run(_register(endpoint, state, "upd-e"))
    before = _identity_hashes(state, "upd-e")
    boss, loop = _start_boss(endpoint, boss_state, "upd-boss-e")
    install = _make_install(tmp_path)
    feed = _make_feed(tmp_path, NEXT_VERSION)
    gate = tmp_path / "work-gate"
    env = _child_env(tmp_path, install, feed, state, endpoint,
                     {"RUN_USER": "upd-e", "RUN_BOSS": "upd-boss-e",
                      "RUN_GATE": str(gate)})
    proc, lines = _spawn(tmp_path, RUNNER_CONTINUITY, env)
    try:
        lines.wait_for("UPLOAD_PARTIAL")   # 1 of 4 chunks sent
        lines.wait_for("READY")
        works = _boss_call(loop, boss.assign_work(
            ["upd-e"], "continuity job"))
        wid = works[0]["id"]
        # Progress reported + checkpoint written; handler now blocks.
        lines.wait_for("WORK_CHECKPOINTED")
        # The update fires while the handler is STILL blocked: the
        # work is checkpointed, so nothing waits on the handler.
        second = lines.wait_for(
            f"RUNNER_START version={NEXT_VERSION}", timeout=180)
        assert _pid_of(second) == proc.pid
        gate.touch()  # release the (dead) first-boot handler's gate
        # After re-exec: resume completes the upload, sends the
        # queued message, and the resumed work handler delivers.
        done = lines.wait_for("UPLOAD_DONE", timeout=120)
        blob_id = re.search(r"blob=(\S+)", done).group(1)
        lines.wait_for("OUTBOX_SENT")
        lines.wait_for("WORK_DELIVERED")
        resumed = lines.wait_for("WORK_RESUMED")
        assert "halfway" in resumed  # the checkpoint traveled
    finally:
        proc.terminate()
    # Work: exactly one delivery, relay-verified proof.
    deliveries = [w for w in boss.work_updates
                  if w["id"] == wid and w.get("proof_verified")]
    assert len(deliveries) == 1, boss.work_updates
    assert deliveries[0]["status"] in ("delivered", "completed")
    # Queued message: arrived exactly once. Delivery to the
    # boss's handler is asynchronous (journal-ACK delivery):
    # OUTBOX_SENT above proves the send, so poll the boss's
    # inbox briefly instead of snapshotting it mid-flight —
    # the count assertion itself is unchanged. (Full-gate
    # runs under load starved this snapshot twice; standalone
    # the message always lands.)
    queued = []
    for _ in range(120):
        queued = [m for m in boss.messages
                  if m.get("body") == "queued-note-survives-update"]
        if len(queued) == 1:
            break
        time.sleep(0.25)
    assert len(queued) == 1, boss.messages
    # Upload: finished byte-exact (SHA-256 of the fetched blob).
    data = _boss_call(loop, boss._request(
        {"type": "blob_get", "blob_id": blob_id}))
    blob_bytes = base64.b64decode(data["data_b64"])
    expected = bytes(range(256)) * 800
    assert len(blob_bytes) == len(expected)
    assert _sha(blob_bytes) == _sha(expected)
    assert _identity_hashes(state, "upd-e") == before


# ------------------------------------------------------------------
# (f) continuity: an update arriving mid-brain-call waits; the
#     reply lands exactly once, then the update applies
# ------------------------------------------------------------------

def test_f_update_waits_for_brain_call(tmp_path):
    _, endpoint = _start_relay(tmp_path)
    boss_state = tmp_path / "boss-state"
    boss_state.mkdir()
    asyncio.run(_register(endpoint, boss_state, "upd-boss-f"))
    state = tmp_path / "state"
    state.mkdir()
    asyncio.run(_register(endpoint, state, "upd-f"))
    before = _identity_hashes(state, "upd-f")
    boss, loop = _start_boss(endpoint, boss_state, "upd-boss-f")
    install = _make_install(tmp_path)
    feed = _make_feed(tmp_path, NEXT_VERSION)
    gate = tmp_path / "brain-gate"
    env = _child_env(tmp_path, install, feed, state, endpoint,
                     {"RUN_USER": "upd-f", "RUN_GATE": str(gate),
                      "TEST_UPDATE_CHECK_SECONDS": "10"})
    proc, lines = _spawn(tmp_path, RUNNER_BRAIN, env)
    try:
        lines.wait_for("READY")
        _boss_call(loop, boss.send_message("upd-f", "hello-brain"))
        lines.wait_for("BRAIN_START", timeout=60)
        # The 10s tick fires mid-brain-call: the daemon logs that it
        # is WAITING for the in-flight operation — no swap, no exec.
        lines.wait_for("waiting up to 120s for 1 in-flight",
                       timeout=60)
        assert lines.count(f"RUNNER_START version={NEXT_VERSION}") == 0
        assert (f'__version__ = "{RUNNING_VERSION}"'
                in (install / "agentlink" / "__init__.py").read_text())
        # Release the brain: its reply must land BEFORE the update.
        gate.touch()
        lines.wait_for("BRAIN_END")
        assert _boss_call(loop, _wait_until(
            lambda: any(m.get("body") == "brain-reply:hello-brain"
                        for m in boss.messages), timeout=60))
        assert lines.count(f"RUNNER_START version={NEXT_VERSION}") == 0
        # Now the drain completes and the update applies.
        second = lines.wait_for(
            f"RUNNER_START version={NEXT_VERSION}", timeout=120)
        assert _pid_of(second) == proc.pid
        lines.wait_count("READY", 2, timeout=60)
    finally:
        proc.terminate()
    replies = [m for m in boss.messages
               if m.get("body") == "brain-reply:hello-brain"]
    assert len(replies) == 1, boss.messages
    assert _identity_hashes(state, "upd-f") == before


# ------------------------------------------------------------------
# (g) config pins + installer on a crontab-less host
# ------------------------------------------------------------------

def test_g_checker_config_pins(monkeypatch):
    assert UPDATE_CHECK_SECONDS == 15 * 60  # the timing law
    assert UPDATE_DRAIN_WAIT_SECONDS > 0
    # HARDENED CORE (v1.2.0): the agent's own environment can neither
    # move the interval (stretch OR shrink) nor disable the checker.
    # The pins below prove the attempts change NOTHING.
    for junk in ("7", "99999", "0", "junk"):
        monkeypatch.setenv("AGENTLINK_UPDATE_CHECK_SECONDS", junk)
        assert resolve_update_check_seconds() == UPDATE_CHECK_SECONDS
    monkeypatch.delenv("AGENTLINK_UPDATE_CHECK_SECONDS", raising=False)
    assert resolve_update_check_seconds() == UPDATE_CHECK_SECONDS
    for off in ("0", "off", "false", "no", ""):
        monkeypatch.setenv("AGENTLINK_SELF_UPDATE", off)
        assert self_update_enabled() is True
    monkeypatch.setenv("AGENTLINK_SELF_UPDATE", "1")
    assert self_update_enabled() is True


def test_g_installer_without_crontab_prints_notice(tmp_path,
                                                   monkeypatch, capsys):
    from agentlink import cli
    shim = tmp_path / "shim"
    shim.mkdir()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("PATH", str(shim))   # no crontab, no systemctl
    monkeypatch.setenv("HOME", str(home))
    assert shutil.which("crontab") is None
    rc = cli._service(["install", "--username", "cronless", "--user"])
    out = capsys.readouterr().out
    assert rc == 0
    # Never a silent skip: a plain notice + the in-daemon guarantee.
    assert "no crontab binary on this host" in out
    assert "checks for updates itself every 15 minutes" in out


# ------------------------------------------------------------------
# (h) mirror-purge + first-boot self-clean (v2.0.11): an update
#     REPLACES the install. The stale set is computed before the
#     swap, backed up with everything else (rollback stays whole),
#     and deleted only after the health + census gates pass. The
#     2.0.11 distribution drops the retired relay era from the
#     manifest, so relay.py/dashboard.py are themselves stale
#     cargo on a 2.0.10 install. State is never a purge target.
# ------------------------------------------------------------------

def _make_feed_2011(tmp_path: Path, version: str) -> Path:
    """The 2.0.11 feed shape: the package WITHOUT relay.py /
    dashboard.py (retired from the distribution), version-bumped,
    with a manifest over exactly what ships."""
    feed = tmp_path / "feed2011"
    pkg = feed / "agentlink"
    shutil.copytree(ROOT / "agentlink", pkg,
                    ignore=shutil.ignore_patterns("__pycache__"))
    (pkg / "relay.py").unlink()
    (pkg / "dashboard.py").unlink()
    init = pkg / "__init__.py"
    init.write_text(re.sub(
        r'__version__ = "[^"]+"', f'__version__ = "{version}"',
        init.read_text()))
    files = {}
    for f in sorted(pkg.glob("*.py")):
        files[f"agentlink/{f.name}"] = _sha(f.read_bytes())
    (feed / "update-manifest.json").write_text(
        json.dumps({"version": version, "files": files}))
    return feed


def _plant_junk(install: Path, state: Path) -> dict:
    """v1-era cargo inside the governed scope + the things that
    must survive: state sentinels (byte-identical or the test
    fails) and an ungoverned install-root file."""
    pkg = install / "agentlink"
    (pkg / "legacy_v1.py").write_text("# a v1-era module\n")
    cache = pkg / "__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "legacy_v1.cpython-312.pyc").write_bytes(b"orphaned pyc")
    (cache / "client.cpython-312.pyc").write_bytes(b"stale pyc")
    (pkg / "client.py.tmp").write_text("half-written swap leftover")
    (install / "leftover.tmp").write_text("root swap leftover")
    docs = install / "docs"
    docs.mkdir(exist_ok=True)
    keep = docs / "keep.txt"
    keep.write_text("not governed — the updater never owned the root")
    state.mkdir(parents=True, exist_ok=True)
    sentinel = state / "secret-junk.json"
    sentinel.write_text('{"username": "junk", "secret": "same-bytes"}')
    return {"sentinel": sentinel,
            "sentinel_bytes": sentinel.read_bytes(), "keep": keep}


_STALE_SET = {"agentlink/legacy_v1.py", "agentlink/relay.py",
              "agentlink/dashboard.py", "agentlink/client.py.tmp",
              "leftover.tmp"}


def test_h_apply_purges_stale_and_preserves_state(tmp_path):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    planted = _plant_junk(install, state)
    feed = _make_feed_2011(tmp_path, NEXT_VERSION)
    result = _updater(tmp_path, feed, install, state).apply()
    assert result["updated"] is True
    assert _STALE_SET <= set(result["purged"])
    pkg = install / "agentlink"
    for rel in _STALE_SET:
        assert not (install / rel).exists(), rel
    assert not (pkg / "__pycache__").exists()
    assert result["purged_caches"] >= 1
    # The new tree is whole and live.
    assert f'__version__ = "{NEXT_VERSION}"' in \
        (pkg / "__init__.py").read_text()
    assert (pkg / "client.py").exists()
    # State byte-identical; the ungoverned root file intact.
    assert planted["sentinel"].read_bytes() == planted["sentinel_bytes"]
    assert planted["keep"].exists()
    # The purged files are IN the rollback backup: a rollback
    # would have restored the exact pre-update tree.
    backup = Path(result["backup"])
    assert (backup / "agentlink" / "relay.py").exists()
    assert (backup / "agentlink" / "legacy_v1.py").exists()


def test_h_staged_purges_stale(tmp_path):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    planted = _plant_junk(install, state)
    feed = _make_feed_2011(tmp_path, NEXT_VERSION)
    outcome = _updater(tmp_path, feed, install, state) \
        .check_and_apply_staged()
    assert outcome["updated"] is True
    assert _STALE_SET <= set(outcome["purged"])
    for rel in _STALE_SET:
        assert not (install / rel).exists(), rel
    assert not (install / "agentlink" / "__pycache__").exists()
    assert planted["sentinel"].read_bytes() == planted["sentinel_bytes"]
    backup = Path(outcome["backup"])
    assert (backup / "agentlink" / "dashboard.py").exists()


def test_h_apply_rollback_never_purges(tmp_path, monkeypatch):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    _plant_junk(install, state)
    feed = _make_feed_2011(tmp_path, NEXT_VERSION)
    up = _updater(tmp_path, feed, install, state)
    monkeypatch.setattr(up, "_health_check", lambda v: False)
    with pytest.raises(UpdateError):
        up.apply()
    pkg = install / "agentlink"
    # Rolled back: replaced files restored, stale files UNTOUCHED
    # (the purge runs only after every gate has passed).
    assert f'__version__ = "{RUNNING_VERSION}"' in \
        (pkg / "__init__.py").read_text()
    assert (pkg / "legacy_v1.py").exists()
    assert (pkg / "relay.py").exists()
    # (client.py.tmp is not asserted: it is the swap's own temp
    # path for client.py, consumed by the install itself.)


def test_h_staged_rollback_never_purges(tmp_path, monkeypatch):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    _plant_junk(install, state)
    feed = _make_feed_2011(tmp_path, NEXT_VERSION)
    up = _updater(tmp_path, feed, install, state)
    monkeypatch.setattr(up, "_health_check", lambda v: False)
    with pytest.raises(UpdateError):
        up.apply_staged()
    pkg = install / "agentlink"
    assert f'__version__ = "{RUNNING_VERSION}"' in \
        (pkg / "__init__.py").read_text()
    assert (pkg / "legacy_v1.py").exists()
    assert (pkg / "dashboard.py").exists()


def test_h_exact_tree_reports_empty_purge(tmp_path):
    feed = _make_feed_2011(tmp_path, NEXT_VERSION)
    install = tmp_path / "install"
    shutil.copytree(feed / "agentlink", install / "agentlink")
    init = install / "agentlink" / "__init__.py"
    init.write_text(re.sub(
        r'__version__ = "[^"]+"', f'__version__ = "{RUNNING_VERSION}"',
        init.read_text()))
    state = tmp_path / "state"
    state.mkdir()
    result = _updater(tmp_path, feed, install, state).apply()
    assert result["updated"] is True
    assert result["purged"] == []
    # (purged_caches is not asserted: the health check's own import
    # creates a fresh __pycache__ that the purge then clears — the
    # cache clear working as ruled, not stale cargo.)


def test_h_self_clean_converges_dirty_tree(tmp_path):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    planted = _plant_junk(install, state)
    # Relay-era config cargo: the persisted peer registry, a
    # platform endpoint planted in the network config, and a
    # platform variable planted in the env file. The agent's own
    # proxy (deliberately per-agent) must SURVIVE.
    (state / "servers.json").write_text(
        '{"wss://old-relay.example/ws": {"health": 100}}')
    (state / "network.json").write_text(json.dumps(
        {"proxy": "http://proxy:8080",
         "endpoint": "wss://old-relay.example/ws",
         "transport": "relay"}))
    (state / "proxy.env").write_text(
        "HTTPS_PROXY=http://proxy:8080\n"
        "AGENTLINK_ENDPOINT=wss://old-relay.example/ws\n")
    feed = _make_feed_2011(tmp_path, RUNNING_VERSION)
    shutil.copy2(feed / "update-manifest.json",
                 install / "update-manifest.json")
    out = self_clean_install(install, state, RUNNING_VERSION)
    assert out["cleaned"] is True and out["changed"] is True
    pkg = install / "agentlink"
    assert not (pkg / "legacy_v1.py").exists()
    assert not (pkg / "relay.py").exists()
    assert not (pkg / "dashboard.py").exists()
    assert not (pkg / "__pycache__").exists()
    assert not (state / "servers.json").exists()
    net = json.loads((state / "network.json").read_text())
    assert net == {"proxy": "http://proxy:8080"}
    env_lines = (state / "proxy.env").read_text()
    assert "HTTPS_PROXY=http://proxy:8080" in env_lines
    assert "AGENTLINK_ENDPOINT" not in env_lines
    assert planted["sentinel"].read_bytes() == planted["sentinel_bytes"]
    assert planted["keep"].exists()
    assert (state / "self-clean.json").exists()
    # Idempotent: the marker makes the second pass a no-op.
    out2 = self_clean_install(install, state, RUNNING_VERSION)
    assert out2["cleaned"] is False
    # A manifest describing a DIFFERENT version never cleans: the
    # clean runs only against the running version's own tree.
    (state / "self-clean.json").unlink()
    (pkg / "legacy_v1.py").write_text("# junk again\n")
    out3 = self_clean_install(install, state, NEXT_VERSION)
    assert out3["cleaned"] is False
    assert (pkg / "legacy_v1.py").exists()


def test_h_self_clean_fetches_manifest(tmp_path):
    install = _make_install(tmp_path)
    state = tmp_path / "state"
    state.mkdir()
    (install / "agentlink" / "legacy_v1.py").write_text("# junk\n")
    feed = _make_feed_2011(tmp_path, RUNNING_VERSION)
    out = self_clean_install(install, state, RUNNING_VERSION,
                             base_url=feed.as_uri())
    assert out["cleaned"] is True
    assert not (install / "agentlink" / "legacy_v1.py").exists()


def test_h_self_clean_skips_source_checkout(tmp_path):
    install = _make_install(tmp_path)
    (install / "tests").mkdir()  # a development checkout marker
    (install / "agentlink" / "legacy_v1.py").write_text("# junk\n")
    state = tmp_path / "state"
    state.mkdir()
    feed = _make_feed_2011(tmp_path, RUNNING_VERSION)
    out = self_clean_install(install, state, RUNNING_VERSION,
                             base_url=feed.as_uri())
    assert out["cleaned"] is False
    assert "checkout" in out["reason"]
    assert (install / "agentlink" / "legacy_v1.py").exists()
