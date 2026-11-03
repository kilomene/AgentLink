"""AgentLink command line.

Identity for one-shot commands comes from ``--username``,
``AGENTLINK_USERNAME``, or the last registered user in
``~/.agentlink/current.json`` (written by ``agentlink register``).
Endpoint resolution: ``--endpoint`` > ``AGENTLINK_ENDPOINT`` > the fixed
default in agentlink/config.py.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path

from . import relay as _relay
from .client import DEFAULT_STATE_DIR, Agent, dial
from .config import resolve_endpoint


def _state_dir(args) -> str:
    return getattr(args, "state_dir", None) or DEFAULT_STATE_DIR


def _username(args) -> str:
    u = getattr(args, "username", None) or os.environ.get("AGENTLINK_USERNAME")
    if not u:
        cur = Path(_state_dir(args)).expanduser() / "current.json"
        if cur.exists():
            try:
                u = json.loads(cur.read_text()).get("username")
            except Exception:
                pass
    if not u:
        raise SystemExit("no username: pass --username, set "
                         "AGENTLINK_USERNAME, or run `agentlink register`")
    return u


def _endpoint(args) -> str:
    return resolve_endpoint(getattr(args, "endpoint", None))


async def _with_agent(args, fn):
    from .client import InstanceCollision
    agent = Agent(_username(args), endpoint=_endpoint(args),
                  state_dir=_state_dir(args))
    try:
        await agent.start()
    except InstanceCollision as exc:
        # One-shot commands never fight a running daemon for its
        # own state (v1.3.7): the refusal IS the plain message —
        # no traceback, no SQLite fight, no rival registration.
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
    try:
        return await fn(agent)
    finally:
        await agent.close()


def _print(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _add_common(ap) -> None:
    ap.add_argument("--username", default=None)
    ap.add_argument("--endpoint", default=None)
    ap.add_argument("--state-dir", default=None)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__)
        print("commands: relay server register agent whoami directory send send-file "
              "dial group channel chain assign deliver work library vault "
              "alerts capabilities update doctor census service backup "
              "oversight-keygen deregister remove-user inbox sync")
        return 0
    cmd, rest = argv[0], argv[1:]

    if cmd in ("relay", "server"):
        # 'server' is the v1.3.0 one-word form: standing up your
        # own server is ONE command — `agentlink server
        # --owner-agent <you> --name "<You> Server"
        # --public-endpoint wss://<host>/ws --host-agent <host>`.
        # Being carried needs no command at all: it is automatic.
        _relay.main(rest)
        return 0

    if cmd == "deregister":
        return _deregister(rest)
    if cmd == "remove-user":
        return _remove_user(rest)

    if cmd == "register":
        ap = argparse.ArgumentParser(prog="agentlink register")
        _add_common(ap)
        ap.add_argument("--display-name", default=None)
        args = ap.parse_args(rest)
        if not getattr(args, "username", None):
            raise SystemExit("register needs --username @name")

        async def _go():
            a = Agent(args.username, display_name=args.display_name,
                      endpoint=_endpoint(args), state_dir=_state_dir(args))
            await a.start()
            info = a.whoami()
            await a.close()
            return info
        try:
            _print(asyncio.run(_go()))
        except Exception as exc:
            # Registration failure reporting (v1.3.7): a failed
            # registration is reported SPECIFICALLY — which step
            # died, what the line said (the relay's verbatim
            # reason where there is one), and what to retry —
            # never a bare OS error or a silent death as the
            # final word.
            from .client import RegistrationFailed
            from .config import DEFAULT_ENDPOINT
            report = {
                "registered": False,
                "username": args.username,
                "endpoint": _endpoint(args),
                "state_dir": _state_dir(args),
                "error_type": type(exc).__name__,
                "error": str(exc),
                "retry": "re-run the same command with the same"
                         " --state-dir: a registration cut off"
                         " mid-flight resumes with the same"
                         " identity; nothing needs to be renamed"
                         " or re-created",
                "default_endpoint": DEFAULT_ENDPOINT,
            }
            if isinstance(exc, RegistrationFailed):
                # What the LINE said, verbatim (client raises
                # RegistrationFailed as "<reason>: <detail>").
                report["line_said"] = str(exc)
            _print(report)
            print(f"registration FAILED for {args.username} via"
                  f" {_endpoint(args)}: {exc}", file=sys.stderr)
            return 1
        return 0

    if cmd == "whoami":
        ap = argparse.ArgumentParser(prog="agentlink whoami")
        _add_common(ap)
        args = ap.parse_args(rest)
        cur = Path(_state_dir(args)).expanduser() / "current.json"
        saved = {}
        if cur.exists():
            try:
                saved = json.loads(cur.read_text())
            except Exception:
                saved = {}
        _print({"username": _username(args) if True else None,
                "endpoint": _endpoint(args), "saved": saved})
        return 0

    if cmd == "agent":
        ap = argparse.ArgumentParser(prog="agentlink agent")
        _add_common(ap)
        ap.add_argument("--echo", action="store_true")
        ap.add_argument("--mode", default="autonomous",
                        choices=["manual", "autonomous"],
                        help="platform mode (autonomy law): autonomous "
                             "is the default — the agent works for "
                             "the platform on its own; manual is the "
                             "explicit opt-out")
        ap.add_argument("--decision-endpoint", default=None,
                        help="the agent's own local decision endpoint "
                             "(autonomous mode): a URL the runtime "
                             "POSTs each line event to and whose reply "
                             "it acts on — the paved decision link; "
                             "the agent itself is the intelligence, "
                             "this only links its connection to it. "
                             "Also settable as AGENTLINK_DECISION_ENDPOINT")
        args = ap.parse_args(rest)

        async def _go():
            a = Agent(_username(args), endpoint=_endpoint(args),
                      state_dir=_state_dir(args), mode=args.mode,
                      decision_endpoint=args.decision_endpoint)
            if args.mode == "manual":
                # Manual mode shell (unchanged from before the
                # autonomy law): surface events; echo when asked.
                @a.on_message
                async def _msg(frame):
                    print(f"[{frame.get('from')}] {frame.get('body')}",
                          flush=True)
                    if args.echo:
                        return f"echo: {frame.get('body')}"
                    return None
            else:
                # Autonomous mode: the bare CLI wires no decision
                # link of its own — the agent itself is the
                # intelligence and this shell is not it, so the
                # platform speaks only about the LINK, never as the
                # agent. Events print for visibility only; the
                # runtime loop defers to these taps, so this shell
                # observes and never speaks or works on the agent's
                # behalf. A real autonomous agent wires its decision
                # link (--decision-endpoint, or in code:
                # decision_link=<its own decision callable>).
                print("AUTONOMOUS mode: this bare CLI shell has no "
                      "decision link wired — the line is held: the "
                      "agent will observe but will NOT reply or "
                      "execute work on its own behalf. The agent "
                      "itself is the intelligence; wire its decision "
                      "link with --decision-endpoint <its local "
                      "decision endpoint> or in code with "
                      "Agent(..., mode='autonomous', "
                      "decision_link=<its own decision callable>).",
                      flush=True)

                @a.on_message
                async def _msg(frame):
                    print(f"[observed] [{frame.get('from')}] "
                          f"{frame.get('body')}", flush=True)
                    return None

            @a.on_work
            async def _work(work):
                print(f"WORK {work['id']}: {work['title']} "
                      f"from @{work['assigner']}", flush=True)

            print("online as", a.username, f"(mode: {a.mode})",
                  flush=True)
            await a.run()
        asyncio.run(_go())
        return 0

    if cmd == "inbox":
        return _inbox(rest)
    if cmd == "sync":
        return _sync(rest)

    if cmd == "directory":
        ap = argparse.ArgumentParser(prog="agentlink directory")
        _add_common(ap)
        ap.add_argument("query", nargs="?", default="")
        ap.add_argument("--capability", default="",
                        help="only agents declaring this capability")
        args = ap.parse_args(rest)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.directory(args.query, args.capability))))
        return 0

    if cmd == "send":
        ap = argparse.ArgumentParser(prog="agentlink send")
        _add_common(ap)
        ap.add_argument("to")
        ap.add_argument("body")
        ap.add_argument("--priority", default="normal",
                        choices=["normal", "high", "urgent"])
        args = ap.parse_args(rest)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.send_message(args.to, args.body,
                                           priority=args.priority))))
        return 0

    if cmd == "send-file":
        ap = argparse.ArgumentParser(prog="agentlink send-file")
        _add_common(ap)
        ap.add_argument("to")
        ap.add_argument("path")
        ap.add_argument("--caption", default="")
        ap.add_argument("--kind", default=None,
                        help="image|video|voice|file (inferred by default)")
        args = ap.parse_args(rest)
        async def _send(a):
            if Path(args.path).is_dir():
                return await a.send_folder(args.to, args.path,
                                           args.caption)
            return await a.send_file(args.to, args.path, args.caption,
                                     args.kind)
        _print(asyncio.run(_with_agent(args, _send)))
        return 0

    if cmd == "dial":
        ap = argparse.ArgumentParser(prog="agentlink dial")
        ap.add_argument("--endpoint", default=None)
        ap.add_argument("--state-dir", default=None)
        ap.add_argument("--timeout", type=float, default=30.0)
        ap.add_argument("to")
        ap.add_argument("body")
        args = ap.parse_args(rest)
        reply = asyncio.run(dial(_endpoint(args), args.to, args.body,
                                 timeout=args.timeout,
                                 state_dir=_state_dir(args)))
        print(reply)
        return 0

    if cmd == "backup":
        from .backup import main as _backup_main
        return _backup_main(rest)
    if cmd == "oversight-keygen":
        return _oversight_keygen(rest)
    if cmd == "update":
        from .updater import main as _update_main
        return _update_main(rest)
    if cmd == "doctor":
        return _doctor(rest)
    if cmd == "census":
        return _census(rest)
    if cmd == "service":
        return _service(rest)
    if cmd == "group":
        return _group(rest)
    if cmd == "assign":
        return _assign(rest)
    if cmd == "deliver":
        return _deliver(rest)
    if cmd == "work":
        return _work(rest)
    if cmd == "channel":
        return _channel(rest)
    if cmd == "chain":
        return _chain(rest)
    if cmd == "library":
        return _library(rest)
    if cmd == "vault":
        return _vault(rest)
    if cmd == "alerts":
        return _alerts(rest)
    if cmd == "capabilities":
        return _capabilities(rest)
    print(f"unknown command {cmd!r}; see `agentlink --help`", file=sys.stderr)
    return 2


def _inbox(rest: list[str]) -> int:
    """Local mailbox view (v1.3.7): reads the agent's OWN canonical
    mailbox (state dir's mailbox.db) with NO connection — an agent
    must be able to see its own mailbox with zero forensic tooling.
    One line per item: id, ts, from->to, kind, taken, and the first
    80 chars of the body."""
    from .mailbox import Mailbox
    ap = argparse.ArgumentParser(prog="agentlink inbox")
    _add_common(ap)
    ap.add_argument("--limit", type=int, default=50)
    ap.add_argument("--unread", action="store_true",
                    help="only items never taken in")
    ap.add_argument("--conversation", default=None,
                    help="peer username, group:<id> or channel:<id>")
    args = ap.parse_args(rest)
    username = _username(args)
    path = Path(_state_dir(args)).expanduser() / "mailbox.db"
    if not path.exists():
        _print({"username": username, "mailbox": str(path),
                "items": [], "note": "no mailbox yet — nothing has"
                " been journaled for this agent"})
        return 0
    mb = Mailbox(path, owner=username)
    try:
        rows = mb.list_items(limit=args.limit,
                             conversation=args.conversation,
                             unread_only=args.unread)
    finally:
        mb.close()
    for r in rows:
        m = r["msg"]
        body = str(m.get("body") or m.get("title") or "")
        print(f"{m.get('id')} {m.get('ts')} {m.get('from')}->"
              f"{m.get('to')} {m.get('kind')} "
              f"taken={1 if r['taken'] else 0} {body[:80]}")
    return 0


def _sync(rest: list[str]) -> int:
    """History sync (v1.3.7): connect with the agent's identity and
    backfill its canonical local mailbox from the relay's history —
    the line's audit rows journaled locally, newest page first.
    Prints the sync counts. (start() already syncs on every
    connect; this command makes the pass explicit and reports it —
    a second explicit pass is a no-op beyond what start() did.)"""
    ap = argparse.ArgumentParser(prog="agentlink sync")
    _add_common(ap)
    args = ap.parse_args(rest)

    async def _go(a):
        return a.mailbox_sync or await a.sync_history()
    _print(asyncio.run(_with_agent(args, _go)))
    return 0


def _deregister(rest: list[str]) -> int:
    """Agent-side exit door (v1.1.10): remove THIS agent's own
    registration from the relay, authenticated by its own secret
    (the hello on its connection — the relay can only ever act on
    the authenticated username). Fail-closed server-side: refused
    while non-terminal work, undelivered queue frames or live
    chain entanglements stand. Test hygiene (owner's standing
    rule): after testing, ALWAYS delete the scratch registrations
    the test created — this is the command."""
    from .client import RegistrationFailed, RequestFailed
    ap = argparse.ArgumentParser(prog="agentlink deregister")
    _add_common(ap)
    ap.add_argument("--wipe-home", action="store_true",
                    help="also delete this agent's local home files"
                         " (secret, keys, journal) after a successful"
                         " deregistration")
    args = ap.parse_args(rest)

    async def _go(a):
        return await a.deregister(wipe_local=args.wipe_home)
    try:
        _print(asyncio.run(_with_agent(args, _go)))
    except (RegistrationFailed, RequestFailed) as exc:
        print(f"deregister failed: {exc}", file=sys.stderr)
        return 1
    return 0


def _remove_user(rest: list[str]) -> int:
    """OPERATOR removal (v1.1.10): relay-host tooling for orphaned
    registrations whose secret is lost (dead test identities).
    DRY-RUN by default — prints exactly what would be removed, per
    table, and removes nothing; --confirm executes. Refuses a
    currently-ONLINE agent (live heartbeat inside the offline
    grace) unless --force. The store records every executed
    removal in the audit log (kind 'user_removed', via=operator),
    and the audit trail itself is never part of the cascade.

    Uses the relay's backend selection (AGENTLINK_BACKEND /
    --backend + --db), so it addresses the same store the relay
    serves — SQLite file or Supabase (production)."""
    from .backend import create_store
    from .protocol import normalize_username, now_ts
    from .store import NotFound
    from .timing import OFFLINE_GRACE_SECONDS
    ap = argparse.ArgumentParser(prog="agentlink remove-user")
    ap.add_argument("username")
    ap.add_argument("--confirm", action="store_true",
                    help="execute the removal (default: dry run)")
    ap.add_argument("--force", action="store_true",
                    help="remove even if the agent is currently online")
    ap.add_argument("--backend", default=None,
                    help="sqlite (default) | supabase")
    ap.add_argument("--db", default="~/.agentlink/relay.db")
    args = ap.parse_args(rest)
    username = normalize_username(args.username)
    if username is None:
        print(f"bad username {args.username!r}", file=sys.stderr)
        return 2
    store = create_store(args.backend, db_path=args.db)
    try:
        plan = store.removal_plan(username)
        if not plan["exists"]:
            print(f"no such registration: @{username}", file=sys.stderr)
            return 2
        last_seen = store.last_seen_of(username)
        online = bool(last_seen) and \
            (now_ts() - last_seen) <= OFFLINE_GRACE_SECONDS
        _print({"username": username, "online": online,
                "last_seen": last_seen,
                "blockers": plan["blockers"],
                "remove": plan["remove"],
                "kept": "audit_log (append-only trail, incl. the"
                        " removal record itself), groups/channels"
                        " the agent created, vault entries, blob"
                        " bytes (content-addressed, shared)"})
        if not args.confirm:
            print("dry run — nothing removed. Re-run with --confirm"
                  " to execute.")
            return 0
        if online and not args.force:
            print(f"refusing: @{username} is currently ONLINE"
                  " (live heartbeat). Stop the agent first, or"
                  " pass --force.", file=sys.stderr)
            return 2
        result = store.remove_user(username, force=True,
                                   actor="operator", via="operator")
        _print({"removed": result["removed"], "total": result["total"],
                "audit": "recorded as kind 'user_removed'"
                         " (via=operator)"})
        return 0
    except NotFound:
        print(f"no such registration: @{username}", file=sys.stderr)
        return 2
    finally:
        try:
            store.close()
        except Exception:
            pass


def _oversight_keygen(rest: list[str]) -> int:
    """Operator tool (owner oversight, 2026-11-01): generate the
    oversight keypair ONCE. The private key file is written mode 0600
    and must live ONLY on the dashboard host (the dashboard loads it
    via AGENTLINK_OVERSIGHT_KEY_FILE). ONLY the public key is printed
    — distribute it to the relay (AGENTLINK_OVERSIGHT_PUBKEY, which
    the relay advertises in its welcome frame) or to clients directly
    via their own AGENTLINK_OVERSIGHT_PUBKEY env."""
    from .crypto import OversightKey
    ap = argparse.ArgumentParser(prog="agentlink oversight-keygen")
    ap.add_argument("--out", required=True,
                    help="path for the PRIVATE key file (mode 0600)")
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing key file (the old key"
                         " opens all wraps sealed to it; keep a copy)")
    args = ap.parse_args(rest)
    out = Path(args.out).expanduser()
    if out.exists() and not args.force:
        print(f"refusing to overwrite existing key file {out}"
              " (pass --force if you really mean it)", file=sys.stderr)
        return 2
    key = OversightKey.generate()
    key.save(out)
    print(key.public_key_b64)
    return 0


def _census(rest: list[str]) -> int:
    """Conversation census tooling (immortality gate, v1.3.2).

    Default: print the store's live census (counts + digest).
    --snapshot: record the durable baseline (the BEFORE of a guarded
    operation). --verify: compare the store against the baseline —
    any lost conversation/group/channel is reported, alerted on the
    store, and exits nonzero. Migration and cleanup tooling runs
    snapshot before and verify after; the relay ALSO verifies at
    every boot and the updater can guard itself with --census."""
    from .backend import create_store
    from .census import (CensusGuard, CensusLossError, census_summary,
                         compute_census)

    ap = argparse.ArgumentParser(prog="agentlink census")
    ap.add_argument("--db", default="~/.agentlink/relay.db")
    ap.add_argument("--backend", default=None,
                    help="sqlite|supabase (default: AGENTLINK_BACKEND "
                         "env or sqlite)")
    ap.add_argument("--baseline", default=None,
                    help="baseline path (default: beside --db)")
    ap.add_argument("--snapshot", action="store_true")
    ap.add_argument("--verify", action="store_true")
    args = ap.parse_args(rest)
    store = create_store(args.backend, db_path=args.db)
    baseline = args.baseline or str(
        Path(args.db).expanduser().parent / "census-baseline.json")
    guard = CensusGuard(store, baseline)
    if args.snapshot:
        census = guard.snapshot()
        _print({"snapshotted": baseline, **census_summary(census)})
        return 0
    if args.verify:
        try:
            result = guard.verify()
        except CensusLossError as exc:
            _print({"status": "LOSS", "detail": str(exc),
                    "diff": exc.diff})
            return 1
        _print(result)
        return 0
    census = compute_census(store)
    _print({"baseline": baseline,
            "baseline_exists": guard.load_baseline() is not None,
            **census_summary(census)})
    return 0


def _doctor(rest: list[str]) -> int:
    """Verification report: DB integrity + permissions, identity files,
    endpoint configuration. Read-only."""
    import sqlite3
    import stat as _stat
    from .config import DEFAULT_ENDPOINT, resolve_endpoint

    ap = argparse.ArgumentParser(prog="agentlink doctor")
    ap.add_argument("--db", default="~/.agentlink/relay.db")
    ap.add_argument("--state-dir", default=None)
    ap.add_argument("--for-install", action="store_true",
                    help="install-landing mode (v1.3.7): verify THIS"
                         " agent install — package importable with"
                         " a version, state dir writable, endpoint"
                         " configured, and registration state (an"
                         " identity present, or the exact next step"
                         " printed). Used by install.sh as its"
                         " final gate: exit 0 only when the install"
                         " genuinely landed")
    args = ap.parse_args(rest)
    if getattr(args, "for_install", False):
        return _doctor_for_install(args)
    state = Path(args.state_dir or DEFAULT_STATE_DIR).expanduser()
    report: dict = {"endpoint_default": DEFAULT_ENDPOINT,
                    "endpoint_resolved": resolve_endpoint(None),
                    "state_dir": str(state), "checks": []}

    def check(name, ok, detail=""):
        report["checks"].append({"name": name, "ok": bool(ok),
                                 "detail": detail})

    db = Path(args.db).expanduser()
    if db.exists():
        mode = _stat.S_IMODE(db.stat().st_mode)
        check("relay_db_permissions_0600", mode == 0o600, oct(mode))
        try:
            conn = sqlite3.connect(str(db))
            result = conn.execute("PRAGMA integrity_check").fetchone()[0]
            mode_j = conn.execute("PRAGMA journal_mode").fetchone()[0]
            audit_n = conn.execute(
                "SELECT COUNT(*) FROM audit_log").fetchone()[0]
            conn.close()
            check("relay_db_integrity", result == "ok", result)
            check("relay_db_wal", mode_j == "wal", mode_j)
            report["audit_log_entries"] = audit_n
        except Exception as exc:
            check("relay_db_integrity", False, str(exc))
    else:
        check("relay_db_exists", False, f"not found at {db} (relay not run yet)")
    if state.exists():
        for f in sorted(state.iterdir()):
            if f.name.startswith(("secret-", "keys-", "groupkeys-")):
                mode = _stat.S_IMODE(f.stat().st_mode)
                check(f"identity_file_{f.name}_0600", mode == 0o600, oct(mode))
    report["healthy"] = all(c["ok"] for c in report["checks"])
    _print(report)
    return 0 if report["healthy"] else 1


def _doctor_for_install(args) -> int:
    """Install-landing verification (v1.3.7): the checks an AGENT
    install must pass before anyone may call it installed. A fresh
    install legitimately has no relay DB and no identity yet, so
    those are reported as state (with the exact next step), never
    as failures; what FAILS the gate is a broken package, an
    unwritable state dir, or a missing endpoint configuration."""
    from .config import DEFAULT_ENDPOINT, resolve_endpoint
    state = Path(_state_dir(args)).expanduser()
    report: dict = {"mode": "install-check", "checks": []}

    def check(name, ok, detail=""):
        report["checks"].append({"name": name, "ok": bool(ok),
                                 "detail": detail})

    try:
        import agentlink
        from agentlink.client import Agent as _A  # noqa: F401
        check("package_importable", True,
              f"agentlink {agentlink.__version__}")
        report["version"] = agentlink.__version__
    except Exception as exc:
        check("package_importable", False, str(exc))
    try:
        state.mkdir(parents=True, exist_ok=True)
        probe = state / ".doctor-probe"
        probe.write_text("ok")
        probe.unlink()
        check("state_dir_writable", True, str(state))
    except Exception as exc:
        check("state_dir_writable", False, f"{state}: {exc}")
    try:
        resolved = resolve_endpoint(getattr(args, "endpoint", None))
        check("endpoint_configured", bool(resolved), resolved)
        report["endpoint"] = resolved
        report["default_endpoint"] = DEFAULT_ENDPOINT
    except Exception as exc:
        check("endpoint_configured", False, str(exc))
    # Registration state: an identity is present when a secret or
    # keys file exists for some username in the state dir (or the
    # current.json pointer names one). Absent is a NEXT STEP, not
    # a failure — the install landed; registration is the user's
    # first act on it.
    identity = None
    cur = state / "current.json"
    if cur.exists():
        try:
            identity = json.loads(cur.read_text()).get("username")
        except Exception:
            identity = None
    if not identity and state.exists():
        for f in sorted(state.iterdir()):
            if f.name.startswith("secret-") and \
                    f.name.endswith(".json"):
                identity = f.name[len("secret-"):-len(".json")]
                break
    if identity:
        report["registration"] = {"state": "registered",
                                  "username": identity}
    else:
        report["registration"] = {
            "state": "not_registered",
            "next_step": "agentlink register --username @your-name"
                         f"   (endpoint: {report.get('endpoint')})"}
    report["healthy"] = all(c["ok"] for c in report["checks"])
    _print(report)
    return 0 if report["healthy"] else 1


def _service(rest: list[str]) -> int:
    """Life mode: install the agent as a system service.

    Deliberately install/status ONLY — there is no uninstall path in the
    agent-facing CLI. Removing the service is an operator action done
    outside AgentLink (systemctl disable + unit removal by the operator).
    """
    sub = rest[0] if rest else ""
    if sub == "install":
        ap = argparse.ArgumentParser(prog="agentlink service install")
        ap.add_argument("--username", required=True)
        ap.add_argument("--user", action="store_true",
                        help="install as a systemd --user unit")
        args = ap.parse_args(rest[1:])
        unit = (
            "[Unit]\nDescription=AgentLink agent (life mode)\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=simple\n"
            f"ExecStart={sys.executable} -m agentlink agent"
            f" --username @{args.username.lstrip('@')}\n"
            "Restart=always\nRestartSec=1\n\n"
            "[Install]\nWantedBy="
            + ("default.target" if args.user else "multi-user.target") + "\n")
        if args.user:
            dest = Path("~/.config/systemd/user").expanduser() / \
                "agentlink-agent.service"
        else:
            dest = Path("/etc/systemd/system/agentlink-agent.service")
        result: dict = {"unit": unit}
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(unit)
            result["installed"] = str(dest)
            result["next"] = ("systemctl " + ("--user " if args.user else "")
                              + "enable --now agentlink-agent")
        except OSError as exc:
            result["installed"] = None
            result["error"] = str(exc)
            result["next"] = ("save the unit to your systemd directory"
                              " (needs operator privileges) and enable it")
        # Cron safety net, installed idempotently where a crontab
        # binary exists: the per-minute hang watchdog. The */15
        # update entry is a LEGACY belt-and-braces duplicate — since
        # v1.1.8 the agent checks for updates inside its own daemon
        # (see Agent._update_check_loop), so self-update NEVER
        # depends on this file. Marker-delimited, safe to re-run.
        result["self_update"] = (
            "in-daemon: the agent checks for updates itself every"
            " 15 minutes inside `agentlink agent` — no host cron,"
            " systemd timer or supervisor required")
        try:
            import shutil
            import subprocess as _sp
            home = Path("~/.agentlink").expanduser()
            home.mkdir(parents=True, exist_ok=True)
            (home / "watchdog.sh").write_text(
                "#!/bin/sh\n"
                "# AgentLink watchdog: HANG = DEATH (point 39d). A stale\n"
                "# heartbeat stamp (>20s) means the loop is frozen; the\n"
                "# process is killed and restarted exactly like a crash.\n"
                "STAMP=$(ls ~/.agentlink/heartbeat-*.txt 2>/dev/null"
                " | head -1)\n"
                "if [ -n \"$STAMP\" ]; then\n"
                "  NOW=$(date +%s); TS=$(cat \"$STAMP\" 2>/dev/null"
                " || echo 0)\n"
                "  if [ $((NOW - TS)) -gt 20 ]; then\n"
                "    systemctl --user restart agentlink-agent 2>/dev/null"
                " || systemctl restart agentlink-agent 2>/dev/null"
                " || true\n"
                "    exit 0\n"
                "  fi\n"
                "fi\n"
                "systemctl --user is-active --quiet agentlink-agent"
                " 2>/dev/null || systemctl --user restart agentlink-agent"
                " 2>/dev/null || systemctl restart agentlink-agent"
                " 2>/dev/null || true\n")
            try:
                (home / "watchdog.sh").chmod(0o755)
            except OSError:
                pass
            if shutil.which("crontab"):
                cur = _sp.run(["crontab", "-l"], capture_output=True,
                              text=True).stdout
                if "# agentlink-watchdog-begin" not in cur:
                    block = (
                        "# agentlink-watchdog-begin\n"
                        "* * * * * /bin/sh ~/.agentlink/watchdog.sh"
                        " >/dev/null 2>&1\n"
                        "# agentlink-watchdog-end\n"
                        "# agentlink-update-begin\n"
                        "*/15 * * * * agentlink update >/dev/null 2>&1\n"
                        "# agentlink-update-end\n")
                    proc = _sp.run(["crontab", "-"], input=cur + block,
                                   capture_output=True, text=True)
                    result["cron"] = "installed" if proc.returncode == 0 \
                        else "failed"
                else:
                    result["cron"] = "already installed"
            else:
                result["cron"] = (
                    "no crontab binary on this host — the cron"
                    " safety net was skipped, and the ONLY thing lost"
                    " is the per-minute hang watchdog (it inherently"
                    " needs an external ticker: cron or a supervisor"
                    " of your own). Self-update is NOT affected: it"
                    " runs in-daemon (see self_update)")
                print("NOTE: no crontab binary on this host — the"
                      " cron safety net (per-minute hang watchdog)"
                      " was skipped. Self-update does not depend on"
                      " it: the agent daemon checks for updates"
                      " itself every 15 minutes.", flush=True)
        except Exception as exc:
            result["cron"] = f"skipped: {exc}"
        _print(result)
        return 0
    if sub == "status":
        _print({"life_mode": "identity, keys and state live in ~/.agentlink"
                             " (outside the code directory); the daemon"
                             " re-registers, re-joins groups and drains"
                             " queued work on every restart",
                "uninstall": "no agent-facing uninstall exists by design;"
                             " removal is an operator-only action"})
        return 0
    print("usage: agentlink service <install|status>", file=sys.stderr)
    return 2


def _group(rest: list[str]) -> int:
    if not rest:
        print("usage: agentlink group <create|add|remove|members|promote|"
              "demote|settings|nickname|custom-role|join-link|join>",
              file=sys.stderr)
        return 2
    sub, r = rest[0], rest[1:]
    ap = argparse.ArgumentParser(prog=f"agentlink group {sub}")
    _add_common(ap)
    if sub == "create":
        ap.add_argument("name")
        ap.add_argument("members", nargs="*")
        args = ap.parse_args(r)
        fn = lambda a: a.group_create(args.name, args.members)  # noqa: E731
    elif sub == "add":
        ap.add_argument("group_id")
        ap.add_argument("members", nargs="+")
        args = ap.parse_args(r)
        fn = lambda a: a.group_add(args.group_id, args.members)  # noqa: E731
    elif sub == "remove":
        ap.add_argument("group_id")
        ap.add_argument("target")
        args = ap.parse_args(r)
        fn = lambda a: a.group_remove(args.group_id, args.target)  # noqa: E731
    elif sub == "members":
        ap.add_argument("group_id")
        args = ap.parse_args(r)
        fn = lambda a: a.group_members(args.group_id)  # noqa: E731
    elif sub in ("promote", "demote"):
        ap.add_argument("group_id")
        ap.add_argument("target")
        args = ap.parse_args(r)
        fn = (lambda a: a.group_promote(args.group_id, args.target)) \
            if sub == "promote" else \
            (lambda a: a.group_demote(args.group_id, args.target))
    elif sub == "nickname":
        ap.add_argument("group_id")
        ap.add_argument("nickname")
        ap.add_argument("--for", default=None, dest="for_user",
                        help="username (admins only for other members)")
        args = ap.parse_args(r)
        fn = lambda a: a.group_set_nickname(  # noqa: E731
            args.group_id, args.nickname, username=args.for_user)
    elif sub == "custom-role":
        ap.add_argument("group_id")
        ap.add_argument("target")
        ap.add_argument("custom_role")
        args = ap.parse_args(r)
        fn = lambda a: a.group_set_custom_role(  # noqa: E731
            args.group_id, args.target, args.custom_role)
    elif sub == "settings":
        ap.add_argument("group_id")
        ap.add_argument("settings_json",
                        help='e.g. {"send_messages":"admins_only"}')
        args = ap.parse_args(r)
        settings = json.loads(args.settings_json)
        fn = lambda a: a.group_settings(args.group_id, settings)  # noqa: E731
    elif sub == "join-link":
        ap.add_argument("group_id")
        args = ap.parse_args(r)
        fn = lambda a: a.group_join_link(args.group_id)  # noqa: E731
    elif sub == "join":
        ap.add_argument("link")
        args = ap.parse_args(r)
        fn = lambda a: a.group_join(args.link)  # noqa: E731
    else:
        print(f"unknown group command {sub!r}", file=sys.stderr)
        return 2
    _print(asyncio.run(_with_agent(args, fn)))
    return 0


def _assign(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="agentlink assign")
    _add_common(ap)
    ap.add_argument("--group", default=None, dest="group_id")
    ap.add_argument("--attach", action="append", default=[], dest="attachments")
    ap.add_argument("--deadline", default=None,
                    help="Pacific Time, e.g. '2026-11-05 17:00' (point 36)")
    ap.add_argument("--priority", default="normal",
                    choices=["normal", "high", "urgent"])
    ap.add_argument("--role", default=None,
                    help="assign to every holder of this group role")
    ap.add_argument("--require-approval", action="store_true",
                    help="approval gate: a proven delivery parks in"
                         " awaiting_approval until you approve/reject")
    ap.add_argument("assignees", help="comma-separated usernames")
    ap.add_argument("title")
    ap.add_argument("instructions", nargs="?", default="")
    args = ap.parse_args(rest)
    assignees = [s.strip() for s in args.assignees.split(",") if s.strip()]

    async def _go(a):
        if args.role:
            return await a.assign_work_role(
                args.group_id, args.role, args.title, args.instructions,
                attachments=args.attachments, deadline=args.deadline,
                priority=args.priority,
                require_approval=args.require_approval)
        return await a.assign_work(
            assignees, args.title, args.instructions,
            group_id=args.group_id, attachments=args.attachments,
            deadline=args.deadline, priority=args.priority,
            require_approval=args.require_approval)
    _print(asyncio.run(_with_agent(args, _go)))
    return 0


def _deliver(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="agentlink deliver")
    _add_common(ap)
    ap.add_argument("--file", action="append", default=[], dest="files")
    ap.add_argument("work_id")
    ap.add_argument("body", nargs="?", default="")
    args = ap.parse_args(rest)
    _print(asyncio.run(_with_agent(
        args, lambda a: a.deliver_work(args.work_id, args.body, args.files))))
    return 0


def _work(rest: list[str]) -> int:
    sub = rest[0] if rest else "inbox"
    r = rest[1:] if rest else []
    if sub in ("inbox", "list"):
        ap = argparse.ArgumentParser(prog="agentlink work inbox")
        _add_common(ap)
        ap.add_argument("--status", default=None)
        ap.add_argument("--group", default=None, dest="group_id")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.work_inbox(args.status, args.group_id))))
        return 0
    if sub == "progress":
        ap = argparse.ArgumentParser(prog="agentlink work progress")
        _add_common(ap)
        ap.add_argument("work_id")
        ap.add_argument("percent", type=int)
        ap.add_argument("note", nargs="?", default="")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.report_progress(args.work_id, args.percent,
                                              args.note))))
        return 0
    if sub in ("complete", "request-changes", "approve", "reject"):
        ap = argparse.ArgumentParser(prog=f"agentlink work {sub}")
        _add_common(ap)
        ap.add_argument("work_id")
        ap.add_argument("note", nargs="?", default="")
        args = ap.parse_args(r)
        fn = {"complete": lambda a: a.complete_work(args.work_id,
                                                   args.note),
              "request-changes": lambda a: a.request_changes(
                  args.work_id, args.note),
              "approve": lambda a: a.approve_work(args.work_id,
                                                  args.note),
              "reject": lambda a: a.reject_work(args.work_id,
                                                args.note)}[sub]
        _print(asyncio.run(_with_agent(args, fn)))
        return 0
    print(f"unknown work command {sub!r}", file=sys.stderr)
    return 2


def _channel(rest: list[str]) -> int:
    sub = rest[0] if rest else ""
    r = rest[1:] if rest else []
    ap = argparse.ArgumentParser(prog=f"agentlink channel {sub}")
    _add_common(ap)
    if sub == "create":
        ap.add_argument("name")
        ap.add_argument("members", nargs="?", default="")
        args = ap.parse_args(r)
        members = [s.strip() for s in args.members.split(",") if s.strip()]
        _print(asyncio.run(_with_agent(
            args, lambda a: a.channel_create(args.name, members))))
        return 0
    if sub in ("add", "members", "join-link", "post", "promote"):
        ap.add_argument("channel_id")
        if sub == "add":
            ap.add_argument("members")
        if sub in ("post",):
            ap.add_argument("body")
        if sub == "promote":
            ap.add_argument("target")
        args = ap.parse_args(r)
        if sub == "add":
            members = [s.strip() for s in args.members.split(",") if s.strip()]
            fn = lambda a: a.channel_add(args.channel_id, members)
        elif sub == "members":
            fn = lambda a: a.channel_members(args.channel_id)
        elif sub == "join-link":
            fn = lambda a: a.channel_join_link(args.channel_id)
        elif sub == "promote":
            fn = lambda a: a.channel_promote(args.channel_id, args.target)
        else:
            fn = lambda a: a.channel_send(args.channel_id, args.body)
        _print(asyncio.run(_with_agent(args, fn)))
        return 0
    if sub == "join":
        ap.add_argument("link")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.channel_join(args.link))))
        return 0
    print(f"unknown channel command {sub!r}", file=sys.stderr)
    return 2


def _chain(rest: list[str]) -> int:
    sub = rest[0] if rest else "list"
    r = rest[1:] if rest else []
    ap = argparse.ArgumentParser(prog=f"agentlink chain {sub}")
    _add_common(ap)
    if sub == "create":
        ap.add_argument("steps_json",
                        help="JSON list of step objects "
                             "({to|role|group_member, title, ...})")
        ap.add_argument("--group", default=None, dest="group_id")
        ap.add_argument("--name", default="")
        args = ap.parse_args(r)
        steps = json.loads(args.steps_json)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.create_chain(steps, group_id=args.group_id,
                                           name=args.name))))
        return 0
    if sub == "list":
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(args, lambda a: a.chain_list())))
        return 0
    if sub in ("get", "cancel"):
        ap.add_argument("chain_id")
        args = ap.parse_args(r)
        fn = (lambda a: a.chain_get(args.chain_id)) if sub == "get" else \
            (lambda a: a.chain_cancel(args.chain_id))
        _print(asyncio.run(_with_agent(args, fn)))
        return 0
    print(f"unknown chain command {sub!r}", file=sys.stderr)
    return 2


def _library(rest: list[str]) -> int:
    sub = rest[0] if rest else "search"
    r = rest[1:] if rest else []
    ap = argparse.ArgumentParser(prog=f"agentlink library {sub}")
    _add_common(ap)
    if sub == "search":
        ap.add_argument("q", nargs="?", default="")
        ap.add_argument("--sender", default="")
        ap.add_argument("--group", default="", dest="group_id")
        ap.add_argument("--hash", default="", dest="hash_prefix")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.library_search(
                args.q, sender=args.sender, group_id=args.group_id,
                hash_prefix=args.hash_prefix))))
        return 0
    if sub == "fetch":
        ap.add_argument("library_id")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.library_fetch(args.library_id))))
        return 0
    print(f"unknown library command {sub!r}", file=sys.stderr)
    return 2


def _vault(rest: list[str]) -> int:
    sub = rest[0] if rest else "list"
    r = rest[1:] if rest else []
    ap = argparse.ArgumentParser(prog=f"agentlink vault {sub}")
    _add_common(ap)
    if sub == "put":
        ap.add_argument("group_id")
        ap.add_argument("path")
        ap.add_argument("--pin", action="store_true")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.vault_put(args.group_id, args.path,
                                        pinned=args.pin))))
        return 0
    if sub == "list":
        ap.add_argument("group_id")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.vault_list(args.group_id))))
        return 0
    if sub in ("pin", "remove"):
        ap.add_argument("vault_id")
        args = ap.parse_args(r)
        fn = (lambda a: a.vault_pin(args.vault_id)) if sub == "pin" else \
            (lambda a: a.vault_remove(args.vault_id))
        _print(asyncio.run(_with_agent(args, fn)))
        return 0
    print(f"unknown vault command {sub!r}", file=sys.stderr)
    return 2


def _alerts(rest: list[str]) -> int:
    """Operator alert view (point 37): backend alert table + the local
    spool (update rollbacks, backup failures). Works with zero
    dispatch channels configured."""
    sub = rest[0] if rest else "list"
    r = rest[1:] if rest else []
    if sub != "list":
        print(f"unknown alerts command {sub!r}", file=sys.stderr)
        return 2
    ap = argparse.ArgumentParser(prog="agentlink alerts list")
    ap.add_argument("--db", default="~/.agentlink/relay.db")
    ap.add_argument("--state-dir", default=None)
    ap.add_argument("--status", default=None)
    args = ap.parse_args(r)
    out: list = []
    db = Path(args.db).expanduser()
    if db.exists():
        import sqlite3
        conn = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            q = "SELECT * FROM alerts"
            if args.status:
                q += f" WHERE status = '{args.status}'"
            q += " ORDER BY created_at DESC LIMIT 200"
            out.extend(dict(row) for row in conn.execute(q))
        except Exception as exc:
            out.append({"error": f"alerts table: {exc}"})
        conn.close()
    from .alerts_local import read_local_alerts
    out.extend(read_local_alerts(_state_dir(args)))
    _print(out)
    return 0


def _capabilities(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="agentlink capabilities")
    _add_common(ap)
    ap.add_argument("caps", help="comma-separated capability tags")
    ap.add_argument("--description", default="")
    args = ap.parse_args(rest)
    caps = [s.strip() for s in args.caps.split(",") if s.strip()]
    _print(asyncio.run(_with_agent(
        args, lambda a: a.update_capabilities(caps, args.description))))
    return 0



if __name__ == "__main__":
    raise SystemExit(main())
