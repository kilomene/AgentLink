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


async def _with_agent(args, fn, forward=None):
    from .client import InstanceCollision
    agent = Agent(_username(args), endpoint=_endpoint(args),
                  state_dir=_state_dir(args))
    try:
        await agent.start()
    except InstanceCollision as exc:
        # One-shot commands never fight a running daemon for its
        # own state (v1.3.7): the refusal IS the plain message —
        # no traceback, no SQLite fight, no rival registration.
        # Owner-seat control channel (v1.3.9): commands that carry
        # a forward spec (send, group add) are FORWARDED to the
        # running instance instead — it executes the command as
        # itself and returns the real result; the daemon is never
        # stopped for an operator action again. Forwarding fails
        # closed with the channel's named error.
        if forward is not None:
            from .client import forward_command, ControlForwardError
            try:
                # A forward spec may carry its own answer budget:
                # write commands keep the 20s fail-fast (a wedged
                # send must surface), read commands (2.0.10) get
                # longer — a history sync or a busy work inbox
                # over a degraded network legitimately takes
                # longer than 20s to answer, and timing it out
                # would report a healthy daemon as wedged. 2.2.0:
                # the read budget is 300s — one hardened network
                # call riding out a proxy stall window can take
                # ~160s by design (5 attempts x 30s stalls), so
                # the old 120s budget cried "wedged" at healthy
                # daemons in bad weather (phoenix's work inbox,
                # 2026-11-07, daemon heartbeating throughout).
                result = await forward_command(
                    _state_dir(args), _username(args), forward,
                    timeout=float(forward.get("timeout") or 20.0))
            except ControlForwardError as fexc:
                print(str(fexc), file=sys.stderr)
                raise SystemExit(1)
            return {"forwarded_via": "running instance",
                    "result": result}
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
        print("commands: relay server register reclaim agent whoami directory send send-file "
              "dial group channel chain assign deliver work library vault "
              "credentials alerts capabilities update doctor census service backup "
              "oversight-keygen deregister remove-user set-designation grant my-grant inbox sync delivery setup install operator support orders liveness nature dossier archive")
        return 0
    cmd, rest = argv[0], argv[1:]

    # Support hook fallback (2.1.0): on hosts where the hook got
    # no scheduler at all, every agentlink command gives due
    # hooks one poll — cheap, silent, and never fatal.
    if cmd != "support":
        try:
            from .support_hook import maybe_tick
            maybe_tick(os.environ.get("AGENTLINK_STATE_DIR")
                       or "~/.agentlink")
        except Exception:
            pass

    if cmd in ("relay", "server"):
        # 'server' is the v1.3.0 one-word form: standing up your
        # own server is ONE command — `agentlink server
        # --owner-agent <you> --name "<You> Server"
        # --public-endpoint wss://<host>/ws --host-agent <host>`.
        # Being carried needs no command at all: it is automatic.
        # The relay module is imported HERE, lazily (v2.0.11): the
        # serverless distribution no longer ships agentlink/relay.py
        # (the relay is retired; the platform is the server), and a
        # top-level import would break every command on every agent
        # install. On such an install this branch says so plainly.
        try:
            from . import relay as _relay
        except ImportError:
            print("the v1 relay is retired and is not part of the"
                  " serverless distribution — there is no server to"
                  " run; agents connect to the platform directly"
                  " (see `agentlink setup`).", file=sys.stderr)
            return 1
        _relay.main(rest)
        return 0

    if cmd == "deregister":
        return _deregister(rest)
    if cmd == "remove-user":
        return _remove_user(rest)
    if cmd == "set-designation":
        return _set_designation(rest)
    if cmd == "grant":
        return _grant(rest)
    if cmd == "my-grant":
        return _my_grant(rest)

    if cmd == "register":
        ap = argparse.ArgumentParser(prog="agentlink register")
        _add_common(ap)
        ap.add_argument("--display-name", default=None)
        ap.add_argument("--provisioning-grant", default=None,
                        help="the one-time provisioning grant the"
                             " operator issued for this username"
                             " (2.6.0): required for a BRAND-NEW"
                             " username (default:"
                             " AGENTLINK_PROVISIONING_GRANT or the"
                             " workspace drop-in file)")
        ap.add_argument("--designation", default="production",
                        choices=["production", "test"],
                        help="registration designation (v1.6.0): "
                             "PASS --designation test for every "
                             "probe/test/scratch registration — the "
                             "identity then files under the "
                             "dashboard's Probe Tests view, apart "
                             "from the production line. Default "
                             "production. Never inferred from the "
                             "username; after registration only the "
                             "operator path (`agentlink "
                             "set-designation`) changes it")
        args = ap.parse_args(rest)
        if not getattr(args, "username", None):
            raise SystemExit("register needs --username @name")

        async def _go():
            a = Agent(args.username, display_name=args.display_name,
                      endpoint=_endpoint(args), state_dir=_state_dir(args),
                      designation=args.designation,
                      provisioning_grant=args.provisioning_grant)
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

    if cmd == "reclaim":
        # Recovery login (v1.7.0): LOG BACK IN to an existing
        # account with its recovery key — never re-register. The
        # key comes from --recovery-key when given, else from the
        # stored copies the storage contract guarantees (the
        # workspace file first, then the state dir). On success
        # the account is rebound to this machine's identity, the
        # account secret rotates, the used key burns and its
        # successor is written to both storage copies; everything
        # on the account — conversations, groups, vault, unread
        # queue — is restored untouched, because it all lives
        # server-side under the username.
        ap = argparse.ArgumentParser(prog="agentlink reclaim")
        _add_common(ap)
        ap.add_argument("--recovery-key", default=None,
                        help="the recovery key (default: read the "
                             "stored copies)")
        ap.add_argument("--workspace", default=None,
                        help="the agent workspace holding the "
                             "recovery file (default: "
                             "AGENTLINK_WORKSPACE or ~/workspace)")
        args = ap.parse_args(rest)
        if not getattr(args, "username", None):
            raise SystemExit("reclaim needs --username @name")

        async def _go_reclaim():
            a = Agent(args.username, endpoint=_endpoint(args),
                      state_dir=_state_dir(args),
                      workspace=args.workspace,
                      recovery_key=args.recovery_key)
            await a.start()
            info = a.whoami()
            await a.close()
            return info
        try:
            info = asyncio.run(_go_reclaim())
            _print({
                "reclaimed": True,
                "username": info["username"],
                "endpoint": info["endpoint"],
                "recovery_file": info.get("recovery_file"),
                "note": "logged back in by recovery key; the used "
                        "key is burned — the NEW recovery key is "
                        "saved in the workspace file above and in "
                        "the client state dir. Record it in your "
                        "own long-term memory too."})
        except Exception as exc:
            from .client import RegistrationFailed
            report = {
                "reclaimed": False,
                "username": args.username,
                "endpoint": _endpoint(args),
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
            if isinstance(exc, RegistrationFailed):
                report["line_said"] = str(exc)
            _print(report)
            print(f"reclaim FAILED for {args.username} via"
                  f" {_endpoint(args)}: {exc}", file=sys.stderr)
            return 1
        return 0

    if cmd == "rectify":
        # Operator rectification (v2.0.9): bring a STRANDED
        # legacy account back — registered to keys this machine
        # does not hold, recovery file lost — with the one-time
        # code the operator issued for the username. The code
        # comes from --rectify-code when given, else the
        # AGENTLINK_RECTIFY_CODE env var, else the drop-in file
        # in the workspace. On success the account is rebound to
        # this machine's identity, the code burns, and a NEW
        # recovery key is issued and saved under the storage
        # contract; everything on the account — conversations,
        # groups, vault, unread queue — is restored untouched,
        # because it all lives server-side under the username.
        #
        # Truthful reporting (2.2.2): "rectified" is printed
        # ONLY when the Edge accepted the code in THIS run
        # (session_ceremony == "rectified"). A session that
        # opens any other way is reported as exactly what it
        # was — the 2.2.1-era report claimed a burn + rebind +
        # new recovery key for a plain key login that never
        # presented the code (the @lean false success).
        # Exit codes: 0 — rectified in this run; 2 — the
        # session opened but NOT by rectification (already
        # fine: the code was unused, or its outcome is
        # unconfirmed — the report's "outcome" says which);
        # 1 — failure, no session.
        ap = argparse.ArgumentParser(prog="agentlink rectify")
        _add_common(ap)
        ap.add_argument("--rectify-code", default=None,
                        help="the operator-issued one-time code "
                             "(default: AGENTLINK_RECTIFY_CODE or "
                             "the workspace drop-in file)")
        ap.add_argument("--workspace", default=None,
                        help="the agent workspace (default: "
                             "AGENTLINK_WORKSPACE or ~/workspace)")
        args = ap.parse_args(rest)
        if not getattr(args, "username", None):
            raise SystemExit("rectify needs --username @name")

        async def _go_rectify():
            a = Agent(args.username, endpoint=_endpoint(args),
                      state_dir=_state_dir(args),
                      workspace=args.workspace,
                      rectify_code=args.rectify_code,
                      rectify_intent=True)
            await a.start()
            info = a.whoami()
            await a.close()
            return info
        try:
            info = asyncio.run(_go_rectify())
        except Exception as exc:
            from .client import RegistrationFailed
            report = {
                "rectified": False,
                "username": args.username,
                "endpoint": _endpoint(args),
                "error_type": type(exc).__name__,
                "error": str(exc),
            }
            if isinstance(exc, RegistrationFailed):
                report["line_said"] = str(exc)
            _print(report)
            print(f"rectify FAILED for {args.username} via"
                  f" {_endpoint(args)}: {exc}", file=sys.stderr)
            return 1
        ceremony = info.get("session_ceremony")
        if ceremony == "rectified":
            _print({
                "rectified": True,
                "username": info["username"],
                "endpoint": info["endpoint"],
                "session_ceremony": "rectified",
                "outcome": "rectified",
                "recovery_file": info.get("recovery_file"),
                "note": "logged back in by operator rectification "
                        "code; the code is burned — the NEW "
                        "recovery key is saved in the workspace "
                        "file above and in the client state dir. "
                        "Record it in your own long-term memory "
                        "too."})
            return 0
        # The session opened WITHOUT a rectification: report
        # exactly what happened — never as success, never as
        # failure (exit 2 distinguishes the state).
        if info.get("rectify_presented"):
            outcome = "rectify_unconfirmed"
            note = ("the rectification code WAS presented and "
                    "the Edge refused the ceremony call, but "
                    "this machine's keys opened the session "
                    "anyway — either a first attempt landed "
                    "(code burned, account rebound) with its "
                    "reply lost, or the code did not verify "
                    "while your keys already open the account. "
                    "The rectification is UNCONFIRMED and no "
                    "NEW recovery key was saved on this "
                    "machine in this run. If you need a fresh "
                    "recovery key, ask the operator to check "
                    "the code's state; if it burned, a new "
                    "code can mint one.")
        elif info.get("rectify_code_held"):
            outcome = "already_open_code_unused"
            note = ("logged in with this machine's existing "
                    "keys; the rectify code was NOT presented "
                    "and remains valid until its expiry; no "
                    "new recovery key was issued. The drop-in "
                    "code file (if any) is left in place.")
        else:
            outcome = "already_open_no_code"
            note = ("no rectification code was held (no "
                    "--rectify-code, AGENTLINK_RECTIFY_CODE "
                    "or workspace drop-in); logged in with "
                    "this machine's existing keys. Nothing "
                    "was rectified — if the account is "
                    "stranded on other keys, get a code from "
                    "the operator and run this command again.")
        _print({
            "rectified": False,
            "username": info["username"],
            "endpoint": info["endpoint"],
            "session_ceremony": ceremony,
            "session_opened_by": ceremony,
            "outcome": outcome,
            "recovery_file": info.get("recovery_file"),
            "note": note})
        return 2

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
        _print({"username": _username(args),
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
        ap.add_argument("--designation", default="production",
                        choices=["production", "test"],
                        help="registration designation (v1.6.0): use "
                             "'test' when this registration is a "
                             "probe/test identity — it files under "
                             "the dashboard's Probe Tests view, "
                             "apart from the production line. "
                             "Declared only at registration; after "
                             "that only the operator path "
                             "(`agentlink set-designation`) changes "
                             "it")
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
                      designation=args.designation,
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

            print("online as", a.username,
                  f"(mode: {a.mode}, designation: {a.designation})",
                  flush=True)
            await a.run()
        asyncio.run(_go())
        return 0

    if cmd == "inbox":
        return _inbox(rest)
    if cmd == "sync":
        return _sync(rest)
    if cmd == "delivery":
        return _delivery(rest)
    if cmd == "setup":
        return _setup(rest)
    if cmd == "install":
        return _install(rest)
    if cmd == "operator":
        return _operator(rest)
    if cmd == "support":
        return _support(rest)
    if cmd == "orders":
        return _orders(rest)
    if cmd == "liveness":
        return _liveness(rest)
    if cmd == "nature":
        return _nature(rest)
    if cmd == "dossier":
        return _dossier(rest)
    if cmd == "archive":
        return _archive(rest)

    if cmd == "directory":
        ap = argparse.ArgumentParser(prog="agentlink directory")
        _add_common(ap)
        ap.add_argument("query", nargs="?", default="")
        ap.add_argument("--capability", default="",
                        help="only agents declaring this capability")
        args = ap.parse_args(rest)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.directory(args.query, args.capability),
            forward={"cmd": "directory", "query": args.query,
                     "timeout": 300})))
        return 0

    if cmd == "send":
        ap = argparse.ArgumentParser(prog="agentlink send")
        _add_common(ap)
        ap.add_argument("to")
        ap.add_argument("body")
        ap.add_argument("--priority", default="normal",
                        choices=["normal", "high", "urgent"])
        ap.add_argument("--disappearing", action="store_true",
                        help="Disappearing Mode v2: 24h per-side "
                             "erase, fail-closed archive deposit")
        args = ap.parse_args(rest)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.send_message(
                args.to, args.body, priority=args.priority,
                disappearing=args.disappearing),
            forward={"cmd": "send", "to": args.to,
                     "body": args.body,
                     "priority": args.priority,
                     "disappearing": args.disappearing})))
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
    if cmd in ("credentials", "creds"):
        return _credentials(rest)
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


def _orders(rest: list[str]) -> int:
    """Standing Orders (2.4.3): the doctrine surface.

    `orders` / `orders status` — the orders state, verified on
    read: the state copy's hash is re-checked (and the copy
    restored, with the event recorded) on EVERY read, per the
    owner's hardening rule. One plain line leads: the orders
    version and the inscription state, so an operator — or the
    agent itself — sees at a glance whether the doctrine is in
    place.

    `orders ack --inscribed --self-check-scheduled` — the
    OPERATING AGENT's attestation that it has inscribed the
    orders into its OWN memory store and scheduled its OWN
    recurring self-check. The only path that sets `inscribed`:
    the platform records the agent's word; it never claims an
    inscription it cannot see. Both flags are required for the
    full attestation — inscription without the scheduled
    self-check is half the duty (Order O9).

    PLATFORM ACCEPTANCE IS NOT THE ACK'S BUSINESS (2.5.1): the
    daemon records acceptance of the installed orders version
    automatically at every start (`platform_accepted` in the
    state, by daemon-machinery) — no one is ever asked to accept
    the orders, and this ack attests only the agent's own
    inscription acts."""
    sub = rest[0] if rest else "status"
    if sub == "status":
        ap = argparse.ArgumentParser(prog="agentlink orders status")
        ap.add_argument("--state-dir", default=None)
        args = ap.parse_args(rest[1:])
        from .orders import orders_state
        st = orders_state(_state_dir(args))
        print(f"standing orders {st.get('orders_version') or '?'}: "
              f"{'installed' if st.get('installed') else 'NOT installed'}"
              f"; platform acceptance: "
              f"{'recorded (daemon-machinery, orders ' + str(st.get('accepted_orders_version')) + ')' if st.get('platform_accepted') else 'NOT recorded'}"
              f"; inscription: {st.get('inscription_state', '?')}"
              f"; self-check scheduled: "
              f"{bool(st.get('self_check_scheduled'))}"
              f"; tamper events: {st.get('tamper_events', 0)}")
        _print(st)
        return 0 if st.get("installed") else 1
    if sub == "ack":
        ap = argparse.ArgumentParser(prog="agentlink orders ack")
        ap.add_argument("--inscribed", action="store_true",
                        help="attest: the operating agent HAS "
                             "inscribed the standing orders into "
                             "its own memory / instruction store")
        ap.add_argument("--self-check-scheduled", action="store_true",
                        help="attest: the agent's recurring "
                             "self-check (Order O9) is scheduled "
                             "in its own scheduler")
        ap.add_argument("--state-dir", default=None)
        args = ap.parse_args(rest[1:])
        if not args.inscribed and not args.self_check_scheduled:
            print("nothing attested: pass --inscribed and/or "
                  "--self-check-scheduled — the ack records only "
                  "what the agent states it has done",
                  file=sys.stderr)
            return 2
        from .orders import ack_inscription
        st = ack_inscription(_state_dir(args),
                             inscribed=args.inscribed,
                             self_check_scheduled=args.self_check_scheduled)
        _print(st)
        return 0
    print("usage: agentlink orders {status|ack} ...", file=sys.stderr)
    return 2


def _liveness(rest: list[str]) -> int:
    """Life Signs (2.5.0): my grade and my proofs.

    `liveness` / `liveness status` — my persistence class,
    windows, server-computed grade and BOTH proof tiers, stated
    separately forever: a daemon receipt proves the DAEMON woke;
    only a runtime proof proves the runtime. `liveness prove` —
    the runtime's own countersignature (the waking duty, Orders
    O2): run by the agent's BRAIN on every waking, never by the
    daemon on its own. `liveness answer` — manually trigger the
    daemon's automatic challenge answer (drill/operator
    convenience; the machinery also runs on beats + reconnects).
    """
    sub = rest[0] if rest else "status"
    r = rest[1:] if rest else []
    if sub == "status":
        ap = argparse.ArgumentParser(prog="agentlink liveness status")
        _add_common(ap)
        args = ap.parse_args(r)
        out = asyncio.run(_with_agent(
            args, lambda a: a.liveness_status(),
            forward={"cmd": "liveness_status", "timeout": 300}))
        st = out.get("result") if isinstance(out, dict) \
            and "result" in out else out
        if isinstance(st, dict):
            grade = st.get("grade") or "unproven"
            print(f"life sign: {grade}"
                  f" (class: {st.get('persistence_class') or 'undeclared'},"
                  f" nature v{st.get('nature_version') or 0},"
                  f" judged by v{st.get('judged_nature_version') or 0})")
            print(f"  daemon-proven: {st.get('last_daemon_receipt_at') or 'never'}"
                  f" · runtime-proven: {st.get('last_runtime_proof_at') or 'never'}"
                  f"{' · DAEMON-ONLY (runtime proof stale)' if st.get('daemon_only') else ''}")
            if st.get("live_node_stale"):
                print(f"  live node STALE (as of {st.get('live_node_as_of')})"
                      " — showing the last known grade, not a current one")
            if st.get("dossier_status"):
                print(f"  dossier: {st['dossier_status']}"
                      f" (last deposited {st.get('dossier_deposited_at') or 'never'};"
                      " content lives only in the AgentLink System tree)")
        _print(out)
        return 0
    if sub == "prove":
        ap = argparse.ArgumentParser(prog="agentlink liveness prove")
        _add_common(ap)
        args = ap.parse_args(r)
        out = asyncio.run(_with_agent(
            args, lambda a: a.liveness_prove(),
            forward={"cmd": "liveness_prove", "timeout": 300}))
        _print(out)
        return 0
    if sub == "answer":
        ap = argparse.ArgumentParser(prog="agentlink liveness answer")
        _add_common(ap)
        args = ap.parse_args(r)

        async def _go(a):
            return await a.liveness_answer()
        out = asyncio.run(_with_agent(args, _go))
        _print(out)
        return 0
    print("usage: agentlink liveness {status|prove|answer} ...",
          file=sys.stderr)
    return 2


def _archive(rest: list[str]) -> int:
    """The owner archive's TWO COPIES (2.5.0): SEALED for proof,
    READABLE for the owner. `archive readable --conversation
    <id> [--agent <user>]` prints the readable transcript from
    the local archive staging tree (AGENTLINK_ARCHIVE_LOCAL_DIR)
    — the same rendering that lands beside the chain file in
    Drive. The operator backfill lives in the drill-evidence
    tooling (backfill_readable.py) on top of
    archive.backfill_entries_from_mailbox."""
    sub = rest[0] if rest else "readable"
    r = rest[1:] if rest else []
    if sub == "readable":
        ap = argparse.ArgumentParser(prog="agentlink archive readable")
        ap.add_argument("--conversation", required=True)
        ap.add_argument("--agent", default="")
        ap.add_argument("--state-dir", default="")
        args = ap.parse_args(r)
        import os as _os
        root = _os.environ.get("AGENTLINK_ARCHIVE_LOCAL_DIR")
        if not root:
            print("AGENTLINK_ARCHIVE_LOCAL_DIR is not set — the "
                  "readable transcript lives beside the chain "
                  "file in the archive tree (Drive in "
                  "production); this command reads the local "
                  "staging form.")
            return 2
        from . import archive as _ar
        backend = _ar.LocalArchiveBackend(root)
        agent = args.agent
        if not agent:
            # The conversation's first participant folder that
            # holds a readable copy.
            import pathlib as _pl
            for p in sorted(_pl.Path(root).glob("*")):
                if (p / args.conversation.replace("/", "_")
                        / "readable.md").exists():
                    agent = p.name
                    break
        if not agent:
            print(f"no readable copy of {args.conversation} in "
                  f"the local staging tree")
            return 1
        path = backend._readable_path(agent, args.conversation)
        if not path.exists():
            print(f"no readable copy at {path} (chain-only "
                  f"deposit — the depositor held no plaintext)")
            return 1
        print(path.read_text())
        return 0
    print("usage: agentlink archive readable --conversation <id>")
    return 2


def _dossier(rest: list[str]) -> int:
    """The Agent Dossier (2.5.0): my extensive record in the
    owner's Google Drive SYSTEM tree — ONLY there. Generation +
    deposit are automatic (setup, daemon start, nature change,
    7-day max-age); these commands are the runtime's window +
    hand on the two parts that are its own: its
    self-description and its declared location label.

    `dossier` / `dossier status` — my dossier flag + version +
    last deposit (content itself is never shown by any client
    surface; it is the owner's archive record).
    `dossier update` — run maintenance now (regenerate if
    stale, drain the deposit queue, report the flag).
    `dossier describe` — author my self-description + location
    label (the dossier's self-description section is
    compulsory; its words are the runtime's own).
    """
    sub = rest[0] if rest else "status"
    r = rest[1:] if rest else []
    if sub == "status":
        ap = argparse.ArgumentParser(prog="agentlink dossier status")
        _add_common(ap)
        args = ap.parse_args(r)
        out = asyncio.run(_with_agent(
            args, lambda a: a.dossier_maintain("status"),
            forward={"cmd": "dossier_maintain",
                     "reason": "status", "timeout": 300}))
        st = out.get("result") if isinstance(out, dict) \
            and "result" in out else out
        if isinstance(st, dict):
            print(f"dossier: {st.get('status')}"
                  f" · version {st.get('version') or 0}"
                  f" · last deposited "
                  f"{st.get('deposited_at') or 'never'}")
            print("  content lives only in the owner's Drive "
                  "system tree (AgentLink System/<agent>/"
                  "DOSSIER.*) — no platform surface carries it")
        _print(out)
        return 0
    if sub == "update":
        ap = argparse.ArgumentParser(prog="agentlink dossier update")
        _add_common(ap)
        args = ap.parse_args(r)
        out = asyncio.run(_with_agent(
            args, lambda a: a.dossier_maintain("manual"),
            forward={"cmd": "dossier_maintain",
                     "reason": "manual", "timeout": 300}))
        _print(out)
        return 0
    if sub == "describe":
        ap = argparse.ArgumentParser(
            prog="agentlink dossier describe")
        _add_common(ap)
        ap.add_argument("--text", default=None,
                        help="my self-description, in my own "
                             "words (how I work, what I am for)")
        ap.add_argument("--location-label", default=None,
                        help="where I run, as a label I or my "
                             "owner declare (never coordinates, "
                             "never IP-derived)")
        args = ap.parse_args(r)
        state_dir = Path(_state_dir(args)).expanduser()
        from . import dossier as _dm
        local = _dm.load_local(state_dir)
        if args.text is not None:
            local["self_description"] = args.text
            local["self_description_updated_at"] = int(time.time())
        if args.location_label is not None:
            local["location_label"] = args.location_label
        _dm.save_local(state_dir, local)
        print("dossier-local.json updated — the next dossier "
              "generation carries it (runs automatically; force "
              "it with `agentlink dossier update`)")
        return 0
    print("usage: agentlink dossier {status|update|describe} ...",
          file=sys.stderr)
    return 2


def _nature(rest: list[str]) -> int:
    """Nature Profile (2.5.0): my signed declaration of how I run.

    `nature` / `nature show` — the declared profile + its
    one-line summary. `nature propose` — sensible per-runtime
    defaults, proposed only: nothing is signed or sent.
    `nature declare` — sign + record a declaration: fields not
    given keep their current declared values (or the proposal,
    when nothing is declared yet). Declarations are versioned
    history; grading judges a silence by the nature in force
    when it began — a redeclaration never rewrites a past
    silence. (2.6.0 spec retirement: no machine snapshot rides
    a declaration any more — the platform takes less; nature
    only.)"""
    from .liveness import (nature_summary, propose_defaults,
                           validate_profile)
    sub = rest[0] if rest else "show"
    r = rest[1:] if rest else []
    if sub == "propose":
        ap = argparse.ArgumentParser(prog="agentlink nature propose")
        ap.add_argument("--state-dir", default=None)
        args = ap.parse_args(r)
        proposal = propose_defaults(_state_dir(args))
        print("proposed nature (NOT declared — review, edit, then"
              " `agentlink nature declare`):")
        _print(proposal)
        return 0
    if sub == "show":
        ap = argparse.ArgumentParser(prog="agentlink nature show")
        _add_common(ap)
        args = ap.parse_args(r)
        out = asyncio.run(_with_agent(
            args, lambda a: a.liveness_status(),
            forward={"cmd": "liveness_status", "timeout": 300}))
        st = out.get("result") if isinstance(out, dict) \
            and "result" in out else out
        profile = (st or {}).get("nature") if isinstance(st, dict) \
            else None
        print(f"declared: {nature_summary(profile)}"
              f" (nature v{(st or {}).get('nature_version') or 0},"
              f" declared at {(st or {}).get('nature_declared_at') or 'never'})")
        _print({"declared": profile})
        return 0
    if sub == "declare":
        ap = argparse.ArgumentParser(prog="agentlink nature declare")
        _add_common(ap)
        ap.add_argument("--runtime-kind", default=None,
                        choices=["persistent-daemon", "session-chat",
                                 "scheduled", "embedded", "other"])
        ap.add_argument("--host-class", default=None,
                        choices=["cloud-vm", "home-pc", "phone",
                                 "server", "other"])
        ap.add_argument("--class", default=None,
                        dest="persistence_class",
                        choices=["persistent", "session"])
        ap.add_argument("--suspect-after", type=int, default=None)
        ap.add_argument("--expected-gap", type=int, default=None)
        ap.add_argument("--dark-after", type=int, default=None)
        ap.add_argument("--supervision", default=None,
                        choices=["none", "service-manager",
                                 "watchdog", "owner-relaunch"])
        ap.add_argument("--wake", action="append", default=None,
                        dest="wake_paths",
                        choices=["boot-autostart", "owner-action",
                                 "inbound-task", "none"])
        ap.add_argument("--duty", default=None)
        ap.add_argument("--network-class", default=None,
                        choices=["datacenter", "residential",
                                 "mobile", ""])
        args = ap.parse_args(r)
        state_dir = _state_dir(args)
        # Step 1: the current declaration (via the daemon when
        # one runs, else a one-shot agent) — unspecified fields
        # keep their current declared values.
        cur_out = asyncio.run(_with_agent(
            args, lambda a: a.liveness_status(),
            forward={"cmd": "liveness_status", "timeout": 300}))
        cur_st = cur_out.get("result") if isinstance(cur_out, dict) \
            and "result" in cur_out else cur_out
        current = (cur_st or {}).get("nature") or {} \
            if isinstance(cur_st, dict) else {}
        # Step 2: merge + validate HERE, so the exact profile
        # being signed is printed before it is sent. Nature
        # fields only (2.6.0): a legacy on-record profile's
        # retired spec keys are dropped, never re-signed.
        base = dict(current) if current else propose_defaults(
            state_dir)
        merged = dict(base)
        merged.pop("machine", None)
        merged.pop("detection_gap", None)
        for key, val in (
                ("runtime_kind", args.runtime_kind),
                ("host_class", args.host_class),
                ("persistence_class", args.persistence_class),
                ("suspect_after_s", args.suspect_after),
                ("expected_gap_s", args.expected_gap),
                ("dark_after_s", args.dark_after),
                ("supervision", args.supervision),
                ("wake_paths", args.wake_paths),
                ("duty_pattern", args.duty),
                ("network_class", args.network_class)):
            if val is not None:
                merged[key] = val
        profile = validate_profile(merged)
        print("declaring nature (signed, versioned, history kept):")
        _print(profile)
        # Step 3: sign + record through the agent's own session.
        out = asyncio.run(_with_agent(
            args, lambda a: a.liveness_declare(profile),
            forward={"cmd": "liveness_declare",
                     "profile": profile, "timeout": 300}))
        _print(out)
        return 0
    print("usage: agentlink nature {show|propose|declare} ...",
          file=sys.stderr)
    return 2


def _setup(rest: list[str]) -> int:
    """Full self-setup (2.0.10, class H): network first, then
    register, supervision, probed capabilities, the one-time
    full admin grant asked of the agent's OWN owner agent-side,
    and self-verification — one plain report. The owner
    supplies only the username."""
    ap = argparse.ArgumentParser(prog="agentlink setup")
    ap.add_argument("username", nargs="?", default=None,
                    help="the username to register (prompted when"
                         " omitted — the only thing the owner"
                         " supplies)")
    ap.add_argument("--state-dir", default=None)
    ap.add_argument("--designation", default="production",
                    choices=["production", "test"])
    ap.add_argument("--grant", default="ask",
                    choices=["ask", "allow", "decline", "skip"],
                    help="ask: record the grant request and leave"
                         " it pending for the owner; allow/decline:"
                         " record the owner's decision now"
                         " (owner-present setups and drills)")
    ap.add_argument("--no-service", action="store_true",
                    help="skip the supervision install")
    ap.add_argument("--declare-nature", action="store_true",
                    help="accepted for compatibility (2.5.0):"
                         " nature declaration at setup is"
                         " AUTOMATIC and carries no opt-out — the"
                         " hardened reporting ruling; the report"
                         " shows the declaration either way")
    ap.add_argument("--provisioning-grant", default=None,
                    help="the one-time provisioning grant the"
                         " operator issued for this username"
                         " (2.6.0): required to register a"
                         " BRAND-NEW username; existing accounts"
                         " and reclaims never need it (default:"
                         " AGENTLINK_PROVISIONING_GRANT or the"
                         " workspace drop-in file)")
    args = ap.parse_args(rest)
    username = args.username
    if not username:
        username = input("Username for this agent: ").strip()
    from .setup import run_setup
    try:
        report = asyncio.run(run_setup(
            username, state_dir=args.state_dir,
            designation=args.designation, grant=args.grant,
            install_service=not args.no_service,
            declare_nature=args.declare_nature,
            provisioning_grant=args.provisioning_grant))
    except Exception as exc:
        support = getattr(exc, "support", None)
        check = getattr(exc, "check", None)
        if support is None and check is None:
            raise
        out = {"ok": False, "username": username,
               "error": str(exc)[:500]}
        if support is not None:
            out["support"] = support
        if check is not None:
            # The unproven-collision diagnosis (2.2.3): the
            # measured conjuncts ride the report so the caller
            # sees WHICH check failed — never a bare collision.
            out["already_running_check"] = check
        _print(out)
        return 1
    _print(report)
    return 0 if report.get("ok") else 1


def _install(rest: list[str]) -> int:
    """Attended install ceremony (2.6.0, SPEC Part 3):
    `agentlink install --username <u> --provisioning-grant
    <token> [--state-dir D]` runs the nine steps in order, each
    landing a signed step receipt in
    <state-dir>/ceremony-state.json. Exit 0 ONLY when all nine
    steps have landed. A failure halts with a named fault (no
    workaround is improvised); re-running the same command
    resumes at the first incomplete step — no step can be
    skipped. `--status` reads the per-username ceremony state
    (the operator's local view; halts and completions are also
    lodged on the support desk, kind 'ceremony')."""
    if "--status" in rest:
        ap = argparse.ArgumentParser(prog="agentlink install --status")
        _add_common(ap)
        ap.add_argument("--status", action="store_true")
        args = ap.parse_args(rest)
        username = _username(args)
        from .ceremony import load_state
        state = load_state(_state_dir(args))
        if state is None or state.get("username") != username:
            print(f"no ceremony state for @{username} in "
                  f"{_state_dir(args)} — no install ceremony has "
                  f"run (or completed a step) there yet")
            return 2
        landed = [r["step"] for r in state.get("receipts") or []
                  if r.get("ok")]
        print(f"ceremony for @{username}: "
              f"{'COMPLETE (all nine steps landed)' if state.get('complete') else 'not complete'}"
              f"; steps landed: {landed or 'none'}"
              + (f"; HALTED at step {state.get('failed_step')} "
                 f"with fault {state.get('fault')}"
                 if state.get("fault") else ""))
        _print(state)
        return 0 if state.get("complete") else 1
    ap = argparse.ArgumentParser(prog="agentlink install")
    _add_common(ap)
    ap.add_argument("--provisioning-grant", default=None,
                    help="the one-time provisioning grant the "
                         "operator issued for this username "
                         "(2.6.0): presented at registration "
                         "(step 4) only; default resolution is "
                         "the Agent's own: this flag, else "
                         "AGENTLINK_PROVISIONING_GRANT, else the "
                         "workspace drop-in file")
    ap.add_argument("--designation", default="production",
                    choices=["production", "test"],
                    help="registration designation (default "
                         "production; drills pass test)")
    args = ap.parse_args(rest)
    if not getattr(args, "username", None):
        raise SystemExit("install needs --username @name")
    from .ceremony import SUPPORT_POINTER, run_install
    try:
        state = run_install(
            args.username, _state_dir(args),
            provisioning_grant=args.provisioning_grant,
            designation=args.designation)
    except Exception as exc:
        print(f"install ceremony could not run for "
              f"{args.username}: {exc}", file=sys.stderr)
        print(SUPPORT_POINTER, file=sys.stderr)
        return 1
    landed = [r["step"] for r in state.get("receipts") or []
              if r.get("ok")]
    if state.get("complete"):
        print(f"install ceremony COMPLETE for @{args.username}: "
              f"all nine steps landed; receipts are in "
              f"{_state_dir(args)}/ceremony-state.json")
        _print({"username": args.username, "complete": True,
                "steps_landed": landed,
                "support": state.get("support")})
        return 0
    print(f"install ceremony HALTED for @{args.username} at step "
          f"{state.get('failed_step')} with fault "
          f"{state.get('fault')}: {state.get('fault_detail') or ''}",
          file=sys.stderr)
    print("re-running `agentlink install` with the same "
          "--username/--state-dir resumes at that step; no step "
          "can be skipped.", file=sys.stderr)
    print(SUPPORT_POINTER, file=sys.stderr)
    _print({"username": args.username, "complete": False,
            "steps_landed": landed,
            "failed_step": state.get("failed_step"),
            "fault": state.get("fault"),
            "support": state.get("support")})
    return 1


def _operator(rest: list[str]) -> int:
    """Operator commands (2.6.0): the operator's own acts,
    authenticated to the oversight Edge with the operator
    credential IT expects (AGENTLINK_OPERATOR_TOKEN — a
    dashboard session token or operator JWT; see
    agentlink/operator.py). Today: the provisioning-grant
    issue/revoke pair (SPEC Part 2)."""
    from .operator import OperatorError
    sub = rest[0] if rest else ""
    r = rest[1:] if rest else []
    if sub == "provisioning":
        action = r[0] if r else ""
        rr = r[1:] if r else []
        if action == "issue":
            ap = argparse.ArgumentParser(
                prog="agentlink operator provisioning issue")
            ap.add_argument("--username", required=True,
                            help="the NEW username the grant is "
                                 "bound to")
            ap.add_argument("--ttl-hours", type=int, default=None,
                            help="grant lifetime in hours "
                                 "(default: the server's 72)")
            args = ap.parse_args(rr)
            from .operator import provisioning_issue
            try:
                out = provisioning_issue(args.username,
                                         ttl_hours=args.ttl_hours)
            except OperatorError as exc:
                print(f"provisioning issue failed: {exc}",
                      file=sys.stderr)
                return 1
            token = str(out.get("provisioning_grant") or "")
            print(f"provisioning grant issued for "
                  f"@{out.get('username')} (grant id "
                  f"{out.get('grant_id')}, expires_at "
                  f"{out.get('expires_at')})")
            print("give this token to the agent ONCE — it is "
                  "shown only here; the server stores only its "
                  "hash, and it cannot be recovered:")
            print(token)
            print("the agent presents it with: agentlink "
                  "install --username "
                  f"{out.get('username')} --provisioning-grant "
                  "<token>  (or `agentlink setup "
                  "--provisioning-grant <token>`)")
            return 0
        if action == "revoke":
            ap = argparse.ArgumentParser(
                prog="agentlink operator provisioning revoke")
            ap.add_argument("--username", default=None,
                            help="revoke every unconsumed grant "
                                 "for this username")
            ap.add_argument("--grant-id", default=None,
                            help="revoke one grant by its id")
            args = ap.parse_args(rr)
            if not args.username and not args.grant_id:
                print("revoke needs --username or --grant-id",
                      file=sys.stderr)
                return 2
            from .operator import provisioning_revoke
            try:
                out = provisioning_revoke(
                    username=args.username,
                    grant_id=args.grant_id)
            except OperatorError as exc:
                print(f"provisioning revoke failed: {exc}",
                      file=sys.stderr)
                return 1
            _print(out)
            return 0
        print("usage: agentlink operator provisioning "
              "{issue|revoke} ...", file=sys.stderr)
        return 2
    print("usage: agentlink operator provisioning "
          "{issue|revoke} ...", file=sys.stderr)
    return 2


def _support(rest: list[str]) -> int:
    """Customer support for signup/login (2.1.0): lodge a
    complaint with NO account, check Phoenix's answer, and the
    hook machinery that registers a stranded agent on its own
    once the fix ships."""
    sub = rest[0] if rest else ""
    if sub == "lodge":
        ap = argparse.ArgumentParser(prog="agentlink support lodge")
        ap.add_argument("--username", required=True,
                        help="the username you want to register")
        ap.add_argument("--message", required=True,
                        help="the problem, in your own words")
        ap.add_argument("--attach", action="append", default=[],
                        help="a proof file (image, log, json, zip);"
                             " repeat for several")
        ap.add_argument("--state-dir", default=None)
        ap.add_argument("--designation", default="production",
                        choices=["production", "test"])
        ap.add_argument("--grant", default="ask",
                        choices=["ask", "allow", "decline", "skip"],
                        help="the grant decision the hook records"
                             " for its post-fix setup run")
        args = ap.parse_args(rest[1:])
        from .support import lodge
        sd = args.state_dir or "~/.agentlink"
        out = lodge(args.username, args.message, sd,
                    attachments=args.attach,
                    designation=args.designation,
                    hook_grant=args.grant)
        print(f"support ticket {out['ticket_id']} lodged for "
              f"@{out['username']}"
              + (" (that username is currently registered — "
                 "Phoenix will see it)" if out["name_taken"] else "")
              + f"; {(out.get('hook') or {}).get('supervision', 'no')}"
                " hook is watching it. Check the answer with: "
                "agentlink support status")
        _print(out)
        return 0
    if sub == "status":
        ap = argparse.ArgumentParser(prog="agentlink support status")
        ap.add_argument("--state-dir", default=None)
        args = ap.parse_args(rest[1:])
        from .support import my_tickets
        _print(my_tickets(args.state_dir or "~/.agentlink"))
        return 0
    if sub in ("hook-run", "hook-check"):
        ap = argparse.ArgumentParser(prog=f"agentlink support {sub}")
        ap.add_argument("--ticket", required=True)
        ap.add_argument("--state-dir", default=None)
        args = ap.parse_args(rest[1:])
        from pathlib import Path as _P
        from . import support_hook
        sd = _P(args.state_dir or "~/.agentlink").expanduser()
        if sub == "hook-run":
            return support_hook.run_loop(sd, args.ticket)
        _print({"ticket": args.ticket,
                "outcome": support_hook.run_cycle(sd, args.ticket)})
        return 0
    if sub == "hooks":
        ap = argparse.ArgumentParser(prog="agentlink support hooks")
        ap.add_argument("--state-dir", default=None)
        args = ap.parse_args(rest[1:])
        from pathlib import Path as _P
        from .support_hook import list_records
        sd = _P(args.state_dir or "~/.agentlink").expanduser()
        _print([{k: r.get(k) for k in
                 ("ticket_id", "username", "supervision",
                  "attempts", "created_at")}
                for r in list_records(sd)])
        return 0
    print("usage: agentlink support "
          "{lodge|status|hooks|hook-run|hook-check} ...")
    return 2


def _delivery(rest: list[str]) -> int:
    """Delivery confirmation (2.0.10, class D): where a message
    I sent stands, from the server's own record — accepted,
    still in a recipient's custody (queued), delivered, or read
    (with the reader list). Never a permanent "queued"."""
    ap = argparse.ArgumentParser(prog="agentlink delivery")
    _add_common(ap)
    ap.add_argument("message_id")
    args = ap.parse_args(rest)
    _print(asyncio.run(_with_agent(
        args, lambda a: a.delivery_status(args.message_id),
        forward={"cmd": "delivery_status",
                 "message_id": args.message_id, "timeout": 300})))
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
    _print(asyncio.run(_with_agent(args, _go,
                                   forward={"cmd": "sync_history", "timeout": 300})))
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


def _set_designation(rest: list[str]) -> int:
    """OPERATOR designation change (v1.6.0): the ONLY path by
    which a registered agent's production/test designation changes
    after registration. Executes immediately (it is fully
    reversible — the identity and every conversation stay exactly
    where they are; only dashboard composition moves) and the
    store records every executed change in the append-only audit
    log as kind 'designation_changed', actor 'operator'.

    Uses the relay's backend selection (AGENTLINK_BACKEND /
    --backend + --db), so it addresses the same store the relay
    serves — SQLite file or Supabase (production)."""
    from .backend import create_store
    from .protocol import normalize_username
    ap = argparse.ArgumentParser(prog="agentlink set-designation")
    ap.add_argument("username")
    ap.add_argument("--designation", required=True,
                    choices=["production", "test"],
                    help="the designation to set")
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
        rows = store.list_users(query=username)
        if not any(r["username"] == username for r in rows):
            print(f"no such registration: @{username}",
                  file=sys.stderr)
            return 2
        before = store.designation_of(username)
        changed = store.set_designation(username, args.designation,
                                        actor="operator")
        after = store.designation_of(username)
        _print({"username": username, "before": before,
                "designation": after, "changed": bool(changed),
                "audit": "designation_changed" if changed else
                         "unchanged — nothing recorded"})
        return 0
    finally:
        try:
            store.close()
        except Exception:
            pass


def _grant(rest: list[str]) -> int:
    """One-time admin grant (v1.8.1 — the owner's corrected
    model). The grant belongs to the AGENT and its owner, and so
    does this command — it runs in the AGENT'S OWN environment:

    * request — the agent ASKS its owner for the one-time
      permission (agent-initiated; creates the pending request).
    * allow — the owner's one-time ALLOW on that request
      (agent-side ceremony): signs the grant statement with the
      agent's identity key and presents it over the agent's own
      connection; the relay records grantor + ceremony.
    * revoke — the owner's kill switch, agent-side, signed.
    * decide — the agent owner's red-line decision on one of the
      agent's OWN queued approvals (signed); approval executes
      the stored action through the agent's host bridge.

    The platform operator CANNOT issue, approve or revoke a
    grant — there is no such subcommand, by design (the v1.8.0
    operator paths were removed on the owner's correction).
    What remains store-direct here is READ-ONLY inspection —
    show / activity / approvals / connectors — the same facts
    the oversight dashboard displays."""
    from .backend import create_store
    from .grants import activity_report, render_activity_markdown
    from .protocol import normalize_username
    sub = rest[0] if rest else "show"
    r = rest[1:] if rest else []

    def _store(args):
        return create_store(args.backend, db_path=args.db)

    def _backend_args(ap):
        ap.add_argument("--backend", default=None,
                        help="sqlite (default) | supabase")
        ap.add_argument("--db", default="~/.agentlink/relay.db")

    # -- the agent-side ceremony (over the agent's own wire) ----
    if sub == "request":
        ap = argparse.ArgumentParser(prog="agentlink grant request")
        ap.add_argument("--reason", default="",
                        help="why the agent is asking (recorded)")
        _add_common(ap)
        args = ap.parse_args(r)
        out = asyncio.run(_with_agent(
            args, lambda a: a.request_permission(args.reason)))
        _print({"username": _username(args), "request": out})
        return 0
    if sub == "allow":
        ap = argparse.ArgumentParser(prog="agentlink grant allow")
        ap.add_argument("--by", default="agent-owner",
                        help="grantor attestation: WHO allows "
                             "this — the agent's owner (recorded "
                             "on the grant)")
        _add_common(ap)
        args = ap.parse_args(r)
        out = asyncio.run(_with_agent(
            args, lambda a: a.allow_permission(args.by)))
        _print({"username": _username(args), "allow": out})
        return 0 if (isinstance(out, dict)
                     and out.get("grant")) else 2
    if sub == "revoke":
        ap = argparse.ArgumentParser(
            prog="agentlink grant revoke")
        _add_common(ap)
        args = ap.parse_args(r)
        out = asyncio.run(_with_agent(
            args, lambda a: a.revoke_permission()))
        _print({"username": _username(args), "revoke": out})
        return 0
    if sub == "decide":
        ap = argparse.ArgumentParser(
            prog="agentlink grant decide")
        ap.add_argument("approval_id")
        ap.add_argument("--approve", action="store_true",
                        help="approve (the action then executes "
                             "through the agent's bridge)")
        ap.add_argument("--reject", action="store_true",
                        help="reject (the action never executes)")
        ap.add_argument("--by", default="agent-owner",
                        help="the deciding owner (recorded)")
        _add_common(ap)
        args = ap.parse_args(r)
        if bool(args.approve) == bool(args.reject):
            print("decide needs exactly one of --approve / "
                  "--reject", file=sys.stderr)
            return 2
        out = asyncio.run(_with_agent(
            args, lambda a: a.decide_approval(
                args.approval_id, args.approve, args.by)))
        _print({"username": _username(args), "decision": out})
        return 0

    # -- read-only inspection (store-direct, changes nothing) ---
    if sub == "show":
        ap = argparse.ArgumentParser(prog="agentlink grant show")
        ap.add_argument("username")
        _backend_args(ap)
        args = ap.parse_args(r)
        username = normalize_username(args.username)
        if username is None:
            print(f"bad username {args.username!r}", file=sys.stderr)
            return 2
        from .connectors import derived_capabilities
        store = _store(args)
        try:
            inventory = store.connector_inventory_of(username)
            _print({"username": username,
                    "grant": store.grant_of(username),
                    "connectors": inventory,
                    "derived_capabilities":
                        derived_capabilities(inventory)})
            return 0
        finally:
            store.close()
    if sub == "activity":
        ap = argparse.ArgumentParser(
            prog="agentlink grant activity")
        ap.add_argument("username")
        ap.add_argument("--hours", type=float, default=24.0,
                        help="window ending now (default 24h)")
        ap.add_argument("--since", type=int, default=None,
                        help="window start, epoch seconds (overrides "
                             "--hours)")
        ap.add_argument("--until", type=int, default=None)
        ap.add_argument("--format", choices=["md", "json"],
                        default="md",
                        help="md = the owner's activity document")
        _backend_args(ap)
        args = ap.parse_args(r)
        username = normalize_username(args.username)
        if username is None:
            print(f"bad username {args.username!r}", file=sys.stderr)
            return 2
        import time as _time
        since = args.since if args.since is not None else int(
            _time.time() - args.hours * 3600)
        store = _store(args)
        try:
            report = activity_report(store, username, since,
                                     args.until)
            if args.format == "json":
                _print(report)
            else:
                print(render_activity_markdown(report))
            return 0
        finally:
            store.close()
    if sub == "approvals":
        ap = argparse.ArgumentParser(
            prog="agentlink grant approvals")
        ap.add_argument("--status", default="awaiting_approval")
        ap.add_argument("--username", default=None)
        _backend_args(ap)
        args = ap.parse_args(r)
        store = _store(args)
        try:
            _print({"approvals": store.list_approvals(
                status=args.status or None,
                username=args.username),
                "note": "read-only: red-line approvals are "
                        "decided by each agent's OWN owner, "
                        "agent-side (`agentlink grant decide` "
                        "in that agent's environment)"})
            return 0
        finally:
            store.close()
    if sub == "connectors":
        ap = argparse.ArgumentParser(
            prog="agentlink grant connectors")
        ap.add_argument("username", nargs="?", default=None,
                        help="one agent (default: the whole "
                             "fleet's declared vaults)")
        _backend_args(ap)
        args = ap.parse_args(r)
        store = _store(args)
        try:
            if args.username:
                username = normalize_username(args.username)
                if username is None:
                    print(f"bad username {args.username!r}",
                          file=sys.stderr)
                    return 2
                _print({"username": username,
                        "connectors":
                            store.connector_inventory_of(username)})
            else:
                _print({"connectors":
                            store.all_connector_inventories()})
            return 0
        finally:
            store.close()
    print(f"unknown grant subcommand {sub!r}: request allow "
          "revoke decide show activity approvals connectors — "
          "note: grants are requested by the agent and allowed "
          "by the agent's OWN owner, agent-side; the platform "
          "operator cannot issue one", file=sys.stderr)
    return 2


def _my_grant(rest: list[str]) -> int:
    """'Show my grant' (v1.8.1): the AGENT-side surface — the
    agent states its exact grant state, its grantor attestation
    and its declared connector vault, read live from the relay
    (never a stale cache)."""
    ap = argparse.ArgumentParser(prog="agentlink my-grant")
    _add_common(ap)
    args = ap.parse_args(rest)
    _print({"username": _username(args),
            "state": asyncio.run(_with_agent(
                args, lambda a: a.my_connectors()))})
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
    # Standing Orders (2.4.3): placement state rides the doctor
    # report — verified on this read like every orders read.
    try:
        from .orders import orders_state as _ostate
        report["orders"] = _ostate(state)
    except Exception as exc:
        report["orders"] = {"installed": False,
                            "error": str(exc)[:200]}
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
        ap.add_argument("--state-dir", default=None,
                        help="the agent's state dir, baked into the"
                             " unit so the supervised daemon runs"
                             " the SAME identity the setup flow"
                             " registered (2.0.10)")
        args = ap.parse_args(rest[1:])
        uname = args.username.lstrip('@')
        exec_start = (f"{sys.executable} -m agentlink agent"
                      f" --username @{uname}")
        if args.state_dir:
            exec_start += f" --state-dir {args.state_dir}"
        unit = (
            "[Unit]\nDescription=AgentLink agent (life mode)\n"
            "After=network-online.target\nWants=network-online.target\n\n"
            "[Service]\nType=simple\n"
            f"ExecStart={exec_start}\n"
            "Restart=always\nRestartSec=1\n"
            # Frozen-but-alive coverage (2.2.0): Restart=always
            # only sees a DEAD process. The daemon pats systemd's
            # watchdog from the same 5s stamp loop that writes
            # its heartbeat stamp (client._sd_notify_watchdog);
            # a frozen loop stops patting, and systemd restarts
            # the unit — a hang is handled exactly like a crash.
            "WatchdogSec=30\nNotifyAccess=main\n\n"
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
        # Activation (2.0.10, class C): installing the unit file
        # is not supervision. ACTUALLY enable + start it and
        # report what systemd said; where systemd cannot run it
        # (no systemctl, no bus, a sandbox), fall back to a
        # cron-driven supervisor loop and say so plainly — the
        # agent ends up supervised either way, and the report
        # names which.
        result["supervision"] = None
        if result.get("installed"):
            import shutil as _shutil
            import subprocess as _sp2
            scope = ["--user"] if args.user else []
            if _shutil.which("systemctl"):
                try:
                    _sp2.run(["systemctl", *scope, "daemon-reload"],
                             capture_output=True, text=True, timeout=30)
                    en = _sp2.run(
                        ["systemctl", *scope, "enable", "--now",
                         "agentlink-agent"],
                        capture_output=True, text=True, timeout=60)
                    act = _sp2.run(
                        ["systemctl", *scope, "is-active",
                         "agentlink-agent"],
                        capture_output=True, text=True, timeout=15)
                    if en.returncode == 0:
                        result["supervision"] = "systemd"
                        result["systemd_active"] = \
                            (act.stdout or "").strip()
                        result.pop("next", None)
                    else:
                        result["systemd_error"] = (
                            (en.stderr or en.stdout or "").strip()
                            [:300])
                except Exception as exc:
                    result["systemd_error"] = str(exc)[:300]
            if result["supervision"] is None:
                # Fallback: a relaunch loop that carries its
                # own watchdog ticker (2.2.0 — @reboot start via
                # the cron block below when cron exists).
                # Honest second class: it restarts on death AND
                # on freeze, and starts on boot, without systemd.
                try:
                    home = Path("~/.agentlink").expanduser()
                    home.mkdir(parents=True, exist_ok=True)
                    sup = home / "supervise-agent.sh"
                    sup.write_text(
                        "#!/bin/sh\n"
                        "# AgentLink fallback supervisor (no systemd):\n"
                        "# relaunch the agent forever. The background\n"
                        "# ticker (2.2.0) is the hang watchdog's clock\n"
                        "# on hosts with no cron: every 30s it runs\n"
                        "# watchdog.sh, which kills a daemon whose\n"
                        "# heartbeat stamp went stale — the relaunch\n"
                        "# loop below then restarts it exactly like a\n"
                        "# crash.\n"
                        "( while true; do sleep 30; /bin/sh "
                        f"\"{home}/watchdog.sh\" >/dev/null 2>&1; "
                        "done ) &\n"
                        "while true; do\n"
                        f"  {exec_start} >>"
                        f"{home}/agent-supervised.log 2>&1\n"
                        "  sleep 2\n"
                        "done\n")
                    try:
                        sup.chmod(0o755)
                    except OSError:
                        pass
                    _sp2.Popen(
                        ["setsid", "/bin/sh", str(sup)],
                        stdout=_sp2.DEVNULL, stderr=_sp2.DEVNULL,
                        start_new_session=True)
                    result["supervision"] = "cron-supervisor"
                    result["supervisor"] = str(sup)
                except Exception as exc:
                    result["supervision"] = "none"
                    result["supervisor_error"] = str(exc)[:300]
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
            # The watchdog (2.2.0 form): stamped for THIS agent
            # and THIS state dir — the old script globbed the
            # first heartbeat-*.txt in ~/.agentlink and could
            # only restart a systemd unit, so a frozen daemon
            # under the fallback supervisor (or on a host whose
            # state dir is not ~/.agentlink) was never killed,
            # and a stopped unit was restarted every minute
            # whether its owner wanted it or not. Now: a stale
            # stamp + a LIVE lock pid = a frozen daemon; kill it
            # and let its supervisor relaunch. systemd keeps its
            # own restart when it manages the unit (its
            # WatchdogSec is the primary net there anyway).
            _sd_path = Path(
                args.state_dir or DEFAULT_STATE_DIR).expanduser()
            _watchdog = (
                "#!/bin/sh\n"
                "# AgentLink watchdog: HANG = DEATH (point 39d).\n"
                "# The daemon stamps its heartbeat file every 5s\n"
                "# from the loop that serves traffic; a stamp\n"
                "# older than 20s means that loop is frozen.\n"
                f"STAMP=\"{_sd_path}/heartbeat-{uname}.txt\"\n"
                f"LOCK=\"{_sd_path}/instance-{uname}.lock\"\n"
                "NOW=$(date +%s)\n"
                "TS=$(cat \"$STAMP\" 2>/dev/null || echo 0)\n"
                "case \"$TS\" in *[!0-9]*|\"\") TS=0 ;; esac\n"
                "[ $((NOW - TS)) -le 20 ] && exit 0\n"
                "# Startup allowance: a daemon that has never\n"
                "# stamped under this lock is still logging in\n"
                "# (first login on a slow network outlasts any\n"
                "# tight grace — this release's drill VM measured\n"
                "# ~75s); it gets 120s from lock time before the\n"
                "# stale-stamp rule may fire. A daemon that HAS\n"
                "# stamped and then froze gets no such shelter.\n"
                "LMT=$(stat -c %Y \"$LOCK\" 2>/dev/null || echo 0)\n"
                "case \"$LMT\" in *[!0-9]*|\"\") LMT=0 ;; esac\n"
                "SMT=$(stat -c %Y \"$STAMP\" 2>/dev/null || echo 0)\n"
                "case \"$SMT\" in *[!0-9]*|\"\") SMT=0 ;; esac\n"
                "if [ \"$LMT\" -gt 0 ] && [ \"$SMT\" -lt \"$LMT\" ]"
                " && [ $((NOW - LMT)) -lt 120 ]; then exit 0; fi\n"
                "if [ \"$LMT\" -gt 0 ] && "
                "[ $((NOW - LMT)) -lt 30 ]; then exit 0; fi\n"
                "# systemd manages the unit: its restart keeps\n"
                "# the unit state truthful (WatchdogSec usually\n"
                "# fires first; this is the second net).\n"
                "if command -v systemctl >/dev/null 2>&1; then\n"
                "  if systemctl --user is-active --quiet"
                " agentlink-agent 2>/dev/null || systemctl"
                " is-active --quiet agentlink-agent 2>/dev/null;"
                " then\n"
                "    systemctl --user restart agentlink-agent"
                " 2>/dev/null || systemctl restart"
                " agentlink-agent 2>/dev/null || true\n"
                "    exit 0\n"
                "  fi\n"
                "fi\n"
                "# Kill the frozen lock holder; its supervisor\n"
                "# (the supervisor loop, or systemd) relaunches a\n"
                "# dead daemon. No live pid: nothing to kill —\n"
                "# starting is the supervisor's job, not ours.\n"
                "PID=$(sed -n 's/.*\"pid\": *\\([0-9][0-9]*\\).*"
                "/\\1/p' \"$LOCK\" 2>/dev/null | head -1)\n"
                "case \"$PID\" in *[!0-9]*|\"\") exit 0 ;; esac\n"
                "kill -0 \"$PID\" 2>/dev/null || exit 0\n"
                "kill -TERM \"$PID\" 2>/dev/null || exit 0\n"
                "sleep 5\n"
                "kill -0 \"$PID\" 2>/dev/null && "
                "kill -KILL \"$PID\" 2>/dev/null\n"
                "exit 0\n")
            (home / "watchdog.sh").write_text(_watchdog)
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
                        "# agentlink-update-end\n"
                        + ("@reboot /bin/sh"
                           " ~/.agentlink/supervise-agent.sh"
                           " >/dev/null 2>&1\n"
                           if result.get("supervision")
                           == "cron-supervisor" else ""))
                    proc = _sp.run(["crontab", "-"], input=cur + block,
                                   capture_output=True, text=True)
                    result["cron"] = "installed" if proc.returncode == 0 \
                        else "failed"
                else:
                    result["cron"] = "already installed"
            else:
                result["cron"] = (
                    "no crontab binary on this host — the cron"
                    " safety net was skipped. Hang coverage does"
                    " NOT depend on it (2.2.0): under systemd the"
                    " unit's WatchdogSec restarts a frozen daemon;"
                    " under the fallback supervisor the loop's"
                    " 30-second ticker runs watchdog.sh itself."
                    " Self-update is NOT affected either: it runs"
                    " in-daemon (see self_update)")
                print("NOTE: no crontab binary on this host — the"
                      " cron safety net was skipped. Hang coverage"
                      " does not depend on it (2.2.0): systemd"
                      " units carry WatchdogSec, and the fallback"
                      " supervisor ticks the watchdog itself."
                      " Self-update does not depend on it either:"
                      " the agent daemon checks for updates itself"
                      " every 15 minutes.", flush=True)
        except Exception as exc:
            result["cron"] = f"skipped: {exc}"
        _print(result)
        return 0
    if sub == "status":
        # REAL state (2.0.10): what supervision exists, whether
        # systemd calls the unit active, and whether the
        # identity's daemon lock is held by a live pid — never a
        # static description.
        ap = argparse.ArgumentParser(prog="agentlink service status")
        ap.add_argument("--username", default=None)
        ap.add_argument("--state-dir", default=None)
        args = ap.parse_args(rest[1:])
        out: dict = {
            "uninstall": "no agent-facing uninstall exists by design;"
                         " removal is an operator-only action"}
        unit_paths = [
            Path("~/.config/systemd/user/agentlink-agent.service")
            .expanduser(),
            Path("/etc/systemd/system/agentlink-agent.service")]
        out["unit_file"] = next(
            (str(p) for p in unit_paths if p.exists()), None)
        sup = Path("~/.agentlink/supervise-agent.sh").expanduser()
        out["fallback_supervisor"] = str(sup) if sup.exists() else None
        import shutil as _shutil2
        import subprocess as _sp3
        if _shutil2.which("systemctl"):
            for scope in (["--user"], []):
                try:
                    act = _sp3.run(
                        ["systemctl", *scope, "is-active",
                         "agentlink-agent"],
                        capture_output=True, text=True, timeout=15)
                    if act.returncode == 0 or \
                            (act.stdout or "").strip() in (
                                    "active", "activating"):
                        out["systemd"] = (act.stdout or "").strip()
                        out["systemd_scope"] = "user" if scope \
                            else "system"
                        break
                except Exception:
                    continue
            else:
                out["systemd"] = "inactive"
        if args.username:
            sd = Path(_state_dir(args))
            lock = sd / f"instance-{_username(args)}.lock"
            out["state_dir"] = str(sd)
            out["daemon_lock"] = str(lock) if lock.exists() else None
            out["daemon_pid_alive"] = False
            if lock.exists():
                try:
                    holder = json.loads(lock.read_text())
                    pid = int(holder.get("pid") or 0)
                    if pid:
                        os.kill(pid, 0)
                        out["daemon_pid_alive"] = True
                        out["daemon_pid"] = pid
                except Exception:
                    pass
        _print(out)
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
    # Owner-seat control channel (v1.3.9): group add forwards to
    # the running instance when the daemon holds the lock.
    _fwd = {"cmd": "group_add", "group_id": args.group_id,
            "members": list(args.members)} if sub == "add" else None
    _print(asyncio.run(_with_agent(args, fn, forward=_fwd)))
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
    ap.add_argument("--heavy", action="store_true",
                    help="accepted for compatibility: the work is"
                         " hardware-heavy. Since 2.6.0 the platform"
                         " keeps no machine record (spec retirement),"
                         " so the nature-fit lines carry nature +"
                         " grade only — fitness is the assigner's"
                         " judgment, never a platform refusal)")
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
    _print(asyncio.run(_with_agent(
        args, _go,
        forward={"cmd": "work_assign", "assignees": assignees,
                 "title": args.title,
                 "instructions": args.instructions,
                 "group_id": args.group_id,
                 "attachments": args.attachments,
                 "deadline": args.deadline,
                 "priority": args.priority, "role": args.role,
                 "require_approval": args.require_approval})))
    # Nature-fit surface (2.5.0): after the assignment, state each
    # assignee's declared nature + grade, so a long job is never
    # handed to a nature that cannot hold it blind. Best-effort
    # display — the assignment already landed; a failed read is
    # reported as unavailable, never hidden. (2.6.0: no machine
    # line — spec retirement; the platform holds no spec record
    # to display.)
    from .liveness import nature_summary
    for name in assignees:
        try:
            out = asyncio.run(_with_agent(
                args, lambda a, n=name: a.peer_liveness(n),
                forward={"cmd": "peer_liveness", "username": name,
                         "timeout": 60}))
            peer = out.get("result") if isinstance(out, dict) \
                and "result" in out else out
            lv = (peer or {}).get("liveness") or {}
            prof = (peer or {}).get("nature") or {}
            print(f"nature-fit @{name}: {nature_summary(prof)} · "
                  f"grade {lv.get('grade') or 'unproven'}"
                  f"{' · daemon-only' if lv.get('daemon_only') else ''}")
        except Exception as exc:
            print(f"nature-fit @{name}: unavailable ({exc})")
    return 0


def _deliver(rest: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="agentlink deliver")
    _add_common(ap)
    ap.add_argument("--file", action="append", default=[], dest="files")
    ap.add_argument("work_id")
    ap.add_argument("body", nargs="?", default="")
    args = ap.parse_args(rest)
    _print(asyncio.run(_with_agent(
        args, lambda a: a.deliver_work(args.work_id, args.body,
                                       args.files),
        forward={"cmd": "work_deliver", "work_id": args.work_id,
                 "body": args.body, "files": args.files})))
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
            args, lambda a: a.work_inbox(args.status, args.group_id),
            forward={"cmd": "work_inbox", "timeout": 300})))
        return 0
    if sub == "progress":
        ap = argparse.ArgumentParser(prog="agentlink work progress")
        _add_common(ap)
        ap.add_argument("work_id")
        ap.add_argument("percent", type=int)
        ap.add_argument("note", nargs="?", default="")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.report_progress(args.work_id,
                                              args.percent,
                                              args.note),
            forward={"cmd": "work_progress",
                     "work_id": args.work_id,
                     "percent": args.percent, "note": args.note})))
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
        _print(asyncio.run(_with_agent(
            args, fn,
            forward={"cmd": "work_" + sub.replace("-", "_"),
                     "work_id": args.work_id, "note": args.note})))
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
        _print(asyncio.run(_with_agent(
            args, lambda a: a.chain_list(),
            forward={"cmd": "chain_list", "timeout": 300})))
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


def _credentials(rest: list[str]) -> int:
    """The agent's OWN credentials vault (v1.4.0) — NOT the group
    vault above (`agentlink vault` is the group's shared shelf and
    is untouched). Entries are sealed to the agent's identity key;
    possession of that key IS the permission, so these commands run
    with no prompt: against the running daemon through its control
    channel when one is live, else through a one-shot agent (whose
    start also syncs the vault). `get` prints the full entry —
    password included — because this CLI runs inside the agent's
    own trust boundary for its operator's use; `list` prints labels
    only, forever."""
    sub = rest[0] if rest else "list"
    r = rest[1:] if rest else []
    ap = argparse.ArgumentParser(prog=f"agentlink credentials {sub}")
    _add_common(ap)
    if sub == "put":
        ap.add_argument("service")
        # dest MUST NOT be "username": _add_common's --username is
        # the AGENT's name and argparse would let the flag overwrite
        # this positional (the v1.4.0 production proof caught an
        # entry saved with the agent's name as its account).
        ap.add_argument("account", metavar="username",
                        help="the account email/username saved")
        ap.add_argument("password")
        ap.add_argument("--notes", default="")
        ap.add_argument("--auth-type", default="password",
                        choices=["password", "api_key", "token",
                                 "other"],
                        help="the form of the secret (v1.5.0): a "
                             "login password, an API key, a token, "
                             "or other auth material")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args,
            lambda a: a.vault.remember(args.service, args.account,
                                       args.password,
                                       notes=args.notes,
                                       auth_type=args.auth_type),
            forward={"cmd": "vault_put", "service": args.service,
                     "username": args.account,
                     "password": args.password,
                     "notes": args.notes,
                     "auth_type": args.auth_type})))
        return 0
    if sub == "list":
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args,
            lambda a: a.vault.list(),
            forward={"cmd": "vault_list"})))
        return 0
    if sub == "get":
        ap.add_argument("service_or_id")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args,
            lambda a: a.vault.get(args.service_or_id),
            forward={"cmd": "vault_get",
                     "service_or_id": args.service_or_id})))
        return 0
    if sub == "remove":
        ap.add_argument("entry_id")
        args = ap.parse_args(r)
        _print(asyncio.run(_with_agent(
            args,
            lambda a: a.vault.remove(args.entry_id),
            forward={"cmd": "vault_remove",
                     "entry_id": args.entry_id})))
        return 0
    print(f"unknown credentials command {sub!r} "
          f"(put/list/get/remove)", file=sys.stderr)
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
