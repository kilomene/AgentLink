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
    agent = Agent(_username(args), endpoint=_endpoint(args),
                  state_dir=_state_dir(args))
    await agent.start()
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
        print("commands: relay register agent whoami directory send send-file "
              "dial group assign deliver work update doctor service backup")
        return 0
    cmd, rest = argv[0], argv[1:]

    if cmd == "relay":
        _relay.main(rest)
        return 0

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
        _print(asyncio.run(_go()))
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
        args = ap.parse_args(rest)

        async def _go():
            a = Agent(_username(args), endpoint=_endpoint(args),
                      state_dir=_state_dir(args))

            @a.on_message
            async def _msg(frame):
                print(f"[{frame.get('from')}] {frame.get('body')}", flush=True)
                if args.echo:
                    return f"echo: {frame.get('body')}"
                return None

            @a.on_work
            async def _work(work):
                print(f"WORK {work['id']}: {work['title']} "
                      f"from @{work['assigner']}", flush=True)

            await a.run()
        asyncio.run(_go())
        return 0

    if cmd == "directory":
        ap = argparse.ArgumentParser(prog="agentlink directory")
        _add_common(ap)
        ap.add_argument("query", nargs="?", default="")
        args = ap.parse_args(rest)
        _print(asyncio.run(_with_agent(args, lambda a: a.directory(args.query))))
        return 0

    if cmd == "send":
        ap = argparse.ArgumentParser(prog="agentlink send")
        _add_common(ap)
        ap.add_argument("to")
        ap.add_argument("body")
        args = ap.parse_args(rest)
        _print(asyncio.run(_with_agent(
            args, lambda a: a.send_message(args.to, args.body))))
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
        _print(asyncio.run(_with_agent(
            args, lambda a: a.send_file(args.to, args.path, args.caption,
                                        args.kind))))
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
    if cmd == "update":
        from .updater import main as _update_main
        return _update_main(rest)
    if cmd == "doctor":
        return _doctor(rest)
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
    print(f"unknown command {cmd!r}; see `agentlink --help`", file=sys.stderr)
    return 2


def _doctor(rest: list[str]) -> int:
    """Verification report: DB integrity + permissions, identity files,
    endpoint configuration. Read-only."""
    import sqlite3
    import stat as _stat
    from .config import DEFAULT_ENDPOINT, resolve_endpoint

    ap = argparse.ArgumentParser(prog="agentlink doctor")
    ap.add_argument("--db", default="~/.agentlink/relay.db")
    ap.add_argument("--state-dir", default=None)
    args = ap.parse_args(rest)
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
            "Restart=always\nRestartSec=3\n\n"
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
        # Cron safety net, installed idempotently: per-minute watchdog
        # + daily update check. Marker-delimited, safe to re-run.
        try:
            import shutil
            import subprocess as _sp
            home = Path("~/.agentlink").expanduser()
            home.mkdir(parents=True, exist_ok=True)
            (home / "watchdog.sh").write_text(
                "#!/bin/sh\n"
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
                        "17 4 * * * agentlink update >/dev/null 2>&1\n"
                        "# agentlink-update-end\n")
                    proc = _sp.run(["crontab", "-"], input=cur + block,
                                   capture_output=True, text=True)
                    result["cron"] = "installed" if proc.returncode == 0 \
                        else "failed"
                else:
                    result["cron"] = "already installed"
            else:
                result["cron"] = "no crontab binary; copy deploy/" \
                                 "agentlink.cron into your cron spool"
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
    ap.add_argument("--deadline", type=int, default=None)
    ap.add_argument("assignees", help="comma-separated usernames")
    ap.add_argument("title")
    ap.add_argument("instructions", nargs="?", default="")
    args = ap.parse_args(rest)
    assignees = [s.strip() for s in args.assignees.split(",") if s.strip()]
    _print(asyncio.run(_with_agent(args, lambda a: a.assign_work(
        assignees, args.title, args.instructions, group_id=args.group_id,
        attachments=args.attachments, deadline=args.deadline))))
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
    if sub in ("complete", "request-changes"):
        ap = argparse.ArgumentParser(prog=f"agentlink work {sub}")
        _add_common(ap)
        ap.add_argument("work_id")
        ap.add_argument("note", nargs="?", default="")
        args = ap.parse_args(r)
        fn = (lambda a: a.complete_work(args.work_id, args.note)) \
            if sub == "complete" else \
            (lambda a: a.request_changes(args.work_id, args.note))
        _print(asyncio.run(_with_agent(args, fn)))
        return 0
    print(f"unknown work command {sub!r}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
