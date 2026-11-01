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
              "dial group assign deliver work")
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


def _group(rest: list[str]) -> int:
    if not rest:
        print("usage: agentlink group <create|add|remove|members|promote|"
              "demote|settings|join-link|join>", file=sys.stderr)
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
        ap.add_argument("username")
        args = ap.parse_args(r)
        fn = lambda a: a.group_remove(args.group_id, args.username)  # noqa: E731
    elif sub == "members":
        ap.add_argument("group_id")
        args = ap.parse_args(r)
        fn = lambda a: a.group_members(args.group_id)  # noqa: E731
    elif sub in ("promote", "demote"):
        ap.add_argument("group_id")
        ap.add_argument("username")
        args = ap.parse_args(r)
        fn = (lambda a: a.group_promote(args.group_id, args.username)) \
            if sub == "promote" else \
            (lambda a: a.group_demote(args.group_id, args.username))
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
