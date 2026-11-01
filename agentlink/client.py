"""AgentLink client SDK.

An agent is identified by username only. On first registration the
relay issues an owner-secret which this client saves to
``~/.agentlink/secret-<username>.json`` (mode 0600) and presents
silently on reconnect to reclaim the username. Users and other agents
never see or type that secret — the address is just ``@username``.

Handlers (decorators)::

    agent = Agent("phoenix")

    @agent.on_message
    async def handle(msg):          # msg: dict, see protocol.py
        return "reply text"         # or None for no reply

    @agent.on_work
    async def handle_work(work):    # work: dict
        await agent.deliver_work(work["id"], "done", files=["out.pdf"])
"""

from __future__ import annotations

import asyncio
import inspect
import json
import logging
import os
from pathlib import Path

import websockets.exceptions
from websockets.client import connect

from .config import resolve_endpoint
from .protocol import (
    MAX_FRAME,
    make_file_payload,
    new_id,
    normalize_username,
    verify_file,
)

log = logging.getLogger("agentlink.client")

DEFAULT_STATE_DIR = os.path.expanduser("~/.agentlink")


class RegistrationFailed(Exception):
    pass


class RequestFailed(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}".strip())
        self.reason = reason
        self.detail = detail


class Agent:
    def __init__(
        self,
        username: str,
        display_name: str | None = None,
        endpoint: str | None = None,
        state_dir: str = DEFAULT_STATE_DIR,
        ephemeral: bool = False,
    ):
        u = normalize_username(username)
        if u is None and not ephemeral:
            raise ValueError(f"bad username {username!r}")
        self.username = u or ""
        self.display_name = display_name or self.username
        self.endpoint = resolve_endpoint(endpoint)
        self.state_dir = Path(state_dir).expanduser()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ephemeral = ephemeral
        self._ws = None
        self._reader: asyncio.Task | None = None
        self._message_handler = None
        self._work_handler = None
        self._group_handler = None
        self._pending: dict[str, asyncio.Future] = {}
        self._reply_waiters: dict[str, asyncio.Future] = {}
        # Collected when no handler is registered (handy for tests/CLI).
        self.messages: list[dict] = []
        self.group_events: list[dict] = []
        self.work_updates: list[dict] = []
        self.assigned_work: list[dict] = []

    # -- decorators ---------------------------------------------------------
    def on_message(self, fn):
        self._message_handler = fn
        return fn

    def on_work(self, fn):
        self._work_handler = fn
        return fn

    def on_group_event(self, fn):
        self._group_handler = fn
        return fn

    # -- identity persistence ---------------------------------------------
    def _secret_path(self) -> Path:
        return self.state_dir / f"secret-{self.username}.json"

    def _load_secret(self) -> str | None:
        p = self._secret_path()
        if p.exists():
            try:
                return json.loads(p.read_text()).get("secret")
            except Exception:
                return None
        return None

    def _save_secret(self, secret: str) -> None:
        p = self._secret_path()
        p.write_text(json.dumps({"username": self.username, "secret": secret}))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        cur = self.state_dir / "current.json"
        cur.write_text(json.dumps(
            {"username": self.username, "display_name": self.display_name}))

    def whoami(self) -> dict:
        return {"username": self.username,
                "display_name": self.display_name,
                "endpoint": self.endpoint}

    # -- connection -----------------------------------------------------------
    async def _send_raw(self, frame: dict) -> None:
        await self._ws.send(json.dumps(frame))

    async def start(self) -> str:
        self._ws = await connect(self.endpoint, max_size=MAX_FRAME)
        await self._send_raw({
            "type": "hello", "username": self.username or None,
            "display_name": self.display_name,
            "secret": None if self.ephemeral else self._load_secret(),
            "ephemeral": self.ephemeral,
        })
        while True:
            raw = await self._ws.recv()
            frame = json.loads(raw)
            if frame.get("type") == "welcome":
                self.username = frame["username"]
                if frame.get("secret"):
                    self._save_secret(frame["secret"])
                log.info("registered as @%s (%d queued)",
                         self.username, frame.get("queued", 0))
                # Reader task processes everything after the welcome,
                # so handlers may themselves make requests (deliver
                # work from inside on_work, reply from on_message).
                self._reader = asyncio.create_task(self._read_loop())
                return self.username
            if frame.get("type") == "error":
                await self._ws.close()
                raise RegistrationFailed(
                    f"{frame.get('reason')}: {frame.get('detail', '')}")
        raise RegistrationFailed("connection closed before welcome")

    async def _read_loop(self) -> None:
        try:
            async for raw in self._ws:
                await self._dispatch(json.loads(raw))
        except websockets.exceptions.ConnectionClosed:
            pass

    async def close(self) -> None:
        reader = getattr(self, "_reader", None)
        if reader is not None:
            reader.cancel()
            self._reader = None
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

    async def serve(self) -> None:
        assert self._ws is not None, "call start() first"
        reader = getattr(self, "_reader", None)
        if reader is not None:
            try:
                await reader
            except asyncio.CancelledError:
                pass

    async def run(self, reconnect_delay: float = 2.0) -> None:
        """Serve forever with auto-reconnect + exponential backoff."""
        delay = reconnect_delay

        async def _pinger():
            while True:
                await asyncio.sleep(20)
                try:
                    if self._ws is not None:
                        await self._send_raw({"type": "ping"})
                except Exception:
                    return

        while True:
            try:
                await self.start()
                delay = reconnect_delay
                ping = asyncio.create_task(_pinger())
                try:
                    await self.serve()
                finally:
                    ping.cancel()
                log.warning("disconnected; reconnecting in %.0fs", delay)
            except RegistrationFailed:
                raise
            except Exception as exc:
                log.warning("connection failed (%s); retrying in %.0fs",
                            exc, delay)
            await asyncio.sleep(delay)
            delay = min(delay * 2, 30.0)

    # -- dispatch ---------------------------------------------------------------
    async def _dispatch(self, frame: dict) -> None:
        ftype = frame.get("type")
        req_id = frame.get("req_id")
        if ftype in ("result", "error") and req_id in self._pending:
            fut = self._pending.pop(req_id)
            if not fut.done():
                if ftype == "result" and frame.get("ok", True):
                    fut.set_result(frame.get("data") or {})
                else:
                    fut.set_exception(RequestFailed(
                        frame.get("reason", "error"), frame.get("detail", "")))
            return
        if ftype == "message":
            if frame.get("file") and not verify_file(frame["file"]):
                log.warning("dropping message %s: file hash mismatch",
                            frame.get("id"))
                return
            self.messages.append(frame)
            waiter = self._reply_waiters.pop(frame.get("in_reply_to"), None) \
                if frame.get("in_reply_to") else None
            if waiter is not None and not waiter.done():
                waiter.set_result(frame)
            handler = self._message_handler
            if handler is not None:
                # Spawned, not awaited inline: a handler may itself send
                # requests whose results this same read loop must process.
                asyncio.create_task(self._run_message_handler(handler, frame))
            return
        if ftype == "group_event":
            self.group_events.append(frame)
            if self._group_handler is not None:
                asyncio.create_task(self._run_simple_handler(
                    self._group_handler, frame))
            return
        if ftype == "work_assigned":
            work = frame.get("work") or {}
            self.assigned_work.append(work)
            if self._work_handler is not None:
                asyncio.create_task(self._run_simple_handler(
                    self._work_handler, work))
            return
        if ftype == "work_update":
            self.work_updates.append(frame.get("work") or {})
            return
        # welcome/pong/delivered acks without req_id: ignore

    async def _run_message_handler(self, handler, frame: dict) -> None:
        try:
            result = handler(frame)
            if inspect.isawaitable(result):
                result = await result
        except Exception:
            log.exception("on_message handler failed")
            return
        if result:
            try:
                if frame.get("group_id"):
                    await self.group_send(frame["group_id"], str(result),
                                          in_reply_to=frame.get("id"))
                else:
                    await self.send_message(frame["from"], str(result),
                                            in_reply_to=frame.get("id"))
            except Exception:
                log.exception("sending handler reply failed")

    async def _run_simple_handler(self, handler, arg) -> None:
        try:
            r = handler(arg)
            if inspect.isawaitable(r):
                await r
        except Exception:
            log.exception("handler failed")

    # -- requests ------------------------------------------------------------------
    async def _request(self, frame: dict, timeout: float = 15.0) -> dict:
        req_id = new_id()
        frame = {**frame, "req_id": req_id}
        fut = asyncio.get_running_loop().create_future()
        self._pending[req_id] = fut
        await self._send_raw(frame)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._pending.pop(req_id, None)

    # -- messaging -------------------------------------------------------------------
    async def send_message(self, to: str, body: str, kind: str = "text",
                           file: dict | None = None,
                           in_reply_to: str | None = None) -> dict:
        return await self._request({
            "type": "send", "to": to, "body": body, "kind": kind,
            "file": file, "id": new_id(), "in_reply_to": in_reply_to})

    async def send_file(self, to: str, path: str, caption: str = "",
                        kind: str | None = None) -> dict:
        return await self.send_message(
            to, caption, file=make_file_payload(path, kind))

    async def wait_reply(self, message_id: str, timeout: float = 15.0) -> dict:
        # A reply may already have arrived (dispatch is sequential, so a
        # fast reply can land before wait_reply is called).
        for m in self.messages:
            if m.get("in_reply_to") == message_id:
                return m
        fut = asyncio.get_running_loop().create_future()
        self._reply_waiters[message_id] = fut
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._reply_waiters.pop(message_id, None)

    # -- groups -----------------------------------------------------------------------
    async def group_create(self, name: str, members: list[str] | None = None,
                           settings: dict | None = None) -> dict:
        return await self._request({"type": "group_create", "name": name,
                                    "members": members or [],
                                    "settings": settings})

    async def group_add(self, group_id: str, members: list[str]) -> dict:
        return await self._request({"type": "group_add", "group_id": group_id,
                                    "members": members})

    async def group_remove(self, group_id: str, username: str) -> dict:
        return await self._request({"type": "group_remove",
                                    "group_id": group_id, "username": username})

    async def group_members(self, group_id: str) -> dict:
        return await self._request({"type": "group_members",
                                    "group_id": group_id})

    async def group_promote(self, group_id: str, username: str) -> dict:
        return await self._request({"type": "group_promote",
                                    "group_id": group_id, "username": username})

    async def group_demote(self, group_id: str, username: str) -> dict:
        return await self._request({"type": "group_demote",
                                    "group_id": group_id, "username": username})

    async def group_settings(self, group_id: str, settings: dict) -> dict:
        return await self._request({"type": "group_settings",
                                    "group_id": group_id, "settings": settings})

    async def group_join_link(self, group_id: str) -> dict:
        return await self._request({"type": "group_join_link",
                                    "group_id": group_id})

    async def group_join(self, link_or_token: str,
                         group_id: str | None = None) -> dict:
        frame = {"type": "group_join", "token": link_or_token}
        if group_id:
            frame["group_id"] = group_id
        return await self._request(frame)

    async def group_send(self, group_id: str, body: str, kind: str = "text",
                         file: dict | None = None,
                         in_reply_to: str | None = None) -> dict:
        return await self._request({
            "type": "group_send", "group_id": group_id, "body": body,
            "kind": kind, "file": file, "id": new_id(),
            "in_reply_to": in_reply_to})

    async def group_send_file(self, group_id: str, path: str,
                              caption: str = "", kind: str | None = None) -> dict:
        return await self.group_send(group_id, caption,
                                     file=make_file_payload(path, kind))

    # -- work ---------------------------------------------------------------------------
    async def assign_work(self, assignees: list[str], title: str,
                          instructions: str = "", group_id: str | None = None,
                          attachments: list[str] | None = None,
                          deadline: int | None = None) -> list[dict]:
        payloads = [make_file_payload(p) for p in (attachments or [])]
        data = await self._request({
            "type": "assign", "assignees": assignees, "group_id": group_id,
            "title": title, "instructions": instructions,
            "attachments": payloads, "deadline": deadline})
        return data["work"]

    async def deliver_work(self, work_id: str, body: str = "",
                           files: list[str] | None = None) -> dict:
        payloads = [make_file_payload(p) for p in (files or [])]
        data = await self._request({"type": "deliver_work", "work_id": work_id,
                                    "body": body, "files": payloads})
        return data["work"]

    async def complete_work(self, work_id: str, note: str = "") -> dict:
        data = await self._request({"type": "work_action", "work_id": work_id,
                                    "action": "complete", "note": note})
        return data["work"]

    async def request_changes(self, work_id: str, note: str = "") -> dict:
        data = await self._request({"type": "work_action", "work_id": work_id,
                                    "action": "request_changes", "note": note})
        return data["work"]

    async def work_inbox(self, status: str | None = None,
                         group_id: str | None = None) -> list[dict]:
        data = await self._request({"type": "work_inbox", "status": status,
                                    "group_id": group_id})
        return data["work"]

    # -- directory -----------------------------------------------------------------------
    async def directory(self, query: str = "") -> list[dict]:
        data = await self._request({"type": "directory", "query": query})
        return data["users"]


async def dial(endpoint: str | None, to: str, body: str,
               timeout: float = 15.0, state_dir: str = DEFAULT_STATE_DIR) -> str:
    """One-shot: send a message as an ephemeral caller and await the reply.

    Mirrors how a caller reaches Fo: fire through the endpoint, then poll
    for / await the reply on the same line.
    """
    caller = Agent("dial", endpoint=endpoint, state_dir=state_dir,
                   ephemeral=True)
    await caller.start()
    serve = asyncio.create_task(caller.serve())
    try:
        sent = await caller.send_message(to, body)
        reply = await caller.wait_reply(sent["id"], timeout=timeout)
        return reply.get("body", "")
    finally:
        serve.cancel()
        await caller.close()
