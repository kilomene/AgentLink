"""The AgentLink relay: routes messages, groups and work between agents.

Host it anywhere: ``agentlink relay --host 0.0.0.0 --port 8765``.
State is one SQLite file. There is no hard-coded connection limit:
peers live in a plain dict and every frame is handled independently,
so the relay scales to thousands of concurrent agents on modest
hardware (SQLite writes are lock-serialised and kept tiny).
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from dataclasses import dataclass, field

import websockets
import websockets.exceptions
from websockets.server import serve

from .protocol import MAX_FRAME, new_id, normalize_username, now_ts, verify_file
from .store import NotFound, Store, UsernameTaken

log = logging.getLogger("agentlink.relay")

ADMIN_ROLES = ("admin", "superadmin")


@dataclass
class Peer:
    ws: object
    username: str
    display_name: str = ""
    ephemeral: bool = False


@dataclass
class Relay:
    host: str = "127.0.0.1"
    port: int = 8765
    db_path: str = "~/.agentlink/relay.db"
    peers: dict = field(default_factory=dict)  # username -> Peer
    _server: object = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.store = Store(os.path.expanduser(self.db_path))

    async def start(self) -> "Relay":
        self._server = await serve(
            self._handle, self.host, self.port, max_size=MAX_FRAME
        )
        sockets = self._server.sockets or ()
        if sockets:
            self.port = sockets[0].getsockname()[1]
        log.info("relay listening on %s:%s", self.host, self.port)
        return self

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self.store.close()

    # -- plumbing ---------------------------------------------------------
    @staticmethod
    async def _send(ws, frame: dict) -> None:
        await ws.send(json.dumps(frame))

    async def _result(self, ws, req_id, ok: bool, data: dict) -> None:
        await self._send(ws, {"type": "result", "req_id": req_id,
                              "ok": ok, "data": data})

    async def _error(self, ws, reason: str, req_id=None, detail: str = "") -> None:
        await self._send(ws, {"type": "error", "req_id": req_id,
                              "reason": reason, "detail": detail})

    async def _deliver(self, username: str, frame: dict) -> bool:
        """Live-deliver a frame, else queue it offline. Returns queued?"""
        peer = self.peers.get(username)
        if peer is not None:
            try:
                await self._send(peer.ws, frame)
                return False
            except websockets.exceptions.ConnectionClosed:
                pass
        self.store.enqueue(username, frame)
        return True

    # -- connection ---------------------------------------------------------
    async def _handle(self, ws) -> None:
        peer: Peer | None = None
        try:
            async for raw in ws:
                try:
                    frame = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    await self._error(ws, "bad_frame")
                    continue
                if not isinstance(frame, dict):
                    await self._error(ws, "bad_frame")
                    continue
                ftype = frame.get("type")
                req_id = frame.get("req_id")
                if ftype == "hello":
                    peer = await self._on_hello(ws, frame, peer)
                elif ftype == "ping":
                    await self._send(ws, {"type": "pong", "req_id": req_id})
                elif peer is None:
                    await self._error(ws, "not_registered", req_id)
                elif ftype == "send":
                    await self._on_send(ws, frame, peer)
                elif ftype == "group_create":
                    await self._on_group_create(ws, frame, peer)
                elif ftype == "group_add":
                    await self._on_group_add(ws, frame, peer)
                elif ftype == "group_remove":
                    await self._on_group_remove(ws, frame, peer)
                elif ftype == "group_members":
                    await self._on_group_members(ws, frame, peer)
                elif ftype in ("group_promote", "group_demote"):
                    await self._on_group_role(ws, frame, peer,
                                              promote=(ftype == "group_promote"))
                elif ftype == "group_settings":
                    await self._on_group_settings(ws, frame, peer)
                elif ftype == "group_join_link":
                    await self._on_group_join_link(ws, frame, peer)
                elif ftype == "group_join":
                    await self._on_group_join(ws, frame, peer)
                elif ftype == "group_send":
                    await self._on_group_send(ws, frame, peer)
                elif ftype == "assign":
                    await self._on_assign(ws, frame, peer)
                elif ftype == "deliver_work":
                    await self._on_deliver_work(ws, frame, peer)
                elif ftype == "work_action":
                    await self._on_work_action(ws, frame, peer)
                elif ftype == "work_inbox":
                    inbox = self.store.list_work(
                        peer.username, frame.get("status"), frame.get("group_id"))
                    await self._result(ws, req_id, True, {"work": inbox})
                elif ftype == "directory":
                    users = self.store.list_users(str(frame.get("query") or ""))
                    for u in users:
                        u["online"] = u["username"] in self.peers
                    await self._result(ws, req_id, True, {"users": users})
                elif ftype == "whoami":
                    await self._result(ws, req_id, True, {
                        "username": peer.username,
                        "display_name": peer.display_name,
                        "online": True,
                    })
                else:
                    await self._error(ws, "unknown_type", req_id)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            if peer is not None and self.peers.get(peer.username) is peer:
                del self.peers[peer.username]
                log.info("peer @%s disconnected", peer.username)

    async def _on_hello(self, ws, frame, old):
        if old is not None and self.peers.get(old.username) is old:
            del self.peers[old.username]
        req_id = frame.get("req_id")
        display = str(frame.get("display_name") or frame.get("name") or "")[:64]
        secret = frame.get("secret")
        if frame.get("ephemeral"):
            username = "dial-" + new_id()[:8]
            peer = Peer(ws=ws, username=username, display_name=display or "dial",
                        ephemeral=True)
            self.peers[username] = peer
            await self._send(ws, {"type": "welcome", "req_id": req_id,
                                  "username": username, "secret": None,
                                  "ephemeral": True, "queued": 0})
            return peer
        username = normalize_username(frame.get("username"))
        if username is None:
            await self._error(ws, "bad_username", req_id,
                              "usernames are 2-32 chars: a-z 0-9 . _ -")
            return None
        if self.store.exists(username):
            if self.store.verify(username, secret):
                self.store.set_display_name(username, display or username)
            else:
                await self._error(ws, "username_taken", req_id)
                return None
            owner_secret = secret
        else:
            try:
                owner_secret = self.store.claim(username, display or username)
            except UsernameTaken:
                await self._error(ws, "username_taken", req_id)
                return None
        stale = self.peers.get(username)
        if stale is not None and stale.ws is not ws:
            try:
                await stale.ws.close(code=4000, reason="superseded")
            except Exception:
                pass
        peer = Peer(ws=ws, username=username,
                    display_name=display or username)
        self.peers[username] = peer
        queued = self.store.dequeue_all(username)
        await self._send(ws, {"type": "welcome", "req_id": req_id,
                              "username": username, "secret": owner_secret,
                              "ephemeral": False, "queued": len(queued)})
        for q in queued:
            await self._send(ws, q)
        log.info("peer @%s registered, flushed %d queued", username, len(queued))
        return peer

    # -- 1:1 messages ---------------------------------------------------------
    async def _on_send(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        to = normalize_username(frame.get("to"))
        body = frame.get("body", "")
        file_payload = frame.get("file")
        if to is None or (not isinstance(body, str)):
            await self._error(ws, "bad_send", req_id)
            return
        if file_payload is not None and not verify_file(file_payload):
            await self._error(ws, "bad_file_hash", req_id)
            return
        if not self.store.exists(to) and to not in self.peers:
            await self._error(ws, "unknown_recipient", req_id)
            return
        msg = {"type": "message", "id": frame.get("id") or new_id(),
               "from": peer.username, "from_name": peer.display_name,
               "body": body, "kind": frame.get("kind") or
               (file_payload or {}).get("kind") or "text",
               "file": file_payload, "ts": now_ts(),
               "in_reply_to": frame.get("in_reply_to"), "group_id": None}
        queued = await self._deliver(to, msg)
        await self._result(ws, req_id, True,
                           {"id": msg["id"], "to": to, "queued": queued})

    # -- groups ---------------------------------------------------------------
    def _group_or_error(self, ws, frame, peer):
        gid = frame.get("group_id")
        group = self.store.get_group(gid) if gid else None
        return gid, group

    async def _membership_event(self, group, event, actor, target):
        frame = {"type": "group_event", "id": new_id(), "group_id": group["id"],
                 "group_name": group["name"], "event": event, "actor": actor,
                 "target": target, "ts": now_ts(),
                 "members": self.store.members(group["id"])}
        for m in self.store.members(group["id"]):
            if m["username"] != actor:
                await self._deliver(m["username"], dict(frame))
        return frame

    async def _on_group_create(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        name = str(frame.get("name") or "")[:80]
        if not name:
            await self._error(ws, "bad_group", req_id, "group needs a name")
            return
        members = []
        for raw in frame.get("members") or []:
            u = normalize_username(raw)
            if u is None or not self.store.exists(u):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            if u != peer.username and u not in members:
                members.append(u)
        gid = self.store.create_group(name, peer.username, frame.get("settings"))
        # WhatsApp-style: added agents do NOT need to accept. They are in.
        for u in members:
            self.store.add_member(gid, u, role="member", added_by=peer.username)
        group = self.store.get_group(gid)
        if members:
            await self._membership_event(group, "added_to_group",
                                         peer.username, None)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "name": name,
                            "members": self.store.members(gid)})

    async def _on_group_add(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        if role is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if group["settings"].get("add_members") == "admins_only" \
                and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can add members in this group")
            return
        added = []
        for raw in frame.get("members") or []:
            u = normalize_username(raw)
            if u is None or not self.store.exists(u):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            if self.store.add_member(gid, u, role="member",
                                      added_by=peer.username):
                added.append(u)
        if added:
            await self._membership_event(group, "added_to_group",
                                         peer.username, None)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "added": added,
                            "members": self.store.members(gid)})

    async def _on_group_remove(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        target = normalize_username(frame.get("username"))
        target_role = self.store.role_of(gid, target) if target else None
        if role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can remove members")
            return
        if target_role is None:
            await self._error(ws, "not_a_member", req_id, str(target))
            return
        if target_role == "superadmin":
            await self._error(ws, "permission_denied", req_id,
                              "the group creator cannot be removed")
            return
        if role == "admin" and target_role == "admin":
            await self._error(ws, "permission_denied", req_id,
                              "admins cannot remove other admins")
            return
        self.store.remove_member(gid, target)
        await self._deliver(target, {
            "type": "group_event", "id": new_id(), "group_id": gid,
            "group_name": group["name"], "event": "removed_from_group",
            "actor": peer.username, "target": target, "ts": now_ts(),
            "members": self.store.members(gid)})
        await self._result(ws, req_id, True, {"group_id": gid, "removed": target})

    async def _on_group_members(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        await self._result(ws, req_id, True,
                           {"group_id": gid, "name": group["name"],
                            "settings": group["settings"],
                            "members": self.store.members(gid)})

    async def _on_group_role(self, ws, frame, peer: Peer, promote: bool) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        target = normalize_username(frame.get("username"))
        target_role = self.store.role_of(gid, target) if target else None
        if role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can promote/demote")
            return
        if target_role is None or target_role == "superadmin":
            await self._error(ws, "permission_denied", req_id,
                              "cannot change that member's role")
            return
        new_role = "admin" if promote else "member"
        self.store.set_role(gid, target, new_role)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "username": target, "role": new_role})

    async def _on_group_settings(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can change group settings")
            return
        try:
            merged = self.store.set_settings(gid, frame.get("settings") or {})
        except NotFound:
            await self._error(ws, "unknown_group", req_id)
            return
        await self._result(ws, req_id, True,
                           {"group_id": gid, "settings": merged})

    async def _on_group_join_link(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        token = self.store.create_invite(gid, peer.username)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "token": token,
                            "link": self.store.invite_link(gid, token)})

    async def _on_group_join(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid = frame.get("group_id")
        token = frame.get("token")
        if token and str(token).startswith("agentlink://"):
            parsed = self.store.parse_invite_link(str(token))
            if parsed:
                gid, token = parsed
        group = self.store.get_group(gid) if gid else None
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if not self.store.invite_valid(gid, token):
            await self._error(ws, "invalid_invite", req_id)
            return
        self.store.add_member(gid, peer.username, role="member",
                              added_by="invite-link")
        await self._membership_event(group, "joined_group",
                                     peer.username, peer.username)
        await self._result(ws, req_id, True,
                           {"group_id": gid,
                            "members": self.store.members(gid)})

    async def _on_group_send(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        if role is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if group["settings"].get("send_messages") == "admins_only" \
                and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can send messages in this group")
            return
        file_payload = frame.get("file")
        if file_payload is not None and not verify_file(file_payload):
            await self._error(ws, "bad_file_hash", req_id)
            return
        msg = {"type": "message", "id": frame.get("id") or new_id(),
               "from": peer.username, "from_name": peer.display_name,
               "body": frame.get("body", ""),
               "kind": frame.get("kind") or (file_payload or {}).get("kind")
               or "text",
               "file": file_payload, "ts": now_ts(),
               "in_reply_to": frame.get("in_reply_to"), "group_id": gid,
               "group_name": group["name"]}
        delivered, queued = [], []
        for m in self.store.members(gid):
            if m["username"] == peer.username:
                continue
            (queued if await self._deliver(m["username"], dict(msg))
             else delivered).append(m["username"])
        await self._result(ws, req_id, True,
                           {"id": msg["id"], "group_id": gid,
                            "delivered": delivered, "queued": queued})

    # -- work -------------------------------------------------------------------
    async def _on_assign(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid = frame.get("group_id")
        group = None
        if gid:
            group = self.store.get_group(gid)
            if group is None:
                await self._error(ws, "unknown_group", req_id)
                return
            role = self.store.role_of(gid, peer.username)
            if role is None:
                await self._error(ws, "not_a_member", req_id)
                return
            if group["settings"].get("assign_work") == "admins_only" \
                    and role not in ADMIN_ROLES:
                await self._error(ws, "permission_denied", req_id,
                                  "only admins can assign work in this group")
                return
        attachments = frame.get("attachments") or []
        for a in attachments:
            if isinstance(a, dict) and "data_b64" in a and not verify_file(a):
                await self._error(ws, "bad_file_hash", req_id)
                return
        created = []
        for raw in frame.get("assignees") or []:
            assignee = normalize_username(raw)
            if assignee is None or not self.store.exists(assignee):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            if group is not None and \
                    self.store.role_of(gid, assignee) is None:
                await self._error(ws, "assignee_not_in_group", req_id, assignee)
                return
            work = self.store.create_work(
                assigner=peer.username, assignee=assignee, group_id=gid,
                title=str(frame.get("title") or "Untitled work"),
                instructions=str(frame.get("instructions") or ""),
                attachments=attachments,
                deadline=frame.get("deadline"))
            created.append(work)
            await self._deliver(assignee,
                                {"type": "work_assigned", "work": work})
        if not created:
            await self._error(ws, "bad_assign", req_id, "no assignees")
            return
        await self._result(ws, req_id, True, {"work": created})

    async def _on_deliver_work(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        if work["assignee"] != peer.username:
            await self._error(ws, "permission_denied", req_id,
                              "only the assignee can deliver this work")
            return
        if work["status"] not in ("assigned", "changes_requested"):
            await self._error(ws, "bad_status", req_id,
                              f"work is {work['status']}, cannot deliver")
            return
        files = frame.get("files") or []
        for f in files:
            if isinstance(f, dict) and "data_b64" in f and not verify_file(f):
                await self._error(ws, "bad_file_hash", req_id)
                return
        updated = self.store.add_delivery(work["id"], peer.username,
                                          str(frame.get("body") or ""), files)
        # Delivery goes back through the SAME line to the assigner.
        await self._deliver(work["assigner"],
                            {"type": "work_update", "work": updated})
        await self._result(ws, req_id, True, {"work": updated})

    async def _on_work_action(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        action = frame.get("action")
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        if work["assigner"] != peer.username:
            await self._error(ws, "permission_denied", req_id,
                              "only the assigner can do that")
            return
        if work["status"] != "delivered":
            await self._error(ws, "bad_status", req_id,
                              f"work is {work['status']}, not delivered")
            return
        if action == "complete":
            status = "completed"
        elif action == "request_changes":
            status = "changes_requested"
        else:
            await self._error(ws, "bad_action", req_id, str(action))
            return
        updated = self.store.set_work_status(work["id"], status)
        await self._deliver(work["assignee"],
                            {"type": "work_update", "work": updated,
                             "note": frame.get("note")})
        await self._result(ws, req_id, True, {"work": updated})


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Run the AgentLink relay server.")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--db", default="~/.agentlink/relay.db")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    async def _run() -> None:
        relay = Relay(host=args.host, port=args.port, db_path=args.db)
        await relay.start()
        try:
            await asyncio.Future()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await relay.stop()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
