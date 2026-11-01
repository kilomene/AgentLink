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
import collections
import json
import logging
import os
from dataclasses import dataclass, field
from http import HTTPStatus

import websockets
import websockets.exceptions
from websockets.server import serve

from .protocol import MAX_FRAME, new_id, normalize_username, now_ts
from .store import GroupFull, NotFound, Store, UsernameTaken

log = logging.getLogger("agentlink.relay")

ADMIN_ROLES = ("admin", "superadmin")


@dataclass
class Peer:
    ws: object
    username: str
    display_name: str = ""
    pubkey: str = ""
    ephemeral: bool = False
    last_seen: int = 0
    home_endpoint: str = ""


@dataclass
class Relay:
    host: str = "127.0.0.1"
    port: int = 8765
    db_path: str = "~/.agentlink/relay.db"
    backend_store: object = None
    blob_store: object = None
    server_name: str | None = None
    dashboard_password: str | None = None
    dashboard_port: int = 8766
    dashboard_enabled: bool = True
    dashboard: object = field(default=None, repr=False)
    peers: dict = field(default_factory=dict)  # username -> Peer
    activity: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=300))
    _server: object = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.store = self.backend_store or \
            Store(os.path.expanduser(self.db_path))
        if self.blob_store is None:
            from .blobstore import create_blob_store
            default_root = os.path.join(
                os.path.dirname(os.path.expanduser(self.db_path)), "blobs")
            self.blob_store = create_blob_store(local_root=default_root)

    @property
    def server_label(self) -> str:
        return self.server_name or f"ws://{self.host}:{self.port}"

    def _log_activity(self, kind: str, actor: str, target: str = "",
                      group_id: str = "", work_id: str = "",
                      status: str = "") -> None:
        """Metadata only — never content. Feeds the live dashboard."""
        self.activity.appendleft({
            "ts": now_ts(), "kind": kind, "from": actor, "to": target,
            "group_id": group_id, "work_id": work_id, "status": status})
        try:
            self.store.audit(kind, actor, target, group_id, work_id, status)
        except Exception:
            pass
        if getattr(self, "dashboard", None) is not None:
            self.dashboard.notify()

    def _dashboard_data(self) -> dict:
        users = self.store.list_users()
        now = now_ts()
        for u in users:
            peer = self.peers.get(u["username"])
            # Presence derives from the 5-second heartbeat: a peer is
            # online only if its last sign of life is fresh.
            u["online"] = bool(peer) and (now - peer.last_seen) <= 20
            u["last_seen"] = peer.last_seen if peer else None
            u["riding"] = self.server_label if peer else None
            u["home"] = peer.home_endpoint if peer else None
            u.pop("pubkey", None)
        return {
            "server": self.server_label,
            "online": sorted(u["username"] for u in users if u["online"]),
            "users": users,
            "groups": self.store.all_groups(),
            "work": self.store.list_work_meta(),
            "activity": self.store.list_audit(),
        }

    def _resolve_dashboard_password(self) -> str:
        if self.dashboard_password:
            return self.dashboard_password
        env = os.environ.get("AGENTLINK_DASHBOARD_PASSWORD")
        if env:
            return env
        from pathlib import Path
        pw_file = Path(os.path.expanduser("~/.agentlink/dashboard-password.txt"))
        if pw_file.exists():
            return pw_file.read_text().strip()
        import secrets as _secrets
        pw = _secrets.token_urlsafe(18)
        pw_file.parent.mkdir(parents=True, exist_ok=True)
        pw_file.write_text(pw)
        try:
            os.chmod(pw_file, 0o600)
        except OSError:
            pass
        log.warning("dashboard password generated; stored at %s", pw_file)
        return pw

    async def start(self) -> "Relay":
        self._server = await serve(
            self._handle, self.host, self.port, max_size=MAX_FRAME,
        )
        if self.dashboard_enabled:
            from .dashboard import DashboardServer
            password = self._resolve_dashboard_password()
            dash_host = self.host
            self.dashboard = DashboardServer(
                self, dash_host, self.dashboard_port, password).start()
            self.dashboard_port = self.dashboard.port
        sockets = self._server.sockets or ()
        if sockets:
            self.port = sockets[0].getsockname()[1]
        log.info("relay listening on %s:%s", self.host, self.port)
        return self

    async def stop(self) -> None:
        if getattr(self, "dashboard", None) is not None:
            self.dashboard.stop()
            self.dashboard = None
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
                if peer is not None:
                    peer.last_seen = now_ts()
                if ftype == "hello":
                    peer = await self._on_hello(ws, frame, peer)
                elif ftype == "ping":
                    if peer is not None:
                        peer.last_seen = now_ts()
                    await self._send(ws, {"type": "pong", "req_id": req_id})
                elif peer is None:
                    await self._error(ws, "not_registered", req_id)
                elif ftype == "blob_put":
                    await self._on_blob_put(ws, frame, peer)
                elif ftype == "blob_get":
                    await self._on_blob_get(ws, frame, peer)
                elif ftype == "blob_delete":
                    await self._on_blob_delete(ws, frame, peer)
                elif ftype == "send":
                    await self._on_send(ws, frame, peer)
                elif ftype == "group_create":
                    await self._on_group_create(ws, frame, peer)
                elif ftype == "group_add":
                    await self._on_group_add(ws, frame, peer)
                elif ftype == "group_remove":
                    await self._on_group_remove(ws, frame, peer)
                elif ftype == "get_key":
                    target = normalize_username(frame.get("username"))
                    await self._result(ws, req_id, True, {
                        "username": target,
                        "pubkey": self.store.pubkey_of(target) if target else ""})
                elif ftype == "group_members":
                    await self._on_group_members(ws, frame, peer)
                elif ftype == "group_nickname":
                    await self._on_group_nickname(ws, frame, peer)
                elif ftype == "group_custom_role":
                    await self._on_group_custom_role(ws, frame, peer)
                elif ftype == "set_group_keys":
                    await self._on_set_group_keys(ws, frame, peer)
                elif ftype == "get_group_key":
                    await self._on_get_group_key(ws, frame, peer)
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
                if not peer.ephemeral:
                    self._log_activity("offline", peer.username)
                log.info("peer @%s disconnected", peer.username)

    async def _on_hello(self, ws, frame, old):
        if old is not None and self.peers.get(old.username) is old:
            del self.peers[old.username]
        req_id = frame.get("req_id")
        display = str(frame.get("display_name") or frame.get("name") or "")[:64]
        secret = frame.get("secret")
        pubkey = str(frame.get("pubkey") or "")
        if frame.get("ephemeral"):
            username = "dial-" + new_id()[:8]
            peer = Peer(ws=ws, username=username, display_name=display or "dial",
                        pubkey=pubkey, ephemeral=True, last_seen=now_ts())
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
                self.store.set_pubkey(username, pubkey)
            else:
                await self._error(ws, "username_taken", req_id)
                return None
            owner_secret = secret
        else:
            try:
                owner_secret = self.store.claim(
                    username, display or username, pubkey)
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
                    display_name=display or username, pubkey=pubkey,
                    last_seen=now_ts(),
                    home_endpoint=str(frame.get("home_endpoint") or ""))
        self.peers[username] = peer
        self._log_activity("online", username)
        queued = self.store.dequeue_all(username)
        await self._send(ws, {"type": "welcome", "req_id": req_id,
                              "username": username, "secret": owner_secret,
                              "ephemeral": False, "queued": len(queued)})
        for q in queued:
            await self._send(ws, q)
        log.info("peer @%s registered, flushed %d queued", username, len(queued))
        return peer

    # -- sealed file blobs (R2 in production; relay proxies ciphertext) -----
    async def _on_blob_put(self, ws, frame, peer: Peer) -> None:
        import base64 as _b64
        import hashlib as _hl
        req_id = frame.get("req_id")
        try:
            data = _b64.b64decode(frame.get("data_b64") or "")
        except Exception:
            await self._error(ws, "bad_blob", req_id)
            return
        if not data:
            await self._error(ws, "bad_blob", req_id, "empty blob")
            return
        for_user = normalize_username(frame.get("for_user"))
        for_group = frame.get("for_group")
        if for_group:
            if self.store.role_of(for_group, peer.username) is None:
                await self._error(ws, "not_a_member", req_id)
                return
        elif for_user:
            if not self.store.exists(for_user):
                await self._error(ws, "unknown_username", req_id, for_user)
                return
        else:
            await self._error(ws, "bad_blob", req_id,
                              "blob needs for_user or for_group")
            return
        blob_id = "b-" + _hl.sha256(data).hexdigest()
        self.blob_store.put(blob_id, data)
        self.store.put_blob_meta(blob_id, owner=peer.username,
                                 for_user=for_user or "",
                                 for_group=for_group or "",
                                 size=len(data))
        await self._result(ws, req_id, True,
                           {"blob_id": blob_id, "size": len(data)})

    def _blob_authorized(self, meta, username) -> bool:
        if meta is None:
            return False
        if username in (meta["owner"], meta.get("for_user")):
            return True
        gid = meta.get("for_group")
        return bool(gid) and self.store.role_of(gid, username) is not None

    async def _on_blob_get(self, ws, frame, peer: Peer) -> None:
        import base64 as _b64
        req_id = frame.get("req_id")
        meta = self.store.get_blob_meta(str(frame.get("blob_id") or ""))
        if not self._blob_authorized(meta, peer.username):
            await self._error(ws, "permission_denied", req_id,
                              "not a recipient of this blob")
            return
        from .blobstore import BlobNotFound
        try:
            data = self.blob_store.get(meta["id"])
        except BlobNotFound:
            await self._error(ws, "unknown_blob", req_id)
            return
        await self._result(ws, req_id, True,
                           {"blob_id": meta["id"],
                            "data_b64": _b64.b64encode(data).decode()})

    async def _on_blob_delete(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        meta = self.store.get_blob_meta(str(frame.get("blob_id") or ""))
        if meta is None:
            await self._error(ws, "unknown_blob", req_id)
            return
        allowed = peer.username == meta["owner"]
        gid = meta.get("for_group")
        if gid and self.store.role_of(gid, peer.username) in ADMIN_ROLES:
            allowed = True
        if not allowed:
            await self._error(ws, "permission_denied", req_id,
                              "only the owner or a group admin can delete")
            return
        self.blob_store.delete(meta["id"])
        self.store.delete_blob_meta(meta["id"])
        await self._result(ws, req_id, True, {"blob_id": meta["id"],
                                              "deleted": True})

    # -- 1:1 messages (E2EE: relay routes ciphertext only) -------------------
    @staticmethod
    def _is_envelope(content) -> bool:
        return isinstance(content, dict) and bool(content.get("ct"))

    async def _on_send(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        to = normalize_username(frame.get("to"))
        if "body" in frame or "file" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id,
                              "content must be end-to-end encrypted")
            return
        content = frame.get("content")
        if to is None or not self._is_envelope(content):
            await self._error(ws, "bad_send", req_id,
                              "missing encrypted content envelope")
            return
        if not self.store.exists(to) and to not in self.peers:
            await self._error(ws, "unknown_recipient", req_id)
            return
        msg = {"type": "message", "id": frame.get("id") or new_id(),
               "from": peer.username, "from_name": peer.display_name,
               "from_pubkey": peer.pubkey or self.store.pubkey_of(peer.username),
               "sender_nickname": "", "sender_role": "",
               "sender_custom_role": "",
               "mentions": frame.get("mentions") or [],
               "content": content, "ts": now_ts(),
               "in_reply_to": frame.get("in_reply_to"), "group_id": None}
        queued = await self._deliver(to, msg)
        self._log_activity("message", peer.username, target=to)
        await self._result(ws, req_id, True,
                           {"id": msg["id"], "to": to, "queued": queued})

    # -- groups ---------------------------------------------------------------
    def _group_or_error(self, ws, frame, peer):
        gid = frame.get("group_id")
        group = self.store.get_group(gid) if gid else None
        return gid, group

    async def _membership_event(self, group, event, actor, target,
                                targets=None):
        frame = {"type": "group_event", "id": new_id(), "group_id": group["id"],
                 "group_name": group["name"], "event": event, "actor": actor,
                 "target": target, "targets": targets or ([target] if target else []),
                 "ts": now_ts(),
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
        try:
            for u in members:
                self.store.add_member(gid, u, role="member",
                                      added_by=peer.username)
        except GroupFull:
            await self._error(ws, "group_full", req_id,
                              "groups are capped at 50 agents")
            return
        group = self.store.get_group(gid)
        if members:
            await self._membership_event(group, "added_to_group",
                                         peer.username, None, targets=members)
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
            try:
                if self.store.add_member(gid, u, role="member",
                                         added_by=peer.username):
                    added.append(u)
            except GroupFull:
                await self._error(ws, "group_full", req_id,
                                  "groups are capped at 50 agents")
                return
        if added:
            await self._membership_event(group, "added_to_group",
                                         peer.username, None, targets=added)
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
        try:
            self.store.add_member(gid, peer.username, role="member",
                                  added_by="invite-link")
        except GroupFull:
            await self._error(ws, "group_full", req_id,
                              "groups are capped at 50 agents")
            return
        await self._membership_event(group, "joined_group",
                                     peer.username, peer.username)
        await self._result(ws, req_id, True,
                           {"group_id": gid,
                            "members": self.store.members(gid)})

    async def _on_group_nickname(self, ws, frame, peer: Peer) -> None:
        """Group-local nickname: a member sets their own, an admin can
        set anyone's. The global username/display name never changes."""
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        target = normalize_username(frame.get("username")) or peer.username
        role = self.store.role_of(gid, peer.username)
        if role is None or self.store.role_of(gid, target) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if target != peer.username and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can set other members' nicknames")
            return
        self.store.set_nickname(gid, target, str(frame.get("nickname") or ""))
        await self._result(ws, req_id, True,
                           {"group_id": gid, "username": target,
                            "members": self.store.members(gid)})

    async def _on_group_custom_role(self, ws, frame, peer: Peer) -> None:
        """Custom per-group role label (e.g. Researcher, Collator).
        This is a label, separate from the admin/member permission role."""
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        target = normalize_username(frame.get("username"))
        if self.store.role_of(gid, peer.username) not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can set custom roles")
            return
        if target is None or self.store.role_of(gid, target) is None:
            await self._error(ws, "not_a_member", req_id, str(target))
            return
        self.store.set_custom_role(gid, target,
                                   str(frame.get("custom_role") or ""))
        await self._result(ws, req_id, True,
                           {"group_id": gid, "username": target,
                            "members": self.store.members(gid)})

    async def _on_set_group_keys(self, ws, frame, peer: Peer) -> None:
        """Store wrapped group keys (ciphertext the relay cannot unwrap)
        and forward each member their wrapped copy."""
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can distribute group keys")
            return
        epoch = int(frame.get("epoch") or 1)
        wrapped_map = frame.get("wrapped") or {}
        for raw_user, wrapped in wrapped_map.items():
            u = normalize_username(raw_user)
            if u is None or self.store.role_of(gid, u) is None:
                continue
            self.store.set_group_key(gid, u, epoch, wrapped)
            if u != peer.username:
                await self._deliver(u, {
                    "type": "group_key", "group_id": gid, "epoch": epoch,
                    "wrapped": wrapped, "from": peer.username,
                    "from_pubkey": peer.pubkey
                    or self.store.pubkey_of(peer.username)})
        await self._result(ws, req_id, True, {"group_id": gid, "epoch": epoch})

    async def _on_get_group_key(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid = frame.get("group_id")
        if not gid or self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        rec = self.store.group_key_for(gid, peer.username)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "key": rec})

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
        if "body" in frame or "file" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id,
                              "content must be end-to-end encrypted")
            return
        content = frame.get("content")
        if not self._is_envelope(content):
            await self._error(ws, "bad_send", req_id,
                              "missing encrypted content envelope")
            return
        msg = {"type": "message", "id": frame.get("id") or new_id(),
               "from": peer.username, "from_name": peer.display_name,
               "from_pubkey": peer.pubkey or self.store.pubkey_of(peer.username),
               "sender_nickname": next(
                   (m["nickname"] for m in self.store.members(gid)
                    if m["username"] == peer.username), ""),
               "sender_role": role,
               "sender_custom_role": next(
                   (m["custom_role"] for m in self.store.members(gid)
                    if m["username"] == peer.username), ""),
               "mentions": frame.get("mentions") or [],
               "content": content, "ts": now_ts(),
               "in_reply_to": frame.get("in_reply_to"), "group_id": gid,
               "group_name": group["name"]}
        delivered, queued = [], []
        for m in self.store.members(gid):
            if m["username"] == peer.username:
                continue
            (queued if await self._deliver(m["username"], dict(msg))
             else delivered).append(m["username"])
        self._log_activity("group_message", peer.username, group_id=gid)
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
        # E2EE: per-assignee content envelopes, prepared by the client.
        envelopes = frame.get("envelopes") or {}
        if "title" in frame or "instructions" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id,
                              "work content must be end-to-end encrypted")
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
            pair = envelopes.get(assignee) or {}
            if not self._is_envelope(pair.get("enc")):
                await self._error(ws, "bad_assign", req_id,
                                  f"missing encrypted content for {assignee}")
                return
            work = self.store.create_work(
                assigner=peer.username, assignee=assignee, group_id=gid,
                content_enc=pair["enc"],
                content_self=pair.get("self") or pair["enc"],
                deadline=frame.get("deadline"))
            created.append(work)
            await self._deliver(assignee,
                                {"type": "work_assigned", "work": work})
            self._log_activity("work_assigned", peer.username,
                               target=assignee, group_id=gid or "",
                               work_id=work["id"], status="assigned")
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
        content_enc = frame.get("content_enc")
        content_self = frame.get("content_self")
        if "body" in frame or "files" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id,
                              "deliveries must be end-to-end encrypted")
            return
        if not self._is_envelope(content_enc):
            await self._error(ws, "bad_delivery", req_id,
                              "missing encrypted delivery content")
            return
        updated = self.store.add_delivery(work["id"], peer.username,
                                          content_enc,
                                          content_self or content_enc)
        # Delivery goes back through the SAME line to the assigner.
        await self._deliver(work["assigner"],
                            {"type": "work_update", "work": updated})
        self._log_activity("work_delivered", peer.username,
                           target=work["assigner"], work_id=work["id"],
                           status="delivered")
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
        self._log_activity("work_" + status, peer.username,
                           target=work["assignee"], work_id=work["id"],
                           status=status)
        await self._deliver(work["assignee"],
                            {"type": "work_update", "work": updated,
                             "note": frame.get("note")})
        await self._result(ws, req_id, True, {"work": updated})


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Run the AgentLink relay server.")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--db", default="~/.agentlink/relay.db")
    ap.add_argument("--backend", default=None,
                    help="sqlite (default) | supabase (production; needs"
                         " SUPABASE_URL + SUPABASE_SERVICE_KEY)")
    ap.add_argument("--dashboard-port", type=int, default=8766)
    ap.add_argument("--name", default=None, dest="server_name",
                    help="label for this server (shown on the dashboard)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    async def _run() -> None:
        store = None
        if args.backend:
            from .backend import create_store
            store = create_store(args.backend, db_path=args.db)
        relay = Relay(host=args.host, port=args.port, db_path=args.db,
                      backend_store=store, dashboard_port=args.dashboard_port,
                      server_name=args.server_name)
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
