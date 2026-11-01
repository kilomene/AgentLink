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
from .timing import (
    ALERT_OFFLINE_SECONDS,
    ALERT_REMINDER_SECONDS,
    ALERT_URGENT_SECONDS,
    OFFLINE_GRACE_SECONDS,
    REASSIGN_GRACE_SECONDS,
)
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
    activity: str = "online_idle"
    touched_at: int = 0


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
    rooms: dict = field(default_factory=dict)  # room_id -> room record
    activity: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=300))
    _server: object = field(default=None, repr=False)
    # Fleet operations (points 29, 36, 37) — operator-configurable.
    reassign_grace_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_REASSIGN_GRACE",
                       str(REASSIGN_GRACE_SECONDS))))
    alert_offline_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_ALERT_OFFLINE_SECONDS",
                       str(ALERT_OFFLINE_SECONDS))))
    alert_urgent_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_ALERT_URGENT_SECONDS",
                       str(ALERT_URGENT_SECONDS))))
    alert_reminder_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_ALERT_REMINDER_SECONDS",
                       str(ALERT_REMINDER_SECONDS))))
    alert_webhook: str = field(default_factory=lambda: os.environ.get(
        "AGENTLINK_ALERT_WEBHOOK", ""))
    _scan_task: object = field(default=None, repr=False)
    alert_chain_completed: bool = field(default_factory=lambda:
        os.environ.get("AGENTLINK_ALERT_CHAIN_COMPLETED", "1") != "0")
    chain_pause_alert_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_ALERT_CHAIN_PAUSE_SECONDS", "300")))
    _pressure_fired: set = field(default_factory=set, repr=False)
    _alert_dispatched: set = field(default_factory=set, repr=False)

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
                      status: str = "", priority: str = "",
                      size: int = 0, mentions=None, ref_id: str = "") -> None:
        """Metadata only — never content. Feeds the live dashboard.

        Evidence labelling (point 32): agent-reported claims (progress
        percents, message sends) are labelled 'claimed'; facts the
        relay itself verified (signed-proof deliveries, heartbeat
        presence, hash-checked files) are labelled 'verified'. The
        dashboard renders the two differently — a claim never displays
        as a fact."""
        claimed = kind in ("work_progress", "message", "group_message",
                           "channel_message")
        self.activity.appendleft({
            "ts": now_ts(), "kind": kind, "from": actor, "to": target,
            "group_id": group_id, "work_id": work_id, "status": status,
            "priority": priority,
            "evidence": "claimed" if claimed else "verified"})
        try:
            self.store.audit(kind, actor, target, group_id, work_id, status,
                             priority, size=size, mentions=mentions,
                             ref_id=ref_id)
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
            u["online"] = bool(peer) and \
                (now - peer.last_seen) <= OFFLINE_GRACE_SECONDS
            u["last_seen"] = peer.last_seen if peer else None
            u["riding"] = self.server_label if peer else None
            u["home"] = peer.home_endpoint if peer else None
            # NO GOING DARK (point 44c): the dashboard distinguishes
            # precisely — online at home, online via a peer, or
            # unreachable with its work protected by the backend.
            if not u["online"]:
                u["reachability"] = "unreachable — work protected"
            elif peer and peer.home_endpoint and \
                    peer.home_endpoint != self.server_label and \
                    peer.home_endpoint not in (
                        f"ws://{self.host}:{self.port}",
                        f"wss://{self.host}:{self.port}"):
                u["reachability"] = f"online (via {self.server_label})"
            else:
                u["reachability"] = "online (home)"
            u["activity_state"] = peer.activity if peer else "offline"
            u["trust_score"] = self.store.compute_trust(u["username"])
            u.pop("pubkey", None)
            u.pop("sign_pub", None)
        return {
            "server": self.server_label,
            "online": sorted(u["username"] for u in users if u["online"]),
            "users": users,
            "groups": self.store.all_groups(),
            "channels": self.store.all_channels(),
            "rooms": [
                {"id": rid, "group_id": r["group_id"],
                 "participants": sorted(r["participants"]),
                 "creator": r["creator"], "opened_at": r["opened_at"]}
                for rid, r in getattr(self, "rooms", {}).items()],
            "work": self.store.list_work_meta(),
            "alerts": self.store.list_alerts(limit=50),
            "chains": self.store.list_chains_meta(),
            "library": self.store.library_all(),
            "vault": self.store.vault_meta(),
            "conversations": self._conversations(),
            "activity": [{**row, "evidence": (
                "claimed" if row.get("kind") in (
                    "work_progress", "message", "group_message",
                    "channel_message") else "verified")}
                for row in self.store.list_audit()],
        }

    def _conversations(self) -> list[dict]:
        """Per-conversation drill-down (point 40b): every message/work
        envelope's DETAILS (id, ts, sender, kind, size, mentions,
        priority, delivery status, evidence) grouped by conversation —
        1:1 pairs and groups. Content stays sealed; this is metadata
        the relay legitimately holds."""
        rows = self.store.list_audit(500)
        convs: dict[str, dict] = {}
        for r in rows:
            if r["kind"] not in ("message", "group_message",
                                 "channel_message", "work_assigned",
                                 "work_delivered", "work_completed",
                                 "work_changes_requested", "work_progress"):
                continue
            if r["group_id"]:
                key = "group:" + r["group_id"]
                participants = []
            else:
                pair = sorted(x for x in (r["from"], r["to"]) if x)
                key = "dm:" + "|".join(pair)
                participants = pair
            c = convs.setdefault(key, {"key": key,
                                       "participants": participants,
                                       "group_id": r["group_id"] or None,
                                       "items": []})
            c["items"].append({
                "id": r.get("ref_id") or r.get("work_id") or "",
                "ts": r["ts"], "from": r["from"], "to": r["to"],
                "kind": r["kind"], "size": r.get("size", 0),
                "mentions": r.get("mentions") or [],
                "priority": r.get("priority") or "normal",
                "status": r.get("status", ""),
                "work_id": r.get("work_id", ""),
                "evidence": "claimed" if r["kind"] in (
                    "work_progress", "message", "group_message",
                    "channel_message") else "verified"})
        out = sorted(convs.values(),
                     key=lambda c: -(c["items"][0]["ts"] if c["items"]
                                     else 0))
        for c in out:
            c["items"] = list(reversed(c["items"]))
        return out

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
        self._scan_task = asyncio.create_task(self._fleet_scan_loop())
        return self

    async def stop(self) -> None:
        if self._scan_task is not None:
            self._scan_task.cancel()
            self._scan_task = None
        if getattr(self, "dashboard", None) is not None:
            self.dashboard.stop()
            self.dashboard = None
        # Force-close live peer sockets first (bounded): a relay
        # shutting down must never hang on connected clients.
        for peer in list(self.peers.values()):
            try:
                await asyncio.wait_for(peer.ws.close(), timeout=1)
            except Exception:
                try:
                    peer.ws.transport.close()
                except Exception:
                    pass
        self.peers.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # Close the store only if this relay created it — a shared
        # backend handed in by the operator (failover topology) is
        # owned by the fleet, not by one relay process.
        if self.backend_store is None:
            self.store.close()


    # -- fleet operations: reassignment, deadline pressure, alerts --------------
    def _is_alive(self, username: str, grace: int) -> bool:
        """Backend-wide presence (point 29): alive = a heartbeat landed
        SOMEWHERE (any relay sharing the backend) within the grace."""
        now = now_ts()
        peer = self.peers.get(username)
        if peer is not None and now - peer.last_seen <= grace:
            return True
        try:
            return now - self.store.last_seen_of(username) <= grace
        except Exception:
            return False

    async def _fleet_scan_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(1)
                await self._fleet_scan_once()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("fleet scan failed")

    async def _fleet_scan_once(self) -> None:
        now = now_ts()
        # Cross-relay live drain (points 16/18): frames queued via
        # ANOTHER relay sharing this backend (or while this agent was
        # between connections) are pushed to the agent on THIS relay
        # within one scan tick — real-time across the fleet, not
        # just at hello. dequeue is atomic in the store, and _deliver
        # re-queues on a dead socket, so nothing is lost or doubled.
        for username, peer in list(self.peers.items()):
            if getattr(peer, "ephemeral", False):
                continue
            try:
                queued = self.store.dequeue_all(username)
            except Exception:
                continue
            for frame in queued:
                await self._deliver(username, frame)
        grace = self.reassign_grace_seconds
        for work in self.store.open_work():
            if not work.get("auto_reassign"):
                continue
            assignee = work["assignee"]
            if self._is_alive(assignee, grace):
                continue
            last = 0
            try:
                last = self.store.last_seen_of(assignee)
            except Exception:
                pass
            peer = self.peers.get(assignee)
            if peer is not None:
                last = max(last, peer.last_seen)
            if last and now - last <= grace:
                continue
            if not last and now - work["updated_at"] <= grace:
                continue
            await self._attempt_reassign(work)
        # Deadline pressure (point 36 — Pacific instants only).
        from .deadlines import pressure_thresholds, pacific_display
        for work in self.store.open_work(
                ("assigned", "in_progress", "changes_requested")):
            deadline = work.get("deadline")
            if not deadline:
                continue
            key = (work["id"], work.get("attempt", 1))
            th = pressure_thresholds(work["created_at"], deadline)
            for name, at in (("half", th["warn_50_at"]),
                             ("late", th["warn_late_at"])):
                fkey = key + (name,)
                if now >= at and now <= deadline and \
                        fkey not in self._pressure_fired:
                    self._pressure_fired.add(fkey)
                    await self._deliver(work["assignee"], {
                        "type": "deadline_warning", "work": work,
                        "threshold": name,
                        "deadline_pt": pacific_display(deadline)})
                    self._log_activity("deadline_warning", "system",
                                       target=work["assignee"],
                                       work_id=work["id"], status=name)
            okey = key + ("overdue",)
            if now > deadline and okey not in self._pressure_fired:
                self._pressure_fired.add(okey)
                updated = self.store.escalate_work_priority(work["id"])
                await self._deliver(work["assigner"], {
                    "type": "work_overdue", "work": updated,
                    "deadline_pt": pacific_display(deadline)})
                await self._deliver(work["assignee"], {
                    "type": "work_overdue", "work": updated,
                    "deadline_pt": pacific_display(deadline)})
                self._log_activity("work_overdue", "system",
                                   target=work["assignee"],
                                   work_id=work["id"], status="overdue",
                                   priority="urgent")
        for chain in self.store.list_chains_meta():
            if chain["status"] == "paused" and chain.get("paused_since") \
                    and now - chain["paused_since"] \
                    > self.chain_pause_alert_seconds:
                alert = self.store.open_alert(
                    "chain_paused", chain["id"],
                    "chain paused on changes_requested")
                await self._dispatch_alert(alert)
        await self._alert_scan(now)

    async def _attempt_reassign(self, work: dict, forced: str = "") -> bool:
        gid = work.get("group_id")
        old = work["assignee"]
        candidate = ""
        if gid:
            members = self.store.members(gid)
            alive = [m for m in members
                     if m["username"] not in (old, work["assigner"])
                     and self._is_alive(m["username"],
                                        self.reassign_grace_seconds)]
            if forced:
                candidate = forced if any(
                    m["username"] == forced for m in alive) else ""
            else:
                role = (work.get("assignee_role") or "").lower()
                same_role = [m for m in alive
                             if (m.get("custom_role") or "").lower()
                             == role and role]
                pick = (same_role or alive)
                candidate = pick[0]["username"] if pick else ""
        if not candidate:
            if work["status"] != "awaiting_agent":
                updated = self.store.set_awaiting_agent(work["id"])
                await self._deliver(work["assigner"], {
                    "type": "work_update", "work": updated,
                    "note": "assignee unreachable; awaiting an agent"})
                self._log_activity("work_awaiting_agent", "system",
                                   target=old, group_id=gid or "",
                                   work_id=work["id"],
                                   status="awaiting_agent")
            return False
        updated = self.store.reassign_work(work["id"], candidate)
        # The replacement reads the GROUP-encrypted copy + the mirrored
        # checkpoint (checkpoints travel with the assignment, point 30).
        view = dict(updated)
        view["content_enc"] = None
        await self._deliver(candidate, {
            "type": "work_assigned", "work": view,
            "reassigned_from": old, "attempt": updated["attempt"]})
        await self._deliver(work["assigner"], {
            "type": "work_reassigned", "work": updated,
            "from": old, "to": candidate})
        await self._deliver(old, {
            "type": "work_reassigned_notice", "work_id": work["id"],
            "attempt": updated["attempt"], "to": candidate})
        self._log_activity("work_reassigned", "system", target=candidate,
                           group_id=gid or "", work_id=work["id"],
                           status=f"attempt {updated['attempt']}")
        alert = self.store.open_alert(
            "reassignment", work["id"],
            f"{old} unreachable; reassigned to {candidate}")
        await self._dispatch_alert(alert)
        return True

    # -- fleet alerts (point 37) -------------------------------------------------
    async def _dispatch_alert(self, alert: dict, reminder: bool = False):
        if alert["id"] in self._alert_dispatched and not reminder:
            return
        self._alert_dispatched.add(alert["id"])
        self._log_activity("alert", "system", target=alert["subject"],
                           status=alert["kind"])
        payload = {"alert": alert, "reminder": reminder,
                   "server": self.server_label, "ts": now_ts()}
        if self.alert_webhook:
            asyncio.create_task(self._post_webhook(payload))
        email_to = os.environ.get("AGENTLINK_ALERT_EMAIL_TO")
        if email_to and os.environ.get("AGENTLINK_SMTP_HOST"):
            asyncio.create_task(asyncio.to_thread(
                self._send_alert_email, email_to, payload))

    async def _post_webhook(self, payload: dict) -> None:
        import hashlib as _hl
        import hmac as _hm
        import urllib.request
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        secret = os.environ.get("AGENTLINK_ALERT_WEBHOOK_SECRET", "")
        if secret:
            headers["X-AgentLink-Signature"] = "sha256=" + _hm.new(
                secret.encode(), body, _hl.sha256).hexdigest()
        req = urllib.request.Request(self.alert_webhook, data=body,
                                     headers=headers, method="POST")
        try:
            await asyncio.to_thread(
                lambda: urllib.request.urlopen(req, timeout=10).read())
        except Exception:
            log.exception("alert webhook delivery failed")

    @staticmethod
    def _send_alert_email(to_addr: str, payload: dict) -> None:
        import smtplib
        from email.message import EmailMessage
        alert = payload["alert"]
        msg = EmailMessage()
        msg["Subject"] = f"[AgentLink] {alert['kind']}: {alert['subject']}"
        msg["From"] = os.environ.get("AGENTLINK_SMTP_FROM", "agentlink@localhost")
        msg["To"] = to_addr
        msg.set_content(json.dumps(payload, indent=2))
        with smtplib.SMTP(os.environ["AGENTLINK_SMTP_HOST"],
                          int(os.environ.get("AGENTLINK_SMTP_PORT", "25")),
                          timeout=15) as smtp:
            user = os.environ.get("AGENTLINK_SMTP_USER")
            if user:
                smtp.starttls()
                smtp.login(user, os.environ.get("AGENTLINK_SMTP_PASSWORD", ""))
            smtp.send_message(msg)

    async def _alert_scan(self, now: int) -> None:
        # Agent offline beyond threshold -> exactly one open alert.
        for u in self.store.list_users():
            name = u["username"]
            if name in self.peers:
                continue
            try:
                last = self.store.last_seen_of(name)
            except Exception:
                last = 0
            if last and now - last > self.alert_offline_seconds:
                alert = self.store.open_alert(
                    "agent_offline", name,
                    f"no heartbeat for {now - last}s")
                await self._dispatch_alert(alert)
        # URGENT items sitting undelivered beyond threshold.
        try:
            urgent = self.store.oldest_urgent_queued()
        except Exception:
            urgent = []
        waiting = {r["to_username"] for r in urgent
                   if now - r["since"] > self.alert_urgent_seconds}
        for name in waiting:
            alert = self.store.open_alert(
                "urgent_undelivered", name,
                "urgent item waiting in the offline queue")
            await self._dispatch_alert(alert)
        for alert in self.store.list_alerts(status="open"):
            if alert["kind"] == "urgent_undelivered" and \
                    alert["subject"] not in waiting and \
                    alert["subject"] not in {r["to_username"]
                                             for r in urgent}:
                self.store.resolve_alerts("urgent_undelivered",
                                          alert["subject"])
            # Throttled reminders for still-open incidents.
            last_touch = max(alert["created_at"],
                             alert["last_reminder_at"])
            if now - last_touch > self.alert_reminder_seconds:
                self.store.bump_reminder(alert["id"])
                await self._dispatch_alert(alert, reminder=True)

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
                        if frame.get("activity"):
                            peer.activity = str(frame["activity"])[:40]
                        if now_ts() - peer.touched_at >= 2:
                            peer.touched_at = now_ts()
                            try:
                                self.store.touch(peer.username)
                            except Exception:
                                pass
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
                        "pubkey": self.store.pubkey_of(target) if target else "",
                        "sign_pub": self.store.sign_pub_of(target)
                        if target else ""})
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
                elif ftype == "work_progress":
                    await self._on_work_progress(ws, frame, peer)
                elif ftype == "work_checkpoint":
                    await self._on_work_checkpoint(ws, frame, peer)
                elif ftype == "chain_create":
                    await self._on_chain_create(ws, frame, peer)
                elif ftype == "chain_cancel":
                    await self._on_chain_cancel(ws, frame, peer)
                elif ftype == "chain_list":
                    await self._on_chain_list(ws, frame, peer)
                elif ftype == "chain_get":
                    await self._on_chain_get(ws, frame, peer)
                elif ftype == "work_resume_failed":
                    await self._on_work_resume_failed(ws, frame, peer)
                elif ftype == "library_search":
                    await self._on_library_search(ws, frame, peer)
                elif ftype == "library_fetch":
                    await self._on_library_fetch(ws, frame, peer)
                elif ftype == "vault_add":
                    await self._on_vault_add(ws, frame, peer)
                elif ftype == "vault_list":
                    await self._on_vault_list(ws, frame, peer)
                elif ftype == "vault_pin":
                    await self._on_vault_pin(ws, frame, peer)
                elif ftype == "vault_remove":
                    await self._on_vault_remove(ws, frame, peer)
                elif ftype == "channel_create":
                    await self._on_channel_create(ws, frame, peer)
                elif ftype == "channel_add":
                    await self._on_channel_add(ws, frame, peer)
                elif ftype == "channel_remove":
                    await self._on_channel_remove(ws, frame, peer)
                elif ftype == "channel_members":
                    await self._on_channel_members(ws, frame, peer)
                elif ftype == "channel_promote":
                    await self._on_channel_role(ws, frame, peer)
                elif ftype == "channel_send":
                    await self._on_channel_send(ws, frame, peer)
                elif ftype == "channel_join_link":
                    await self._on_channel_join_link(ws, frame, peer)
                elif ftype == "channel_join":
                    await self._on_channel_join(ws, frame, peer)
                elif ftype == "set_channel_keys":
                    await self._on_set_channel_keys(ws, frame, peer)
                elif ftype == "get_channel_key":
                    await self._on_get_channel_key(ws, frame, peer)
                elif ftype == "room_open":
                    await self._on_room_open(ws, frame, peer)
                elif ftype == "room_join":
                    await self._on_room_join(ws, frame, peer)
                elif ftype == "room_leave":
                    await self._on_room_leave(ws, frame, peer)
                elif ftype == "room_close":
                    await self._on_room_close(ws, frame, peer)
                elif ftype == "room_signal":
                    await self._on_room_signal(ws, frame, peer)
                elif ftype == "blob_session_start":
                    await self._on_blob_session_start(ws, frame, peer)
                elif ftype == "blob_chunk":
                    await self._on_blob_chunk(ws, frame, peer)
                elif ftype == "blob_session_status":
                    await self._on_blob_session_status(ws, frame, peer)
                elif ftype == "blob_session_finish":
                    await self._on_blob_session_finish(ws, frame, peer)
                elif ftype == "work_action":
                    await self._on_work_action(ws, frame, peer)
                elif ftype == "work_inbox":
                    inbox = self.store.list_work(
                        peer.username, frame.get("status"), frame.get("group_id"))
                    await self._result(ws, req_id, True, {"work": inbox})
                elif ftype == "update_capabilities":
                    await self._on_update_capabilities(ws, frame, peer)
                elif ftype == "chain_context":
                    step = self.store.step_by_work(
                        str(frame.get("work_id") or ""))
                    nxt_assignees: list[str] = []
                    if step is not None:
                        chain = self.store.get_chain(step["chain_id"])
                        if chain is not None:
                            nxt = next(
                                (x for x in chain["steps"]
                                 if x["position"]
                                 == step["position"] + 1), None)
                            if nxt is not None:
                                nxt_assignees = nxt.get("assignees") or []
                    await self._result(ws, req_id, True, {
                        "chain_id": step["chain_id"] if step else "",
                        "next_assignees": nxt_assignees})
                elif ftype == "my_groups":
                    await self._result(ws, req_id, True, {
                        "groups": self.store.groups_for_user(peer.username),
                        "channels": self.store.channels_for_user(
                            peer.username)})
                elif ftype == "self_report":
                    self.store.audit("self_repair", peer.username,
                                     status=str(frame.get("event") or ""))
                    self._log_activity("self_repair", peer.username,
                                       status=str(frame.get("event") or ""))
                    await self._result(ws, req_id, True, {"ok": True})
                elif ftype == "directory":
                    users = self.store.list_users(
                        str(frame.get("query") or ""),
                        capability=str(frame.get("capability") or ""))
                    for u in users:
                        u["online"] = u["username"] in self.peers
                        u["trust_score"] = self.store.compute_trust(
                            u["username"])
                        u.pop("secret", None)
                    users.sort(key=lambda u: (not u["online"],
                                              u["username"]))
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
        sign_pub = str(frame.get("sign_pub") or "")
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
                self.store.set_sign_pub(username, sign_pub)
            else:
                await self._error(ws, "username_taken", req_id)
                return None
            owner_secret = secret
        else:
            try:
                owner_secret = self.store.claim(
                    username, display or username, pubkey, sign_pub,
                    capabilities=frame.get("capabilities") or [],
                    cap_desc=str(frame.get("cap_description") or ""))
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
        try:
            self.store.touch(username)
        except Exception:
            pass
        if self.store.resolve_alerts("agent_offline", username):
            self._log_activity("alert_resolved", "system", target=username,
                               status="agent_offline")
        self._log_activity("online", username)
        queued = self.store.dequeue_all(username)
        await self._send(ws, {"type": "welcome", "req_id": req_id,
                              "username": username, "secret": owner_secret,
                              "ephemeral": False, "queued": len(queued)})
        for q in queued:
            await self._send(ws, q)
        log.info("peer @%s registered, flushed %d queued", username, len(queued))
        # Awaiting-agent work: an agent coming online picks up pooled
        # group work immediately (point 29 fallback).
        try:
            for work in self.store.open_work(("awaiting_agent",)):
                gid = work.get("group_id")
                if gid and work["assigner"] != username and \
                        self.store.role_of(gid, username) is not None:
                    await self._attempt_reassign(work, forced=username)
        except Exception:
            log.exception("awaiting-agent pickup failed")
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
               "priority": (lambda pr: pr if pr in ("normal", "high", "urgent") else "normal")(str(frame.get("priority") or "normal")),
               "content": content, "ts": now_ts(),
               "in_reply_to": frame.get("in_reply_to"), "group_id": None}
        queued = await self._deliver(to, msg)
        msg["delivery_status"] = "queued" if queued else "live"
        self._log_activity("message", peer.username, target=to,
                           priority=msg["priority"],
                           size=len(str(content.get("ct") or "")),
                           mentions=msg["mentions"], ref_id=msg["id"])
        await self._result(ws, req_id, True,
                           {"id": msg["id"], "to": to, "queued": queued})

    # -- groups ---------------------------------------------------------------
    def _group_or_error(self, ws, frame, peer):
        gid = frame.get("group_id")
        group = self.store.get_group(gid) if gid else None
        return gid, group

    async def _membership_event(self, group, event, actor, target,
                                targets=None, extra=None):
        frame = {"type": "group_event", "id": new_id(), "group_id": group["id"],
                 "group_name": group["name"], "event": event, "actor": actor,
                 "target": target, "targets": targets or ([target] if target else []),
                 "ts": now_ts(),
                 "members": self.store.members(group["id"])}
        if extra:
            frame.update(extra)
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
        await self._membership_event(
            group, "promoted" if promote else "demoted",
            peer.username, target)
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
        await self._membership_event(group, "settings_changed",
                                     peer.username, None,
                                     extra={"settings": merged})
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
        await self._membership_event(group, "nickname_changed",
                                     peer.username, target)
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
        await self._membership_event(group, "custom_role_changed",
                                     peer.username, target)
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

    def _expand_role_mentions(self, gid: str, mentions: list) -> list:
        """A @RoleName mention expands to every current holder of that
        custom role in the group (usernames stay public metadata)."""
        out = list(mentions)
        for m in mentions:
            for holder in self.store.resolve_role(gid, str(m)):
                if holder not in out:
                    out.append(holder)
        return out

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
               "mentions": self._expand_role_mentions(
                   gid, frame.get("mentions") or []),
               "role_mentions": [m for m in (frame.get("mentions") or [])
                                 if self.store.resolve_role(gid, m)],
               "priority": (lambda pr: pr if pr in
                            ("normal", "high", "urgent") else "normal")(
                                str(frame.get("priority") or "normal")),
               "content": content, "ts": now_ts(),
               "in_reply_to": frame.get("in_reply_to"), "group_id": gid,
               "group_name": group["name"]}
        delivered, queued = [], []
        for m in self.store.members(gid):
            if m["username"] == peer.username:
                continue
            (queued if await self._deliver(m["username"], dict(msg))
             else delivered).append(m["username"])
        self._log_activity("group_message", peer.username, group_id=gid,
                           priority=msg["priority"],
                           size=len(str(content.get("ct") or "")),
                           mentions=msg["mentions"], ref_id=msg["id"])
        await self._result(ws, req_id, True,
                           {"id": msg["id"], "group_id": gid,
                            "delivered": delivered, "queued": queued})

    async def _on_update_capabilities(self, ws, frame, peer: Peer) -> None:
        """Capability updates are SIGNED with the identity (signing)
        key and verified against the registered public key — an agent
        can only ever rewrite its OWN profile (point 33)."""
        req_id = frame.get("req_id")
        caps = [str(c)[:40] for c in (frame.get("capabilities") or [])][:32]
        desc = str(frame.get("description") or "")[:200]
        canonical = "caps|{}|{}|{}".format(
            peer.username, ",".join(caps), desc).encode()
        from .crypto import Identity as _Identity
        sign_pub = self.store.sign_pub_of(peer.username)
        if not sign_pub or not _Identity.verify_signature(
                sign_pub, canonical, frame.get("sig") or ""):
            self.store.audit("capability_update_rejected", peer.username)
            await self._error(ws, "bad_signature", req_id,
                              "capability update signature did not verify")
            return
        self.store.set_capabilities(peer.username, caps, desc)
        self._log_activity("capabilities_updated", peer.username)
        await self._result(ws, req_id, True,
                           {"username": peer.username,
                            "capabilities": caps, "description": desc})

    # -- channels (broadcast: admins post, subscribers read-only) ------------
    CHANNEL_ADMIN_ROLES = ("admin", "superadmin")

    async def _channel_event(self, channel, event, actor, target,
                             targets=None):
        frame = {"type": "channel_event", "id": new_id(),
                 "channel_id": channel["id"], "channel_name": channel["name"],
                 "event": event, "actor": actor, "target": target,
                 "targets": targets or ([target] if target else []),
                 "ts": now_ts(),
                 "members": self.store.channel_members(channel["id"])}
        for m in self.store.channel_members(channel["id"]):
            if m["username"] != actor:
                await self._deliver(m["username"], dict(frame))
        return frame

    async def _on_channel_create(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        name = str(frame.get("name") or "")[:80]
        if not name:
            await self._error(ws, "bad_channel", req_id, "channel needs a name")
            return
        subs = []
        for raw in frame.get("members") or []:
            u = normalize_username(raw)
            if u is None or not self.store.exists(u):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            if u != peer.username and u not in subs:
                subs.append(u)
        from .store import GroupFull
        cid = self.store.create_channel(name, peer.username)
        try:
            for u in subs:
                self.store.add_subscriber(cid, u, added_by=peer.username)
        except GroupFull:
            await self._error(ws, "channel_full", req_id,
                              "channels are capped at 1000 subscribers")
            return
        channel = self.store.get_channel(cid)
        if subs:
            await self._channel_event(channel, "subscribed_to_channel",
                                      peer.username, None, targets=subs)
        self._log_activity("channel_created", peer.username, group_id=cid)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "name": name,
                            "members": self.store.channel_members(cid)})

    async def _on_channel_add(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        channel = self.store.get_channel(cid) if cid else None
        if channel is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) not in \
                self.CHANNEL_ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only channel admins can add subscribers")
            return
        from .store import GroupFull
        added = []
        for raw in frame.get("members") or []:
            u = normalize_username(raw)
            if u is None or not self.store.exists(u):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            try:
                if self.store.add_subscriber(cid, u,
                                             added_by=peer.username):
                    added.append(u)
            except GroupFull:
                await self._error(ws, "channel_full", req_id,
                                  "channels are capped at 1000 subscribers")
                return
        if added:
            await self._channel_event(channel, "subscribed_to_channel",
                                      peer.username, None, targets=added)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "added": added,
                            "members": self.store.channel_members(cid)})

    async def _on_channel_remove(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        channel = self.store.get_channel(cid) if cid else None
        if channel is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) not in \
                self.CHANNEL_ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only channel admins can remove subscribers")
            return
        target = normalize_username(frame.get("username"))
        if self.store.channel_role_of(cid, target) == "superadmin":
            await self._error(ws, "permission_denied", req_id,
                              "the channel creator cannot be removed")
            return
        self.store.remove_subscriber(cid, target)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "removed": target})

    async def _on_channel_members(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        channel = self.store.get_channel(cid) if cid else None
        if channel is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "name": channel["name"],
                            "members": self.store.channel_members(cid)})

    async def _on_channel_role(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        if self.store.get_channel(cid) is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) != "superadmin":
            await self._error(ws, "permission_denied", req_id,
                              "only the creator can promote channel admins")
            return
        target = normalize_username(frame.get("username"))
        if self.store.channel_role_of(cid, target) is None:
            await self._error(ws, "not_a_member", req_id, str(target))
            return
        self.store.set_channel_role(cid, target, "admin")
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "username": target,
                            "role": "admin"})

    async def _on_channel_send(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        channel = self.store.get_channel(cid) if cid else None
        if channel is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        role = self.store.channel_role_of(cid, peer.username)
        if role is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if role not in self.CHANNEL_ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "channels are read-only for subscribers")
            return
        if "body" in frame or "file" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id)
            return
        content = frame.get("content")
        if not self._is_envelope(content):
            await self._error(ws, "bad_send", req_id,
                              "missing encrypted content envelope")
            return
        msg = {"type": "message", "id": frame.get("id") or new_id(),
               "from": peer.username, "from_name": peer.display_name,
               "from_pubkey": peer.pubkey
               or self.store.pubkey_of(peer.username),
               "sender_nickname": "", "sender_role": role,
               "sender_custom_role": "",
               "mentions": frame.get("mentions") or [],
               "priority": str(frame.get("priority") or "normal"),
               "content": content, "ts": now_ts(),
               "in_reply_to": frame.get("in_reply_to"), "group_id": None,
               "channel_id": cid, "channel_name": channel["name"]}
        delivered, queued = [], []
        for m in self.store.channel_members(cid):
            if m["username"] == peer.username:
                continue
            (queued if await self._deliver(m["username"], dict(msg))
             else delivered).append(m["username"])
        self._log_activity("channel_message", peer.username, group_id=cid,
                           priority=msg["priority"],
                           size=len(str(content.get("ct") or "")),
                           mentions=msg["mentions"], ref_id=msg["id"])
        await self._result(ws, req_id, True,
                           {"id": msg["id"], "channel_id": cid,
                            "delivered": delivered, "queued": queued})

    async def _on_channel_join_link(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        if self.store.get_channel(cid) is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        token = self.store.create_invite(cid, peer.username)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "token": token,
                            "link": self.store.invite_link(cid, token)})

    async def _on_channel_join(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        token = frame.get("token")
        if token and str(token).startswith("agentlink://"):
            parsed = self.store.parse_invite_link(str(token))
            if parsed:
                cid, token = parsed
        if self.store.get_channel(cid) is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if not self.store.invite_valid(cid, token):
            await self._error(ws, "invalid_invite", req_id)
            return
        from .store import GroupFull
        try:
            self.store.add_subscriber(cid, peer.username,
                                      added_by="invite-link")
        except GroupFull:
            await self._error(ws, "channel_full", req_id)
            return
        channel = self.store.get_channel(cid)
        await self._channel_event(channel, "joined_channel",
                                  peer.username, peer.username)
        # Key provisioning hook: admins' clients wrap the channel key
        # for the new subscriber on this event (same as channel_add).
        await self._channel_event(channel, "subscribed_to_channel",
                                  peer.username, peer.username)
        await self._result(ws, req_id, True,
                           {"channel_id": cid,
                            "members": self.store.channel_members(cid)})

    async def _on_set_channel_keys(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        if self.store.get_channel(cid) is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) not in \
                self.CHANNEL_ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id)
            return
        epoch = int(frame.get("epoch") or 1)
        for raw_user, wrapped in (frame.get("wrapped") or {}).items():
            u = normalize_username(raw_user)
            if u is None or self.store.channel_role_of(cid, u) is None:
                continue
            self.store.set_channel_key(cid, u, epoch, wrapped)
            if u != peer.username:
                await self._deliver(u, {
                    "type": "channel_key", "channel_id": cid,
                    "epoch": epoch, "wrapped": wrapped,
                    "from": peer.username})
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "epoch": epoch})

    async def _on_get_channel_key(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        if not cid or self.store.channel_role_of(cid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        rec = self.store.channel_key_for(cid, peer.username)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "key": rec})

    # -- voice rooms (WebRTC signalling only; media is peer-to-peer) ----------
    async def _on_room_open(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid = frame.get("group_id")
        if not gid or self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id,
                              "voice rooms are for group members only")
            return
        rid = new_id("r-")[:14]
        self.rooms[rid] = {"group_id": gid, "creator": peer.username,
                           "participants": {peer.username},
                           "opened_at": now_ts()}
        self._log_activity("room_opened", peer.username, group_id=gid,
                           status=rid)
        await self._result(ws, req_id, True,
                           {"room_id": rid, "group_id": gid,
                            "participants": [peer.username]})

    def _room_or_error(self, frame):
        rid = frame.get("room_id")
        return rid, self.rooms.get(rid)

    async def _room_broadcast_meta(self, rid, event, actor):
        room = self.rooms.get(rid)
        if not room:
            return
        frame = {"type": "room_event", "room_id": rid, "event": event,
                 "actor": actor,
                 "participants": sorted(room["participants"]),
                 "group_id": room["group_id"], "ts": now_ts()}
        for u in list(room["participants"]):
            if u != actor:
                await self._deliver(u, dict(frame))

    async def _on_room_join(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        rid, room = self._room_or_error(frame)
        if room is None:
            await self._error(ws, "unknown_room", req_id)
            return
        if peer.ephemeral:
            pass  # dashboard browser client (operator-side, visible in
            # room metadata as its dial-* name); agents need membership
        elif self.store.role_of(room["group_id"], peer.username) is None:
            await self._error(ws, "not_a_member", req_id,
                              "voice rooms are for group members only")
            return
        room["participants"].add(peer.username)
        self._log_activity("room_joined", peer.username,
                           group_id=room["group_id"], status=rid)
        await self._room_broadcast_meta(rid, "joined", peer.username)
        await self._result(ws, req_id, True,
                           {"room_id": rid,
                            "participants": sorted(room["participants"])})

    async def _on_room_leave(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        rid, room = self._room_or_error(frame)
        if room is None:
            await self._error(ws, "unknown_room", req_id)
            return
        room["participants"].discard(peer.username)
        self._log_activity("room_left", peer.username,
                           group_id=room["group_id"], status=rid)
        await self._room_broadcast_meta(rid, "left", peer.username)
        if not room["participants"]:
            del self.rooms[rid]
            self._log_activity("room_closed", peer.username,
                               group_id=room["group_id"], status=rid)
        await self._result(ws, req_id, True, {"room_id": rid, "left": True})

    async def _on_room_close(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        rid, room = self._room_or_error(frame)
        if room is None:
            await self._error(ws, "unknown_room", req_id)
            return
        role = self.store.role_of(room["group_id"], peer.username)
        if peer.username != room["creator"] and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only the room creator or a group admin"
                              " can close the room")
            return
        await self._room_broadcast_meta(rid, "closed", peer.username)
        del self.rooms[rid]
        self._log_activity("room_closed", peer.username,
                           group_id=room["group_id"], status=rid)
        await self._result(ws, req_id, True, {"room_id": rid,
                                              "closed": True})

    async def _on_room_signal(self, ws, frame, peer: Peer) -> None:
        """Signalling (offer/answer/ICE) routed to the ADDRESSED room
        participant only. Never stored, never queued: WebRTC media is
        peer-to-peer (DTLS-SRTP); the relay never sees audio."""
        req_id = frame.get("req_id")
        rid, room = self._room_or_error(frame)
        if room is None:
            await self._error(ws, "unknown_room", req_id)
            return
        if peer.username not in room["participants"]:
            await self._error(ws, "not_in_room", req_id)
            return
        target = normalize_username(frame.get("to"))
        if target not in room["participants"]:
            await self._error(ws, "not_in_room", req_id, str(target))
            return
        target_peer = self.peers.get(target)
        if target_peer is None:
            await self._error(ws, "peer_offline", req_id)
            return
        await self._send(target_peer.ws, {
            "type": "room_signal", "room_id": rid, "from": peer.username,
            "kind": frame.get("kind"), "payload": frame.get("payload")})
        await self._result(ws, req_id, True,
                           {"room_id": rid, "to": target, "signalled": True})

    # -- resumable chunked uploads (relay proxies ciphertext to R2) -----------
    async def _on_blob_session_start(self, ws, frame, peer: Peer) -> None:
        import hashlib as _hl
        req_id = frame.get("req_id")
        whole_sha = str(frame.get("whole_sha") or "")
        ct_sha = str(frame.get("ct_sha") or "")
        for_user = normalize_username(frame.get("for_user"))
        for_group = frame.get("for_group")
        for_channel = frame.get("for_channel")
        if for_group and self.store.role_of(for_group, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if for_channel and self.store.channel_role_of(
                for_channel, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if for_user and not self.store.exists(for_user):
            await self._error(ws, "unknown_username", req_id, for_user)
            return
        # Dedup: a completed blob with this whole-file hash, from this
        # sender to this same scope, completes instantly by reference.
        existing = self.store.find_blob_by_whole_sha(
            whole_sha, owner=peer.username, for_user=for_user or "",
            for_group=for_group or "", for_channel=for_channel or "")
        if existing:
            await self._result(ws, req_id, True,
                               {"dedup": True, "blob_id": existing["id"]})
            return
        from .store import CHUNK_SIZE
        chunk_size = int(frame.get("chunk_size") or CHUNK_SIZE)
        chunk_size = max(1024, min(chunk_size, CHUNK_SIZE))
        sid = self.store.create_upload_session(
            owner=peer.username, whole_sha=whole_sha, ct_sha=ct_sha,
            size=int(frame.get("size") or 0), chunk_size=chunk_size,
            for_user=for_user or "", for_group=for_group or "",
            for_channel=for_channel or "")
        await self._result(ws, req_id, True,
                           {"dedup": False, "session_id": sid,
                            "chunk_size": chunk_size})

    async def _on_blob_chunk(self, ws, frame, peer: Peer) -> None:
        import base64 as _b64
        import hashlib as _hl
        req_id = frame.get("req_id")
        sess = self.store.get_upload_session(
            str(frame.get("session_id") or ""))
        if sess is None or sess["owner"] != peer.username:
            await self._error(ws, "unknown_session", req_id)
            return
        try:
            data = _b64.b64decode(frame.get("data_b64") or "")
        except Exception:
            await self._error(ws, "bad_chunk", req_id)
            return
        if _hl.sha256(data).hexdigest() != frame.get("chunk_sha"):
            await self._error(ws, "bad_chunk_hash", req_id,
                              "chunk sha256 mismatch; chunk rejected")
            return
        index = int(frame.get("index"))
        self.blob_store.put(f"{sess['session_id']}-{index}", data)
        have = self.store.record_chunk(sess["session_id"], index)
        await self._result(ws, req_id, True, {"have": have})

    async def _on_blob_session_status(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        sess = self.store.get_upload_session(
            str(frame.get("session_id") or ""))
        if sess is None or sess["owner"] != peer.username:
            await self._error(ws, "unknown_session", req_id)
            return
        total = (sess["size"] + sess["chunk_size"] - 1) // sess["chunk_size"] \
            if sess["size"] else 0
        have = sorted(sess["chunks"])
        missing = [i for i in range(total) if i not in have]
        await self._result(ws, req_id, True,
                           {"session_id": sess["session_id"], "have": have,
                            "missing": missing, "total": total})

    async def _on_blob_session_finish(self, ws, frame, peer: Peer) -> None:
        import hashlib as _hl
        req_id = frame.get("req_id")
        sess = self.store.get_upload_session(
            str(frame.get("session_id") or ""))
        if sess is None or sess["owner"] != peer.username:
            await self._error(ws, "unknown_session", req_id)
            return
        total = (sess["size"] + sess["chunk_size"] - 1) // sess["chunk_size"] \
            if sess["size"] else 0
        have = sorted(sess["chunks"])
        if have != list(range(total)):
            await self._error(ws, "incomplete_upload", req_id,
                              f"have {len(have)} of {total} chunks")
            return
        from .blobstore import BlobNotFound
        parts = []
        try:
            for i in range(total):
                parts.append(self.blob_store.get(f"{sess['session_id']}-{i}"))
        except BlobNotFound:
            await self._error(ws, "incomplete_upload", req_id,
                              "a chunk is missing from storage")
            return
        data = b"".join(parts)
        if _hl.sha256(data).hexdigest() != sess["ct_sha"]:
            await self._error(ws, "bad_whole_hash", req_id,
                              "assembled ciphertext hash mismatch")
            return
        blob_id = "b-" + sess["ct_sha"]
        self.blob_store.put(blob_id, data)
        self.store.put_blob_meta(
            blob_id, owner=peer.username, for_user=sess["for_user"],
            for_group=sess["for_group"], for_channel=sess["for_channel"],
            whole_sha=sess["whole_sha"], size=len(data))
        for i in range(total):
            self.blob_store.delete(f"{sess['session_id']}-{i}")
        self.store.delete_upload_session(sess["session_id"])
        self.store.audit("blob_upload_completed", peer.username,
                         sess["for_user"], sess["for_group"], blob_id, "")
        await self._result(ws, req_id, True, {"blob_id": blob_id,
                                              "size": len(data)})


    async def _on_work_checkpoint(self, ws, frame, peer: Peer) -> None:
        """Durable checkpoint mirror (point 30): the backend stores the
        E2E-encrypted checkpoint so it travels with the assignment if
        the assignee dies and the work is reassigned (point 29)."""
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        if work["assignee"] != peer.username:
            await self._error(ws, "permission_denied", req_id,
                              "only the assignee can checkpoint")
            return
        attempt = int(frame.get("attempt") or work.get("attempt") or 1)
        if attempt != int(work.get("attempt") or 1):
            await self._error(ws, "stale_attempt", req_id)
            return
        self.store.set_checkpoint(
            work["id"], attempt, peer.username,
            frame.get("content_assigner"), frame.get("content_group"))
        await self._deliver(work["assigner"], {
            "type": "work_checkpoint", "work": work,
            "content_assigner": frame.get("content_assigner"),
            "by": peer.username, "attempt": attempt})
        self.store.audit("work_checkpoint", peer.username,
                         work["assigner"], work["group_id"] or "",
                         work["id"], f"attempt {attempt}")
        await self._result(ws, req_id, True,
                           {"work_id": work["id"], "attempt": attempt})

    async def _on_work_resume_failed(self, ws, frame, peer: Peer) -> None:
        """A handler that cannot resume a checkpoint says so EXPLICITLY
        (point 30) — it never silently restarts from zero."""
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        self.store.audit("resume_failed", peer.username,
                         work["assigner"], work["group_id"] or "",
                         work["id"], str(frame.get("reason") or ""))
        self._log_activity("resume_failed", peer.username,
                           target=work["assigner"], work_id=work["id"],
                           status="explicit")
        await self._deliver(work["assigner"], {
            "type": "work_update", "work": work,
            "note": "assignee reported resume_failed"})
        await self._result(ws, req_id, True, {"work_id": work["id"]})

    # -- delivery library (point 38a) ---------------------------------------------
    async def _on_library_search(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        rows = self.store.search_library(
            peer.username, q=str(frame.get("q") or ""),
            sender=str(frame.get("sender") or ""),
            group_id=str(frame.get("group_id") or ""),
            hash_prefix=str(frame.get("hash_prefix") or ""))
        await self._result(ws, req_id, True, {"entries": rows})

    async def _on_library_fetch(self, ws, frame, peer: Peer) -> None:
        """Fetch a library deliverable THROUGH THE LINE with the same
        entitlement checks: only the deliverer, the assigner, or an
        entitled group member gets the (still encrypted) payload."""
        req_id = frame.get("req_id")
        entry = self.store.library_entry(str(frame.get("library_id")
                                             or ""))
        if entry is None:
            await self._error(ws, "unknown_library_entry", req_id)
            return
        work = self.store.get_work(entry["work_id"])
        entitled = (
            peer.username in (entry["sender"], entry["to_user"]) or
            entry.get("chain_next") == peer.username or
            (entry["group_id"] and self.store.role_of(
                entry["group_id"], peer.username) is not None))
        if not entitled or work is None:
            await self._error(ws, "permission_denied", req_id,
                              "not entitled to this delivery")
            return
        delivery = next((d for d in work.get("deliveries", [])
                         if d["id"] == entry["delivery_id"]), None)
        if delivery is None:
            await self._error(ws, "unknown_library_entry", req_id)
            return
        if peer.username == entry["to_user"]:
            content = delivery.get("content_enc")
        elif peer.username == entry["sender"]:
            content = delivery.get("content_self")
        elif entry.get("chain_next") == peer.username:
            # Chain handoff copy, encrypted to THIS assignee by the
            # delivering client at delivery time (point 41c).
            content = (delivery.get("content_next") or {}).get(
                peer.username)
        else:
            content = delivery.get("content_group")
        await self._result(ws, req_id, True,
                           {"entry": entry, "content": content})

    # -- group vault (point 38b) ------------------------------------------------------
    async def _on_vault_add(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        if role is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if group["settings"].get("vault_add") == "admins_only" \
                and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can add to this group's vault")
            return
        descriptor = frame.get("descriptor") or {}
        if not descriptor.get("blob_id"):
            await self._error(ws, "bad_vault_file", req_id,
                              "descriptor needs a blob_id")
            return
        entry = self.store.vault_add(gid, descriptor, peer.username,
                                     pinned=bool(frame.get("pinned")))
        self._log_activity("vault_added", peer.username, group_id=gid,
                           status=descriptor.get("name", ""))
        await self._result(ws, req_id, True, {"entry": entry})

    async def _on_vault_list(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        await self._result(ws, req_id, True,
                           {"group_id": gid,
                            "files": self.store.vault_list(gid)})

    async def _on_vault_pin(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        entry = self.store.vault_entry(str(frame.get("vault_id") or ""))
        if entry is None:
            await self._error(ws, "unknown_vault_entry", req_id)
            return
        role = self.store.role_of(entry["group_id"], peer.username)
        if role is None or (peer.username != entry["added_by"]
                            and role not in ADMIN_ROLES):
            await self._error(ws, "permission_denied", req_id)
            return
        updated = self.store.vault_set_pinned(
            entry["id"], bool(frame.get("pinned")))
        await self._result(ws, req_id, True, {"entry": updated})

    async def _on_vault_remove(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        entry = self.store.vault_entry(str(frame.get("vault_id") or ""))
        if entry is None:
            await self._error(ws, "unknown_vault_entry", req_id)
            return
        role = self.store.role_of(entry["group_id"], peer.username)
        if role is None or (peer.username != entry["added_by"]
                            and role not in ADMIN_ROLES):
            await self._error(ws, "permission_denied", req_id)
            return
        self.store.vault_remove(entry["id"])
        await self._result(ws, req_id, True,
                           {"vault_id": entry["id"], "removed": True})


    # -- work chains (point 41) -----------------------------------------------------
    async def _release_step(self, chain: dict, step: dict) -> None:
        """Release a pending step: create its work row(s) from the
        PRE-CREATED envelopes and push-dispatch instantly."""
        gid = step.get("group_id") or chain.get("group_id") or None
        assignees = list(step.get("assignees") or [])
        envelopes = step.get("envelopes") or {}
        if step.get("target_type") == "member":
            # 'a member of the group': first alive non-creator member.
            members = self.store.members(gid) if gid else []
            pick = next((m["username"] for m in members
                         if m["username"] != chain["creator"]
                         and self._is_alive(m["username"], 60)), "")
            if not pick and members:
                pick = next((m["username"] for m in members
                             if m["username"] != chain["creator"]), "")
            assignees = [pick] if pick else []
        batch_id = new_id("batch-")[:20] if len(assignees) > 1 else None
        first_work = None
        for assignee in assignees:
            pair = envelopes.get(assignee) or {}
            role = ""
            if gid:
                mrow = next((m for m in self.store.members(gid)
                             if m["username"] == assignee), None)
                role = (mrow or {}).get("custom_role") or ""
            work = self.store.create_work(
                assigner=chain["creator"], assignee=assignee,
                group_id=gid,
                content_enc=pair.get("enc") or {},
                content_self=pair.get("self") or pair.get("enc") or {},
                deadline=step.get("deadline"), batch_id=batch_id,
                priority=step.get("priority", "normal"),
                auto_reassign=True, assignee_role=role,
                content_group=step.get("content_group"),
                chain_id=chain["id"], chain_step=step["position"])
            view = dict(work)
            view["prev_deliverables"] = step.get("handoff") or []
            await self._deliver(assignee, {
                "type": "work_assigned", "work": view,
                "chain_id": chain["id"], "chain_step": step["position"]})
            if first_work is None:
                first_work = work
        if first_work is not None:
            self.store.set_step_status(step["id"], "active",
                                       work_id=first_work["id"])
            self._log_activity("chain_step_released", chain["creator"],
                               group_id=gid or "", work_id=first_work["id"],
                               status=f"step {step['position']}")

    async def _on_chain_create(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        steps = frame.get("steps") or []
        if not steps:
            await self._error(ws, "bad_chain", req_id,
                              "a chain needs at least one step")
            return
        gid = frame.get("group_id")
        if gid:
            if self.store.get_group(gid) is None:
                await self._error(ws, "unknown_group", req_id)
                return
            if self.store.role_of(gid, peer.username) is None:
                await self._error(ws, "not_a_member", req_id)
                return
        for st in steps:
            for a in st.get("assignees") or []:
                if not self.store.exists(a):
                    await self._error(ws, "unknown_username", req_id, a)
                    return
        from .deadlines import parse_deadline
        for st in steps:
            st["deadline"] = parse_deadline(st.get("deadline"))
        chain = self.store.create_chain(
            peer.username, gid or "", str(frame.get("name") or ""), steps)
        first = chain["steps"][0]
        await self._release_step(chain, first)
        self._log_activity("chain_created", peer.username,
                           group_id=gid or "", status=chain["id"])
        await self._result(ws, req_id, True,
                           {"chain": self.store.get_chain(chain["id"])})

    async def _advance_chain(self, work: dict) -> None:
        """Trigger = VERIFIED + ACCEPTED delivery only: this runs from
        the complete action, which itself requires status 'delivered'
        (reachable only with a valid signed proof). A cancelled chain
        NEVER advances, even if a trigger is faked later."""
        chain = self.store.get_chain(work["chain_id"])
        if chain is None or chain["status"] not in ("running", "paused"):
            return
        step = self.store.step_by_work(work["id"])
        if step is None or step["status"] == "completed":
            return
        self.store.set_step_status(step["id"], "completed")
        entries = self.store.library_for_work(work["id"])
        handoff = [{"library_id": e["id"], "filename": e["filename"],
                    "sha256": e["sha256"], "size": e["size"],
                    "sender": e["sender"]} for e in entries]
        nxt = next((s for s in chain["steps"]
                    if s["position"] == step["position"] + 1), None)
        if nxt is None:
            self.store.set_chain_status(chain["id"], "completed")
            self.store.resolve_alerts("chain_paused", chain["id"])
            await self._deliver(chain["creator"], {
                "type": "chain_event", "event": "completed",
                "chain_id": chain["id"]})
            self._log_activity("chain_completed", chain["creator"],
                               group_id=chain["group_id"],
                               status=chain["id"])
            if self.alert_chain_completed:
                alert = self.store.open_alert(
                    "chain_completed", chain["id"],
                    "chain finished all steps")
                await self._dispatch_alert(alert)
            return
        self.store.set_step_handoff(nxt["id"], handoff,
                                    nxt.get("assignees") or [])
        if chain["status"] == "paused":
            self.store.set_chain_status(chain["id"], "running")
            self.store.resolve_alerts("chain_paused", chain["id"])
        fresh = self.store.get_chain(chain["id"])
        nxt_fresh = next(s for s in fresh["steps"]
                         if s["id"] == nxt["id"])
        await self._release_step(fresh, nxt_fresh)

    async def _on_chain_cancel(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        chain = self.store.get_chain(str(frame.get("chain_id") or ""))
        if chain is None:
            await self._error(ws, "unknown_chain", req_id)
            return
        is_admin = chain.get("group_id") and self.store.role_of(
            chain["group_id"], peer.username) in ADMIN_ROLES
        if peer.username != chain["creator"] and not is_admin:
            await self._error(ws, "permission_denied", req_id,
                              "only the chain creator (or a group admin)"
                              " can cancel a chain")
            return
        if chain["status"] in ("completed", "cancelled"):
            await self._error(ws, "bad_status", req_id,
                              f"chain is {chain['status']}")
            return
        self.store.set_chain_status(chain["id"], "cancelled")
        involved = {chain["creator"]}
        for st in chain["steps"]:
            if st["status"] == "pending":
                self.store.set_step_status(st["id"], "cancelled")
            involved.update(st.get("assignees") or [])
            if st.get("work_id"):
                w = self.store.get_work(st["work_id"])
                if w:
                    involved.add(w["assignee"])
        for user in involved:
            if user != peer.username:
                await self._deliver(user, {
                    "type": "chain_event", "event": "cancelled",
                    "chain_id": chain["id"], "by": peer.username})
        self._log_activity("chain_cancelled", peer.username,
                           group_id=chain["group_id"], status=chain["id"])
        await self._result(ws, req_id, True,
                           {"chain": self.store.get_chain(chain["id"])})

    async def _on_chain_list(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        await self._result(ws, req_id, True,
                           {"chains": self.store.chains_for_user(
                               peer.username)})

    async def _on_chain_get(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        chain = self.store.get_chain(str(frame.get("chain_id") or ""))
        if chain is None:
            await self._error(ws, "unknown_chain", req_id)
            return
        involved = {chain["creator"]}
        for st in chain["steps"]:
            involved.update(st.get("assignees") or [])
        if peer.username not in involved and not (
                chain.get("group_id") and self.store.role_of(
                    chain["group_id"], peer.username)):
            await self._error(ws, "permission_denied", req_id)
            return
        meta = next((c for c in self.store.list_chains_meta()
                     if c["id"] == chain["id"]), chain)
        await self._result(ws, req_id, True, {"chain": meta})


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
        # Assign-by-role: the relay re-resolves the role server-side so
        # the assignee set is exactly the current holders.
        target_role = frame.get("target_role")
        batch_id = None
        if target_role:
            if not gid:
                await self._error(ws, "bad_assign", req_id,
                                  "role assignment needs a group")
                return
            holders = self.store.resolve_role(gid, str(target_role))
            if not holders:
                await self._error(ws, "empty_role", req_id,
                                  f"nobody in this group holds the role"
                                  f" '{target_role}'")
                return
            requested = sorted(normalize_username(a) or "" for a in
                               frame.get("assignees") or [])
            if requested != sorted(holders):
                await self._error(ws, "role_mismatch", req_id,
                                  "assignees must be exactly the current"
                                  " role holders")
                return
            batch_id = new_id("batch-")[:20]
        priority = str(frame.get("priority") or "normal")
        if priority not in ("normal", "high", "urgent"):
            priority = "normal"
        from .deadlines import parse_deadline
        deadline = parse_deadline(frame.get("deadline"))
        auto_reassign = frame.get("auto_reassign")
        if auto_reassign is None:
            auto_reassign = True  # default ON (group and 1:1 alike)
        content_group = frame.get("content_group")
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
            assignee_role = ""
            if gid:
                mrow = next((m for m in self.store.members(gid)
                             if m["username"] == assignee), None)
                assignee_role = (mrow or {}).get("custom_role") or ""
            work = self.store.create_work(
                assigner=peer.username, assignee=assignee, group_id=gid,
                content_enc=pair["enc"],
                content_self=pair.get("self") or pair["enc"],
                deadline=deadline, batch_id=batch_id,
                priority=priority, auto_reassign=bool(auto_reassign),
                assignee_role=assignee_role,
                content_group=content_group)
            created.append(work)
            await self._deliver(assignee,
                                {"type": "work_assigned", "work": work})
            self._log_activity("work_assigned", peer.username,
                               target=assignee, group_id=gid or "",
                               work_id=work["id"], status="assigned",
                               priority=priority)
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
        attempt = frame.get("attempt")
        if attempt is not None and int(attempt) != int(
                work.get("attempt") or 1):
            self.store.audit("stale_attempt_delivery", peer.username,
                             work["assigner"], work["group_id"] or "",
                             work["id"], f"attempt {attempt}")
            await self._error(ws, "stale_attempt", req_id,
                              "this assignment was reassigned; attempt"
                              f" {attempt} is closed")
            return
        if work["status"] not in ("assigned", "in_progress",
                                  "changes_requested"):
            await self._error(ws, "bad_status", req_id,
                              f"work is {work['status']}, cannot deliver")
            return
        # Signed delivery proof (Ed25519): canonical payload is
        # work_id|content_hash|timestamp|deliverer, verified against
        # the deliverer's REGISTERED signing public key. The verdict
        # goes to the audit log either way; a bad proof is rejected.
        proof = frame.get("proof") or {}
        from .crypto import Identity as _Identity
        canonical = "{}|{}|{}|{}".format(
            work["id"], proof.get("hash", ""), proof.get("ts", ""),
            peer.username).encode()
        sign_pub = self.store.sign_pub_of(peer.username)
        verified = bool(proof.get("sig")) and bool(sign_pub) and \
            _Identity.verify_signature(sign_pub, canonical,
                                       proof.get("sig", ""))
        self.store.audit("delivery_proof_verified", peer.username,
                         work["assigner"], work["group_id"] or "",
                         work["id"], "true" if verified else "false")
        if getattr(self, "dashboard", None) is not None:
            self.dashboard.notify()
        if not verified:
            await self._error(ws, "bad_proof", req_id,
                              "delivery signature did not verify")
            return
        proof = {**proof, "verified": True}
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
        updated = self.store.add_delivery(
            work["id"], peer.username, content_enc,
            content_self or content_enc, proof=proof,
            content_group=frame.get("content_group"),
            content_next=frame.get("content_next"))
        # Delivery library index (point 38a): METADATA the deliverer
        # supplies in the clear envelope (filename/size/sha256) — the
        # content itself stays sealed ciphertext.
        library_files = frame.get("library") or []
        if library_files and updated.get("deliveries"):
            self.store.add_library_entries(
                updated["deliveries"][-1]["id"], updated, library_files)
        self.store.resolve_alerts("reassignment", work["id"])
        # Delivery goes back through the SAME line to the assigner.
        await self._deliver(work["assigner"],
                            {"type": "work_update", "work": updated})
        self._log_activity("work_delivered", peer.username,
                           target=work["assigner"], work_id=work["id"],
                           status="delivered",
                           priority=work.get("priority", "normal"))
        # Role batch: this delivery satisfies the whole batch.
        for covered in self.store.cover_batch(work.get("batch_id"),
                                              work["id"]):
            await self._deliver(covered["assignee"],
                                {"type": "work_update", "work": covered,
                                 "covered_by": work["id"]})
            await self._deliver(work["assigner"],
                                {"type": "work_update", "work": covered,
                                 "covered_by": work["id"]})
            self._log_activity("work_covered", peer.username,
                               target=covered["assignee"],
                               group_id=covered["group_id"] or "",
                               work_id=covered["id"], status="covered")
        await self._result(ws, req_id, True, {"work": updated})

    async def _on_work_progress(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        if work["assignee"] != peer.username:
            await self._error(ws, "permission_denied", req_id,
                              "only the assignee can report progress")
            return
        percent = frame.get("percent")
        if not isinstance(percent, int) or not (0 <= percent <= 100):
            await self._error(ws, "bad_percent", req_id,
                              "percent must be an integer 0-100")
            return
        if work["status"] not in ("assigned", "in_progress",
                                  "changes_requested"):
            await self._error(ws, "bad_status", req_id,
                              f"work is {work['status']}")
            return
        updated = self.store.set_work_progress(work["id"], percent)
        event = {"type": "work_progress", "work": updated,
                 "percent": percent, "ts": now_ts(),
                 "content_enc": frame.get("content_enc"),
                 "content_self": frame.get("content_self")}
        # Assigner gets the (encrypted) note; group members get the
        # live metadata event (percent is envelope metadata).
        await self._deliver(work["assigner"], dict(event))
        if work["group_id"]:
            meta = {**event, "content_enc": None, "content_self": None}
            for m in self.store.members(work["group_id"]):
                if m["username"] not in (peer.username, work["assigner"]):
                    await self._deliver(m["username"], dict(meta))
        self._log_activity("work_progress", peer.username,
                           target=work["assigner"],
                           group_id=work["group_id"] or "",
                           work_id=work["id"], status=str(percent))
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
        if work.get("chain_id"):
            if status == "changes_requested":
                # The chain PAUSES at this step until an accepted
                # re-delivery (point 41b) — a real, visible status.
                self.store.set_chain_status(work["chain_id"], "paused")
                self._log_activity("chain_paused", peer.username,
                                   group_id=work["group_id"] or "",
                                   work_id=work["id"],
                                   status=work["chain_id"])
            elif status == "completed":
                await self._advance_chain(work)
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
