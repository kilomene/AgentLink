"""AgentLink client SDK — always-online, end-to-end encrypted.

Identity is a username only. Two local secrets, both mode 0600 in
``~/.agentlink/`` and never sent anywhere except as described:

* ``secret-<username>.json`` — the relay owner-secret, presented silently
  on reconnect to reclaim the username (stops impersonation).
* ``keys-<username>.json`` — the X25519 *private* key for end-to-end
  encryption. It never leaves the disk. Only the public key is
  registered with the relay; the relay routes ciphertext only.

Handlers (decorators)::

    agent = Agent("phoenix")

    @agent.on_message
    async def handle(msg):      # rich dict: body, file, from, sender
        return "reply text"     # nickname/role, mentions, size, ...

    @agent.on_work
    async def handle_work(work):
        await agent.deliver_work(work["id"], "done", files=["out.pdf"])

    @agent.on_mention
    async def mentioned(msg):   # fired when @you or @all names you
        ...
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import logging
import os
import re
from pathlib import Path

import websockets.exceptions
from websockets.client import connect

from .config import resolve_endpoint, resolve_fallbacks
from .crypto import Identity, decrypt_with_key, encrypt_with_key, new_group_key
from .protocol import (
    MAX_FRAME,
    make_file_payload,
    new_id,
    normalize_username,
    verify_file,
)

log = logging.getLogger("agentlink.client")

DEFAULT_STATE_DIR = os.path.expanduser("~/.agentlink")

_MENTION_RE = re.compile(r"@([a-z0-9][a-z0-9._-]{0,30})", re.IGNORECASE)


def parse_mentions(body: str) -> list[str]:
    out: list[str] = []
    for m in _MENTION_RE.findall(body or ""):
        u = m.lower()
        if u not in out:
            out.append(u)
    return out


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
        fallbacks: list[str] | None = None,
        state_dir: str = DEFAULT_STATE_DIR,
        ephemeral: bool = False,
    ):
        u = normalize_username(username)
        if u is None and not ephemeral:
            raise ValueError(f"bad username {username!r}")
        self.username = u or ""
        self.display_name = display_name or self.username
        self.endpoint = resolve_endpoint(endpoint)
        # Failover, own server first: home (self.endpoint) is always
        # tried first; fallbacks are only ridden while home is down,
        # and the client migrates back home when home recovers.
        self.fallbacks = resolve_fallbacks(fallbacks)
        self.endpoints = [self.endpoint] + self.fallbacks
        self.current_endpoint: str | None = None
        self.state_dir = Path(state_dir).expanduser()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ephemeral = ephemeral
        self.identity: Identity | None = None
        if not ephemeral and self.username:
            self.identity = Identity(self.username, self.state_dir)
        self._ws = None
        self._reader: asyncio.Task | None = None
        self._message_handler = None
        self._work_handler = None
        self._group_handler = None
        self._mention_handler = None
        self._pending: dict[str, asyncio.Future] = {}
        self._reply_waiters: dict[str, asyncio.Future] = {}
        self._pubkey_cache: dict[str, str] = {}
        self._group_keys: dict[str, dict] = {}  # gid -> {epoch, key bytes}
        self._load_group_keys()
        # Rich, decrypted views (handlers and tests read these).
        self.messages: list[dict] = []
        self.group_events: list[dict] = []
        self.work_updates: list[dict] = []
        self.assigned_work: list[dict] = []
        self.mention_inbox_items: list[dict] = []

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

    def on_mention(self, fn):
        self._mention_handler = fn
        return fn

    # -- local persistence ----------------------------------------------------
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
        (self.state_dir / "current.json").write_text(json.dumps(
            {"username": self.username, "display_name": self.display_name}))

    def _group_keys_path(self) -> Path:
        return self.state_dir / f"groupkeys-{self.username}.json"

    def _load_group_keys(self) -> None:
        p = self._group_keys_path()
        if p.exists():
            try:
                for gid, rec in json.loads(p.read_text()).items():
                    self._group_keys[gid] = {
                        "epoch": rec["epoch"],
                        "key": base64.b64decode(rec["key"])}
            except Exception:
                pass

    def _store_group_key(self, gid: str, epoch: int, key: bytes) -> None:
        self._group_keys[gid] = {"epoch": epoch, "key": key}
        data = {g: {"epoch": r["epoch"],
                    "key": base64.b64encode(r["key"]).decode()}
                for g, r in self._group_keys.items()}
        p = self._group_keys_path()
        p.write_text(json.dumps(data))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    def whoami(self) -> dict:
        return {"username": self.username,
                "display_name": self.display_name,
                "endpoint": self.endpoint}

    # -- connection -------------------------------------------------------------
    async def _send_raw(self, frame: dict) -> None:
        await self._ws.send(json.dumps(frame))

    async def start(self, endpoint: str | None = None) -> str:
        if self.identity is None:  # ephemeral dial client
            self.identity = Identity.ephemeral()
        url = endpoint or self.endpoint
        self.current_endpoint = url
        self._ws = await connect(url, max_size=MAX_FRAME)
        await self._send_raw({
            "type": "hello", "username": self.username or None,
            "display_name": self.display_name,
            "pubkey": self.identity.public_key_b64,
            "secret": None if self.ephemeral else self._load_secret(),
            "ephemeral": self.ephemeral,
            "home_endpoint": self.endpoint,
        })
        while True:
            raw = await self._ws.recv()
            frame = json.loads(raw)
            if frame.get("type") == "welcome":
                self.username = frame["username"]
                if not self.ephemeral and \
                        self.identity.path is None:
                    pass
                if frame.get("secret"):
                    self._save_secret(frame["secret"])
                log.info("registered as @%s (%d queued)",
                         self.username, frame.get("queued", 0))
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
        if self._reader is not None:
            self._reader.cancel()
            self._reader = None
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

    async def serve(self) -> None:
        assert self._ws is not None, "call start() first"
        if self._reader is not None:
            try:
                await self._reader
            except asyncio.CancelledError:
                pass

    async def run(self, reconnect_delay: float = 2.0,
                  home_probe_interval: float = 10.0) -> None:
        """Always online. Heartbeat: a ping every 5 seconds, on its own
        task, independent of the message/work loop — it never stops
        while the daemon lives, and presence derives from it.

        Failover: home is tried first on every cycle. Fallbacks are
        ridden only while home is unavailable; a home-probe task checks
        home every ``home_probe_interval`` seconds while riding a
        fallback and migrates the connection back home the moment home
        answers. Because relays share one backend, queued messages and
        work follow the agent — nothing is lost or duplicated.
        """
        async def _heartbeat():
            while True:
                await asyncio.sleep(5)
                try:
                    if self._ws is not None:
                        await self._send_raw({"type": "ping"})
                except Exception:
                    return

        async def _home_probe():
            while True:
                await asyncio.sleep(home_probe_interval)
                if self.current_endpoint == self.endpoint:
                    continue
                try:
                    probe = await connect(self.endpoint, max_size=MAX_FRAME)
                    await probe.close()
                except Exception:
                    continue
                log.info("home endpoint %s recovered; migrating back",
                         self.endpoint)
                if self._ws is not None:
                    try:
                        await self._ws.close()
                    except Exception:
                        pass
                return

        while True:
            connected = False
            for url in self.endpoints:
                try:
                    await self.start(url)
                    connected = True
                    break
                except RegistrationFailed:
                    raise
                except Exception as exc:
                    log.warning("endpoint %s unavailable (%s)", url, exc)
                    continue
            if not connected:
                await asyncio.sleep(reconnect_delay)
                continue
            beats = asyncio.create_task(_heartbeat())
            probe = asyncio.create_task(_home_probe())
            try:
                await self.serve()
            finally:
                beats.cancel()
                probe.cancel()
            log.warning("disconnected from %s; reconnecting (home first)",
                        self.current_endpoint)
            await asyncio.sleep(reconnect_delay)

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

    # -- keys -------------------------------------------------------------------------
    async def pubkey_of(self, username: str) -> str:
        u = normalize_username(username) or username
        if u == self.username and self.identity:
            return self.identity.public_key_b64
        if u in self._pubkey_cache:
            return self._pubkey_cache[u]
        data = await self._request({"type": "get_key", "username": u})
        pub = data.get("pubkey") or ""
        if pub:
            self._pubkey_cache[u] = pub
        return pub

    def _encrypt_obj(self, recipient_pub: str, obj: dict) -> dict:
        return self.identity.encrypt_for(
            recipient_pub, json.dumps(obj).encode())

    def _decrypt_obj(self, envelope: dict) -> dict:
        return json.loads(self.identity.decrypt_envelope(envelope))

    # -- dispatch ------------------------------------------------------------------------
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
            # Spawned: processing may fetch group keys / pubkeys, whose
            # results this same read loop must deliver.
            asyncio.create_task(self._process_message(frame))
            return
        if ftype == "group_key":
            try:
                key = self.identity.unwrap_key(frame["wrapped"])
                self._store_group_key(frame["group_id"],
                                      int(frame["epoch"]), key)
            except Exception:
                log.exception("failed to unwrap group key")
            return
        if ftype == "group_event":
            self.group_events.append(frame)
            if self._group_handler is not None:
                asyncio.create_task(self._run_simple_handler(
                    self._group_handler, frame))
            asyncio.create_task(self._maybe_provision_keys(frame))
            return
        if ftype == "work_assigned":
            asyncio.create_task(self._process_work(frame.get("work") or {},
                                                   assigned=True))
            return
        if ftype == "work_update":
            asyncio.create_task(self._process_work(frame.get("work") or {},
                                                   assigned=False))
            return

    async def _maybe_provision_keys(self, event: dict) -> None:
        """If I am an admin of this group and hold its key, wrap it for
        newly added/joined members (e.g. invite-link joins)."""
        if event.get("event") not in ("added_to_group", "joined_group"):
            return
        gid = event.get("group_id")
        rec = self._group_keys.get(gid)
        if rec is None:
            return
        my_role = next((m["role"] for m in event.get("members", [])
                        if m["username"] == self.username), None)
        if my_role not in ("admin", "superadmin"):
            return
        targets = [t for t in event.get("targets") or []
                   if t and t != self.username]
        if not targets:
            return
        try:
            wrapped = {}
            for t in targets:
                pub = await self.pubkey_of(t)
                if pub:
                    wrapped[t] = self.identity.wrap_key(pub, rec["key"])
            if wrapped:
                await self._request({"type": "set_group_keys",
                                     "group_id": gid, "epoch": rec["epoch"],
                                     "wrapped": wrapped})
        except Exception:
            log.exception("group key provisioning failed")

    # -- messages ---------------------------------------------------------------------------
    async def _ensure_group_key(self, gid: str) -> dict | None:
        rec = self._group_keys.get(gid)
        if rec:
            return rec
        try:
            data = await self._request({"type": "get_group_key",
                                        "group_id": gid})
        except Exception:
            return None
        key_rec = data.get("key")
        if not key_rec:
            return None
        try:
            key = self.identity.unwrap_key(key_rec["wrapped"])
        except Exception:
            return None
        self._store_group_key(gid, int(key_rec["epoch"]), key)
        return self._group_keys[gid]

    async def _process_message(self, frame: dict) -> None:
        try:
            if frame.get("group_id"):
                rec = await self._ensure_group_key(frame["group_id"])
                if rec is None:
                    log.warning("no group key for %s; cannot decrypt",
                                frame["group_id"])
                    return
                payload = json.loads(decrypt_with_key(
                    rec["key"], frame["content"]))
                to = frame["group_id"]
            else:
                payload = self._decrypt_obj(frame["content"])
                to = self.username
        except Exception:
            log.exception("failed to decrypt message %s", frame.get("id"))
            return
        if frame.get("from_pubkey"):
            self._pubkey_cache[frame["from"]] = frame["from_pubkey"]
        file_payload = payload.get("file")
        if file_payload and file_payload.get("blob_id"):
            try:
                file_payload = await self._resolve_blob_file(
                    file_payload, frame)
            except Exception:
                log.exception("failed to fetch/decrypt blob file")
                return
            payload["file"] = file_payload
        if file_payload and not verify_file(file_payload):
            log.warning("dropping message %s: file hash mismatch",
                        frame.get("id"))
            return
        body = payload.get("body", "")
        msg = {
            "id": frame.get("id"),
            "from": frame.get("from"),
            "from_name": frame.get("from_name"),
            "sender_nickname": frame.get("sender_nickname") or "",
            "sender_role": frame.get("sender_role") or "",
            "sender_custom_role": frame.get("sender_custom_role") or "",
            "to": to,
            "group_id": frame.get("group_id"),
            "group_name": frame.get("group_name"),
            "ts": frame.get("ts"),
            "time": frame.get("ts"),
            "kind": payload.get("kind") or
            (file_payload or {}).get("kind") or "text",
            "body": body,
            "file": file_payload,
            "size": (file_payload or {}).get("size", len(body)),
            "mentions": frame.get("mentions") or [],
            "in_reply_to": frame.get("in_reply_to"),
            "delivery_status": "queued" if frame.get("queued") else "live",
            "queued": bool(frame.get("queued")),
            "encrypted": True,
        }
        self.messages.append(msg)
        waiter = self._reply_waiters.pop(msg["in_reply_to"], None) \
            if msg["in_reply_to"] else None
        if waiter is not None and not waiter.done():
            waiter.set_result(msg)
        mentions = msg["mentions"]
        if self.username in mentions or \
                ("all" in mentions and msg["group_id"]):
            self.mention_inbox_items.append(msg)
            if self._mention_handler is not None:
                asyncio.create_task(self._run_simple_handler(
                    self._mention_handler, msg))
        if self._message_handler is not None:
            asyncio.create_task(self._run_message_handler(
                self._message_handler, msg))

    async def _run_message_handler(self, handler, msg: dict) -> None:
        try:
            result = handler(msg)
            if inspect.isawaitable(result):
                result = await result
        except Exception:
            log.exception("on_message handler failed")
            return
        if result:
            try:
                if msg.get("group_id"):
                    await self.group_send(msg["group_id"], str(result),
                                          in_reply_to=msg.get("id"))
                else:
                    await self.send_message(msg["from"], str(result),
                                            in_reply_to=msg.get("id"))
            except Exception:
                log.exception("sending handler reply failed")

    async def _run_simple_handler(self, handler, arg) -> None:
        try:
            r = handler(arg)
            if inspect.isawaitable(r):
                await r
        except Exception:
            log.exception("handler failed")

    async def _resolve_blob_file(self, descriptor: dict,
                                 frame: dict) -> dict:
        """Fetch a sealed blob through the relay and decrypt it.

        Scheme (see _make_blob_descriptor): the blob bytes are the raw
        ChaCha20-Poly1305 ciphertext of the file under a random file
        key; the nonce rides in the descriptor; the file key is wrapped
        to the recipient (1:1) or under the group key (groups). The
        relay only ever proxies ciphertext.
        """
        import base64 as _b64
        data = await self._request({"type": "blob_get",
                                    "blob_id": descriptor["blob_id"]})
        ct_b64 = data["data_b64"]
        if descriptor.get("wrapped_key"):
            key = self.identity.decrypt_envelope(descriptor["wrapped_key"])
        else:
            rec = await self._ensure_group_key(frame.get("group_id"))
            key = decrypt_with_key(rec["key"],
                                   descriptor["group_wrapped_key"])
        raw = decrypt_with_key(key, {"nonce": descriptor["blob_nonce"],
                                     "ct": ct_b64})
        return {"name": descriptor["name"], "kind": descriptor["kind"],
                "mime": descriptor["mime"], "size": len(raw),
                "sha256": descriptor["sha256"],
                "data_b64": _b64.b64encode(raw).decode()}

    async def _make_blob_descriptor(self, path: str, kind: str | None,
                                    for_user: str | None = None,
                                    group_id: str | None = None) -> dict:
        import hashlib
        import secrets as _secrets
        from .protocol import infer_kind
        p = Path(path)
        raw = p.read_bytes()
        file_key = _secrets.token_bytes(32)
        enc = encrypt_with_key(file_key, raw)
        import base64 as _b64
        ct_bytes = _b64.b64decode(enc["ct"])
        frame = {"type": "blob_put",
                 "data_b64": _b64.b64encode(ct_bytes).decode()}
        if group_id:
            frame["for_group"] = group_id
        else:
            frame["for_user"] = for_user
        put = await self._request(frame)
        import mimetypes as _mt
        descriptor = {
            "name": p.name, "kind": infer_kind(p, kind),
            "mime": _mt.guess_type(str(p))[0] or "application/octet-stream",
            "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "blob_id": put["blob_id"], "blob_nonce": enc["nonce"],
        }
        if group_id:
            rec = await self._ensure_group_key(group_id)
            descriptor["group_wrapped_key"] = encrypt_with_key(
                rec["key"], file_key)
        else:
            pub = await self.pubkey_of(for_user)
            descriptor["wrapped_key"] = self.identity.encrypt_for(
                pub, file_key)
        return descriptor

    async def send_message(self, to: str, body: str, kind: str = "text",
                           file: dict | None = None,
                           in_reply_to: str | None = None) -> dict:
        u = normalize_username(to) or to
        pub = await self.pubkey_of(u)
        if not pub:
            raise RequestFailed("unknown_recipient", f"no key for @{u}")
        content = self._encrypt_obj(pub, {"body": body, "kind": kind,
                                          "file": file})
        return await self._request({
            "type": "send", "to": u, "content": content, "id": new_id(),
            "mentions": parse_mentions(body), "in_reply_to": in_reply_to})

    async def send_file(self, to: str, path: str, caption: str = "",
                        kind: str | None = None,
                        via_blob: bool = False) -> dict:
        if via_blob:
            u = normalize_username(to) or to
            descriptor = await self._make_blob_descriptor(
                path, kind, for_user=u)
            return await self.send_message(to, caption,
                                           kind=descriptor["kind"],
                                           file=descriptor)
        payload = make_file_payload(path, kind)
        return await self.send_message(to, caption, kind=payload["kind"],
                                       file=payload)

    async def wait_reply(self, message_id: str, timeout: float = 15.0) -> dict:
        for m in self.messages:
            if m.get("in_reply_to") == message_id:
                return m
        fut = asyncio.get_running_loop().create_future()
        self._reply_waiters[message_id] = fut
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._reply_waiters.pop(message_id, None)

    def mention_inbox(self, group_id: str | None = None) -> list[dict]:
        items = self.mention_inbox_items
        if group_id:
            items = [m for m in items if m.get("group_id") == group_id]
        return list(items)

    # -- groups ------------------------------------------------------------------------------
    async def _distribute_group_key(self, gid: str, epoch: int, key: bytes,
                                      members: list[str]) -> None:
        wrapped = {}
        for u in members:
            if u == self.username:
                continue
            pub = await self.pubkey_of(u)
            if pub:
                wrapped[u] = self.identity.wrap_key(pub, key)
        if wrapped:
            await self._request({"type": "set_group_keys", "group_id": gid,
                                 "epoch": epoch, "wrapped": wrapped})

    async def group_create(self, name: str, members: list[str] | None = None,
                           settings: dict | None = None) -> dict:
        data = await self._request({"type": "group_create", "name": name,
                                    "members": members or [],
                                    "settings": settings})
        gid = data["group_id"]
        key = new_group_key()
        self._store_group_key(gid, 1, key)
        all_members = [m["username"] for m in data["members"]]
        await self._distribute_group_key(gid, 1, key, all_members)
        return data

    async def group_add(self, group_id: str, members: list[str]) -> dict:
        data = await self._request({"type": "group_add",
                                    "group_id": group_id, "members": members})
        rec = self._group_keys.get(group_id)
        if rec and data.get("added"):
            await self._distribute_group_key(group_id, rec["epoch"],
                                             rec["key"], data["added"])
        return data

    async def group_remove(self, group_id: str, username: str) -> dict:
        data = await self._request({"type": "group_remove",
                                    "group_id": group_id, "username": username})
        # Rotate the group key so the removed member cannot read
        # anything sent after their removal.
        rec = self._group_keys.get(group_id)
        if rec:
            try:
                members = await self.group_members(group_id)
                remaining = [m["username"] for m in members["members"]]
                new_key = new_group_key()
                epoch = rec["epoch"] + 1
                self._store_group_key(group_id, epoch, new_key)
                await self._distribute_group_key(group_id, epoch, new_key,
                                                 remaining)
            except Exception:
                log.exception("group key rotation failed")
        return data

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

    async def group_set_nickname(self, group_id: str, nickname: str,
                                 username: str | None = None) -> dict:
        return await self._request({"type": "group_nickname",
                                    "group_id": group_id,
                                    "username": username or self.username,
                                    "nickname": nickname})

    async def group_set_custom_role(self, group_id: str, username: str,
                                    custom_role: str) -> dict:
        return await self._request({"type": "group_custom_role",
                                    "group_id": group_id, "username": username,
                                    "custom_role": custom_role})

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
        rec = await self._ensure_group_key(group_id)
        if rec is None:
            raise RequestFailed("no_group_key",
                                f"no encryption key for group {group_id}")
        payload = json.dumps({"body": body, "kind": kind,
                              "file": file}).encode()
        content = {"epoch": rec["epoch"],
                   **encrypt_with_key(rec["key"], payload)}
        return await self._request({
            "type": "group_send", "group_id": group_id, "content": content,
            "id": new_id(), "mentions": parse_mentions(body),
            "in_reply_to": in_reply_to})

    async def group_send_file(self, group_id: str, path: str,
                              caption: str = "", kind: str | None = None,
                              via_blob: bool = False) -> dict:
        if via_blob:
            descriptor = await self._make_blob_descriptor(
                path, kind, group_id=group_id)
            return await self.group_send(group_id, caption,
                                         kind=descriptor["kind"],
                                         file=descriptor)
        payload = make_file_payload(path, kind)
        return await self.group_send(group_id, caption, kind=payload["kind"],
                                     file=payload)

    async def blob_delete(self, blob_id: str) -> dict:
        return await self._request({"type": "blob_delete",
                                    "blob_id": blob_id})

    # -- work -----------------------------------------------------------------------------------
    def _decrypt_work(self, raw: dict) -> dict:
        def _try(envelope):
            try:
                return self._decrypt_obj(envelope) if envelope else None
            except Exception:
                return None

        content = _try(raw.get("content_enc")) or _try(raw.get("content_self")) or {}
        deliveries = []
        for d in raw.get("deliveries", []):
            dc = _try(d.get("content_enc")) or _try(d.get("content_self")) or {}
            deliveries.append({
                "id": d.get("id"), "work_id": d.get("work_id"),
                "deliverer": d.get("deliverer"), "ts": d.get("ts"),
                "body": dc.get("body", ""), "files": dc.get("files", []),
                "encrypted": True})
        return {
            "id": raw.get("id"), "assigner": raw.get("assigner"),
            "assignee": raw.get("assignee"), "group_id": raw.get("group_id"),
            "title": content.get("title", ""),
            "instructions": content.get("instructions", ""),
            "attachments": content.get("attachments", []),
            "deadline": raw.get("deadline"), "status": raw.get("status"),
            "created_at": raw.get("created_at"),
            "updated_at": raw.get("updated_at"),
            "deliveries": deliveries, "encrypted": True}

    async def _process_work(self, raw: dict, assigned: bool) -> None:
        try:
            work = self._decrypt_work(raw)
        except Exception:
            log.exception("failed to decrypt work")
            return
        if assigned:
            self.assigned_work.append(work)
            if self._work_handler is not None:
                asyncio.create_task(self._run_simple_handler(
                    self._work_handler, work))
        else:
            self.work_updates.append(work)

    async def assign_work(self, assignees: list[str], title: str,
                          instructions: str = "", group_id: str | None = None,
                          attachments: list[str] | None = None,
                          deadline: int | None = None) -> list[dict]:
        payloads = [make_file_payload(p) for p in (attachments or [])]
        obj = {"title": title, "instructions": instructions,
               "attachments": payloads}
        envelopes = {}
        self_pub = self.identity.public_key_b64
        for a in assignees:
            u = normalize_username(a) or a
            pub = await self.pubkey_of(u)
            if not pub:
                raise RequestFailed("unknown_username", f"no key for @{u}")
            envelopes[u] = {"enc": self._encrypt_obj(pub, obj),
                            "self": self._encrypt_obj(self_pub, obj)}
        data = await self._request({
            "type": "assign",
            "assignees": [normalize_username(a) or a for a in assignees],
            "group_id": group_id, "envelopes": envelopes,
            "deadline": deadline})
        return [self._decrypt_work(w) for w in data["work"]]

    async def deliver_work(self, work_id: str, body: str = "",
                           files: list[str] | None = None) -> dict:
        inbox = await self.work_inbox()
        mine = next((w for w in inbox if w["id"] == work_id), None)
        if mine is None:
            raise RequestFailed("unknown_work", work_id)
        payloads = [make_file_payload(p) for p in (files or [])]
        obj = {"body": body, "files": payloads}
        assigner_pub = await self.pubkey_of(mine["assigner"])
        data = await self._request({
            "type": "deliver_work", "work_id": work_id,
            "content_enc": self._encrypt_obj(assigner_pub, obj),
            "content_self": self._encrypt_obj(
                self.identity.public_key_b64, obj)})
        return self._decrypt_work(data["work"])

    async def complete_work(self, work_id: str, note: str = "") -> dict:
        data = await self._request({"type": "work_action", "work_id": work_id,
                                    "action": "complete", "note": note})
        return self._decrypt_work(data["work"])

    async def request_changes(self, work_id: str, note: str = "") -> dict:
        data = await self._request({"type": "work_action", "work_id": work_id,
                                    "action": "request_changes", "note": note})
        return self._decrypt_work(data["work"])

    async def work_inbox(self, status: str | None = None,
                         group_id: str | None = None) -> list[dict]:
        data = await self._request({"type": "work_inbox", "status": status,
                                    "group_id": group_id})
        return [self._decrypt_work(w) for w in data["work"]]

    # -- directory ---------------------------------------------------------------------------------
    async def directory(self, query: str = "") -> list[dict]:
        data = await self._request({"type": "directory", "query": query})
        for u in data["users"]:
            if u.get("pubkey"):
                self._pubkey_cache[u["username"]] = u["pubkey"]
        return data["users"]


async def dial(endpoint: str | None, to: str, body: str,
               timeout: float = 15.0, state_dir: str = DEFAULT_STATE_DIR) -> str:
    """One-shot: send a message as an ephemeral caller and await the reply
    on the same line — the ask_fo / get_fo_reply pattern, generalised."""
    caller = Agent("dial", endpoint=endpoint, state_dir=state_dir,
                   ephemeral=True)
    await caller.start()
    try:
        sent = await caller.send_message(to, body)
        reply = await caller.wait_reply(sent["id"], timeout=timeout)
        return reply.get("body", "")
    finally:
        await caller.close()
