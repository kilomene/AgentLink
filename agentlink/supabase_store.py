"""Supabase (Postgres via PostgREST) backend for the AgentLink relay.

PRODUCTION backend. The relay talks to ONE store interface; this class
implements exactly the same semantics as the SQLite dev/test Store
(``agentlink/store.py``) against the tables in
``deploy/supabase-schema.sql``. Because every relay reads/writes the
same Postgres, ANY relay can serve ANY agent — that shared backend is
what makes own-server-first failover lossless: queues, groups and work
follow the agent to whichever relay it is riding.

Operator configuration (relay-side only; agents never see these):
    SUPABASE_URL          https://<project>.supabase.co
    SUPABASE_SERVICE_KEY  service-role key for the relay process

Realtime: Supabase Realtime can mirror table changes to other relays;
AgentLink's own live sync rides the relay's websocket + dashboard SSE
push, so Realtime is an enhancement, not a requirement.

Files are NOT stored in Supabase Storage (owner storage split):
Supabase is database + realtime only; file ciphertext lives in
Cloudflare R2 behind the relay (see blobstore.py).

LIVE-VERIFIED 2026-11-02 against the production AgentLink Supabase
project: the full store surface (users, queue, groups, keys, invites,
work, deliveries, checkpoints, channels, upload sessions, alerts,
library, vault, chains, blob metadata, dashboard sessions, audit) was
exercised end-to-end through this adapter. The parity drift found then
(alerts/chains/library/vault/upload-session shapes) is fixed in this
file; the adapter now mirrors the SQLite Store contract exactly,
against the tables in supabase/schema.sql.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import json
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .protocol import new_id, new_secret, now_ts
from .store import DEFAULT_SETTINGS, MAX_GROUP_MEMBERS, GroupFull, NotFound, UsernameTaken


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _loads(val, default):
    """Tolerant JSON decode: Postgres jsonb columns may hand back an
    already-parsed value, a JSON string (this adapter's write shape),
    or an empty string (the SQLite store's 'no value' marker)."""
    if val is None:
        return default
    if isinstance(val, str):
        if not val:
            return default
        try:
            return json.loads(val)
        except Exception:
            return default
    return val


class SupabaseStore:
    def __init__(self, url: str, service_key: str):
        if not url or not service_key:
            raise ValueError(
                "SupabaseStore needs SUPABASE_URL and SUPABASE_SERVICE_KEY")
        self.base = url.rstrip("/") + "/rest/v1"
        self._key = service_key
        _p = urllib.parse.urlparse(self.base)
        self._host = _p.hostname
        self._port = _p.port or 443
        self._path_prefix = _p.path.rstrip("/")
        self._local = threading.local()

    # -- transport ----------------------------------------------------
    # Persistent per-thread HTTPS connections over a hand-rolled
    # CONNECT tunnel. Why hand-rolled: this deployment's egress
    # gateway rejects http.client's CONNECT form outright (it answers
    # with a plain-text policy line, surfacing as BadStatusLine) and
    # intermittently drops or stalls fresh urllib connections, while
    # an explicitly formed CONNECT (Proxy-Connection: Keep-Alive)
    # establishes cleanly and the tunnel then serves requests at
    # ~0.1s each, reused. Any failure drops the connection and the
    # bounded retry reconnects: GET x5, PATCH/DELETE/POST x4, POST x1
    # for the identity-sequenced append tables (a retry there could
    # double-apply); a 409 on a POST retry means the first attempt
    # landed and its response was lost — treated as success.
    @staticmethod
    def _proxy_url() -> str:
        import os as _os
        for k in ("https_proxy", "HTTPS_PROXY", "http_proxy",
                  "HTTP_PROXY"):
            v = _os.environ.get(k)
            if v:
                return v
        return ""

    def _open_conn(self):
        proxy = self._proxy_url()
        if proxy:
            p = urllib.parse.urlparse(proxy)
            raw = socket.create_connection((p.hostname, p.port or 3128),
                                           timeout=6)
            lines = [f"CONNECT {self._host}:{self._port} HTTP/1.1",
                     f"Host: {self._host}:{self._port}",
                     "Proxy-Connection: Keep-Alive"]
            if p.username:
                cred = "%s:%s" % (urllib.parse.unquote(p.username),
                                  urllib.parse.unquote(p.password or ""))
                lines.append("Proxy-Authorization: Basic " +
                             base64.b64encode(cred.encode()).decode())
            raw.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
            buf = b""
            _deadline = time.time() + 8
            while b"\r\n\r\n" not in buf and len(buf) < 65536:
                if time.time() > _deadline:
                    raw.close()
                    raise ConnectionError("CONNECT response deadline")
                chunk = raw.recv(1)
                if not chunk:
                    raw.close()
                    raise ConnectionError("proxy closed during CONNECT")
                buf += chunk
            status = buf.decode("latin1").split("\r\n", 1)[0]
            if " 200 " not in status and not status.endswith(" 200"):
                raw.close()
                raise ConnectionError(f"CONNECT refused: {status}")
        else:
            raw = socket.create_connection((self._host, self._port),
                                           timeout=6)
        ctx = ssl.create_default_context()
        wrapped = ctx.wrap_socket(raw, server_hostname=self._host)
        wrapped.settimeout(6)
        return wrapped, wrapped.makefile("rb")

    def _conn(self):
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._open_conn()
            self._local.conn = conn
        return conn

    def _drop_conn(self) -> None:
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn[0].close()
            except Exception:
                pass
            self._local.conn = None

    @staticmethod
    def _read_response(reader, sock=None, deadline=None):
        def _tick():
            if deadline is not None:
                left = deadline - time.time()
                if left <= 0:
                    raise TimeoutError("response deadline exceeded")
                if sock is not None:
                    try:
                        sock.settimeout(min(6, left))
                    except Exception:
                        pass
        _tick()
        while True:
            status_line = reader.readline().decode("latin1").strip()
            if not status_line:
                raise ConnectionError("server closed the connection")
            parts = status_line.split(" ", 2)
            status = int(parts[1])
            reason = parts[2] if len(parts) > 2 else ""
            headers = {}
            while True:
                _tick()
                line = reader.readline().decode("latin1")
                if line in ("\r\n", ""):
                    break
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            if 100 <= status < 200:  # interim response: read the real one
                continue
            break
        body = b""
        if status not in (204, 304):
            if headers.get("transfer-encoding") == "chunked":
                chunks = []
                while True:
                    _tick()
                    n = int(reader.readline().strip() or b"0", 16)
                    if n == 0:
                        reader.readline()
                        break
                    chunks.append(reader.read(n))
                    reader.readline()
                body = b"".join(chunks)
            elif "content-length" in headers:
                _tick()
                body = reader.read(int(headers["content-length"]))
            elif headers.get("connection", "").lower() == "close":
                body = reader.read()
        if headers.get("content-encoding") == "gzip" and body:
            body = gzip.decompress(body)
        return status, reason, headers, body

    def _roundtrip(self, method: str, path: str, headers: dict,
                   data: bytes | None):
        sock, reader = self._conn()
        lines = [f"{method} {path} HTTP/1.1", f"Host: {self._host}"]
        for k, v in headers.items():
            lines.append(f"{k}: {v}")
        if data is not None:
            lines.append(f"Content-Length: {len(data)}")
        payload = ("\r\n".join(lines) + "\r\n\r\n").encode()
        if data:
            payload += data
        sock.sendall(payload)
        status, reason, resp_headers, raw = self._read_response(
            reader, sock, time.time() + 10)
        if resp_headers.get("connection", "").lower() == "close":
            self._drop_conn()
        return status, reason, resp_headers, raw

    def _req(self, method: str, table: str, query: str = "",
             body=None, prefer: str = ""):
        import os as _os
        prefix = _os.environ.get("AGENTLINK_SUPABASE_TABLE_PREFIX", "")
        if prefix and not table.startswith(prefix):
            table = prefix + table
        path = f"{self._path_prefix}/{table}"
        if query:
            path += "?" + query
        data = json.dumps(body).encode() if body is not None else None
        headers = {"apikey": self._key,
                   "Authorization": f"Bearer {self._key}",
                   "Accept-Encoding": "gzip"}
        if data:
            headers["Content-Type"] = "application/json"
        if prefer:
            headers["Prefer"] = prefer
        if method == "GET":
            attempts = 5
        elif method == "POST" and (table.endswith("queue")
                                   or table.endswith("audit_log")):
            attempts = 1
        else:
            attempts = 4
        last = None
        for i in range(attempts):
            try:
                status, reason, _rh, raw = self._roundtrip(
                    method, path, headers, data)
                if status >= 400:
                    raise urllib.error.HTTPError(path, status, reason,
                                                 None, None)
                return json.loads(raw) if raw else None
            except urllib.error.HTTPError as e:
                self._drop_conn()
                if method == "POST" and e.code == 409 and i > 0:
                    return None
                if e.code < 500 or i == attempts - 1:
                    raise
                last = e
            except Exception as e:  # reset / timeout / stale connection
                self._drop_conn()
                if i == attempts - 1:
                    raise
                last = e
            time.sleep(min(0.3 * (2 ** i), 1.5))
        raise last  # pragma: no cover

    def _get(self, table: str, query: str) -> list[dict]:
        return self._req("GET", table, query) or []

    def _one(self, table: str, query: str) -> dict | None:
        rows = self._get(table, query + ("&" if query else "") + "limit=1")
        return rows[0] if rows else None

    @staticmethod
    def _eq(col: str, val) -> str:
        return f"{col}=eq.{urllib.parse.quote(str(val), safe='')}"

    def close(self) -> None:
        pass

    # -- users -----------------------------------------------------------------
    def claim(self, username, display_name, pubkey="", sign_pub="",
              capabilities=None, cap_desc="", mode="autonomous"):
        secret = new_secret()
        try:
            self._req("POST", "users", body={
                "username": username, "secret": _sha(secret),
                "display_name": display_name, "pubkey": pubkey,
                "sign_pub": sign_pub,
                "capabilities": json.dumps(capabilities or []),
                "cap_desc": cap_desc,
                "mode": mode if mode in ("manual", "autonomous")
                        else "autonomous",
                "created_at": now_ts()}, prefer="return=minimal")
        except Exception as exc:
            if "409" in str(exc) or "duplicate" in str(exc):
                raise UsernameTaken(username)
            raise
        return secret

    def verify(self, username, secret):
        if not secret:
            return False
        row = self._one("users", self._eq("username", username) + "&select=secret")
        return bool(row) and row["secret"] == _sha(secret)

    def exists(self, username):
        return self._one("users", self._eq("username", username)
                         + "&select=username") is not None

    def set_display_name(self, username, display_name):
        self._req("PATCH", "users", self._eq("username", username),
                  body={"display_name": display_name}, prefer="return=minimal")

    def pubkey_of(self, username):
        row = self._one("users", self._eq("username", username) + "&select=pubkey")
        return row["pubkey"] if row else ""

    def set_pubkey(self, username, pubkey):
        if pubkey:
            self._req("PATCH", "users", self._eq("username", username),
                      body={"pubkey": pubkey}, prefer="return=minimal")

    def sign_pub_of(self, username):
        row = self._one("users", self._eq("username", username)
                        + "&select=sign_pub")
        return row["sign_pub"] if row else ""

    def set_sign_pub(self, username, sign_pub):
        if sign_pub:
            self._req("PATCH", "users", self._eq("username", username),
                      body={"sign_pub": sign_pub}, prefer="return=minimal")

    def touch(self, username):
        self._req("PATCH", "users", self._eq("username", username),
                  body={"last_seen": now_ts()}, prefer="return=minimal")

    def last_seen_of(self, username):
        row = self._one("users", self._eq("username", username)
                        + "&select=last_seen")
        return int(row["last_seen"]) if row else 0

    def set_capabilities(self, username, capabilities, cap_desc=""):
        self._req("PATCH", "users", self._eq("username", username),
                  body={"capabilities": json.dumps(capabilities or []),
                        "cap_desc": cap_desc}, prefer="return=minimal")

    def set_mode(self, username, mode):
        # Autonomy law (v1.1.7): the agent declares its mode in its
        # hello; the relay only records it. Unknown values refused.
        if mode not in ("manual", "autonomous"):
            return
        self._req("PATCH", "users", self._eq("username", username),
                  body={"mode": mode}, prefer="return=minimal")

    def list_users(self, query="", capability=""):
        q = ("select=username,display_name,pubkey,sign_pub,capabilities,"
             "cap_desc,mode,last_seen,created_at&order=username")
        if query:
            q += f"&username=like.%25{urllib.parse.quote(query)}%25"
        rows = self._get("users", q)
        out = []
        for r in rows:
            try:
                r["capabilities"] = json.loads(r.get("capabilities")
                                               or "[]")
            except Exception:
                r["capabilities"] = []
            # Presentation rule (autonomy law): anything that is not
            # an explicit 'manual' presents as autonomous.
            r["mode"] = r.get("mode") if r.get("mode") in (
                "manual", "autonomous") else "autonomous"
            if capability and capability.lower() not in \
                    [c.lower() for c in r["capabilities"]]:
                continue
            out.append(r)
        return out

    # -- queue ---------------------------------------------------------------------
    def enqueue(self, to_username, payload):
        from .store import PRIORITY_WEIGHT
        weight = PRIORITY_WEIGHT.get(str(payload.get("priority")
                                         or "normal"), 0)
        self._req("POST", "queue", body={
            "to_username": to_username, "payload": json.dumps(payload),
            "priority": weight, "ts": now_ts()}, prefer="return=minimal")

    def oldest_urgent_queued(self):
        rows = self._get("queue", "priority=gte.2"
                                  "&select=to_username,ts&order=ts.asc")
        seen = {}
        for r in rows:
            seen.setdefault(r["to_username"], r["ts"])
        return [{"to_username": k, "since": v} for k, v in seen.items()]

    def dequeue_all(self, to_username):
        rows = self._get("queue", self._eq("to_username", to_username)
                         + "&select=payload"
                         + "&order=priority.desc,seq.asc")
        self._req("DELETE", "queue", self._eq("to_username", to_username),
                  prefer="return=minimal")
        out = []
        for r in rows:
            frame = json.loads(r["payload"])
            frame["queued"] = True
            out.append(frame)
        return out

    # -- groups ----------------------------------------------------------------------
    def create_group(self, name, creator, settings=None):
        gid = new_id("g-")[:14]
        merged = dict(DEFAULT_SETTINGS)
        if settings:
            for k in DEFAULT_SETTINGS:
                if k in settings:
                    merged[k] = settings[k]
        self._req("POST", "groups", body={
            "id": gid, "name": name, "creator": creator,
            "settings": json.dumps(merged), "created_at": now_ts()},
            prefer="return=minimal")
        self.add_member(gid, creator, role="superadmin", added_by=creator)
        return gid

    def get_group(self, group_id):
        row = self._one("groups", self._eq("id", group_id))
        if row is None:
            return None
        row["settings"] = json.loads(row["settings"])
        return row

    def set_settings(self, group_id, settings):
        g = self.get_group(group_id)
        if g is None:
            raise NotFound(group_id)
        merged = dict(g["settings"])
        for k in DEFAULT_SETTINGS:
            if k in settings:
                merged[k] = settings[k]
        self._req("PATCH", "groups", self._eq("id", group_id),
                  body={"settings": json.dumps(merged)},
                  prefer="return=minimal")
        return merged

    def add_member(self, group_id, username, role="member", added_by=""):
        if self.role_of(group_id, username) is not None:
            return False
        if len(self.members(group_id)) >= MAX_GROUP_MEMBERS:
            raise GroupFull(group_id)
        self._req("POST", "group_members", body={
            "group_id": group_id, "username": username, "role": role,
            "added_by": added_by, "joined_at": now_ts()},
            prefer="return=minimal,resolution=ignore-duplicates")
        return True

    def remove_member(self, group_id, username):
        existed = self.role_of(group_id, username) is not None
        self._req("DELETE", "group_members",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username), prefer="return=minimal")
        self._req("DELETE", "group_keys",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username), prefer="return=minimal")
        return existed

    def set_role(self, group_id, username, role):
        self._req("PATCH", "group_members",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username),
                  body={"role": role}, prefer="return=minimal")

    def role_of(self, group_id, username):
        row = self._one("group_members",
                        self._eq("group_id", group_id) + "&"
                        + self._eq("username", username) + "&select=role")
        return row["role"] if row else None

    def members(self, group_id):
        return self._get(
            "group_members",
            self._eq("group_id", group_id)
            + "&select=username,role,nickname,custom_role,added_by,joined_at"
            + "&order=joined_at.asc")

    def set_nickname(self, group_id, username, nickname):
        self._req("PATCH", "group_members",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username),
                  body={"nickname": nickname[:48]}, prefer="return=minimal")

    def set_custom_role(self, group_id, username, custom_role):
        self._req("PATCH", "group_members",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username),
                  body={"custom_role": custom_role[:48]},
                  prefer="return=minimal")

    def all_groups(self):
        rows = self._get("groups", "select=id,name,creator,created_at"
                                   "&order=created_at.asc")
        for r in rows:
            r["member_count"] = len(self.members(r["id"]))
        return rows

    # -- group keys ---------------------------------------------------------------------
    def set_group_key(self, group_id, username, epoch, wrapped):
        self._req("POST", "group_keys", body={
            "group_id": group_id, "username": username, "epoch": epoch,
            "wrapped": json.dumps(wrapped)},
            prefer="return=minimal,resolution=merge-duplicates")

    def group_key_for(self, group_id, username):
        row = self._one("group_keys",
                        self._eq("group_id", group_id) + "&"
                        + self._eq("username", username))
        if row is None:
            return None
        return {"epoch": row["epoch"], "wrapped": json.loads(row["wrapped"])}

    def group_key_epoch(self, group_id):
        rows = self._get("group_keys",
                         self._eq("group_id", group_id)
                         + "&select=epoch&order=epoch.desc&limit=1")
        return int(rows[0]["epoch"]) if rows else 0

    # -- invites ---------------------------------------------------------------------------
    def create_invite(self, group_id, created_by, ttl_seconds=None):
        # Canonical al_invites shape (v1.1.0): token + created_at.
        # The token column stores the token's SHA-256; validity is
        # created_at + INVITE_TTL_SECONDS >= now (created_at is
        # shifted so a custom ttl keeps its exact meaning) — mirrors
        # the SQLite Store exactly.
        from .store import INVITE_TTL_SECONDS
        import secrets as _s
        if ttl_seconds is None:
            ttl_seconds = INVITE_TTL_SECONDS
        token = _s.token_urlsafe(24)
        self._req("POST", "invites", body={
            "token": _sha(token), "group_id": group_id,
            "created_by": created_by,
            "created_at": now_ts() + int(ttl_seconds)
            - INVITE_TTL_SECONDS}, prefer="return=minimal")
        return token

    def invite_valid(self, group_id, token):
        from .store import INVITE_TTL_SECONDS
        if not token:
            return False
        row = self._one("invites",
                        self._eq("token", _sha(token)) + "&"
                        + self._eq("group_id", group_id)
                        + "&select=created_at")
        return bool(row) and \
            row["created_at"] + INVITE_TTL_SECONDS >= now_ts()

    @staticmethod
    def invite_link(group_id, token):
        from .store import Store
        return Store.invite_link(group_id, token)

    @staticmethod
    def parse_invite_link(link):
        from .store import Store
        return Store.parse_invite_link(link)

    # -- work ----------------------------------------------------------------------------------
    def create_work(self, assigner, assignee, group_id, content_enc,
                    content_self, deadline, batch_id=None,
                    priority="normal", auto_reassign=True,
                    assignee_role="", content_group=None,
                    chain_id="", chain_step=0, require_approval=False):
        wid = new_id("w-")[:14]
        ts = now_ts()
        self._req("POST", "work", body={
            "id": wid, "assigner": assigner, "assignee": assignee,
            "group_id": group_id, "content_enc": json.dumps(content_enc),
            "content_self": json.dumps(content_self),
            "content_group": json.dumps(content_group)
            if content_group else "",
            "batch_id": batch_id, "chain_id": chain_id,
            "chain_step": chain_step,
            "priority": priority,
            "auto_reassign": 1 if auto_reassign else 0,
            "require_approval": 1 if require_approval else 0,
            "assignee_role": assignee_role, "deadline": deadline,
            "status": "assigned", "created_at": ts, "updated_at": ts},
            prefer="return=minimal")
        return self.get_work(wid)

    def get_work(self, work_id):
        row = self._one("work", self._eq("id", work_id))
        if row is None:
            return None
        row["content_enc"] = json.loads(row["content_enc"] or "{}")
        row["content_self"] = json.loads(row["content_self"] or "{}")
        try:
            row["content_group"] = json.loads(row["content_group"]
                                              or "null")
        except Exception:
            row["content_group"] = None
        drows = self._get("work_deliveries",
                          self._eq("work_id", work_id) + "&order=ts.asc")
        row["deliveries"] = [
            {**d, "content_enc": json.loads(d["content_enc"] or "{}"),
             "content_self": json.loads(d["content_self"] or "{}"),
             "content_group": json.loads(d["content_group"] or "null")
             if "content_group" in d else None}
            for d in drows]
        cp = self.get_checkpoint(work_id)
        if cp is not None:
            row["checkpoint"] = cp
        return row

    def set_checkpoint(self, work_id, attempt, by_user, content_assigner,
                       content_group):
        self._req("POST", "work_checkpoints", body={
            "work_id": work_id, "attempt": attempt, "by_user": by_user,
            "content_assigner": json.dumps(content_assigner)
            if content_assigner else "",
            "content_group": json.dumps(content_group)
            if content_group else "", "ts": now_ts()},
            prefer="return=minimal,resolution=merge-duplicates")

    def get_checkpoint(self, work_id):
        row = self._one("work_checkpoints", self._eq("work_id", work_id))
        if row is None:
            return None
        for k in ("content_assigner", "content_group"):
            try:
                row[k] = json.loads(row[k]) if row.get(k) else None
            except Exception:
                row[k] = None
        return row

    WORK_TRANSITIONS = None  # bound from store.Store below

    def set_work_status(self, work_id, status):
        from .store import InvalidTransition, Store
        current = self.get_work(work_id)
        if current is None:
            raise NotFound(work_id)
        allowed = Store.WORK_TRANSITIONS.get(current["status"], set())
        if status != current["status"] and status not in allowed:
            raise InvalidTransition(
                f"{current['status']} -> {status} is not legal")
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"status": status, "updated_at": now_ts()},
                  prefer="return=minimal")
        return self.get_work(work_id)

    def set_work_progress(self, work_id, percent):
        row = self._one("work", self._eq("id", work_id) + "&select=status")
        if row is None:
            raise NotFound(work_id)
        status = "in_progress" if row["status"] == "assigned" \
            else row["status"]
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"progress_percent": percent,
                        "progress_at": now_ts(), "status": status,
                        "updated_at": now_ts()}, prefer="return=minimal")
        return self.get_work(work_id)

    def escalate_work_priority(self, work_id):
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"priority": "urgent", "updated_at": now_ts()},
                  prefer="return=minimal")
        return self.get_work(work_id)

    def cover_batch(self, batch_id, delivered_work_id):
        if not batch_id:
            return []
        rows = self._get("work", self._eq("batch_id", batch_id)
                         + "&select=id,status")
        out = []
        for r in rows:
            if r["id"] != delivered_work_id and r["status"] in (
                    "assigned", "in_progress", "changes_requested"):
                self._req("PATCH", "work", self._eq("id", r["id"]),
                          body={"status": "covered",
                                "updated_at": now_ts()},
                          prefer="return=minimal")
                out.append(self.get_work(r["id"]))
        return out

    def resolve_role(self, group_id, role_name):
        rows = self._get("group_members",
                         self._eq("group_id", group_id)
                         + "&select=username,custom_role&order=joined_at.asc")
        return [r["username"] for r in rows
                if (r.get("custom_role") or "").lower()
                == role_name.lower()]

    def compute_trust(self, username):
        from .store import Store
        rows = self._get("work", self._eq("assignee", username)
                         + "&select=status,deadline,updated_at")
        changes = self._get(
            "audit_log", "kind=eq.work_changes_requested&"
            + self._eq("target", username) + "&select=seq")
        bad = self._get(
            "audit_log", "kind=eq.delivery_proof_verified&status=eq.false&"
            + self._eq("actor", username) + "&select=seq")
        score = 50
        now = now_ts()
        for r in rows:
            if r["status"] in ("completed", "covered"):
                score += 4
            elif r["status"] in ("delivered", "awaiting_approval"):
                score += 1
            if r.get("deadline"):
                if r["status"] == "completed" and \
                        r["updated_at"] > r["deadline"]:
                    score -= 6
                elif r["status"] not in ("completed", "covered",
                                         "delivered", "awaiting_approval") \
                        and now > r["deadline"]:
                    score -= 6
        score -= 6 * len(changes) + 10 * len(bad)
        return max(0, min(100, score))

    def add_delivery(self, work_id, deliverer, content_enc, content_self,
                     proof=None, content_group=None, content_next=None):
        did = new_id("d-")[:14]
        self._req("POST", "work_deliveries", body={
            "id": did, "work_id": work_id, "deliverer": deliverer,
            "content_enc": json.dumps(content_enc),
            "content_self": json.dumps(content_self),
            "content_group": json.dumps(content_group)
            if content_group else "",
            "content_next": json.dumps(content_next)
            if content_next else "", "ts": now_ts()},
            prefer="return=minimal")
        if proof:
            self._req("PATCH", "work", self._eq("id", work_id),
                      body={"proof_hash": proof.get("hash", ""),
                            "proof_ts": int(proof.get("ts") or 0),
                            "proof_sig": proof.get("sig", ""),
                            "proof_verified": 1 if proof.get("verified")
                            else 0}, prefer="return=minimal")
        row = self._one("work", self._eq("id", work_id)
                        + "&select=require_approval")
        gated = bool(row and row.get("require_approval"))
        return self.set_work_status(
            work_id, "awaiting_approval" if gated else "delivered")

    def reassign_work(self, work_id, new_assignee):
        row = self._one("work", self._eq("id", work_id)
                        + "&select=attempt")
        attempt = int(row["attempt"] or 1) + 1 if row else 2
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"assignee": new_assignee, "attempt": attempt,
                        "status": "assigned", "progress_percent": 0,
                        "updated_at": now_ts()}, prefer="return=minimal")
        return self.get_work(work_id)

    def set_awaiting_agent(self, work_id):
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"status": "awaiting_agent",
                        "updated_at": now_ts()}, prefer="return=minimal")
        return self.get_work(work_id)

    def open_work(self, statuses=("assigned", "in_progress")):
        q = "status=in.(" + ",".join(statuses) + ")&select=id"
        rows = self._get("work", q)
        return [self.get_work(r["id"]) for r in rows]

    def list_work(self, username, status=None, group_id=None):
        q = (f"or=(assignee.eq.{username},assigner.eq.{username})"
             "&select=id&order=created_at.asc")
        if status:
            q += f"&status=eq.{status}"
        if group_id:
            q += f"&group_id=eq.{group_id}"
        rows = self._get("work", q)
        return [self.get_work(r["id"]) for r in rows]

    def list_work_meta(self):
        return self._get(
            "work", "select=id,assigner,assignee,group_id,status,priority,"
                    "batch_id,progress_percent,progress_at,proof_verified,"
                    "proof_hash,deadline,chain_id,chain_step,attempt,"
                    "require_approval,created_at,updated_at"
                    "&order=updated_at.desc&limit=200")

    # -- blob metadata -----------------------------------------------------
    def put_blob_meta(self, blob_id, owner, for_user="", for_group="",
                      size=0, for_channel="", whole_sha=""):
        self._req("POST", "blobs", body={
            "id": blob_id, "owner": owner, "for_user": for_user,
            "for_group": for_group, "for_channel": for_channel,
            "whole_sha": whole_sha, "size": size,
            "created_at": now_ts()},
            prefer="return=minimal,resolution=merge-duplicates")

    def find_blob_by_whole_sha(self, whole_sha, owner="", for_user="",
                               for_group="", for_channel=""):
        return self._one(
            "blobs", self._eq("whole_sha", whole_sha) + "&"
            + self._eq("owner", owner) + "&" + self._eq("for_user", for_user)
            + "&" + self._eq("for_group", for_group) + "&"
            + self._eq("for_channel", for_channel))

    def get_blob_meta(self, blob_id):
        return self._one("blobs", self._eq("id", blob_id))

    def delete_blob_meta(self, blob_id):
        self._req("DELETE", "blobs", self._eq("id", blob_id),
                  prefer="return=minimal")

    def list_blob_meta(self):
        return self._get("blobs", "select=*&order=id.asc")

    # -- channels / uploads / alerts / library / vault / chains (parity) --
    def create_channel(self, name, creator):
        cid = new_id("c-")[:14]
        self._req("POST", "channels", body={
            "id": cid, "name": name, "creator": creator,
            "created_at": now_ts()}, prefer="return=minimal")
        self.add_subscriber(cid, creator, role="superadmin",
                            added_by=creator)
        return cid

    def get_channel(self, channel_id):
        row = self._one("channels", self._eq("id", channel_id))
        if row is None:
            return None
        row["member_count"] = len(self.subscribers(channel_id))
        return row

    def all_channels(self):
        rows = self._get("channels",
                         "select=id,name,creator,created_at"
                         "&order=created_at.asc")
        for r in rows:
            r["member_count"] = len(self.subscribers(r["id"]))
        return rows

    def add_subscriber(self, channel_id, username, role="member",
                       added_by=""):
        if self.subscriber_role(channel_id, username) is not None:
            return False
        from .store import MAX_CHANNEL_SUBSCRIBERS
        if len(self.subscribers(channel_id)) >= MAX_CHANNEL_SUBSCRIBERS:
            raise GroupFull(channel_id)
        self._req("POST", "channel_members", body={
            "channel_id": channel_id, "username": username, "role": role,
            "added_by": added_by, "joined_at": now_ts()},
            prefer="return=minimal,resolution=ignore-duplicates")
        return True

    def remove_subscriber(self, channel_id, username):
        existed = self.subscriber_role(channel_id, username) is not None
        self._req("DELETE", "channel_members",
                  self._eq("channel_id", channel_id) + "&"
                  + self._eq("username", username),
                  prefer="return=minimal")
        self._req("DELETE", "channel_keys",
                  self._eq("channel_id", channel_id) + "&"
                  + self._eq("username", username),
                  prefer="return=minimal")
        return existed

    def subscriber_role(self, channel_id, username):
        row = self._one("channel_members",
                        self._eq("channel_id", channel_id) + "&"
                        + self._eq("username", username) + "&select=role")
        return row["role"] if row else None

    def set_subscriber_role(self, channel_id, username, role):
        self._req("PATCH", "channel_members",
                  self._eq("channel_id", channel_id) + "&"
                  + self._eq("username", username),
                  body={"role": role}, prefer="return=minimal")

    def subscribers(self, channel_id):
        return self._get("channel_members",
                         self._eq("channel_id", channel_id)
                         + "&select=username,role,added_by,joined_at"
                         + "&order=joined_at.asc")

    def set_channel_key(self, channel_id, username, epoch, wrapped):
        self._req("POST", "channel_keys", body={
            "channel_id": channel_id, "username": username,
            "epoch": epoch, "wrapped": json.dumps(wrapped)},
            prefer="return=minimal,resolution=merge-duplicates")

    def channel_key_for(self, channel_id, username):
        row = self._one("channel_keys",
                        self._eq("channel_id", channel_id) + "&"
                        + self._eq("username", username))
        if row is None:
            return None
        return {"epoch": row["epoch"],
                "wrapped": json.loads(row["wrapped"])}

    def channel_key_epoch(self, channel_id):
        rows = self._get("channel_keys",
                         self._eq("channel_id", channel_id)
                         + "&select=epoch&order=epoch.desc&limit=1")
        return int(rows[0]["epoch"]) if rows else 0

    def create_channel_invite(self, channel_id, created_by,
                              ttl_seconds=None):
        from .store import INVITE_TTL_SECONDS
        import secrets as _s
        if ttl_seconds is None:
            ttl_seconds = INVITE_TTL_SECONDS
        token = _s.token_urlsafe(24)
        self._req("POST", "invites", body={
            "token": _sha(token), "group_id": "ch:" + channel_id,
            "created_by": created_by,
            "created_at": now_ts() + int(ttl_seconds)
            - INVITE_TTL_SECONDS}, prefer="return=minimal")
        return token

    def channel_invite_valid(self, channel_id, token):
        from .store import INVITE_TTL_SECONDS
        if not token:
            return False
        row = self._one("invites",
                        self._eq("token", _sha(token)) + "&"
                        + self._eq("group_id", "ch:" + channel_id)
                        + "&select=created_at")
        return bool(row) and \
            row["created_at"] + INVITE_TTL_SECONDS >= now_ts()

    def create_upload_session(self, owner, whole_sha, ct_sha, size,
                              chunk_size, for_user="", for_group="",
                              for_channel=""):
        sid = new_id("u-")[:14]
        # Canonical al_upload_sessions shape (v1.1.0): no for_channel
        # column — channel scope is asserted by the relay at session
        # start and carried on the finish frame. The parameter stays
        # for interface parity with the SQLite Store.
        self._req("POST", "upload_sessions", body={
            "session_id": sid, "owner": owner, "for_user": for_user,
            "for_group": for_group,
            "whole_sha": whole_sha, "ct_sha": ct_sha,
            "size": int(size or 0), "chunk_size": int(chunk_size or 0),
            "chunks": "[]", "created_at": now_ts()},
            prefer="return=minimal")
        return sid

    def get_upload_session(self, session_id):
        row = self._one("upload_sessions",
                        self._eq("session_id", session_id))
        if row is None:
            return None
        row["chunks"] = _loads(row.get("chunks"), [])
        row.setdefault("for_channel", "")
        return row

    def record_chunk(self, session_id, index):
        sess = self.get_upload_session(session_id)
        if sess is None:
            raise NotFound(session_id)
        chunks = sorted(set(sess["chunks"]) | {int(index)})
        self._req("PATCH", "upload_sessions",
                  self._eq("session_id", session_id),
                  body={"chunks": json.dumps(chunks)},
                  prefer="return=minimal")
        return chunks

    def delete_upload_session(self, session_id):
        self._req("DELETE", "upload_sessions",
                  self._eq("session_id", session_id),
                  prefer="return=minimal")

    def open_alert(self, kind, subject, detail=""):
        row = self._one("alerts", self._eq("kind", kind) + "&"
                        + self._eq("subject", subject) + "&status=eq.open")
        if row is not None:
            return row
        aid = new_id("a-")[:14]
        self._req("POST", "alerts", body={
            "id": aid, "kind": kind, "subject": subject,
            "detail": detail, "status": "open", "reminders": 0,
            "last_reminder_at": 0, "created_at": now_ts(),
            "resolved_at": 0}, prefer="return=minimal")
        return self._one("alerts", self._eq("id", aid))

    def resolve_alerts(self, kind, subject):
        rows = self._req("PATCH", "alerts",
                         self._eq("kind", kind) + "&"
                         + self._eq("subject", subject)
                         + "&status=eq.open",
                         body={"status": "resolved",
                               "resolved_at": now_ts()},
                         prefer="return=representation")
        return len(rows or [])

    # Singular alias (older callers).
    resolve_alert = resolve_alerts

    def bump_reminder(self, alert_id):
        row = self._one("alerts", self._eq("id", alert_id))
        if row is None:
            return
        self._req("PATCH", "alerts", self._eq("id", alert_id),
                  body={"reminders": int(row.get("reminders") or 0) + 1,
                        "last_reminder_at": now_ts()},
                  prefer="return=minimal")

    def list_alerts(self, status=None, limit=100):
        q = f"select=*&order=created_at.desc&limit={int(limit)}"
        if status:
            q += "&" + self._eq("status", status)
        return self._get("alerts", q)

    def library_add(self, lib_id, filename, size, sha256, sender,
                    to_user="", group_id="", work_id="", delivery_id=""):
        self._req("POST", "library", body={
            "id": lib_id, "delivery_id": delivery_id, "work_id": work_id,
            "filename": filename[:200], "size": int(size or 0),
            "sha256": sha256, "sender": sender, "to_user": to_user,
            "group_id": group_id, "chain_next": "", "ts": now_ts()},
            prefer="return=minimal,resolution=ignore-duplicates")

    def _library_visible(self, row, requester):
        if row.get("sender") == requester or row.get("to_user") == requester:
            return True
        if row.get("chain_next") and row["chain_next"] == requester:
            return True
        if row.get("group_id"):
            return self.role_of(row["group_id"], requester) is not None
        return False

    def library_search(self, requester, q="", sender="", group_id="",
                       hash_prefix="", limit=100):
        rows = self._get("library",
                         "select=*&order=ts.desc&limit=1000")
        out = []
        for d in rows:
            if not self._library_visible(d, requester):
                continue
            if q and q.lower() not in (d.get("filename") or "").lower():
                continue
            if sender and d.get("sender") != sender:
                continue
            if group_id and d.get("group_id") != group_id:
                continue
            if hash_prefix and not (d.get("sha256") or "").startswith(
                    hash_prefix):
                continue
            out.append(d)
            if len(out) >= limit:
                break
        return out

    # Relay calls search_library with Store-API argument names.
    search_library = library_search

    def library_entry(self, lib_id):
        return self._one("library", self._eq("id", lib_id))

    def library_all(self, limit=200):
        return self._get("library", "select=*&order=ts.desc"
                                    f"&limit={int(limit)}")

    library_all_meta = library_all

    def library_for_work(self, work_id):
        return self._get("library", self._eq("work_id", work_id)
                         + "&order=ts.asc")

    @staticmethod
    def _vault_norm(d):
        if d is None:
            return None
        d = dict(d)
        d["descriptor"] = _loads(d.get("descriptor"), {})
        d["pinned"] = bool(d.get("pinned"))
        return d

    def vault_add(self, group_id, descriptor, added_by, pinned=False):
        vid = new_id("v-")[:14]
        self._req("POST", "vault", body={
            "id": vid, "group_id": group_id,
            "name": descriptor.get("name", ""),
            "size": int(descriptor.get("size") or 0),
            "sha256": descriptor.get("sha256", ""),
            "blob_id": descriptor.get("blob_id", ""),
            "descriptor": json.dumps(descriptor),
            "added_by": added_by, "pinned": 1 if pinned else 0,
            "ts": now_ts()}, prefer="return=minimal")
        return self.vault_entry(vid)

    def vault_list(self, group_id):
        rows = self._get("vault", self._eq("group_id", group_id)
                         + "&order=pinned.desc,ts.desc")
        return [self._vault_norm(r) for r in rows]

    def vault_entry(self, vault_id):
        return self._vault_norm(
            self._one("vault", self._eq("id", vault_id)))

    def vault_set_pinned(self, vault_id, pinned):
        self._req("PATCH", "vault", self._eq("id", vault_id),
                  body={"pinned": 1 if pinned else 0},
                  prefer="return=minimal")
        return self.vault_entry(vault_id)

    def vault_remove(self, vault_id):
        existed = self.vault_entry(vault_id) is not None
        self._req("DELETE", "vault", self._eq("id", vault_id),
                  prefer="return=minimal")
        return existed

    @staticmethod
    def _step_norm(d):
        d = dict(d)
        d["assignees"] = _loads(d.get("assignees"), [])
        d["envelopes"] = _loads(d.get("envelopes"), {})
        cg = d.get("content_group")
        d["content_group"] = _loads(cg, None) if cg else None
        d["handoff"] = _loads(d.get("handoff"), [])
        return d

    def create_chain(self, creator, group_id, name, steps):
        cid = new_id("chain-")[:18]
        ts = now_ts()
        self._req("POST", "chains", body={
            "id": cid, "creator": creator, "group_id": group_id or "",
            "name": name, "status": "running",
            "created_at": ts, "updated_at": ts},
            prefer="return=minimal")
        for i, st in enumerate(steps):
            self._req("POST", "chain_steps", body={
                "id": new_id("step-")[:16], "chain_id": cid,
                "position": i + 1,
                "target_type": st.get("target_type", "user"),
                "target": st.get("target", ""),
                "group_id": st.get("group_id", "") or group_id or "",
                "assignees": json.dumps(st.get("assignees") or []),
                "envelopes": json.dumps(st.get("envelopes") or {}),
                "content_group": json.dumps(st["content_group"])
                if st.get("content_group") else "",
                "deadline": st.get("deadline"),
                "priority": st.get("priority", "normal"),
                "require_approval": 1 if st.get("require_approval") else 0,
                "status": "pending", "created_at": ts},
                prefer="return=minimal")
        return self.get_chain(cid)

    def get_chain(self, chain_id):
        row = self._one("chains", self._eq("id", chain_id))
        if row is None:
            return None
        srows = self._get("chain_steps",
                          self._eq("chain_id", chain_id)
                          + "&order=position.asc")
        row["steps"] = [self._step_norm(r) for r in srows]
        return row

    def set_chain_status(self, chain_id, status):
        body = {"status": status, "updated_at": now_ts()}
        if status == "paused":
            body["paused_since"] = now_ts()
        self._req("PATCH", "chains", self._eq("id", chain_id),
                  body=body, prefer="return=minimal")
        return self.get_chain(chain_id)

    def set_step_status(self, step_id, status, work_id=""):
        body = {"status": status}
        if work_id:
            body["work_id"] = work_id
        self._req("PATCH", "chain_steps", self._eq("id", step_id),
                  body=body, prefer="return=minimal")

    def set_step_handoff(self, step_id, handoff, next_assignees):
        self._req("PATCH", "chain_steps", self._eq("id", step_id),
                  body={"handoff": json.dumps(handoff)},
                  prefer="return=minimal")
        for entry in handoff:
            for nxt in next_assignees:
                self._req("PATCH", "library",
                          self._eq("id", entry.get("library_id", "")),
                          body={"chain_next": nxt},
                          prefer="return=minimal")

    def step_by_work(self, work_id):
        row = self._one("chain_steps", self._eq("work_id", work_id))
        if row is None:
            return None
        row = dict(row)
        row["assignees"] = _loads(row.get("assignees"), [])
        return row

    def list_chains_meta(self, limit=100):
        rows = self._get("chains", "select=*&order=updated_at.desc"
                                   f"&limit={int(limit)}")
        out = []
        for r in rows:
            chain = self.get_chain(r["id"])
            if chain is None:
                continue
            for st in chain["steps"]:
                st.pop("envelopes", None)
                st.pop("content_group", None)
                if st.get("work_id"):
                    w = self.get_work(st["work_id"])
                    if w:
                        st["work_status"] = w["status"]
                        st["progress_percent"] = w.get(
                            "progress_percent", 0)
                        st["assignee"] = w["assignee"]
            out.append(chain)
        return out

    def chains_for_user(self, username):
        out = []
        for c in self.list_chains_meta(200):
            involved = {c["creator"]}
            for st in c["steps"]:
                involved.update(st.get("assignees") or [])
                if st.get("assignee"):
                    involved.add(st["assignee"])
            if username in involved:
                out.append(c)
        return out

    def groups_for_user(self, username):
        rows = self._get("group_members",
                         self._eq("username", username)
                         + "&select=group_id")
        out = []
        for r in rows:
            g = self.get_group(r["group_id"])
            if g is None:
                continue
            g["members"] = self.members(g["id"])
            mine = next((m for m in g["members"]
                         if m["username"] == username), None)
            out.append({"group_id": g["id"], "name": g["name"],
                        "settings": g["settings"], "my": mine,
                        "members": g["members"]})
        return out

    def channels_for_user(self, username):
        rows = self._get("channel_members",
                         self._eq("username", username)
                         + "&select=channel_id,role")
        out = []
        for r in rows:
            c = self.get_channel(r["channel_id"])
            if c:
                out.append({"channel_id": c["id"], "name": c["name"],
                            "my_role": r["role"]})
        return out

    # -- name parity aliases (relay calls the Store API names) ---------

    def channel_members(self, channel_id):
        return self.subscribers(channel_id)

    def channel_role_of(self, channel_id, username):
        return self.subscriber_role(channel_id, username)

    def set_channel_role(self, channel_id, username, role):
        return self.set_subscriber_role(channel_id, username, role)

    def add_library_entries(self, delivery_id, work, files):
        ids = []
        for f in files:
            lid = new_id("lib-")[:16]
            self.library_add(
                lid, f.get("name", ""), f.get("size", 0),
                f.get("sha256", ""), work["assignee"],
                to_user=work["assigner"],
                group_id=work["group_id"] or "",
                work_id=work["id"], delivery_id=delivery_id)
            ids.append(lid)
        out = []
        for lid in ids:
            row = self.library_entry(lid)
            if row is not None:
                out.append(row)
        return out

    def vault_meta(self):
        # Operator (dashboard) view: blob_id + descriptor ride along
        # (parity with the SQLite store) so the dashboard can resolve
        # the descriptor's oversight wrap into an owner download; the
        # dashboard strips the descriptor before the browser payload.
        rows = self._get(
            "vault",
            "select=id,group_id,name,size,sha256,blob_id,descriptor,"
            "added_by,pinned,ts"
            "&order=pinned.desc,ts.desc&limit=500")
        return [self._vault_norm(r) for r in rows]

    # -- dashboard sessions -----------------------------------------------------------------------
    def create_session(self, token_hash, expires_at):
        self._req("POST", "dashboard_sessions", body={
            "token_hash": token_hash, "created_at": now_ts(),
            "expires_at": expires_at}, prefer="return=minimal")

    def session_valid(self, token_hash):
        row = self._one("dashboard_sessions",
                        self._eq("token_hash", token_hash)
                        + "&select=expires_at")
        return bool(row) and row["expires_at"] >= now_ts()

    def revoke_session(self, token_hash):
        self._req("DELETE", "dashboard_sessions",
                  self._eq("token_hash", token_hash), prefer="return=minimal")

    # -- audit ---------------------------------------------------------------------------------------
    def audit(self, kind, actor, target="", group_id="", work_id="",
              status="", priority="", size=0, mentions=None, ref_id="",
              sender_nickname="", sender_role="",
              sender_custom_role="", oversight="",
              content_envelope=""):
        self._req("POST", "audit_log", body={
            "ts": now_ts(), "kind": kind, "actor": actor, "target": target,
            "group_id": group_id, "work_id": work_id, "status": status,
            "priority": priority, "size": int(size or 0),
            "mentions": json.dumps(mentions or []), "ref_id": ref_id,
            "sender_nickname": sender_nickname or "",
            "sender_role": sender_role or "",
            "sender_custom_role": sender_custom_role or "",
            "oversight": oversight or "",
            "content_envelope": content_envelope or ""},
            prefer="return=minimal")

    def list_audit(self, limit=300):
        rows = self._get(
            "audit_log",
            "select=ts,kind,actor,target,group_id,work_id,status,priority,"
            "size,mentions,ref_id,sender_nickname,sender_role,"
            f"sender_custom_role,oversight,content_envelope"
            f"&order=seq.desc&limit={limit}")
        out = []
        for r in rows:
            try:
                mentions = json.loads(r.get("mentions") or "[]")
            except Exception:
                mentions = []
            try:
                oversight = json.loads(r.get("oversight") or "null")
            except Exception:
                oversight = None
            try:
                content_envelope = json.loads(
                    r.get("content_envelope") or "null")
            except Exception:
                content_envelope = None
            out.append({"ts": r["ts"], "kind": r["kind"],
                        "from": r["actor"], "to": r["target"],
                        "group_id": r["group_id"], "work_id": r["work_id"],
                        "status": r["status"],
                        "priority": r.get("priority", ""),
                        "size": r.get("size", 0), "mentions": mentions,
                        "ref_id": r.get("ref_id", ""),
                        "sender_nickname": r.get("sender_nickname", ""),
                        "sender_role": r.get("sender_role", ""),
                        "sender_custom_role":
                            r.get("sender_custom_role", ""),
                        "oversight": oversight,
                        "content_envelope": content_envelope})
        return out

    # -- read receipts (v1.1.2: WhatsApp-style Seen state) -------------------
    def message_meta(self, message_id):
        """Parity with the SQLite Store: the audit row for one
        message id, or None. The relay derives the conversation
        from this row, never from the reader's claim."""
        if not message_id:
            return None
        row = self._one("audit_log", self._eq("ref_id", message_id)
                        + "&select=kind,actor,target,group_id")
        if not row or row.get("kind") not in (
                "message", "group_message", "channel_message"):
            return None
        return row

    def record_read(self, message_id, reader, read_at=None):
        """First read wins; returns the stored read_at."""
        ts = int(read_at or now_ts())
        existing = self._one(
            "message_reads", self._eq("message_id", message_id)
            + "&" + self._eq("reader", reader) + "&select=read_at")
        if existing:
            return int(existing["read_at"])
        try:
            self._req("POST", "message_reads", body={
                "message_id": message_id, "reader": reader,
                "read_at": ts}, prefer="return=minimal")
        except Exception:
            # Lost a concurrent first-read race: the primary key
            # kept the earliest row — report its time.
            existing = self._one(
                "message_reads", self._eq("message_id", message_id)
                + "&" + self._eq("reader", reader) + "&select=read_at")
            if existing:
                return int(existing["read_at"])
            raise
        return ts

    def reads_for(self, message_ids):
        """{message_id: [{"username", "read_at"}, ...]} ordered by
        read_at; unread ids are absent (honesty rule). Message ids
        are uuid hex — safe to inline into the in.(...) filter."""
        ids = [str(i) for i in (message_ids or []) if i]
        if not ids:
            return {}
        rows = self._get(
            "message_reads",
            "message_id=in.(" + ",".join(ids) + ")"
            "&select=message_id,reader,read_at&order=read_at.asc")
        out = {}
        for r in rows:
            out.setdefault(r["message_id"], []).append(
                {"username": r["reader"],
                 "read_at": int(r["read_at"])})
        return out

    def set_audit_status(self, ref_id, status):
        if not ref_id:
            return
        self._req("PATCH", "audit_log",
                  self._eq("ref_id", ref_id)
                  + "&kind=in.(message,group_message,channel_message)",
                  body={"status": status}, prefer="return=minimal")
