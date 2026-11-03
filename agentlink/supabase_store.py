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
import secrets as _secrets
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .protocol import new_id, new_secret, now_ts
from .store import CONTENT_AUDIT_KINDS, ROOM_AUDIT_KINDS, DEFAULT_SETTINGS, MAX_GROUP_MEMBERS, GroupFull, NotFound, UsernameTaken
from .store import NON_TERMINAL_WORK_STATUSES, RemovalBlocked
from .store import carry_claim_blocked


def _ack_id_matches(frame, wanted) -> bool:
    """Does an ack carrying ``wanted`` ids retire this queued frame?
    Message frames match by top-level id; a work_assigned frame has
    no top-level id, so it matches by its nested work id (the client
    acks work by work id). One rule, both stores, exactly."""
    if str(frame.get("id") or "") in wanted:
        return True
    if frame.get("type") == "work_assigned":
        work = frame.get("work") or {}
        return str(work.get("id") or "") in wanted
    return False


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
                                   or table.endswith("audit_log")
                                   or table.endswith("room_frames")):
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
              capabilities=None, cap_desc="", mode="autonomous",
              decision_link="", delivery_ack=0):
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
                "decision_link": decision_link if decision_link in
                        ("linked", "pending") else "",
                "delivery_ack": 1 if delivery_ack else 0,
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

    def set_secret(self, username, secret):
        # Registration-resume rotation (v1.3.8), SQLite parity:
        # only the SHA-256 hash is stored, exactly as claim()
        # stores it — the backend never holds a usable secret.
        if secret:
            self._req("PATCH", "users", self._eq("username", username),
                      body={"secret": _sha(secret)},
                      prefer="return=minimal")

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

    # -- connection registry (v1.3.4 presence truth) -------------------
    # Parity with the SQLite Store EXACTLY: every hello (and every
    # heartbeat cadence thereafter) notes WHERE the agent is
    # connected in the shared backend, so every dashboard composes
    # the same backend-wide presence truth — online from the shared
    # last_seen, current server from the freshest connection note —
    # instead of the serving relay's local peer table (the pre-1.3.4
    # home dashboard read deploy-probe "offline" while it was online
    # on its own server).

    def note_connection(self, username, server_id, endpoint,
                        home_endpoint):
        self._req("POST", "connections", body={
            "username": username, "server_id": server_id or "",
            "endpoint": endpoint or "",
            "home_endpoint": home_endpoint or "",
            "updated_at": now_ts()},
            prefer="return=minimal,resolution=merge-duplicates")

    def connections_map(self):
        rows = self._get(
            "connections",
            "select=username,server_id,endpoint,home_endpoint,"
            "updated_at")
        out = {}
        for r in rows:
            r = dict(r)
            try:
                r["updated_at"] = int(r.get("updated_at") or 0)
            except (TypeError, ValueError):
                r["updated_at"] = 0
            out[r["username"]] = r
        return out

    # -- voice-room live state (v1.3.9, shared backend) -----------------
    # Parity with the SQLite Store EXACTLY (see store.py): room state
    # is a fact in the shared backend (al_rooms), never one relay's
    # memory — a room opened on any server is joinable and signallable
    # from every server, and a closed room is closed everywhere.
    # Participants ride a jsonb list; membership changes are
    # read-modify-write, matching the SQLite store's contract.
    # Room frames for participants on brother relays ride al_room_frames
    # and are claimed (select + delete by seq) by the relay that hosts
    # the participant's connection, on its scan tick.

    @staticmethod
    def _shape_room(r):
        if r is None:
            return None
        parts = _loads(r.get("participants"), [])
        return {"room_id": r["room_id"],
                "group_id": r.get("group_id") or "",
                "creator": r.get("creator") or "",
                "participants": [str(p) for p in parts],
                "opened_at": int(r.get("opened_at") or 0),
                "updated_at": int(r.get("updated_at") or 0),
                "closed": bool(r.get("closed"))}

    def room_create(self, room_id, group_id, creator):
        now = now_ts()
        self._req("POST", "rooms", body={
            "room_id": room_id, "group_id": group_id or "",
            "creator": creator,
            "participants": json.dumps([creator]),
            "opened_at": now, "updated_at": now, "closed": 0},
            prefer="return=minimal")
        return self.room_get(room_id) or {
            "room_id": room_id, "group_id": group_id or "",
            "creator": creator, "participants": [creator],
            "opened_at": now, "updated_at": now, "closed": False}

    def room_get(self, room_id):
        row = self._one("rooms", self._eq("room_id", room_id)
                        + "&closed=eq.0")
        return self._shape_room(row)

    def rooms_open(self):
        rows = self._get("rooms", "closed=eq.0"
                                  "&order=opened_at.asc")
        return [self._shape_room(r) for r in rows]

    def room_add_participant(self, room_id, username):
        room = self.room_get(room_id)
        if room is None:
            return None
        if username not in room["participants"]:
            room["participants"].append(username)
            self._req("PATCH", "rooms", self._eq("room_id", room_id),
                      body={"participants": json.dumps(
                          room["participants"]),
                            "updated_at": now_ts()},
                      prefer="return=minimal")
        return room

    def room_remove_participant(self, room_id, username):
        room = self.room_get(room_id)
        if room is None:
            return None
        if username in room["participants"]:
            room["participants"] = [
                p for p in room["participants"] if p != username]
            closed = 0 if room["participants"] else 1
            room["closed"] = bool(closed)
            self._req("PATCH", "rooms", self._eq("room_id", room_id),
                      body={"participants": json.dumps(
                          room["participants"]),
                            "updated_at": now_ts(), "closed": closed},
                      prefer="return=minimal")
        return room

    def room_close(self, room_id):
        room = self.room_get(room_id)
        if room is None:
            return None
        self._req("PATCH", "rooms", self._eq("room_id", room_id),
                  body={"closed": 1, "updated_at": now_ts()},
                  prefer="return=minimal")
        room["closed"] = True
        return room

    def rooms_of_participant(self, username):
        return [r for r in self.rooms_open()
                if username in r["participants"]]

    def room_frame_put(self, to_username, frame):
        # room_frames is an identity-sequenced append table like the
        # queue: POST attempts=1 semantics come from the _req table
        # rule only for queue/audit_log names, so pass the frame via
        # a plain POST — a lost signal is perishable by design and
        # the sender's result does not depend on it landing twice.
        self._req("POST", "room_frames", body={
            "to_username": to_username, "frame": json.dumps(frame),
            "ts": now_ts()}, prefer="return=minimal")

    def room_frames_drain(self, usernames, max_age=120):
        """Claim pending room frames for the given usernames
        (select + delete by seq, the ack_frames discipline). Stale
        frames are claimed and dropped, never delivered late."""
        wanted = [u for u in (usernames or []) if u]
        if not wanted:
            return {}
        in_list = ",".join(f'"{u}"' for u in wanted)
        rows = self._get(
            "room_frames",
            f"to_username=in.({urllib.parse.quote(in_list, safe='(),\"')})"
            "&select=seq,to_username,frame,ts&order=seq.asc")
        if rows:
            seqs = [r["seq"] for r in rows]
            self._req("DELETE", "room_frames",
                      "seq=in.(" + ",".join(str(s) for s in seqs) + ")",
                      prefer="return=minimal")
        now = now_ts()
        out = {}
        for r in rows:
            if now - int(r.get("ts") or 0) > max_age:
                continue
            frame = _loads(r.get("frame"), None)
            if not isinstance(frame, dict):
                continue
            frame["queued"] = True
            out.setdefault(r["to_username"], []).append(frame)
        return out

    def list_room_audit(self):
        """Parity with the SQLite Store: EVERY voice-room lifecycle
        row, oldest first, paged to exhaustion — never a window."""
        kinds = ",".join(ROOM_AUDIT_KINDS)
        out = []
        offset = 0
        while True:
            rows = self._get(
                "audit_log",
                self._AUDIT_SELECT + f"&kind=in.({kinds})"
                f"&order=seq.asc&limit=1000&offset={offset}")
            out.extend(self._shape_audit(rows))
            if len(rows) < 1000:
                return out
            offset += len(rows)

    def dashboard_digest(self):
        """Parity with the SQLite Store: a cheap change signal over
        the backend facts the dashboard renders (newest presence
        beat, connection registry shape, newest server heartbeat,
        audit tail) — four one-row reads."""
        def _top(table, col):
            rows = self._get(
                table, f"select={col}&order={col}.desc&limit=1")
            if rows:
                try:
                    return int(rows[0].get(col) or 0)
                except (TypeError, ValueError):
                    return 0
            return 0
        conns = self._get("connections", "select=username")
        return "|".join(str(v) for v in (
            _top("users", "last_seen"), len(conns),
            _top("connections", "updated_at"),
            _top("servers", "last_seen"),
            _top("audit_log", "seq"),
            _top("rooms", "updated_at"),
            _top("room_frames", "seq")))

    # -- server registry (v1.2.0 peer mesh) --------------------------------
    # Parity with the SQLite Store EXACTLY (same semantics): every
    # relay registers itself on boot and heartbeats the row; clients
    # discover the live mesh from any relay and race home + peers.

    # -- server registry (v1.2.0 peer mesh; v1.3.0 carrying) -------------
    # Parity with the SQLite Store EXACTLY (same semantics): every
    # relay registers itself on boot and heartbeats the row; clients
    # discover the live mesh from any relay and race home + peers.
    # v1.3.0: server_id is the STABLE identity; owner_agent is the
    # permanent owner of a per-agent server; carried_by is only the
    # temporary helper; a lease token makes carry claims
    # single-winner (optimistic concurrency over PostgREST).

    @staticmethod
    def _norm_server(r):
        r = dict(r)
        for k in ("health", "riders", "capacity", "last_seen",
                  "first_seen", "home_last_seen", "home_healthy_since",
                  "home_health", "home_riders", "home_capacity",
                  "carry_lease_until", "carry_claimed_at"):
            if r.get(k) is not None:
                try:
                    r[k] = int(r[k])
                except (TypeError, ValueError):
                    pass
        cc = r.get("can_carry")
        r["can_carry"] = 1 if cc in (1, True, "1", "true") else \
            (0 if cc is not None else 1)
        return r

    def register_server(self, label, endpoint, host_agent="",
                        version="", health=-1, riders=0, capacity=10,
                        server_id="", owner_agent="", home_host="",
                        home_endpoint="", can_carry=True):
        from .timing import (CARRY_HANDBACK_SECONDS,
                             SERVER_STALE_SECONDS)
        now = now_ts()
        sid = server_id or endpoint
        home_ep = home_endpoint or (endpoint if owner_agent else "")
        existing = self._one("servers", self._eq("server_id", sid)
                             + "&select=*")
        if existing is None:
            self._req("POST", "servers", body={
                "endpoint": endpoint, "label": label,
                "host_agent": host_agent, "version": version,
                "health": int(health), "riders": int(riders),
                "capacity": int(capacity), "last_seen": now,
                "first_seen": now, "server_id": sid,
                "owner_agent": owner_agent,
                "home_host": home_host or host_agent,
                "home_endpoint": home_ep,
                "home_last_seen": now if owner_agent else 0,
                "home_healthy_since": now if owner_agent else 0,
                "home_health": int(health) if owner_agent else -1,
                "home_riders": int(riders) if owner_agent else 0,
                "home_capacity": int(capacity) if owner_agent else 0,
                "carry_state": "home" if owner_agent else "",
                "can_carry": 1 if can_carry else 0},
                prefer="return=minimal")
            return
        row = self._norm_server(existing)
        if owner_agent:
            prev_home = int(row.get("home_last_seen") or 0)
            if prev_home and now - prev_home <= SERVER_STALE_SECONDS:
                healthy_since = int(row.get("home_healthy_since")
                                    or now)
            else:
                healthy_since = now
            state = row.get("carry_state") or "home"
            lease_until = int(row.get("carry_lease_until") or 0)
            home_only = {
                "home_last_seen": now,
                "home_healthy_since": healthy_since,
                "home_health": int(health), "home_riders": int(riders),
                "home_capacity": int(capacity), "version": version,
                "can_carry": 1 if can_carry else 0}
            if state == "carried" and (lease_until > now or
                                       now - healthy_since
                                       < CARRY_HANDBACK_SECONDS):
                # Carried (or carrier gone but home not yet proven
                # strongly): home heartbeat ONLY, exactly the
                # SQLite semantics.
                self._req("PATCH", "servers",
                          self._eq("server_id", sid), body=home_only,
                          prefer="return=minimal")
                return
            body = dict(home_only)
            body.update({
                "endpoint": home_ep, "label": label,
                "host_agent": host_agent, "health": int(health),
                "riders": int(riders), "capacity": int(capacity),
                "last_seen": now,
                "home_host": home_host or host_agent,
                "home_endpoint": home_ep, "carry_state": "home",
                "carried_by": "", "carried_by_id": "",
                "carry_endpoint": "", "carry_lease_token": "",
                "carry_lease_until": 0, "carry_claimed_at": 0})
            self._req("PATCH", "servers", self._eq("server_id", sid),
                      body=body, prefer="return=minimal")
            return
        self._req("PATCH", "servers", self._eq("server_id", sid),
                  body={"endpoint": endpoint, "label": label,
                        "host_agent": host_agent, "version": version,
                        "health": int(health), "riders": int(riders),
                        "capacity": int(capacity), "last_seen": now,
                        "can_carry": 1 if can_carry else 0},
                  prefer="return=minimal")

    def list_servers(self, stale_after=None):
        """Live servers only (fresh registry heartbeat); a dead
        relay's row ages out and is never offered as a peer."""
        from .timing import SERVER_STALE_SECONDS
        if stale_after is None:
            stale_after = SERVER_STALE_SECONDS
        cutoff = now_ts() - int(stale_after)
        rows = self._get(
            "servers",
            f"select=*&last_seen=gte.{cutoff}&order=endpoint")
        return [self._norm_server(r) for r in rows]

    def list_agent_servers(self):
        rows = self._get(
            "servers",
            "select=*&owner_agent=neq.&order=home_last_seen,server_id")
        return [self._norm_server(r) for r in rows]

    def get_server(self, server_id):
        row = self._one("servers", self._eq("server_id", server_id)
                        + "&select=*")
        return self._norm_server(row) if row else None

    def _all_servers(self):
        rows = self._get("servers", "select=*")
        return [self._norm_server(r) for r in rows]

    def claim_carry(self, server_id, *, carrier_id, carrier_agent,
                    endpoint, carrier_health, carrier_capacity,
                    carrier_riders=0, carrier_can_carry=True,
                    carrier_carrying=0, now=None, lease_seconds=45,
                    stale_after=20, home_probe_failed=False):
        """Single-winner claim, SQLite parity: the conditional
        PATCH matches only while the lease token + lease expiry +
        claimed-at still equal the values read — a racing brother's
        landed claim changes them and this write matches zero rows."""
        if now is None:
            now = now_ts()
        if carrier_id == server_id:
            return None
        rows = self._all_servers()
        target = next((r for r in rows
                       if r.get("server_id") == server_id), None)
        if target is None or not target.get("owner_agent"):
            return None
        if not home_probe_failed and \
                now - int(target.get("home_last_seen") or 0) \
                <= stale_after:
            return None
        if target.get("carry_state") == "carried" and \
                int(target.get("carry_lease_until") or 0) > now:
            return None
        if carry_claim_blocked(
                rows, claimant_id=carrier_id,
                claimant_health=carrier_health,
                claimant_capacity=carrier_capacity,
                claimant_riders=carrier_riders,
                claimant_can_carry=carrier_can_carry,
                claimant_carrying=carrier_carrying,
                now=now, stale_after=stale_after):
            return None
        token = _secrets.token_hex(16)
        q = (self._eq("server_id", server_id)
             + f"&carry_lease_until=eq."
             f"{int(target.get('carry_lease_until') or 0)}"
             + f"&carry_claimed_at=eq."
             f"{int(target.get('carry_claimed_at') or 0)}")
        old_token = str(target.get("carry_lease_token") or "")
        if old_token:
            q += "&" + self._eq("carry_lease_token", old_token)
        body = {"endpoint": endpoint, "host_agent": carrier_agent,
                "health": int(carrier_health), "riders": 0,
                "capacity": int(carrier_capacity), "last_seen": now,
                "carry_state": "carried", "carried_by": carrier_agent,
                "carried_by_id": carrier_id, "carry_endpoint": endpoint,
                "carry_lease_token": token,
                "carry_lease_until": now + lease_seconds,
                "carry_claimed_at": now}
        out = self._req("PATCH", "servers", q, body=body,
                        prefer="return=representation")
        if out:
            return self._norm_server(out[0])
        # The conditional write may have landed while its response
        # was lost (the transport retries): if the row now shows
        # THIS carrier holding the alias, the claim is ours.
        row = self.get_server(server_id)
        if row and row.get("carried_by_id") == carrier_id and \
                row.get("carry_endpoint") == endpoint and \
                int(row.get("carry_lease_until") or 0) > now:
            return row
        return None

    def renew_carry(self, server_id, *, carrier_id, token,
                    carrier_agent, endpoint, health, riders, capacity,
                    now=None, lease_seconds=45):
        if now is None:
            now = now_ts()
        q = (self._eq("server_id", server_id)
             + "&carry_state=eq.carried"
             + "&" + self._eq("carried_by_id", carrier_id)
             + "&" + self._eq("carry_lease_token", token))
        out = self._req("PATCH", "servers", q, body={
            "endpoint": endpoint, "host_agent": carrier_agent,
            "health": int(health), "riders": int(riders),
            "capacity": int(capacity), "last_seen": now,
            "carry_lease_until": now + lease_seconds},
            prefer="return=representation")
        return bool(out)

    def release_carry(self, server_id, *, carrier_id, token,
                      now=None):
        row = self.get_server(server_id)
        if row is None:
            return False
        q = (self._eq("server_id", server_id)
             + "&carry_state=eq.carried"
             + "&" + self._eq("carried_by_id", carrier_id)
             + "&" + self._eq("carry_lease_token", token))
        out = self._req("PATCH", "servers", q, body={
            "endpoint": row.get("home_endpoint") or "",
            "host_agent": row.get("home_host") or "",
            "health": int(row.get("home_health")
                          if row.get("home_health") is not None
                          else -1),
            "riders": int(row.get("home_riders") or 0),
            "capacity": int(row.get("home_capacity") or 0),
            "last_seen": int(row.get("home_last_seen") or 0),
            "carry_state": "down", "carried_by": "",
            "carried_by_id": "", "carry_endpoint": "",
            "carry_lease_token": "", "carry_lease_until": 0,
            "carry_claimed_at": 0}, prefer="return=representation")
        if out:
            return True
        # Lost-response recovery: the release may have landed.
        row = self.get_server(server_id)
        return bool(row) and row.get("carry_state") == "down" \
            and not row.get("carried_by_id")

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

    def set_decision_link(self, username, state):
        # Decision link (v1.3.5): the agent declares in its hello
        # whether its connection is linked to its own
        # decision-making; the relay only records the declaration.
        # A connection-side fact — never a judgement on the agent.
        if state not in ("linked", "pending"):
            return
        self._req("PATCH", "users", self._eq("username", username),
                  body={"decision_link": state},
                  prefer="return=minimal")

    def set_delivery_ack(self, username, flag):
        # Delivery custody (v1.3.7): the agent declares in its
        # hello whether its client acks queued frames into its
        # durable journal; the relay only records the declaration,
        # exactly like set_decision_link. Normalised to 1/0.
        self._req("PATCH", "users", self._eq("username", username),
                  body={"delivery_ack": 1 if flag else 0},
                  prefer="return=minimal")

    def set_auth_method(self, username, method):
        # Key-signed hello (v1.3.9): how the agent's most recent
        # hello authenticated, recorded from the hello exactly like
        # set_delivery_ack records its declaration. Parity with the
        # SQLite Store: unknown values are refused.
        if method not in ("key", "secret", "resume", "bootstrap"):
            return
        self._req("PATCH", "users", self._eq("username", username),
                  body={"auth_method": method},
                  prefer="return=minimal")

    def list_users(self, query="", capability=""):
        q = ("select=username,display_name,pubkey,sign_pub,capabilities,"
             "cap_desc,mode,decision_link,delivery_ack,auth_method,"
             "last_seen,created_at&order=username")
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
            # Delivery-ack declaration (v1.3.7): anything not
            # explicitly recorded as ack-capable presents as 0.
            r["delivery_ack"] = 1 if r.get("delivery_ack") else 0
            if capability and capability.lower() not in \
                    [c.lower() for c in r["capabilities"]]:
                continue
            out.append(r)
        return out

    # -- registration removal (v1.1.10) --------------------------------
    # Parity with the SQLite Store EXACTLY (same cascade, same
    # blockers, same audit record — see store.py for the full
    # rationale: what is deleted, what is deliberately kept).

    def _ids_where(self, table, query, col):
        return {r[col] for r in self._get(table, query
                                          + f"&select={col}") if r.get(col)}

    def _removal_refs(self, username):
        work_ids = (
            self._ids_where("work", self._eq("assigner", username), "id")
            | self._ids_where("work", self._eq("assignee", username), "id"))
        chain_ids = self._ids_where(
            "chains", self._eq("creator", username), "id")
        return work_ids, chain_ids

    def _removal_id_sets(self, username):
        """{table: (pk_column, {row keys})} for the cascade tables
        whose membership is an OR over two predicates — resolved to
        explicit key sets so plan counts and delete counts are exact
        (a self-assigned work row matches both predicates once)."""
        work_ids, chain_ids = self._removal_refs(username)
        sets: dict[str, tuple[str, set]] = {}

        def by_ids(table, col, ids):
            out: set = set()
            ids = list(ids)
            for i in range(0, len(ids), 100):
                chunk = ids[i:i + 100]
                out |= self._ids_where(
                    table, f"{col}=in.("
                    + ",".join(str(v) for v in chunk) + ")", col)
            return out

        sets["work"] = ("id", set(work_ids))
        sets["chains"] = ("id", set(chain_ids))
        sets["chain_steps"] = ("id", by_ids("chain_steps", "chain_id",
                                           chain_ids))
        sets["work_deliveries"] = ("id",
                                   by_ids("work_deliveries", "work_id",
                                          work_ids)
                                   | self._ids_where(
                                       "work_deliveries",
                                       self._eq("deliverer", username),
                                       "id"))
        sets["work_checkpoints"] = ("work_id",
                                    by_ids("work_checkpoints", "work_id",
                                           work_ids)
                                    | self._ids_where(
                                        "work_checkpoints",
                                        self._eq("by_user", username),
                                        "work_id"))
        sets["upload_sessions"] = (
            "session_id",
            self._ids_where("upload_sessions",
                            self._eq("owner", username), "session_id")
            | self._ids_where("upload_sessions",
                              self._eq("for_user", username),
                              "session_id"))
        sets["blobs"] = ("id",
                         self._ids_where("blobs",
                                         self._eq("owner", username), "id")
                         | self._ids_where("blobs",
                                           self._eq("for_user", username),
                                           "id"))
        sets["library"] = ("id",
                           self._ids_where("library",
                                           self._eq("sender", username),
                                           "id")
                           | self._ids_where("library",
                                             self._eq("to_user", username),
                                             "id"))
        return sets

    # Single-predicate cascade tables, in delete order (the id-set
    # tables slot into the same overall order in _removal_tables()).
    _REMOVAL_FILTERS = (
        ("queue", "to_username"),
        ("message_reads", "reader"),
        ("group_keys", "username"),
        ("group_members", "username"),
        ("channel_keys", "username"),
        ("channel_members", "username"),
        ("invites", "created_by"),
        ("alerts", "subject"),
    )
    _REMOVAL_ORDER = (
        "work_deliveries", "work_checkpoints", "work", "chain_steps",
        "chains", "queue", "message_reads", "group_keys",
        "group_members", "channel_keys", "channel_members", "invites",
        "upload_sessions", "alerts", "blobs", "library", "users")

    def removal_blockers(self, username):
        blockers = []
        n = len(self._get("queue", self._eq("to_username", username)
                          + "&select=seq"))
        if n:
            blockers.append(
                f"{n} undelivered frame(s) in the offline queue")
        # A self-assigned live item matches both scans; dedupe by id.
        live_ids = set()
        for col in ("assigner", "assignee"):
            live_ids |= {r["id"] for r in self._get(
                "work", self._eq(col, username) + "&select=id,status")
                if r.get("status") in NON_TERMINAL_WORK_STATUSES}
        if live_ids:
            blockers.append(
                f"{len(live_ids)} non-terminal work item(s) as"
                " assigner/assignee")
        own_live = [c for c in self._get(
            "chains", self._eq("creator", username) + "&select=id,status")
            if c.get("status") in ("running", "paused")]
        if own_live:
            blockers.append(
                f"{len(own_live)} live chain(s) created by this agent")
        steps_hit = 0
        for chain in self.list_chains_meta(500):
            if chain["creator"] == username or \
                    chain.get("status") not in ("running", "paused"):
                continue
            for st in chain["steps"]:
                if st.get("status") in ("pending", "active") and (
                        st.get("target") == username
                        or username in (st.get("assignees") or [])):
                    steps_hit += 1
        if steps_hit:
            blockers.append(
                f"{steps_hit} live chain step(s) in other agents'"
                " chains target this agent")
        return blockers

    def removal_plan(self, username):
        plan = {"username": username, "exists": self.exists(username),
                "blockers": [], "remove": {}}
        if not plan["exists"]:
            return plan
        plan["blockers"] = self.removal_blockers(username)
        sets = self._removal_id_sets(username)
        counts = {}
        for table, (col, ids) in sets.items():
            counts[table] = len(ids)
        for table, col in self._REMOVAL_FILTERS:
            counts[table] = len(self._get(
                table, self._eq(col, username) + f"&select={col}"))
        counts["users"] = 1
        plan["remove"] = {t: counts.get(t, 0)
                          for t in self._REMOVAL_ORDER}
        return plan

    def _delete_where(self, table, query):
        rows = self._req("DELETE", table, query,
                         prefer="return=representation")
        return len(rows) if isinstance(rows, list) else 0

    def _delete_ids(self, table, col, ids):
        n = 0
        ids = list(ids)
        for i in range(0, len(ids), 100):
            chunk = ids[i:i + 100]
            # PostgREST returns integer columns (e.g. queue.seq) as
            # ints; the in.(...) filter is a string — stringify, or
            # the join raises TypeError and the delete never happens
            # (v1.3.7's first production ack hit exactly this).
            n += self._delete_where(
                table, f"{col}=in.(" + ",".join(str(v) for v in chunk)
                + ")")
        return n

    def remove_user(self, username, *, force=False, actor="",
                    via="self"):
        """Parity with Store.remove_user — see store.py."""
        if not self.exists(username):
            raise NotFound(username)
        blockers = [] if force else self.removal_blockers(username)
        if blockers:
            raise RemovalBlocked(username, blockers)
        sets = self._removal_id_sets(username)
        filters = dict(self._REMOVAL_FILTERS)
        removed: dict[str, int] = {}
        for table in self._REMOVAL_ORDER:
            if table == "users":
                removed[table] = self._delete_where(
                    "users", self._eq("username", username))
            elif table in sets:
                col, ids = sets[table]
                removed[table] = self._delete_ids(table, col, ids)
            else:
                removed[table] = self._delete_where(
                    table, self._eq(filters[table], username))
        total = sum(removed.values())
        self.audit("user_removed", actor or username, target=username,
                   status=f"via={via};rows={total}")
        return {"username": username, "removed": removed, "total": total}

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

    # -- delivery custody (v1.3.7): the queue as an acked outbox -------
    # Parity with the SQLite Store EXACTLY (see store.py): dequeue_all
    # stays the legacy flush; ack-capable clients are peeked with
    # pending_frames and their frames leave only on ack_frames.

    def pending_frames(self, to_username):
        """Peek WITHOUT deleting — same frames, same order
        (priority DESC, seq ASC), same queued=True stamp as
        dequeue_all, but custody stays in the store until acked."""
        rows = self._get("queue", self._eq("to_username", to_username)
                         + "&select=payload"
                         + "&order=priority.desc,seq.asc")
        out = []
        for r in rows:
            frame = json.loads(r["payload"])
            frame["queued"] = True
            out.append(frame)
        return out

    def ack_frames(self, to_username, ids):
        """Delete ONLY this user's queue rows whose payload matches
        an acked id; unknown ids are ignored. A frame matches by its
        top-level "id" (message frames), or — for a work_assigned
        frame, which carries no top-level id — by its nested work
        id: the client acks work by work id after journaling the
        assignment, and that ack must retire the frame or custody
        never completes for work. Returns the acked frames (parsed
        payloads, seq order). Match in Python over seq+payload,
        delete by seq — the same shape as the SQLite store."""
        wanted = {str(i) for i in (ids or []) if i}
        if not wanted:
            return []
        rows = self._get("queue", self._eq("to_username", to_username)
                         + "&select=seq,payload&order=seq.asc")
        seqs = []
        acked = []
        for r in rows:
            try:
                frame = json.loads(r["payload"])
            except Exception:
                continue
            if _ack_id_matches(frame, wanted):
                seqs.append(r["seq"])
                acked.append(frame)
        if seqs:
            self._delete_ids("queue", "seq", seqs)
        return acked

    def queue_stats(self, to_username):
        """{"count", "oldest_ts"} for one user's queue; oldest_ts
        is MIN(ts), None when the queue is empty."""
        rows = self._get("queue", self._eq("to_username", to_username)
                         + "&select=ts")
        if not rows:
            return {"count": 0, "oldest_ts": None}
        return {"count": len(rows),
                "oldest_ts": min(int(r["ts"]) for r in rows)}

    def queue_stats_all(self):
        """queue_stats keyed by username, only users with count>0."""
        rows = self._get("queue", "select=to_username,ts")
        out = {}
        for r in rows:
            st = out.setdefault(r["to_username"],
                                {"count": 0, "oldest_ts": None})
            st["count"] += 1
            ts = int(r["ts"])
            if st["oldest_ts"] is None or ts < st["oldest_ts"]:
                st["oldest_ts"] = ts
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

    def restore_awaiting(self, work_id):
        # Direct-work restoration (v1.3.1): the NAMED assignee of a
        # parked 1:1 work is back — return it to 'assigned' unchanged
        # (same assignee, same attempt; parked, never reassigned).
        # Guarded on the parked status, mirroring the SQLite store.
        self._req("PATCH", "work",
                  self._eq("id", work_id) + "&status=eq.awaiting_agent",
                  body={"status": "assigned",
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

    _AUDIT_SELECT = ("select=ts,kind,actor,target,group_id,work_id,"
                     "status,priority,size,mentions,ref_id,"
                     "sender_nickname,sender_role,sender_custom_role,"
                     "oversight,content_envelope")

    @staticmethod
    def _shape_audit(rows):
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

    def list_audit(self, limit=300):
        rows = self._get(
            "audit_log",
            self._AUDIT_SELECT + f"&order=seq.desc&limit={limit}")
        return self._shape_audit(rows)

    def list_content_audit(self):
        """Parity with the SQLite Store (v1.3.2): EVERY content row
        (CONTENT_AUDIT_KINDS), oldest first, paged to exhaustion —
        never a bounded window. The source for conversation
        composition and the immortality census."""
        kinds = ",".join(CONTENT_AUDIT_KINDS)
        out = []
        offset = 0
        while True:
            rows = self._get(
                "audit_log",
                self._AUDIT_SELECT + f"&kind=in.({kinds})"
                f"&order=seq.asc&limit=1000&offset={offset}")
            out.extend(self._shape_audit(rows))
            if len(rows) < 1000:
                return out
            offset += len(rows)

    def count_online_since(self, username, ts):
        """Parity with the SQLite Store: audit rows with
        kind='online' AND actor=username AND ts strictly after the
        given ts (the relay writes one per hello via
        _log_activity("online", username)). Paged to exhaustion so
        the count is exact however many reconnects are on record."""
        n = 0
        offset = 0
        while True:
            rows = self._get(
                "audit_log",
                "select=seq&kind=eq.online"
                f"&actor=eq.{urllib.parse.quote(str(username), safe='')}"
                f"&ts=gt.{int(ts)}&order=seq.asc"
                f"&limit=1000&offset={offset}")
            n += len(rows)
            if len(rows) < 1000:
                return n
            offset += len(rows)

    # _AUDIT_SELECT plus seq, the cursor column (list_content_audit's
    # select deliberately carries no seq; the per-user catch-up does).
    _AUDIT_SELECT_SEQ = ("select=seq,ts,kind,actor,target,group_id,"
                         "work_id,status,priority,size,mentions,ref_id,"
                         "sender_nickname,sender_role,sender_custom_role,"
                         "oversight,content_envelope")

    def content_audit_for_user(self, username, limit=200,
                               before_seq=None):
        """Parity with the SQLite Store EXACTLY (see store.py):
        content rows (CONTENT_AUDIT_KINDS) where the user is a
        party — "from"/"to" match, or the row's group_id is one of
        the user's groups or channels (channel frames carry the
        channel id in group_id). Only seq < before_seq when given.
        Returns the NEWEST ``limit`` matches, oldest-first, each row
        carrying seq plus exactly the fields list_content_audit
        returns."""
        group_ids = {g["group_id"]
                     for g in self.groups_for_user(username)}
        channel_ids = {c["channel_id"]
                       for c in self.channels_for_user(username)}
        kinds = ",".join(CONTENT_AUDIT_KINDS)
        q = (self._AUDIT_SELECT_SEQ + f"&kind=in.({kinds})")
        if before_seq is not None:
            q += f"&seq=lt.{int(before_seq)}"
        q += "&order=seq.asc"
        raw = []
        offset = 0
        while True:
            rows = self._get("audit_log",
                             q + f"&limit=1000&offset={offset}")
            raw.extend(rows)
            if len(rows) < 1000:
                break
            offset += len(rows)
        shaped = self._shape_audit(raw)
        for row, s in zip(raw, shaped):
            try:
                s["seq"] = int(row.get("seq"))
            except (TypeError, ValueError):
                s["seq"] = row.get("seq")
        scopes = group_ids | channel_ids
        matching = []
        for r in shaped:
            if r.get("from") == username or r.get("to") == username:
                matching.append(r)
            elif r.get("group_id") and r["group_id"] in scopes:
                matching.append(r)
            elif r.get("channel_id") and \
                    r["channel_id"] in channel_ids:
                matching.append(r)
        limit = int(limit)
        if limit <= 0:
            return []
        return matching[-limit:]

    def audit_rows_for_ids(self, ids):
        """Parity with the SQLite Store: audit rows (any kind) whose
        ref_id OR work_id is in ``ids``, chunked so the filter URL
        stays bounded however large the id set grows."""
        ids = [str(i) for i in (ids or []) if i]
        if not ids:
            return []
        out = []
        for i in range(0, len(ids), 150):
            chunk = ",".join(ids[i:i + 150])
            for col in ("ref_id", "work_id"):
                rows = self._get(
                    "audit_log",
                    self._AUDIT_SELECT + f"&{col}=in.({chunk})"
                    "&order=seq.asc")
                out.extend(self._shape_audit(rows))
        out.sort(key=lambda r: r["ts"])
        return out

    def audit_for_work(self, work_id):
        """Parity with the SQLite Store: every audit row recorded
        against one work id."""
        if not work_id:
            return []
        rows = self._get(
            "audit_log",
            self._AUDIT_SELECT + "&" + self._eq("work_id", work_id)
            + "&order=seq.asc")
        return self._shape_audit(rows)

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
        out = {}
        for i in range(0, len(ids), 150):
            rows = self._get(
                "message_reads",
                "message_id=in.(" + ",".join(ids[i:i + 150]) + ")"
                "&select=message_id,reader,read_at&order=read_at.asc")
            for r in rows:
                out.setdefault(r["message_id"], []).append(
                    {"username": r["reader"],
                     "read_at": int(r["read_at"])})
        for v in out.values():
            v.sort(key=lambda x: x["read_at"])
        return out

    def set_audit_status(self, ref_id, status):
        if not ref_id:
            return
        self._req("PATCH", "audit_log",
                  self._eq("ref_id", ref_id)
                  + "&kind=in.(message,group_message,channel_message)",
                  body={"status": status}, prefer="return=minimal")
