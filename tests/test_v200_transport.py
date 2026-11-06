"""Serverless transport + doorbell tests (v2.0 Phase 3+4).

Everything runs against a fake HTTP layer (a callable with the
opener contract shared by ServerlessTransport and DoorbellClient):
no network, no Firebase project, no Supabase project. The fake
Edge login VERIFIES the challenge signature for real, against a
real Ed25519 Identity, so the login flow is tested end to end.

Covered: login challenge-response; send shapes mirroring
supabase_store (al_queue / al_audit_log) + signal taps; fetch/ack
custody semantics; 401 re-login; slow-sync engagement; the
activeness ladder + beat economy + transition-only mirrors;
reconnect backoff; pre-expiry JWT refresh; scoped presence
subscriptions; content never touching the Firebase wire.
"""

from __future__ import annotations

import ast
import base64
import http.client
import json
import threading
import time
import urllib.error
import urllib.parse
from pathlib import Path

import pytest

from agentlink import doorbell as doorbell_mod
from agentlink import proxycreds
from agentlink import transport_v2 as transport_mod
from agentlink.crypto import Identity
from agentlink.doorbell import (
    BEAT_INTERVAL_S, ONLINE_MAX_AGE_S, SUSPECT_MAX_AGE_S,
    DoorbellClient, DoorbellError, ScopedPresenceWatcher,
    activeness_of_record, activeness_state, build_counterparty_set,
    presence_is_online, sanitize_key, unsanitize_key, user_key)
from agentlink.protocol import auth_challenge_payload
from agentlink.transport_v2 import (
    JWT_REFRESH_MARGIN_S, RECONNECT_BACKOFF_CAP_S,
    SLOW_SYNC_INTERVAL_SECONDS, ServerlessConfig, ServerlessTransport,
    TransportError, next_backoff_s, transport_mode)

SUPA = "https://supa.test"
EDGE = "https://edge.test/agentlink-login"
RTDB = "https://proj-default-rtdb.firebaseio.com"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt(payload: dict) -> str:
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    return f"{head}.{body}.fakesig"


class FakeHttp:
    """One fake for every leg (the transport shares its opener
    with the doorbell, exactly as production wiring does)."""

    def __init__(self, jwt_exp: int | None = None):
        self.calls = []  # (method, url, headers, body_obj|None)
        self.identity = Identity.ephemeral()
        self.jwt_exp = jwt_exp or (int(time.time()) + 3600)
        self.challenge_count = 0
        self.verify_ok = None
        self.last_verify = None
        self.advertise_oversight = ""   # verify-reply oversight key
        self.queue_rows = []   # stored al_queue rows (dicts)
        self.audit_rows = []   # stored al_audit_log rows (raw cols)
        self.postgrest_401_once = False
        self.rpc_result = True       # al_attach_oversight's verdict
        self.audit_patch_failures = 0  # next N audit PATCHes -> 500
        self.empty_get_responses = 0   # next N PostgREST GETs -> 200, zero-byte body
        self.empty_queue_gets_after_first = False  # queue GETs past the first -> empty body
        self._queue_gets_seen = 0
        self.group_member_rows = []    # al_group_members seed
        self.channel_member_rows = []  # al_channel_members seed
        self._seq = 1000

    # -- helpers for tests -------------------------------------------
    def find(self, method=None, url_part=""):
        out = []
        for m, u, _h, b in self.calls:
            if method and m != method:
                continue
            if url_part and url_part not in u:
                continue
            out.append((m, u, b))
        return out

    def postgrest_writes(self):
        return [(m, u, b) for (m, u, b) in self.find()
                if "/rest/v1/" in u and m in ("POST", "PATCH", "DELETE")]

    def seed_queue(self, to_username, frame):
        self._seq += 1
        self.queue_rows.append({
            "seq": self._seq, "to_username": to_username,
            "payload": json.dumps(frame),
            "priority": 0, "ts": int(time.time())})
        return self._seq

    # -- the opener ----------------------------------------------------
    def __call__(self, method, url, headers, body):
        obj = json.loads(body) if body else None
        self.calls.append((method, url, headers, obj))
        if method == "GET" and "/rest/v1/" in url \
                and self.empty_get_responses > 0:
            self.empty_get_responses -= 1
            return 200, {}, b""
        if method == "GET" and "/rest/v1/al_queue" in url:
            self._queue_gets_seen += 1
            if self.empty_queue_gets_after_first \
                    and self._queue_gets_seen > 1:
                return 200, {}, b""
        status, payload = self._route(method, url, obj)
        raw = b"" if payload is None else json.dumps(payload).encode()
        return status, {}, raw

    def _route(self, method, url, obj):
        # Identity Toolkit: custom token -> ID token.
        if "accounts:signInWithCustomToken" in url:
            return 200, {"idToken": "fake-id-token",
                         "refreshToken": "fake-refresh",
                         "expiresIn": "3600"}
        if "securetoken.googleapis.com" in url:
            return 200, {"id_token": "fake-id-token-2",
                         "refresh_token": "fake-refresh",
                         "expires_in": "3600"}
        # Login Edge.
        if url.startswith(EDGE + "/challenge"):
            self.challenge_count += 1
            return 200, {"nonce": "nonce-xyz", "relay": "edge-login-1",
                         "expires": int(time.time()) + 60}
        if url.startswith(EDGE + "/verify"):
            self.last_verify = obj
            payload = auth_challenge_payload(
                obj["nonce"], obj["relay"], obj["username"],
                obj["expires"])
            self.verify_ok = Identity.verify_signature(
                self.identity.signing_public_key_b64, payload,
                obj["signature"])
            jwt = make_jwt({"sub": obj["username"],
                            "role": "authenticated",
                            "username": obj["username"],
                            "exp": self.jwt_exp})
            reply = {"supabase_jwt": jwt,
                     "firebase_custom_token": "custom-token-1",
                     "expires_at": self.jwt_exp}
            if self.advertise_oversight:
                reply["oversight_pubkey"] = self.advertise_oversight
            return 200, reply
        # Firebase RTDB.
        if url.startswith(RTDB):
            if "/signals/" in url and method == "GET":
                return 200, {"counter": 41, "latest_item_id": "old",
                             "ts": 1}
            return 200, {}
        # PostgREST.
        if "/rest/v1/" in url:
            if self.postgrest_401_once:
                self.postgrest_401_once = False
                return 401, {"message": "JWT expired"}
            return self._postgrest(method, url, obj)
        return 404, {"message": f"unrouted {url}"}

    def _postgrest(self, method, url, obj):
        parsed = urllib.parse.urlparse(url)
        table = parsed.path.rsplit("/", 1)[-1]
        query = urllib.parse.parse_qs(parsed.query)
        if "/rpc/" in parsed.path:
            return 200, self.rpc_result
        if table in ("al_group_members", "al_channel_members") \
                and method == "GET":
            rows = self.group_member_rows if table == "al_group_members" \
                else self.channel_member_rows
            key = "group_id" if table == "al_group_members" \
                else "channel_id"
            want = query.get(key, [""])[0]
            if want.startswith("eq."):
                rows = [r for r in rows if r.get(key) == want[3:]]
            return 200, rows
        if table == "al_queue":
            if method == "POST":
                self._seq += 1
                row = dict(obj)
                row["seq"] = self._seq
                self.queue_rows.append(row)
                return 201, None
            if method == "GET":
                rows = list(self.queue_rows)
                want = query.get("to_username", [""])[0]
                if want.startswith("eq."):
                    rows = [r for r in rows
                            if r["to_username"] == want[3:]]
                off = query.get("offset", [""])[0]
                lim = query.get("limit", [""])[0]
                if off.isdigit():
                    rows = rows[int(off):]
                if lim.isdigit():
                    rows = rows[:int(lim)]
                return 200, rows
            if method == "DELETE":
                seqs = set()
                for key, vals in query.items():
                    if key == "seq":
                        inside = vals[0]
                        seqs = {int(s) for s in
                                inside[inside.index("(") + 1:-1].split(",")
                                if s}
                self.queue_rows = [r for r in self.queue_rows
                                   if r["seq"] not in seqs]
                return 204, None
        if table == "al_audit_log":
            if method == "POST":
                return 201, None
            if method == "GET":
                rows = list(self.audit_rows)
                order = query.get("order", [""])[0]
                if order.startswith("seq."):
                    rows.sort(key=lambda r: r["seq"],
                              reverse=order.endswith(".desc"))
                lim = query.get("limit", [""])[0]
                if lim:
                    rows = rows[:int(lim)]
                return 200, rows
            if method == "PATCH":
                if self.audit_patch_failures > 0:
                    self.audit_patch_failures -= 1
                    return 500, {"message": "simulated write loss"}
                return 204, None
        if method in ("POST", "PATCH"):
            return 201 if method == "POST" else 204, None
        if method == "GET":
            return 200, []
        return 204, None


def make_config():
    return ServerlessConfig(
        supabase_url=SUPA, anon_key="anon-key-public",
        firebase_project_id="proj", firebase_api_key="api-key-public",
        login_edge_url=EDGE)


def make_transport(fake, stream_opener=None):
    return ServerlessTransport(make_config(), opener=fake,
                               stream_opener=stream_opener)


@pytest.fixture()
def logged_in():
    fake = FakeHttp()
    transport = make_transport(fake)
    transport.login("alice", fake.identity.sign, client_version="2.0.0-test")
    yield fake, transport
    transport.logout()


ENVELOPE = {"v": 1, "alg": "x25519-chacha20poly1305",
            "eph_pub": "EPH", "nonce": "NONCE", "ct": "CIPHERTEXT"}
OVERSIGHT = {"v": 1, "alg": "x25519-chacha20poly1305",
             "eph_pub": "OEPH", "nonce": "ONONCE", "ct": "OCT"}


# ============================ login =================================

def test_login_challenge_flow_and_presence_and_mirror():
    fake = FakeHttp()
    transport = make_transport(fake)
    try:
        result = transport.login("alice", fake.identity.sign,
                                 client_version="2.0.0-test")
        assert result["username"] == "alice"
        assert fake.challenge_count == 1
        # The fake Edge verified the signature over the CANONICAL
        # payload (protocol.auth_challenge_payload) for real.
        assert fake.verify_ok is True
        assert transport._jwt
        assert transport.doorbell.has_token
        # Presence connect write: full metadata node shape.
        puts = fake.find("PUT", "/presence/alice.json")
        assert len(puts) == 1
        body = puts[0][2]
        assert set(body.keys()) == {"state", "ts", "connected_at",
                                    "client_version", "transport"}
        assert body["state"] == "online"
        assert body["client_version"] == "2.0.0-test"
        assert body["transport"] == "serverless-rest"
        # Login transition mirrored exactly once: activeness +
        # connections + last_seen.
        assert len(fake.find("POST", "/rest/v1/al_activeness")) == 1
        act = fake.find("POST", "/rest/v1/al_activeness")[0][2]
        assert act["username"] == "alice" and act["state"] == "online"
        assert len(fake.find("POST", "/rest/v1/al_connections")) == 1
        assert len(fake.find("PATCH", "/rest/v1/al_users")) == 1
        assert transport.activeness_state == "online"
    finally:
        transport.logout()


def test_send_requires_login():
    transport = make_transport(FakeHttp())
    with pytest.raises(TransportError):
        transport.send_dm("bob", ENVELOPE)


def test_jwt_carries_no_service_material():
    fake = FakeHttp()
    transport = make_transport(fake)
    try:
        transport.login("alice", fake.identity.sign)
        payload = json.loads(base64.urlsafe_b64decode(
            transport._jwt.split(".")[1] + "=="))
        assert payload["role"] == "authenticated"
        assert "service" not in transport._jwt
        assert not hasattr(transport.config, "service_key")
        assert not hasattr(transport.config, "service_role_key")
    finally:
        transport.logout()


def test_401_triggers_one_relogin_and_retry(logged_in):
    fake, transport = logged_in
    before = fake.challenge_count
    fake.postgrest_401_once = True
    rows = transport.fetch_unacked("alice")
    assert rows == []
    assert fake.challenge_count == before + 1


# ============================ send ==================================

def test_send_dm_shapes_and_signal_tap(logged_in):
    fake, transport = logged_in
    fake.calls.clear()
    out = transport.send_dm("bob", ENVELOPE, oversight=OVERSIGHT,
                            priority="urgent")
    assert out["queued"] is True and out["to"] == "bob"
    # al_queue insert: supabase_store.enqueue body shape exactly.
    queue_posts = fake.find("POST", "/rest/v1/al_queue")
    assert len(queue_posts) == 1
    body = queue_posts[0][2]
    assert set(body.keys()) == {"to_username", "payload", "priority", "ts"}
    assert body["to_username"] == "bob"
    assert body["priority"] == 2  # PRIORITY_WEIGHT["urgent"]
    frame = json.loads(body["payload"])
    assert frame["type"] == "message" and frame["from"] == "alice"
    assert frame["id"] == out["id"] and frame["group_id"] is None
    # Content passed through untouched (transport never decrypts).
    assert frame["content"] == ENVELOPE
    assert frame["oversight"] == OVERSIGHT
    # al_audit_log insert: SupabaseStore.audit body shape exactly.
    audits = fake.find("POST", "/rest/v1/al_audit_log")
    assert len(audits) == 1
    abody = audits[0][2]
    assert set(abody.keys()) == {
        "ts", "kind", "actor", "target", "group_id", "work_id",
        "status", "priority", "size", "mentions", "ref_id",
        "sender_nickname", "sender_role", "sender_custom_role",
        "oversight", "content_envelope"}
    assert abody["kind"] == "message" and abody["actor"] == "alice"
    assert abody["target"] == "bob" and abody["ref_id"] == out["id"]
    assert json.loads(abody["mentions"]) == []
    assert json.loads(abody["oversight"]) == OVERSIGHT
    # The audit row MUST carry the content envelope (the relay's
    # _on_send recorded it; the group/channel paths record it):
    # without it, DM history read-back returns rows whose content
    # is gone once the queue frame is acked — live-proven defect
    # 2026-11-06 (every v2 DM audit row had content_envelope="").
    assert json.loads(abody["content_envelope"]) == ENVELOPE
    assert abody["size"] == len("CIPHERTEXT")
    # Signal tap: sanitized DM key, counter bumped, ids only.
    taps = fake.find("PATCH", "/signals/")
    assert len(taps) == 1
    assert "/signals/dm%3Aalice%7Cbob.json" in taps[0][1]
    assert taps[0][2] == {"latest_item_id": out["id"], "counter": 42,
                          "ts": {".sv": "timestamp"}}


def test_send_group_frame_fanout_one_audit_one_tap(logged_in):
    fake, transport = logged_in
    fake.calls.clear()
    content = {"epoch": 3, "nonce": "GN", "ct": "GCT"}
    out = transport.send_group_frame(
        "g-abc123", content, members=["alice", "bob", "carol"])
    assert sorted(out["queued"]) == ["bob", "carol"]
    queue_posts = fake.find("POST", "/rest/v1/al_queue")
    assert len(queue_posts) == 2
    assert {json.loads(b["payload"])["group_id"]
            for _m, _u, b in queue_posts} == {"g-abc123"}
    audits = fake.find("POST", "/rest/v1/al_audit_log")
    assert len(audits) == 1
    assert audits[0][2]["kind"] == "group_message"
    assert audits[0][2]["group_id"] == "g-abc123"
    assert json.loads(audits[0][2]["content_envelope"]) == content
    # ONE signal tap regardless of member count.
    assert len(fake.find("PATCH", "/signals/")) == 1


# ======================= fetch / ack ================================

def test_fetch_unacked_peeks_in_seq_order_without_releasing(logged_in):
    fake, transport = logged_in
    f1 = {"type": "message", "id": "m1", "content": ENVELOPE}
    f2 = {"type": "message", "id": "m2", "content": ENVELOPE}
    transport.doorbell  # silence linter noise
    fake.seed_queue("alice", f2)
    fake.seed_queue("alice", f1)
    fake.seed_queue("bob", {"type": "message", "id": "other"})
    rows = transport.fetch_unacked()
    assert [r["frame"]["id"] for r in rows] == ["m2", "m1"]  # seq order
    assert all(r["frame"]["queued"] is True for r in rows)
    assert fake.find("DELETE", "/rest/v1/al_queue") == []
    assert len(fake.queue_rows) == 3  # custody intact


def test_login_surfaces_advertised_oversight_key():
    # 2.0.4: the login Edge advertises the owner-oversight public
    # key with the session tokens (the serverless welcome frame);
    # the transport must surface it for the Agent to adopt. A reply
    # without the field leaves the key empty, and a later reply
    # that omits it never wipes a key already delivered.
    fake = FakeHttp()
    fake.advertise_oversight = "oversight-pub-b64"
    transport = make_transport(fake)
    assert transport.oversight_pubkey == ""
    transport.login("alice", fake.identity.sign)
    assert transport.oversight_pubkey == "oversight-pub-b64"
    transport.logout()

    fake2 = FakeHttp()
    transport2 = make_transport(fake2)
    transport2.login("alice", fake2.identity.sign)
    assert transport2.oversight_pubkey == ""
    transport2.logout()


def test_clipped_get_body_retries_then_succeeds():
    # 2.0.3 (soak catch, 2026-11-06): an imperfect network clipped a
    # large queue response mid-JSON and the raw JSONDecodeError
    # escaped _rest into the daemon's signal handler. A read whose
    # body will not decode is a transient fault: retried in place.
    good = json.dumps([{
        "seq": 1, "to_username": "alice", "priority": "normal",
        "ts": 1,
        "payload": json.dumps({"type": "message", "id": "m1"})}]).encode()
    clipped = good[:len(good) // 2]
    calls = []

    def opener(method, url, headers, body):
        calls.append(method)
        if len(calls) == 1:
            return 200, {}, clipped
        return 200, {}, good

    transport = make_transport(opener)
    transport.username = "alice"
    rows = transport.fetch_unacked()
    assert [r["frame"]["id"] for r in rows] == ["m1"]
    assert calls == ["GET", "GET"]


def test_persistent_clip_raises_transport_error_not_decode_error():
    calls = []

    def opener(method, url, headers, body):
        calls.append(method)
        return 200, {}, b'[{"seq": 1, "payload": "unterminated'

    transport = make_transport(opener)
    transport.username = "alice"
    with pytest.raises(transport_mod.TransportError):
        transport.fetch_unacked()
    assert calls == ["GET"] * 4  # first attempt + 3 bounded retries


def test_clipped_write_response_raises_without_reexecuting():
    calls = []

    def opener(method, url, headers, body):
        calls.append(method)
        return 200, {}, b'{"id": "unterminated'

    transport = make_transport(opener)
    transport.username = "alice"
    with pytest.raises(transport_mod.TransportError):
        transport._rest("POST", "queue", body={"x": 1})
    assert calls == ["POST"]  # a write is never blindly re-executed


def test_ack_releases_only_matching_and_marks_delivered(logged_in):
    fake, transport = logged_in
    fake.seed_queue("alice", {"type": "message", "id": "m1"})
    fake.seed_queue("alice", {"type": "message", "id": "m2"})
    fake.seed_queue("alice", {"type": "work_assigned",
                              "work": {"id": "w1"}})
    fake.calls.clear()
    acked = transport.ack(["m1", "w1", "unknown-id"])
    assert [f.get("id") or f["work"]["id"] for f in acked] == ["m1", "w1"]
    deletes = fake.find("DELETE", "/rest/v1/al_queue")
    assert len(deletes) == 1
    remaining = [json.loads(r["payload"])["id"]
                 for r in fake.queue_rows]
    assert remaining == ["m2"]
    patches = fake.find("PATCH", "/rest/v1/al_audit_log")
    assert len(patches) == 1  # only the message frame, not the work
    assert "ref_id=eq.m1" in patches[0][1]
    assert patches[0][2] == {"status": "delivered"}
    # Acking nothing / unknown ids retires nothing.
    fake.calls.clear()
    assert transport.ack(["nope"]) == []
    assert fake.find("DELETE", "/rest/v1/al_queue") == []


def test_ack_status_write_precedes_custody_release(logged_in):
    fake, transport = logged_in
    fake.seed_queue("alice", {"type": "message", "id": "m1"})
    fake.calls.clear()
    transport.ack(["m1"])
    patch_at = next(i for i, (m, u, _h, _b) in enumerate(fake.calls)
                    if m == "PATCH" and "al_audit_log" in u)
    delete_at = next(i for i, (m, u, _h, _b) in enumerate(fake.calls)
                     if m == "DELETE" and "al_queue" in u)
    assert patch_at < delete_at


def test_ack_failed_status_write_keeps_custody_for_retry(logged_in):
    fake, transport = logged_in
    fake.seed_queue("alice", {"type": "message", "id": "m1"})
    fake.seed_queue("alice", {"type": "message", "id": "m2"})
    fake.audit_patch_failures = 1  # m1's status write is lost
    fake.calls.clear()
    acked = transport.ack(["m1", "m2"])
    # m1 was NOT retired (its frame stays in custody for the next
    # cycle); m2's failure-free ack was not aborted by m1's.
    assert [f.get("id") for f in acked] == ["m2"]
    remaining = [json.loads(r["payload"])["id"] for r in fake.queue_rows]
    assert remaining == ["m1"]
    # The retry lands whole: status write, then custody release.
    acked = transport.ack(["m1"])
    assert [f.get("id") for f in acked] == ["m1"]
    assert fake.queue_rows == []


def test_attach_oversight_rpc_round_trip(logged_in):
    fake, transport = logged_in
    fake.calls.clear()
    out = transport.attach_oversight(
        {"ref_id": "ref-1", "oversight": dict(OVERSIGHT)})
    assert out == {"attached": True}
    calls = [(m, u, b) for (m, u, _h, b) in fake.calls if "/rpc/" in u]
    assert len(calls) == 1
    method, url, body = calls[0]
    assert method == "POST"
    assert url.endswith("/rest/v1/rpc/al_attach_oversight")
    assert body["p_ref_id"] == "ref-1"
    assert json.loads(body["p_oversight"]) == OVERSIGHT
    # The function's own verdict (row already wrapped / not mine)
    # surfaces as attached=False, not an error.
    fake.rpc_result = False
    out = transport.attach_oversight(
        {"ref_id": "ref-1", "oversight": dict(OVERSIGHT)})
    assert out == {"attached": False}
    # A missing wrap is a no-op: no RPC is spent on it.
    fake.calls.clear()
    assert transport.attach_oversight({"ref_id": "ref-1"}) == \
        {"attached": False}
    assert [c for c in fake.calls if "/rpc/" in c[1]] == []


def test_request_group_key_enqueues_admins_only(logged_in):
    fake, transport = logged_in
    fake.group_member_rows = [
        {"group_id": "g1", "username": "alice", "role": "member"},
        {"group_id": "g1", "username": "bob", "role": "admin"},
        {"group_id": "g1", "username": "carol", "role": "superadmin"},
        {"group_id": "g1", "username": "dave", "role": "member"},
        {"group_id": "g2", "username": "erin", "role": "admin"},
    ]
    fake.calls.clear()
    out = transport.request_group_key({"group_id": "g1"})
    assert out == {"admins": ["bob", "carol"]}
    queued = {r["to_username"]: json.loads(r["payload"])
              for r in fake.queue_rows}
    assert set(queued) == {"bob", "carol"}
    for frame in queued.values():
        assert frame["type"] == "group_key_request"
        assert frame["group_id"] == "g1"
        assert frame["from"] == "alice"
        assert frame["id"]


def test_request_channel_key_enqueues_admins_only(logged_in):
    fake, transport = logged_in
    fake.channel_member_rows = [
        {"channel_id": "c1", "username": "alice", "role": "member"},
        {"channel_id": "c1", "username": "bob", "role": "admin"},
        {"channel_id": "c1", "username": "dave", "role": "member"},
    ]
    out = transport.request_channel_key({"channel_id": "c1"})
    assert out == {"admins": ["bob"]}
    queued = {r["to_username"]: json.loads(r["payload"])
              for r in fake.queue_rows}
    assert set(queued) == {"bob"}
    assert queued["bob"]["type"] == "channel_key_request"
    assert queued["bob"]["channel_id"] == "c1"


def test_fetch_conversation_dm_shaping(logged_in):
    fake, transport = logged_in
    fake.audit_rows = [
        {"seq": 7, "ts": 100, "kind": "message", "actor": "alice",
         "target": "bob", "group_id": "", "work_id": "",
         "status": "delivered", "priority": "normal", "size": 3,
         "mentions": "[]", "ref_id": "m1", "sender_nickname": "",
         "sender_role": "", "sender_custom_role": "",
         "oversight": "", "content_envelope": ""},
        {"seq": 8, "ts": 101, "kind": "message", "actor": "bob",
         "target": "alice", "group_id": "", "work_id": "",
         "status": "delivered", "priority": "normal", "size": 3,
         "mentions": "[]", "ref_id": "m2", "sender_nickname": "",
         "sender_role": "", "sender_custom_role": "",
         "oversight": "", "content_envelope": ""},
        {"seq": 9, "ts": 102, "kind": "message", "actor": "alice",
         "target": "carol", "group_id": "", "work_id": "",
         "status": "delivered", "priority": "normal", "size": 3,
         "mentions": "[]", "ref_id": "m3", "sender_nickname": "",
         "sender_role": "", "sender_custom_role": "",
         "oversight": "", "content_envelope": ""}]
    rows = transport.fetch_conversation(peer="bob")
    assert [r["ref_id"] for r in rows] == ["m1", "m2"]
    assert rows[0]["from"] == "alice" and rows[0]["to"] == "bob"
    assert rows[0]["seq"] == 7 and rows[0]["oversight"] is None


def test_fetch_conversation_bounds_the_wire_window(logged_in):
    """The history read must ask PostgREST for the newest `limit`
    rows (order=seq.desc + limit=), never fetch the whole thread
    and slice locally — the unbounded read truncates on lossy
    links (live-proven 2026-11-06)."""
    fake, transport = logged_in
    fake.audit_rows = [
        {"seq": s, "ts": 100 + s, "kind": "message",
         "actor": "alice" if s % 2 else "bob",
         "target": "bob" if s % 2 else "alice", "group_id": "",
         "work_id": "", "status": "delivered", "priority": "normal",
         "size": 3, "mentions": "[]", "ref_id": f"m{s}",
         "sender_nickname": "", "sender_role": "",
         "sender_custom_role": "", "oversight": "",
         "content_envelope": ""}
        for s in range(1, 6)]
    rows = transport.fetch_conversation(peer="bob", limit=2)
    assert [r["ref_id"] for r in rows] == ["m4", "m5"]  # newest, oldest-first
    gets = fake.find("GET", "/rest/v1/al_audit_log")
    assert gets and "order=seq.desc" in gets[-1][1]
    assert "limit=2" in gets[-1][1]


# ==================== doorbell wire hygiene ==========================

def test_firebase_wire_carries_no_content_fields(logged_in):
    fake, transport = logged_in
    transport.send_dm("bob", ENVELOPE, oversight=OVERSIGHT)
    transport.doorbell.tap_doorbell("bob", "work_assigned", "w-9")
    transport.doorbell.beat_presence("alice")
    forbidden = {"content", "body", "ct", "nonce", "eph_pub",
                 "oversight", "file", "data_b64", "envelope"}

    def keys_of(node):
        if isinstance(node, dict):
            for k, v in node.items():
                yield k
                yield from keys_of(v)
        elif isinstance(node, list):
            for v in node:
                yield from keys_of(v)

    rtdb_calls = [(m, u, b) for (m, u, b) in fake.find()
                  if u.startswith(RTDB) and b is not None]
    assert rtdb_calls, "expected RTDB traffic"
    for _m, _u, body in rtdb_calls:
        assert not (set(keys_of(body)) & forbidden), body


def test_stream_failure_engages_slow_sync():
    fake = FakeHttp()

    def bad_stream(url, headers):
        raise DoorbellError("stream refused")

    transport = make_transport(fake, stream_opener=bad_stream)
    try:
        transport.login("alice", fake.identity.sign)
        assert transport.listen_signals(lambda p, d: None) is False
        assert transport.slow_sync_active is True
        fake.seed_queue("alice", {"type": "message", "id": "m9"})
        frames = transport.slow_sync_once()
        assert [f["frame"]["id"] for f in frames] == ["m9"]
    finally:
        transport.logout()


def test_silent_stream_death_engages_slow_sync():
    # 2.0.6 (found live in the release exercise): a stream whose
    # path died silently — opened fine, then no line ever arrives
    # and no error is raised — must surface as an ordinary stream
    # failure (socket read timeout -> DoorbellError), so the
    # supervisor reconnects and slow-sync takes over delivery.
    # Before the fix the listen loop blocked on it forever and
    # delivery stalled while presence stayed green.
    fake = FakeHttp()

    def stalling_stream(url, headers):
        def gen():
            raise TimeoutError("read timed out")
            yield b""
        return gen()

    transport = make_transport(fake, stream_opener=stalling_stream)
    try:
        transport.login("alice", fake.identity.sign)
        assert transport.listen_signals(lambda p, d: None) is False
        assert transport.slow_sync_active is True
    finally:
        transport.logout()


def test_stream_socket_carries_a_liveness_timeout():
    # The opener must never leave a stream socket unbounded: an
    # infinite timeout is exactly the half-open trap above.
    import inspect
    src = inspect.getsource(doorbell_mod._default_stream_opener)
    assert "settimeout(None)" not in src
    assert "STREAM_READ_TIMEOUT_S" in src
    assert 60 <= doorbell_mod.STREAM_READ_TIMEOUT_S <= 300


def test_empty_body_get_is_retried_then_raises(logged_in):
    # 2.0.6 (found live in the release exercise): this VM's
    # egress proxy answers LARGE PostgREST reads with 200 and a
    # zero-byte body. PostgREST itself never does that (an empty
    # result set is "[]"), so an empty body on a GET is a clipped
    # transfer, not a result. Before the fix _rest returned None
    # for it and fetch_unacked read that as "queue empty" —
    # delivery stalled forever with every health light green.
    fake, transport = logged_in
    fake.seed_queue("alice", {"type": "message", "id": "m1"})
    fake.calls.clear()
    fake.empty_get_responses = 10  # outlasts the retry budget
    with pytest.raises(TransportError):
        transport.fetch_unacked()
    gets = fake.find("GET", "/rest/v1/al_queue")
    assert len(gets) == 4  # initial attempt + 3 bounded retries


def test_empty_body_get_recovers_on_retry(logged_in):
    # The same fault, transient: two emptied responses, then the
    # real one — the fetch must land the rows, not report an
    # empty queue.
    fake, transport = logged_in
    fake.seed_queue("alice", {"type": "message", "id": "m1"})
    fake.empty_get_responses = 2
    frames = transport.fetch_unacked()
    assert [f["frame"]["id"] for f in frames] == ["m1"]


def test_fetch_unacked_pages_through_a_deep_queue(logged_in):
    # 2.0.6: the custody read pages at _QUEUE_PAGE rows — one
    # whole-queue response is exactly the size a lossy path
    # kills. 25 seeded rows must arrive complete and in seq
    # order across multiple page reads.
    fake, transport = logged_in
    for i in range(25):
        fake.seed_queue("alice", {"type": "message",
                                  "id": f"m{i:02d}"})
    fake.calls.clear()
    frames = transport.fetch_unacked()
    assert [f["frame"]["id"] for f in frames] == \
        [f"m{i:02d}" for i in range(25)]
    gets = fake.find("GET", "/rest/v1/al_queue")
    assert len(gets) >= 3  # paged, not one whole-queue read


def test_fetch_unacked_returns_partial_progress(logged_in):
    # A page failure AFTER progress returns the progress (the
    # caller processes and acks it; the next cycle resumes the
    # rest) — only a first-page failure raises.
    fake, transport = logged_in
    for i in range(25):
        fake.seed_queue("alice", {"type": "message",
                                  "id": f"m{i:02d}"})
    fake.empty_queue_gets_after_first = True
    frames = transport.fetch_unacked()
    assert [f["frame"]["id"] for f in frames] == \
        [f"m{i:02d}" for i in range(transport._QUEUE_PAGE)]


def test_empty_body_write_still_returns_none(logged_in):
    # Writes keep the legitimate empty -> None path (a 204 /
    # return=minimal response is bodyless by design); the
    # empty-body suspicion applies to reads only.
    fake, transport = logged_in
    fake.queue_rows = []
    out = transport._rest("DELETE", "queue", "seq=in.(424242)")
    assert out is None


def test_slow_sync_fetches_even_with_a_healthy_stream(monkeypatch):
    # 2.0.6 (found live in the release exercise): delivery must
    # not hinge on signal arrival. A freshly booted daemon whose
    # stream snapshot was lost sat on a full custody queue and
    # fetched NOTHING because the cadence fetch was gated on
    # slow_sync_active (stream known-down). The reconciliation
    # fetch now runs every cadence regardless; signals remain
    # only the instant path.
    import threading as _threading
    monkeypatch.setattr(transport_mod, "SLOW_SYNC_INTERVAL_SECONDS",
                        0.2)
    fake = FakeHttp()
    transport = make_transport(fake)
    try:
        transport.login("alice", fake.identity.sign)
        assert transport.slow_sync_active is False
        fake.seed_queue("alice", {"type": "message", "id": "m-lost-tap"})
        delivered = []
        stop = _threading.Event()
        worker = _threading.Thread(
            target=transport.run_slow_sync,
            args=(lambda frames: delivered.extend(frames), stop),
            daemon=True)
        worker.start()
        time.sleep(1.15)
        stop.set()
        worker.join(timeout=5)
        ids = [f["frame"]["id"] for f in delivered]
        assert "m-lost-tap" in ids
    finally:
        transport.logout()


# ==================== activeness ladder ===============================

def test_ladder_constants_are_the_owners_numbers():
    assert BEAT_INTERVAL_S == 5
    assert ONLINE_MAX_AGE_S == 10
    assert SUSPECT_MAX_AGE_S == 15


@pytest.mark.parametrize("age,expected", [
    (0, "online"), (5, "online"), (10, "online"),
    (11, "suspect"), (13, "suspect"), (15, "suspect"),
    (16, "offline"), (45, "offline"), (3600, "offline"),
    (None, "offline"), (-3, "online"),
])
def test_activeness_ladder_boundaries(age, expected):
    assert activeness_state(age) == expected


def test_activeness_disconnect_overrides_any_age():
    assert activeness_state(0, disconnect_fired=True) == "offline"
    assert activeness_state(3, disconnect_fired=True) == "offline"


def test_activeness_of_record_uses_ladder_and_offline_write():
    now_ms = int(time.time() * 1000)
    fresh = {"state": "online", "ts": now_ms - 3_000}
    assert activeness_of_record(fresh, now_ms=now_ms) == "online"
    ageing = {"state": "online", "ts": now_ms - 12_000}
    assert activeness_of_record(ageing, now_ms=now_ms) == "suspect"
    stale = {"state": "online", "ts": now_ms - 20_000}
    assert activeness_of_record(stale, now_ms=now_ms) == "offline"
    fired = {"state": "offline", "ts": now_ms}
    assert activeness_of_record(fired, now_ms=now_ms) == "offline"
    assert activeness_of_record(None) == "offline"
    assert presence_is_online(fresh, now_ms=now_ms) is True
    assert presence_is_online(ageing, now_ms=now_ms) is False


def test_beat_economy_300_virtual_seconds_zero_postgrest():
    """300 virtual seconds at BEAT_INTERVAL_S=5 => ~60 beats, all
    on the OWN presence node, and ZERO PostgREST calls from beats.
    Virtual time is scaled 100x (interval 0.05s) so the test runs
    in ~3 real seconds; the production default stays 5s (pinned
    by test_ladder_constants_are_the_owners_numbers)."""
    fake = FakeHttp()
    doorbell = DoorbellClient(project_id="proj",
                              api_key="api-key-public", opener=fake)
    doorbell.exchange_custom_token("custom-token-1")
    doorbell.set_presence("alice", client_version="t",
                          transport="serverless-rest")
    fake.calls.clear()
    beats = []
    doorbell.start_heartbeat("alice", interval_s=0.05,
                             on_beat=lambda ok: beats.append(ok))
    try:
        time.sleep(3.05)  # 300 virtual seconds at 100x scale
    finally:
        doorbell.stop_heartbeat(fire_offline=False)
    assert 55 <= len(beats) <= 66, f"expected ~60 beats, got {len(beats)}"
    assert all(beats), "every beat should land against the fake"
    beat_calls = fake.find("PATCH", "/presence/alice.json")
    assert len(beat_calls) == len(beats)
    assert all(b == {"state": "online", "ts": {".sv": "timestamp"}}
               for _m, _u, b in beat_calls)
    assert [c for c in fake.calls if "/rest/v1/" in c[1]] == []
    assert [c for c in fake.calls if c[1].startswith(EDGE)] == []


def test_heartbeat_runs_independent_of_a_blocked_worker():
    """A wedged worker callback must never stop the beats: the
    beat loop is its own thread in doorbell.py."""
    fake = FakeHttp()
    doorbell = DoorbellClient(project_id="proj",
                              api_key="api-key-public", opener=fake)
    doorbell.exchange_custom_token("custom-token-1")
    doorbell.set_presence("alice")
    beats = []
    doorbell.start_heartbeat("alice", interval_s=0.05,
                             on_beat=lambda ok: beats.append(ok))
    release = threading.Event()
    worker_done = threading.Event()

    def wedged_worker():
        release.wait(10)  # stuck: never returns until released
        worker_done.set()

    worker = threading.Thread(target=wedged_worker, daemon=True)
    worker.start()
    try:
        time.sleep(0.6)
        assert len(beats) >= 8, f"beats starved by worker: {len(beats)}"
        assert doorbell.heartbeat_running
        assert doorbell._hb_thread.name == "agentlink-heartbeat"
        assert doorbell._hb_thread is not threading.current_thread()
        assert not worker_done.is_set()  # the worker really was stuck
    finally:
        release.set()
        doorbell.stop_heartbeat(fire_offline=False)
        worker.join(timeout=2)


def test_mirror_writes_happen_on_transitions_only(logged_in):
    fake, transport = logged_in
    baseline = len(fake.postgrest_writes())
    assert transport.activeness_state == "online"
    # Same-state repeats are free: no mirror traffic at all.
    assert transport._transition_activeness("online") is False
    assert len(fake.postgrest_writes()) == baseline
    # A real transition writes: al_activeness + connections + users.
    assert transport._transition_activeness("suspect") is True
    after = fake.postgrest_writes()
    assert len(after) == baseline + 3
    assert transport._transition_activeness("suspect") is False
    assert len(fake.postgrest_writes()) == baseline + 3
    assert transport._transition_activeness("offline") is True
    assert len(fake.postgrest_writes()) == baseline + 6
    states = [b["state"] for _m, u, b
              in fake.postgrest_writes()[baseline:]
              if "/rest/v1/al_activeness" in u]
    assert states == ["suspect", "offline"]


# ==================== reconnect / refresh =============================

def test_reconnect_backoff_first_immediate_and_capped():
    assert RECONNECT_BACKOFF_CAP_S == 5
    assert [next_backoff_s(i) for i in range(7)] == \
        [0.0, 1.0, 2.0, 4.0, 5.0, 5.0, 5.0]
    assert SLOW_SYNC_INTERVAL_SECONDS == 60


def test_refresh_scheduled_from_token_exp():
    now = int(time.time())
    fake = FakeHttp(jwt_exp=now + 130)
    transport = make_transport(fake)
    try:
        transport.login("alice", fake.identity.sign)
        assert JWT_REFRESH_MARGIN_S == 120
        until = transport.seconds_until_refresh(now=now)
        assert until is not None and 0 <= until <= 12
        assert transport._refresh_timer is not None
        assert abs(transport._refresh_timer.interval - 10) <= 4
    finally:
        transport.logout()
    assert transport._refresh_timer is None


def test_source_pins_cadence_and_mirror_structure():
    """Structural pins over both modules' sources:
    * run_slow_sync waits on SLOW_SYNC_INTERVAL_SECONDS (60s);
    * the heartbeat wait in doorbell.py is the interval variable
      whose default is BEAT_INTERVAL_S;
    * update_presence_backup is called ONLY from _mirror_activeness
      (transition-only mirrors are structural, not a promise)."""
    tpath = Path(__file__).resolve().parents[1] / \
        "agentlink" / "transport_v2.py"
    dpath = Path(__file__).resolve().parents[1] / \
        "agentlink" / "doorbell.py"
    ttree = ast.parse(tpath.read_text())
    dtree = ast.parse(dpath.read_text())

    def funcs(tree):
        return {n.name: n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef)}

    tfuncs = funcs(ttree)
    waits = [c for c in ast.walk(tfuncs["run_slow_sync"])
             if isinstance(c, ast.Call)
             and isinstance(c.func, ast.Attribute)
             and c.func.attr == "wait"]
    assert waits and isinstance(waits[0].args[0], ast.Name)
    assert waits[0].args[0].id == "SLOW_SYNC_INTERVAL_SECONDS"

    callers = set()
    for name, fn in tfuncs.items():
        for c in ast.walk(fn):
            if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) \
                    and c.func.attr == "update_presence_backup":
                callers.add(name)
    assert callers == {"_mirror_activeness"}

    dsrc = dpath.read_text()
    assert "BEAT_INTERVAL_S if interval_s is None" in dsrc
    assert "self._hb_stop.wait(interval)" in dsrc
    # No periodic PostgREST: transport source has no other .wait()
    # cadence literal below the slow-sync constant.
    for c in ast.walk(ttree):
        if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) \
                and c.func.attr == "wait" and c.args \
                and isinstance(c.args[0], ast.Constant) \
                and isinstance(c.args[0].value, (int, float)):
            raise AssertionError(
                f"literal wait cadence found: {c.args[0].value}")


# ==================== scoped subscriptions ============================

def test_counterparty_set_builder():
    s = build_counterparty_set(
        dm_peers=["bob"], group_members=["bob", "carol"],
        channel_members=["dave"], assignees=["erin"],
        assigners=["frank"], exclude=["alice"])
    assert s == {"bob", "carol", "dave", "erin", "frank"}


def test_scoped_subscriptions_follow_membership_changes():
    fake = FakeHttp()
    now_ms = int(time.time() * 1000)
    opened = []

    def stream_opener(url, headers):
        opened.append(url)
        record = {"state": "online", "ts": now_ms,
                  "connected_at": now_ms, "client_version": "t",
                  "transport": "serverless-rest"}
        data = json.dumps({"path": "/", "data": record})
        return [b"event: put", f"data: {data}".encode(), b""]

    doorbell = DoorbellClient(project_id="proj",
                              api_key="api-key-public", opener=fake,
                              stream_opener=stream_opener)
    doorbell.exchange_custom_token("custom-token-1")
    membership = {"alice", "bob"}
    changes = []
    watcher = ScopedPresenceWatcher(
        doorbell, provider=lambda: set(membership),
        on_change=lambda u, rec, st: changes.append((u, st)))
    try:
        watcher.refresh()
        assert watcher.subscribed_paths() == \
            {"presence/alice", "presence/bob"}
        deadline = time.time() + 3
        while time.time() < deadline and len(changes) < 2:
            time.sleep(0.02)
        assert {u for u, _s in changes} == {"alice", "bob"}
        assert all(s == "online" for _u, s in changes)
        # Membership change: carol joins, alice leaves — the
        # subscription set must track it exactly.
        membership.discard("alice")
        membership.add("carol")
        watcher.refresh()
        assert watcher.subscribed_paths() == \
            {"presence/bob", "presence/carol"}
        assert watcher.subscribed_usernames() == {"bob", "carol"}
        assert any("/presence/carol.json" in u for u in opened)
    finally:
        watcher.close()


def test_transport_presence_watch_requires_provider():
    transport = make_transport(FakeHttp())
    with pytest.raises(TransportError):
        transport.start_presence_watch(lambda u, r, s: None)


# ==================== key sanitization / mode =========================

def test_sanitize_key_maps_forbidden_chars_and_roundtrips():
    raw = "dm:alice.smith|bob#x/y[z]$w"
    key = sanitize_key(raw)
    for ch in ".$#[]/":
        assert ch not in key
    assert unsanitize_key(key) == raw
    assert user_key("alice.smith") == "alice%2Esmith"
    assert sanitize_key("g-abc123") == "g-abc123"


def test_transport_mode_flip():
    assert transport_mode({"AGENTLINK_TRANSPORT": "serverless"}) \
        == "serverless"
    assert transport_mode({"AGENTLINK_TRANSPORT": "relay"}) == "relay"
    # 2.0.1: the v1 relay is retired — the DEFAULT is serverless.
    # The old relay default stranded every auto-updated agent that
    # had no flip set (beulah, frozen 2026-11-04 on 2.0.0).
    assert transport_mode({}) == "serverless"


def test_serverless_config_production_defaults():
    # 2.0.1: a stock daemon connects with zero configuration — the
    # production endpoints are baked in (all public client
    # coordinates); env still overrides every one of them.
    cfg = ServerlessConfig.from_env({})
    assert cfg.supabase_url == \
        "https://gqmzwbmmloklrkvxlmdc.supabase.co"
    assert cfg.login_edge_url.endswith("/functions/v1/agentlink-login")
    assert cfg.firebase_database_url == \
        "https://agentlink-84609-default-rtdb.firebaseio.com"
    assert cfg.anon_key  # the public, RLS-guarded anon key
    assert cfg.firebase_api_key.startswith("AIza")
    over = ServerlessConfig.from_env(
        {"AGENTLINK_SUPABASE_URL": "https://example.invalid"})
    assert over.supabase_url == "https://example.invalid"


# ============ default openers route through proxycreds ============

class _FakeResp:
    """Minimal stand-in for an http.client response as returned
    by proxycreds.open_url (context manager + status/headers/
    read)."""

    def __init__(self, status=200, body=b"{}"):
        self.status = status
        self.headers = {}
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_v2_default_openers_route_through_proxycreds(monkeypatch):
    """The v2 transport and doorbell DEFAULT openers must dial
    through proxycreds.open_url — the egress proxy credential
    resolved FRESH at dial time. The pre-fix defaults used
    plain urllib, whose proxy comes from the process
    environment pinned at process start, so a long-lived v2
    daemon stranded at the first credential rotation on hosts
    with a rotating egress proxy (every other platform module
    was wired to proxycreds in v1.8.1, pins PX1-PX6)."""
    seen = []

    def fake_open_url(req, timeout=None):
        seen.append((req.full_url, timeout))
        return _FakeResp(200, b'{"ok": true}')

    monkeypatch.setattr(proxycreds, "open_url", fake_open_url)
    out = transport_mod._default_opener(
        "GET", "https://db.test/rest", {}, None)
    assert out[0] == 200 and out[2] == b'{"ok": true}'
    out = doorbell_mod._default_opener(
        "GET", "https://db.test/rest", {}, None)
    assert out[0] == 200 and out[2] == b'{"ok": true}'
    assert [u for u, _ in seen] == ["https://db.test/rest"] * 2

    def raising_open_url(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 403, "nope", {}, None)

    monkeypatch.setattr(proxycreds, "open_url", raising_open_url)
    out = transport_mod._default_opener(
        "GET", "https://db.test/rest", {}, None)
    assert out[0] == 403  # HTTP errors RETURNED, never raised
    out = doorbell_mod._default_opener(
        "GET", "https://db.test/rest", {}, None)
    assert out[0] == 403


class _ClippedResp(_FakeResp):
    """A response whose chunked stream lost its terminating
    chunk AFTER the full body arrived: read() raises
    IncompleteRead carrying the complete payload in .partial
    (the egress proxy's intermittent clip, seen live in the
    v2.0 exercise: DM fetch read 4983 bytes then raised)."""

    def read(self):
        raise http.client.IncompleteRead(self._body)


def test_v2_default_openers_tolerate_clipped_body(monkeypatch):
    """A clipped stream must surface its (complete) payload,
    not an exception: both v2 default openers return the
    partial body and let the downstream JSON parser judge
    completeness — the blobstore R2 reader's doctrine."""
    body = b'{"ok": true, "rows": [1, 2, 3]}'
    monkeypatch.setattr(
        proxycreds, "open_url",
        lambda req, timeout=None: _ClippedResp(200, body))
    out = transport_mod._default_opener(
        "GET", "https://db.test/rest", {}, None)
    assert out[0] == 200 and out[2] == body
    out = doorbell_mod._default_opener(
        "GET", "https://db.test/rest", {}, None)
    assert out[0] == 200 and out[2] == body

    def raising_open_url(req, timeout=None):
        err = urllib.error.HTTPError(
            req.full_url, 500, "boom", {}, None)
        err.read = lambda *a: (_ for _ in ()).throw(
            http.client.IncompleteRead(body))
        raise err

    monkeypatch.setattr(proxycreds, "open_url", raising_open_url)
    out = transport_mod._default_opener(
        "GET", "https://db.test/rest", {}, None)
    assert out[0] == 500 and out[2] == body


def test_v2_stream_opener_routes_through_proxycreds(monkeypatch):
    """The doorbell's default STREAM opener also dials through
    proxycreds (fresh credential), then returns the live
    response for the supervised listen loop."""
    monkeypatch.setattr(
        proxycreds, "open_url",
        lambda req, timeout=None: _FakeResp(200))
    resp = doorbell_mod._default_stream_opener(
        "https://db.test/stream", {})
    assert resp.status == 200


def test_activeness_mirror_failure_retries_on_slow_sync_cadence():
    # 2.0.2 (beulah, 2026-11-06): her connect transition mirrored
    # into a transient failure; the write is fail-soft, so she
    # stayed invisible in al_activeness while fully active. The
    # slow-sync cadence now re-asserts the current state whenever
    # a mirror error is outstanding, and stops once it lands.
    import threading as _threading
    fake = FakeHttp()
    transport = make_transport(fake)
    try:
        transport.login("alice", fake.identity.sign,
                        client_version="2.0.2-test")
        assert transport.last_mirror_error == ""
        # The beulah state: an error outstanding, no row landed
        # for it, agent steadily online (no ladder change coming).
        transport.last_mirror_error = "simulated mirror failure"
        fake.calls.clear()
        stop = _threading.Event()
        worker = _threading.Thread(
            target=transport.run_slow_sync,
            args=(lambda frames: None, stop), daemon=True)
        worker.start()
        deadline = time.time() + 5
        while time.time() < deadline and transport.last_mirror_error:
            time.sleep(0.05)
        stop.set()
        worker.join(timeout=5)
        assert transport.last_mirror_error == ""
        posts = fake.find("POST", "/rest/v1/al_activeness")
        assert len(posts) == 1
        assert posts[0][2]["state"] == "online"
        assert posts[0][2]["client_version"] == "2.0.2-test"
    finally:
        transport.logout()


def test_slow_sync_reasserts_mirror_while_online(monkeypatch):
    # 2.0.4 (owner catch, 2026-11-06): the Postgres activeness
    # mirror is written on transitions, but the sweep ages rows
    # by beat_at/last_seen — timestamps nothing advanced for a
    # steadily online serverless agent (its 5s beats live in
    # Firebase by design), so the sweep stamped live agents
    # 'offline' ~1 minute after login and the dashboard's mirror
    # floor lied forever. The slow-sync cadence now re-asserts
    # the mirror while the state is online, keeping the Postgres
    # record as fresh as the sweep's serverless thresholds
    # (migration v205) require.
    import threading as _threading
    monkeypatch.setattr(transport_mod, "SLOW_SYNC_INTERVAL_SECONDS",
                        0.2)
    fake = FakeHttp()
    transport = make_transport(fake)
    try:
        transport.login("alice", fake.identity.sign,
                        client_version="2.0.4-test")
        assert transport.last_mirror_error == ""
        fake.calls.clear()
        stop = _threading.Event()
        worker = _threading.Thread(
            target=transport.run_slow_sync,
            args=(lambda frames: None, stop), daemon=True)
        worker.start()
        time.sleep(1.15)
        stop.set()
        worker.join(timeout=5)
        posts = fake.find("POST", "/rest/v1/al_activeness")
        assert len(posts) >= 3
        assert all(p[2]["state"] == "online" for p in posts)
        assert all(p[2]["transport"] == "rtdb" for p in posts)
        # The backup touch rides the same write (last_seen is the
        # sweep's other aging input).
        assert fake.find("PATCH", "/rest/v1/al_users")
    finally:
        transport.logout()


def test_mirror_backup_failure_is_fail_soft_and_recorded(logged_in):
    # 2.0.5 (2.0.4 soak catch, 2026-11-06): _mirror_activeness
    # documented fail-soft, but its backup leg
    # (update_presence_backup) raised straight through — a
    # clipped PATCH users response killed the slow-sync thread
    # at soak minute 12. The whole mirror now honors the
    # contract: failure recorded in last_mirror_error, never
    # raised, and the activeness write itself still lands.
    _fake, transport = logged_in
    def boom(online=True):
        raise transport_mod.TransportError("simulated backup failure")
    transport.update_presence_backup = boom
    transport.last_mirror_error = ""
    transport._mirror_activeness("online")  # must not raise
    assert transport.last_mirror_error == "simulated backup failure"
    posts = _fake.find("POST", "/rest/v1/al_activeness")
    assert posts and posts[-1][2]["state"] == "online"


def test_slow_sync_thread_survives_a_failing_mirror(monkeypatch):
    # The slow-sync loop must keep cycling (and keep retrying
    # the mirror) even when every mirror attempt fails — a dead
    # slow-sync thread silently removes the fallback fetch and
    # the mirror truth-keeping with it.
    import threading as _threading
    monkeypatch.setattr(transport_mod, "SLOW_SYNC_INTERVAL_SECONDS",
                        0.2)
    fake = FakeHttp()
    transport = make_transport(fake)
    try:
        transport.login("alice", fake.identity.sign)
        def boom(online=True):
            raise transport_mod.TransportError("simulated outage")
        transport.update_presence_backup = boom
        stop = _threading.Event()
        worker = _threading.Thread(
            target=transport.run_slow_sync,
            args=(lambda frames: None, stop), daemon=True)
        worker.start()
        time.sleep(0.75)
        alive = worker.is_alive()
        stop.set()
        worker.join(timeout=5)
        assert alive
        assert transport.last_mirror_error == "simulated outage"
    finally:
        transport.logout()


def test_mark_read_409_is_first_read_wins_not_an_error():
    # 2.0.2 (2026-11-06): a duplicate read delivery (signal +
    # slow-sync overlap, or a retry) makes the message_reads POST
    # answer 409. mark_read's contract is first-read-wins, so the
    # 409 is success with the ORIGINAL timestamp — a bare raise
    # killed the live DM read-state proof mid-run.
    transport = make_transport(FakeHttp())
    transport.username = "alice"
    calls = []

    def fake_rest(method, table, query="", body=None, prefer="",
                  _retried=False):
        calls.append((method, table))
        if table == "audit_log":
            return [{"kind": "message", "actor": "bob",
                     "target": "alice", "group_id": ""}]
        if table == "message_reads" and method == "GET":
            # First look: nothing. After the 409: the winner's row.
            if sum(1 for m, t in calls
                   if t == "message_reads" and m == "GET") >= 2:
                return [{"read_at": 424242}]
            return []
        if table == "message_reads" and method == "POST":
            raise TransportError(
                "PostgREST POST message_reads HTTP 409")
        return None

    transport._rest = fake_rest
    transport._audit = lambda *a, **kw: None
    transport._enqueue = lambda *a, **kw: None
    transport._tap = lambda *a, **kw: None
    out = transport.mark_read(["msg-x"])
    assert out["read"] == ["msg-x"]
    assert out["reads"] == [{"id": "msg-x", "read_at": 424242}]
