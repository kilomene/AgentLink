"""Split-architecture tests (2.3.0): the event-driven rebuild.

Everything runs against a fake HTTP layer (the opener contract
shared by ServerlessTransport and DoorbellClient) with a REAL
RTDB node store behind it — no network, no Firebase project, no
Supabase project. The fake Edge login verifies challenge
signatures for real, per username.

The invariants pinned here are the release's reason to exist
(owner-ratified 2026-11-09, after the polling architecture burned
the Supabase org into the 2026-11-08 restriction):

(a) NO Supabase fetch happens without a doorbell/inbox signal:
    the degraded loop fetches nothing while the stream is up,
    transit delivery performs zero custody reads, and a signal
    whose item the transit stream already delivered fetches
    nothing either.
(b) History sync is cursor deltas only: fetch_history_since
    returns strictly-newer rows, and a returning client's boot
    sync asks for nothing it has already journaled (the full
    backfill runs exactly once per install).
(c) Delivery retries are hard-capped and park: the outbox parks
    an entry at the policy cap, a failing ack parks at the cap
    and stops churning, a failing disappearing push parks too.
(d) Disappearing messages produce ZERO Supabase rows (queue,
    audit — anything) while standard messages produce exactly
    one custody row + one archive row; expired disappearing
    items are purged unopened; acking a disappearing item
    touches no Supabase surface at all.
(e) Presence works with NO activeness-mirror writes: login,
    transitions and logout write nothing to al_activeness /
    al_connections / al_users — presence is the Firebase
    connection, the 180s health beat and the ladder alone.
"""

from __future__ import annotations

import asyncio
import base64
import json
import threading
import time
import urllib.parse
from pathlib import Path

import pytest

from agentlink import doorbell as doorbell_mod
from agentlink import transport_v2 as transport_mod
from agentlink.crypto import Identity
from agentlink.doorbell import (
    BEAT_INTERVAL_S, DIGEST_EVERY_N_BEATS, ONLINE_MAX_AGE_S,
    SUSPECT_MAX_AGE_S, DoorbellError, activeness_state,
    sanitize_key)
from agentlink.outbox import Outbox
from agentlink.protocol import auth_challenge_payload, now_ts
from agentlink.retry import DeadLetterPark, RetryPolicy
from agentlink.transport_v2 import (
    ServerlessConfig, ServerlessTransport, TransportError)

SUPA = "https://supa.test"
EDGE = "https://edge.test/agentlink-login"
RTDB = "https://proj-default-rtdb.firebaseio.com"
ROOT = Path(__file__).resolve().parent.parent

ENVELOPE = {"v": 1, "alg": "x25519-chacha20poly1305",
            "eph_pub": "EPH", "nonce": "NONCE", "ct": "CIPHERTEXT"}
OVERSIGHT = {"v": 1, "alg": "x25519-chacha20poly1305",
             "eph_pub": "OEPH", "nonce": "ONONCE", "ct": "OCT"}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt(payload: dict) -> str:
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    return f"{head}.{body}.fakesig"


class SplitFake:
    """One fake for every leg: Edge login (real signature
    verification per username), PostgREST (queue / audit_log /
    directory with the filters the transport actually uses) and
    an RTDB node store (presence / signals / inbox / directory).
    """

    def __init__(self):
        self.calls = []  # (method, url, headers, body_obj|None)
        self.sign_pubs = {}       # username -> sign_pub b64
        self.queue_rows = []      # al_queue rows
        self.audit_rows = []      # al_audit_log rows
        self.directory_rows = []  # al_directory rows
        self.rtdb = {}            # path -> node value
        self.audit_patch_failures = 0
        self.queue_get_500 = 0    # next N queue GETs -> HTTP 500
        self.inbox_put_500 = 0    # next N RTDB inbox PUTs -> 500
        self._seq = 1000

    # -- helpers ---------------------------------------------------
    def find(self, method=None, url_part=""):
        return [(m, u, b) for (m, u, _h, b) in self.calls
                if (method is None or m == method)
                and url_part in u]

    def postgrest_calls(self):
        return [(m, u, b) for (m, u, b) in self.find()
                if "/rest/v1/" in u]

    def postgrest_writes(self):
        return [(m, u, b) for (m, u, b) in self.postgrest_calls()
                if m in ("POST", "PATCH", "DELETE")]

    def seed_queue(self, to_username, frame):
        self._seq += 1
        self.queue_rows.append({
            "seq": self._seq, "to_username": to_username,
            "payload": json.dumps(frame),
            "priority": 0, "ts": int(time.time())})
        return self._seq

    def seed_audit(self, seq, kind="message", actor="bob",
                   target="alice", ref_id="m", **kw):
        row = {"seq": seq, "ts": 1700000000 + seq, "kind": kind,
               "actor": actor, "target": target, "group_id": "",
               "work_id": "", "status": "sent", "priority": "normal",
               "size": 3, "mentions": "[]", "ref_id": ref_id,
               "sender_nickname": "", "sender_role": "",
               "sender_custom_role": "", "oversight": "",
               "content_envelope": ""}
        row.update(kw)
        self.audit_rows.append(row)
        return row

    # -- the opener --------------------------------------------------
    def __call__(self, method, url, headers, body):
        obj = json.loads(body) if body else None
        self.calls.append((method, url, headers, obj))
        status, payload = self._route(method, url, obj)
        raw = b"" if payload is None else json.dumps(payload).encode()
        return status, {}, raw

    def _route(self, method, url, obj):
        if "accounts:signInWithCustomToken" in url:
            return 200, {"idToken": "fake-id-token",
                         "refreshToken": "fake-refresh",
                         "expiresIn": "3600"}
        if "securetoken.googleapis.com" in url:
            return 200, {"id_token": "fake-id-token-2",
                         "refresh_token": "fake-refresh",
                         "expires_in": "3600"}
        if url.startswith(EDGE + "/challenge"):
            return 200, {"nonce": "nonce-xyz", "relay": "edge-login-1",
                         "expires": int(time.time()) + 60}
        if url.startswith(EDGE + "/verify"):
            payload = auth_challenge_payload(
                obj["nonce"], obj["relay"], obj["username"],
                obj["expires"])
            ok = Identity.verify_signature(
                self.sign_pubs[obj["username"]], payload,
                obj["signature"])
            if not ok:
                return 401, {"error": "bad signature"}
            jwt = make_jwt({"sub": obj["username"],
                            "role": "authenticated",
                            "username": obj["username"],
                            "exp": int(time.time()) + 3600})
            return 200, {"supabase_jwt": jwt,
                         "firebase_custom_token": "custom-token-1",
                         "expires_at": int(time.time()) + 3600}
        if url.startswith(RTDB):
            return self._rtdb(method, url, obj)
        if "/rest/v1/" in url:
            return self._postgrest(method, url, obj)
        return 404, {"message": f"unrouted {url}"}

    # -- RTDB store ----------------------------------------------------
    def _rtdb_path(self, url):
        path = url[len(RTDB):].lstrip("/")
        path = path.split("?", 1)[0]
        if path.endswith(".json"):
            path = path[:-5]
        return urllib.parse.unquote(path)

    def _rtdb(self, method, url, obj):
        path = self._rtdb_path(url)
        if method == "GET":
            node = self.rtdb.get(path)
            return 200, node
        if method == "PUT":
            if path.startswith("inbox/") and self.inbox_put_500 > 0:
                self.inbox_put_500 -= 1
                return 500, {"error": "simulated RTDB failure"}
            self.rtdb[path] = obj
            return 200, obj
        if method == "PATCH":
            node = dict(self.rtdb.get(path) or {})
            node.update(obj or {})
            self.rtdb[path] = node
            return 200, node
        if method == "DELETE":
            self.rtdb.pop(path, None)
            return 200, None
        return 405, {}

    # -- PostgREST -------------------------------------------------------
    def _postgrest(self, method, url, obj):
        parsed = urllib.parse.urlparse(url)
        table = parsed.path.rsplit("/", 1)[-1]
        query = urllib.parse.parse_qs(parsed.query)
        if "/rpc/" in parsed.path:
            return 200, True
        if table == "al_queue":
            if method == "POST":
                self._seq += 1
                row = dict(obj)
                row["seq"] = self._seq
                self.queue_rows.append(row)
                return 201, None
            if method == "GET":
                if self.queue_get_500 > 0:
                    self.queue_get_500 -= 1
                    return 500, {"message": "simulated queue outage"}
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
                                inside[inside.index("(") + 1:-1]
                                .split(",") if s}
                self.queue_rows = [r for r in self.queue_rows
                                   if r["seq"] not in seqs]
                return 204, None
        if table == "al_audit_log":
            if method == "POST":
                self._seq += 1
                row = dict(obj)
                row["seq"] = self._seq
                self.audit_rows.append(row)
                return 201, None
            if method == "GET":
                rows = list(self.audit_rows)
                kinds = query.get("kind", [""])[0]
                if kinds.startswith("in.("):
                    wanted = {k.strip() for k in
                              kinds[4:-1].split(",") if k.strip()}
                    rows = [r for r in rows if r["kind"] in wanted]
                ref = query.get("ref_id", [""])[0]
                if ref.startswith("eq."):
                    rows = [r for r in rows
                            if str(r.get("ref_id")) == ref[3:]]
                seqf = query.get("seq", [""])[0]
                if seqf.startswith("gt."):
                    rows = [r for r in rows
                            if int(r["seq"]) > int(seqf[3:])]
                elif seqf.startswith("lt."):
                    rows = [r for r in rows
                            if int(r["seq"]) < int(seqf[3:])]
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
                ref = query.get("ref_id", [""])[0]
                for r in self.audit_rows:
                    if ref.startswith("eq.") \
                            and str(r.get("ref_id")) == ref[3:]:
                        r.update(obj or {})
                return 204, None
        if table == "al_directory" and method == "GET":
            want = query.get("username", [""])[0]
            rows = list(self.directory_rows)
            if want.startswith("eq."):
                rows = [r for r in rows
                        if r.get("username") == want[3:]]
            return 200, rows
        if method in ("POST", "PATCH"):
            return (201 if method == "POST" else 204), None
        if method == "GET":
            return 200, []
        return 204, None


def make_config():
    return ServerlessConfig(
        supabase_url=SUPA, anon_key="anon-key-public",
        firebase_project_id="proj", firebase_api_key="api-key-public",
        firebase_database_url=RTDB, login_edge_url=EDGE)


@pytest.fixture()
def pair():
    """Two logged-in transports (alice, bob) on one fake."""
    fake = SplitFake()
    alice_id, bob_id = Identity.ephemeral(), Identity.ephemeral()
    fake.sign_pubs = {
        "alice": alice_id.signing_public_key_b64,
        "bob": bob_id.signing_public_key_b64}
    alice = ServerlessTransport(make_config(), opener=fake)
    bob = ServerlessTransport(make_config(), opener=fake)
    alice.login("alice", alice_id.sign, client_version="2.3.0-test")
    bob.login("bob", bob_id.sign, client_version="2.3.0-test")
    yield fake, alice, bob
    alice.logout()
    bob.logout()


# ============================ (e) presence ==========================

def test_presence_constants_are_the_ratified_ladder():
    assert BEAT_INTERVAL_S == 180
    assert ONLINE_MAX_AGE_S == 240
    assert SUSPECT_MAX_AGE_S == 420
    assert DIGEST_EVERY_N_BEATS == 1
    assert activeness_state(100) == "online"
    assert activeness_state(240) == "online"
    assert activeness_state(300) == "suspect"
    assert activeness_state(420) == "suspect"
    assert activeness_state(421) == "offline"
    assert activeness_state(None) == "offline"
    assert activeness_state(5, disconnect_fired=True) == "offline"


def test_login_and_logout_write_no_activeness_mirror(pair):
    fake, alice, _bob = pair
    # Presence DID happen — in Firebase, as a connection fact.
    node = fake.rtdb.get("presence/alice")
    assert node is not None and node["state"] == "online"
    # The Postgres mirror is deleted: nothing was written to
    # al_activeness / al_connections, and al_users was never
    # PATCHed (the last_seen touch is gone with the mirror).
    assert fake.find("POST", "/rest/v1/al_activeness") == []
    assert fake.find("POST", "/rest/v1/al_connections") == []
    assert fake.find("PATCH", "/rest/v1/al_users") == []
    # Ladder transitions are local bookkeeping: zero REST calls.
    fake.calls.clear()
    assert alice._transition_activeness("suspect") is True
    assert alice._transition_activeness("online") is True
    assert fake.postgrest_calls() == []
    alice.logout()
    # Clean close wrote offline instantly — again Firebase only.
    node = fake.rtdb.get("presence/alice")
    assert node["state"] == "offline"
    assert fake.find("POST", "/rest/v1/al_activeness") == []
    assert fake.find("POST", "/rest/v1/al_connections") == []


# ==================== (a) no fetch without a signal =================

def test_degraded_loop_fetches_nothing_while_stream_up(pair,
                                                       monkeypatch):
    fake, alice, _bob = pair
    monkeypatch.setattr(transport_mod, "SLOW_SYNC_INTERVAL_SECONDS",
                        0.05)
    fake.calls.clear()
    assert alice.slow_sync_active is False
    stop = threading.Event()
    thread = threading.Thread(
        target=alice.run_slow_sync,
        args=(lambda rows: None,), kwargs={"stop_event": stop},
        daemon=True)
    thread.start()
    try:
        time.sleep(0.35)  # ~7 cadences with the stream up
        assert fake.find("GET", "/rest/v1/al_queue") == []
        # The stream drops: the degraded cadence is the guarantee.
        alice.slow_sync_active = True
        deadline = time.time() + 3
        while time.time() < deadline and not fake.find(
                "GET", "/rest/v1/al_queue"):
            time.sleep(0.02)
        assert fake.find("GET", "/rest/v1/al_queue") != []
    finally:
        stop.set()
        thread.join(timeout=3)


def test_transit_delivery_performs_zero_supabase_reads(pair):
    fake, alice, bob = pair
    result = alice.send_dm("bob", ENVELOPE, message_id="m-transit-1",
                           oversight=OVERSIGHT)
    assert result["queued"] is True
    node = fake.rtdb.get("inbox/bob/m-transit-1")
    assert node is not None
    fake.calls.clear()
    delivered = []
    bob._on_transit_item("m-transit-1", node, delivered.extend)
    assert [r["frame"]["id"] for r in delivered] == ["m-transit-1"]
    # The live path read NOTHING from Supabase — no queue fetch,
    # no audit read, nothing.
    assert fake.find("GET", "/rest/v1/") == []
    assert bob.transit_seen("m-transit-1") is True


def test_reconnect_reconciliation_fetches_the_queue(pair):
    fake, alice, _bob = pair
    frame = {"type": "message", "id": "m-recon-1", "from": "bob",
             "content": ENVELOPE, "ts": int(time.time())}
    fake.seed_queue("alice", frame)
    stream_calls = {"n": 0}

    def stream_opener(url, headers):
        stream_calls["n"] += 1
        if stream_calls["n"] == 1:
            return iter([])  # first stream ends cleanly at once
        raise DoorbellError("stream down")

    alice.doorbell._stream_opener = stream_opener
    got = []
    stop = threading.Event()
    thread = threading.Thread(
        target=alice.listen_supervised,
        args=(lambda key, signal: None,),
        kwargs={"on_frames": got.extend, "stop_event": stop},
        daemon=True)
    thread.start()
    try:
        deadline = time.time() + 5
        while time.time() < deadline and not got:
            time.sleep(0.02)
        # The reconciliation delivered the seeded custody frame
        # after the first stream ended. (It may re-offer it on
        # later cycles while it stays unacked — at-least-once is
        # the contract; dedupe is the mailbox's job.)
        assert got and got[0]["frame"]["id"] == "m-recon-1"
        assert stream_calls["n"] >= 2  # a reconnect really happened
    finally:
        stop.set()
        thread.join(timeout=3)


# ==================== (b) cursor-delta history ======================

def test_fetch_history_since_returns_only_newer_rows(pair):
    fake, alice, _bob = pair
    for seq in (1, 2, 3, 4, 5):
        fake.seed_audit(seq, ref_id=f"m{seq}")
    fake.calls.clear()
    rows = alice.fetch_history_since(3)
    assert [r["seq"] for r in rows] == [4, 5]
    gets = fake.find("GET", "/rest/v1/al_audit_log")
    assert len(gets) == 1 and "seq=gt.3" in gets[0][1]
    assert alice.fetch_history_since(5) == []
    # The backward page still exists for the once-per-install
    # first sync.
    page = alice.fetch_history_page(limit=2)
    assert [r["seq"] for r in page] == [4, 5]


# ==================== (c) retry caps + dead-letter ==================

def test_retry_policy_schedule_and_cap():
    policy = RetryPolicy(jitter=False)
    assert policy.delay_for(0) == 1.0
    assert policy.delay_for(1) == 2.0
    assert policy.delay_for(2) == 4.0
    assert policy.delay_for(10) == 60.0  # capped
    assert policy.exhausted(4) is False
    assert policy.exhausted(5) is True


def test_dead_letter_park_records_and_persists(tmp_path):
    path = tmp_path / "dead-letter.jsonl"
    park = DeadLetterPark(str(path))
    rec = park.park("outbox", "f-1", to="bob", attempts=5,
                    last_error="boom")
    assert rec["kind"] == "outbox" and rec["attempts"] == 5
    assert park.records() == [rec]
    lines = path.read_text().strip().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["item_id"] == "f-1"


def test_outbox_entry_parks_at_the_cap(tmp_path):
    outbox = Outbox(tmp_path / "outbox-alice.json")
    outbox.add({"id": "f-poison", "type": "send", "to": "bob"})
    entry = None
    for _ in range(5):
        entry = outbox.mark_failed("f-poison", "still down")
    assert entry["attempts"] == 5
    assert entry["status"] == "parked"
    assert outbox.due(now=int(time.time()) + 10 ** 9) == []
    assert [e["id"] for e in outbox.parked()] == ["f-poison"]
    # Under the cap an entry stays pending and due.
    outbox.add({"id": "f-ok", "type": "send", "to": "bob"})
    entry = outbox.mark_failed("f-ok", "blip")
    assert entry["status"] == "pending"


def test_ack_parks_at_the_cap_and_stops_churning(pair):
    fake, alice, _bob = pair
    frame = {"type": "message", "id": "m-ack-1", "from": "bob",
             "content": ENVELOPE, "ts": int(time.time())}
    fake.seed_queue("alice", frame)
    fake.queue_get_500 = 999  # every custody read fails
    fake.calls.clear()
    for _ in range(5):
        assert alice.ack(["m-ack-1"]) == []
    records = alice.dead_letters.records()
    assert len(records) == 1
    assert records[0]["kind"] == "ack"
    assert records[0]["item_id"] == "m-ack-1"
    assert records[0]["attempts"] == 5
    gets = len(fake.find("GET", "/rest/v1/al_queue"))
    assert gets == 5  # one bounded read per ack call
    # Parked: further acks do NO Supabase work for the id.
    assert alice.ack(["m-ack-1"]) == []
    assert len(fake.find("GET", "/rest/v1/al_queue")) == gets


def test_disappearing_push_failure_parks(pair, monkeypatch):
    fake, alice, _bob = pair
    monkeypatch.setattr(transport_mod, "_sleep", lambda s: None)
    fake.inbox_put_500 = 999
    fake.calls.clear()
    result = alice.send_dm("bob", ENVELOPE, message_id="m-gone-1",
                           disappearing=True)
    assert result["transit"] is False
    assert len(fake.find("PUT", "/inbox/bob/m-gone-1")) == 5
    records = alice.dead_letters.records()
    assert len(records) == 1
    assert records[0]["kind"] == "transit_push"
    assert records[0]["item_id"] == "m-gone-1"
    assert records[0]["attempts"] == 5


# ============== (d) disappearing: zero archive rows =================

def test_disappearing_dm_writes_zero_supabase_rows(pair):
    fake, alice, _bob = pair
    fake.calls.clear()
    result = alice.send_dm("bob", ENVELOPE, message_id="m-vanish-1",
                           oversight=OVERSIGHT, disappearing=True)
    assert result["disappearing"] is True
    assert result["transit"] is True
    # ZERO Supabase writes of any kind — no custody, no archive.
    assert fake.postgrest_writes() == []
    assert fake.queue_rows == []
    assert [r for r in fake.audit_rows
            if r.get("ref_id") == "m-vanish-1"] == []
    # The transit node is its ONLY home, expiry-stamped, and the
    # frame carries the disappearing stamp + no oversight wrap.
    node = fake.rtdb.get("inbox/bob/m-vanish-1")
    assert node is not None
    assert set(node.keys()) == {"frame", "expires_at", "ts"}
    assert node["expires_at"] > now_ts()
    assert node["frame"]["disappearing"] is True
    assert node["frame"]["oversight"] is None


def test_standard_dm_writes_exactly_one_archive_row(pair):
    fake, alice, _bob = pair
    fake.calls.clear()
    alice.send_dm("bob", ENVELOPE, message_id="m-std-1",
                  oversight=OVERSIGHT)
    assert len(fake.find("POST", "/rest/v1/al_queue")) == 1
    audits = fake.find("POST", "/rest/v1/al_audit_log")
    assert len(audits) == 1 and audits[0][2]["kind"] == "message"
    # ...and the transit copy rides along for the live path.
    assert fake.rtdb.get("inbox/bob/m-std-1") is not None


def test_disappearing_group_writes_zero_supabase_rows(pair):
    fake, alice, _bob = pair
    fake.calls.clear()
    result = alice.send_group_frame(
        "g-vanish", ENVELOPE, members=["alice", "bob", "carol"],
        message_id="m-gvanish-1", disappearing=True)
    assert result["disappearing"] is True
    assert sorted(result["transit"]) == ["bob", "carol"]
    assert fake.postgrest_writes() == []
    assert fake.rtdb.get("inbox/bob/m-gvanish-1") is not None
    assert fake.rtdb.get("inbox/carol/m-gvanish-1") is not None


def test_standard_group_writes_one_archive_row(pair):
    fake, alice, _bob = pair
    fake.calls.clear()
    alice.send_group_frame(
        "g-std", ENVELOPE, members=["alice", "bob", "carol"],
        message_id="m-gstd-1", oversight=OVERSIGHT)
    assert len(fake.find("POST", "/rest/v1/al_queue")) == 2
    audits = fake.find("POST", "/rest/v1/al_audit_log")
    assert len(audits) == 1
    assert audits[0][2]["kind"] == "group_message"


def test_expired_disappearing_item_is_purged_unopened(pair):
    fake, _alice, bob = pair
    node = {"frame": {"type": "message", "id": "m-old-1",
                      "from": "alice", "content": ENVELOPE,
                      "disappearing": True,
                      "expires_at": now_ts() - 10},
            "expires_at": now_ts() - 10, "ts": 1}
    fake.rtdb["inbox/bob/m-old-1"] = node
    fake.calls.clear()
    delivered = []
    bob._on_transit_item("m-old-1", node, delivered.extend)
    assert delivered == []
    assert "inbox/bob/m-old-1" not in fake.rtdb
    assert fake.find("DELETE", "/inbox/bob/m-old-1") != []


def test_disappearing_ack_touches_no_supabase(pair):
    fake, alice, bob = pair
    alice.send_dm("bob", ENVELOPE, message_id="m-vanish-2",
                  disappearing=True)
    node = fake.rtdb.get("inbox/bob/m-vanish-2")
    delivered = []
    bob._on_transit_item("m-vanish-2", node, delivered.extend)
    assert len(delivered) == 1
    fake.calls.clear()
    acked = bob.ack(["m-vanish-2"])
    assert [f["id"] for f in acked] == ["m-vanish-2"]
    assert fake.postgrest_calls() == []
    assert "inbox/bob/m-vanish-2" not in fake.rtdb


def test_standard_ack_releases_custody_and_transit(pair):
    fake, alice, bob = pair
    alice.send_dm("bob", ENVELOPE, message_id="m-std-2",
                  oversight=OVERSIGHT)
    node = fake.rtdb.get("inbox/bob/m-std-2")
    delivered = []
    bob._on_transit_item("m-std-2", node, delivered.extend)
    acked = bob.ack(["m-std-2"])
    assert [f["id"] for f in acked] == ["m-std-2"]
    assert fake.queue_rows == []  # custody released
    assert "inbox/bob/m-std-2" not in fake.rtdb  # transit consumed
    row = [r for r in fake.audit_rows
           if r.get("ref_id") == "m-std-2"][0]
    assert row["status"] == "delivered"


# ==================== directory working copy ========================

def test_directory_working_copy_serves_reads(pair):
    fake, alice, bob = pair
    entry = {"username": "alice", "pubkey": "PK-ALICE",
             "sign_pub": "SP-ALICE", "capabilities": ["chat"],
             "cap_desc": "d", "designation": "production",
             "mode": "manual"}
    assert alice.publish_my_directory(entry) is True
    fake.calls.clear()
    got = bob.directory_entry("alice")
    assert got is not None and got["pubkey"] == "PK-ALICE"
    assert got["capabilities"] == ["chat"]
    # Served from the live layer: no PostgREST directory read.
    assert fake.find("GET", "/rest/v1/al_directory") == []
    # A miss falls back to the master record, once, and the
    # 2.2.0 double-encoded capabilities shape still decodes.
    fake.directory_rows.append(
        {"username": "carol", "pubkey": "PK-CAROL",
         "sign_pub": "SP-CAROL", "capabilities": "[\"x\"]",
         "cap_desc": "", "mode": "manual",
         "designation": "production", "last_seen": 1})
    got = bob.directory_entry("carol")
    assert got["pubkey"] == "PK-CAROL"
    assert got["capabilities"] == ["x"]
    assert len(fake.find("GET", "/rest/v1/al_directory")) == 1


def test_inbox_and_directory_node_shapes_are_pinned(pair):
    fake, alice, _bob = pair
    alice.send_dm("bob", ENVELOPE, message_id="m-shape-1")
    node = fake.rtdb["inbox/bob/m-shape-1"]
    assert set(node.keys()) == set(doorbell_mod.INBOX_FIELDS)
    alice.publish_my_directory(
        {"username": "alice", "pubkey": "PK", "sign_pub": "SP",
         "capabilities": [], "cap_desc": "", "designation": "test",
         "mode": "manual", "secret_field": "MUST NOT SHIP"})
    node = fake.rtdb["directory/alice"]
    assert set(node.keys()) <= set(doorbell_mod.DIRECTORY_FIELDS)
    assert "secret_field" not in node


def test_rules_cover_inbox_and_directory():
    rules = json.loads(
        (ROOT / "firebase" / "database.rules.json").read_text())
    top = rules["rules"]
    assert "inbox" in top and "directory" in top
    inbox_user = top["inbox"]["$user"]
    # Only the owner reads an inbox; pushes are create-only for
    # others (a delete by a non-owner fails newData.exists()).
    assert "auth.uid === $user" in inbox_user[".read"]
    item_write = inbox_user["$item"][".write"]
    assert "newData.exists()" in item_write
    assert "auth.uid === $user" in item_write
    directory = top["directory"]["$user"]
    assert "auth.uid === $user" in directory[".write"]
    assert directory[".read"] == "auth != null"


# ============ client level: signals + cursor sync (a)/(b) ===========

def _thin_agent(tmp_path, name, transport):
    """A real Agent with a logged-in transport bound, without
    start(): the two methods under test (_on_v2_signal,
    sync_history) route through self._v2 exactly as the daemon
    wires them."""
    from agentlink.client import Agent
    agent = Agent(username=name, state_dir=str(tmp_path / name),
                  transport="serverless",
                  serverless_transport=transport, mode="manual")
    agent._v2 = transport
    return agent


def test_signal_for_transit_delivered_item_fetches_nothing(
        pair, tmp_path):
    fake, alice, _bob = pair
    agent = _thin_agent(tmp_path, "alice", alice)
    alice._note_transit("m-live-1", {"frame": {"id": "m-live-1"},
                                     "expires_at": 0, "ts": 1})
    fake.calls.clear()
    agent._on_v2_signal("dm:alice|bob",
                        {"latest_item_id": "m-live-1", "counter": 3})
    assert fake.find("GET", "/rest/v1/al_queue") == []
    # A signal for an item the transit stream did NOT deliver is
    # the custody fallback: exactly then is a fetch correct.
    agent._on_v2_signal("dm:alice|bob",
                        {"latest_item_id": "m-other-9", "counter": 4})
    assert len(fake.find("GET", "/rest/v1/al_queue")) == 1


def test_boot_sync_backfills_once_then_deltas_only(pair, tmp_path):
    fake, alice, _bob = pair
    agent = _thin_agent(tmp_path, "alice", alice)
    sender = Identity.ephemeral()

    def seed(seq):
        env = sender.encrypt_for(
            agent.identity.public_key_b64,
            json.dumps({"body": f"history {seq}",
                        "kind": "text"}).encode())
        fake.seed_audit(seq, ref_id=f"h{seq}",
                        content_envelope=json.dumps(env),
                        oversight=json.dumps(OVERSIGHT))

    for seq in (10, 11, 12):
        seed(seq)
    first = asyncio.run(agent.sync_history())
    assert first["fetched"] == 3 and first["inserted"] == 3
    assert agent._history_cursor() == 12
    # The one-time backfill never used a forward cursor.
    assert [c for c in fake.find("GET", "/rest/v1/al_audit_log")
            if "seq=gt." in c[1]] == []

    for seq in (13, 14):
        seed(seq)
    fake.calls.clear()
    second = asyncio.run(agent.sync_history())
    assert second["fetched"] == 2 and second["inserted"] == 2
    gets = fake.find("GET", "/rest/v1/al_audit_log")
    assert len(gets) == 1 and "seq=gt.12" in gets[0][1]
    assert agent._history_cursor() == 14
    # Nothing new: the delta probe returns zero rows and journals
    # nothing — journaled history is never re-downloaded.
    third = asyncio.run(agent.sync_history())
    assert third["fetched"] == 0 and third["inserted"] == 0
    assert agent.mailbox is not None


# ================================================================
# (f) v211 (the D1 ship follow-up): the activeness mirror retires.
# The migration ships in the repo and applies at ship time to the
# NEW production project; these pins hold its shape so the ship
# pass cannot drift from the ratified design.
# ================================================================

V211 = ROOT / "supabase" / "migration-v211-activeness-login-record.sql"


@pytest.fixture(scope="module")
def v211():
    return V211.read_text()


def test_v211_migration_exists_and_is_v211(v211):
    assert "migration v211" in v211
    assert "al_activeness_from_login" in v211


def test_v211_login_trigger_maintains_the_row(v211):
    # The ONLY writer of al_activeness rows after 2.3.0 is the
    # login event: a trigger on al_users.last_seen (the login
    # Edge stamps it on every successful ceremony).
    assert "create trigger al_users_activeness_from_login" in v211
    assert "after insert or update of last_seen" in v211
    assert "on conflict (username) do update" in v211
    # ...and it writes a LOGIN record, not a beat: state online at
    # the authentication timestamp, never liveness.
    assert "state = 'online'" in v211
    assert "excluded.beat_at > public.al_activeness.beat_at" in v211


def test_v211_aging_sweep_is_a_noop(v211):
    # al_sweep_activeness must never age login records again: its
    # replacement body returns 0 and performs NO update of
    # al_activeness. Any other function in the file may update
    # al_work freely — the ban is scoped to the sweep's own body.
    start = v211.index(
        "create or replace function public.al_sweep_activeness()")
    body = v211[start:v211.index("$$;", start)]
    assert "return 0;" in body
    assert "update public.al_activeness" not in body
    assert "update public.al_work" not in body


def test_v211_reassignment_derives_offline_from_last_seen(v211):
    # Confirmed offline = last authentication older than
    # SUSPECT_MAX_AGE_S (420) + the reassignment grace, with a
    # missing al_users row coalescing to 0 (deregistered agent).
    assert "al_sweep_activeness_reassignment" in v211
    assert "coalesce(u.last_seen, 0) >= 420 + p_grace_seconds" in v211
    assert "awaiting_agent" in v211


def test_v211_restore_sweep(v211):
    # Back = authenticated within ONLINE_MAX_AGE_S (240).
    assert "al_sweep_activeness_restore" in v211
    assert "now_s - u.last_seen <= 240" in v211
    assert "status = 'assigned'" in v211


def test_dashboard_mirror_floor_is_freshness_gated():
    # presence.js: a stale 'online' login record must NOT lift a
    # missing RTDB node to suspect; only a record whose
    # updated_at sits inside ONLINE_MAX_AGE_S may. activeness.js
    # stays the single source of the constant.
    presence = (ROOT / "dashboard-v2" / "js" / "presence.js").read_text()
    assert 'ONLINE_MAX_AGE_S } from "./activeness.js"' in presence
    floor = presence[presence.index("activenessMirror"):]
    assert "now - Number(u.activenessMirror.updated_at)" in floor
    assert "<= ONLINE_MAX_AGE_S" in floor

