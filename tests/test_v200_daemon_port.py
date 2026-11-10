"""Daemon-loop port tests (v2.0): client.py's Agent on the
serverless transport.

The port's contract, pinned here against a fake HTTP backend and
a stub doorbell (the real doorbell's behaviour is proven by the
Phase 3+4/6 suites; this phase proves the DAEMON starts and wires
it):

* start() on the serverless flip performs the Edge login ceremony
  (real signature verification at the fake Edge), starts the
  doorbell heartbeat via login, and starts ALL FOUR supervision
  pieces the Phase 6 finding names (2.3.0 added the inbox
  transit stream): listen_supervised (signal
  stream thread), listen_inbox_supervised (transit stream),
  run_slow_sync (degraded-cadence thread) and the scoped
  presence watcher.
* Inbound custody frames flow fetch -> _dispatch -> handler ->
  ack exactly as on the relay path.
* Sends route through the transport (send_message -> directory
  lookup -> send_dm custody row).
* Read receipts route through the transport's mark_read.
* (Coverage phase) the full request surface has serverless
  paths — work_inbox answers here; the room/voice types remain
  the named fail-closed exception, and `servers` answers its
  deliberate empty mesh. The per-type contracts live in
  test_v200_coverage.py.
* close() tears the session down: supervision stopped, logout
  (offline presence) written.
* Version: the package is 2.0.0 and update-manifest.json offers
  2.0.0 — regenerated at the owner's direct release order
  (2026-11-05) so the fleet can auto-update into this tree.
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
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey)

from agentlink import __version__
from agentlink.client import Agent, RequestFailed
from agentlink.crypto import Identity, encrypt_with_key
from agentlink.doorbell import DoorbellError, sanitize_key
from agentlink.protocol import auth_challenge_payload
from agentlink.transport_v2 import ServerlessConfig, ServerlessTransport
from agentlink.updater import Updater

SUPA = "https://supa.test"
EDGE = "https://edge.test/agentlink-login"
RTDB = "https://proj-default-rtdb.firebaseio.com"
ROOT = Path(__file__).resolve().parent.parent


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt(payload: dict) -> str:
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    return f"{head}.{body}.fakesig"


class FakeBackend:
    """One fake for the Edge login + PostgREST legs. The Edge
    VERIFIES the challenge signature for real against the sign
    pubkey the test registers for the username."""

    TABLES = ("queue", "audit_log", "directory", "group_keys",
              "channel_keys", "group_members", "channel_members",
              "groups", "channels", "message_reads", "connections",
              "users", "activeness", "work", "work_deliveries",
              "work_checkpoints")

    def __init__(self):
        self.tables = {name: [] for name in self.TABLES}
        self.sign_pubs = {}   # username -> sign_pub b64
        self.advertise_oversight = ""   # verify-reply oversight key
        self.calls = []
        self.attach_calls = []   # al_attach_oversight RPC params
        self._seq = 1000

    # -- helpers ------------------------------------------------------
    def rows(self, table):
        return self.tables[table]

    def find_calls(self, method=None, part=""):
        return [(m, u) for (m, u) in self.calls
                if (method is None or m == method) and part in u]

    # -- the opener -----------------------------------------------------
    def opener(self, method, url, headers, body):
        self.calls.append((method, url))
        if url.startswith(EDGE):
            return self._edge(method, url, body)
        if url.startswith("https://edge.test/agentlink-"):
            # Sibling Edge functions (coverage phase): this suite
            # does not fake them; a clean 404 keeps the daemon's
            # best-effort boot declarations honest no-ops here.
            # The coverage suite fakes them for real.
            return 404, {}, b'{"error":"not_found"}'
        if "/rest/v1/rpc/" in url:
            return self._rpc(url, body)
        if "/rest/v1/" in url:
            return self._rest(method, url, body)
        raise AssertionError(f"unexpected URL {url}")

    def _rpc(self, url, body):
        # Database functions (migration v207): al_attach_oversight
        # with its real semantics — fill the oversight column only
        # while the row carries none.
        fn = url.rsplit("/", 1)[-1]
        params = json.loads(body or b"{}")
        if fn == "al_attach_oversight":
            self.attach_calls.append(params)
            ref = params.get("p_ref_id")
            for row in self.tables["audit_log"]:
                if row.get("ref_id") == ref and not row.get("oversight"):
                    row["oversight"] = params.get("p_oversight")
                    return 200, {}, b"true"
            return 200, {}, b"false"
        return 404, {}, b"{}"

    def _edge(self, method, url, body):
        payload = json.loads(body or b"{}")
        if url.endswith("/challenge"):
            return 200, {}, json.dumps({
                "nonce": "nonce-1", "relay": "edge.test",
                "expires": int(time.time()) + 300}).encode()
        if url.endswith("/verify"):
            username = payload["username"]
            raw = base64.b64decode(self.sign_pubs[username])
            pub = Ed25519PublicKey.from_public_bytes(raw)
            signed = auth_challenge_payload(
                payload["nonce"], payload["relay"], username,
                payload["expires"])
            try:
                pub.verify(base64.b64decode(payload["signature"]),
                           signed)
            except Exception:
                return 401, {}, b'{"error":"bad signature"}'
            jwt = make_jwt({"sub": username,
                            "role": "authenticated",
                            "exp": int(time.time()) + 3600})
            reply = {"supabase_jwt": jwt,
                     "firebase_custom_token": "custom-token-1"}
            if self.advertise_oversight:
                reply["oversight_pubkey"] = self.advertise_oversight
            return 200, {}, json.dumps(reply).encode()
        return 404, {}, b"{}"

    def _rest(self, method, url, body):
        split = urllib.parse.urlsplit(url)
        table = split.path.rsplit("/", 1)[-1]
        if table.startswith("al_"):
            table = table[3:]
        params = urllib.parse.parse_qs(split.query)
        rows = self.tables[table]

        def matches(row):
            for key, vals in params.items():
                if key in ("select", "order", "limit", "offset"):
                    continue
                val = vals[0]
                if val.startswith("eq."):
                    if str(row.get(key)) != val[3:]:
                        return False
                elif val.startswith("in.("):
                    wanted = {v.strip() for v in
                              val[4:-1].split(",") if v.strip()}
                    if str(row.get(key)) not in wanted:
                        return False
                else:
                    return False
            return True

        if method == "GET":
            out = [dict(r) for r in rows if matches(r)]
            return 200, {}, json.dumps(out).encode()
        if method == "POST":
            row = dict(json.loads(body or b"{}"))
            if table in ("queue", "audit_log"):
                self._seq += 1
                row["seq"] = self._seq
                rows.append(row)
            else:
                pk = ("username" if "username" in row else None)
                done = False
                if pk:
                    for i, old in enumerate(rows):
                        if old.get(pk) == row.get(pk):
                            rows[i] = row
                            done = True
                            break
                if not done:
                    rows.append(row)
            return 201, {}, b""
        if method == "PATCH":
            patch = json.loads(body or b"{}")
            for r in rows:
                if matches(r):
                    r.update(patch)
            return 204, {}, b""
        if method == "DELETE":
            self.tables[table] = [r for r in rows if not matches(r)]
            return 204, {}, b""
        return 405, {}, b""


class StubDoorbell:
    """Records the transport's doorbell calls and simulates the
    streams. listen_signals delivers ONE signal on its first run,
    then blocks until released (a live stream); listen_presence
    records the subscribed username and waits on the watcher's
    own stop event."""

    def __init__(self):
        self.custom_token = None
        self.exchanged = False
        self.presence_writes = []
        self.heartbeat = None        # (username, on_transition)
        self.heartbeat_stopped = False
        self.cleared = []
        self.taps = []
        self.presence_listeners = []  # usernames, in start order
        self.signals_started = threading.Event()
        self._signal_release = threading.Event()
        self._signal_delivered = False
        self.signal_conversation = None  # conversation id to signal
        self.inbox_listeners = []    # usernames (2.3.0)
        self._inbox_release = threading.Event()
        self.inbox_nodes = {}
        self.directory_published = []
        self.directory_nodes = {}

    @property
    def has_token(self):
        return bool(self.custom_token)

    def set_custom_token(self, token):
        self.custom_token = token

    def exchange_custom_token(self):
        self.exchanged = True
        return {"idToken": "id-token"}

    def set_presence(self, username, client_version="",
                     transport=""):
        self.presence_writes.append(
            {"username": username, "client_version": client_version,
             "transport": transport})
        return {}

    def start_heartbeat(self, username, on_transition=None):
        self.heartbeat = (username, on_transition)

    def stop_heartbeat(self, fire_offline=True):
        self.heartbeat_stopped = True

    def clear_presence(self, username):
        self.cleared.append(username)
        return {}

    def tap_signal(self, conversation_id, item_id):
        self.taps.append((conversation_id, item_id))
        return {}

    def listen_signals(self, callback, on_error=None):
        self.signals_started.set()
        if not self._signal_delivered and self.signal_conversation:
            self._signal_delivered = True
            key = sanitize_key(self.signal_conversation)
            callback("/" + key, {"latest_item_id": "x",
                                 "counter": 1, "ts": 1})
        # A live stream blocks; the test releases it to simulate
        # the stream ending.
        self._signal_release.wait(timeout=30)
        raise DoorbellError("stream ended")

    def release_signals(self):
        self._signal_release.set()

    def listen_presence(self, username, callback, stop_event=None):
        self.presence_listeners.append(username)
        if stop_event is not None:
            stop_event.wait(timeout=30)

    def listen_digest(self, username, callback, stop_event=None):
        self.presence_listeners.append(username)
        if stop_event is not None:
            stop_event.wait(timeout=30)

    # -- 2.3.0 live-layer surface --------------------------------
    def listen_inbox(self, username, callback, on_error=None,
                     stop_event=None):
        self.inbox_listeners.append(username)
        # Block until released (a live stream) or the supervisor
        # stops; on release the stream ends, like listen_signals.
        released = self._inbox_release.wait(timeout=30)
        if stop_event is not None and stop_event.is_set():
            return
        raise DoorbellError("inbox stream ended")

    def release_inbox(self):
        self._inbox_release.set()

    def put_inbox(self, username, item_id, frame, expires_at=0):
        self.inbox_nodes[(username, item_id)] = {
            "frame": frame, "expires_at": expires_at, "ts": 1}
        return {}

    def read_inbox(self, username):
        return {item: node for (user, item), node
                in self.inbox_nodes.items() if user == username}

    def delete_inbox_item(self, username, item_id):
        self.inbox_nodes.pop((username, item_id), None)
        return {}

    def publish_directory(self, entry):
        self.directory_published.append(dict(entry))
        return {}

    def read_directory(self, username):
        return self.directory_nodes.get(username)


def _make_agent(tmp_path, backend, doorbell, **kw):
    config = ServerlessConfig(
        supabase_url=SUPA, anon_key="anon-key",
        firebase_project_id="proj", firebase_api_key="fb-key",
        firebase_database_url=RTDB, login_edge_url=EDGE)
    transport = ServerlessTransport(config, opener=backend.opener,
                                    doorbell=doorbell)
    agent = Agent(username="alice", state_dir=str(tmp_path / "alice"),
                  transport="serverless", serverless_transport=transport,
                  mode="manual", **kw)
    backend.sign_pubs["alice"] = agent.identity.signing_public_key_b64
    return agent, transport


def _enqueue_frame(backend, to_username, frame):
    backend.tables["queue"].append({
        "seq": 5000 + len(backend.tables["queue"]),
        "to_username": to_username, "payload": json.dumps(frame),
        "priority": 0, "ts": int(time.time())})


def _dm_frame(bob: Identity, alice_pub: str, body: str,
              mid: str = "msg-1") -> dict:
    content = bob.encrypt_for(
        alice_pub, json.dumps({"body": body, "kind": "text"}).encode())
    return {"type": "message", "id": mid, "from": "bob",
            "from_name": "bob", "from_pubkey": bob.public_key_b64,
            "sender_nickname": "", "sender_role": "",
            "sender_custom_role": "", "oversight": None,
            "mentions": [], "priority": "normal", "content": content,
            "ts": int(time.time()), "in_reply_to": None,
            "group_id": None}


async def _wait_for(pred, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        await asyncio.sleep(0.02)
    return pred()


# ----------------------------------------------------------------------

def test_transport_mode_default_and_flip(tmp_path, monkeypatch):
    # 2.0.1: serverless is the default (the v1 relay is retired);
    # relay survives only as the explicit opt-in.
    monkeypatch.delenv("AGENTLINK_TRANSPORT", raising=False)
    a = Agent(username="defaultuser", state_dir=str(tmp_path / "r"))
    assert a.transport_mode == "serverless"
    monkeypatch.setenv("AGENTLINK_TRANSPORT", "relay")
    b = Agent(username="relayuser", state_dir=str(tmp_path / "s"))
    assert b.transport_mode == "relay"
    assert b._v2 is None
    c = Agent(username="kwuser", state_dir=str(tmp_path / "k"),
              transport="serverless")
    assert c.transport_mode == "serverless"


def test_daemon_start_supervision_delivery_and_close(tmp_path):
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(tmp_path, backend, doorbell)
    bob = Identity.ephemeral()
    # Directory knows bob (send path + pubkey_of).
    backend.tables["directory"].append({
        "username": "bob", "pubkey": bob.public_key_b64,
        "sign_pub": bob.signing_public_key_b64})
    # A taken mailbox item from bob makes bob a DM counterparty,
    # so the scoped watcher must subscribe to him at start.
    agent.mailbox.put_if_absent(
        {"id": "seed-1", "from": "bob", "to": "alice",
         "group_id": None, "channel_id": None, "body": "earlier",
         "kind": "text", "ts": int(time.time())}, taken=True)
    # Bob's inbound message sits in alice's custody queue; the
    # stub doorbell signals its conversation on stream start.
    _enqueue_frame(backend, "alice",
                   _dm_frame(bob, agent.identity.public_key_b64,
                             "hello alice"))
    doorbell.signal_conversation = "dm:alice|bob"
    received = []
    agent.on_message(lambda msg: received.append(msg))

    async def scenario():
        name = await agent.start()
        assert name == "alice"
        # Login ceremony ran for real (signature verified by the
        # fake Edge) and activeness came up through the transport.
        assert transport.username == "alice"
        assert doorbell.exchanged is True
        assert doorbell.presence_writes and \
            doorbell.presence_writes[0]["username"] == "alice"
        # The heartbeat was started by login, doorbell-owned.
        assert doorbell.heartbeat is not None
        assert doorbell.heartbeat[0] == "alice"
        # ALL FOUR supervision pieces are running (2.3.0 added
        # the inbox transit stream to the 2.0 set).
        assert doorbell.signals_started.wait(timeout=5)
        thread_names = {t.name for t in agent._v2_threads}
        assert thread_names == {"agentlink-v2-signals",
                                "agentlink-v2-inbox",
                                "agentlink-v2-slowsync"}
        assert all(t.is_alive() for t in agent._v2_threads)
        assert await _wait_for(
            lambda: doorbell.inbox_listeners == ["alice"])
        # Scoped presence: exactly bob, never the fleet.
        assert await _wait_for(
            lambda: doorbell.presence_listeners == ["bob"])
        # The signal drove fetch -> dispatch -> handler, and the
        # ack released custody (queue row deleted).
        assert await _wait_for(lambda: len(received) == 1)
        assert received[0]["body"] == "hello alice"
        assert received[0]["from"] == "bob"
        assert await _wait_for(
            lambda: backend.rows("queue") == [])
        assert agent.mailbox.get("msg-1") is not None
        # A beat-ladder transition writes NOTHING to the record
        # layer (2.3.0: the Postgres mirror is deleted; the
        # ladder state is local bookkeeping over the Firebase
        # connection fact).
        _user, on_transition = doorbell.heartbeat
        on_transition("suspect")
        await asyncio.sleep(0.3)
        assert backend.rows("activeness") == []
        assert transport.activeness_state == "suspect"
        # Send routing: directory lookup + custody row for bob,
        # decryptable by bob, mailbox-recorded by alice.
        result = await agent.send_message("bob", "hi bob")
        rows = [r for r in backend.rows("queue")
                if r["to_username"] == "bob"]
        assert len(rows) == 1
        frame = json.loads(rows[0]["payload"])
        assert frame["id"] == result["id"]
        opened = json.loads(bob.decrypt_envelope(frame["content"]))
        assert opened["body"] == "hi bob"
        # Read receipts route through the transport.
        backend.tables["audit_log"].append({
            "seq": 9001, "kind": "message", "actor": "bob",
            "target": "alice", "group_id": "", "ref_id": "msg-1"})
        out = await agent.mark_read(["msg-1"])
        assert out["read"] == ["msg-1"]
        assert any(r["message_id"] == "msg-1"
                   for r in backend.rows("message_reads"))
        assert any(
            json.loads(r["payload"]).get("type") == "read_receipt"
            for r in backend.rows("queue")
            if r["to_username"] == "bob")
        # Coverage phase: work_inbox now has a serverless path
        # (PostgREST under RLS) and answers the relay's shape.
        out = await agent._request({"type": "work_inbox"})
        assert out == {"work": []}
        # The mesh question gets its deliberate, truthful answer:
        # no peer servers exist in serverless mode.
        assert await agent.servers() == []
        # The room/voice signalling types still fail CLOSED, by
        # name — the voice leg is parked by the owner's ruling.
        with pytest.raises(RequestFailed) as ei:
            await agent._request({"type": "room_open"})
        assert ei.value.reason == "serverless_unsupported"
        # serve() waits for the session, close() ends it.
        serve_task = asyncio.create_task(agent.serve())
        await asyncio.sleep(0.1)
        assert not serve_task.done()
        doorbell.release_signals()
        doorbell.release_inbox()
        await agent.close()
        await asyncio.wait_for(serve_task, timeout=10)
        # Teardown (2.3.0): logout wrote the offline presence to
        # Firebase — and NOTHING to the record layer's activeness
        # table (the mirror is deleted).
        assert doorbell.cleared == ["alice"]
        assert doorbell.heartbeat_stopped is True
        assert agent._v2 is None
        assert backend.rows("activeness") == []

    asyncio.run(scenario())


def test_signal_fetch_failure_logs_one_warning_no_traceback(
        tmp_path, caplog):
    # 2.0.6 soak catch (2026-11-06): a transient custody-fetch
    # failure on the signal path is the designed degradation —
    # slow-sync retries within the minute — but _on_v2_signal
    # logged it with log.exception, stamping a crash-shaped
    # traceback on a self-healing event and failing the soak's
    # stderr watch while the daemon delivered on around it. The
    # handler now logs ONE warning line with no exception info.
    import logging as _logging
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, _transport = _make_agent(tmp_path, backend, doorbell)

    class _Boom:
        def fetch_unacked(self):
            raise RuntimeError("PostgREST GET queue returned "
                               "an empty body")

    agent._v2 = _Boom()
    with caplog.at_level(_logging.WARNING, logger="agentlink.client"):
        agent._on_v2_signal("dm:alice|bob", {"counter": 1})
    records = [r for r in caplog.records
               if "signal fetch failed" in r.getMessage()]
    assert len(records) == 1
    assert records[0].levelno == _logging.WARNING
    assert records[0].exc_info is None


def test_run_loop_connects_and_close_returns(tmp_path):
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(tmp_path, backend, doorbell)

    async def scenario():
        run_task = asyncio.create_task(agent.run())
        assert await _wait_for(
            lambda: agent.connection_state == "connected"
            and agent._v2 is not None)
        assert doorbell.heartbeat is not None
        doorbell.release_signals()
        await agent.close()
        await asyncio.wait_for(run_task, timeout=15)
        assert agent._v2 is None

    asyncio.run(scenario())


def test_serverless_start_refuses_ephemeral(tmp_path):
    backend = FakeBackend()
    doorbell = StubDoorbell()
    config = ServerlessConfig(
        supabase_url=SUPA, anon_key="anon-key",
        firebase_database_url=RTDB, login_edge_url=EDGE)
    transport = ServerlessTransport(config, opener=backend.opener,
                                    doorbell=doorbell)
    agent = Agent(ephemeral=True, state_dir=str(tmp_path / "eph"),
                  transport="serverless",
                  serverless_transport=transport, mode="manual")

    async def scenario():
        with pytest.raises(Exception) as ei:
            await agent.start()
        assert "serverless_requires_identity" in str(ei.value)

    asyncio.run(scenario())


def test_serverless_login_adopts_advertised_oversight_key(tmp_path):
    # 2.0.4 (owner catch, 2026-11-06): in v1 the relay's welcome
    # frame advertised the owner-oversight public key and every
    # zero-config agent adopted it, so every message carried an
    # oversight wrap and the dashboard could read it. The v2 login
    # ceremony originally advertised nothing, so a zero-config
    # serverless agent knew no oversight key and EVERY message it
    # sent landed sealed with no wrap. The login Edge now
    # advertises the key with the session tokens; the transport
    # surfaces it and the Agent adopts it at login.
    oversight_id = Identity.ephemeral()
    backend = FakeBackend()
    backend.advertise_oversight = oversight_id.public_key_b64
    doorbell = StubDoorbell()
    agent, transport = _make_agent(tmp_path, backend, doorbell)
    assert agent.oversight_pubkey == ""

    async def scenario():
        await agent.start()
        try:
            assert transport.oversight_pubkey == \
                oversight_id.public_key_b64
            assert agent.oversight_pubkey == oversight_id.public_key_b64
            # And the adopted key actually seals: a wrap built the
            # way sends build it decrypts under the oversight key.
            wrap = agent._oversight_for_obj({"body": "readable"})
            assert wrap is not None
            plain = oversight_id.decrypt_envelope(wrap)
            assert b"readable" in plain
        finally:
            await agent.close()

    asyncio.run(scenario())


def test_serverless_login_never_replaces_local_oversight_key(tmp_path):
    # A locally configured oversight key (env/arg) is the override:
    # the advertised key must not replace it (the welcome-frame
    # rule, carried to the serverless ceremony).
    local_id = Identity.ephemeral()
    backend = FakeBackend()
    backend.advertise_oversight = Identity.ephemeral().public_key_b64
    doorbell = StubDoorbell()
    agent, transport = _make_agent(
        tmp_path, backend, doorbell,
        oversight_pubkey=local_id.public_key_b64)

    async def scenario():
        await agent.start()
        try:
            assert agent.oversight_pubkey == local_id.public_key_b64
        finally:
            await agent.close()

    asyncio.run(scenario())


def test_receiver_rectifies_unwrapped_dm_live(tmp_path):
    # 2.0.6 (owner order: no "sealed" on the dashboard): a DM from
    # an old client carries no oversight wrap. The receiving agent
    # — which decrypts it legitimately — computes the sender's
    # content wrap itself and attaches it to the audit row through
    # the pinned database function.
    oversight_id = Identity.ephemeral()
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(
        tmp_path, backend, doorbell,
        oversight_pubkey=oversight_id.public_key_b64)
    bob = Identity.ephemeral()
    backend.tables["directory"].append({
        "username": "bob", "pubkey": bob.public_key_b64,
        "sign_pub": bob.signing_public_key_b64})
    frame = _dm_frame(bob, agent.identity.public_key_b64, "hello alice")
    backend.tables["audit_log"].append({
        "seq": 9001, "ts": int(time.time()), "kind": "message",
        "actor": "bob", "target": "alice", "group_id": "",
        "ref_id": "msg-1", "status": "sent", "priority": "normal",
        "size": 10, "mentions": [], "oversight": "",
        "content_envelope": json.dumps(frame["content"])})
    _enqueue_frame(backend, "alice", frame)
    doorbell.signal_conversation = "dm:alice|bob"
    received = []
    agent.on_message(lambda msg: received.append(msg))

    async def scenario():
        await agent.start()
        try:
            assert await _wait_for(lambda: len(received) == 1)
            assert await _wait_for(
                lambda: len(backend.attach_calls) >= 1)
            call = backend.attach_calls[0]
            assert call["p_ref_id"] == "msg-1"
            wrap = json.loads(call["p_oversight"])
            assert wrap["kind"] == "content"
            plain = json.loads(oversight_id.decrypt_envelope(wrap))
            assert plain["body"] == "hello alice"
            assert backend.tables["audit_log"][0]["oversight"]
        finally:
            await agent.close()

    asyncio.run(scenario())


def test_receiver_rectifies_unwrapped_group_message(tmp_path):
    # The group twin: the receiver wraps the ROOM KEY (the
    # content_key form group senders use), so the dashboard opens
    # the whole room history with the one wrap.
    oversight_id = Identity.ephemeral()
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(
        tmp_path, backend, doorbell,
        oversight_pubkey=oversight_id.public_key_b64)
    bob = Identity.ephemeral()
    backend.tables["directory"].append({
        "username": "bob", "pubkey": bob.public_key_b64,
        "sign_pub": bob.signing_public_key_b64})
    room_key = b"r" * 32
    agent._store_group_key("g1", 1, room_key)
    content = encrypt_with_key(
        room_key, json.dumps({"body": "group hi", "kind": "text"}).encode())
    frame = {"type": "message", "id": "gm-1", "from": "bob",
             "from_name": "bob", "from_pubkey": bob.public_key_b64,
             "sender_nickname": "", "sender_role": "",
             "sender_custom_role": "", "oversight": None,
             "mentions": [], "priority": "normal", "content": content,
             "ts": int(time.time()), "in_reply_to": None,
             "group_id": "g1", "group_name": "G"}
    backend.tables["audit_log"].append({
        "seq": 9002, "ts": int(time.time()), "kind": "group_message",
        "actor": "bob", "target": "", "group_id": "g1",
        "ref_id": "gm-1", "status": "sent", "priority": "normal",
        "size": 10, "mentions": [], "oversight": "",
        "content_envelope": json.dumps(content)})
    _enqueue_frame(backend, "alice", frame)
    doorbell.signal_conversation = "dm:alice|bob"
    received = []
    agent.on_message(lambda msg: received.append(msg))

    async def scenario():
        await agent.start()
        try:
            assert await _wait_for(lambda: len(received) == 1)
            assert await _wait_for(
                lambda: len(backend.attach_calls) >= 1)
            wrap = json.loads(backend.attach_calls[0]["p_oversight"])
            assert backend.attach_calls[0]["p_ref_id"] == "gm-1"
            assert wrap["kind"] == "content_key"
            assert oversight_id.decrypt_envelope(wrap) == room_key
        finally:
            await agent.close()

    asyncio.run(scenario())


def test_receiver_rectifies_identity_sealed_group_message(tmp_path):
    # 2.0.7 (the Nova family drill defect, found live 2026-11-06):
    # a sender whose client mis-seals GROUP traffic to a member's
    # identity key instead of the room key. The member can still
    # read it — via the identity fallback — and the rectification
    # wraps the CONTENT (a room-key wrap would open nothing: the
    # envelope was never sealed under the room key).
    oversight_id = Identity.ephemeral()
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(
        tmp_path, backend, doorbell,
        oversight_pubkey=oversight_id.public_key_b64)
    bob = Identity.ephemeral()
    backend.tables["directory"].append({
        "username": "bob", "pubkey": bob.public_key_b64,
        "sign_pub": bob.signing_public_key_b64})
    room_key = b"r" * 32
    agent._store_group_key("g1", 1, room_key)
    content = bob.encrypt_for(
        agent.identity.public_key_b64,
        json.dumps({"body": "mis-sealed group hi",
                    "kind": "text"}).encode())
    frame = {"type": "message", "id": "gm-2", "from": "bob",
             "from_name": "bob", "from_pubkey": bob.public_key_b64,
             "sender_nickname": "", "sender_role": "",
             "sender_custom_role": "", "oversight": None,
             "mentions": [], "priority": "normal", "content": content,
             "ts": int(time.time()), "in_reply_to": None,
             "group_id": "g1", "group_name": "G"}
    backend.tables["audit_log"].append({
        "seq": 9004, "ts": int(time.time()), "kind": "group_message",
        "actor": "bob", "target": "", "group_id": "g1",
        "ref_id": "gm-2", "status": "sent", "priority": "normal",
        "size": 10, "mentions": [], "oversight": "",
        "content_envelope": json.dumps(content)})
    _enqueue_frame(backend, "alice", frame)
    doorbell.signal_conversation = "dm:alice|bob"
    received = []
    agent.on_message(lambda msg: received.append(msg))

    async def scenario():
        await agent.start()
        try:
            assert await _wait_for(lambda: len(received) == 1)
            assert received[0]["body"] == "mis-sealed group hi"
            assert await _wait_for(
                lambda: len(backend.attach_calls) >= 1)
            call = backend.attach_calls[0]
            assert call["p_ref_id"] == "gm-2"
            wrap = json.loads(call["p_oversight"])
            assert wrap["kind"] == "content"
            plain = json.loads(oversight_id.decrypt_envelope(wrap))
            assert plain["body"] == "mis-sealed group hi"
        finally:
            await agent.close()

    asyncio.run(scenario())


def test_history_row_identity_sealed_group_opens_and_rectifies(tmp_path):
    # The history twin of the 2.0.7 fallback: a stored group row
    # whose envelope was sealed to my identity key opens in history
    # (no sealed stub) and backfills a CONTENT wrap.
    oversight_id = Identity.ephemeral()
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(
        tmp_path, backend, doorbell,
        oversight_pubkey=oversight_id.public_key_b64)
    bob = Identity.ephemeral()
    agent._store_group_key("g1", 1, b"r" * 32)
    content = bob.encrypt_for(
        agent.identity.public_key_b64,
        json.dumps({"body": "old drill post", "kind": "text"}).encode())
    row = {"kind": "group_message", "ref_id": "gm-old",
           "group_id": "g1", "from": "bob", "to": "",
           "ts": int(time.time()), "size": 10, "mentions": [],
           "oversight": "", "content_envelope": content}
    msg = agent._history_row_to_msg(row)
    assert msg is not None
    assert not msg.get("sealed")
    assert msg["body"] == "old drill post"
    rect = msg.get("_rectify")
    assert rect and rect["ref_id"] == "gm-old"
    wrap = rect["oversight"]
    assert wrap["kind"] == "content"
    plain = json.loads(oversight_id.decrypt_envelope(wrap))
    assert plain["body"] == "old drill post"


def test_history_backfill_rectifies_unwrapped_rows(tmp_path):
    # The same rectification applied to HISTORY at start(): an old
    # unwrapped row gains its wrap during the boot history sync,
    # so the dashboard reads back-conversations too.
    oversight_id = Identity.ephemeral()
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(
        tmp_path, backend, doorbell,
        oversight_pubkey=oversight_id.public_key_b64)
    bob = Identity.ephemeral()
    backend.tables["directory"].append({
        "username": "bob", "pubkey": bob.public_key_b64,
        "sign_pub": bob.signing_public_key_b64})
    frame = _dm_frame(bob, agent.identity.public_key_b64,
                      "from before", mid="old-1")
    backend.tables["audit_log"].append({
        "seq": 9003, "ts": int(time.time()), "kind": "message",
        "actor": "bob", "target": "alice", "group_id": "",
        "ref_id": "old-1", "status": "delivered", "priority": "normal",
        "size": 10, "mentions": [], "oversight": "",
        "content_envelope": json.dumps(frame["content"])})

    async def scenario():
        await agent.start()
        try:
            assert await _wait_for(
                lambda: len(backend.attach_calls) >= 1)
            assert backend.attach_calls[0]["p_ref_id"] == "old-1"
            wrap = json.loads(backend.attach_calls[0]["p_oversight"])
            plain = json.loads(oversight_id.decrypt_envelope(wrap))
            assert plain["body"] == "from before"
            assert agent.mailbox_sync["rectified"] >= 1
        finally:
            await agent.close()

    asyncio.run(scenario())


def test_unwrap_failure_asks_admins_for_reissue(tmp_path):
    # 2.0.6 key self-heal (swift-otter-7's Nova family defect): a
    # member whose stored wrap no longer unwraps — its identity
    # rotated after the wrap was sealed — asks the room's admins
    # to re-issue the wrap against its CURRENT directory key,
    # instead of sitting on unreadable history forever.
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(tmp_path, backend, doorbell)
    backend.tables["group_members"] += [
        {"group_id": "g1", "username": "alice", "role": "member"},
        {"group_id": "g1", "username": "carol", "role": "admin"}]
    backend.tables["groups"].append({"id": "g1", "name": "G"})
    stranger = Identity.ephemeral()
    bad_wrap = stranger.encrypt_for(stranger.public_key_b64, b"k" * 32)
    backend.tables["group_keys"].append({
        "group_id": "g1", "username": "alice", "epoch": 1,
        "wrapped": json.dumps(bad_wrap)})

    async def scenario():
        await agent.start()
        try:
            rec = await agent._ensure_group_key("g1")
            assert rec is None
            assert await _wait_for(lambda: any(
                r["to_username"] == "carol"
                and json.loads(r["payload"]).get("type")
                == "group_key_request"
                for r in backend.rows("queue")))
        finally:
            await agent.close()

    asyncio.run(scenario())


def test_admin_reissues_group_key_on_request(tmp_path):
    # The admin side of the self-heal: on a member's request, an
    # admin who holds the room key re-seals the SAME epoch key to
    # the requester's current directory pubkey and distributes it
    # to them alone; the request frame is then acked away.
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(tmp_path, backend, doorbell)
    bob = Identity.ephemeral()
    backend.tables["directory"].append({
        "username": "bob", "pubkey": bob.public_key_b64,
        "sign_pub": bob.signing_public_key_b64})
    backend.tables["group_members"] += [
        {"group_id": "g1", "username": "alice", "role": "superadmin"},
        {"group_id": "g1", "username": "bob", "role": "member"}]
    backend.tables["groups"].append({"id": "g1", "name": "G"})
    room_key = b"g" * 32
    agent._store_group_key("g1", 1, room_key)
    _enqueue_frame(backend, "alice", {
        "type": "group_key_request", "group_id": "g1",
        "from": "bob", "id": "gkreq-1", "epoch": 1,
        "ts": int(time.time())})
    doorbell.signal_conversation = "dm:alice|bob"

    async def scenario():
        await agent.start()
        try:
            assert await _wait_for(lambda: any(
                r.get("username") == "bob"
                for r in backend.rows("group_keys")))
            row = next(r for r in backend.rows("group_keys")
                       if r.get("username") == "bob")
            wrapped = row["wrapped"]
            if isinstance(wrapped, str):
                wrapped = json.loads(wrapped)
            assert bob.unwrap_key(wrapped) == room_key
            assert await _wait_for(lambda: all(
                json.loads(r["payload"]).get("id") != "gkreq-1"
                for r in backend.rows("queue")
                if r["to_username"] == "alice"))
        finally:
            await agent.close()

    asyncio.run(scenario())


def test_version_230_and_manifest_offers_230():
    assert __version__ == "2.4.1"
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert 'version = "2.4.1"' in pyproject
    # The fleet's update manifest was regenerated at the owner's
    # direct release order (2026-11-05): it offers 2.0.5, and its
    # file set covers the whole package INCLUDING the v2.0
    # serverless modules, each with a matching SHA-256.
    import hashlib
    manifest = json.loads((ROOT / "update-manifest.json").read_text())
    assert manifest["version"] == "2.4.1"
    assert "agentlink/doorbell.py" in manifest["files"]
    assert "agentlink/transport_v2.py" in manifest["files"]
    assert "agentlink/retry.py" in manifest["files"]  # new in 2.3.0
    # 2.0.11: the retired relay era no longer ships to installs —
    # relay.py/dashboard.py stay in the source tree (the suite's
    # local-relay harness imports them) but are NOT distributed;
    # the mirror-purge + first-boot clean remove leftover copies
    # from agent installs.
    assert "agentlink/relay.py" not in manifest["files"]
    assert "agentlink/dashboard.py" not in manifest["files"]
    for rel, digest in manifest["files"].items():
        actual = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
        assert actual == digest, rel
    # A 1.8.1 install reading this manifest sees the 2.3.1 update.
    updater = Updater(current_version="1.8.1")
    updater.fetch_manifest = lambda: manifest
    check = updater.check()
    assert check["available"] == "2.4.1"
    assert check["update_available"] is True


def test_login_refusal_classification_405_retries_401_key_auth_final(
        tmp_path, monkeypatch):
    # 2.0.2 (beulah crash-loop, 2026-11-06): the daemon classified
    # ANY HTTP 4xx from the login Edge as a permanent identity
    # refusal and exited; her challenge arrived as the wrong
    # method (405), so every supervisor relaunch died on the same
    # fixable fault. Only key_auth_failed is permanent; a 405 /
    # 404 / 429 is configuration or weather and must surface as a
    # retryable ConnectionError so _run_serverless rides it out.
    from agentlink.client import RegistrationFailed
    from agentlink.transport_v2 import TransportError
    backend = FakeBackend()
    doorbell = StubDoorbell()
    agent, transport = _make_agent(tmp_path, backend, doorbell)

    def refuse_405(username, signer, *a, **kw):
        raise TransportError(
            "login Edge challenge HTTP 405: method_not_allowed")

    monkeypatch.setattr(transport, "login", refuse_405)

    async def scenario_405():
        with pytest.raises(ConnectionError):
            await agent.start()

    asyncio.run(scenario_405())

    def refuse_key(username, signer, *a, **kw):
        raise TransportError(
            "login Edge verify HTTP 401: key_auth_failed")

    monkeypatch.setattr(transport, "login", refuse_key)

    # 2.0.8 refinement: key_auth_failed first runs the
    # first-contact suite — a FREE name would register and a held
    # recovery key would reclaim. Here the name is taken and no
    # key is held, so the suite exhausts and the refusal stands
    # as the permanent identity verdict it always was.
    def refuse_register(*a, **kw):
        raise TransportError(
            "login Edge register HTTP 409: username_taken")

    monkeypatch.setattr(transport, "register_and_login", refuse_register)

    async def scenario_key():
        with pytest.raises(RegistrationFailed):
            await agent.start()

    asyncio.run(scenario_key())
