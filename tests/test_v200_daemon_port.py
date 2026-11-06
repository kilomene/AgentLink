"""Daemon-loop port tests (v2.0): client.py's Agent on the
serverless transport.

The port's contract, pinned here against a fake HTTP backend and
a stub doorbell (the real doorbell's behaviour is proven by the
Phase 3+4/6 suites; this phase proves the DAEMON starts and wires
it):

* start() on the serverless flip performs the Edge login ceremony
  (real signature verification at the fake Edge), starts the
  doorbell heartbeat via login, and starts ALL THREE supervision
  pieces the Phase 6 finding names: listen_supervised (signal
  stream thread), run_slow_sync (slow-sync thread) and the scoped
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
from agentlink.crypto import Identity
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
        self.calls = []
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
        if "/rest/v1/" in url:
            return self._rest(method, url, body)
        raise AssertionError(f"unexpected URL {url}")

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
            return 200, {}, json.dumps({
                "supabase_jwt": jwt,
                "firebase_custom_token": "custom-token-1"}).encode()
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
        # ALL THREE supervision pieces are running.
        assert doorbell.signals_started.wait(timeout=5)
        thread_names = {t.name for t in agent._v2_threads}
        assert thread_names == {"agentlink-v2-signals",
                                "agentlink-v2-slowsync"}
        assert all(t.is_alive() for t in agent._v2_threads)
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
        # A beat-ladder transition mirrors to Supabase exactly
        # once (activeness + connections + last_seen).
        _user, on_transition = doorbell.heartbeat
        on_transition("suspect")
        assert await _wait_for(
            lambda: any(r.get("state") == "suspect"
                        for r in backend.rows("activeness")))
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
        await agent.close()
        await asyncio.wait_for(serve_task, timeout=10)
        # Teardown: logout wrote the offline presence + mirror.
        assert doorbell.cleared == ["alice"]
        assert doorbell.heartbeat_stopped is True
        assert agent._v2 is None
        assert await _wait_for(
            lambda: any(r.get("state") == "offline"
                        for r in backend.rows("activeness")))

    asyncio.run(scenario())


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


def test_version_201_and_manifest_offers_201():
    assert __version__ == "2.0.1"
    pyproject = (ROOT / "pyproject.toml").read_text()
    assert 'version = "2.0.1"' in pyproject
    # The fleet's update manifest was regenerated at the owner's
    # direct release order (2026-11-05): it offers 2.0.1, and its
    # file set covers the whole package INCLUDING the v2.0
    # serverless modules, each with a matching SHA-256.
    import hashlib
    manifest = json.loads((ROOT / "update-manifest.json").read_text())
    assert manifest["version"] == "2.0.1"
    assert "agentlink/doorbell.py" in manifest["files"]
    assert "agentlink/transport_v2.py" in manifest["files"]
    for rel, digest in manifest["files"].items():
        actual = hashlib.sha256((ROOT / rel).read_bytes()).hexdigest()
        assert actual == digest, rel
    # A 1.8.1 install reading this manifest sees the 2.0.1 update.
    updater = Updater(current_version="1.8.1")
    updater.fetch_manifest = lambda: manifest
    check = updater.check()
    assert check["available"] == "2.0.1"
    assert check["update_available"] is True
