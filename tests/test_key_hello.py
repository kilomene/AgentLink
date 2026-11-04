"""Key-signed hello pins (v1.3.9, WS6).

The defect: the client hello carried the RAW reusable account
secret, presented to ANY relay — including peer/carrier relays
during failover — a bearer credential a carrier could reuse to
impersonate the agent anywhere until rotation.

The cure pinned here:
  1. a current client connecting to a relay that has NEVER seen
     it presents NO secret (relay-side frame capture) and
     authenticates by Ed25519 challenge-response;
  2. a forged signature / wrong key is refused (key_auth_failed);
  3. a captured signature replays nowhere — not to a different
     relay, not after the challenge expiry;
  4. a legacy secret hello still connects during the transition
     AND is recorded + flagged legacy (row auth_method, dashboard
     payload auth_legacy, audit trail auth:<method>);
  6. a brand-new registration bootstraps once and authenticates
     by key on every later hello.
(Pin 5 — failover with key-signed reconnect, work exactly once —
lives in test_key_hello_failover inside this file too.)
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest
from websockets.client import connect

from agentlink.client import Agent
from agentlink.crypto import Identity
from agentlink.protocol import auth_challenge_payload
from agentlink.relay import Relay

HOST = "127.0.0.1"


class RelayHandle:
    """One real relay on its own thread/loop (the failover-test
    harness shape)."""

    def __init__(self, db, name):
        self.db = db
        self.name = name
        self.relay = None
        self.loop = None
        self.thread = None
        self.port = 0
        self.dash_port = 0

    def start(self):
        self.relay = Relay(host=HOST, port=self.port, db_path=self.db,
                           server_name=self.name,
                           dashboard_password="test-password",
                           dashboard_port=self.dash_port)
        ready = threading.Event()

        def _thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.loop = loop

            async def _serve():
                await self.relay.start()
                ready.set()
                await asyncio.Future()

            try:
                loop.run_until_complete(_serve())
            except (RuntimeError, asyncio.CancelledError):
                pass

        self.thread = threading.Thread(target=_thread, daemon=True)
        self.thread.start()
        assert ready.wait(timeout=10)
        self.port = self.relay.port
        self.dash_port = self.relay.dashboard_port
        return f"ws://{HOST}:{self.relay.port}"

    def stop(self):
        if self.relay is not None and self.loop is not None:
            fut = asyncio.run_coroutine_threadsafe(
                self.relay.stop(), self.loop)
            try:
                fut.result(timeout=10)
            except Exception:
                pass
            self.relay = None

    def kill(self):
        if self.relay is None or self.loop is None:
            return
        relay = self.relay

        async def _kill():
            if relay.dashboard is not None:
                relay.dashboard.stop()
                relay.dashboard = None
            for peer in list(relay.peers.values()):
                try:
                    await peer.ws.close()
                except Exception:
                    pass
            if relay._server is not None:
                relay._server.close()

        fut = asyncio.run_coroutine_threadsafe(_kill(), self.loop)
        try:
            fut.result(timeout=10)
        except Exception:
            pass
        self.relay = None


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def wait_for(pred, timeout=20.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


def _auth_method(db, username):
    conn = sqlite3.connect(db)
    try:
        row = conn.execute(
            "SELECT auth_method FROM users WHERE username = ?",
            (username,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def _audit_statuses(db, username, kind):
    conn = sqlite3.connect(db)
    try:
        return [r[0] for r in conn.execute(
            "SELECT status FROM audit_log WHERE kind = ?"
            " AND actor = ?", (kind, username)).fetchall()]
    finally:
        conn.close()


async def _raw_key_hello(url, username, identity, hello_extra=None):
    """One raw key-signed hello attempt. Returns (frames, welcome)
    where frames is every frame received, in order."""
    frames = []
    async with connect(url) as ws:
        hello = {"type": "hello", "username": username,
                 "display_name": username, "secret": None,
                 "auth": "key", "ephemeral": False,
                 "pubkey": identity.public_key_b64,
                 "sign_pub": identity.signing_public_key_b64,
                 "capabilities": [], "mode": "autonomous"}
        if hello_extra:
            hello.update(hello_extra)
        await ws.send(json.dumps(hello))
        while True:
            frame = json.loads(await asyncio.wait_for(ws.recv(), 10))
            frames.append(frame)
            if frame.get("type") == "auth_challenge":
                payload = auth_challenge_payload(
                    frame["nonce"], frame["relay"], username,
                    frame["expires"])
                await ws.send(json.dumps({
                    "type": "auth_response",
                    "signature": identity.sign(payload)}))
                continue
            return frames, frame


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-kh-agents-") as tmp:
        yield Path(tmp)


def _db(tmp):
    return str(Path(tmp) / "shared.db")


def test_key_hello_no_secret_to_unseen_relay(state_root):
    """Pin 1 + 6: bootstrap on relay A; the SAME identity then
    connects to relay B (never seen it) — relay-side capture shows
    the hello carries auth='key' and NO secret value, a challenge
    is issued and answered, and the row records auth_method=key."""
    tmp = tempfile.mkdtemp(prefix="agentlink-kh-")
    db = _db(tmp)
    a = RelayHandle(db, "kh-home")
    b = RelayHandle(db, "kh-peer")
    url_a = a.start()
    url_b = b.start()
    captured = []
    orig_on_hello = b.relay._on_hello

    async def _spy(ws, frame, old, server_id=""):
        captured.append(dict(frame))
        return await orig_on_hello(ws, frame, old, server_id)

    b.relay._on_hello = _spy

    async def _t():
        first = Agent("keyalice", endpoint=url_a,
                      state_dir=str(state_root / "keyalice"))
        await first.start()
        await first.close()
        assert _auth_method(db, "keyalice") == "bootstrap"
        second = Agent("keyalice", endpoint=url_b,
                       state_dir=str(state_root / "keyalice"))
        await second.start()
        try:
            assert second.username == "keyalice"
        finally:
            await second.close()

    run(_t())
    hellos = [f for f in captured if f.get("type") == "hello"
              and f.get("username") == "keyalice"]
    assert len(hellos) == 1
    hello = hellos[0]
    assert hello.get("auth") == "key"
    assert not hello.get("secret"), \
        "the reusable secret crossed to an unseen relay"
    assert _auth_method(db, "keyalice") == "key"
    a.stop()
    b.stop()


def test_forged_signature_refused(state_root):
    """Pin 2: an attacker who knows the username (and even puts
    the victim's real pubkeys in the hello) but signs with the
    WRONG key is refused with key_auth_failed — never downgraded
    to a weaker gate."""
    tmp = tempfile.mkdtemp(prefix="agentlink-kh-")
    db = _db(tmp)
    h = RelayHandle(db, "kh-forge")
    url = h.start()

    async def _t():
        victim = Agent("victim", endpoint=url,
                       state_dir=str(state_root / "victim"))
        await victim.start()
        await victim.close()
        real = Identity("victim", str(state_root / "victim"))
        attacker = Identity.ephemeral()
        frames, last = await _raw_key_hello(url, "victim", attacker)
        assert last["type"] == "error"
        assert last["reason"] == "key_auth_failed"
        # The genuine key still works afterwards — a failed forgery
        # changed nothing.
        frames, last = await _raw_key_hello(url, "victim", real)
        assert last["type"] == "welcome"

    run(_t())
    h.stop()


def test_signature_replay_refused(state_root):
    """Pin 3: a valid signature captured from one challenge is
    bound to (nonce, relay, username, expires): replaying it to a
    DIFFERENT relay fails, and answering after the challenge
    expiry fails."""
    tmp = tempfile.mkdtemp(prefix="agentlink-kh-")
    db = _db(tmp)
    a = RelayHandle(db, "kh-replay-a")
    b = RelayHandle(db, "kh-replay-b")
    url_a = a.start()
    url_b = b.start()

    async def _t():
        reg = Agent("replay", endpoint=url_a,
                    state_dir=str(state_root / "replay"))
        await reg.start()
        await reg.close()
        ident = Identity("replay", str(state_root / "replay"))
        # Legit hello to A, capturing the signature used.
        captured = {}
        async with connect(url_a) as ws:
            await ws.send(json.dumps(
                {"type": "hello", "username": "replay",
                 "display_name": "replay", "secret": None,
                 "auth": "key", "ephemeral": False,
                 "pubkey": ident.public_key_b64,
                 "sign_pub": ident.signing_public_key_b64,
                 "capabilities": [], "mode": "autonomous"}))
            ch = json.loads(await ws.recv())
            assert ch["type"] == "auth_challenge"
            sig = ident.sign(auth_challenge_payload(
                ch["nonce"], ch["relay"], "replay", ch["expires"]))
            captured["sig"] = sig
            await ws.send(json.dumps(
                {"type": "auth_response", "signature": sig}))
            w = json.loads(await ws.recv())
            assert w["type"] == "welcome"
        # Replay the SAME signature to relay B: B's challenge has a
        # different nonce and a different relay identity.
        async with connect(url_b) as ws:
            await ws.send(json.dumps(
                {"type": "hello", "username": "replay",
                 "display_name": "replay", "secret": None,
                 "auth": "key", "ephemeral": False,
                 "pubkey": ident.public_key_b64,
                 "sign_pub": ident.signing_public_key_b64,
                 "capabilities": [], "mode": "autonomous"}))
            ch = json.loads(await ws.recv())
            assert ch["type"] == "auth_challenge"
            await ws.send(json.dumps(
                {"type": "auth_response",
                 "signature": captured["sig"]}))
            err = json.loads(await ws.recv())
            assert err["type"] == "error"
            assert err["reason"] == "key_auth_failed"

    run(_t())

    # Expiry: shrink the relay's TTL below zero — a correctly
    # signed answer to an already-expired challenge is refused.
    import agentlink.relay as relay_mod
    old_ttl = relay_mod.AUTH_CHALLENGE_TTL_SECONDS
    relay_mod.AUTH_CHALLENGE_TTL_SECONDS = -60
    try:
        async def _t2():
            ident = Identity("replay", str(state_root / "replay"))
            frames, last = await _raw_key_hello(url_a, "replay",
                                                ident)
            assert last["type"] == "error"
            assert last["reason"] == "key_auth_failed"

        run(_t2())
    finally:
        relay_mod.AUTH_CHALLENGE_TTL_SECONDS = old_ttl
    a.stop()
    b.stop()


def test_legacy_secret_hello_flagged(state_root):
    """Pin 4: a pre-1.3.9-style hello (the raw secret, no auth
    announcement) still connects during the transition — and is
    recorded auth_method='secret', flagged auth_legacy in the
    dashboard payload, and written to the audit trail."""
    tmp = tempfile.mkdtemp(prefix="agentlink-kh-")
    db = _db(tmp)
    h = RelayHandle(db, "kh-legacy")
    url = h.start()

    async def _t():
        reg = Agent("oldtimer", endpoint=url,
                    state_dir=str(state_root / "oldtimer"))
        await reg.start()
        await reg.close()
        secret_file = state_root / "oldtimer" / "secret-oldtimer.json"
        secret = json.loads(secret_file.read_text())["secret"]
        ident = Identity("oldtimer", str(state_root / "oldtimer"))
        async with connect(url) as ws:
            await ws.send(json.dumps(
                {"type": "hello", "username": "oldtimer",
                 "display_name": "oldtimer", "secret": secret,
                 "ephemeral": False,
                 "pubkey": ident.public_key_b64,
                 "sign_pub": ident.signing_public_key_b64,
                 "capabilities": [], "mode": "autonomous"}))
            w = json.loads(await ws.recv())
            assert w["type"] == "welcome"
        assert _auth_method(db, "oldtimer") == "secret"
        data = h.relay._dashboard_data()
        row = [u for u in data["users"]
               if u["username"] == "oldtimer"][0]
        assert row["auth_method"] == "secret"
        assert row["auth_legacy"] is True
        assert "auth:secret" in _audit_statuses(db, "oldtimer",
                                                "online")

    run(_t())
    h.stop()


def test_registration_then_key_thereafter(state_root):
    """Pin 6 (row-level): a brand-new agent's claiming hello is
    recorded 'bootstrap'; its very next hello — same relay — is a
    key hello, recorded 'key', with the audit trail to match."""
    tmp = tempfile.mkdtemp(prefix="agentlink-kh-")
    db = _db(tmp)
    h = RelayHandle(db, "kh-reg")
    url = h.start()

    async def _t():
        one = Agent("newbie", endpoint=url,
                    state_dir=str(state_root / "newbie"))
        await one.start()
        await one.close()
        assert _auth_method(db, "newbie") == "bootstrap"
        two = Agent("newbie", endpoint=url,
                    state_dir=str(state_root / "newbie"))
        await two.start()
        await two.close()
        assert _auth_method(db, "newbie") == "key"

    run(_t())
    statuses = _audit_statuses(db, "newbie", "online")
    assert "auth:bootstrap" in statuses
    assert "auth:key" in statuses
    h.stop()


def test_key_hello_failover_work_exactly_once(state_root):
    """Pin 5: an agent loses its home mid-work, reconnects via a
    peer relay with a KEY-signed hello (no secret presented), and
    the work completes exactly once."""
    tmp = tempfile.mkdtemp(prefix="agentlink-kh-")
    db = _db(tmp)
    home = RelayHandle(db, "kh-fo-home")
    peer = RelayHandle(db, "kh-fo-peer")
    home_url = home.start()
    peer_url = peer.start()
    holder = {}

    async def _t():
        rider = Agent("kfrider", endpoint=home_url,
                      fallbacks=[peer_url],
                      state_dir=str(state_root / "kfrider"))
        task = asyncio.create_task(
            rider.run(reconnect_delay=0.5, home_probe_interval=1.0))
        try:
            assert await wait_for(
                lambda: home.relay and "kfrider" in home.relay.peers)
            boss = Agent("kfboss", endpoint=home_url,
                         state_dir=str(state_root / "kfboss"))
            await boss.start()
            works = await boss.assign_work(
                ["kfrider"], "Survive the key-hello failover",
                instructions="deliver after the move")
            wid = works[0]["id"]
            holder["wid"] = wid
            assert await wait_for(
                lambda: len(rider.assigned_work) == 1)
            # Home dies mid-work; the rider fails over to the peer
            # and its reconnect hello there is key-signed.
            home.kill()
            assert await wait_for(
                lambda: peer.relay and "kfrider" in peer.relay.peers)
            assert rider.current_endpoint == peer_url
            assert await wait_for(
                lambda: _auth_method(db, "kfrider") == "key")
            await rider.deliver_work(wid, body="done via peer, "
                                               "key-signed")
            assert await wait_for(lambda: _work_status(db, wid)
                                  == "delivered")
            # The assigner (whose own home connection died with
            # the relay) re-enters via the peer and completes it.
            boss2 = Agent("kfboss", endpoint=peer_url,
                          state_dir=str(state_root / "kfboss"))
            await boss2.start()
            await boss2.complete_work(wid)
            await boss2.close()
            assert await wait_for(lambda: _work_status(db, wid)
                                  == "completed")
            await boss.close()
        finally:
            task.cancel()
            try:
                await rider.close()
            except Exception:
                pass

    run(_t())
    conn = sqlite3.connect(db)
    try:
        n = conn.execute(
            "SELECT COUNT(*) FROM work_deliveries WHERE work_id = ?",
            (holder["wid"],)).fetchone()[0]
    finally:
        conn.close()
    assert n == 1, f"expected exactly one delivery, saw {n}"
    home.kill()
    peer.stop()


def _work_status(db, wid):
    conn = sqlite3.connect(db)
    try:
        row = conn.execute("SELECT status FROM work WHERE id = ?",
                           (wid,)).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def test_ping_inside_auth_window_does_not_kill_hello(state_root):
    """v1.6.0 pin — the 44-race gate failure, root-caused: a
    liveness ping landing between the auth_challenge and the
    auth_response must be answered with a pong while the
    authentication proceeds. The pre-fix relay waited with a
    single recv and refused the hello outright ('expected
    auth_response, got ping' -> key_auth_failed): a migrated
    agent whose previous session's heartbeat loop ticked on its
    new socket mid-handshake had its hello assassinated by its
    own ping, and its queued work then waited on a session that
    never landed. Equally pinned: a NON-liveness frame in the
    same window still fails the authentication — the tolerance
    is for pings only, and the signature gate is unchanged."""
    tmp = tempfile.mkdtemp(prefix="agentlink-kh-")
    db = _db(tmp)
    h = RelayHandle(db, "kh-pingwindow")
    url = h.start()

    async def _hello_with_interleave(identity, interleave):
        frames = []
        async with connect(url) as ws:
            await ws.send(json.dumps({
                "type": "hello", "username": "pingvic",
                "display_name": "pingvic", "secret": None,
                "auth": "key", "ephemeral": False,
                "pubkey": identity.public_key_b64,
                "sign_pub": identity.signing_public_key_b64,
                "capabilities": [], "mode": "autonomous"}))
            while True:
                frame = json.loads(
                    await asyncio.wait_for(ws.recv(), 10))
                frames.append(frame)
                if frame.get("type") == "auth_challenge":
                    await ws.send(json.dumps(interleave))
                    continue
                return frames, frame

    async def _t():
        first = Agent("pingvic", endpoint=url,
                      state_dir=str(state_root / "pingvic"))
        await first.start()
        await first.close()
        real = Identity("pingvic", str(state_root / "pingvic"))
        # The interleave is a ping: a pong must come back, and the
        # NEXT frame after it must be a fresh decision point — the
        # challenge is still outstanding, so we then answer it.
        frames = []
        async with connect(url) as ws:
            await ws.send(json.dumps({
                "type": "hello", "username": "pingvic",
                "display_name": "pingvic", "secret": None,
                "auth": "key", "ephemeral": False,
                "pubkey": real.public_key_b64,
                "sign_pub": real.signing_public_key_b64,
                "capabilities": [], "mode": "autonomous"}))
            challenge = None
            while True:
                frame = json.loads(
                    await asyncio.wait_for(ws.recv(), 10))
                frames.append(frame)
                if frame.get("type") == "auth_challenge":
                    challenge = frame
                    await ws.send(json.dumps({"type": "ping"}))
                    continue
                if frame.get("type") == "pong":
                    payload = auth_challenge_payload(
                        challenge["nonce"], challenge["relay"],
                        "pingvic", challenge["expires"])
                    await ws.send(json.dumps({
                        "type": "auth_response",
                        "signature": real.sign(payload)}))
                    continue
                last = frame
                break
        assert last["type"] == "welcome", frames
        # A junk frame in the window still kills the hello.
        frames2, last2 = await _hello_with_interleave(
            real, {"type": "send", "to": "anyone", "body": "x"})
        assert last2["type"] == "error"
        assert last2["reason"] == "key_auth_failed"
        # And the genuine key still works afterwards.
        frames3, last3 = await _raw_key_hello(url, "pingvic", real)
        assert last3["type"] == "welcome"

    run(_t())
    h.stop()
