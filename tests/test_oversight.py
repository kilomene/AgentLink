"""Owner-oversight suite (owner's direct order 2026-11-01: he reads
agents' conversations on his dashboard, WhatsApp-style, 1v1 and
groups, live).

Design pinned here:
- An oversight X25519 keypair lives with the operator. The PUBLIC key
  reaches clients via the relay's welcome frame (zero manual config)
  or the client env AGENTLINK_OVERSIGHT_PUBKEY (the override).
- Clients attach an ``oversight`` wrap to content frames: kind
  ``content`` (the content payload JSON, sealed to the oversight key)
  for 1:1 messages and work assignments/deliveries; kind
  ``content_key`` (the raw symmetric key) for group/channel messages
  and blob file keys.
- The relay carries the wrap into the audit/dashboard path
  (audit_log.oversight, _conversations items) but stores CIPHERTEXT
  ONLY — it holds no oversight private key.
- Relay env AGENTLINK_REQUIRE_OVERSIGHT=1 rejects unwrapped content
  with 'oversight_required'; default off.
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import stat
import tempfile
import threading
from pathlib import Path

import pytest

from agentlink import cli
from agentlink.client import Agent, RequestFailed
from agentlink.crypto import OversightKey, decrypt_with_key
from agentlink.relay import Relay

HOST = "127.0.0.1"


@pytest.fixture()
def relay_factory():
    started = []

    def make(**relay_kw):
        tmp = tempfile.mkdtemp(prefix="agentlink-ov-")
        db = str(Path(tmp) / "relay.db")
        relay = Relay(host=HOST, port=0, db_path=db,
                      dashboard_password="pw", **relay_kw)
        ready = threading.Event()
        box: dict = {}

        def _thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            box["loop"] = loop

            async def _serve():
                await relay.start()
                ready.set()
                await asyncio.Future()

            try:
                loop.run_until_complete(_serve())
            except (RuntimeError, asyncio.CancelledError):
                pass

        t = threading.Thread(target=_thread, daemon=True)
        t.start()
        assert ready.wait(timeout=10)
        env = {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
               "db": db, "relay": relay, "tmp": Path(tmp)}
        started.append(env)
        return env

    yield make
    for env in started:
        fut = asyncio.run_coroutine_threadsafe(
            env["relay"].stop(), env.get("loop") or _loop_of(env))
        try:
            fut.result(timeout=10)
        except Exception:
            pass


def _loop_of(env):  # pragma: no cover - teardown helper
    return env["relay"]._scan_task.get_loop() if env["relay"]._scan_task \
        else None


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-ov-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


async def make(env, state_root, username, **kw):
    a = Agent(username, endpoint=env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=8.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


def audit_rows(env, kind):
    rows = env["relay"].store.list_audit(500)
    return [r for r in rows if r["kind"] == kind]


# -- keygen / key file ------------------------------------------------------

def test_keygen_cli_writes_0600_and_prints_only_pubkey(tmp_path, capsys):
    out = tmp_path / "oversight-key.json"
    rc = cli.main(["oversight-keygen", "--out", str(out)])
    assert rc == 0
    printed = capsys.readouterr().out.strip()
    data = json.loads(out.read_text())
    assert data["kind"] == "agentlink-oversight-key"
    assert data["version"] == 1
    # stdout is ONLY the public key; the private key never prints.
    assert printed == data["public_key"]
    assert data["private_key"] not in printed
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    key = OversightKey.load(out)
    assert key.public_key_b64 == data["public_key"]
    # Refuses to clobber without --force.
    assert cli.main(["oversight-keygen", "--out", str(out)]) == 2


def test_oversight_key_content_and_key_roundtrip():
    key = OversightKey.generate()
    a = Agent.__new__(Agent)  # wrap helpers need no connection
    a.oversight_pubkey = key.public_key_b64
    from agentlink.crypto import encrypt_to_pubkey
    env = encrypt_to_pubkey(key.public_key_b64,
                            json.dumps({"body": "hi"}).encode())
    env["kind"] = "content"
    assert key.open_content(env) == {"body": "hi"}
    raw = os.urandom(32)
    kenv = encrypt_to_pubkey(key.public_key_b64, raw)
    kenv["kind"] = "content_key"
    assert key.open_key(kenv) == raw


# -- distribution: welcome advertisement + env override ---------------------

def test_welcome_advertises_and_client_adopts(relay_factory, state_root):
    okey = OversightKey.generate()
    env = relay_factory(oversight_pubkey=okey.public_key_b64)

    async def scenario():
        a = await make(env, state_root, "alice")
        try:
            # No local config: the welcome frame's key is adopted.
            assert a.oversight_pubkey == okey.public_key_b64
        finally:
            await a.close()
        # Local config is the override: the relay's key never
        # replaces a client-configured one.
        other = OversightKey.generate()
        b = await make(env, state_root, "bob",
                       oversight_pubkey=other.public_key_b64)
        try:
            assert b.oversight_pubkey == other.public_key_b64
        finally:
            await b.close()

    run(scenario())


def test_env_var_is_client_config(relay_factory, state_root, monkeypatch):
    okey = OversightKey.generate()
    monkeypatch.setenv("AGENTLINK_OVERSIGHT_PUBKEY",
                       okey.public_key_b64)
    env = relay_factory()  # relay advertises nothing

    async def scenario():
        a = await make(env, state_root, "alice")
        try:
            assert a.oversight_pubkey == okey.public_key_b64
        finally:
            await a.close()

    run(scenario())


# -- 1:1: content wrap, decryptable, in audit + conversations ----------------

def test_1v1_oversight_roundtrip(relay_factory, state_root):
    okey = OversightKey.generate()
    env = relay_factory(oversight_pubkey=okey.public_key_b64)
    body = "oversight checks the mail"

    async def scenario():
        a = await make(env, state_root, "alice")
        b = await make(env, state_root, "bob")
        try:
            await a.send_message("bob", body)
            assert await wait_for(lambda: len(b.messages) == 1)
            assert b.messages[0]["body"] == body
        finally:
            await a.close()
            await b.close()

    run(scenario())
    rows = audit_rows(env, "message")
    assert len(rows) == 1
    ov = rows[0]["oversight"]
    assert ov and ov["kind"] == "content"
    assert ov["alg"] == "x25519-chacha20poly1305"
    opened = okey.open_content(ov)
    assert opened["body"] == body
    # The dashboard data path carries the same wrap.
    convs = env["relay"]._conversations()
    items = [i for c in convs for i in c["items"] if i["kind"] == "message"]
    assert items and items[0]["oversight"]["ct"] == ov["ct"]


# -- group + channel: content-key wraps ---------------------------------------

def test_group_oversight_is_key_wrap(relay_factory, state_root):
    okey = OversightKey.generate()
    env = relay_factory(oversight_pubkey=okey.public_key_b64)

    async def scenario():
        a = await make(env, state_root, "alice")
        b = await make(env, state_root, "bob")
        try:
            g = await a.group_create("ov group", ["bob"])
            gid = g["group_id"]
            await a.group_send(gid, "group secret hello")
            assert await wait_for(
                lambda: any(m.get("group_id") == gid for m in b.messages))
            return a, gid
        finally:
            await a.close()
            await b.close()

    a_gid = run(scenario())
    a, gid = a_gid
    rows = audit_rows(env, "group_message")
    assert len(rows) == 1
    ov = rows[0]["oversight"]
    assert ov and ov["kind"] == "content_key"
    key = okey.open_key(ov)
    # The wrapped key IS the group key: it decrypts group-key content.
    probe = {"nonce": "", "ct": ""}
    from agentlink.crypto import encrypt_with_key
    probe = encrypt_with_key(key, b"dashboard-can-read-this")
    assert decrypt_with_key(key, probe) == b"dashboard-can-read-this"


def test_channel_oversight_is_key_wrap(relay_factory, state_root):
    okey = OversightKey.generate()
    env = relay_factory(oversight_pubkey=okey.public_key_b64)

    async def scenario():
        a = await make(env, state_root, "alice")
        b = await make(env, state_root, "bob")
        try:
            c = await a.channel_create("ov channel", ["bob"])
            await a.channel_send(c["channel_id"], "channel post hello")
            assert await wait_for(lambda: len(b.messages) == 1)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    rows = audit_rows(env, "channel_message")
    assert len(rows) == 1
    ov = rows[0]["oversight"]
    assert ov and ov["kind"] == "content_key"
    assert len(okey.open_key(ov)) == 32


# -- file keys -----------------------------------------------------------------

def test_file_key_oversight_wrap(relay_factory, state_root, tmp_path):
    okey = OversightKey.generate()
    env = relay_factory(oversight_pubkey=okey.public_key_b64)
    f = tmp_path / "report.bin"
    payload = b"file-body-for-oversight" * 4
    f.write_bytes(payload)

    async def scenario():
        a = await make(env, state_root, "alice")
        b = await make(env, state_root, "bob")
        try:
            desc = await a._make_blob_descriptor(
                str(f), None, for_user="bob")
            assert desc["oversight"]["kind"] == "content_key"
            key = okey.open_key(desc["oversight"])
            data = await a._request({"type": "blob_get",
                                     "blob_id": desc["blob_id"]})
            raw = decrypt_with_key(
                key, {"nonce": desc["blob_nonce"], "ct": data["data_b64"]})
            assert raw == payload
            # End to end: the recipient still receives the file intact.
            await a.send_file("bob", str(f), via_blob=True)
            assert await wait_for(lambda: len(b.messages) == 1)
            got = b.messages[0]["file"]
            assert base64.b64decode(got["data_b64"]) == payload
        finally:
            await a.close()
            await b.close()

    run(scenario())


# -- work: assignment + delivery content wraps ---------------------------------

def test_work_assign_and_delivery_oversight(relay_factory, state_root):
    okey = OversightKey.generate()
    env = relay_factory(oversight_pubkey=okey.public_key_b64)

    async def scenario():
        a = await make(env, state_root, "alice")
        b = await make(env, state_root, "bob")
        try:
            works = await a.assign_work(["bob"], "oversight title",
                                        "do the thing")
            wid = works[0]["id"]
            await b.deliver_work(wid, "delivery body here")
        finally:
            await a.close()
            await b.close()

    run(scenario())
    assigned = audit_rows(env, "work_assigned")
    assert assigned and assigned[0]["oversight"]["kind"] == "content"
    assert okey.open_content(
        assigned[0]["oversight"])["title"] == "oversight title"
    delivered = audit_rows(env, "work_delivered")
    assert delivered and delivered[0]["oversight"]["kind"] == "content"
    assert okey.open_content(
        delivered[0]["oversight"])["body"] == "delivery body here"


# -- policy knob -----------------------------------------------------------------

def test_require_oversight_rejects_unwrapped(relay_factory, state_root):
    okey = OversightKey.generate()
    # Policy ON, but the relay does NOT advertise a key: only clients
    # configured out-of-band (env/arg) can satisfy the policy.
    env = relay_factory(require_oversight=True)

    async def scenario():
        bare = await make(env, state_root, "bare")
        wrapped = await make(env, state_root, "wrapped",
                             oversight_pubkey=okey.public_key_b64)
        try:
            with pytest.raises(RequestFailed) as exc:
                await bare.send_message("wrapped", "must be rejected")
            assert exc.value.reason == "oversight_required"
            # A wrapped send passes the same gate.
            await wrapped.send_message("bare", "wrapped and fine")
            assert await wait_for(lambda: len(bare.messages) == 1)
            # Deliveries are gated too.
            works = await wrapped.assign_work(["bare"], "gated work", "")
            with pytest.raises(RequestFailed) as exc:
                await bare.deliver_work(works[0]["id"], "unwrapped")
            assert exc.value.reason == "oversight_required"
        finally:
            await bare.close()
            await wrapped.close()

    run(scenario())


def test_no_oversight_configured_sends_without_wrap(relay_factory,
                                                    state_root):
    env = relay_factory()  # no pubkey anywhere, policy off (default)

    async def scenario():
        a = await make(env, state_root, "alice")
        b = await make(env, state_root, "bob")
        try:
            assert a.oversight_pubkey == ""
            await a.send_message("bob", "plain old sealed mail")
            assert await wait_for(lambda: len(b.messages) == 1)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    rows = audit_rows(env, "message")
    assert len(rows) == 1
    assert rows[0]["oversight"] is None


# -- relay storage stays ciphertext-only -----------------------------------------

def test_relay_storage_is_ciphertext_only(relay_factory, state_root,
                                          tmp_path):
    okey = OversightKey.generate()
    env = relay_factory(oversight_pubkey=okey.public_key_b64)
    markers = [b"OVERSIGHT-MARKER-DM-9f27", b"OVERSIGHT-MARKER-GRP-9f27",
               b"OVERSIGHT-MARKER-TITLE-9f27",
               b"OVERSIGHT-MARKER-DELIV-9f27",
               b"OVERSIGHT-MARKER-FILE-9f27"]
    f = tmp_path / "blob.bin"
    f.write_bytes(markers[4] * 3)

    async def scenario():
        a = await make(env, state_root, "alice")
        b = await make(env, state_root, "bob")
        try:
            await a.send_message("bob", markers[0].decode())
            g = await a.group_create("scan group", ["bob"])
            await a.group_send(g["group_id"], markers[1].decode())
            await a.send_file("bob", str(f), via_blob=True)
            works = await a.assign_work(["bob"], markers[2].decode(), "x")
            await b.deliver_work(works[0]["id"], markers[3].decode())
            assert await wait_for(lambda: len(b.messages) >= 3)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    # Every byte the relay persists (db + WAL + blob files) is scanned:
    # the plaintext markers appear NOWHERE.
    scanned = 0
    for p in env["tmp"].rglob("*"):
        if p.is_file():
            scanned += 1
            blob = p.read_bytes()
            for m in markers:
                assert m not in blob, f"{m!r} found in relay file {p}"
    assert scanned >= 2  # db (+ blobs dir contents)
    # And the dashboard-facing dumps are ciphertext-only too.
    dump = json.dumps(env["relay"]._dashboard_data(), default=str)
    for m in markers:
        assert m.decode() not in dump
