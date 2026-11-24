"""v2.6.1: ENCRYPTION KEY EPOCHS, client half (SPEC Fix 2 + Fix 3).

Pins, against the pinned protocol in drill-evidence/v261/STATE.md:

* crypto.Identity: keys file carries key_epoch (default 1);
  the keyring retains prior encryption keys (mode 600) and
  decrypt_any opens a message sealed to a retired key after
  rotate_encryption_key; ephemeral identities write no files.
* Possession handshake: register / recovery / rectify ALWAYS
  call the login Edge method key_challenge first and attach a
  key_proof whose signature verifies against the candidate
  signing key; without a candidate identity the handshake
  fails closed instead of publishing an unproven key.
* Send-time freshness: the serverless DM send resolves
  (pubkey, epoch) via peer_key on EVERY send (no cached key
  is consulted) and stamps the envelope with key_epoch.
* Decrypt failure: an undecryptable DM parks unreadable AND
  sends exactly one key_mismatch notice per (message_id, own
  current epoch), across restarts and re-offers.
* Auto-reseal: on a key_mismatch frame the sender reseals its
  stored sent plaintext to the recipient's CURRENT key exactly
  once per (message_id, recipient_epoch), with meta.reseals;
  the receiver links a reseal to a readable original (never
  surfaced twice) and surfaces + heals an unreadable one.
* Fix 2 sub-item 6: a group with no admin still heals: the
  group key request falls back to every other member, and the
  re-issuer needs only to hold the key.
* Fix 3: the control channel forwards group_create and
  group_remove to the running daemon like group_add.
"""
from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentlink import cli as cli_mod  # noqa: E402
from agentlink.client import Agent, RequestFailed  # noqa: E402
from agentlink.crypto import (Identity, encrypt_to_pubkey)  # noqa: E402
from agentlink.mailbox import Mailbox  # noqa: E402
from agentlink.transport_v2 import (ServerlessTransport,  # noqa: E402
                                    TransportError)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=30))


def _identity(tmp_path, name, sub="state"):
    return Identity(name, tmp_path / sub)


# ---------------------------------------------------------------- crypto

def test_keys_file_carries_epoch_and_keyring_mode_600(tmp_path):
    ident = _identity(tmp_path, "alice")
    assert ident.key_epoch == 1
    data = json.loads((tmp_path / "state" / "keys-alice.json")
                      .read_text())
    assert data["key_epoch"] == 1
    # a pre-epoch keys file reads as epoch 1 and gains the field
    old = {"username": "old", "private_key": data["private_key"],
           "public_key": data["public_key"],
           "signing_private_key": data["signing_private_key"],
           "signing_public_key": data["signing_public_key"]}
    (tmp_path / "state2").mkdir()
    (tmp_path / "state2" / "keys-old.json").write_text(
        json.dumps(old))
    ident2 = Identity("old", tmp_path / "state2")
    assert ident2.key_epoch == 1
    assert json.loads(
        (tmp_path / "state2" / "keys-old.json").read_text()
    )["key_epoch"] == 1
    # rotate: epoch 2, keyring written mode 600 with epoch 1
    ident.rotate_encryption_key()
    assert ident.key_epoch == 2
    assert json.loads((tmp_path / "state" / "keys-alice.json")
                      .read_text())["key_epoch"] == 2
    kring = tmp_path / "state" / "keyring-alice.json"
    assert kring.exists()
    assert stat.S_IMODE(kring.stat().st_mode) == 0o600
    retired = json.loads(kring.read_text())["retired"]
    assert [r["key_epoch"] for r in retired] == [1]
    assert stat.S_IMODE(
        (tmp_path / "state" / "keys-alice.json").stat().st_mode
    ) == 0o600


def test_keyring_retention_decrypt_any_after_rotation(tmp_path):
    ident = _identity(tmp_path, "bob")
    old_pub = ident.public_key_b64
    env = encrypt_to_pubkey(old_pub, b"sealed before rotation")
    # the current key cannot open it after the rotation...
    ident.rotate_encryption_key()
    assert ident.public_key_b64 != old_pub
    with pytest.raises(Exception):
        ident.decrypt_envelope(env)
    # ...but decrypt_any opens it via the retained epoch-1 key
    plaintext, epoch_used = ident.decrypt_any(env)
    assert plaintext == b"sealed before rotation"
    assert epoch_used == 1
    # a message sealed to the CURRENT key reports epoch 2
    env2 = encrypt_to_pubkey(ident.public_key_b64, b"current key")
    plaintext2, epoch2 = ident.decrypt_any(env2)
    assert plaintext2 == b"current key"
    assert epoch2 == 2
    # archiving twice does not duplicate the epoch
    assert ident.archive_current_key() is True
    assert ident.archive_current_key() is False
    retired = json.loads(
        (tmp_path / "state" / "keyring-bob.json").read_text()
    )["retired"]
    assert sorted(r["key_epoch"] for r in retired) == [1, 2]


def test_ephemeral_identity_writes_no_files(tmp_path):
    ident = Identity.ephemeral()
    assert ident.key_epoch == 1
    assert ident.archive_current_key() is False
    assert ident.rotate_encryption_key() == 2
    assert ident.key_epoch == 2
    assert list(tmp_path.iterdir()) == []


def test_restore_retired_key_rolls_rotation_back(tmp_path):
    ident = _identity(tmp_path, "carol")
    old_pub = ident.public_key_b64
    ident.rotate_encryption_key()
    assert ident.public_key_b64 != old_pub
    assert ident.restore_retired_key(1) is True
    assert ident.key_epoch == 1
    assert ident.public_key_b64 == old_pub
    assert ident.restore_retired_key(99) is False


# ------------------------------------------------------- handshake (fake Edge)

def _edge_transport(captured):
    t = ServerlessTransport.__new__(ServerlessTransport)
    t.username = ""
    t._decision_link = ""
    t._decision_detail = None
    t.client_version = ""

    def _pre(username, signer, client_version="",
             decision_link=None, decision_link_detail=None):
        t.username = username

    t._session_preamble = _pre

    def _edge(route, payload):
        captured.append((route, dict(payload)))
        if route == "key_challenge":
            env = encrypt_to_pubkey(
                payload["candidate_pubkey"],
                json.dumps({"nonce": "n-9",
                            "challenge_id": "ch-9",
                            "username": payload["username"]})
                .encode())
            return {"challenge_id": "ch-9", "envelope": env}
        return {"ok": True, "recovery_key": "issued-key"}

    t._edge_post = _edge
    t._adopt_tokens = lambda username, r: {"username": username}
    t.start_activeness = lambda: None
    return t


def _check_proof(cap, route, ident):
    chal = [p for r, p in cap if r == "key_challenge"]
    assert len(chal) == 1
    assert chal[0]["candidate_pubkey"] == ident.public_key_b64
    assert chal[0]["candidate_sign_pub"] == \
        ident.signing_public_key_b64
    assert cap[0][0] == "key_challenge"
    assert cap[1][0] == route
    payload = [p for r, p in cap if r == route][0]
    proof = payload.get("key_proof")
    assert proof
    assert proof["challenge_id"] == "ch-9"
    assert proof["nonce"] == "n-9"
    assert Identity.verify_signature(
        ident.signing_public_key_b64,
        b"agentlink-key-proof-v1:ch-9:n-9",
        proof["signature"])


def test_handshake_proof_on_register_recovery_rectify(tmp_path):
    ident = _identity(tmp_path, "dave")
    cap = []
    t = _edge_transport(cap)
    t.register_and_login("dave", ident.sign,
                         ident.signing_public_key_b64,
                         ident.public_key_b64, identity=ident)
    _check_proof(cap, "register", ident)
    assert [p for r, p in cap if r == "key_challenge"][0][
        "purpose"] == "register"

    cap = []
    t = _edge_transport(cap)
    t.recover_and_login("dave", ident.sign, "rk-1",
                        ident.signing_public_key_b64,
                        ident.public_key_b64, identity=ident)
    _check_proof(cap, "recovery", ident)
    assert [p for r, p in cap if r == "key_challenge"][0][
        "purpose"] == "recovery"

    cap = []
    t = _edge_transport(cap)
    t.rectify_and_login("dave", ident.sign, "code-1",
                        ident.signing_public_key_b64,
                        ident.public_key_b64, identity=ident)
    _check_proof(cap, "rectify", ident)
    assert [p for r, p in cap if r == "key_challenge"][0][
        "purpose"] == "rectify"


def test_handshake_resolves_identity_from_bound_signer(tmp_path):
    # Every real call site passes identity.sign; the bound
    # method carries the identity, so no explicit identity=
    # kwarg is needed.
    ident = _identity(tmp_path, "erin")
    cap = []
    t = _edge_transport(cap)
    t.register_and_login("erin", ident.sign,
                         ident.signing_public_key_b64,
                         ident.public_key_b64)
    _check_proof(cap, "register", ident)


def test_handshake_fails_closed_without_identity(tmp_path):
    cap = []
    t = _edge_transport(cap)
    with pytest.raises(TransportError) as ei:
        t.register_and_login("fran", lambda b: "c2ln", "SP", "PK")
    assert "key_challenge" in str(ei.value)
    # no register call was ever made: nothing unpublished
    assert [r for r, _ in cap] == ["key_challenge"] or \
        [r for r, _ in cap] == []


def test_handshake_fails_closed_on_unopenable_envelope(tmp_path):
    ident = _identity(tmp_path, "gail")
    other = _identity(tmp_path, "hank", sub="state2")
    t = ServerlessTransport.__new__(ServerlessTransport)
    t.username = "gail"
    t._session_preamble = lambda *a, **k: None

    def _edge(route, payload):
        if route == "key_challenge":
            # sealed to a DIFFERENT key: the candidate cannot
            # open it, so no proof is ever produced
            env = encrypt_to_pubkey(
                other.public_key_b64,
                json.dumps({"nonce": "n", "challenge_id": "c",
                            "username": "gail"}).encode())
            return {"challenge_id": "c", "envelope": env}
        raise AssertionError("must not reach register")

    t._edge_post = _edge
    with pytest.raises(TransportError):
        t.register_and_login("gail", ident.sign,
                             ident.signing_public_key_b64,
                             ident.public_key_b64, identity=ident)


# ------------------------------------------------------------- peer_key

def _rest_transport(rows):
    t = ServerlessTransport.__new__(ServerlessTransport)
    t.username = "alice"
    t._directory_cache = {}
    t.doorbell = type("D", (), {"has_token": False})()
    calls = []

    def _rest(method, table, query="", body=None, prefer=None,
              **kw):
        calls.append((method, table, query))
        return [dict(r) for r in rows]

    t._rest = _rest
    t.calls = calls
    return t


def test_peer_key_fresh_read_every_call(tmp_path):
    rows = [{"username": "bob", "pubkey": "PUB-BOB",
             "key_epoch": 4}]
    t = _rest_transport(rows)
    assert t.peer_key("bob") == ("PUB-BOB", 4)
    assert t.peer_key("bob") == ("PUB-BOB", 4)
    # two sends, two REST reads: no cross-send cache is
    # consulted or populated by peer_key
    assert len(t.calls) == 2
    assert all("key_epoch" in q for _m, _t, q in t.calls)
    assert t._directory_cache == {}


def test_peer_key_missing_key_raises(tmp_path):
    t = _rest_transport([])
    with pytest.raises(TransportError):
        t.peer_key("nobody")


def test_directory_entry_carries_key_epoch(tmp_path):
    rows = [{"username": "bob", "pubkey": "PUB",
             "sign_pub": "SP", "capabilities": [],
             "key_epoch": 5}]
    t = _rest_transport(rows)
    entry = t.directory_entry("bob")
    assert entry["key_epoch"] == 5
    # a pre-epoch row reads as epoch 1
    t2 = _rest_transport([{"username": "bob", "pubkey": "PUB",
                           "sign_pub": "SP", "capabilities": []}])
    assert t2.directory_entry("bob")["key_epoch"] == 1


# ------------------------------------------------------------- Agent shell

class FakeV2:
    """A scripted stand-in for the serverless transport."""

    def __init__(self, peer_keys=None):
        self.peer_keys = peer_keys or {}
        self.peer_key_calls: list[str] = []
        self.mismatch_calls: list[tuple] = []
        self.acked: list[list[str]] = []
        self._directory_cache: dict = {}

    def peer_key(self, username):
        self.peer_key_calls.append(username)
        return self.peer_keys[username]

    def key_mismatch(self, message_id, recipient_epoch):
        self.mismatch_calls.append(
            (message_id, recipient_epoch))
        return {"ok": True}

    def ack(self, ids):
        self.acked.append(list(ids))
        return {"acked": list(ids)}

    def directory_entry(self, username):
        return {"username": username, "pubkey": "PUB",
                "key_epoch": 2}

    def publish_my_directory(self, entry):
        self.published = dict(entry)
        return True


def _agent_shell(tmp_path, username, identity, v2=None):
    a = Agent.__new__(Agent)
    a.username = username
    a.state_dir = Path(tmp_path / f"state-{username}")
    a.state_dir.mkdir(parents=True, exist_ok=True)
    a.ephemeral = False
    a.identity = identity
    a.display_name = username
    a.mode = "manual"
    a.auto_read = False
    a.oversight_pubkey = ""
    a._v2 = v2
    a._ws = None
    a.mailbox = Mailbox(a.state_dir / "mailbox.db",
                        owner=username)
    a.messages = []
    a.mention_inbox_items = []
    a._unreadable = {}
    a._key_mismatch_sent = {}
    a._load_key_mismatch_sent()
    a._key_reseals = {}
    a._load_key_reseals()
    a._pubkey_cache = {}
    a._group_keys = {}
    a._channel_keys = {}
    a._reply_waiters = {}
    a._takein_inflight = set()
    a._message_handler = None
    a._mention_handler = None
    a._urgent_handler = None
    a._pending_reads = set()
    a._recovery_key_manual = None
    a._declared_link_sent = None
    a._decision_detail = lambda: {}
    a._key_reissue_asked = set()
    return a


def _dm_frame(sender, mid, recipient_identity, body,
              meta=None):
    obj = {"body": body, "kind": "text", "file": None}
    if meta:
        obj["meta"] = dict(meta)
    env = encrypt_to_pubkey(
        recipient_identity.public_key_b64,
        json.dumps(obj).encode())
    return {"type": "message", "id": mid, "from": sender,
            "ts": 1700000000, "content": env}


# ------------------------------------------------------- send stamping

def test_send_message_stamps_key_epoch_fresh_every_send(tmp_path):
    sender = _identity(tmp_path, "alice")
    stale = _identity(tmp_path, "stale", sub="state-stale")
    fresh = _identity(tmp_path, "bob", sub="state-bob")
    v2 = FakeV2(peer_keys={"bob": (fresh.public_key_b64, 9)})
    a = _agent_shell(tmp_path, "alice", sender, v2=v2)
    # a STALE cached pubkey must never be consulted on the
    # serverless path: the seal must open with the FRESH key
    a._pubkey_cache["bob"] = (stale.public_key_b64, 9999999999.0)
    sent_frames = []

    async def _send_request(frame):
        sent_frames.append(frame)
        return {"id": frame["id"]}

    a._send_request = _send_request
    a._archive_readable_sync = lambda *args, **k: {"ok": True}
    run(a.send_message("bob", "hello epoch nine"))
    run(a.send_message("bob", "second send"))
    assert v2.peer_key_calls == ["bob", "bob"]
    assert len(sent_frames) == 2
    for frame in sent_frames:
        assert frame["content"]["key_epoch"] == 9
        # the envelope opens with the FRESH key, not the stale
        # cached one
        opened = json.loads(
            fresh.decrypt_envelope(frame["content"]))
        assert opened["body"] in ("hello epoch nine",
                                  "second send")
        with pytest.raises(Exception):
            stale.decrypt_envelope(frame["content"])


# ------------------------------------------------- mismatch notice (once)

def test_key_mismatch_notice_at_most_once_across_restart(tmp_path):
    ident = _identity(tmp_path, "alice")
    v2 = FakeV2()
    a = _agent_shell(tmp_path, "alice", ident, v2=v2)
    assert run(a._report_key_mismatch("m-1")) is True
    assert run(a._report_key_mismatch("m-1")) is False
    assert v2.mismatch_calls == [("m-1", 1)]
    # a restart (fresh shell, same state dir) still does not
    # re-notice the same (message, epoch)
    a2 = _agent_shell(tmp_path, "alice", ident, v2=v2)
    assert a2._key_mismatch_sent == {"m-1:1": a._key_mismatch_sent[
        "m-1:1"]}
    assert run(a2._report_key_mismatch("m-1")) is False
    assert len(v2.mismatch_calls) == 1
    # a NEW epoch is a new notice key
    ident.rotate_encryption_key()
    assert run(a2._report_key_mismatch("m-1")) is True
    assert v2.mismatch_calls[-1] == ("m-1", 2)


def test_undecryptable_dm_parks_and_notices_once(tmp_path):
    receiver = _identity(tmp_path, "alice")
    stranger = _identity(tmp_path, "stranger", sub="state-x")
    v2 = FakeV2()
    a = _agent_shell(tmp_path, "alice", receiver, v2=v2)
    frame = _dm_frame("bob", "m-undec", stranger, "lost mail")
    run(a._process_message(frame))
    stub = a.mailbox.get("m-undec")
    assert stub is not None
    assert stub.get("unreadable") is True
    assert stub.get("sealed") is True
    assert v2.mismatch_calls == [("m-undec", 1)]
    assert a.messages == []
    # the re-offer inside the park backoff does not re-notice
    run(a._process_message(frame))
    assert len(v2.mismatch_calls) == 1
    # a GROUP frame that cannot be decrypted never sends a DM
    # notice (room traffic heals through the room key reissue)
    group_frame = dict(frame)
    group_frame["id"] = "m-group-undec"
    group_frame["group_id"] = "g-1"
    run(a._process_message(group_frame))
    assert len(v2.mismatch_calls) == 1


def test_receive_path_opens_epoch1_message_after_rotation(tmp_path):
    receiver = _identity(tmp_path, "alice")
    old_pub = receiver.public_key_b64
    frame = _dm_frame("bob", "m-old", receiver, "before rotation")
    receiver.rotate_encryption_key()
    assert receiver.public_key_b64 != old_pub
    v2 = FakeV2()
    a = _agent_shell(tmp_path, "alice", receiver, v2=v2)
    run(a._process_message(frame))
    assert len(a.messages) == 1
    assert a.messages[0]["body"] == "before rotation"
    assert v2.mismatch_calls == []
    assert a.mailbox.get("m-old")["body"] == "before rotation"


# ---------------------------------------------------------------- reseal

def test_reseal_sent_exactly_once_with_meta(tmp_path):
    sender = _identity(tmp_path, "alice")
    receiver = _identity(tmp_path, "bob", sub="state-bob")
    receiver.rotate_encryption_key()
    new_pub = receiver.public_key_b64
    v2 = FakeV2(peer_keys={"bob": (new_pub, 2)})
    a = _agent_shell(tmp_path, "alice", sender, v2=v2)
    a.mailbox.put_if_absent(
        {"id": "m-orig", "from": "alice", "to": "bob",
         "body": "please reseal me", "kind": "text",
         "file": None, "meta": {}, "ts": 1700000000},
        taken=True)
    sent_frames = []

    async def _send_request(frame):
        sent_frames.append(frame)
        return {"id": frame["id"]}

    a._send_request = _send_request
    a._archive_readable_sync = lambda *args, **k: {"ok": True}
    frame = {"type": "key_mismatch", "message_id": "m-orig",
             "from": "bob", "recipient_epoch": 2}
    run(a._handle_key_mismatch(frame))
    run(a._handle_key_mismatch(frame))
    assert len(sent_frames) == 1
    assert v2.peer_key_calls == ["bob"]
    reseal = sent_frames[0]
    assert reseal["content"]["key_epoch"] == 2
    opened = json.loads(
        receiver.decrypt_envelope(reseal["content"]))
    assert opened["body"] == "please reseal me"
    assert opened["meta"] == {"reseals": "m-orig"}
    assert a._key_reseals == {
        "m-orig:2": {"reseal_id": reseal["id"],
                     "ts": a._key_reseals["m-orig:2"]["ts"],
                     "epoch": 2}}
    # a restart (fresh shell, same state dir) still does not
    # re-reseal the same (message, epoch)
    a2 = _agent_shell(tmp_path, "alice", sender, v2=v2)
    a2._send_request = _send_request
    a2._archive_readable_sync = lambda *args, **k: {"ok": True}
    run(a2._handle_key_mismatch(frame))
    assert len(sent_frames) == 1


def test_reseal_skipped_without_stored_plaintext(tmp_path):
    sender = _identity(tmp_path, "alice")
    v2 = FakeV2(peer_keys={"bob": ("PUB", 2)})
    a = _agent_shell(tmp_path, "alice", sender, v2=v2)
    sent_frames = []

    async def _send_request(frame):
        sent_frames.append(frame)
        return {"id": frame["id"]}

    a._send_request = _send_request
    run(a._handle_key_mismatch(
        {"type": "key_mismatch", "message_id": "m-gone",
         "from": "bob", "recipient_epoch": 2}))
    assert sent_frames == []
    assert a._key_reseals == {}


def test_reseal_of_readable_original_not_surfaces_twice(tmp_path):
    receiver = _identity(tmp_path, "alice")
    v2 = FakeV2()
    a = _agent_shell(tmp_path, "alice", receiver, v2=v2)
    a.mailbox.put_if_absent(
        {"id": "m-orig", "from": "bob", "to": "alice",
         "body": "already readable", "kind": "text",
         "file": None, "meta": {}, "ts": 1700000000},
        taken=True)
    frame = _dm_frame("bob", "m-reseal", receiver,
                      "already readable",
                      meta={"reseals": "m-orig"})
    run(a._process_message(frame))
    assert a.messages == []
    assert a.mailbox.get("m-orig").get("resealed_by") == "m-reseal"
    assert v2.acked == [["m-reseal"]]


def test_reseal_of_unreadable_original_surfaces_and_heals(tmp_path):
    receiver = _identity(tmp_path, "alice")
    v2 = FakeV2()
    a = _agent_shell(tmp_path, "alice", receiver, v2=v2)
    a.mailbox.put_if_absent(
        {"id": "m-orig", "from": "bob", "to": "alice",
         "body": "", "kind": "text", "file": None, "meta": {},
         "ts": 1700000000, "sealed": True, "unreadable": True},
        taken=False)
    a._unreadable = {"m-orig": {"attempts": 1, "next_ts": 0}}
    frame = _dm_frame("bob", "m-reseal", receiver,
                      "healed body", meta={"reseals": "m-orig"})
    run(a._process_message(frame))
    assert len(a.messages) == 1
    assert a.messages[0]["body"] == "healed body"
    healed = a.mailbox.get("m-orig")
    assert healed is not None
    assert healed.get("body") == "healed body"
    assert not healed.get("unreadable")
    assert "m-orig" not in a._unreadable


# ------------------------------------------------------- rotate_keys

def test_rotate_keys_rebinds_via_recovery(tmp_path):
    ident = _identity(tmp_path, "alice")
    old_pub = ident.public_key_b64
    v2 = FakeV2()
    recover_calls = []
    saved = []

    def _recover(username, signer, key, sign_pub, pubkey,
                 version="", decision_link=None,
                 decision_link_detail=None, identity=None):
        recover_calls.append({
            "username": username, "key": key,
            "sign_pub": sign_pub, "pubkey": pubkey,
            "identity": identity})
        return {"recovery_key": "rk-2"}

    v2.recover_and_login = _recover
    a = _agent_shell(tmp_path, "alice", ident, v2=v2)
    a._find_recovery_key = lambda: "rk-1"
    a._save_recovery_key = lambda k: saved.append(k)
    out = run(a.rotate_keys())
    assert out == {"rotated": True, "old_epoch": 1,
                   "key_epoch": 2, "recovery_key_issued": True}
    assert ident.key_epoch == 2
    assert ident.public_key_b64 != old_pub
    assert len(recover_calls) == 1
    assert recover_calls[0]["key"] == "rk-1"
    assert recover_calls[0]["pubkey"] == ident.public_key_b64
    assert recover_calls[0]["identity"] is ident
    assert saved == ["rk-2"]
    # the retired epoch-1 key is retained in the keyring
    retired = json.loads(
        (a.state_dir.parent / "state" / "keyring-alice.json")
        .read_text())["retired"]
    assert [r["key_epoch"] for r in retired] == [1]
    # the live directory copy is republished with the new epoch
    assert v2.published["key_epoch"] == 2


def test_rotate_keys_rolls_back_when_rebind_fails(tmp_path):
    ident = _identity(tmp_path, "alice")
    old_pub = ident.public_key_b64

    def _recover(*args, **kw):
        raise TransportError("recovery_failed")

    v2 = FakeV2()
    v2.recover_and_login = _recover
    a = _agent_shell(tmp_path, "alice", ident, v2=v2)
    a._find_recovery_key = lambda: "rk-1"
    with pytest.raises(RequestFailed) as ei:
        run(a.rotate_keys())
    assert "rotate_keys_rebind_failed" in str(ei.value)
    assert ident.key_epoch == 1
    assert ident.public_key_b64 == old_pub


def test_rotate_keys_needs_recovery_key(tmp_path):
    ident = _identity(tmp_path, "alice")
    v2 = FakeV2()
    a = _agent_shell(tmp_path, "alice", ident, v2=v2)
    a._find_recovery_key = lambda: None
    with pytest.raises(RequestFailed) as ei:
        run(a.rotate_keys())
    assert "rotate_keys_needs_recovery_key" in str(ei.value)
    assert ident.key_epoch == 1


# ------------------------------------------- Fix 2 sub-item 6 (no admin)

def test_group_key_request_falls_back_to_members_no_admin(tmp_path):
    t = ServerlessTransport.__new__(ServerlessTransport)
    t.username = "alice"
    enqueued = []

    def _members(gid):
        return [
            {"username": "alice", "role": "member"},
            {"username": "bob", "role": "member"},
            {"username": "carol", "role": "member"}]

    t.group_members = _members
    t._enqueue = lambda to, frame: enqueued.append((to, frame))
    out = t.request_group_key({"group_id": "g-1"})
    assert out == {"admins": []}
    assert [to for to, _ in enqueued] == ["bob", "carol"]
    assert all(f["type"] == "group_key_request"
               for _, f in enqueued)
    # with admins present the ask still goes to admins only
    t.group_members = lambda gid: [
        {"username": "alice", "role": "member"},
        {"username": "bob", "role": "admin"},
        {"username": "carol", "role": "member"}]
    enqueued.clear()
    out = t.request_group_key({"group_id": "g-1"})
    assert out == {"admins": ["bob"]}
    assert [to for to, _ in enqueued] == ["bob"]


def test_reissue_group_key_needs_only_the_key(tmp_path):
    # The re-issuer side enforces no admin precondition: a
    # member holding the group key answers a requester. (The
    # docstring names the rule; the CODE must not test roles.)
    src = (ROOT / "agentlink" / "client.py").read_text()
    body = src[src.index("async def _reissue_group_key"):]
    body = body[:body.index("async def _reissue_channel_key")]
    start = body.index('"""')
    code = body[body.index('"""', start + 3) + 3:]
    assert "admin" not in code.lower()
    assert "_distribute_group_key" in code


# ------------------------------------------------------------- Fix 3

class _FakeReader:
    def __init__(self, line):
        self._line = line

    async def readline(self):
        return self._line


class _FakeWriter:
    def __init__(self):
        self.written: list[bytes] = []

    def write(self, data):
        self.written.append(data)

    async def drain(self):
        return None

    def close(self):
        return None


def _control_agent(tmp_path):
    a = Agent.__new__(Agent)
    a.username = "alice"
    a._control_token = "tok-1"
    a.current_endpoint = None
    a.endpoint = None
    calls = {}

    async def _create(name, members=None, settings=None):
        calls["create"] = (name, members)
        return {"group_id": "g-new"}

    async def _remove(group_id, username):
        calls["remove"] = (group_id, username)
        return {"removed": username}

    a.group_create = _create
    a.group_remove = _remove
    a.calls = calls
    return a


def test_control_channel_forwards_group_create(tmp_path):
    a = _control_agent(tmp_path)
    writer = _FakeWriter()
    line = json.dumps({"token": "tok-1", "cmd": "group_create",
                       "name": "PACE", "members": ["bob"]}).encode()
    run(a._control_handle(_FakeReader(line), writer))
    assert a.calls["create"] == ("PACE", ["bob"])
    reply = json.loads(writer.written[-1])
    assert reply == {"ok": True,
                     "result": {"group_id": "g-new"}}


def test_control_channel_forwards_group_remove(tmp_path):
    a = _control_agent(tmp_path)
    writer = _FakeWriter()
    line = json.dumps({"token": "tok-1", "cmd": "group_remove",
                       "group_id": "g-1",
                       "target": "bob"}).encode()
    run(a._control_handle(_FakeReader(line), writer))
    assert a.calls["remove"] == ("g-1", "bob")
    reply = json.loads(writer.written[-1])
    assert reply == {"ok": True,
                     "result": {"removed": "bob"}}


def test_cli_group_forwards_create_and_remove():
    src = (ROOT / "agentlink" / "cli.py").read_text()
    assert '"cmd": "group_create"' in src
    assert '"cmd": "group_remove"' in src
    assert '"cmd": "group_add"' in src
    assert cli_mod.main(["keys"]) == 2
    assert cli_mod.main(["keys", "bogus"]) == 2


def test_sent_record_upgrades_own_sealed_echo(tmp_path):
    """Journal race (drill leg g5 root cause): a send's own
    sealed echo can return through the inbox/history path and
    journal first as a sealed, body-less copy under the send's
    id. The sent record (plaintext + meta) must upgrade that
    stub in place; the journal is the sender's memory of what
    it said, and the reseal record is read back from it."""
    ident = _identity(tmp_path, "alice")
    a = _agent_shell(tmp_path, "alice", ident)
    echo = {"id": "m-echo", "from": "alice", "to": "bob",
            "kind": "text", "body": "", "meta": {},
            "sealed": True, "unreadable": True, "ts": 1700000000}
    assert a.mailbox.put_if_absent(echo) is True
    a._mailbox_record_sent(
        {"id": "m-echo", "from": "alice", "to": "bob",
         "kind": "text", "body": "heal-me-261", "file": None,
         "meta": {"reseals": "m-orig"}, "ts": 1700000001})
    got = a.mailbox.get("m-echo")
    assert got["body"] == "heal-me-261"
    assert got["meta"] == {"reseals": "m-orig"}
    assert not got.get("sealed")


def test_sent_record_never_replaces_other_items(tmp_path):
    """The upgrade is narrow: a readable item, or another
    sender's item, already journaled under the id is never
    replaced by a sent record."""
    ident = _identity(tmp_path, "alice")
    a = _agent_shell(tmp_path, "alice", ident)
    inbound = {"id": "m-in", "from": "bob", "to": "alice",
               "kind": "text", "body": "hello alice",
               "meta": {}, "ts": 1700000000}
    assert a.mailbox.put_if_absent(inbound) is True
    a._mailbox_record_sent(
        {"id": "m-in", "from": "alice", "to": "bob",
         "kind": "text", "body": "forged", "file": None,
         "meta": {}, "ts": 1700000001})
    got = a.mailbox.get("m-in")
    assert got["from"] == "bob"
    assert got["body"] == "hello alice"
    own_readable = {"id": "m-own", "from": "alice", "to": "bob",
                    "kind": "text", "body": "first record",
                    "meta": {}, "ts": 1700000000}
    assert a.mailbox.put_if_absent(own_readable,
                                   taken=True) is True
    a._mailbox_record_sent(
        {"id": "m-own", "from": "alice", "to": "bob",
         "kind": "text", "body": "second record", "file": None,
         "meta": {"reseals": "m-x"}, "ts": 1700000002})
    got = a.mailbox.get("m-own")
    assert got["body"] == "first record"
    assert got["meta"] == {}


def test_cli_keys_rotate_wiring():
    src = (ROOT / "agentlink" / "cli.py").read_text()
    assert "if cmd == \"keys\":" in src
    assert "a.rotate_keys()" in src or "rotate_keys" in src
    assert "agentlink keys rotate" in src
