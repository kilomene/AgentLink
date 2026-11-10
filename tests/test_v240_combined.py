"""Combined-release tests (2.4.0): epoch trial fallback,
Disappearing Mode v2, the B4 partial-wedge detector, the
log-ingestion/egress discipline pins, and the Supabase<->
Firebase compute split.

Pinned rules (owner directives 2026-11-10 + DESIGN-BRIEF):
* A legacy room envelope with NO epoch stamp, sealed under a
  PRIOR epoch, opens after rotation — stamped dispatch alone
  (2.3.1) left the Nova family's unstamped epoch-1 rows sealed
  even with the epoch archived. An epoch never held still
  fails closed.
* Disappearing v2: 24h window, per-side clocks (sender at
  send+24h; receiver at READ+24h; an UNREAD item has NO
  deadline and never expires), the fail-closed oversight
  deposit (no wrap / no depositor / unconfirmed deposit ->
  the send is blocked and the deposit parked, never a silent
  unarchived send), erase waits for archive confirmation,
  standard messages untouched, files refuse disappearing.
* B4: a PROVABLY truncated body (Content-Length > partial
  bytes) is detected at read time and treated as a PROXY
  failure, never returned as the payload.
* Logging/egress discipline: no success logging in any Edge
  function or Firebase function source; no select=* on the
  client/transport hot paths; the dashboard audit read is
  field-minimal with seq-delta refresh; the v212 pruning
  migration touches delivery machinery ONLY.
* Diversification: the archive service + live-layer
  housekeeping live in firebase/functions (capped), the
  archive does NOT live on Supabase Edge, and the portable
  core has a Python twin with identical semantics.
"""

from __future__ import annotations

import asyncio
import http.client
import io
import json
import re
from pathlib import Path

import pytest

from agentlink import archive
from agentlink import doorbell as doorbell_mod
from agentlink import transport_v2 as transport_mod
from agentlink.client import Agent, RequestFailed
from agentlink.crypto import encrypt_with_key, new_group_key
from agentlink.mailbox import (DISAPPEARING_WINDOW_S, Mailbox,
                               disappearing_deadline)
from agentlink.transport_v2 import (ServerlessTransport,
                                    TransportError)

ROOT = Path(__file__).resolve().parent.parent
GID = "g-trial-test"
OVERSIGHT = {"v": 1, "alg": "x25519-chacha20poly1305",
             "eph_pub": "OEPH", "nonce": "ONONCE", "ct": "OCT"}
ENVELOPE = {"v": 1, "alg": "x25519-chacha20poly1305",
            "eph_pub": "EPH", "nonce": "NONCE", "ct": "CIPHERTEXT"}
NOW = 1_800_000_000


def _agent(tmp_path, name="alice"):
    return Agent(username=name, state_dir=str(tmp_path / name),
                 mode="manual")


def _rec(key1, key2):
    return {"epoch": 2, "key": key2, "epochs": {1: key1, 2: key2}}


# ============ epoch trial fallback (unstamped legacy rows) =====

def test_unstamped_prior_epoch_envelope_opens():
    key1, key2 = new_group_key(), new_group_key()
    payload = json.dumps({"body": "epoch one words",
                          "kind": "text"}).encode()
    legacy = encrypt_with_key(key1, payload)  # NO epoch stamp
    assert "epoch" not in legacy
    opened = Agent._open_room_envelope(_rec(key1, key2), legacy)
    assert opened is not None
    assert opened["body"] == "epoch one words"


def test_unstamped_current_epoch_envelope_opens():
    key1, key2 = new_group_key(), new_group_key()
    payload = json.dumps({"body": "now", "kind": "text"}).encode()
    opened = Agent._open_room_envelope(
        _rec(key1, key2), encrypt_with_key(key2, payload))
    assert opened["body"] == "now"


def test_never_held_epoch_stays_sealed():
    key1, key2, key7 = (new_group_key(), new_group_key(),
                        new_group_key())
    payload = json.dumps({"body": "x", "kind": "text"}).encode()
    env = {"epoch": 7, **encrypt_with_key(key7, payload)}
    assert Agent._open_room_envelope(_rec(key1, key2), env) is None
    # And an unstamped envelope under a never-held key too.
    assert Agent._open_room_envelope(
        _rec(key1, key2), encrypt_with_key(key7, payload)) is None


def test_history_row_unstamped_epoch1_opens_after_rotation(tmp_path):
    agent = _agent(tmp_path)
    key1 = new_group_key()
    agent._store_group_key(GID, 1, key1)
    payload = json.dumps({"body": "family words",
                          "kind": "text"}).encode()
    legacy = encrypt_with_key(key1, payload)
    agent._store_group_key(GID, 2, new_group_key())  # rotation
    row = {"kind": "group_message", "ref_id": "m-legacy-1",
           "group_id": GID, "from": "bob", "to": GID,
           "ts": 1700000000, "content_envelope": legacy}
    msg = agent._history_row_to_msg(row)
    assert not msg.get("sealed")
    assert msg["body"] == "family words"


def test_live_frame_unstamped_epoch1_opens_after_rotation(tmp_path):
    agent = _agent(tmp_path)
    key1 = new_group_key()
    agent._store_group_key(GID, 1, key1)
    payload = json.dumps({"body": "live old",
                          "kind": "text"}).encode()
    legacy = encrypt_with_key(key1, payload)
    agent._store_group_key(GID, 2, new_group_key())

    async def main():
        opened, _via, _rec_out, _to = \
            await agent._open_frame_payload(
                {"group_id": GID, "content": legacy})
        return opened
    assert asyncio.run(main())["body"] == "live old"


# ============ disappearing: mailbox clocks + sweep =============

def _mb(tmp_path):
    return Mailbox(tmp_path / "mb.db", owner="jerry")


def _item(mid, **kw):
    base = {"id": mid, "from": "tom", "to": "jerry",
            "kind": "text", "body": "hi", "ts": NOW - 1000,
            "disappearing": True, "sent_at": NOW - 1000,
            "archive_confirmed": True}
    base.update(kw)
    return base


def test_unread_disappearing_never_expires(tmp_path):
    mb = _mb(tmp_path)
    mb.put_if_absent(_item("m-unread"))
    # 72h later, still unread: NO deadline, sweep keeps it.
    assert disappearing_deadline(mb.get("m-unread"), "jerry") is None
    out = mb.sweep_disappearing(now=NOW + 72 * 3600)
    assert out["erased"] == []
    assert mb.get("m-unread") is not None


def test_receiver_clock_starts_at_read(tmp_path):
    mb = _mb(tmp_path)
    mb.put_if_absent(_item("m-read"))
    mb.mark_taken(["m-read"], now=NOW)
    item = mb.get("m-read")
    assert item["read_at"] == NOW
    assert disappearing_deadline(item, "jerry") == \
        NOW + DISAPPEARING_WINDOW_S
    # Just before the deadline: kept. At it: erased.
    assert mb.sweep_disappearing(
        now=NOW + DISAPPEARING_WINDOW_S - 1)["erased"] == []
    out = mb.sweep_disappearing(now=NOW + DISAPPEARING_WINDOW_S)
    assert out["erased"] == ["m-read"]
    assert mb.get("m-read") is None


def test_read_at_stamps_first_read_only(tmp_path):
    mb = _mb(tmp_path)
    mb.put_if_absent(_item("m-twice"))
    mb.mark_taken(["m-twice"], now=NOW)
    mb.mark_taken(["m-twice"], now=NOW + 5000)
    assert mb.get("m-twice")["read_at"] == NOW


def test_sender_clock_is_send_plus_24h(tmp_path):
    mb = Mailbox(tmp_path / "mb2.db", owner="tom")
    sent = _item("m-sent", **{"from": "tom", "to": "jerry"})
    mb.put_if_absent(sent, taken=True)
    assert disappearing_deadline(sent, "tom") == \
        (NOW - 1000) + DISAPPEARING_WINDOW_S
    out = mb.sweep_disappearing(now=NOW - 1000
                                + DISAPPEARING_WINDOW_S)
    assert out["erased"] == ["m-sent"]


def test_erase_waits_for_archive_confirmation(tmp_path):
    mb = _mb(tmp_path)
    mb.put_if_absent(_item("m-unconf", archive_confirmed=False))
    mb.mark_taken(["m-unconf"], now=NOW)
    out = mb.sweep_disappearing(now=NOW + DISAPPEARING_WINDOW_S + 9)
    assert out["erased"] == []
    assert out["blocked"] == ["m-unconf"]
    assert mb.get("m-unconf") is not None  # archive first, always


def test_standard_message_untouched_by_sweep(tmp_path):
    mb = _mb(tmp_path)
    std = _item("m-std")
    del std["disappearing"]
    mb.put_if_absent(std)
    mb.mark_taken(["m-std"], now=NOW)
    out = mb.sweep_disappearing(now=NOW + 365 * 86400)
    assert out == {"erased": [], "blocked": []}
    assert mb.get("m-std") is not None


# ============ disappearing: transport deposit gate =============

def _bare_transport():
    t = ServerlessTransport.__new__(ServerlessTransport)
    from agentlink.retry import DeadLetterPark, RetryPolicy
    t.username = "alice"
    t.retry_policy = RetryPolicy()
    t.dead_letters = DeadLetterPark()
    t.archive_depositor = None
    t._parks = []
    t._park = lambda kind, item_id, **kw: t._parks.append(
        (kind, item_id, kw))
    return t


def test_gate_blocks_without_oversight():
    t = _bare_transport()
    with pytest.raises(TransportError, match="oversight"):
        t._disappearing_gate(
            mid="m1", conversation_id="dm:alice:bob",
            participants=["alice", "bob"], oversight=None)
    # The refusal is VISIBLE: a park record (attempts=0) is the
    # blocked send's durable trace — blocked and visible, never
    # dropped, and nothing was sent.
    assert len(t._parks) == 1
    assert t._parks[0][0] == "archive_deposit"
    assert t._parks[0][2]["attempts"] == 0


def test_gate_blocks_without_depositor():
    t = _bare_transport()
    with pytest.raises(TransportError, match="depositor"):
        t._disappearing_gate(
            mid="m1", conversation_id="dm:alice:bob",
            participants=["alice", "bob"], oversight=OVERSIGHT)


def test_gate_parks_and_blocks_on_unconfirmed_deposit(monkeypatch):
    monkeypatch.setattr(transport_mod, "_sleep", lambda s: None)
    t = _bare_transport()

    def failing(record):
        raise archive.ArchiveError("drive unreachable")
    t.archive_depositor = failing
    with pytest.raises(TransportError, match="unconfirmed"):
        t._disappearing_gate(
            mid="m1", conversation_id="dm:alice:bob",
            participants=["alice", "bob"], oversight=OVERSIGHT)
    assert len(t._parks) == 1
    kind, item_id, _kw = t._parks[0]
    assert kind == "archive_deposit" and item_id == "m1"


def test_gate_returns_confirmation():
    t = _bare_transport()
    seen = []
    t.archive_depositor = lambda rec: (
        seen.append(rec),
        {"confirmed": True, "entry_id": rec["message_id"]})[1]
    conf = t._disappearing_gate(
        mid="m1", conversation_id="dm:alice:bob",
        participants=["alice", "bob"], oversight=OVERSIGHT, ts=42)
    assert conf["confirmed"] is True
    assert seen[0]["oversight"] == OVERSIGHT
    assert seen[0]["ts"] == 42


def test_client_refuses_disappearing_file_send(tmp_path):
    agent = _agent(tmp_path)

    async def main():
        with pytest.raises(RequestFailed):
            await agent.send_message(
                "bob", "caption", file={"name": "x"},
                disappearing=True)
        with pytest.raises(RequestFailed):
            await agent.group_send(
                GID, "caption", file={"name": "x"},
                disappearing=True)
    asyncio.run(main())


def test_client_refuses_disappearing_without_oversight_key(tmp_path):
    agent = _agent(tmp_path)
    agent.oversight_pubkey = None
    agent._oversight_configured = False

    async def main():
        # Key resolution for bob is stubbed: the refusal must
        # come from the oversight gate, before any send.
        async def fake_pub(_u):
            from agentlink.crypto import Identity
            return Identity.ephemeral().public_key_b64
        agent.pubkey_of = fake_pub
        with pytest.raises(RequestFailed,
                           match="disappearing|oversight"):
            await agent.send_message("bob", "hi", disappearing=True)
    asyncio.run(main())


# ============ archive core (portable, python twin) =============

def _record(**kw):
    base = {"message_id": "m-a1",
            "conversation_id": "dm:alice:bob",
            "participants": ["alice", "bob"],
            "sender": "alice", "kind": "dm", "ts": NOW,
            "oversight": dict(OVERSIGHT),
            "oversight_kind": "content"}
    base.update(kw)
    return base


def test_archive_files_under_every_participant(tmp_path):
    backend = archive.LocalArchiveBackend(tmp_path / "arch")
    conf = backend.deposit(_record())
    assert conf["confirmed"] is True
    assert conf["folders"] == ["alice", "bob"]
    for who in ("alice", "bob"):
        entries = backend.read_conversation(who, "dm:alice:bob")
        assert len(entries) == 1
        assert entries[0]["oversight"]["ct"] == "OCT"
        assert archive.verify_chain(entries)


def test_archive_chain_links_and_tamper_evidence(tmp_path):
    backend = archive.LocalArchiveBackend(tmp_path / "arch")
    backend.deposit(_record())
    backend.deposit(_record(message_id="m-a2", ts=NOW + 5))
    entries = backend.read_conversation("alice", "dm:alice:bob")
    assert entries[1]["prev"] == entries[0]["hash"]
    entries[0]["ts"] = 1  # tamper
    assert not archive.verify_chain(entries)


def test_archive_refuses_plaintext_and_unsealed(tmp_path):
    backend = archive.LocalArchiveBackend(tmp_path / "arch")
    with pytest.raises(archive.ArchiveError):
        backend.deposit(_record(body="plaintext!"))
    with pytest.raises(archive.ArchiveError):
        backend.deposit(_record(oversight=None))
    with pytest.raises(archive.ArchiveError):
        backend.deposit(_record(oversight={"nonce": "x"}))


def test_archive_group_conversation_ids():
    assert archive.conversation_id_dm("bob", "alice") == \
        "dm:alice:bob"
    assert archive.conversation_id_group("g-1") == "group:g-1"
    assert archive.conversation_id_channel("c-1") == "channel:c-1"


# ============ B4 partial-wedge detector ========================

class _WedgeResp(io.RawIOBase):
    """A response whose chunked stream dies mid-body with a
    Content-Length that proves the truncation."""

    def __init__(self, partial: bytes, declared: int):
        self._partial = partial
        self.headers = {"Content-Length": str(declared)}

    def read(self, *a):
        raise http.client.IncompleteRead(self._partial)


def test_transport_read_body_detects_partial_wedge():
    resp = _WedgeResp(b'[{"seq": 1', declared=4000)
    with pytest.raises(transport_mod.PartialWedgeError):
        transport_mod._read_body(resp)


def test_transport_read_body_tolerates_unprovable_clip():
    # No Content-Length: the terminator was lost but the payload
    # may be whole — downstream parsing judges, as before.
    class _ClipResp(io.RawIOBase):
        headers = {}

        def read(self, *a):
            raise http.client.IncompleteRead(b"[1,2,3]")
    assert transport_mod._read_body(_ClipResp()) == b"[1,2,3]"


def test_wedge_is_a_proxy_class_failure():
    assert transport_mod._proxy_failure_text(
        "partial wedge: body truncated at 10/4000 bytes "
        "mid-response (tunnel connection failed)")


def test_doorbell_read_body_detects_partial_wedge():
    resp = _WedgeResp(b'{"frame":', declared=900)
    with pytest.raises(doorbell_mod.DoorbellError,
                       match="partial wedge"):
        doorbell_mod._read_body(resp)


# ============ logging + egress discipline pins =================

def _sources(base: Path, suffix: str):
    return [p for p in base.rglob(f"*{suffix}") if p.is_file()]


def test_no_success_logging_in_edge_or_firebase_functions():
    """Error-only logging (the log-ingestion discipline): no
    console.log/info/debug/warn in ANY Edge function source or
    Firebase function source. console.error (operator-actionable
    errors) is the only permitted channel."""
    offenders = []
    for p in _sources(ROOT / "supabase" / "functions", ".ts"):
        text = p.read_text()
        if re.search(r"console\.(log|info|debug|warn)\s*\(", text):
            offenders.append(str(p.relative_to(ROOT)))
    for p in _sources(ROOT / "firebase" / "functions", ".js"):
        if "node_modules" in str(p) or "/test/" in str(p):
            continue
        text = p.read_text()
        if re.search(r"console\.(log|info|debug|warn)\s*\(", text):
            offenders.append(str(p.relative_to(ROOT)))
    assert offenders == []


def test_no_select_star_on_hot_paths():
    for rel in ("agentlink/transport_v2.py", "agentlink/doorbell.py",
                "agentlink/client.py"):
        assert "select=*" not in (ROOT / rel).read_text(), rel
    data_js = (ROOT / "dashboard-v2" / "js" / "data.js").read_text()
    # The audit read (the egress driver) is field-minimal and
    # delta-refreshed by seq.
    assert "AUDIT_SELECT" in data_js
    assert 'pgAll("al_audit_log","select=*' not in data_js \
        and 'pgAll("al_audit_log", "select=*' not in data_js
    assert "seq=gt." in data_js


def test_pruning_migration_touches_machinery_only():
    sql = (ROOT / "supabase"
           / "migration-v212-pruning.sql").read_text()
    assert "al_doorbell_outbox" in sql and "tapped" in sql
    deletes = re.findall(r"delete\s+from\s+public\.(\w+)", sql)
    assert deletes, "expected at least one pruning DELETE"
    for table in deletes:
        assert table not in ("al_audit_log", "al_queue",
                             "al_group_messages", "al_messages"), \
            f"pruning must never touch content table {table}"


def test_dashboard_reads_disappearing_from_archive():
    data_js = (ROOT / "dashboard-v2" / "js" / "data.js").read_text()
    assert "archiveConversation" in data_js
    assert "archiveRead" in data_js
    chat_js = (ROOT / "dashboard-v2" / "js"
               / "views" / "chat.js").read_text()
    assert "archiveConversation" in chat_js


# ============ compute diversification shape ====================

def test_firebase_functions_exist_capped_and_complete():
    idx = (ROOT / "firebase" / "functions" / "index.js").read_text()
    for name in ("archiveDeposit", "archiveRead",
                 "transitHousekeeping", "presenceHousekeeping",
                 "directoryMirror", "signalRelay"):
        assert f"exports.{name}" in idx, name
    assert "maxInstances" in idx  # hard safety caps from day one
    core = (ROOT / "firebase" / "functions"
            / "archiveCore.js").read_text()
    # Portability: the core REQUIRES no platform SDK (prose in
    # its header names what it avoids — imports are the law).
    assert 'require("firebase-admin")' not in core
    assert 'require("googleapis")' not in core
    assert 'require("firebase-functions")' not in core
    fj = json.loads((ROOT / "firebase" / "firebase.json").read_text())
    assert fj["functions"] and fj["emulators"]["functions"]


def test_archive_is_not_a_supabase_edge_function():
    # Workstream (d): the archive service's home is Firebase.
    # Supabase Edge keeps login/registry/support/work/dashboard.
    assert not (ROOT / "supabase" / "functions"
                / "agentlink-archive").exists()


def test_windows_agree():
    assert DISAPPEARING_WINDOW_S == 24 * 3600
    assert transport_mod.DISAPPEARING_WINDOW_S == \
        DISAPPEARING_WINDOW_S
    assert transport_mod.DEFAULT_DISAPPEARING_TTL_S == 24 * 3600
