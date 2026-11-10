"""Universal archive deposit tests (2.4.1, owner ruling
2026-11-10): EVERY chat deposits into the owner Drive archive —
standard sends too, not just disappearing ones.

Pinned rules:
* A standard DM and a standard group send deposit their
  oversight-sealed envelope at send time, through the same
  archive path as disappearing, filed under EVERY participant,
  hash-chained, carrying mode="standard" and the al_audit_log
  seq cross-reference (audit_seq).
* ASYMMETRY: a standard deposit failure NEVER fails the send —
  the record enters the durable deposit-retry queue and lands
  after the service recovers; at policy exhaustion it parks in
  the dead-letter park WITH the full record, never dropped.
* The disappearing gate is UNCHANGED: no deposit confirmation,
  no send (fail-closed), and its records carry
  mode="disappearing".
* Backfill: idempotent (second run deposits 0), dedupes by
  message id, chains per conversation, and a chain mixing
  standard + disappearing records verifies end-to-end.
* The record whitelist is mirrored in the JS twin
  (firebase/functions/archiveCore.js): mode + audit_seq pass
  through both, so chain hashes agree across platforms.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from agentlink import archive
from agentlink import transport_v2 as transport_mod
from agentlink.retry import DeadLetterPark, RetryPolicy
from agentlink.transport_v2 import ServerlessTransport

ROOT = Path(__file__).resolve().parent.parent
OVERSIGHT = {"v": 1, "alg": "x25519-chacha20poly1305",
             "eph_pub": "OEPH", "nonce": "ONONCE", "ct": "OCT"}
ENVELOPE = {"v": 1, "alg": "x25519-chacha20poly1305",
            "eph_pub": "EPH", "nonce": "NONCE", "ct": "CIPHERTEXT"}
NOW = 1_800_000_000


def _bare_transport(queue=None):
    t = ServerlessTransport.__new__(ServerlessTransport)
    t.username = "alice"
    t.retry_policy = RetryPolicy()
    t.dead_letters = DeadLetterPark()
    t.archive_depositor = None
    t.deposit_retry_queue = queue
    t._parks = []
    t._park = lambda kind, item_id, **kw: t._parks.append(
        (kind, item_id, kw))
    t._audit_seq_for = lambda mid: None
    return t


def _std(t, mid, **over):
    kw = dict(mid=mid, conversation_id="dm:alice:bob",
              participants=["alice", "bob"], oversight=OVERSIGHT,
              ts=NOW)
    kw.update(over)
    return t._standard_deposit(**kw)


# ============ record whitelist: mode + audit_seq ===============

def test_validate_record_stamps_mode_and_seq():
    out = archive.validate_record({
        "message_id": "m1", "conversation_id": "dm:alice:bob",
        "participants": ["alice", "bob"], "sender": "alice",
        "kind": "dm", "ts": NOW, "oversight": OVERSIGHT,
        "oversight_kind": "content", "mode": "standard",
        "audit_seq": 4242})
    assert out["mode"] == "standard"
    assert out["audit_seq"] == 4242
    # Legacy records (no mode) normalize by kind.
    legacy = archive.validate_record({
        "message_id": "m0", "conversation_id": "dm:alice:bob",
        "participants": ["alice"], "sender": "alice",
        "kind": "dm", "ts": NOW, "oversight": OVERSIGHT})
    assert legacy["mode"] == "standard"
    assert "audit_seq" not in legacy
    dis = archive.validate_record({
        "message_id": "m9", "conversation_id": "dm:alice:bob",
        "participants": ["alice"], "sender": "alice",
        "kind": "disappearing", "ts": NOW, "oversight": OVERSIGHT})
    assert dis["mode"] == "disappearing"


def test_validate_record_rejects_non_integer_seq():
    with pytest.raises(archive.ArchiveError):
        archive.validate_record({
            "message_id": "m1", "conversation_id": "dm:alice:bob",
            "participants": ["alice"], "sender": "alice",
            "kind": "dm", "ts": NOW, "oversight": OVERSIGHT,
            "mode": "standard", "audit_seq": "soon"})


def test_js_twin_validates_mode_and_seq_identically():
    src = (ROOT / "firebase" / "functions" /
           "archiveCore.js").read_text()
    assert '"standard"' in src and '"disappearing"' in src
    assert "audit_seq" in src
    # The JS twin refuses a non-integer audit_seq, like Python.
    assert re.search(r"audit_seq is not an integer", src)


# ============ universal deposit: standard sends ================

def test_standard_deposit_confirmed_with_cross_reference():
    t = _bare_transport()
    seen = []
    t.archive_depositor = lambda rec: (
        seen.append(rec),
        {"confirmed": True, "entry_id": rec["message_id"],
         "hashes": {"alice": "h1", "bob": "h1"}})[1]
    out = _std(t, "m-std-1", audit_row={"seq": 777})
    assert out["confirmed"] is True
    rec = seen[0]
    assert rec["mode"] == "standard"
    assert rec["audit_seq"] == 777
    assert rec["message_id"] == "m-std-1"
    assert rec["participants"] == ["alice", "bob"]


def test_standard_deposit_seq_fetched_when_insert_reply_blank():
    t = _bare_transport()
    seen = []
    t.archive_depositor = lambda rec: (
        seen.append(rec), {"confirmed": True})[1]
    t._audit_seq_for = lambda mid: 555
    out = _std(t, "m-std-2", audit_row=None)
    assert out["confirmed"] is True
    assert seen[0]["audit_seq"] == 555


def test_standard_send_dm_deposits_under_both(tmp_path):
    """End-to-end at the transport: send_dm (standard) writes
    the audit row, then deposits — the archive holds the record
    in BOTH participants' folders, chained, mode=standard."""
    backend = archive.LocalArchiveBackend(tmp_path / "arch")
    t = _bare_transport()
    t.archive_depositor = backend.deposit
    calls = []
    t._enqueue = lambda to, frame: calls.append(("q", to))
    t._audit = lambda *a, **kw: {"seq": 9001}
    t._push_transit = lambda to, frame: True
    t._tap = lambda conv, mid: None
    res = t.send_dm("bob", ENVELOPE, oversight=OVERSIGHT)
    assert res["queued"] is True
    assert res["deposit"]["confirmed"] is True
    conv = "dm:alice:bob"
    for who in ("alice", "bob"):
        entries = backend.read_conversation(who, conv)
        assert len(entries) == 1
        assert entries[0]["message_id"] == res["id"]
        assert entries[0]["mode"] == "standard"
        assert entries[0]["audit_seq"] == 9001
        assert archive.verify_chain(entries)


def test_standard_group_send_deposits_under_every_member(tmp_path):
    backend = archive.LocalArchiveBackend(tmp_path / "arch")
    t = _bare_transport()
    t.archive_depositor = backend.deposit
    t._enqueue = lambda to, frame: None
    t._audit = lambda *a, **kw: {"seq": 31}
    t._push_transit = lambda to, frame: True
    t._tap = lambda conv, mid: None
    res = t.send_group_frame("g-241", ENVELOPE,
                             members=["alice", "bob", "carol"],
                             oversight=OVERSIGHT)
    assert res["deposit"]["confirmed"] is True
    conv = "group:g-241"
    for who in ("alice", "bob", "carol"):
        entries = backend.read_conversation(who, conv)
        assert len(entries) == 1
        assert entries[0]["oversight_kind"] == "content_key"
        assert entries[0]["mode"] == "standard"
        assert entries[0]["audit_seq"] == 31
        assert archive.verify_chain(entries)


# ============ asymmetry: failure never fails the send ==========

def test_deposit_failure_queues_and_send_succeeds(tmp_path):
    queue = archive.DepositRetryQueue(tmp_path / "q.json")
    t = _bare_transport(queue=queue)

    def failing(rec):
        raise archive.ArchiveError("archive service down")
    t.archive_depositor = failing
    t._enqueue = lambda to, frame: None
    t._audit = lambda *a, **kw: {"seq": 5}
    t._push_transit = lambda to, frame: True
    t._tap = lambda conv, mid: None
    res = t.send_dm("bob", ENVELOPE, oversight=OVERSIGHT)
    assert res["queued"] is True           # the send succeeded
    assert res["deposit"]["confirmed"] is False
    assert res["deposit"]["queued"] is True
    assert len(queue) == 1
    entry = queue.records()[0]
    assert entry["record"]["message_id"] == res["id"]
    assert entry["record"]["audit_seq"] == 5
    assert entry["attempts"] == 1
    # Durable: a fresh queue object over the same file sees it.
    assert len(archive.DepositRetryQueue(tmp_path / "q.json")) == 1


def test_queued_deposit_lands_after_recovery(tmp_path):
    backend = archive.LocalArchiveBackend(tmp_path / "arch")
    queue = archive.DepositRetryQueue(tmp_path / "q.json")
    t = _bare_transport(queue=queue)
    state = {"down": True}

    def flaky(rec):
        if state["down"]:
            raise archive.ArchiveError("down")
        return backend.deposit(rec)
    t.archive_depositor = flaky
    out = _std(t, "m-recover")
    assert out["queued"] is True and len(queue) == 1
    state["down"] = False
    drained = t.drain_deposit_queue(now=time.time() + 10_000)
    assert drained == {"attempted": 1, "deposited": 1, "parked": 0}
    assert len(queue) == 0
    entries = backend.read_conversation("bob", "dm:alice:bob")
    assert [e["message_id"] for e in entries] == ["m-recover"]


def test_drain_respects_backoff_and_parks_at_exhaustion(tmp_path):
    queue = archive.DepositRetryQueue(tmp_path / "q.json")
    t = _bare_transport(queue=queue)

    def failing(rec):
        raise archive.ArchiveError("still down")
    t.archive_depositor = failing
    _std(t, "m-doomed")
    future = queue.records()[0]["next_attempt_at"]
    # Not yet due: the drain is a no-op (no polling burn).
    assert t.drain_deposit_queue(now=future - 1)["attempted"] == 0
    # Drive it to exhaustion: each due drain adds one attempt;
    # at the policy cap the record PARKS with the full record
    # in detail — visible, never dropped.
    for i in range(10):
        t.drain_deposit_queue(now=future + 10_000 * (i + 1))
        if not len(queue):
            break
    assert len(queue) == 0
    assert len(t._parks) == 1
    kind, item_id, kw = t._parks[0]
    assert kind == "archive_deposit" and item_id == "m-doomed"
    assert kw["detail"]["record"]["message_id"] == "m-doomed"
    assert kw["attempts"] >= t.retry_policy.max_attempts


def test_no_depositor_skips_openly_without_queueing(tmp_path):
    queue = archive.DepositRetryQueue(tmp_path / "q.json")
    t = _bare_transport(queue=queue)
    t.archive_depositor = None
    out = _std(t, "m-nodep")
    assert out == {"confirmed": False, "skipped": "no_depositor"}
    assert len(queue) == 0 and t._parks == []


def test_unsealed_standard_deposit_parks_immediately(tmp_path):
    queue = archive.DepositRetryQueue(tmp_path / "q.json")
    t = _bare_transport(queue=queue)
    t.archive_depositor = lambda rec: {"confirmed": True}
    out = _std(t, "m-unsealed", oversight=None)
    assert out["parked"] is True
    assert len(queue) == 0
    assert t._parks and t._parks[0][0] == "archive_deposit"


def test_queue_dedupe_and_durability(tmp_path):
    q = archive.DepositRetryQueue(tmp_path / "q.json")
    rec = {"message_id": "m1", "conversation_id": "dm:a:b"}
    assert q.enqueue(rec, last_error="x", next_attempt_at=1.0)
    assert not q.enqueue(rec, last_error="y", next_attempt_at=2.0)
    assert len(q) == 1
    q2 = archive.DepositRetryQueue(tmp_path / "q.json")
    assert "m1" in q2
    assert q2.remove("m1") and len(q2) == 0


# ============ disappearing gate unchanged ======================

def test_disappearing_gate_still_fail_closed(monkeypatch):
    monkeypatch.setattr(transport_mod, "_sleep", lambda s: None)
    t = _bare_transport()
    t.archive_depositor = None
    with pytest.raises(transport_mod.TransportError,
                       match="depositor"):
        t._disappearing_gate(
            mid="m-vanish", conversation_id="dm:alice:bob",
            participants=["alice", "bob"], oversight=OVERSIGHT)
    assert t._parks and t._parks[0][0] == "archive_deposit"


def test_disappearing_record_carries_mode():
    t = _bare_transport()
    seen = []
    t.archive_depositor = lambda rec: (
        seen.append(rec), {"confirmed": True})[1]
    conf = t._disappearing_gate(
        mid="m-vanish", conversation_id="dm:alice:bob",
        participants=["alice", "bob"], oversight=OVERSIGHT, ts=42)
    assert conf["confirmed"] is True
    assert seen[0]["mode"] == "disappearing"
    assert seen[0]["kind"] == "disappearing"


# ============ backfill =========================================

def _row(seq, kind, actor, target, gid, ref, wrap=OVERSIGHT):
    return {"seq": seq, "ts": NOW + seq, "kind": kind,
            "actor": actor, "target": target, "group_id": gid,
            "ref_id": ref,
            "oversight": json.dumps(wrap) if wrap else "",
            "oversight_kind": "content",
            "content_envelope": json.dumps(ENVELOPE)}


def _seed_rows():
    return [
        _row(1, "message", "alice", "bob", "", "m-b1"),
        _row(2, "message", "bob", "alice", "", "m-b2"),
        _row(3, "group_message", "alice", "", "g-1", "m-b3"),
        _row(4, "group_message", "carol", "", "g-1", "m-b4"),
        _row(5, "message", "alice", "bob", "", "m-b5",
             wrap=None),
    ]


def test_backfill_deposits_history_and_is_idempotent(tmp_path):
    backend = archive.LocalArchiveBackend(tmp_path / "arch")
    rows = _seed_rows()
    members = {"g-1": ["alice", "bob", "carol"]}
    rep = archive.backfill_history(rows, backend,
                                   group_members=members)
    assert rep["deposited"] == 4
    assert rep["skipped_unsealed"] == 1
    dm = rep["per_conversation"]["dm:alice:bob"]
    assert dm["deposited"] == 2 and dm["archive_rows"] == 3
    grp = rep["per_conversation"]["group:g-1"]
    assert grp["deposited"] == 2 and grp["archive_rows"] == 2
    # Filed under every participant; chains verify.
    for who in ("alice", "bob"):
        entries = backend.read_conversation(who, "dm:alice:bob")
        assert len(entries) == 2 and archive.verify_chain(entries)
        assert {e["audit_seq"] for e in entries} == {1, 2}
        assert all(e["mode"] == "standard" for e in entries)
    for who in ("alice", "bob", "carol"):
        entries = backend.read_conversation(who, "group:g-1")
        assert len(entries) == 2 and archive.verify_chain(entries)
    # Second run: dedupe by message id deposits NOTHING new.
    rep2 = archive.backfill_history(rows, backend,
                                    group_members=members)
    assert rep2["deposited"] == 0
    assert rep2["skipped_existing"] == 4


def test_backfill_skips_ids_already_deposited_live(tmp_path):
    backend = archive.LocalArchiveBackend(tmp_path / "arch")
    backend.deposit({
        "message_id": "m-b1", "conversation_id": "dm:alice:bob",
        "participants": ["alice", "bob"], "sender": "alice",
        "kind": "dm", "ts": NOW, "oversight": OVERSIGHT,
        "oversight_kind": "content", "mode": "standard",
        "audit_seq": 1})
    rep = archive.backfill_history(_seed_rows(), backend)
    assert rep["skipped_existing"] == 1
    assert rep["deposited"] == 3


def test_mixed_chain_integrity(tmp_path):
    """One conversation chain holding a disappearing record
    (live send) + standard records (backfill + live standard
    send) verifies end-to-end — the 2.4.1 mixed-history pin."""
    backend = archive.LocalArchiveBackend(tmp_path / "arch")
    backend.deposit({  # disappearing, deposited live at send
        "message_id": "m-vanish", "conversation_id": "dm:alice:bob",
        "participants": ["alice", "bob"], "sender": "alice",
        "kind": "disappearing", "ts": NOW, "oversight": OVERSIGHT,
        "oversight_kind": "content", "mode": "disappearing"})
    archive.backfill_history(_seed_rows()[:2], backend)
    backend.deposit({  # standard, deposited live at send
        "message_id": "m-live-std", "conversation_id": "dm:alice:bob",
        "participants": ["alice", "bob"], "sender": "bob",
        "kind": "dm", "ts": NOW + 99, "oversight": OVERSIGHT,
        "oversight_kind": "content", "mode": "standard",
        "audit_seq": 12})
    entries = backend.read_conversation("alice", "dm:alice:bob")
    assert [e["message_id"] for e in entries] == [
        "m-vanish", "m-b1", "m-b2", "m-live-std"]
    assert [e["mode"] for e in entries] == [
        "disappearing", "standard", "standard", "standard"]
    assert archive.verify_chain(entries)
    # Tamper with any link and the mixed chain breaks.
    entries[1]["ts"] = 1
    assert not archive.verify_chain(entries)


def test_row_to_record_group_participants_default():
    row = _row(7, "group_message", "alice", "", "g-9", "m-g9")
    rec = archive.row_to_record(
        row, participants=["alice", "dave"])
    assert rec["conversation_id"] == "group:g-9"
    assert rec["participants"] == ["alice", "dave"]
    assert rec["kind"] == "group" and rec["mode"] == "standard"
    assert rec["audit_seq"] == 7
    assert archive.row_to_record(_row(8, "message", "a", "b", "",
                                      "m-x", wrap=None)) is None
