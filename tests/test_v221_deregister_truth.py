"""2.2.1 — deregistration truthfulness.

Two defects from the 2.2.0 cleanup drills, both in the removal
contract (client -> account Edge -> PG, and its store ports):

1. THE FALSE REPORT. In 2 of 4 drill deregisters the CLI exited 1
   with `unknown_username` AFTER the server-side deletion had
   already succeeded (PG-verified). Mechanism: the first
   deregister POST committed the cascade, its response was lost
   in an egress-proxy window, the hardened client retried the
   POST, and the retry met a missing user row — which the Edge
   mapped to unknown_username, a verdict about a username that
   was never unknown, only already removed. The reported result
   must ALWAYS match server truth: when the audit log carries
   the completed removal of this identity, a repeat deregister
   reports that outcome (already_removed, with the recorded row
   count); with no removal on record, the identity is genuinely
   unknown and is refused BEFORE any delete attempt.

2. THE STRANDED NOTICE. Six drill notification frames
   (work_update / read_receipt) stranded in the offline queue
   below the agents' fetch cursors after lost acks, and
   deregistration refused until they were deleted via PG by
   hand. Notice-class frames report state persisted in its own
   tables — they carry no unique content — so they are excluded
   from the blocker count and voided by the removal cascade.
   Content frames block exactly as before, and the blocker count
   names content frames only.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentlink.client import RequestFailed
from agentlink.protocol import NOTICE_FRAME_TYPES, queue_payload_type
from agentlink.store import NotFound, RemovalBlocked, Store
from agentlink.transport_v2 import Refusal

from test_v200_coverage import (CoverageBackend, make_agent, run,
                                start, stop)

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT_TS = (ROOT / "supabase/functions/agentlink-account/index.ts"
              ).read_text()


# ----------------------------------------------------------------------
# The notice class itself
# ----------------------------------------------------------------------

def test_notice_class_is_exactly_the_state_reports():
    assert NOTICE_FRAME_TYPES == frozenset(
        {"work_update", "read_receipt"})
    assert queue_payload_type(
        json.dumps({"type": "message", "id": "x"})) == "message"
    assert queue_payload_type({"type": "work_update"}) == "work_update"
    # Undecodable / shapeless payloads classify as "" — callers
    # treat that as CONTENT (fail-closed), never as a notice.
    assert queue_payload_type("not json") == ""
    assert queue_payload_type("") == ""
    assert queue_payload_type(None) == ""


def test_edge_ts_carries_the_same_notice_set_and_verdict():
    assert 'new Set(["work_update", "read_receipt"])' in ACCOUNT_TS
    assert "NOTICE_FRAME_TYPES" in ACCOUNT_TS
    assert "already_removed" in ACCOUNT_TS
    assert 'eq("kind", "user_removed")' in ACCOUNT_TS


# ----------------------------------------------------------------------
# Client -> (mirrored) Edge: the false report, drill timing included
# ----------------------------------------------------------------------

def _no_sleep(monkeypatch):
    import agentlink.transport_v2 as tv2
    monkeypatch.setattr(tv2, "_sleep", lambda _s: None)


def test_lost_response_retry_reports_the_truth(tmp_path, monkeypatch):
    """THE drill reproduction: the first deregister POST commits
    server-side, its response is destroyed by a proxy-shaped
    connection failure, and the hardened client's retry must
    surface the SUCCESS the server already recorded — not a
    false unknown_username failure."""
    _no_sleep(monkeypatch)
    backend = CoverageBackend()

    async def scenario():
        carol, transport, dc = make_agent(tmp_path, backend, "carol")
        await start(carol)
        try:
            real_opener = backend.opener
            dropped = {"hit": False}

            def sabotage(method, url, headers, body):
                result = real_opener(method, url, headers, body)
                if not dropped["hit"] and "agentlink-account" in url \
                        and url.rstrip("/").endswith("/deregister"):
                    dropped["hit"] = True
                    raise ConnectionError(
                        "Tunnel connection failed: 407 Proxy"
                        " Authentication Required")
                return result

            transport._opener = sabotage
            out = await carol.deregister()
            assert dropped["hit"], \
                "the sabotage never fired — the drill was not run"
            # The retry's verdict is the recorded truth.
            assert out.get("already_removed") is True
            assert out["total"] >= 1
            assert backend.one("users", username="carol") is None
            removed_rows = [r for r in backend.rows("audit_log")
                            if r["kind"] == "user_removed"
                            and r["target"] == "carol"]
            assert len(removed_rows) == 1, \
                "the retry must not re-run the cascade or its audit"
        finally:
            await stop(carol, dc)

    run(scenario)


def test_repeat_deregister_reports_already_removed(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        carol, transport, dc = make_agent(tmp_path, backend, "carol")
        await start(carol)
        try:
            # Both executions ride the SAME authenticated session —
            # exactly what a re-run (or a retry that outlived its
            # first response) presents to the Edge. (The agent-level
            # deregister() closes the session after its own call,
            # so the repeat is driven at the transport surface the
            # client's _request dispatches to verbatim.)
            out = transport.account_edge("deregister", {})
            assert out["removed"]["users"] == 1
            again = transport.account_edge("deregister", {})
            assert again.get("already_removed") is True
            assert again["total"] == out["total"]
            assert again["removed"] == {}
        finally:
            await stop(carol, dc)

    run(scenario)


def test_genuinely_unknown_still_reports_unknown(tmp_path):
    """No user row AND no removal on record: unknown_username,
    refused before any delete attempt (nothing is deleted)."""
    backend = CoverageBackend()

    async def scenario():
        dave, transport, dd = make_agent(tmp_path, backend, "dave")
        await start(dave)
        try:
            # The row vanishes WITHOUT the platform's removal
            # cascade (no audit record) — the platform has never
            # removed this identity.
            backend.tables["users"] = [
                u for u in backend.rows("users")
                if u["username"] != "dave"]
            with pytest.raises(Refusal) as ei:
                transport.account_edge("deregister", {})
            assert ei.value.reason == "unknown_username"
            assert not [r for r in backend.rows("audit_log")
                        if r["kind"] == "user_removed"]
        finally:
            await stop(dave, dd)

    run(scenario)


# ----------------------------------------------------------------------
# Client -> (mirrored) Edge: stranded notices never block
# ----------------------------------------------------------------------

def test_stranded_notices_do_not_block_deregistration(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        carol, _t, dc = make_agent(tmp_path, backend, "carol")
        await start(carol)
        try:
            backend.enqueue("carol", {
                "type": "work_update",
                "work": {"id": "w1", "status": "completed"}})
            backend.enqueue("carol", {
                "type": "read_receipt", "id": "m1",
                "from": "carol", "reader": "bob", "read_at": 1})
            out = await carol.deregister()
            assert out["removed"]["users"] == 1
            # The cascade VOIDED the stranded notices with the
            # rest of the queue — they are gone, not carried.
            assert out["removed"]["queue"] == 2
            assert backend.rows("queue") == []
        finally:
            await stop(carol, dc)

    run(scenario)


def test_content_frame_still_blocks_and_notices_dont_pad_count(
        tmp_path):
    backend = CoverageBackend()

    async def scenario():
        carol, _t, dc = make_agent(tmp_path, backend, "carol")
        await start(carol)
        try:
            backend.enqueue("carol", {"type": "message",
                                      "id": "held-1"})
            backend.enqueue("carol", {
                "type": "work_update",
                "work": {"id": "w1", "status": "completed"}})
            backend.enqueue("carol", {
                "type": "read_receipt", "id": "m1",
                "from": "carol", "reader": "bob", "read_at": 1})
            with pytest.raises(RequestFailed) as ei:
                await carol.deregister()
            assert ei.value.reason == "deregister_blocked"
            assert "1 undelivered frame(s)" in ei.value.detail
            assert backend.one("users", username="carol") is not None
            # Drain ONLY the content frame (as a delivery would);
            # the notices never needed anyone's hands on them.
            backend.tables["queue"] = [
                q for q in backend.rows("queue")
                if json.loads(q["payload"]).get("type") != "message"]
            out = await carol.deregister()
            assert out["removed"]["users"] == 1
            assert out["removed"]["queue"] == 2
        finally:
            await stop(carol, dc)

    run(scenario)


# ----------------------------------------------------------------------
# Store port (SQLite): the same contract
# ----------------------------------------------------------------------

def test_store_notices_never_block_and_repeat_is_truthful(tmp_path):
    s = Store(str(tmp_path / "r.db"))
    s.claim("carol", "C")
    s.enqueue("carol", {"type": "work_update",
                        "work": {"id": "w1", "status": "completed"}})
    s.enqueue("carol", {"type": "read_receipt", "id": "m1"})
    assert s.removal_blockers("carol") == []
    out = s.remove_user("carol")
    assert out["removed"]["users"] == 1
    # The repeat reports the recorded outcome, not NotFound.
    again = s.remove_user("carol")
    assert again.get("already_removed") is True
    assert again["total"] == out["total"]
    # An identity the platform has never removed is still
    # genuinely unknown.
    with pytest.raises(NotFound):
        s.remove_user("ghost")


def test_store_content_frame_still_blocks(tmp_path):
    s = Store(str(tmp_path / "r.db"))
    s.claim("dave", "D")
    s.enqueue("dave", {"type": "message", "body": "waiting"})
    s.enqueue("dave", {"type": "read_receipt", "id": "m1"})
    blockers = s.removal_blockers("dave")
    assert blockers == ["1 undelivered frame(s) in the offline queue"]
    with pytest.raises(RemovalBlocked):
        s.remove_user("dave")
    assert s.exists("dave")
