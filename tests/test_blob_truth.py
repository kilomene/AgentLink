"""Blob-layer truth (v1.3.8): a finished blob's object and its
meta must never SILENTLY diverge.

Proven production mechanism (2026-11-03 forensics + relay logs):
the server health battery's routine cleanup deletes its test
blob through Relay._on_blob_delete; through the lossy egress the
R2 DELETE executed while its response died in transit,
_request_raw exhausted retries and raised, the handler aborted
as 'blob_store_failed' BEFORE the meta delete, and nothing ever
reconciled — the production store accumulated 100+ orphaned
metas, all battery (dial-*) owned, their objects verifiably
gone, with no trace anywhere. The library's real deliverables
were verified byte-exact in the same pass: the divergence was
confined to the delete path's lost-response window.

The fix, pinned here:
  * blobstore delete is decided by PRESENCE, not by a response
    that may not have arrived (404 = already-deleted success;
    failure + absent = landed; failure + present = real error);
  * _on_blob_delete verifies the pair after deleting (read-back)
    and shouts (audit + fleet alert) if the meta survived;
  * a reconciliation sweep reaps orphaned ephemeral (dial-*)
    metas and alerts — never auto-deletes — for real owners.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import types
import urllib.error
from pathlib import Path

import pytest

from agentlink.blobstore import BlobNotFound, LocalBlobStore, \
    R2BlobStore
from agentlink.relay import Relay

HOST = "127.0.0.1"


# ---------------------------------------------------------------------
# Blob store level: presence + presence-decided delete
# ---------------------------------------------------------------------

def _r2():
    return R2BlobStore("bucket", "ak", "sk", account_id="acct")


def test_r2_exists_presence_truth():
    bs = _r2()
    bs._signed_request = lambda method, bid, data=None: b""
    assert bs.exists("b-1") is True

    def _404(method, bid, data=None):
        raise BlobNotFound(bid)
    bs._signed_request = _404
    assert bs.exists("b-1") is False

    def _down(method, bid, data=None):
        raise urllib.error.URLError("egress down")
    bs._signed_request = _down
    with pytest.raises(urllib.error.URLError):
        bs.exists("b-1")  # unknown must never read as absent


def test_r2_delete_decided_by_presence():
    bs = _r2()
    state = {"present": True}

    def _transport(method, bid, data=None):
        if method == "HEAD":
            if state["present"]:
                return b""
            raise BlobNotFound(bid)
        if method == "DELETE":
            # The request EXECUTES at R2; the response dies in
            # transit — the production failure shape.
            state["present"] = False
            raise urllib.error.URLError("response lost")
        raise AssertionError(method)
    bs._signed_request = _transport
    bs.delete("b-1")  # landed despite the lost response: no raise
    assert state["present"] is False

    # A delete that genuinely fails (object still present) raises.
    state["present"] = True

    def _failing(method, bid, data=None):
        if method == "HEAD":
            return b""
        raise urllib.error.URLError("refused")
    bs._signed_request = _failing
    with pytest.raises(urllib.error.URLError):
        bs.delete("b-1")

    # 404 on DELETE: the deleted state is already achieved.
    def _gone(method, bid, data=None):
        raise BlobNotFound(bid)
    bs._signed_request = _gone
    bs.delete("b-1")


def test_local_blob_store_exists(tmp_path):
    bs = LocalBlobStore(tmp_path)
    assert bs.exists("b-1") is False
    bs.put("b-1", b"abc")
    assert bs.exists("b-1") is True
    bs.delete("b-1")
    assert bs.exists("b-1") is False
    bs.delete("b-1")  # deleting the absent is a no-op success


# ---------------------------------------------------------------------
# Relay level: the delete handler keeps the pair consistent
# ---------------------------------------------------------------------

@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-blobtruth-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db, dashboard_port=0,
                  dashboard_password="test-pw")
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
    yield {"relay": relay, "store": relay.store, "db": db}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


class _FakeWS:
    def __init__(self):
        self.frames = []

    async def send(self, data):
        self.frames.append(json.loads(data))


class _MemBlobStore:
    """In-memory blob store with a switchable delete failure."""

    def __init__(self):
        self.objects = {}
        self.delete_error = None

    def put(self, blob_id, data):
        self.objects[blob_id] = data

    def get(self, blob_id):
        if blob_id not in self.objects:
            raise BlobNotFound(blob_id)
        return self.objects[blob_id]

    def exists(self, blob_id):
        return blob_id in self.objects

    def delete(self, blob_id):
        if self.delete_error is not None:
            raise self.delete_error
        self.objects.pop(blob_id, None)


def _delete_frame(relay, store, blob_store, blob_id="b-victim"):
    store.claim("owner1", "Owner One")
    store.put_blob_meta(blob_id, owner="owner1", size=3)
    relay.blob_store = blob_store
    ws = _FakeWS()
    peer = types.SimpleNamespace(username="owner1", ephemeral=False)
    asyncio.run(relay._on_blob_delete(
        ws, {"type": "blob_delete", "blob_id": blob_id,
             "req_id": "rq-1"}, peer))
    return ws


def test_blob_delete_pair_consistent(relay_env):
    relay, store = relay_env["relay"], relay_env["store"]
    bs = _MemBlobStore()
    bs.put("b-victim", b"abc")
    ws = _delete_frame(relay, store, bs)
    assert store.get_blob_meta("b-victim") is None
    assert bs.exists("b-victim") is False
    assert any(f.get("type") == "result" and f.get("ok")
               for f in ws.frames), ws.frames


def test_blob_delete_failure_keeps_pair(relay_env):
    relay, store = relay_env["relay"], relay_env["store"]
    bs = _MemBlobStore()
    bs.put("b-victim", b"abc")
    bs.delete_error = RuntimeError("storage genuinely down")
    ws = _delete_frame(relay, store, bs)
    # The delete failed with the object still present: the meta
    # must NOT be deleted either — the pair stays consistent and
    # the client is told the truth.
    assert store.get_blob_meta("b-victim") is not None
    assert bs.exists("b-victim") is True
    assert any(f.get("type") == "error" for f in ws.frames), ws.frames


def test_blob_delete_meta_survival_is_loud(relay_env):
    relay, store = relay_env["relay"], relay_env["store"]
    bs = _MemBlobStore()
    bs.put("b-victim", b"abc")
    # A meta delete that silently does not land (the store write
    # is lost): the handler must notice via read-back and shout.
    store.delete_blob_meta = lambda blob_id: None
    ws = _delete_frame(relay, store, bs)
    assert bs.exists("b-victim") is False  # object deletion landed
    kinds = [r["kind"] for r in store.list_audit(100)]
    assert "blob_divergence" in kinds, kinds
    alerts = store.list_alerts(status="open")
    assert any(a["kind"] == "blob_divergence"
               and a["subject"] == "b-victim" for a in alerts), alerts


# ---------------------------------------------------------------------
# Reconciliation: reap battery litter, alert for real owners
# ---------------------------------------------------------------------

def test_reconcile_blobs_reaps_dial_alerts_real(relay_env):
    relay, store = relay_env["relay"], relay_env["store"]
    store.put_blob_meta("b-battery", owner="dial-deadbeef", size=3)
    store.put_blob_meta("b-real", owner="realagent", size=3)
    store.put_blob_meta("b-alive", owner="realagent", size=3)
    bs = _MemBlobStore()
    bs.put("b-alive", b"abc")  # only this object actually exists
    relay.blob_store = bs
    relay._reconcile_blobs()
    assert store.get_blob_meta("b-battery") is None, (
        "ephemeral battery orphan was not reaped")
    assert store.get_blob_meta("b-real") is not None, (
        "a real owner's meta must never be auto-deleted")
    assert store.get_blob_meta("b-alive") is not None
    kinds = [r["kind"] for r in store.list_audit(100)]
    assert "blob_meta_reaped" in kinds, kinds
    assert "blob_divergence" in kinds, kinds
    alerts = store.list_alerts(status="open")
    assert any(a["kind"] == "blob_divergence"
               and a["subject"] == "b-real" for a in alerts), alerts


def test_reconcile_reaps_stale_battery_pairs_only(relay_env):
    """An INTACT battery pair is live-cycle property for seconds
    and abandoned litter after BATTERY_LITTER_AGE_SECONDS: the
    sweep reaps the stale pair (object + meta together, never
    one without the other) and leaves a fresh pair untouched."""
    import sqlite3
    import time as _time
    relay, store = relay_env["relay"], relay_env["store"]
    store.put_blob_meta("b-stale", owner="dial-deadbeef", size=3)
    store.put_blob_meta("b-fresh", owner="dial-deadbeef", size=3)
    bs = _MemBlobStore()
    bs.put("b-stale", b"abc")
    bs.put("b-fresh", b"abc")
    relay.blob_store = bs
    con = sqlite3.connect(relay_env["db"])
    con.execute("UPDATE blobs SET created_at = ? WHERE id = ?",
                (int(_time.time()) - 7200, "b-stale"))
    con.commit()
    con.close()
    relay._reconcile_blobs()
    assert store.get_blob_meta("b-stale") is None
    assert bs.exists("b-stale") is False
    assert store.get_blob_meta("b-fresh") is not None
    assert bs.exists("b-fresh") is True


def test_reconcile_unknown_presence_leaves_everything(relay_env):
    relay, store = relay_env["relay"], relay_env["store"]
    store.put_blob_meta("b-battery", owner="dial-deadbeef", size=3)

    class _Down:
        def exists(self, blob_id):
            raise RuntimeError("egress down")
    relay.blob_store = _Down()
    relay._reconcile_blobs()
    # Unknown is not absent: nothing reaped, nothing alerted.
    assert store.get_blob_meta("b-battery") is not None
    kinds = [r["kind"] for r in store.list_audit(100)]
    assert "blob_meta_reaped" not in kinds
    assert "blob_divergence" not in kinds
