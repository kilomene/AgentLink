"""v1.1 production hardening tests (Phase 1, Step 1).

Two structural fixes carried over from the production cutover:

(a) The relay's fleet scan must do its store work OFF the event loop.
    With the network-backed Supabase store every store call is a round
    trip; on the loop it starved hello/message handling and wedged
    reconnecting agents.

(b) The client's hello/welcome wait is bounded (HELLO_TIMEOUT_SECONDS):
    a hello landing in a bad egress window times out, closes, and the
    unlimited retry loop tries again until a hello lands in a good
    window — no service restart needed to recover.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from websockets.server import serve as ws_serve

import agentlink.timing as T
from agentlink.client import Agent
from agentlink.relay import Relay

HOST = "127.0.0.1"


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


async def wait_for(pred, timeout=25.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


@pytest.fixture()
def state_root(tmp_path):
    return tmp_path


def test_fleet_scan_store_work_runs_off_event_loop(state_root):
    db = str(Path(state_root) / "scan.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="test-password", dashboard_port=0)
    loop_thread = threading.get_ident()
    seen: dict[str, int] = {}

    def wrap(name):
        orig = getattr(relay.store, name)

        def recorder(*a, **kw):
            seen[name] = threading.get_ident()
            return orig(*a, **kw)

        return recorder

    for name in ("dequeue_all", "open_work", "list_chains_meta",
                 "list_users", "oldest_urgent_queued", "list_alerts"):
        setattr(relay.store, name, wrap(name))

    # A connected peer so the drain phase has a queue to pull.
    relay.peers["someone"] = SimpleNamespace(
        ephemeral=False, last_seen=int(time.time()))

    async def _t():
        await relay._fleet_scan_once()

    run(_t())
    assert seen, "scan made no store calls at all"
    for name, ident in seen.items():
        assert ident != loop_thread, \
            f"store.{name} ran on the event-loop thread"


def test_fleet_scan_does_not_block_the_loop(state_root):
    db = str(Path(state_root) / "scan2.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="test-password", dashboard_port=0)
    orig = relay.store.dequeue_all

    def slow_dequeue(username):
        time.sleep(0.6)  # a bad-window Supabase round trip
        return orig(username)

    relay.store.dequeue_all = slow_dequeue
    relay.peers["someone"] = SimpleNamespace(
        ephemeral=False, last_seen=int(time.time()))

    async def _t():
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                ticks += 1
                await asyncio.sleep(0.05)

        tick_task = asyncio.create_task(ticker())
        await relay._fleet_scan_once()
        tick_task.cancel()
        return ticks

    ticks = run(_t())
    # The 0.6s store block must not stall the loop: the ticker keeps
    # beating while the scan waits on its worker thread.
    assert ticks >= 5, f"event loop stalled during scan ({ticks} ticks)"


def test_blob_io_runs_off_event_loop_and_file_lands(state_root):
    """Blob put/get are network I/O with the R2 backend: they must run
    on worker threads, never the relay loop (a slow fetch on the loop
    starved clients into blob_get timeouts in the live exercise)."""
    from agentlink.blobstore import LocalBlobStore

    class RecordingBlobStore(LocalBlobStore):
        def __init__(self, root):
            super().__init__(root)
            self.threads = {}

        def put(self, blob_id, data):
            self.threads.setdefault("put", threading.get_ident())
            return super().put(blob_id, data)

        def get(self, blob_id):
            self.threads.setdefault("get", threading.get_ident())
            return super().get(blob_id)

    async def _t():
        store = RecordingBlobStore(str(state_root / "blobs"))
        relay = Relay(host=HOST, port=0,
                      db_path=str(state_root / "blob.db"),
                      dashboard_password="test-password",
                      dashboard_port=0, blob_store=store)
        await relay.start()
        url = f"ws://{HOST}:{relay.port}"
        a = Agent("sender-a", endpoint=url,
                  state_dir=str(state_root / "a"))
        b = Agent("receiver-b", endpoint=url,
                  state_dir=str(state_root / "b"))
        got = []

        @b.on_message
        async def _m(msg):
            got.append(msg)

        try:
            await a.start()
            await b.start()
            payload = state_root / "blob-payload.bin"
            payload.write_bytes(b"x" * 4096)
            await a.send_file("receiver-b", str(payload), via_blob=True)
            ok = await wait_for(lambda: len(got) == 1, timeout=20)
            assert ok, "blob file never reached the receiver"
            f = got[0].get("file") or {}
            assert f.get("size") == 4096, f
            loop_thread = threading.get_ident()
            assert store.threads.get("put") not in (None, loop_thread)
            assert store.threads.get("get") not in (None, loop_thread)
        finally:
            await a.close()
            await b.close()
            await relay.stop()

    run(_t())


def test_hello_timeout_then_retry_connects(state_root, monkeypatch):
    monkeypatch.setattr(T, "HELLO_TIMEOUT_SECONDS", 0.3)

    async def _t():
        # A "bad window" server: accepts sockets, never speaks.
        async def silent(ws, *rest):
            try:
                await asyncio.Future()
            except asyncio.CancelledError:
                pass

        server = await ws_serve(silent, HOST, 0)
        port = server.sockets[0].getsockname()[1]
        url = f"ws://{HOST}:{port}"
        agent = Agent("patient", endpoint=url,
                      state_dir=str(state_root / "patient"))

        # 1) A direct start() against the silent server must fail
        #    FAST with a retryable ConnectionError — not hang, and not
        #    a terminal RegistrationFailed.
        t0 = time.monotonic()
        with pytest.raises(ConnectionError):
            await agent.start()
        assert time.monotonic() - t0 < 5

        # 2) run() keeps retrying on its own; when the window clears
        #    (a real relay takes over the port) the SAME client process
        #    connects — no restart, no outside help.
        run_task = asyncio.create_task(agent.run(reconnect_delay=0.5))
        relay = None
        try:
            await asyncio.sleep(1.2)  # a couple of doomed attempts
            server.close()
            try:
                await asyncio.wait_for(server.wait_closed(), timeout=2)
            except asyncio.TimeoutError:
                pass
            relay = Relay(host=HOST, port=port,
                          db_path=str(state_root / "real.db"),
                          dashboard_password="test-password",
                          dashboard_port=0)
            await relay.start()
            ok = await wait_for(lambda: "patient" in relay.peers)
            assert ok, "client never connected after the window cleared"
            assert agent.connection_state == "connected"
        finally:
            run_task.cancel()
            try:
                await agent.close()
            except Exception:
                pass
            if relay is not None:
                await relay.stop()

    run(_t())
