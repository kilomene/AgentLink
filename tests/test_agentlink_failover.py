"""Failover + heartbeat tests.

Two real relays share ONE backend DB (the local stand-in for the
shared Supabase backend): any relay can serve any agent, queues and
work are shared, so riding a fallback loses nothing. Own server first:
the agent migrates back home when home recovers.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import time
from pathlib import Path

import pytest
from websockets.client import connect

from agentlink.backend import create_store
from agentlink.client import Agent
from agentlink.relay import Relay
from agentlink.supabase_store import SupabaseStore

HOST = "127.0.0.1"


class RelayHandle:
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
                           dashboard_password="test-pass",
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
        # A real home server recovers at the SAME address: pin the ports.
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
        """Simulate sudden server death: listener + live sockets die,
        the shared backend (separate in production) is untouched."""
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


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-fo-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


async def wait_for(pred, timeout=20.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


def test_failover_home_first_and_migrate_back(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-fo-")
    db = str(Path(tmp) / "shared.db")
    home = RelayHandle(db, "home-server")
    fallback = RelayHandle(db, "fallback-server")
    home_url = home.start()
    fb_url = fallback.start()

    async def _t():
        rider = Agent("rider", endpoint=home_url, fallbacks=[fb_url],
                      state_dir=str(state_root / "rider"))
        run_task = asyncio.create_task(
            rider.run(reconnect_delay=0.5, home_probe_interval=1.0))
        try:
            assert await wait_for(
                lambda: home.relay and "rider" in home.relay.peers)
            assert rider.current_endpoint == home_url

            # Home dies: the agent rides the fallback, same backend.
            home.kill()
            assert await wait_for(
                lambda: fallback.relay and "rider" in fallback.relay.peers)
            assert rider.current_endpoint == fb_url

            # Work assigned via the fallback is received by the rider —
            # nothing lost in the move.
            boss = Agent("boss", endpoint=fb_url,
                         state_dir=str(state_root / "boss"))
            await boss.start()
            works = await boss.assign_work(["rider"], "Survive failover",
                                           instructions="shared backend")
            assert await wait_for(lambda: len(rider.assigned_work) == 1)
            assert rider.assigned_work[0]["id"] == works[0]["id"]
            await boss.close()

            # Home recovers (same address): the home-probe migrates
            # the agent back.
            home.start()
            assert await wait_for(
                lambda: home.relay and "rider" in home.relay.peers)
            assert rider.current_endpoint == home_url
        finally:
            run_task.cancel()
            try:
                await rider.close()
            except Exception:
                pass
    run(_t())
    home.kill()
    fallback.stop()


def test_heartbeat_presence_and_last_seen(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-hb-")
    handle = RelayHandle(str(Path(tmp) / "relay.db"), "hb-server")
    url = handle.start()

    async def _t():
        # Raw client: hello, then a ping heartbeat.
        async with connect(url) as ws:
            await ws.send(json.dumps(
                {"type": "hello", "username": "beater",
                 "display_name": "Beater", "secret": None,
                 "ephemeral": False, "pubkey": ""}))
            frame = json.loads(await ws.recv())
            assert frame["type"] == "welcome"
            before = handle.relay.peers["beater"].last_seen
            await asyncio.sleep(1.1)
            await ws.send(json.dumps({"type": "ping"}))
            pong = json.loads(await ws.recv())
            assert pong["type"] == "pong"
            after = handle.relay.peers["beater"].last_seen
            assert after > before
            data = handle.relay._dashboard_data()
            me = [u for u in data["users"] if u["username"] == "beater"][0]
            assert me["online"] is True
            assert me["riding"] == "hb-server"
            assert me["last_seen"] == after
    run(_t())
    handle.stop()


def test_backend_factory_and_supabase_adapter_wiring(tmp_path):
    store = create_store("sqlite", db_path=str(tmp_path / "x.db"))
    assert type(store).__name__ == "Store"
    store.close()
    # Supabase adapter refuses to construct without operator credentials.
    with pytest.raises(ValueError):
        create_store("supabase", supabase_url="", supabase_key="")
    s = SupabaseStore("https://example.supabase.co", "operator-key")
    assert s.base == "https://example.supabase.co/rest/v1"
    with pytest.raises(ValueError):
        create_store("bogus-backend")
    # The production schema ships with the repo and covers every table
    # the adapter touches.
    schema = (Path(__file__).parent.parent / "deploy"
              / "supabase-schema.sql").read_text()
    for table in ("users", "queue", "groups", "group_members",
                  "group_keys", "invites", "work", "work_deliveries",
                  "dashboard_sessions", "audit_log"):
        assert f"create table if not exists {table}" in schema
    assert time.time() > 0  # (silence unused-import style checkers)
