"""Hardened core tests (v1.2.0) — the survival invariants are
HARDCODED, and non-compliance is VISIBLE.

Owner's law (2026-11-02 ~05:56 PST), prompted by an agent that had
configured itself to check in hourly and presented that as meeting
NO GOING DARK: heartbeat 5s, continuous connection, unlimited
reconnect with a 5s backoff cap, home probe 5s, failover race
always on, self-update check 900s — no env var, config file, CLI
flag or constructor argument may weaken, stretch or disable any of
them. What stays flexible is network adaptation only.

These tests pin the law from both sides: attempts to stretch the
invariants provably change nothing, the one sanctioned kill switch
is relay-side and visible, every client declares a core fingerprint
the relay judges, and a scripted check-in client gets flagged.
"""

from __future__ import annotations

import asyncio
import collections
import json
import tempfile
import threading
import time
from pathlib import Path

import pytest
from websockets.client import connect

from agentlink.client import Agent, core_fingerprint
from agentlink.relay import Relay
from agentlink.timing import (
    HEARTBEAT_SECONDS,
    HOME_PROBE_SECONDS,
    RECONNECT_BACKOFF_CAP_SECONDS,
    UPDATE_CHECK_SECONDS,
)

HOST = "127.0.0.1"


class RelayHandle:
    def __init__(self, db, name, **relay_kw):
        self.db = db
        self.name = name
        self.relay_kw = relay_kw
        self.relay = None
        self.loop = None
        self.thread = None
        self.port = 0
        self.dash_port = 0

    def start(self):
        if not self.port:
            import socket as _s
            _tmp = _s.socket()
            _tmp.bind((HOST, 0))
            self.port = _tmp.getsockname()[1]
            _tmp.close()
        self.relay = Relay(host=HOST, port=self.port, db_path=self.db,
                           server_name=self.name,
                           dashboard_password="test-pass",
                           dashboard_port=self.dash_port,
                           public_endpoint=f"ws://{HOST}:{self.port}",
                           **self.relay_kw)
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


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-core-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=120))


async def wait_for(pred, timeout=20.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


def test_fingerprint_matches_the_hardcoded_constants():
    fp = core_fingerprint()
    assert fp["heartbeat_s"] == HEARTBEAT_SECONDS == 5
    assert fp["backoff_cap_s"] == RECONNECT_BACKOFF_CAP_SECONDS == 5
    assert fp["home_probe_s"] == HOME_PROBE_SECONDS == 5
    assert fp["update_check_s"] == UPDATE_CHECK_SECONDS == 900
    assert fp["race"] is True and fp["continuous"] is True


def test_real_client_declares_a_compliant_core(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-core-")
    handle = RelayHandle(str(Path(tmp) / "relay.db"), "core-server")
    url = handle.start()

    async def _t():
        agent = Agent("honest", endpoint=url,
                      state_dir=str(state_root / "honest"))
        await agent.start()
        try:
            data = handle.relay._dashboard_data()
            row = next(u for u in data["users"]
                       if u["username"] == "honest")
            assert row["core"]["heartbeat_s"] == 5
            assert row["core_compliant"] is True
            assert row["connection_pattern"] == "continuous"
            assert data["updates_enabled"] is True
            # The directory (what agents route by) carries it too.
            entries = await agent.directory()
            me = next(u for u in entries
                      if u["username"] == "honest")
            assert me["core_compliant"] is True
        finally:
            await agent.close()
    run(_t())
    handle.stop()


def test_tampered_core_declaration_is_flagged(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-core-tamper-")
    handle = RelayHandle(str(Path(tmp) / "relay.db"), "core-server")
    url = handle.start()

    async def _t():
        # A foreign client that DECLARES a stretched core (hourly
        # heartbeat — the owner's check-in confession, in numbers).
        async with connect(url) as ws:
            await ws.send(json.dumps({
                "type": "hello", "username": "sneaky",
                "display_name": "Sneaky", "secret": None,
                "ephemeral": False, "pubkey": "",
                "core": {"core": "agentlink-hardened-core/1",
                         "heartbeat_s": 3600, "backoff_cap_s": 3600,
                         "home_probe_s": 3600, "update_check_s": 3600,
                         "race": True, "continuous": True}}))
            frame = json.loads(await ws.recv())
            assert frame["type"] == "welcome"
            data = handle.relay._dashboard_data()
            row = next(u for u in data["users"]
                       if u["username"] == "sneaky")
            # Recorded verbatim — and judged non-compliant, in the
            # open. The relay never trusts the declaration.
            assert row["core"]["heartbeat_s"] == 3600
            assert row["core_compliant"] is False
    run(_t())
    handle.stop()


def test_checkin_pattern_is_flagged(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-core-checkin-")
    handle = RelayHandle(str(Path(tmp) / "relay.db"), "core-server")
    url = handle.start()

    async def _t():
        agent = Agent("pollster", endpoint=url,
                      state_dir=str(state_root / "pollster"))
        await agent.start()
        await agent.close()
        relay = handle.relay
        now = int(time.time())
        # Fabricate the signature: three 30-second sessions with
        # 300-second dark gaps inside the last hour.
        relay._sessions["pollster"] = collections.deque([
            (now - 1500, now - 1470),
            (now - 1170, now - 1140),
            (now - 840, now - 810)])
        assert relay._connection_pattern("pollster") == "check-in"
        data = relay._dashboard_data()
        row = next(u for u in data["users"]
                   if u["username"] == "pollster")
        assert row["connection_pattern"] == "check-in"
        # A long-lived session is continuous even with company.
        relay._sessions["pollster"] = collections.deque([
            (now - 3000, now - 100)])
        assert relay._connection_pattern("pollster") == "continuous"
        # Short sessions with SHORT gaps are flapping, not check-in:
        # presence already shows that honestly; the flag is specific.
        relay._sessions["pollster"] = collections.deque([
            (now - 300, now - 290), (now - 280, now - 270),
            (now - 260, now - 250)])
        assert relay._connection_pattern("pollster") == "continuous"
    run(_t())
    handle.stop()


def test_update_kill_switch_is_relay_side_only(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-core-switch-")
    off = RelayHandle(str(Path(tmp) / "off.db"), "off-server",
                      updates_enabled=False)
    off_url = off.start()
    on = RelayHandle(str(Path(tmp) / "on.db"), "on-server")
    on_url = on.start()

    async def _t():
        # Relay operator switched updates OFF: the welcome says so,
        # the client obeys the RELAY (never its own env), and the
        # dashboard shows the state.
        agent = Agent("switched-off", endpoint=off_url,
                      state_dir=str(state_root / "switched-off"))
        await agent.start()
        assert agent._relay_updates_enabled is False
        assert off.relay._dashboard_data()["updates_enabled"] is False
        task = asyncio.create_task(agent.serve())
        await asyncio.sleep(0.5)
        assert agent._update_task is None  # checker never armed
        task.cancel()
        await agent.close()

        # Default relay: the checker arms inside serve(), at the
        # hardcoded interval — nothing agent-side can stop it.
        agent2 = Agent("switched-on", endpoint=on_url,
                       state_dir=str(state_root / "switched-on"))
        await agent2.start()
        assert agent2._relay_updates_enabled is True
        task2 = asyncio.create_task(agent2.serve())
        await asyncio.sleep(0.5)
        assert agent2._update_task is not None
        assert not agent2._update_task.done()
        task2.cancel()
        await agent2.close()
    run(_t())
    off.stop()
    on.stop()


def test_stretched_daemon_params_cannot_weaken_the_core(state_root):
    """reconnect_delay / home_probe_interval are legacy knobs a
    caller can still pass — the CAPS make them harmless: even at
    3600 the reconnect pacing is capped at 5s and the home probe at
    5s, so the agent rides and migrates on core timing, not on the
    stretched values."""
    tmp = tempfile.mkdtemp(prefix="agentlink-core-stretch-")
    db = str(Path(tmp) / "shared.db")
    home = RelayHandle(db, "stretch-home")
    peer = RelayHandle(db, "stretch-peer")
    home_url = home.start()
    peer_url = peer.start()

    async def _t():
        agent = Agent("stretched", endpoint=home_url,
                      state_dir=str(state_root / "stretched"))
        task = asyncio.create_task(agent.run(
            reconnect_delay=3600, home_probe_interval=3600))
        try:
            assert await wait_for(
                lambda: home.relay and "stretched" in home.relay.peers)
            home.kill()
            # Backoff cap: riding within seconds, not in an hour.
            assert await wait_for(
                lambda: peer.relay and "stretched" in peer.relay.peers,
                timeout=15)
            assert agent.current_endpoint == peer_url
            home.start()
            # Probe cap: home within seconds of its return.
            assert await wait_for(
                lambda: home.relay and "stretched" in home.relay.peers,
                timeout=15)
            assert agent.current_endpoint == home_url
        finally:
            task.cancel()
            try:
                await agent.close()
            except Exception:
                pass
    run(_t())
    home.kill()
    peer.stop()
