"""Peer mesh tests (v1.2.0) — the NO GOING DARK peer-server law,
made real.

The owner's scenario: agents online, everybody's server healthy;
agent 4's server fails; agent 4 must STAY online and keep working
by riding another online agent's server at FULL capability; it
keeps probing home; the moment home is back strongly it migrates
back. A peer is a waiting room, never a new home.

Two real relays share ONE backend. Crucially, the agents here are
given NO configured fallbacks: everything they ride on must come
from DISCOVERY (the server registry, learned from any relay's
welcome) and from the PERSISTED server list in their state dirs.

Exactly-once is proven by message-id set comparison, not eyeballs:
every id sent is tracked, every id received is collected, and the
sets must match exactly — nothing lost, nothing duplicated — across
the kill, the ride, and the migration home.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest

from agentlink.client import Agent
from agentlink.protocol import file_bytes, verify_file
from agentlink.relay import Relay

HOST = "127.0.0.1"


class RelayHandle:
    """Same harness shape as the failover tests: a relay in its own
    thread/loop, ports pinned across restarts so a recovered home
    comes back at the SAME address."""

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
        """Sudden server death: listener + live sockets die; the
        shared backend (separate in production) is untouched."""
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
    with tempfile.TemporaryDirectory(prefix="agentlink-mesh-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=180))


async def wait_for(pred, timeout=30.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


def _mesh(tmp):
    db = str(Path(tmp) / "shared.db")
    home = RelayHandle(db, "home-server")
    peer = RelayHandle(db, "peer-server")
    home_url = home.start()
    peer_url = peer.start()
    return home, peer, home_url, peer_url


def test_peer_mesh_kill_drill(state_root, tmp_path):
    tmp = tempfile.mkdtemp(prefix="agentlink-mesh-")
    home, peer, home_url, peer_url = _mesh(tmp)
    sent_ids: set[str] = set()

    async def _t():
        boss = Agent("boss", endpoint=home_url,
                     state_dir=str(state_root / "boss"))
        worker = Agent("worker", endpoint=home_url,
                       state_dir=str(state_root / "worker"))

        @worker.on_message
        async def _reply(msg):
            return f"roger {msg['body']}"

        def _work(work, ctx):
            async def _go():
                await worker.deliver_work(work["id"],
                                          body="mesh delivery")
            asyncio.create_task(_go())
        worker.on_work(_work)

        boss_task = asyncio.create_task(
            boss.run(reconnect_delay=0.5, home_probe_interval=1.0))
        worker_task = asyncio.create_task(
            worker.run(reconnect_delay=0.5, home_probe_interval=1.0))
        try:
            assert await wait_for(
                lambda: home.relay and "boss" in home.relay.peers
                and "worker" in home.relay.peers)
            assert boss.current_endpoint == home_url
            assert worker.current_endpoint == home_url

            # DISCOVERY: no fallbacks were configured — both agents
            # learned BOTH servers from the welcome payload alone.
            # The peer starts UNRATED (earned health, v1.3.0): it
            # joins the race set only once its battery has earned a
            # rating above the floor.
            assert await wait_for(
                lambda: all(set(a.endpoints) == {home_url, peer_url}
                            for a in (boss, worker)), timeout=40)
            for a in (boss, worker):
                known = {s["endpoint"] for s in a.known_servers}
                assert known == {home_url, peer_url}, known
                # …and the list PERSISTED into the state dir.
                saved = json.loads(
                    (Path(a.state_dir) / "servers.json").read_text())
                assert {s["endpoint"] for s in saved["servers"]} == \
                    {home_url, peer_url}
                assert saved["home"] == home_url

            # Baseline DM at home.
            s1 = await boss.send_message("worker", "before the fall")
            sent_ids.add(s1["id"])
            r1 = await boss.wait_reply(s1["id"], timeout=15)
            assert r1["body"] == "roger before the fall"
            sent_ids.add(r1["id"])

            # HOME DIES mid-session. Both agents must ride the peer.
            home.kill()
            assert await wait_for(
                lambda: peer.relay and "boss" in peer.relay.peers
                and "worker" in peer.relay.peers)
            assert boss.current_endpoint == peer_url
            assert worker.current_endpoint == peer_url

            # Presence, from the peer's own dashboard data: riding.
            data = peer.relay._dashboard_data()
            rows = {u["username"]: u for u in data["users"]}
            assert rows["worker"]["reachability"] == \
                "online (via peer-server)", rows["worker"]
            assert rows["boss"]["reachability"] == \
                "online (via peer-server)", rows["boss"]
            # The mesh block on that same dashboard: the peer's
            # health is real and high, and it is carrying exactly
            # the two riders (2 of its health-scaled capacity).
            mesh = {s["endpoint"]: s for s in data["servers"]}
            prow = mesh[peer_url]
            assert prow["health"] > 50, prow
            assert prow["riders"] == 2, prow
            assert prow["capacity"] == (10 * prow["health"]) // 100

            # FULL CAPABILITY while riding — DM round-trip:
            s2 = await boss.send_message("worker", "riding the peer")
            sent_ids.add(s2["id"])
            r2 = await boss.wait_reply(s2["id"], timeout=15)
            assert r2["body"] == "roger riding the peer"
            sent_ids.add(r2["id"])

            # …group traffic:
            g = await boss.group_create("Mesh Room", ["worker"])
            gid = g["group_id"]
            await boss.group_send(gid, "group while riding")
            assert await wait_for(
                lambda: any(m.get("group_id") == gid
                            and m.get("body") == "group while riding"
                            for m in worker.messages), timeout=15)
            for m in worker.messages:
                if m.get("group_id") == gid:
                    sent_ids.add(m["id"])

            # …file transfer (upload + download, hash-verified):
            payload = tmp_path / "mesh-payload.bin"
            blob = bytes(range(256)) * 8
            payload.write_bytes(blob)
            fs = await boss.send_file("worker", str(payload),
                                      caption="mesh file")
            sent_ids.add(fs["id"])
            assert await wait_for(
                lambda: any(m.get("file") for m in worker.messages),
                timeout=15)
            fmsg = next(m for m in worker.messages if m.get("file"))
            sent_ids.add(fmsg["id"])
            assert verify_file(fmsg["file"])
            assert file_bytes(fmsg["file"]) == blob

            # …and work, delivered with a VERIFIED signed proof:
            works = await boss.assign_work(
                ["worker"], "mesh micro-work",
                instructions="deliver while riding the peer")
            wid = works[0]["id"]
            assert await wait_for(
                lambda: peer.relay.store.get_work(wid)["status"]
                in ("delivered", "completed"), timeout=20)
            raw = peer.relay.store.get_work(wid)
            assert len(raw["deliveries"]) == 1
            assert raw["proof_verified"] == 1, raw

            # HOME RECOVERS at the same address: both migrate back.
            home.start()
            assert await wait_for(
                lambda: home.relay and "boss" in home.relay.peers
                and "worker" in home.relay.peers)
            assert boss.current_endpoint == home_url
            assert worker.current_endpoint == home_url
            data = home.relay._dashboard_data()
            rows = {u["username"]: u for u in data["users"]}
            assert rows["worker"]["reachability"] == "online (home)"
            assert rows["boss"]["reachability"] == "online (home)"

            # Still fully working after the migration home.
            s3 = await boss.send_message("worker", "back home again")
            sent_ids.add(s3["id"])
            r3 = await boss.wait_reply(s3["id"], timeout=15)
            assert r3["body"] == "roger back home again"
            sent_ids.add(r3["id"])

            # EXACTLY-ONCE, by set comparison: every received id is
            # unique per receiver, and the union of received ids is
            # exactly the set of ids that were sent.
            received: list[str] = []
            for a in (boss, worker):
                ids = [m["id"] for m in a.messages if m.get("id")]
                assert len(ids) == len(set(ids)), \
                    f"duplicate delivery to {a.username}: {ids}"
                received.extend(ids)
            # Brain replies to counted traffic count as sent too
            # (the worker's brain answers the group post and the
            # file DM as well) — close the set over in_reply_to.
            for a in (boss, worker):
                for m in a.messages:
                    if m.get("in_reply_to") in sent_ids:
                        sent_ids.add(m["id"])
            assert set(received) == sent_ids, (
                f"lost={sent_ids - set(received)} "
                f"extra={set(received) - sent_ids}")
        finally:
            for t in (boss_task, worker_task):
                t.cancel()
            for a in (boss, worker):
                try:
                    await a.close()
                except Exception:
                    pass
    run(_t())
    home.kill()
    peer.stop()


def test_stale_peer_is_never_offered(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-mesh-stale-")
    home, peer, home_url, peer_url = _mesh(tmp)

    async def _t():
        store = home.relay.store
        # A fresh registry row IS offered…
        store.register_server("Fresh Relay", "ws://127.0.0.1:59998",
                              host_agent="", version="9.9.9")
        # …a stale one (heartbeat an hour old) is a dead relay and
        # must never be offered to anyone.
        store.register_server("Ghost Relay", "ws://127.0.0.1:59999",
                              host_agent="", version="9.9.9")
        db = sqlite3.connect(store.path)
        db.execute("UPDATE servers SET last_seen = ?"
                   " WHERE endpoint = ?",
                   (int(time.time()) - 3600, "ws://127.0.0.1:59999"))
        db.commit()
        db.close()

        live = {s["endpoint"] for s in home.relay._live_servers()}
        assert "ws://127.0.0.1:59998" in live
        assert "ws://127.0.0.1:59999" not in live

        agent = Agent("learner", endpoint=home_url,
                      state_dir=str(state_root / "learner"))
        await agent.start()
        try:
            known = {s["endpoint"] for s in agent.known_servers}
            assert "ws://127.0.0.1:59998" in known
            assert "ws://127.0.0.1:59999" not in known
            assert "ws://127.0.0.1:59999" not in agent.endpoints
            # Same answer through the explicit discovery request.
            entries = await agent.servers()
            offered = {s["endpoint"] for s in entries}
            assert "ws://127.0.0.1:59999" not in offered
            assert "ws://127.0.0.1:59998" in offered
        finally:
            await agent.close()
    run(_t())
    home.kill()
    peer.stop()


def test_boot_onto_peer_from_persisted_list(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-mesh-boot-")
    home, peer, home_url, peer_url = _mesh(tmp)

    async def _t():
        # The peer must have EARNED its rating before the first
        # boot's welcome can offer it as a fallback (v1.3.0).
        assert await wait_for(lambda: peer.relay._rated, timeout=40)
        first = Agent("booter", endpoint=home_url,
                      state_dir=str(state_root / "booter"))
        task = asyncio.create_task(
            first.run(reconnect_delay=0.5, home_probe_interval=1.0))
        try:
            assert await wait_for(
                lambda: home.relay and "booter" in home.relay.peers)
            # Discovery lands with the welcome/refresh a beat after
            # the server-side registration the line above waits on —
            # wait for the condition meant (a bare sample raced it:
            # the endpoint arrives ~0.5s after boot, measured in
            # arb_mesh_probe.py during the v1.4.4 gate arbitration).
            assert await wait_for(lambda: peer_url in first.endpoints)
        finally:
            task.cancel()
            try:
                await first.close()
            except Exception:
                pass

        # Home dies BEFORE the agent's next boot. A fresh process
        # with only its state dir (identity + persisted server list)
        # must boot straight onto the peer.
        home.kill()
        await asyncio.sleep(0.3)
        # The persisted list is also HOURS old by the time of this
        # boot (learned_at backdated past the TTL): restored entries
        # are the agent's memory of the mesh and must NOT be pruned
        # before the first live learn — that was the second half of
        # the v1.2.0 production drill failure.
        import json as _json
        p = state_root / "booter" / "servers.json"
        data = _json.loads(p.read_text())
        data["saved_at"] -= 7200
        for e in data["servers"]:
            if "learned_at" in e:
                e["learned_at"] -= 7200
        p.write_text(_json.dumps(data))
        second = Agent("booter", endpoint=home_url,
                       state_dir=str(state_root / "booter"))
        assert peer_url in second.endpoints  # loaded from disk
        task2 = asyncio.create_task(
            second.run(reconnect_delay=0.5, home_probe_interval=1.0))
        try:
            assert await wait_for(
                lambda: peer.relay and "booter" in peer.relay.peers)
            assert second.current_endpoint == peer_url
        finally:
            task2.cancel()
            try:
                await second.close()
            except Exception:
                pass
    run(_t())
    home.kill()
    peer.stop()


# ---------------------------------------------------------------------------
# Mesh rules (owner, 2026-11-02 ~05:52 PST): host anywhere, max 10
# riders per server, health on every server, ride only above 50%.
# ---------------------------------------------------------------------------

from agentlink.client import RegistrationFailed  # noqa: E402
from agentlink.relay import compute_server_health, effective_capacity  # noqa: E402


def test_health_formula_is_deterministic_and_real():
    # Earned health (v1.3.0): the percentage comes ONLY from
    # measured test evidence. No evidence at all earns NOTHING —
    # the score is 0, and a server in that state publishes UNRATED,
    # never a friendly static 100.
    assert compute_server_health() == 0
    full = dict(probe_ok=10, hello_ok=10, reg_ok=10, msg_ok=10,
                file_ok=10, hb_ok=10, scan_ok=10)
    # Clean evidence in every component earns the full 100.
    assert compute_server_health(**full) == 100
    # Load pressure: 50 peers -> -round(5 x 50/50) = -5.
    assert compute_server_health(**full, peers=50) == 95
    assert compute_server_health(**full, peers=3) == 100
    # Probe failures: 10% of probe round-trips failed -> -round(2.5).
    assert compute_server_health(
        **{**full, "probe_ok": 90, "probe_fail": 10}) == 98
    # Admission failures carry their weight: all hellos failed -> -20.
    assert compute_server_health(
        **{**full, "hello_ok": 0, "hello_fail": 5}) == 80
    # Registry write/read-back failures: all failed -> -20.
    assert compute_server_health(
        **{**full, "reg_ok": 0, "reg_fail": 2}) == 80
    # A component with NO evidence deducts its FULL weight:
    # untested is unearned (no message round-trips -> -15).
    no_msg = {k: v for k, v in full.items()
              if not k.startswith("msg")}
    assert compute_server_health(**no_msg) == 85
    # Everything broken at once floors at 0, never negative.
    assert compute_server_health(
        probe_fail=10, hello_fail=10, reg_fail=10, msg_fail=10,
        file_fail=10, hb_fail=10, scan_fail=10, peers=50) == 0
    # Capacity: floor(10 x health/100), hard max 10.
    assert effective_capacity(100) == 10
    assert effective_capacity(99) == 9
    assert effective_capacity(60) == 6
    assert effective_capacity(51) == 5
    assert effective_capacity(50) == 5
    assert effective_capacity(0) == 0


def _craft_events(relay, spec):
    """Shape a relay's measured-evidence window directly (the
    events ARE the health currency in v1.3.0 — there is no override
    to pin). spec maps event kind -> count; the battery keeps
    adding its own trickle on top, so counts are large."""
    import collections as _c
    now = int(time.time())
    dq = _c.deque(maxlen=20000)
    for kind, n in spec.items():
        dq.extend([(now, kind)] * n)
    relay._health_events = dq
    relay._register_server_row()


def test_unhealthy_peer_is_never_selected(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-mesh-health-")
    db = str(Path(tmp) / "shared.db")
    home = RelayHandle(db, "home-server")
    good = RelayHandle(db, "good-peer")
    sick = RelayHandle(db, "sick-peer")
    home_url = home.start()
    good_url = good.start()
    sick_url = sick.start()

    async def _t():
        # Both peers earn their ratings through the battery first.
        assert await wait_for(
            lambda: good.relay._rated and sick.relay._rated,
            timeout=40)
        # The sick peer's MEASURED evidence collapses (probe, hello
        # and message round-trips failing in its window) — its
        # percentage falls to the floor on real failures, never by
        # an operator pin (v1.3.0: no health override exists).
        _craft_events(sick.relay, {
            "probe_fail": 2000, "hello_fail": 2000, "msg_fail": 2000,
            "reg_ok": 2000, "file_ok": 2000, "hb_ok": 2000,
            "scan_ok": 2000})
        sick_health = sick.relay._compute_health()
        assert 0 < sick_health <= 50, sick_health
        agent = Agent("chooser", endpoint=home_url,
                      state_dir=str(state_root / "chooser"))
        await agent.start()
        try:
            known = {s["endpoint"]: s for s in agent.known_servers}
            assert known[sick_url]["health"] <= 50
            assert known[good_url]["health"] > 50
            # At/below the floor: in the directory, NEVER in the
            # race set. The healthy peer is.
            assert sick_url not in agent.endpoints
            assert good_url in agent.endpoints
            assert home_url in agent.endpoints
            # Rank: healthier peer beats a less healthy one.
            agent._learn_servers([
                {"label": "mid", "endpoint": "ws://127.0.0.1:41001",
                 "health": 80, "riders": 0},
                {"label": "best", "endpoint": "ws://127.0.0.1:41002",
                 "health": 95, "riders": 4},
                {"label": "busy", "endpoint": "ws://127.0.0.1:41003",
                 "health": 95, "riders": 1}])
            assert agent._endpoint_rank("ws://127.0.0.1:41003") < \
                agent._endpoint_rank("ws://127.0.0.1:41002") < \
                agent._endpoint_rank("ws://127.0.0.1:41001")
            assert agent._endpoint_rank(home_url) == (0, 0, 0)
        finally:
            await agent.close()
        # Backstop: even a client that tries the sick server
        # directly is refused as a rider — server_unhealthy.
        rider = Agent("hopeful", endpoint=home_url,
                      state_dir=str(state_root / "hopeful"))
        with pytest.raises(RegistrationFailed) as ei:
            await rider.start(sick_url)
        assert "server_unhealthy" in str(ei.value)
        await rider.close()
    run(_t())
    home.kill()
    good.stop()
    sick.stop()


def test_rider_capacity_cap_and_deflection(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-mesh-cap-")
    db = str(Path(tmp) / "shared.db")
    home = RelayHandle(db, "cap-home")
    peer = RelayHandle(db, "cap-peer")
    home_url = home.start()
    peer_url = peer.start()

    async def _t():
        # Earned health in the 60s -> capacity floor(10 x h/100) = 6
        # riders. The percentage is shaped by MEASURED evidence
        # (hello + message round-trips failing in the window) —
        # v1.3.0 has no health pin to set.
        assert await wait_for(lambda: peer.relay._rated, timeout=40)
        _craft_events(peer.relay, {
            "probe_ok": 2000, "hello_fail": 2000, "reg_ok": 2000,
            "msg_fail": 2000, "file_ok": 2000, "hb_ok": 2000,
            "scan_ok": 2000})
        peer_health = peer.relay._compute_health()
        assert 60 <= peer_health <= 69, peer_health
        assert peer.relay._effective_capacity() == 6
        riders = []
        for i in range(6):
            r = Agent(f"cap-rider-{i}", endpoint=home_url,
                      state_dir=str(state_root / f"cap-rider-{i}"))
            await r.start(peer_url)  # rides the peer directly
            riders.append(r)
        assert peer.relay._riders_count() == 6
        # The 7th rider hits the hard cap: server_full, by name.
        seventh = Agent("cap-rider-6", endpoint=home_url,
                        state_dir=str(state_root / "cap-rider-6"))
        with pytest.raises(RegistrationFailed) as ei:
            await seventh.start(peer_url)
        assert "server_full" in str(ei.value)
        await seventh.close()

        # Through the daemon path, a refusal is a DEFLECTION, not a
        # death: the agent learns the mesh while home is alive, home
        # dies, the agent races to the peer, gets deflected, keeps
        # trying — and boards the moment a slot frees.
        late = Agent("cap-late", endpoint=home_url,
                     state_dir=str(state_root / "cap-late"))
        await late.start()   # connects home, discovers the peer
        assert peer_url in late.endpoints
        await late.close()
        home.kill()
        task = asyncio.create_task(
            late.run(reconnect_delay=0.5, home_probe_interval=1.0))
        try:
            assert await wait_for(lambda: len(late.deflections) >= 1,
                                  timeout=20)
            assert "cap-late" not in (peer.relay.peers
                                      if peer.relay else {})
            await riders[0].close()
            riders.pop(0)
            assert await wait_for(
                lambda: peer.relay and "cap-late" in peer.relay.peers,
                timeout=30)
            assert late.current_endpoint == peer_url
        finally:
            task.cancel()
            try:
                await late.close()
            except Exception:
                pass
        for r in riders:
            try:
                await r.close()
            except Exception:
                pass
    run(_t())
    home.kill()
    peer.stop()


# ---------------------------------------------------------------------------
# Phantom endpoints (v1.2.2): the production shape the staging drill
# could not see — an endpoint fronted by a tunnel completes the WS
# handshake even when the relay behind it is dead, then closes. A
# bare-open race probe crowns the phantom forever (the v1.2.0
# production kill-drill failure). Probes now dwell.
# ---------------------------------------------------------------------------

class PhantomHandle:
    """A WS server that accepts the handshake, then closes within
    ~0.2s — exactly what a tunnel fronting a dead relay looks like
    to a client."""

    def __init__(self):
        self.port = 0
        self.loop = None
        self.thread = None
        self.server = None

    def start(self):
        from websockets.server import serve as _ws_serve
        ready = threading.Event()

        def _thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.loop = loop

            async def _main():
                async def handler(ws, path=None):
                    await asyncio.sleep(0.2)
                    try:
                        await ws.close()
                    except Exception:
                        pass
                self.server = await _ws_serve(handler, HOST, self.port)
                self.port = self.server.sockets[0].getsockname()[1]
                ready.set()
                await asyncio.Future()

            try:
                loop.run_until_complete(_main())
            except (RuntimeError, asyncio.CancelledError):
                pass

        self.thread = threading.Thread(target=_thread, daemon=True)
        self.thread.start()
        assert ready.wait(timeout=10)
        return f"ws://{HOST}:{self.port}"

    def stop(self):
        if self.loop is not None and self.server is not None:
            try:
                fut = asyncio.run_coroutine_threadsafe(
                    _close_server(self.server), self.loop)
                fut.result(timeout=5)
            except Exception:
                pass
            self.server = None


async def _close_server(server):
    server.close()
    await server.wait_closed()


def test_phantom_home_never_wins_the_race(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-mesh-phantom-")
    db = str(Path(tmp) / "shared.db")
    peer = RelayHandle(db, "real-peer")
    peer_url = peer.start()
    phantom = PhantomHandle()
    phantom_url = phantom.start()

    async def _t():
        agent = Agent("phantom-rider", endpoint=phantom_url,
                      fallbacks=[peer_url],
                      state_dir=str(state_root / "phantom-rider"))
        task = asyncio.create_task(agent.run(
            reconnect_delay=0.5, home_probe_interval=1.0))
        try:
            # The race must see through the phantom (dwell) and land
            # on the real peer. Under earned health (v1.3.0) the
            # peer starts UNRATED: the first boarding attempt is
            # deflected (server_unrated) and the agent boards for
            # real once the peer's battery has earned its rating —
            # so the wait is on actual peer membership, not on the
            # endpoint label (which flips at attempt time).
            assert await wait_for(
                lambda: peer.relay
                and "phantom-rider" in peer.relay.peers, timeout=60)
            assert agent.current_endpoint == peer_url
            # And the dwell-checked home probe must not knock it off
            # the peer every few seconds: still riding after 6s.
            await asyncio.sleep(6)
            assert agent.current_endpoint == peer_url
            assert "phantom-rider" in peer.relay.peers
        finally:
            task.cancel()
            try:
                await agent.close()
            except Exception:
                pass
    run(_t())
    phantom.stop()
    peer.stop()
