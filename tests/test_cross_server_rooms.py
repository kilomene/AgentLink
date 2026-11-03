"""Cross-server rooms + room liveness truth (v1.3.9, WS2 + WS3).

The defects, proven live 2026-11-03:
  * a room opened via the home relay refused a member's join via
    its own server (unknown_room) — room live state sat in each
    relay's own memory, visible backend-wide on the dashboard
    since v1.3.4 but not OPERABLE backend-wide;
  * the same room then lingered on the dashboard as a GHOST —
    rendered with its creator as participant long after the
    creator's connection died unclosed.

The cure pinned here: room live state is a shared store record;
signals cross relays through the store-backed frame queue; room
composition is reconciled with connection liveness; a disconnect
without leave/close reaps the participant on the spot.
"""

from __future__ import annotations

import asyncio
import tempfile
import threading
from pathlib import Path

import pytest

from agentlink.client import Agent, RequestFailed
from agentlink.relay import Relay

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
                           dashboard_password="test-password",
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


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def wait_for(pred, timeout=20.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-xr-agents-") as tmp:
        yield Path(tmp)


def _rooms(relay):
    return relay._dashboard_data()["rooms"]


def _setup(tmp, state_root):
    db = str(Path(tmp) / "shared.db")
    home = RelayHandle(db, "xr-home")
    x3 = RelayHandle(db, "xr-x3")
    return db, home, x3, home.start(), x3.start()


def test_cross_server_room_full_cycle(state_root):
    """The exact configuration that failed live: phoenix opens on
    home; deploy-probe joins via its OWN server; signals flow
    BOTH ways cross-server and reach only the addressed
    participant; a non-member is refused cross-server; close on
    home ends the room for the x3 side too."""
    tmp = tempfile.mkdtemp(prefix="agentlink-xr-")
    db, home, x3, home_url, x3_url = _setup(tmp, state_root)

    async def _t():
        phx = Agent("xrphoenix", endpoint=home_url,
                    state_dir=str(state_root / "xrphoenix"))
        probe = Agent("xrprobe", endpoint=x3_url,
                      state_dir=str(state_root / "xrprobe"))
        third = Agent("xrthird", endpoint=home_url,
                      state_dir=str(state_root / "xrthird"))
        outsider = Agent("xrout", endpoint=x3_url,
                         state_dir=str(state_root / "xrout"))
        for a in (phx, probe, third, outsider):
            await a.start()
        try:
            g = await phx.group_create(
                "xr-group", ["xrprobe", "xrthird"])
            gid = g["id"] if "id" in g else g["group_id"]
            opened = await phx.room_open(gid)
            rid = opened["room_id"]
            # Join from the OTHER server — refused unknown_room
            # before v1.3.9.
            await probe.room_join(rid)
            await third.room_join(rid)
            got = {"probe": [], "phx": [], "third": []}

            @probe.on_room_signal
            async def _ps(frame):
                got["probe"].append(frame)

            @phx.on_room_signal
            async def _hs(frame):
                got["phx"].append(frame)

            @third.on_room_signal
            async def _ts(frame):
                got["third"].append(frame)

            await phx.room_signal(rid, "xrprobe", "offer",
                                  {"type": "offer", "sdp": "v=0 o"})
            assert await wait_for(lambda: len(got["probe"]) == 1)
            assert got["probe"][0]["kind"] == "offer"
            assert got["probe"][0]["from"] == "xrphoenix"
            await probe.room_signal(rid, "xrphoenix", "answer",
                                    {"type": "answer", "sdp": "v=0 a"})
            assert await wait_for(lambda: len(got["phx"]) == 1)
            assert got["phx"][0]["kind"] == "answer"
            # Addressed only: the third participant got nothing.
            await asyncio.sleep(1.5)
            assert got["third"] == []
            # Non-member join refused, cross-server.
            with pytest.raises(RequestFailed):
                await outsider.room_join(rid)
            # Dashboard on the OTHER relay composes the same room.
            assert await wait_for(lambda: any(
                r["id"] == rid for r in _rooms(x3.relay)))
            room = [r for r in _rooms(x3.relay) if r["id"] == rid][0]
            assert sorted(room["participants"]) == [
                "xrphoenix", "xrprobe", "xrthird"]
            # Close on home disappears for x3.
            await phx.room_close(rid)
            assert await wait_for(lambda: not any(
                r["id"] == rid for r in _rooms(x3.relay)))
            with pytest.raises(RequestFailed):
                await probe.room_join(rid)
        finally:
            for a in (phx, probe, third, outsider):
                try:
                    await a.close()
                except Exception:
                    pass

    run(_t())
    home.stop()
    x3.stop()


def test_ghost_room_reaped_on_unclosed_death(state_root):
    """WS3: a room's only client dies WITHOUT leave/close — the
    room does not linger as a dashboard ghost, on either relay."""
    tmp = tempfile.mkdtemp(prefix="agentlink-xr-")
    db, home, x3, home_url, x3_url = _setup(tmp, state_root)

    async def _t():
        solo = Agent("xrsolo", endpoint=home_url,
                     state_dir=str(state_root / "xrsolo"))
        mate = Agent("xrmate", endpoint=home_url,
                     state_dir=str(state_root / "xrmate"))
        await solo.start()
        await mate.start()
        try:
            g = await solo.group_create("xr-ghost", ["xrmate"])
            gid = g["id"] if "id" in g else g["group_id"]
            rid = (await solo.room_open(gid))["room_id"]
            assert any(r["id"] == rid for r in _rooms(home.relay))
            # Unclosed death: the socket dies; no leave, no close,
            # no Agent.close().
            await solo._ws.close()
            assert await wait_for(lambda: not any(
                r["id"] == rid for r in _rooms(home.relay)))
            assert await wait_for(lambda: not any(
                r["id"] == rid for r in _rooms(x3.relay)))
            assert home.relay.store.room_get(rid) is None
        finally:
            try:
                await mate.close()
            except Exception:
                pass
            try:
                await solo.close()
            except Exception:
                pass

    run(_t())
    home.stop()
    x3.stop()


def test_signal_routes_on_connection_note_when_last_seen_stale(state_root):
    """Regression pin for the production-proof find (2026-11-03):
    x3 refused a signal to phoenix with peer_offline although
    phoenix was connected to home — the signal handler consulted
    presence with NO connection map, so only last_seen counted,
    and a participant between heartbeats (or a driver that has
    not started its serve loop) read as gone. Presence for
    routing is the shared truth: a fresh CONNECTION NOTE must
    carry the decision even when last_seen is stale."""
    import sqlite3

    from agentlink.protocol import now_ts
    tmp = tempfile.mkdtemp(prefix="agentlink-xr-")
    db, home, x3, home_url, x3_url = _setup(tmp, state_root)

    async def _t():
        a = Agent("xrnote-a", endpoint=home_url,
                  state_dir=str(state_root / "xrnote-a"))
        b = Agent("xrnote-b", endpoint=x3_url,
                  state_dir=str(state_root / "xrnote-b"))
        await a.start()
        await b.start()
        try:
            g = await a.group_create("xr-note", ["xrnote-b"])
            gid = g["group_id"]
            rid = (await a.room_open(gid))["room_id"]
            await b.room_join(rid)
            got = []

            @a.on_room_signal
            async def _hs(frame):
                got.append(frame)

            # Age a's last_seen far beyond the offline grace; its
            # connection NOTE (written at hello by the home relay)
            # stays fresh — the shared record says it is connected.
            conn = sqlite3.connect(db)
            conn.execute("UPDATE users SET last_seen = ?"
                         " WHERE username = ?",
                         (now_ts() - 3600, "xrnote-a"))
            conn.commit()
            conn.close()
            await b.room_signal(rid, "xrnote-a", "answer",
                                {"type": "answer", "sdp": "note-pin"})
            assert await wait_for(lambda: len(got) == 1), \
                "signal refused/routed nowhere on a stale last_seen"
            assert got[0]["kind"] == "answer"
        finally:
            for ag in (a, b):
                try:
                    await ag.close()
                except Exception:
                    pass

    run(_t())
    home.stop()
    x3.stop()


def test_legacy_composition_fallback_for_recordless_store(state_root):
    """The pre-1.3.9 audit-replay composition survives ONLY as the
    fallback for a store backend without shared room records —
    pinned so the fallback stays wired and honest: with
    rooms_open unavailable, the dashboard composes the room from
    the lifecycle audit, and a close removes it."""
    tmp = tempfile.mkdtemp(prefix="agentlink-xr-")
    db, home, x3, home_url, x3_url = _setup(tmp, state_root)
    store = home.relay.store
    store.rooms_open = None  # a backend without room records
    store.claim("legone", "Leg One")
    store.claim("legtwo", "Leg Two")
    for u in ("legone", "legtwo"):
        store.note_connection(u, home_url, home_url, home_url)
        store.touch(u)
    gid = store.create_group("leg-group", "legone", None)
    store.audit("room_opened", "legone", group_id=gid,
                status="r-leg1")
    store.audit("room_joined", "legtwo", group_id=gid,
                status="r-leg1")
    rooms = [r for r in _rooms(home.relay) if r["id"] == "r-leg1"]
    assert len(rooms) == 1
    assert sorted(rooms[0]["participants"]) == ["legone", "legtwo"]
    store.audit("room_closed", "legone", group_id=gid,
                status="r-leg1")
    assert [r for r in _rooms(home.relay)
            if r["id"] == "r-leg1"] == []
    home.stop()
    x3.stop()


def test_live_dead_mix_lists_only_live(state_root):
    """WS3: a room with one live + one dead participant lists
    only the live one — including when the dead participant was
    connected through the OTHER relay (its own relay reaps the
    shared record on disconnect)."""
    tmp = tempfile.mkdtemp(prefix="agentlink-xr-")
    db, home, x3, home_url, x3_url = _setup(tmp, state_root)

    async def _t():
        live = Agent("xrlive", endpoint=home_url,
                     state_dir=str(state_root / "xrlive"))
        dead = Agent("xrdead", endpoint=x3_url,
                     state_dir=str(state_root / "xrdead"))
        await live.start()
        await dead.start()
        try:
            g = await live.group_create("xr-mix", ["xrdead"])
            gid = g["id"] if "id" in g else g["group_id"]
            rid = (await live.room_open(gid))["room_id"]
            await dead.room_join(rid)
            assert await wait_for(lambda: any(
                r["id"] == rid
                and sorted(r["participants"]) == ["xrdead", "xrlive"]
                for r in _rooms(home.relay)))
            await dead._ws.close()  # unclosed death, via x3
            assert await wait_for(lambda: any(
                r["id"] == rid and r["participants"] == ["xrlive"]
                for r in _rooms(home.relay)))
            rec = home.relay.store.room_get(rid)
            assert rec is not None
            assert rec["participants"] == ["xrlive"]
        finally:
            try:
                await live.close()
            except Exception:
                pass
            try:
                await dead.close()
            except Exception:
                pass

    run(_t())
    home.stop()
    x3.stop()


def test_start_only_client_keeps_presence_past_grace(state_root):
    """v1.4.3 regression pin (fast leg) — the heartbeat belongs to
    the CONNECTION: a start()-only client (one-shot SDK embedding,
    the CLI posture — no run()/serve loop) must keep its shared
    last_seen advancing. Before the fix the ping loop lived only
    in run(), so a start()-only client's last_seen froze at its
    hello and brother relays read it offline after the 15s
    presence grace while it was connected and active."""
    tmp = tempfile.mkdtemp(prefix="agentlink-xr-hb-")
    db = str(Path(tmp) / "shared.db")
    home = RelayHandle(db, "xr-hb-home")
    url = home.start()

    async def _t():
        a = Agent("xrheartbeat", endpoint=url,
                  state_dir=str(state_root / "xrheartbeat"))
        await a.start()
        try:
            store = home.relay.store
            first = store.last_seen_of("xrheartbeat")
            assert first > 0
            await asyncio.sleep(12)
            later = store.last_seen_of("xrheartbeat")
            assert later >= first + 5, (first, later)
        finally:
            await a.close()

    run(_t())
    home.stop()


def test_cross_server_room_signal_after_presence_grace(state_root):
    """v1.4.3 regression pin — the exact v1.4.2 PRODUCTION room
    proof failure: phoenix (start()-only driver) opened a room on
    home, deploy-probe joined via x3, the offer crossed, and the
    ANSWER died peer_offline on x3 because phoenix's last_seen
    was 20s old — frozen at its hello, the grace being 15s. Wait
    past the grace after both hellos, then the both-ways signal
    cycle must complete."""
    tmp = tempfile.mkdtemp(prefix="agentlink-xr-grace-")
    db, home, x3, home_url, x3_url = _setup(tmp, state_root)

    async def _t():
        phx = Agent("xrgphoenix", endpoint=home_url,
                    state_dir=str(state_root / "xrgphoenix"))
        probe = Agent("xrgprobe", endpoint=x3_url,
                      state_dir=str(state_root / "xrgprobe"))
        await phx.start()
        await probe.start()
        try:
            # Past OFFLINE_GRACE_SECONDS (15) from BOTH hellos —
            # the window the production proof died in.
            await asyncio.sleep(17)
            g = await phx.group_create("xr-grace", ["xrgprobe"])
            gid = g["id"] if "id" in g else g["group_id"]
            rid = (await phx.room_open(gid))["room_id"]
            await probe.room_join(rid)
            got = {"probe": [], "phx": []}

            @probe.on_room_signal
            async def _ps(frame):
                got["probe"].append(frame)

            @phx.on_room_signal
            async def _hs(frame):
                got["phx"].append(frame)

            await phx.room_signal(rid, "xrgprobe", "offer",
                                  {"type": "offer", "sdp": "v=0 o"})
            assert await wait_for(lambda: len(got["probe"]) == 1)
            await probe.room_signal(rid, "xrgphoenix", "answer",
                                    {"type": "answer", "sdp": "v=0 a"})
            assert await wait_for(lambda: len(got["phx"]) == 1)
            assert got["phx"][0]["kind"] == "answer"
        finally:
            await phx.close()
            await probe.close()

    run(_t())
    home.stop()
    x3.stop()


def test_room_signals_flow_with_fleet_scan_wedged(state_root):
    """v1.4.4 pin — room signalling must not ride the fleet scan.
    The v1.4.3 production room proof: relays restarted, the
    health battery running, and an x3->home answer sat UNCLAIMED
    in the store for 25s+ because the only drain lived inside
    _fleet_scan_once, whose pass latency is unbounded under load.
    Wedge both relays' scan passes entirely; the dedicated room
    drain loop must still deliver signals both ways in seconds."""
    tmp = tempfile.mkdtemp(prefix="agentlink-xr-wedge-")
    db, home, x3, home_url, x3_url = _setup(tmp, state_root)

    async def _wedged():
        await asyncio.sleep(3600)

    home.relay._fleet_scan_once = _wedged
    x3.relay._fleet_scan_once = _wedged

    async def _t():
        phx = Agent("xrwphoenix", endpoint=home_url,
                    state_dir=str(state_root / "xrwphoenix"))
        probe = Agent("xrwprobe", endpoint=x3_url,
                      state_dir=str(state_root / "xrwprobe"))
        await phx.start()
        await probe.start()
        try:
            g = await phx.group_create("xr-wedge", ["xrwprobe"])
            gid = g["id"] if "id" in g else g["group_id"]
            rid = (await phx.room_open(gid))["room_id"]
            await probe.room_join(rid)
            got = {"probe": [], "phx": []}

            @probe.on_room_signal
            async def _ps(frame):
                got["probe"].append(frame)

            @phx.on_room_signal
            async def _hs(frame):
                got["phx"].append(frame)

            await phx.room_signal(rid, "xrwprobe", "offer",
                                  {"type": "offer", "sdp": "v=0 o"})
            assert await wait_for(lambda: len(got["probe"]) == 1,
                                  timeout=6)
            await probe.room_signal(rid, "xrwphoenix", "answer",
                                    {"type": "answer", "sdp": "v=0 a"})
            assert await wait_for(lambda: len(got["phx"]) == 1,
                                  timeout=6)
        finally:
            await phx.close()
            await probe.close()

    run(_t())
    home.stop()
    x3.stop()
