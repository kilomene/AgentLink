"""Presence truth (v1.3.4) — the dashboard must state BACKEND
facts, never the serving relay's local observations.

THE DEFECT (flagged by the v1.3.3 crew, confirmed live):
Relay._dashboard_data() computed each user's `online` from the
SERVING relay's local peer table only. deploy-probe — registered
and heartbeating on its own server (x3, the per-agent-server
topology of v1.3.1) — read "offline — work protected" on the home
dashboard while actually online. The same local lie lived in the
agent-facing directory call. And the Voice Rooms view read only
the serving relay's local room table, so rooms hosted by a brother
server were invisible.

THE FIX, pinned here:
* every hello + heartbeat cadence notes WHERE the agent is
  connected in the shared store (connection registry);
* presence composes from the shared last_seen (the timing law:
  5s heartbeat, 15s grace) and the current server from the
  freshest connection note, labelled honestly — "online (home)",
  "online (via <peer>)", "online (own server)", "online (via
  carried server)", or a bare "online" when the heartbeat is
  fresh but the server is momentarily unknown (never a guess);
* offline shows the store's last_seen, never None-by-locality;
* servers name their live riders and the brothers' servers they
  carry, joined from the same backend facts on every dashboard;
* voice rooms compose from the shared room-lifecycle audit,
  merged with the serving relay's own live rooms.
"""

from __future__ import annotations

import asyncio
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest

from agentlink.protocol import now_ts
from agentlink.relay import Peer, Relay
from agentlink.store import Store

HOME_EP = "ws://127.0.0.1:9101"
PEER_EP = "ws://127.0.0.1:9102"
PROBE_EP = "ws://127.0.0.1:9103"
PROBE_SID = "probe-server"


def _store(tmp_path) -> Store:
    return Store(str(tmp_path / "shared.db"))


def _relay(store, name, ep, **kw) -> Relay:
    return Relay(host="127.0.0.1", port=0,
                 db_path=str(Path(store.path).with_name("unused.db")),
                 backend_store=store, server_name=name,
                 public_endpoint=ep, dashboard_enabled=False, **kw)


def _connect(relay: Relay, store: Store, username: str,
             server_id: str, conn_endpoint: str, home_endpoint: str):
    """Simulate a live connection on `relay` exactly as its hello
    path records it: peer object + shared touch + connection note."""
    peer = Peer(ws=None, username=username, last_seen=now_ts(),
                connected_at=now_ts(), home_endpoint=home_endpoint,
                server_id=server_id, conn_endpoint=conn_endpoint)
    relay.peers[username] = peer
    store.touch(username)
    relay._note_connection(peer)
    return peer


def _user(data, name):
    for u in data["users"]:
        if u["username"] == name:
            return u
    raise AssertionError(f"user {name} missing")


def _server(data, sid):
    for s in data["servers"]:
        if s.get("server_id") == sid:
            return s
    raise AssertionError(f"server {sid} missing from "
                         f"{[s.get('server_id') for s in data['servers']]}")


def _mesh(tmp_path):
    store = _store(tmp_path)
    home = _relay(store, "Home Relay", HOME_EP)
    peer = _relay(store, "Peer Relay", PEER_EP)
    store.register_server("Home Relay", HOME_EP, server_id=HOME_EP,
                          health=99)
    store.register_server("Peer Relay", PEER_EP, server_id=PEER_EP,
                          health=100)
    return store, home, peer


def test_agent_on_brother_server_reads_online_on_home_dashboard(tmp_path):
    """THE core defect: connected ONLY to the peer relay, the agent
    must read online — via that peer — on the HOME dashboard."""
    store, home, peer = _mesh(tmp_path)
    store.claim("rider", "Rider")
    _connect(peer, store, "rider", PEER_EP, PEER_EP, HOME_EP)

    data = home._dashboard_data()
    u = _user(data, "rider")
    assert u["online"] is True
    assert u["reachability"] == "online (via Peer Relay)"
    assert u["current_server"]["server_id"] == PEER_EP
    assert u["current_server"]["how"] == "via"
    assert u["last_seen"] is not None
    assert "rider" in data["online"]
    # The peer's own dashboard states the same truth.
    u2 = _user(peer._dashboard_data(), "rider")
    assert u2["online"] is True
    assert u2["reachability"] == "online (via Peer Relay)"
    # And the Servers view names the rider on the peer, live.
    assert _server(data, PEER_EP)["riding_now"] == ["rider"]
    assert _server(data, HOME_EP)["riding_now"] == []


def test_agent_at_home_reads_home(tmp_path):
    store, home, peer = _mesh(tmp_path)
    store.claim("local", "Local")
    _connect(home, store, "local", HOME_EP, HOME_EP, HOME_EP)
    u = _user(peer._dashboard_data(), "local")
    assert u["online"] is True
    assert u["reachability"] == "online (home)"
    assert u["current_server"]["server_id"] == HOME_EP


def test_own_server_label(tmp_path):
    """An agent connected to its OWN per-agent server reads
    'online (own server)' on every dashboard."""
    store, home, peer = _mesh(tmp_path)
    store.claim("probe", "Probe")
    own = _relay(store, "Probe Server", PROBE_EP,
                 server_id=PROBE_SID, owner_agent="probe")
    store.register_server("Probe Server", PROBE_EP,
                          server_id=PROBE_SID, owner_agent="probe",
                          home_endpoint=PROBE_EP, health=98)
    _connect(own, store, "probe", PROBE_SID, PROBE_EP, PROBE_EP)
    u = _user(home._dashboard_data(), "probe")
    assert u["online"] is True
    assert u["reachability"] == "online (own server)"
    assert u["current_server"]["owner_agent"] == "probe"
    assert u["current_server"]["how"] == "own"


def test_carried_server_label_and_carrier_view(tmp_path):
    """Probe's server is DOWN at home and CARRIED by the peer;
    probe, connected through the carry alias, reads 'online (via
    carried server)', and the peer's server entry names the
    brother's server it is carrying."""
    store, home, peer = _mesh(tmp_path)
    store.claim("probe", "Probe")
    store.register_server("Probe Server", PROBE_EP,
                          server_id=PROBE_SID, owner_agent="probe",
                          home_endpoint=PROBE_EP, health=98)
    alias = PEER_EP + "?carry=" + PROBE_SID
    conn = sqlite3.connect(store.path)
    conn.execute(
        "UPDATE servers SET carry_state = 'carried',"
        " carried_by = 'helper', carried_by_id = ?,"
        " carry_endpoint = ?, endpoint = ?,"
        " carry_lease_until = ?, last_seen = ?"
        " WHERE server_id = ?",
        (PEER_EP, alias, alias, now_ts() + 300, now_ts(), PROBE_SID))
    conn.commit()
    conn.close()
    _connect(peer, store, "probe", PROBE_SID, alias, PROBE_EP)

    data = home._dashboard_data()
    u = _user(data, "probe")
    assert u["online"] is True
    assert u["reachability"] == "online (via carried server)"
    assert u["current_server"]["how"] == "carried"
    assert u["current_server"]["carried_by"] == "helper"
    carrying = _server(data, PEER_EP)["carrying_now"]
    assert [c["owner_agent"] for c in carrying] == ["probe"]
    assert carrying[0]["server_id"] == PROBE_SID
    # The carried server itself still belongs to probe, at its
    # permanent home endpoint, in state carried.
    srv = _server(data, PROBE_SID)
    assert srv["owner_agent"] == "probe"
    assert srv["carry_state"] == "carried"


def test_offline_truth_carries_store_last_seen(tmp_path):
    store, home, peer = _mesh(tmp_path)
    store.claim("ghost", "Ghost")
    old = now_ts() - 3600
    conn = sqlite3.connect(store.path)
    conn.execute("UPDATE users SET last_seen = ? WHERE username = ?",
                 (old, "ghost"))
    conn.commit()
    conn.close()
    u = _user(home._dashboard_data(), "ghost")
    assert u["online"] is False
    assert u["reachability"] == "unreachable — work protected"
    assert u["last_seen"] == old
    assert u["current_server"] is None


def test_fresh_heartbeat_unknown_server_never_guessed(tmp_path):
    """A fresh shared heartbeat with an AGED-OUT connection note
    (the migration instant): online is a fact, the server is not
    — the dashboard says 'online' and names no server."""
    store, home, peer = _mesh(tmp_path)
    store.claim("moving", "Moving")
    store.note_connection("moving", PEER_EP, PEER_EP, HOME_EP)
    conn = sqlite3.connect(store.path)
    conn.execute("UPDATE connections SET updated_at = ?"
                 " WHERE username = ?", (now_ts() - 3600, "moving"))
    conn.commit()
    conn.close()
    store.touch("moving")
    u = _user(home._dashboard_data(), "moving")
    assert u["online"] is True
    assert u["reachability"] == "online"
    assert u["current_server"] is None


def test_rooms_compose_backend_wide(tmp_path):
    """A room opened on a brother server (its lifecycle landed in
    the shared audit) is a room on THIS dashboard; closing it
    removes it; the local relay's own live rooms merge in."""
    store, home, peer = _mesh(tmp_path)
    store.claim("probe", "Probe")
    store.claim("phoenix", "Phoenix")
    gid = store.create_group("room-group", "phoenix", None)
    store.audit("room_opened", "probe", group_id=gid, status="r-bro1")
    store.audit("room_joined", "phoenix", group_id=gid,
                status="r-bro1")
    rooms = home._dashboard_data()["rooms"]
    mine = [r for r in rooms if r["id"] == "r-bro1"]
    assert len(mine) == 1
    assert sorted(mine[0]["participants"]) == ["phoenix", "probe"]
    assert mine[0]["creator"] == "probe"
    store.audit("room_closed", "probe", group_id=gid, status="r-bro1")
    rooms = home._dashboard_data()["rooms"]
    assert [r for r in rooms if r["id"] == "r-bro1"] == []
    home.rooms["r-local"] = {"group_id": gid, "creator": "phoenix",
                             "participants": {"phoenix"},
                             "opened_at": now_ts()}
    rooms = home._dashboard_data()["rooms"]
    assert [r["id"] for r in rooms] == ["r-local"]


def test_digest_moves_with_backend_events(tmp_path):
    store, home, peer = _mesh(tmp_path)
    d0 = store.dashboard_digest()
    store.claim("someone", "Someone")
    store.touch("someone")
    d1 = store.dashboard_digest()
    assert d1 != d0
    store.note_connection("someone", PEER_EP, PEER_EP, HOME_EP)
    d2 = store.dashboard_digest()
    assert d2 != d1
    store.audit("online", "someone")
    assert store.dashboard_digest() != d2
    assert home._backend_digest() == store.dashboard_digest()


# -- end-to-end: a real agent on a real brother relay -----------------

HOST = "127.0.0.1"


class _Handle:
    """Two real relays sharing ONE backend file (the peer-mesh
    harness shape, narrowed to what this pin needs)."""

    def __init__(self, db, name):
        self.db = db
        self.name = name
        self.relay = None
        self.loop = None
        self.port = 0

    def start(self):
        import socket as _s
        _tmp = _s.socket()
        _tmp.bind((HOST, 0))
        self.port = _tmp.getsockname()[1]
        _tmp.close()
        self.relay = Relay(
            host=HOST, port=self.port, db_path=self.db,
            server_name=self.name, dashboard_password="test-pass",
            dashboard_port=0,
            public_endpoint=f"ws://{HOST}:{self.port}")
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

        threading.Thread(target=_thread, daemon=True).start()
        assert ready.wait(timeout=15)
        return f"ws://{HOST}:{self.port}"

    def stop(self):
        if self.relay is not None and self.loop is not None:
            fut = asyncio.run_coroutine_threadsafe(
                self.relay.stop(), self.loop)
            try:
                fut.result(timeout=10)
            except Exception:
                pass
            self.relay = None


def test_e2e_agent_on_brother_reads_online_on_home_dashboard(tmp_path):
    from agentlink.client import Agent
    db = str(tmp_path / "shared.db")
    home = _Handle(db, "home-server")
    peer = _Handle(db, "peer-server")
    home_url = home.start()
    peer_url = peer.start()
    state = tempfile.mkdtemp(prefix="agentlink-presence-")

    async def _t():
        remote = Agent("remote-one", endpoint=peer_url,
                       state_dir=str(Path(state) / "remote"))
        local = Agent("local-one", endpoint=home_url,
                      state_dir=str(Path(state) / "local"))
        try:
            await remote.start()
            await local.start()
            # The agent connected ONLY to the peer relay...
            assert home.relay is not None
            assert "remote-one" not in home.relay.peers
            # ...yet the HOME dashboard states the backend truth.
            data = home.relay._dashboard_data()
            u = _user(data, "remote-one")
            assert u["online"] is True
            assert u["current_server"]["label"] == "peer-server"
            assert u["reachability"] == "online (home)"
            assert "remote-one" in data["online"]
            # And the agent-facing directory agrees.
            rows = await local.directory("remote-one")
            row = next(r for r in rows
                       if r["username"] == "remote-one")
            assert row["online"] is True
        finally:
            await remote.close()
            await local.close()

    try:
        asyncio.run(asyncio.wait_for(_t(), timeout=60))
    finally:
        home.stop()
        peer.stop()
