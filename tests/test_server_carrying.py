"""Server carrying + earned health tests (v1.3.0) — the owner's
passage model, made real.

Three friends, each with their own system. One friend's server is
sick and can't host — another friend hosts that server ON HIS OWN
system, while the first friend's brain (the agent) is untouched,
still on its own side. The carried server REMAINS its owner's
server: owner_agent is permanent; carried_by is only the temporary
helper whose machine runs it.

And health: a server's percentage is EARNED THROUGH TESTING, every
time. A brand-new server is UNRATED — no percentage, not eligible
to be ridden or to carry — until its battery (probe round-trips,
hello handshakes, registry write/read-back, a real message
round-trip, a chunked hash-verified file round-trip, heartbeat
stability) completes. There is no override: no env var, no config
value, no friendly default may set the number.

The drill below is the owner's acceptance shape, plus the extra
beat: carry -> traffic -> the CARRIER also falls -> a second
brother hops in -> home returns -> handback. Exactly-once is
proven by message-id set comparison, never by eyeballs.
"""

from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest

from agentlink.client import Agent
from agentlink.relay import Relay
from agentlink.store import Store

HOST = "127.0.0.1"


class RelayHandle:
    """A relay in its own thread/loop, ports pinned across restarts
    so a recovered home comes back at the SAME address."""

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

    def crash(self):
        """Sudden process death: background tasks die FIRST (no
        graceful release, no more heartbeats — the lease is left to
        expire on its own), then the listener and sockets die. The
        shared backend is untouched."""
        if self.relay is None or self.loop is None:
            return
        relay = self.relay

        async def _crash():
            for task in (relay._carrier_task, relay._health_task,
                         relay._server_hb_task, relay._scan_task):
                if task is not None:
                    task.cancel()
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
        fut = asyncio.run_coroutine_threadsafe(_crash(), self.loop)
        try:
            fut.result(timeout=10)
        except Exception:
            pass
        self.relay = None


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-carry-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=300))


async def wait_for(pred, timeout=30.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


def _sql(db, query, params=()):
    conn = sqlite3.connect(db)
    conn.execute(query, params)
    conn.commit()
    conn.close()


def _server_row(db, server_id):
    store = Store(db)
    return store.get_server(server_id)


# ---------------------------------------------------------------------------
# Earned health: unrated until tested; no override exists.
# ---------------------------------------------------------------------------

def test_new_server_is_unrated_until_battery_completes(tmp_path):
    db = str(tmp_path / "h.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  server_name="fresh-server", dashboard_enabled=False)
    # A brand-new server: NO percentage, not eligible for anything.
    assert relay._rated is False
    assert relay._compute_health() == -1
    assert relay._effective_capacity() == 0
    # Its registry row says the same: health -1 = UNRATED.
    relay._register_server_row()
    row = relay.store.get_server(relay.server_id)
    assert row["health"] == -1, row


def test_health_cannot_be_tampered_with(tmp_path, monkeypatch):
    # The v1.2.x env pin is abolished: setting it changes NOTHING.
    monkeypatch.setenv("AGENTLINK_SERVER_HEALTH", "5")
    db = str(tmp_path / "h2.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  server_name="tamper-server", dashboard_enabled=False)
    assert not hasattr(relay, "health_override")
    assert relay._compute_health() == -1  # still unrated, not 5
    # And no constructor/config surface accepts a health value.
    with pytest.raises(TypeError):
        Relay(host=HOST, port=0, db_path=db, health=42,
              dashboard_enabled=False)


def test_two_servers_different_measured_outcomes_differ(tmp_path):
    from test_peer_mesh import _craft_events
    a = Relay(host=HOST, port=0, db_path=str(tmp_path / "a.db"),
              server_name="server-a", dashboard_enabled=False)
    b = Relay(host=HOST, port=0, db_path=str(tmp_path / "b.db"),
              server_name="server-b", dashboard_enabled=False)
    a._rated = b._rated = True  # both past their first battery
    _craft_events(a, {"probe_ok": 500, "hello_ok": 500,
                      "reg_ok": 500, "msg_ok": 500, "file_ok": 500,
                      "hb_ok": 500, "scan_ok": 500})
    _craft_events(b, {"probe_ok": 500, "hello_ok": 500,
                      "reg_ok": 500, "msg_fail": 500, "file_ok": 500,
                      "hb_ok": 500, "scan_ok": 500})
    ha, hb = a._compute_health(), b._compute_health()
    assert ha == 100, ha
    assert hb == 85, hb  # every message round-trip failed: -15
    assert ha != hb


# ---------------------------------------------------------------------------
# Store-level claim mechanics: single-winner, lease, eligibility.
# ---------------------------------------------------------------------------

def _agent_server_row(store, owner="victim", endpoint="ws://h:1",
                      host_agent="victimhost"):
    store.register_server(
        f"{owner} server", endpoint, host_agent=host_agent,
        version="1.3.0", health=99, riders=0, capacity=9,
        server_id=f"{owner}-server", owner_agent=owner,
        home_host=host_agent)


def test_claim_is_single_winner_and_lease_bound(tmp_path):
    store = Store(str(tmp_path / "c.db"))
    _agent_server_row(store)
    # Home stops answering: heartbeat goes stale.
    _sql(store.path,
         "UPDATE servers SET home_last_seen = ?, last_seen = ?"
         " WHERE server_id = 'victim-server'",
         (int(time.time()) - 3600, int(time.time()) - 3600))
    now = int(time.time())
    won = store.claim_carry(
        "victim-server", carrier_id="carrier-a", carrier_agent="alice",
        endpoint="ws://a/carry/victim-server", carrier_health=99,
        carrier_capacity=9, now=now, lease_seconds=45)
    assert won is not None
    assert won["carry_state"] == "carried"
    assert won["carried_by"] == "alice"
    # Ownership did NOT move: the helper is not the owner.
    assert won["owner_agent"] == "victim"
    assert won["endpoint"] == "ws://a/carry/victim-server"
    # A second brother racing the same instant loses: live lease.
    lost = store.claim_carry(
        "victim-server", carrier_id="carrier-b", carrier_agent="bob",
        endpoint="ws://b/carry/victim-server", carrier_health=100,
        carrier_capacity=10, now=now, lease_seconds=45)
    assert lost is None
    # The loser cannot renew or release a lease it does not hold.
    assert store.renew_carry(
        "victim-server", carrier_id="carrier-b", token="nope",
        carrier_agent="bob", endpoint="ws://b/x", health=99,
        riders=0, capacity=9, now=now) is False
    assert store.release_carry(
        "victim-server", carrier_id="carrier-b", token="nope",
        now=now) is False
    # The holder renews, then releases: row flips home-side, owner
    # intact, helper gone.
    assert store.renew_carry(
        "victim-server", carrier_id="carrier-a",
        token=won["carry_lease_token"], carrier_agent="alice",
        endpoint="ws://a/carry/victim-server", health=98, riders=1,
        capacity=9, now=now) is True
    assert store.release_carry(
        "victim-server", carrier_id="carrier-a",
        token=won["carry_lease_token"], now=now) is True
    row = store.get_server("victim-server")
    assert row["carry_state"] == "down"
    assert row["carried_by"] == "" and row["endpoint"] == "ws://h:1"
    assert row["owner_agent"] == "victim"


def test_claim_refusals_unrated_sick_full_and_home_alive(tmp_path):
    store = Store(str(tmp_path / "c2.db"))
    _agent_server_row(store)
    now = int(time.time())
    # Home still answering (fresh heartbeat): nobody may claim.
    assert store.claim_carry(
        "victim-server", carrier_id="c1", carrier_agent="alice",
        endpoint="ws://a/carry/victim-server", carrier_health=99,
        carrier_capacity=9, now=now) is None
    _sql(store.path,
         "UPDATE servers SET home_last_seen = ? WHERE server_id = ?",
         (now - 3600, "victim-server"))
    # UNRATED carrier (health -1) may not carry.
    assert store.claim_carry(
        "victim-server", carrier_id="c1", carrier_agent="alice",
        endpoint="ws://a/carry/victim-server", carrier_health=-1,
        carrier_capacity=0, now=now) is None
    # At/below the floor may not carry.
    assert store.claim_carry(
        "victim-server", carrier_id="c1", carrier_agent="alice",
        endpoint="ws://a/carry/victim-server", carrier_health=50,
        carrier_capacity=5, now=now) is None
    # At carrying capacity may not carry one more.
    assert store.claim_carry(
        "victim-server", carrier_id="c1", carrier_agent="alice",
        endpoint="ws://a/carry/victim-server", carrier_health=99,
        carrier_capacity=3, carrier_carrying=3, now=now) is None
    # A server never carries itself.
    assert store.claim_carry(
        "victim-server", carrier_id="victim-server",
        carrier_agent="victim",
        endpoint="ws://a/carry/victim-server", carrier_health=99,
        carrier_capacity=9, now=now) is None


def test_better_brother_wins_the_claim(tmp_path):
    store = Store(str(tmp_path / "c3.db"))
    _agent_server_row(store)
    now = int(time.time())
    _sql(store.path,
         "UPDATE servers SET home_last_seen = ? WHERE server_id = ?",
         (now - 3600, "victim-server"))
    # A live, healthier brother is registered in the mesh...
    store.register_server("Strong Relay", "ws://strong:1",
                          host_agent="strong", version="1.3.0",
                          health=99, riders=0, capacity=9,
                          server_id="strong-server")
    # ...so a weaker claimant is refused while the strong one lives.
    assert store.claim_carry(
        "victim-server", carrier_id="weak-server",
        carrier_agent="weak", endpoint="ws://weak/carry/victim-server",
        carrier_health=80, carrier_capacity=8, now=now) is None
    # The strong brother itself claims cleanly.
    won = store.claim_carry(
        "victim-server", carrier_id="strong-server",
        carrier_agent="strong",
        endpoint="ws://strong:1/carry/victim-server",
        carrier_health=99, carrier_capacity=9, now=now)
    assert won is not None and won["carried_by"] == "strong"


# ---------------------------------------------------------------------------
# The carried-by label (v1.3.8): an agent-less carrier leaves
# carried_by EMPTY in the row — composition must resolve the
# carrier from its recorded server id, or honestly omit the name.
# ---------------------------------------------------------------------------

def test_carry_label_resolution_ladder():
    """The resolution ladder, rung by rung: a recorded agent name
    wins; a carrier id resolving to an agent-hosted server yields
    that host agent; a carrier id resolving to an agent-less
    operator relay yields its LABEL (no '@' — a server is not an
    agent); an unresolvable id yields the bare state. The wart
    shape — 'carried by @' with nothing after it — is unreachable
    on every rung."""
    by_id = {
        "srv-a": {"server_id": "srv-a", "label": "A Relay",
                  "host_agent": "alice"},
        "srv-op": {"server_id": "srv-op", "label": "Operator Relay",
                   "host_agent": ""},
    }
    base = {"carry_state": "carried", "carried_by": "",
            "carried_by_id": ""}
    assert Relay._carry_label({**base, "carried_by": "carol"}) == \
        "carried by @carol"
    assert Relay._carry_label({**base, "carried_by_id": "srv-a"},
                              by_id) == "carried by @alice"
    assert Relay._carry_label({**base, "carried_by_id": "srv-op"},
                              by_id) == "carried by Operator Relay"
    assert Relay._carry_label({**base, "carried_by_id": "ghost"},
                              by_id) == "carried"
    assert Relay._carry_label(dict(base)) == "carried"
    assert Relay._carry_label({"carry_state": "home"}) == "at home"
    assert Relay._carry_label({"carry_state": "down"}) == \
        "down — awaiting carrier"
    assert Relay._carry_label({"carry_state": ""}) == ""
    # _server_entry alone (no set context) never dangles either.
    entry = Relay.__new__(Relay)._server_entry({
        "owner_agent": "victim", "carry_state": "carried",
        "carried_by": "", "carried_by_id": "srv-op",
        "carry_lease_until": int(time.time()) + 60,
        "endpoint": "ws://victim", "server_id": "victim-server"})
    assert entry["carry_state"] == "carried"
    assert entry["carry_state_label"] == "carried"


def test_agentless_carrier_dashboard_label(tmp_path):
    """The production shape that produced the wart (v1.3.4 drill):
    an OPERATOR relay — no host_agent, exactly like the Phoenix
    Peer Relay — carries a fallen per-agent server. The claim
    lands with carried_by='' and carried_by_id set. Composition
    (the dashboard payload) must name the carrier truthfully by
    its server label, on BOTH the Servers entry and the owner's
    per-agent server line, and never render 'carried by @'."""
    tmp = tempfile.mkdtemp(prefix="agentlink-carry-label-")
    db = str(Path(tmp) / "shared.db")
    victim_home = RelayHandle(
        db, "Victim Server", host_agent="victim",
        owner_agent="victim", server_id="victim-server")
    operator = RelayHandle(db, "Operator Relay")  # no host_agent
    victim_home.start()
    operator.start()

    async def _t():
        store = Store(db)
        store.claim("victim", "Victim")
        assert await wait_for(
            lambda: victim_home.relay._rated
            and operator.relay._rated, timeout=60)
        assert await wait_for(
            lambda: _server_row(db, "victim-server")["health"] > 50,
            timeout=30)
        victim_home.crash()
        _sql(db, "UPDATE servers SET home_last_seen = ?,"
                 " last_seen = ? WHERE server_id = ?",
             (int(time.time()) - 3600, int(time.time()) - 3600,
              "victim-server"))
        assert await wait_for(
            lambda: _server_row(db, "victim-server")
            ["carry_state"] == "carried", timeout=40)
        row = _server_row(db, "victim-server")
        # The premise, pinned: this is the row shape production
        # produced — state carried, carrier NAME empty, carrier
        # ID recorded.
        assert row["carried_by"] == "", row
        assert row["carried_by_id"] == operator.relay.server_id, row

        data = operator.relay._dashboard_data()
        srow = next(s for s in data["servers"]
                    if s.get("server_id") == "victim-server")
        assert srow["carry_state"] == "carried", srow
        assert srow["carry_state_label"] == \
            "carried by Operator Relay", srow
        urow = next(u for u in data["users"]
                    if u["username"] == "victim")
        assert urow["server_state"] == "carried", urow
        assert urow["server_state_label"] == \
            "carried by Operator Relay", urow
        # The raw field stays truthful (the row carries no agent
        # name); only the composed label resolves it.
        assert urow["server_carried_by"] == "", urow
        store.close()
    try:
        asyncio.run(asyncio.wait_for(_t(), timeout=180))
    finally:
        operator.stop()
        victim_home.stop()


# ---------------------------------------------------------------------------
# The full drill: carry -> traffic -> carrier falls -> hop -> handback.
# ---------------------------------------------------------------------------

def test_server_carrying_drill(state_root, tmp_path):
    tmp = tempfile.mkdtemp(prefix="agentlink-carry-")
    db = str(Path(tmp) / "shared.db")
    # Three friends: the victim's own server (owned by @victim,
    # hosted at home by @victim itself), and two brothers' relays.
    victim_home = RelayHandle(
        db, "Victim Server", host_agent="victim",
        owner_agent="victim", server_id="victim-server")
    brother_a = RelayHandle(db, "Brother A Relay", host_agent="alice")
    brother_b = RelayHandle(db, "Brother B Relay", host_agent="bob")
    home_url = victim_home.start()
    a_url = brother_a.start()
    b_url = brother_b.start()
    sent_ids: set[str] = set()

    async def _t():
        store = Store(db)
        # Everyone earns their rating through the battery first —
        # and the registry row must show the EARNED percentage
        # (the cycle that flips _rated still published UNRATED;
        # the next heartbeat publishes the score).
        assert await wait_for(
            lambda: victim_home.relay._rated
            and brother_a.relay._rated and brother_b.relay._rated,
            timeout=60)
        assert await wait_for(
            lambda: _server_row(db, "victim-server")["health"] > 50,
            timeout=30)
        row = _server_row(db, "victim-server")
        assert row["owner_agent"] == "victim"
        assert row["carry_state"] == "home"
        assert row["health"] > 50, row

        boss = Agent("boss", endpoint=home_url,
                     state_dir=str(state_root / "boss"))
        victim = Agent("victim", endpoint=home_url,
                       state_dir=str(state_root / "victim"))

        @victim.on_message
        async def _reply(msg):
            return f"roger {msg['body']}"

        def _work(work, ctx):
            async def _go():
                await victim.deliver_work(work["id"],
                                          body="carried delivery")
            asyncio.create_task(_go())
        victim.on_work(_work)

        boss_task = asyncio.create_task(
            boss.run(reconnect_delay=0.5, home_probe_interval=1.0))
        victim_task = asyncio.create_task(
            victim.run(reconnect_delay=0.5, home_probe_interval=1.0))
        try:
            assert await wait_for(
                lambda: victim_home.relay
                and "boss" in victim_home.relay.peers
                and "victim" in victim_home.relay.peers)
            # Baseline at home.
            s1 = await boss.send_message("victim", "before the fall")
            sent_ids.add(s1["id"])
            r1 = await boss.wait_reply(s1["id"], timeout=15)
            assert r1["body"] == "roger before the fall"
            sent_ids.add(r1["id"])

            # THE VICTIM'S SERVER DIES. Its brain (the agent) is
            # untouched and keeps running — only the server fell.
            victim_home.crash()
            _sql(db, "UPDATE servers SET home_last_seen = ?,"
                     " last_seen = ? WHERE server_id = ?",
                 (int(time.time()) - 3600, int(time.time()) - 3600,
                  "victim-server"))
            # A brother claims the carry — exactly one of them.
            assert await wait_for(
                lambda: _server_row(db, "victim-server")
                ["carry_state"] == "carried", timeout=40)
            row = _server_row(db, "victim-server")
            assert row["owner_agent"] == "victim"  # STILL the owner
            first_carrier = row["carried_by"]
            assert first_carrier in ("alice", "bob"), row
            carrier = brother_a if first_carrier == "alice" \
                else brother_b
            other = brother_b if carrier is brother_a else brother_a
            alias1 = row["endpoint"]
            assert alias1 != home_url and "carry" in alias1, row
            # The dashboard says it plainly, on the carrier's view.
            data = carrier.relay._dashboard_data()
            srow = next(s for s in data["servers"]
                        if s.get("server_id") == "victim-server")
            assert srow["carry_state"] == "carried", srow
            assert srow["carry_state_label"] == \
                f"carried by @{first_carrier}", srow
            assert srow["owner_agent"] == "victim", srow

            # The victim's agent rides on — through a brother —
            # and KEEPS WORKING. To prove the CARRIED IDENTITY
            # itself serves (not just the carrier's own endpoint),
            # a fresh agent connects through the carry alias:
            assert await wait_for(
                lambda: (carrier.relay
                         and "victim" in carrier.relay.peers)
                or (other.relay and "victim" in other.relay.peers),
                timeout=40)
            probe = Agent("probe", endpoint=home_url,
                          state_dir=str(state_root / "probe"))
            await probe.start(alias1)
            try:
                assert "probe" in carrier.relay.peers
                assert carrier.relay.peers["probe"].server_id == \
                    "victim-server", carrier.relay.peers["probe"]
                ps = await probe.send_message(
                    "victim", "via the carried server")
                sent_ids.add(ps["id"])
                pr = await probe.wait_reply(ps["id"], timeout=20)
                assert pr["body"] == "roger via the carried server"
                sent_ids.add(pr["id"])
            finally:
                await probe.close()
            # DM round-trip through the carry, on the mesh:
            s2 = await boss.send_message("victim",
                                         "through the carry")
            sent_ids.add(s2["id"])
            r2 = await boss.wait_reply(s2["id"], timeout=20)
            assert r2["body"] == "roger through the carry"
            sent_ids.add(r2["id"])
            # …and work, delivered with a VERIFIED signed proof:
            works = await boss.assign_work(
                ["victim"], "carry micro-work",
                instructions="deliver while your server is carried")
            wid = works[0]["id"]
            assert await wait_for(
                lambda: store.get_work(wid)["status"]
                in ("delivered", "completed"), timeout=25)
            raw = store.get_work(wid)
            assert raw["proof_verified"] == 1, raw

            # THE CARRIER ALSO FALLS. No graceful release — the
            # lease is left behind to expire.
            carrier.crash()
            _sql(db, "UPDATE servers SET carry_lease_until = ?"
                     " WHERE server_id = ?",
                 (int(time.time()) - 1, "victim-server"))
            # The second brother hops in and claims the carry.
            assert await wait_for(
                lambda: _server_row(db, "victim-server")
                .get("carried_by_id") == other.relay.server_id,
                timeout=40)
            row = _server_row(db, "victim-server")
            assert row["owner_agent"] == "victim", row
            assert await wait_for(
                lambda: other.relay and "victim" in other.relay.peers
                and "boss" in other.relay.peers, timeout=40)
            s3 = await boss.send_message("victim", "second brother")
            sent_ids.add(s3["id"])
            r3 = await boss.wait_reply(s3["id"], timeout=20)
            assert r3["body"] == "roger second brother"
            sent_ids.add(r3["id"])

            # HOME RETURNS, strongly and continuously. The holding
            # carrier observes it answering for the handback window
            # (the test stamps the continuity clock — the window
            # itself is timing.CARRY_HANDBACK_SECONDS) and releases.
            victim_home.start()
            assert await wait_for(
                lambda: victim_home.relay
                and "victim" in victim_home.relay.peers, timeout=40)
            other.relay._home_ok_since["victim-server"] = \
                int(time.time()) - 61
            other.relay._carrier_tick_sync(
                {"victim-server": True})
            row = _server_row(db, "victim-server")
            assert row["carried_by"] == "", row
            # The home instance's next heartbeat flips it home.
            victim_home.relay._register_server_row()
            row = _server_row(db, "victim-server")
            assert row["carry_state"] == "home", row
            assert row["endpoint"] == home_url, row
            assert row["owner_agent"] == "victim", row
            # Both agents migrate back home and keep working.
            assert await wait_for(
                lambda: victim_home.relay
                and "boss" in victim_home.relay.peers
                and "victim" in victim_home.relay.peers, timeout=40)
            assert boss.current_endpoint == home_url
            assert victim.current_endpoint == home_url
            s4 = await boss.send_message("victim", "home again")
            sent_ids.add(s4["id"])
            r4 = await boss.wait_reply(s4["id"], timeout=15)
            assert r4["body"] == "roger home again"
            sent_ids.add(r4["id"])

            # EXACTLY-ONCE across kill, carry, hop and handback.
            received: list[str] = []
            for a in (boss, victim, probe):
                ids = [m["id"] for m in a.messages if m.get("id")]
                assert len(ids) == len(set(ids)), \
                    f"duplicate delivery to {a.username}: {ids}"
                received.extend(ids)
            for a in (boss, victim, probe):
                for m in a.messages:
                    if m.get("in_reply_to") in sent_ids:
                        sent_ids.add(m["id"])
            assert set(received) == sent_ids, (
                f"lost={sent_ids - set(received)} "
                f"extra={set(received) - sent_ids}")
        finally:
            for t in (boss_task, victim_task):
                t.cancel()
            for a in (boss, victim):
                try:
                    await a.close()
                except Exception:
                    pass
    run(_t())
    victim_home.stop()
    brother_a.stop()
    brother_b.stop()


def test_first_contact_refusal_never_strands_identity(state_root):
    """Regression (v1.3.0 root-cause find): rider admission used to
    run AFTER the identity claim, so a first-ever hello refused by
    an UNRATED server claimed the username server-side while the
    client never received its secret — every retry then died as
    username_taken and the daemon exited. Admission now runs
    first: a refused first contact claims NOTHING, and the same
    agent boards cleanly once the server earns its rating."""
    tmp = tempfile.mkdtemp(prefix="agentlink-carry-strand-")
    db = str(Path(tmp) / "shared.db")
    peer = RelayHandle(db, "gated-peer")
    peer_url = peer.start()

    async def _t():
        agent = Agent("newcomer", endpoint="ws://127.0.0.1:9",
                      fallbacks=[peer_url],
                      state_dir=str(state_root / "newcomer"),
                      workspace=str(state_root))
        # The peer is still UNRATED: the rider hello is refused...
        from agentlink.client import RegistrationFailed
        with pytest.raises(RegistrationFailed) as ei:
            await agent.start(peer_url)
        assert "server_unrated" in str(ei.value)
        await agent.close()
        # ...and the refusal claimed NOTHING in the store.
        store = Store(db)
        assert store.exists("newcomer") is False
        # Once the battery earns the rating, the very same agent
        # boards with the very same identity — no stranding.
        assert await wait_for(lambda: peer.relay._rated, timeout=60)
        await agent.start(peer_url)
        try:
            assert "newcomer" in peer.relay.peers
            assert store.exists("newcomer") is True
        finally:
            await agent.close()
    run(_t())
    peer.stop()


def test_sick_or_full_brother_never_claims(state_root):
    tmp = tempfile.mkdtemp(prefix="agentlink-carry-sick-")
    db = str(Path(tmp) / "shared.db")
    victim_home = RelayHandle(
        db, "Victim Server", host_agent="victim",
        owner_agent="victim", server_id="victim-server")
    sick = RelayHandle(db, "Sick Relay", host_agent="sick")
    home_url = victim_home.start()
    sick.start()

    async def _t():
        from test_peer_mesh import _craft_events
        assert await wait_for(
            lambda: victim_home.relay._rated and sick.relay._rated,
            timeout=60)
        # The only brother's measured health collapses to the floor.
        _craft_events(sick.relay, {
            "probe_fail": 2000, "hello_fail": 2000, "msg_fail": 2000,
            "reg_ok": 2000, "file_ok": 2000, "hb_ok": 2000,
            "scan_ok": 2000})
        assert sick.relay._compute_health() <= 50
        victim_home.crash()
        _sql(db, "UPDATE servers SET home_last_seen = ?,"
                 " last_seen = ? WHERE server_id = ?",
             (int(time.time()) - 3600, int(time.time()) - 3600,
              "victim-server"))
        # Several watch cycles pass: the sick brother must NOT
        # claim, and the server stays honestly DOWN.
        for _ in range(3):
            sick.relay._carrier_tick_sync({"victim-server": False})
        row = _server_row(db, "victim-server")
        assert row["carry_state"] != "carried", row
        assert row["carried_by"] == "", row
        data = sick.relay._dashboard_data()
        srow = next(s for s in data["servers"]
                    if s.get("server_id") == "victim-server")
        assert srow["carry_state"] == "down", srow
        assert srow["carry_state_label"] == \
            "down — awaiting carrier", srow
    run(_t())
    victim_home.stop()
    sick.stop()
