"""v1.6.2 stability pins.

B1 — earned health survives restarts: a relay whose registry row
carries a rating earned in a previous boot publishes that rating
during the re-earning window instead of deflecting riders as
UNRATED; fresh/stale/unrated rows still start UNRATED.

B2 — the welcome is not blocked behind hello record writes: with a
store whose record setters are artificially slow, a hello's welcome
must arrive fast (the records are deferred past the welcome), and
the records must still land on the row.

B3 — close-code telemetry: disconnect paths on both sides log the
WebSocket close code/reason.
"""
import asyncio
import inspect
import logging
import threading
import time
from pathlib import Path

import pytest

from agentlink.client import Agent
from agentlink.relay import Relay
from agentlink.store import Store
from agentlink.timing import HEALTH_INITIAL_CYCLES, HEALTH_UNRATED

HOST = "127.0.0.1"


async def wait_for(pred, timeout=30.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


class RelayHandle:
    """A relay in its own thread/loop (same harness shape as the
    peer-mesh tests)."""

    def __init__(self, db, name, **relay_kw):
        self.db = db
        self.name = name
        self.relay_kw = relay_kw
        self.relay = None
        self.loop = None
        self.thread = None
        self.port = 0
        self.dash_port = 0

    def build(self):
        import socket as _s
        _tmp = _s.socket()
        _tmp.bind((HOST, 0))
        self.port = _tmp.getsockname()[1]
        _tmp.close()
        self.relay = Relay(host=HOST, port=self.port, db_path=self.db,
                           server_name=self.name,
                           dashboard_password="<redacted>",
                           dashboard_port=self.dash_port,
                           public_endpoint=f"ws://{HOST}:{self.port}",
                           **self.relay_kw)
        return self.relay

    def start(self):
        if self.relay is None:
            self.build()
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
        assert ready.wait(timeout=15)
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


def _unstarted_relay(tmp_path, name="home-server", **kw):
    db = str(Path(tmp_path) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db, server_name=name,
                  dashboard_password="<redacted>", dashboard_port=0,
                  public_endpoint="ws://127.0.0.1:9", **kw)
    return relay


def _seed_earned_row(relay, health, *, age_seconds=0):
    """Write this server's registry row as a previous boot's battery
    left it: an earned rating and a heartbeat `age_seconds` old."""
    relay.store.register_server(
        relay.server_label, relay._registry_endpoint(),
        host_agent="", version="1.6.1", health=health, riders=0,
        capacity=0, server_id=relay.server_id, owner_agent="",
        home_host="", can_carry=True)
    if age_seconds:
        import agentlink.relay as relay_mod
        real_now = relay_mod.now_ts
        # Age the row by rewinding its heartbeat directly in the
        # local store (test-only reach into the row, same spirit as
        # the drill harnesses).
        with relay.store._lock:
            relay.store._db.execute(
                "UPDATE servers SET last_seen = ? WHERE server_id = ?",
                (real_now() - age_seconds, relay.server_id))
            relay.store._db.commit()


# ----------------------------------------------------------------------
# B1 — health-rating persistence
# ----------------------------------------------------------------------

def test_b1_fresh_server_starts_unrated(tmp_path):
    relay = _unstarted_relay(tmp_path)
    relay._restore_health_rating()
    assert relay._restored_health is None
    assert relay._compute_health() == HEALTH_UNRATED


def test_b1_earned_rating_restored_for_reearning_window(tmp_path):
    relay = _unstarted_relay(tmp_path)
    _seed_earned_row(relay, 87)
    relay._restore_health_rating()
    assert relay._restored_health == 87
    # Published during the re-earning window: riders are admitted
    # (capacity derives from the restored rating, not from zero).
    assert relay._compute_health() == 87
    assert relay._effective_capacity() > 0
    # The restored rating retires once this boot's battery has run
    # the initial window without (yet) re-earning.
    relay._health_cycles = HEALTH_INITIAL_CYCLES
    assert relay._compute_health() == HEALTH_UNRATED
    # And once the battery HAS earned, the live score rules.
    relay._rated = True
    relay._health_event("probe_ok")
    relay._health_event("hello_ok")
    relay._health_event("reg_ok")
    relay._health_event("msg_ok")
    relay._health_event("file_ok")
    relay._health_event("hb_ok")
    assert relay._compute_health() == relay._health_score()


def test_b1_stale_rating_is_not_restored(tmp_path):
    relay = _unstarted_relay(tmp_path)
    _seed_earned_row(relay, 92, age_seconds=3600)
    relay._restore_health_rating()
    assert relay._restored_health is None
    assert relay._compute_health() == HEALTH_UNRATED


def test_b1_unrated_row_restores_nothing(tmp_path):
    relay = _unstarted_relay(tmp_path)
    _seed_earned_row(relay, HEALTH_UNRATED)
    relay._restore_health_rating()
    assert relay._restored_health is None
    assert relay._compute_health() == HEALTH_UNRATED


def test_b1_restored_rating_survives_start(tmp_path):
    """Integration: start() restores BEFORE its first registry
    write, so the row keeps the earned rating (never clobbered to
    UNRATED) and the running relay publishes it immediately."""
    db = str(Path(tmp_path) / "relay.db")
    handle = RelayHandle(db, "home-server")
    relay = handle.build()
    _seed_earned_row(relay, 87)
    url = handle.start()
    try:
        assert relay._restored_health == 87
        assert relay._compute_health() == 87
        row = relay.store.get_server(relay.server_id)
        assert row is not None and int(row["health"]) == 87
    finally:
        handle.stop()


# ----------------------------------------------------------------------
# B2 — welcome not blocked behind hello record writes
# ----------------------------------------------------------------------

class SlowRecordStore:
    """Store proxy whose hello RECORD writes are artificially slow
    (the production failure shape: each is a proxied HTTPS round
    trip that can stall for seconds). Everything else delegates at
    full speed."""

    SLOW_METHODS = ("set_display_name", "set_pubkey", "set_sign_pub",
                    "set_mode", "set_decision_link", "set_delivery_ack",
                    "set_auth_method", "touch")
    DELAY = 1.0

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        attr = getattr(self._inner, name)
        if name in self.SLOW_METHODS and callable(attr):
            def slow(*a, **kw):
                time.sleep(self.DELAY)
                return attr(*a, **kw)
            return slow
        return attr


def test_b2_welcome_not_blocked_by_slow_record_writes(tmp_path):
    db = str(Path(tmp_path) / "relay.db")
    state = Path(tmp_path) / "agent-state"
    state.mkdir()

    async def _register_with_fast_store():
        handle = RelayHandle(db, "home-server")
        url = handle.start()
        agent = Agent("slowpoke", endpoint=url,
                      state_dir=str(state))
        await agent.start()
        await agent.close()
        handle.stop()

    asyncio.run(_register_with_fast_store())

    # Second boot of the same server: same store, but every hello
    # record write now costs 1s. The verified hello path records
    # display/pubkey/sign/mode/link/ack + presence touch — inline,
    # that stack would hold the welcome for many seconds. v1.6.2
    # defers those past the welcome; only the auth record (a
    # security record) stays synchronous in front of it, so the
    # welcome should land at ~1s, and start() returns once the
    # whole hello completes.
    inner = Store(db)
    handle = RelayHandle(db, "home-server",
                         backend_store=SlowRecordStore(inner))
    url = handle.start()
    agent = Agent("slowpoke", endpoint=url, state_dir=str(state))

    # Time the WELCOME, not start()'s whole boot sequence: start()
    # processes the welcome (spawning the reader task) before its
    # post-connect resync requests, and those requests legitimately
    # queue behind the deferred batch in the relay's per-connection
    # frame loop. The production defect was the welcome itself
    # missing the client's hello timeout — that is what is pinned
    # here. The reader task exists the moment the welcome lands.
    start_error = []

    def _start_in_thread():
        try:
            asyncio.run(agent.start())
        except Exception as exc:  # surfaced by the main thread
            start_error.append(exc)

    t0 = time.monotonic()
    starter = threading.Thread(target=_start_in_thread, daemon=True)
    starter.start()
    welcome_at = None
    while time.monotonic() - t0 < 10:
        if agent._reader is not None:
            welcome_at = time.monotonic() - t0
            break
        if start_error:
            break
        time.sleep(0.02)
    try:
        assert not start_error, f"start() failed: {start_error!r}"
        assert welcome_at is not None, "welcome never arrived"
        # The record stack is many seconds of slow writes; the
        # welcome must beat it by a wide margin — only the single
        # synchronous auth record (~1s) precedes it.
        assert welcome_at < 3.0, \
            f"welcome took {welcome_at:.1f}s behind slow record writes"
        starter.join(timeout=30)
        assert not starter.is_alive(), "start() never completed"

        def _row():
            rows = {u["username"]: u for u in inner.list_users()}
            return rows.get("slowpoke") or {}

        assert asyncio.run(wait_for(
            lambda: _row().get("auth_method") == "key", timeout=20)), \
            "hello records never landed on the row"
        row = _row()
        assert row.get("display_name")
        assert row.get("pubkey")
    finally:
        asyncio.run(agent.close())
        handle.stop()


def test_b2_welcome_server_list_is_the_live_list(tmp_path):
    """The welcome payload's server list comes from _live_servers()
    (no stale cache): a row registered a moment ago is advertised."""
    relay = _unstarted_relay(tmp_path)
    relay.store.register_server(
        "other-server", "ws://127.0.0.1:59998", host_agent="",
        version="1.6.2", health=90, riders=0, capacity=9,
        server_id="ws://127.0.0.1:59998", owner_agent="",
        home_host="", can_carry=True)
    eps = {s["endpoint"] for s in relay._live_servers()}
    assert "ws://127.0.0.1:59998" in eps


# ----------------------------------------------------------------------
# B3 — close-code telemetry
# ----------------------------------------------------------------------

def test_b3_disconnect_paths_log_close_codes():
    import agentlink.client as client_mod
    import agentlink.relay as relay_mod
    relay_src = inspect.getsource(relay_mod.Relay._handle)
    assert "_close_telemetry" in relay_src
    telemetry_src = inspect.getsource(relay_mod.Relay._close_telemetry)
    assert "close_code" in telemetry_src
    assert "close_reason" in telemetry_src
    read_src = inspect.getsource(client_mod.Agent._read_loop)
    assert "_closed_code" in read_src
    run_src = inspect.getsource(client_mod.Agent.run)
    assert "close_code" in run_src


def test_b3_relay_logs_close_code_on_client_disconnect(tmp_path,
                                                       caplog):
    db = str(Path(tmp_path) / "relay.db")
    handle = RelayHandle(db, "home-server")
    url = handle.start()
    state = Path(tmp_path) / "agent-state"
    state.mkdir()
    agent = Agent("closer", endpoint=url, state_dir=str(state))

    async def _connect_close():
        await agent.start()
        await agent.close()

    def _saw_disconnect_line():
        return any("disconnected" in r.message
                   and "close_code=1000" in r.message
                   and "closer" in r.message
                   for r in caplog.records)

    try:
        with caplog.at_level(logging.INFO, logger="agentlink.relay"):
            asyncio.run(_connect_close())
            # The relay's handler logs on its own loop thread; give
            # the disconnect a moment to be reaped.
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and \
                    not _saw_disconnect_line():
                time.sleep(0.1)
            assert _saw_disconnect_line(), \
                "no relay disconnect line carrying close_code=1000"

        # Client side: when the SERVER severs the session, the read
        # loop captures the close code for the disconnect log. The
        # agent's event loop must stay alive while the relay stops
        # (asyncio.run would cancel the reader on return), so the
        # whole sever sequence runs inside one scenario coroutine;
        # the relay stop is driven from a side thread (its handle
        # stop is thread-safe by construction).
        agent2 = Agent("closer2", endpoint=url,
                       state_dir=str(Path(tmp_path) / "agent-state2"))

        async def _sever_scenario():
            await agent2.start()
            threading.Thread(target=handle.stop, daemon=True).start()
            for _ in range(150):
                if agent2._closed_code is not None:
                    break
                await asyncio.sleep(0.1)
            code = agent2._closed_code
            await agent2.close()
            return code

        code = asyncio.run(_sever_scenario())
        assert code in (1000, 1001), \
            f"client captured no close code (got {code!r})"
    finally:
        handle.stop()
