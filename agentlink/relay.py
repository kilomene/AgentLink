"""The AgentLink relay: routes messages, groups and work between agents.

Host it anywhere: ``agentlink relay --host 0.0.0.0 --port 8765``.
State is one SQLite file. There is no hard-coded connection limit:
peers live in a plain dict and every frame is handled independently,
so the relay scales to thousands of concurrent agents on modest
hardware (SQLite writes are lock-serialised and kept tiny).
"""

from __future__ import annotations

import argparse
import asyncio
import collections
import json
import logging
import os
import time
import urllib.parse
from dataclasses import dataclass, field
from http import HTTPStatus

import websockets
import websockets.exceptions
from websockets.server import serve

from .protocol import MAX_FRAME, new_id, normalize_username, now_ts
from .timing import (
    ALERT_OFFLINE_SECONDS,
    ALERT_REMINDER_SECONDS,
    ALERT_URGENT_SECONDS,
    CARRY_HANDBACK_SECONDS,
    CARRY_LEASE_SECONDS,
    CARRY_WATCH_SECONDS,
    CHECKIN_GAP_MIN_SECONDS,
    CHECKIN_MIN_SESSIONS,
    CHECKIN_SESSION_MAX_SECONDS,
    CHECKIN_WINDOW_SECONDS,
    HEALTH_FRAME_TIMEOUT_SECONDS,
    HEALTH_INITIAL_CYCLES,
    HEALTH_PROBE_ROUNDS,
    HEALTH_TEST_CYCLE_SECONDS,
    HEALTH_UNRATED,
    HEARTBEAT_SECONDS,
    HOME_PROBE_SECONDS,
    OFFLINE_GRACE_SECONDS,
    REASSIGN_GRACE_SECONDS,
    RECONNECT_BACKOFF_CAP_SECONDS,
    SERVER_HEALTHY_MIN,
    SERVER_HEARTBEAT_SECONDS,
    SERVER_HEALTH_WINDOW_SECONDS,
    SERVER_STALE_SECONDS,
    UPDATE_CHECK_SECONDS,
)
from .store import GroupFull, NotFound, RemovalBlocked, Store, UsernameTaken

log = logging.getLogger("agentlink.relay")

ADMIN_ROLES = ("admin", "superadmin")


def _ws_client_connect():
    """The websocket client connect for this interpreter's
    websockets build: 14+ ships websockets.asyncio.client, older
    builds ship the legacy websockets.client. Returns
    (connect, is_modern) — the battery and the carry home-probe
    speak to both identically; only the proxy kwarg differs
    (the modern client honours it, the legacy one has none)."""
    try:
        from websockets.asyncio.client import connect
        return connect, True
    except ImportError:
        from websockets.client import connect
        return connect, False


def compute_server_health(*, probe_ok: int = 0, probe_fail: int = 0,
                          hello_ok: int = 0, hello_fail: int = 0,
                          reg_ok: int = 0, reg_fail: int = 0,
                          msg_ok: int = 0, msg_fail: int = 0,
                          file_ok: int = 0, file_fail: int = 0,
                          hb_ok: int = 0, hb_fail: int = 0,
                          scan_ok: int = 0, scan_fail: int = 0,
                          peers: int = 0) -> int:
    """THE health percentage (v1.3.0 earned-health law) — computed
    ONLY from the server's own measured test evidence over the
    trailing SERVER_HEALTH_WINDOW_SECONDS (5 min). Every point is
    earned by testing and every deduction is a real measured
    failure. There is no default, no static assignment and no
    override: a component with NO evidence in the window deducts
    its FULL weight (untested is unearned), so a server that stops
    testing watches its percentage fall to zero as the window
    slides.

    Weights (documented, sum 100, plus load):
        25  probe round-trips (application ping -> pong)
        20  hello handshakes (admissions)
        20  registry write + read-back integrity
        15  message round-trips (real DM through this server)
        10  file round-trips (chunked upload, hash-verified fetch)
         5  heartbeat stability (registry heartbeats landing)
         5  fleet-scan reliability (internal work loop)
       + up to 5 more for load pressure (connected peers, capped)

    The relay's battery (see _run_health_cycle) generates the
    probe/hello/registry/message/file/heartbeat evidence actively
    and continuously; real traffic adds its own outcomes on top.
    Pure function of its inputs — the tests pin it deterministically."""
    def _deduct(weight: int, ok: int, fail: int) -> int:
        total = ok + fail
        if total <= 0:
            return weight  # no evidence: nothing was earned
        return round(weight * fail / total)
    health = 100
    health -= _deduct(25, probe_ok, probe_fail)
    health -= _deduct(20, hello_ok, hello_fail)
    health -= _deduct(20, reg_ok, reg_fail)
    health -= _deduct(15, msg_ok, msg_fail)
    health -= _deduct(10, file_ok, file_fail)
    health -= _deduct(5, hb_ok, hb_fail)
    health -= _deduct(5, scan_ok, scan_fail)
    health -= round(5 * min(1.0, max(0, peers) / 50))
    return max(0, min(100, health))


def effective_capacity(health: int) -> int:
    """Mesh rule: capacity scales with health and never exceeds the
    hard cap — floor(SERVER_MAX_RIDERS x health / 100). At 100% a
    server hosts the full 10 riders; at 60% it hosts 6."""
    from .timing import SERVER_MAX_RIDERS
    return max(0, (SERVER_MAX_RIDERS * int(health)) // 100)


@dataclass
class Peer:
    ws: object
    username: str
    display_name: str = ""
    pubkey: str = ""
    ephemeral: bool = False
    last_seen: int = 0
    home_endpoint: str = ""
    activity: str = "online_idle"
    touched_at: int = 0
    connected_at: int = 0
    core: dict = field(default_factory=dict)
    # v1.3.0 carrying: the server identity this connection arrived
    # through — this relay's own server_id, or the carried server's
    # id when the connection came in on a carry alias.
    server_id: str = ""


@dataclass
class Relay:
    host: str = "127.0.0.1"
    port: int = 8765
    db_path: str = "~/.agentlink/relay.db"
    backend_store: object = None
    blob_store: object = None
    server_name: str | None = None
    # Peer mesh (v1.2.0): the username of the agent hosting this
    # relay, when an agent host runs it (''/None for a bare operator
    # relay). Recorded in the server registry so the mesh can say
    # WHOSE server a rider is riding.
    host_agent: str | None = None
    # Server carrying (v1.3.0): this server's STABLE identity in the
    # registry (defaults to its registry endpoint). owner_agent set
    # means this relay IS that agent's own server — the agent owns
    # it permanently, wherever it runs; home_host names the host
    # agent of its home machine. carrier_enabled: this relay watches
    # the registry and carries brothers' servers when they fall
    # (every relay is a carrier by default — that is the passage).
    server_id: str | None = None
    owner_agent: str | None = None
    home_host: str | None = None
    carrier_enabled: bool = True
    # Immortality gate (v1.3.2): on startup the relay verifies the
    # store's conversation census against a durable baseline before
    # serving. The baseline lives beside the relay's state file —
    # never in the code directory, so no update can touch it. None
    # derives the path from db_path; census_gate_enabled=False is an
    # operator-only escape for store-less stub relays in tests.
    census_baseline_path: str | None = None
    census_gate_enabled: bool = True
    dashboard_password: str | None = None
    dashboard_port: int = 8766
    public_endpoint: str | None = None
    dashboard_enabled: bool = True
    dashboard: object = field(default=None, repr=False)
    peers: dict = field(default_factory=dict)  # username -> Peer
    rooms: dict = field(default_factory=dict)  # room_id -> room record
    activity: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=300))
    _server: object = field(default=None, repr=False)
    # Fleet operations (points 29, 36, 37) — operator-configurable.
    reassign_grace_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_REASSIGN_GRACE",
                       str(REASSIGN_GRACE_SECONDS))))
    alert_offline_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_ALERT_OFFLINE_SECONDS",
                       str(ALERT_OFFLINE_SECONDS))))
    alert_urgent_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_ALERT_URGENT_SECONDS",
                       str(ALERT_URGENT_SECONDS))))
    alert_reminder_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_ALERT_REMINDER_SECONDS",
                       str(ALERT_REMINDER_SECONDS))))
    alert_webhook: str = field(default_factory=lambda: os.environ.get(
        "AGENTLINK_ALERT_WEBHOOK", ""))
    # Owner oversight (2026-11-01): the oversight PUBLIC key this
    # relay advertises in every welcome frame (clients adopt it with
    # zero manual config; a client-side env key overrides it). The
    # private key never reaches the relay. REQUIRE_OVERSIGHT=1 makes
    # the relay reject content envelopes that lack a valid-shaped
    # oversight wrap ('oversight_required').
    oversight_pubkey: str = field(default_factory=lambda: os.environ.get(
        "AGENTLINK_OVERSIGHT_PUBKEY", ""))
    require_oversight: bool = field(default_factory=lambda:
        os.environ.get("AGENTLINK_REQUIRE_OVERSIGHT", "") == "1")
    _scan_task: object = field(default=None, repr=False)
    _server_hb_task: object = field(default=None, repr=False)
    # Earned health (v1.3.0): a server starts UNRATED — it carries
    # NO percentage and is eligible neither to be ridden nor to
    # carry until its battery has completed HEALTH_INITIAL_CYCLES
    # cycles with real evidence in every component. There is NO
    # health override: no env var, config value or operator switch
    # may set the number (the v1.2.x AGENTLINK_SERVER_HEALTH pin is
    # abolished — a tampered number is a lie the mesh would route
    # by). _health_events is the ONLY source of the percentage.
    _health_events: object = field(
        default_factory=lambda: collections.deque(maxlen=20000),
        repr=False)
    _health_task: object = field(default=None, repr=False)
    _health_cycles: int = field(default=0, repr=False)
    _rated: bool = field(default=False, repr=False)
    _last_health_publish: object = field(default=None, repr=False)
    # Carrying (v1.3.0): server_id -> {"token", "endpoint", "owner"}
    # for the brothers' servers THIS relay currently carries, and
    # the per-server home-probe continuity clock for handback.
    _carrier_task: object = field(default=None, repr=False)
    _carried: dict = field(default_factory=dict, repr=False)
    _home_ok_since: dict = field(default_factory=dict, repr=False)
    # Hardened core (v1.2.0): the relay operator's update switch —
    # the ONLY sanctioned kill switch for agents' self-update
    # checkers (AGENTLINK_UPDATES_ENABLED=0 on the RELAY). Advertised
    # in every welcome and shown on the dashboard; agents cannot
    # switch themselves off.
    updates_enabled: bool = field(default_factory=lambda:
        os.environ.get("AGENTLINK_UPDATES_ENABLED", "1") != "0")
    # Compliance visibility: per-agent session history (for the
    # check-in pattern flag) and last declared core fingerprint.
    _sessions: dict = field(default_factory=dict, repr=False)
    _last_core: dict = field(default_factory=dict, repr=False)
    _last_mesh_publish: object = field(default=None, repr=False)
    alert_chain_completed: bool = field(default_factory=lambda:
        os.environ.get("AGENTLINK_ALERT_CHAIN_COMPLETED", "1") != "0")
    chain_pause_alert_seconds: int = field(default_factory=lambda: int(
        os.environ.get("AGENTLINK_ALERT_CHAIN_PAUSE_SECONDS", "300")))
    _pressure_fired: set = field(default_factory=set, repr=False)
    _alert_dispatched: set = field(default_factory=set, repr=False)

    def __post_init__(self) -> None:
        self.store = self.backend_store or \
            Store(os.path.expanduser(self.db_path))
        if self.blob_store is None:
            from .blobstore import create_blob_store
            default_root = os.path.join(
                os.path.dirname(os.path.expanduser(self.db_path)), "blobs")
            self.blob_store = create_blob_store(local_root=default_root)
        # Carrying identity (v1.3.0): a stable server_id (defaults
        # to the registry endpoint — a server's identity must not
        # change when its endpoint moves to a carrier), a permanent
        # owner for per-agent servers, and the home host label.
        if not self.server_id:
            self.server_id = self._registry_endpoint()
        self.owner_agent = (self.owner_agent or "").strip() \
            .lstrip("@").lower() or None
        if not self.home_host:
            self.home_host = self.host_agent or ""

    @property
    def server_label(self) -> str:
        return self.server_name or f"ws://{self.host}:{self.port}"

    def _is_home_endpoint(self, endpoint: str) -> bool:
        """Home = the agent's declared home endpoint IS this relay.
        The comparison runs against the relay's own endpoint identity
        — its ws/wss bind address, its configured public endpoint
        (field or AGENTLINK_PUBLIC_ENDPOINT), and the fixed product
        endpoint — NEVER against the friendly --name label (the
        v1.0 bug: a named relay labelled its own home agents
        'online (via <its own name>)')."""
        if not endpoint:
            return False

        def _norm_ep(value: str) -> str:
            # Endpoints in this system canonically end in /ws (every
            # production endpoint does); a relay's own bind identity
            # has no path. Compare path-insensitively for that one
            # suffix so a home agent is never misread as a rider
            # (v1.3.0 root-cause fix — invisible while health was
            # instant, fatal once the UNRATED gate could refuse).
            v = str(value).strip().rstrip("/").lower()
            if v.endswith("/ws"):
                v = v[:-3]
            return v

        norm = _norm_ep(endpoint)
        candidates = {_norm_ep(f"ws://{self.host}:{self.port}"),
                      _norm_ep(f"wss://{self.host}:{self.port}")}
        ep = self.public_endpoint or \
            os.environ.get("AGENTLINK_PUBLIC_ENDPOINT")
        if ep:
            candidates.add(_norm_ep(ep))
        try:
            from .config import DEFAULT_ENDPOINT
            default_norm = str(DEFAULT_ENDPOINT).strip().rstrip("/") \
                .lower()
            # The fixed product endpoint counts as MY home identity
            # only when this relay IS the product endpoint's relay —
            # no public endpoint of its own configured, or configured
            # AS the default. A peer relay (own public endpoint, e.g.
            # x2.novamail.store) must NOT claim the default endpoint
            # as home: agents homed there are RIDING when they are
            # here, and the dashboard must say "online (via <peer>)"
            # (v1.2.0 — with one relay this distinction was invisible;
            # with a live mesh it is the whole point).
            if not ep or _norm_ep(ep) == _norm_ep(default_norm):
                candidates.add(_norm_ep(default_norm))
        except Exception:
            pass
        return norm in candidates

    # -- server registry (v1.2.0 peer mesh) --------------------------------
    # NO GOING DARK, peer-server law: an agent whose server dies
    # rides another agent's server at full capability until home is
    # back. That only works if the mesh is DISCOVERABLE — so every
    # relay registers itself in the shared backend on boot and
    # heartbeats the row; any relay hands the live list to any
    # client that connects (welcome payload + 'servers' request).

    def _registry_endpoint(self) -> str:
        """This relay's canonical endpoint identity in the registry:
        its configured public endpoint when it has one, else its
        bind address (the local/test shape)."""
        ep = self.public_endpoint or \
            os.environ.get("AGENTLINK_PUBLIC_ENDPOINT")
        if ep:
            return str(ep).strip().rstrip("/")
        return f"ws://{self.host}:{self.port}"

    # -- health (v1.2.0 mesh rule) -------------------------------------------
    # Every server carries a health percentage computed from REAL
    # signals it measured itself (see compute_server_health). The
    # events below are the raw material: timestamped outcomes of the
    # relay's own fleet scans, hello admissions and registry writes
    # over the trailing window. Published in every registry
    # heartbeat; enforced at rider admission; shown on the
    # dashboard and in the directory.

    def _health_event(self, kind: str) -> None:
        try:
            self._health_events.append((now_ts(), kind))
        except Exception:
            pass

    def _health_counts(self) -> dict:
        cutoff = now_ts() - SERVER_HEALTH_WINDOW_SECONDS
        counts = {"probe_ok": 0, "probe_fail": 0,
                  "hello_ok": 0, "hello_fail": 0,
                  "reg_ok": 0, "reg_fail": 0,
                  "msg_ok": 0, "msg_fail": 0,
                  "file_ok": 0, "file_fail": 0,
                  "hb_ok": 0, "hb_fail": 0,
                  "scan_ok": 0, "scan_fail": 0}
        for ts, kind in list(self._health_events):
            if ts >= cutoff and kind in counts:
                counts[kind] += 1
        return counts

    def _health_score(self) -> int:
        """The earned percentage from the evidence in the window —
        the only computation of health anywhere in the system."""
        return compute_server_health(
            peers=len(self.peers), **self._health_counts())

    def _compute_health(self) -> int:
        """This server's published health: HEALTH_UNRATED (-1)
        until the battery has earned a first rating, then the
        measured score. Riders and carriers treat unrated exactly
        like at/below the floor: not eligible."""
        if not self._rated:
            return HEALTH_UNRATED
        return self._health_score()

    def _effective_capacity(self) -> int:
        health = self._compute_health()
        if health <= SERVER_HEALTHY_MIN:
            return 0
        return effective_capacity(health)

    def _riders_count(self, exclude: str = "",
                      server_id: str | None = None) -> int:
        """Agents RIDING this server right now: connected, not
        ephemeral, and their home is somewhere else. Home agents are
        not riders and never count against capacity. With
        server_id, counts the agents connected through that carried
        server's identity instead."""
        n = 0
        for p in self.peers.values():
            if p.ephemeral or p.username == exclude:
                continue
            if server_id is not None:
                if p.server_id == server_id:
                    n += 1
                continue
            if p.home_endpoint and \
                    not self._is_home_endpoint(p.home_endpoint):
                n += 1
        return n

    # -- hardened-core compliance (v1.2.0) -----------------------------------
    # The survival invariants are hardcoded in the client; the
    # relay's job is VISIBILITY: record what each agent declares and
    # how it actually connects, and expose both — a weakened setup
    # must be SEEN, never silently look compliant.

    @staticmethod
    def _sanitize_core(raw) -> dict:
        if not isinstance(raw, dict):
            return {}
        out = {}
        for k, v in list(raw.items())[:12]:
            if isinstance(v, (str, int, float, bool)) and v is not None:
                out[str(k)[:32]] = v
        return out

    @staticmethod
    def _core_compliant(core: dict) -> bool:
        """True only when the declared fingerprint matches the
        hardcoded core EXACTLY: heartbeat 5s, backoff cap 5s, home
        probe 5s, update check 900s, race on, continuous on."""
        if not core:
            return False
        return (core.get("heartbeat_s") == HEARTBEAT_SECONDS
                and core.get("backoff_cap_s")
                == RECONNECT_BACKOFF_CAP_SECONDS
                and core.get("home_probe_s") == HOME_PROBE_SECONDS
                and core.get("update_check_s") == UPDATE_CHECK_SECONDS
                and core.get("race") is True
                and core.get("continuous") is True)

    def _record_session(self, username: str, connected_at: int,
                        ended_at: int) -> None:
        dq = self._sessions.setdefault(
            username, collections.deque(maxlen=50))
        dq.append((int(connected_at), int(ended_at)))

    def _connection_pattern(self, username: str) -> str:
        """'check-in' when the agent's recent history is repeated
        SHORT sessions separated by LONG dark gaps — the signature
        of an agent configured to poll instead of staying connected.
        Anything else is 'continuous'. Deterministic over the
        recorded session stamps (timing.CHECKIN_*)."""
        now = now_ts()
        sessions = [(a, b) for a, b in
                    self._sessions.get(username, [])
                    if b >= now - CHECKIN_WINDOW_SECONDS]
        recent = sessions[-CHECKIN_MIN_SESSIONS:]
        if len(recent) < CHECKIN_MIN_SESSIONS:
            return "continuous"
        for (a1, b1), (a2, _b2) in zip(recent, recent[1:]):
            if a2 - b1 <= CHECKIN_GAP_MIN_SECONDS:
                return "continuous"
        if all(b - a < CHECKIN_SESSION_MAX_SECONDS
               for a, b in recent):
            return "check-in"
        return "continuous"

    def _compliance_fields(self, username: str) -> dict:
        peer = self.peers.get(username)
        core = (peer.core if peer is not None and peer.core
                else self._last_core.get(username) or {})
        return {"core": core,
                "core_compliant": self._core_compliant(core)
                if core else None,
                "connection_pattern":
                    self._connection_pattern(username)}

    def _register_server_row(self) -> None:
        from . import __version__
        health = self._compute_health()
        try:
            self.store.register_server(
                self.server_label, self._registry_endpoint(),
                host_agent=self.host_agent or "",
                version=__version__, health=health,
                riders=self._riders_count(),
                capacity=effective_capacity(health)
                if health > SERVER_HEALTHY_MIN else 0,
                server_id=self.server_id,
                owner_agent=self.owner_agent or "",
                home_host=self.home_host or "",
                can_carry=self.carrier_enabled)
            # Read-back integrity (earned-health battery): the row
            # must come back from the shared store with this
            # server's identity and label intact — a registry that
            # cannot prove its own write is a measured failure.
            row = self.store.get_server(self.server_id)
            if row is not None and \
                    row.get("label") == self.server_label:
                self._health_event("reg_ok")
                self._health_event("hb_ok")
            else:
                self._health_event("reg_fail")
                self._health_event("hb_fail")
        except Exception:
            # A registry write must never take the relay down: the
            # relay keeps serving; clients just don't learn about it
            # until a heartbeat lands. Loud in the log, never fatal.
            self._health_event("reg_fail")
            self._health_event("hb_fail")
            log.exception("server registry registration failed")

    async def _server_heartbeat_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(SERVER_HEARTBEAT_SECONDS)
                await asyncio.to_thread(self._register_server_row)
                # Real time (Law A): when this server's published
                # mesh state (health / rider load) actually changes,
                # push it to dashboard subscribers NOW — mesh state
                # moves at heartbeat cadence at the slowest, never
                # on a polling delay.
                sig = (self._compute_health(), self._riders_count())
                if sig != self._last_mesh_publish:
                    self._last_mesh_publish = sig
                    if getattr(self, "dashboard", None) is not None:
                        self.dashboard.notify()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("server registry heartbeat failed")

    # -- earned health: the battery (v1.3.0) ------------------------------
    # A server's percentage is EARNED THROUGH TESTING, every time.
    # This loop is the testing: every HEALTH_TEST_CYCLE_SECONDS it
    # exercises the REAL server end-to-end over real loopback
    # websocket connections — probe round-trips, ephemeral hello
    # handshakes, a real (battery-labelled, audit-exempt) message
    # round-trip between two ephemeral peers, a chunked file
    # round-trip verified by SHA-256 — plus the registry
    # write/read-back and heartbeat evidence _register_server_row
    # records. Real traffic adds its own outcomes on top. Nothing
    # here is simulated: every component talks to the live listener
    # and the live store, exactly like a real client.

    def _battery_base(self) -> str:
        host = self.host if self.host not in ("0.0.0.0", "::", "") \
            else "127.0.0.1"
        return f"ws://{host}:{self.port}"

    async def _battery_recv(self, ws, want: set,
                            timeout: float = HEALTH_FRAME_TIMEOUT_SECONDS):
        deadline = time.monotonic() + timeout
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                raise TimeoutError("battery frame timeout")
            raw = await asyncio.wait_for(ws.recv(), timeout=left)
            try:
                frame = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                continue
            if isinstance(frame, dict) and frame.get("type") in want:
                return frame

    async def _run_health_cycle(self) -> None:
        import base64 as _b64
        import hashlib as _hl
        _ws_connect, _modern = _ws_client_connect()
        base = self._battery_base()
        kw = {"max_size": MAX_FRAME, "open_timeout": 3}
        if _modern:
            kw["proxy"] = None  # loopback: never via an egress proxy
        done = {"probe": False, "msg": False, "file": False}
        try:
            # Probe round-trips: application ping -> pong, timed.
            try:
                async with _ws_connect(base, **kw) as ws:
                    for i in range(HEALTH_PROBE_ROUNDS):
                        t0 = time.monotonic()
                        await ws.send(json.dumps(
                            {"type": "ping",
                             "req_id": f"hb-probe-{i}"}))
                        frame = await self._battery_recv(ws, {"pong"})
                        if frame.get("type") == "pong":
                            self._health_event("probe_ok")
                            _ = time.monotonic() - t0  # latency seen
                        else:  # pragma: no cover - recv filters pong
                            self._health_event("probe_fail")
                    done["probe"] = True
            except Exception:
                self._health_event("probe_fail")
            # Hello + message + file on two ephemeral peers. The
            # hellos themselves are counted by _on_hello.
            try:
                async with _ws_connect(base, **kw) as a, \
                        _ws_connect(base, **kw) as b:
                    for ws in (a, b):
                        await ws.send(json.dumps(
                            {"type": "hello", "ephemeral": True,
                             "req_id": "hb-hello"}))
                    wa = await self._battery_recv(a, {"welcome"})
                    wb = await self._battery_recv(b, {"welcome"})
                    b_user = wb["username"]
                    _ = wa
                    # Message round-trip (battery-labelled: routed
                    # for real, exempt from the audit/activity feed
                    # and the oversight gate — it is the server's own
                    # self-test traffic, never user activity).
                    await a.send(json.dumps(
                        {"type": "send", "to": b_user,
                         "content": {"ct": "agentlink-health-battery"},
                         "battery": True, "req_id": "hb-msg",
                         "id": "hb-msg-1"}))
                    res = await self._battery_recv(a, {"result",
                                                       "error"})
                    got = await self._battery_recv(b, {"message"})
                    if res.get("type") == "result" and \
                            (got.get("content") or {}).get("ct") == \
                            "agentlink-health-battery":
                        self._health_event("msg_ok")
                    else:
                        self._health_event("msg_fail")
                    done["msg"] = True
                    # Chunked file round-trip, hash-verified.
                    # The payload is nonce-stamped per server and
                    # cycle: on a SHARED blob store an identical
                    # payload would give every relay's battery the
                    # same blob_id, and one server's cleanup delete
                    # could pull another server's test file out from
                    # under its verification.
                    nonce = _hl.sha256(
                        f"{self.server_id}:{self._health_cycles}:"
                        f"{time.time_ns()}".encode()).digest()
                    payload = bytes((i * 7 + 13) % 256
                                    for i in range(3000 - 32)) + nonce
                    digest = _hl.sha256(payload).hexdigest()
                    await a.send(json.dumps(
                        {"type": "blob_session_start",
                         "whole_sha": digest, "ct_sha": digest,
                         "size": len(payload), "chunk_size": 1024,
                         "req_id": "hb-f0"}))
                    st = await self._battery_recv(a, {"result",
                                                      "error"})
                    sid = (st.get("data") or {}).get("session_id")
                    if not sid:
                        raise RuntimeError("battery upload start "
                                           "refused")
                    for idx in range(3):
                        chunk = payload[idx * 1024:(idx + 1) * 1024]
                        await a.send(json.dumps(
                            {"type": "blob_chunk", "session_id": sid,
                             "index": idx,
                             "data_b64": _b64.b64encode(
                                 chunk).decode(),
                             "chunk_sha": _hl.sha256(
                                 chunk).hexdigest(),
                             "req_id": f"hb-fc-{idx}"}))
                        await self._battery_recv(a, {"result", "error"})
                    await a.send(json.dumps(
                        {"type": "blob_session_finish",
                         "session_id": sid, "req_id": "hb-f9"}))
                    fin = await self._battery_recv(a, {"result",
                                                       "error"})
                    blob_id = (fin.get("data") or {}).get("blob_id")
                    if not blob_id:
                        raise RuntimeError("battery upload finish "
                                           "refused")
                    await a.send(json.dumps(
                        {"type": "blob_get", "blob_id": blob_id,
                         "req_id": "hb-fg"}))
                    gotf = await self._battery_recv(a, {"result",
                                                        "error"})
                    data = _b64.b64decode(
                        (gotf.get("data") or {}).get("data_b64")
                        or "")
                    if _hl.sha256(data).hexdigest() == digest:
                        self._health_event("file_ok")
                    else:
                        self._health_event("file_fail")
                    done["file"] = True
                    await a.send(json.dumps(
                        {"type": "blob_delete", "blob_id": blob_id,
                         "req_id": "hb-fd"}))
                    await self._battery_recv(a, {"result", "error"})
            except Exception:
                if not done["msg"]:
                    self._health_event("msg_fail")
                if not done["file"]:
                    self._health_event("file_fail")
        finally:
            self._health_cycles += 1
            if not self._rated and \
                    self._health_cycles >= HEALTH_INITIAL_CYCLES:
                counts = self._health_counts()
                if all(counts.get(k, 0) >= 1 for k in (
                        "probe_ok", "hello_ok", "reg_ok", "msg_ok",
                        "file_ok", "hb_ok")):
                    self._rated = True
                    log.info("server %s earned its first health "
                             "rating: %s%% after %d battery cycles",
                             self.server_label, self._health_score(),
                             self._health_cycles)
            # Registry write/read-back + heartbeat evidence — AFTER
            # the rating flip, so the row this cycle publishes
            # already carries the rating it just earned (a client
            # reading the registry must never see UNRATED for a
            # server that has already earned its percentage).
            await asyncio.to_thread(self._register_server_row)
            # Real-time law: a changed percentage republishes NOW.
            sig = self._compute_health()
            if sig != self._last_health_publish:
                self._last_health_publish = sig
                if getattr(self, "dashboard", None) is not None:
                    self.dashboard.notify()

    async def _health_battery_loop(self) -> None:
        while True:
            try:
                await self._run_health_cycle()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("health battery cycle failed")
            await asyncio.sleep(HEALTH_TEST_CYCLE_SECONDS)

    # -- server carrying (v1.3.0) ------------------------------------------
    # The passage model: what is carried is a brother's SERVER,
    # never its brain. This relay watches the registry; a per-agent
    # server whose home stops answering (heartbeat stale, or the
    # endpoint itself refuses an application probe) is claimed by
    # the best eligible carrier under a single-winner lease, and
    # this relay then serves that server's identity — same label,
    # same permanent owner — at its carry alias. When home answers
    # strongly for CARRY_HANDBACK_SECONDS the lease is released and
    # the server goes home; if THIS carrier falls, the lease simply
    # expires and the next brother claims — the server hops again.

    def _carry_endpoint_for(self, server_id: str) -> str:
        """This relay's reachable alias for a carried server: a
        ?carry=<id> query on /ws endpoints (the production tunnel
        routes /ws), a /carry/<id> path everywhere else. Clients
        learn it from the registry row, exactly like any endpoint."""
        base = self._registry_endpoint()
        sid = urllib.parse.quote(str(server_id), safe="")
        if "?" in base:
            return base + "&carry=" + sid
        if urllib.parse.urlsplit(base).path.endswith("/ws"):
            return base + "?carry=" + sid
        return base.rstrip("/") + "/carry/" + sid

    @staticmethod
    def _connection_server_id(ws) -> str:
        """The server identity a websocket arrived through, from
        its request path (?carry=<id> or /carry/<id>); '' for the
        relay's own plain endpoint."""
        try:
            path = ws.request.path
        except Exception:
            # Legacy websockets (11.x) exposes the path directly.
            path = getattr(ws, "path", "") or ""
        parsed = urllib.parse.urlsplit(str(path))
        qs = urllib.parse.parse_qs(parsed.query)
        if qs.get("carry"):
            return str(qs["carry"][0])
        parts = [p for p in parsed.path.split("/") if p]
        if len(parts) >= 2 and parts[-2] == "carry":
            return urllib.parse.unquote(parts[-1])
        return ""

    async def _probe_server_endpoint(self, endpoint: str) -> bool:
        """Application-level life check of a server endpoint: a
        websocket that completes the protocol's own ping -> pong.
        A tunnel fronting a dead relay passes a bare handshake and
        fails this — the v1.2.2 lesson, applied to home-watching."""
        try:
            _c, _modern = _ws_client_connect()
            host = urllib.parse.urlsplit(endpoint).hostname or ""
            kw: dict = {"max_size": MAX_FRAME, "open_timeout": 3}
            if _modern and host in ("127.0.0.1", "localhost", "::1"):
                kw["proxy"] = None
            async with _c(endpoint, **kw) as ws:
                await ws.send(json.dumps(
                    {"type": "ping", "req_id": "carry-probe"}))
                raw = await asyncio.wait_for(ws.recv(), timeout=3)
                frame = json.loads(raw)
                return isinstance(frame, dict) and \
                    frame.get("type") == "pong"
        except Exception:
            return False

    async def _carrier_loop(self) -> None:
        while True:
            try:
                await self._carrier_tick()
            except asyncio.CancelledError:
                return
            except Exception:
                log.exception("carrier watch failed")
            await asyncio.sleep(CARRY_WATCH_SECONDS)

    async def _carrier_tick(self) -> None:
        rows = await asyncio.to_thread(self.store.list_agent_servers)
        now = now_ts()
        probes: dict[str, bool] = {}
        for row in rows:
            sid = str(row.get("server_id") or "")
            if not sid or sid == self.server_id:
                continue
            lease = int(row.get("carry_lease_until") or 0)
            if row.get("carry_state") == "carried" and \
                    lease > now and \
                    row.get("carried_by_id") != self.server_id:
                continue  # another brother is carrying it
            ep = str(row.get("home_endpoint") or "")
            if not ep:
                continue
            ok = await self._probe_server_endpoint(ep)
            probes[sid] = ok
            if ok:
                self._home_ok_since.setdefault(sid, now)
            else:
                self._home_ok_since.pop(sid, None)
        await asyncio.to_thread(self._carrier_tick_sync, probes)

    def _carrier_tick_sync(self, probes: dict | None = None) -> None:
        probes = probes or {}
        now = now_ts()
        health = self._compute_health()
        cap = effective_capacity(health) \
            if health > SERVER_HEALTHY_MIN else 0
        rows = self.store.list_agent_servers()
        changed = False
        # Sync local holds against the registry truth.
        live_holds = {}
        for row in rows:
            sid = str(row.get("server_id") or "")
            if row.get("carry_state") == "carried" and \
                    row.get("carried_by_id") == self.server_id and \
                    int(row.get("carry_lease_until") or 0) > now and \
                    sid in self._carried:
                live_holds[sid] = row
        for sid in list(self._carried):
            if sid not in live_holds:
                del self._carried[sid]
        if health <= SERVER_HEALTHY_MIN:
            # Unrated or fallen: not good — hand every carried
            # server back to the registry for a healthier brother.
            for sid, info in list(self._carried.items()):
                try:
                    if self.store.release_carry(
                            sid, carrier_id=self.server_id,
                            token=info["token"]):
                        changed = True
                        log.info("released carried server %s: this "
                                 "carrier's health fell to %s",
                                 sid, health)
                except Exception:
                    log.exception("carry release failed for %s", sid)
                self._carried.pop(sid, None)
            if changed and getattr(self, "dashboard", None):
                self.dashboard.notify()
            return
        # Handback + renewal for the servers I carry.
        for sid, info in list(self._carried.items()):
            row = live_holds.get(sid)
            if row is None:
                continue
            ok_since = self._home_ok_since.get(sid)
            home_fresh = now - int(row.get("home_last_seen") or 0) \
                <= SERVER_STALE_SECONDS
            if probes.get(sid) and home_fresh and ok_since \
                    and now - ok_since >= CARRY_HANDBACK_SECONDS:
                try:
                    if self.store.release_carry(
                            sid, carrier_id=self.server_id,
                            token=info["token"]):
                        log.info("handback: server %s (owner @%s) "
                                 "returns home after %ds of strong "
                                 "home answers", sid,
                                 row.get("owner_agent"),
                                 CARRY_HANDBACK_SECONDS)
                        changed = True
                except Exception:
                    log.exception("carry handback failed for %s",
                                  sid)
                self._carried.pop(sid, None)
                continue
            try:
                if not self.store.renew_carry(
                        sid, carrier_id=self.server_id,
                        token=info["token"],
                        carrier_agent=self.host_agent or "",
                        endpoint=info["endpoint"], health=health,
                        riders=self._riders_count(server_id=sid),
                        capacity=cap):
                    self._carried.pop(sid, None)
            except Exception:
                log.exception("carry renewal failed for %s", sid)
        # Claims: longest-down first (list_agent_servers order).
        carrying = len(self._carried)
        for row in rows:
            if carrying >= cap:
                break
            sid = str(row.get("server_id") or "")
            if not sid or sid == self.server_id:
                continue
            if not row.get("owner_agent"):
                continue
            if row.get("carry_state") == "carried" and \
                    int(row.get("carry_lease_until") or 0) > now:
                continue
            home_stale = now - int(row.get("home_last_seen") or 0) \
                > SERVER_STALE_SECONDS
            if not home_stale and probes.get(sid) is not False:
                continue  # home is answering; nothing to carry
            alias = self._carry_endpoint_for(sid)
            try:
                claimed = self.store.claim_carry(
                    sid, carrier_id=self.server_id,
                    carrier_agent=self.host_agent or "",
                    endpoint=alias, carrier_health=health,
                    carrier_capacity=cap,
                    carrier_riders=self._riders_count(),
                    carrier_can_carry=self.carrier_enabled,
                    carrier_carrying=carrying,
                    lease_seconds=CARRY_LEASE_SECONDS,
                    stale_after=SERVER_STALE_SECONDS,
                    home_probe_failed=probes.get(sid) is False)
            except Exception:
                log.exception("carry claim failed for %s", sid)
                continue
            if claimed:
                self._carried[sid] = {
                    "token": claimed["carry_lease_token"],
                    "endpoint": alias,
                    "owner": row.get("owner_agent") or ""}
                carrying += 1
                changed = True
                log.info("carrying server %s for @%s (owner stays "
                         "@%s; this machine is only the helper)",
                         sid, row.get("owner_agent"),
                         row.get("owner_agent"))
        if changed and getattr(self, "dashboard", None) is not None:
            self.dashboard.notify()

    def _release_all_carries(self) -> None:
        for sid, info in list(self._carried.items()):
            try:
                self.store.release_carry(
                    sid, carrier_id=self.server_id,
                    token=info["token"])
            except Exception:
                pass
        self._carried.clear()

    # -- server presentation (registry rows -> wire shape) -----------------

    @staticmethod
    def _carry_state_of(row: dict, now: int | None = None) -> str:
        """A per-agent server's honest state: 'home', 'carried' or
        'down'. Agent presence is a different layer and never
        feeds this."""
        if now is None:
            now = now_ts()
        if not row.get("owner_agent"):
            return ""
        if row.get("carry_state") == "carried" and \
                int(row.get("carry_lease_until") or 0) > now:
            return "carried"
        if row.get("carry_state") == "home" and \
                now - int(row.get("home_last_seen") or 0) \
                <= SERVER_STALE_SECONDS:
            return "home"
        return "down"

    def _server_entry(self, row: dict,
                      now: int | None = None) -> dict:
        if now is None:
            now = now_ts()
        health = row.get("health")
        health = HEALTH_UNRATED if health is None else int(health)
        cap = row.get("capacity")
        state = self._carry_state_of(row, now)
        label = {"home": "at home",
                 "carried": "carried by @%s" % row.get("carried_by"),
                 "down": "down — awaiting carrier"}.get(state, "")
        return {"label": row.get("label") or row.get("endpoint")
                or "",
                "endpoint": str(row.get("endpoint") or "")
                .strip().rstrip("/"),
                "host_agent": row.get("host_agent") or "",
                "version": row.get("version") or "",
                "health": health,
                "riders": int(row.get("riders") or 0),
                "capacity": effective_capacity(health)
                if cap is None else int(cap),
                "server_id": row.get("server_id") or "",
                "owner_agent": row.get("owner_agent") or "",
                "home_host": row.get("home_host") or "",
                "home_endpoint": row.get("home_endpoint") or "",
                "carried_by": row.get("carried_by") or "",
                "carry_state": state,
                "carry_state_label": label}

    def _dashboard_servers(self) -> list[dict]:
        """The dashboard's server view: the live mesh PLUS every
        per-agent server in its honest state — a down server must
        be SEEN as down, never silently absent."""
        out = self._live_servers()
        seen = {s.get("server_id") for s in out}
        now = now_ts()
        try:
            rows = self.store.list_agent_servers()
        except Exception:
            rows = []
        for row in rows:
            sid = row.get("server_id") or ""
            if not sid or sid in seen:
                continue
            entry = self._server_entry(row, now)
            # Not currently served: present the home endpoint and
            # the home instance's last earned stats.
            entry["endpoint"] = row.get("home_endpoint") \
                or entry["endpoint"]
            entry["health"] = int(row.get("home_health")
                                  if row.get("home_health")
                                  is not None else HEALTH_UNRATED)
            entry["riders"] = int(row.get("home_riders") or 0)
            entry["capacity"] = int(row.get("home_capacity") or 0)
            out.append(entry)
        out.sort(key=lambda s: s["endpoint"])
        return out

    def _live_servers(self) -> list[dict]:
        """The live mesh as this relay knows it: fresh registry rows
        (stale rows are dead relays, never offered), with this relay
        itself always present — a relay that cannot write its own
        row still advertises itself to the clients it serves."""
        out: list[dict] = []
        try:
            rows = self.store.list_servers()
        except Exception:
            rows = []
        mine = self._registry_endpoint()
        seen_eps: set = set()
        seen_ids: set = set()
        now = now_ts()
        for r in rows:
            ep = str(r.get("endpoint") or "").strip().rstrip("/")
            if not ep or ep in seen_eps:
                continue
            seen_eps.add(ep)
            if r.get("server_id"):
                seen_ids.add(str(r["server_id"]))
            out.append(self._server_entry(r, now))
        # My own row is always present and always LIVE-computed (the
        # stored heartbeat can lag up to one cadence; the dashboard
        # and the drill read the truth, not the echo) — unless the
        # registry row for MY server_id is a carried row, in which
        # case the brother serving it is the truth and I add nothing.
        from . import __version__
        if self.server_id not in seen_ids:
            my_health = self._compute_health()
            myself = {"label": self.server_label, "endpoint": mine,
                      "host_agent": self.host_agent or "",
                      "version": __version__, "health": my_health,
                      "riders": self._riders_count(),
                      "capacity": effective_capacity(my_health)
                      if my_health > SERVER_HEALTHY_MIN else 0,
                      "server_id": self.server_id,
                      "owner_agent": self.owner_agent or "",
                      "home_host": self.home_host or "",
                      "home_endpoint": mine if self.owner_agent
                      else "",
                      "carried_by": "",
                      "carry_state": "home" if self.owner_agent
                      else "",
                      "carry_state_label": "at home"
                      if self.owner_agent else ""}
            out = [myself if s["endpoint"] == mine else s
                   for s in out]
            if mine not in seen_eps:
                out.append(myself)
        else:
            # Refresh my stored row's live stats in place when I am
            # the serving instance (at home / shared relay).
            for s in out:
                if s.get("server_id") == self.server_id and \
                        s.get("carry_state") != "carried":
                    s["health"] = self._compute_health()
                    s["riders"] = self._riders_count()
                    s["capacity"] = effective_capacity(s["health"]) \
                        if s["health"] > SERVER_HEALTHY_MIN else 0
        out.sort(key=lambda s: s["endpoint"])
        return out

    def _sender_meta(self, username: str, group_id: str = ""):
        """(nickname, role, custom_role) of a sender inside a group
        — the identity stamped onto audit rows so dashboard
        conversation items show who spoke, not just a username."""
        if group_id:
            for m in self.store.members(group_id):
                if m["username"] == username:
                    return (m.get("nickname", ""), m.get("role", ""),
                            m.get("custom_role", ""))
        return ("", "", "")

    def _log_activity(self, kind: str, actor: str, target: str = "",
                      group_id: str = "", work_id: str = "",
                      status: str = "", priority: str = "",
                      size: int = 0, mentions=None, ref_id: str = "",
                      sender_nickname: str = "", sender_role: str = "",
                      sender_custom_role: str = "",
                      oversight: dict | None = None,
                      content_envelope: dict | None = None) -> None:
        """Metadata only — never content. Feeds the live dashboard.

        Evidence labelling (point 32): agent-reported claims (progress
        percents, message sends) are labelled 'claimed'; facts the
        relay itself verified (signed-proof deliveries, heartbeat
        presence, hash-checked files) are labelled 'verified'. The
        dashboard renders the two differently — a claim never displays
        as a fact."""
        claimed = kind in ("work_progress", "message", "group_message",
                           "channel_message")
        # Owner oversight: the wrap rides the audit row as ciphertext
        # JSON — the relay stores it but can never open it (it holds
        # no oversight private key, by construction).
        oversight = json.dumps(oversight) if oversight else ""
        # Group/channel content envelope {epoch, nonce, ct}: also
        # ciphertext the relay cannot open (it holds no group key).
        # Persisted so the dashboard can combine it with the
        # oversight content-key wrap to render group/channel content
        # for the operator session.
        content_envelope = json.dumps(content_envelope) \
            if content_envelope else ""
        self.activity.appendleft({
            "ts": now_ts(), "kind": kind, "from": actor, "to": target,
            "group_id": group_id, "work_id": work_id, "status": status,
            "priority": priority,
            "sender_nickname": sender_nickname,
            "sender_role": sender_role,
            "sender_custom_role": sender_custom_role,
            "oversight": oversight or None,
            "content_envelope": content_envelope or None,
            "evidence": "claimed" if claimed else "verified"})
        try:
            self.store.audit(kind, actor, target, group_id, work_id, status,
                             priority, size=size, mentions=mentions,
                             ref_id=ref_id,
                             sender_nickname=sender_nickname,
                             sender_role=sender_role,
                             sender_custom_role=sender_custom_role,
                             oversight=oversight,
                             content_envelope=content_envelope)
        except Exception:
            pass
        if getattr(self, "dashboard", None) is not None:
            self.dashboard.notify()

    def _dashboard_data(self) -> dict:
        users = self.store.list_users()
        now = now_ts()
        for u in users:
            peer = self.peers.get(u["username"])
            # Presence derives from the 5-second heartbeat: a peer is
            # online only if its last sign of life is fresh.
            u["online"] = bool(peer) and \
                (now - peer.last_seen) <= OFFLINE_GRACE_SECONDS
            u["last_seen"] = peer.last_seen if peer else None
            u["riding"] = self.server_label if peer else None
            u["home"] = peer.home_endpoint if peer else None
            # NO GOING DARK (point 44c): the dashboard distinguishes
            # precisely — online at home, online via a peer, or
            # unreachable with its work protected by the backend.
            if not u["online"]:
                u["reachability"] = "unreachable — work protected"
            elif peer and peer.home_endpoint and \
                    not self._is_home_endpoint(peer.home_endpoint):
                u["reachability"] = f"online (via {self.server_label})"
            else:
                u["reachability"] = "online (home)"
            u["activity_state"] = peer.activity if peer else "offline"
            u.update(self._compliance_fields(u["username"]))
            u["trust_score"] = self.store.compute_trust(u["username"])
            u.pop("pubkey", None)
            u.pop("sign_pub", None)
        # Mesh state (v1.2.0): the live server registry, and — for
        # agents who HOST a server — that server's health, rider
        # load and capacity ride on the agent's own row, because on
        # this platform every agent carries its server's health.
        # v1.3.0: the dashboard view includes down per-agent servers
        # in their honest state, and a per-agent server is
        # attributed to its OWNER (permanent), never to the
        # temporary carrier whose machine happens to run it.
        servers = self._dashboard_servers()
        hosting = {}
        for s in servers:
            key = s.get("owner_agent") or s.get("host_agent")
            if key:
                hosting[key] = s
        for u in users:
            srv = hosting.get(u["username"])
            if srv:
                u["server_health"] = srv["health"]
                u["server_endpoint"] = srv["endpoint"]
                u["server_riders"] = srv["riders"]
                u["server_capacity"] = srv["capacity"]
                u["server_state"] = srv.get("carry_state") or ""
                u["server_carried_by"] = srv.get("carried_by") or ""
        return {
            "server": self.server_label,
            "servers": servers,
            "updates_enabled": self.updates_enabled,
            "online": sorted(u["username"] for u in users if u["online"]),
            "users": users,
            "groups": self.store.all_groups(),
            "channels": self.store.all_channels(),
            "rooms": [
                {"id": rid, "group_id": r["group_id"],
                 "participants": sorted(r["participants"]),
                 "creator": r["creator"], "opened_at": r["opened_at"]}
                for rid, r in getattr(self, "rooms", {}).items()],
            "work": self.store.list_work_meta(),
            "alerts": self.store.list_alerts(limit=50),
            "chains": self.store.list_chains_meta(),
            "library": self.store.library_all(),
            "vault": self.store.vault_meta(),
            "conversations": self._conversations(),
            "activity": [{**row, "evidence": (
                "claimed" if row.get("kind") in (
                    "work_progress", "message", "group_message",
                    "channel_message") else "verified")}
                for row in self.store.list_audit()],
        }

    def _conversations(self) -> list[dict]:
        """Per-conversation drill-down (point 40b): every message/work
        envelope's DETAILS (id, ts, sender, kind, size, mentions,
        priority, delivery status, evidence) grouped by conversation —
        1:1 pairs and groups. Content stays sealed; this is metadata
        the relay legitimately holds.

        IMMORTALITY (v1.3.2): composed from the store's FULL content
        history (list_content_audit), never from a bounded activity
        window. The pre-1.3.2 code read list_audit(500) — the 500
        newest audit rows of ALL kinds — so any conversation whose
        latest item aged past the presence/alert churn flooding the
        tail silently vanished from the dashboard while sitting
        intact in the store (owner-reported 2026-11-02: the beulah
        and deploy-probe conversations "disappeared" while only the
        freshest drill conversation rendered).

        TRUE CHRONOLOGY (v1.3.3): items inside a conversation are in
        ascending ts order — the head of a thread is its FIRST item,
        and the flow reads downward through time, WhatsApp-style.
        The pre-1.3.3 code reversed every item list at the end, so
        each thread opened with its NEWEST item: the restored
        beulah thread rendered Beulah's reply above Phoenix's
        opener, reading as if she had started a conversation
        Phoenix started (owner-reported 2026-11-02). The sort here
        is explicit, so the composed order is ts-ascending whatever
        order the store returned rows in.

        FIRST-CLASS CONVERSATIONS (v1.3.3): a group or broadcast
        channel IS a conversation from the moment it exists — it is
        seeded into this list from the group/channel registry even
        with zero messages (the pre-1.3.3 list only ever contained
        conversations that already had content rows, so the Nova
        family group was invisible in the chat list while it sat in
        the store)."""
        rows = self.store.list_content_audit()
        groups = {g["id"]: g for g in self.store.all_groups()}
        channels = {c["id"]: c for c in self.store.all_channels()}

        def _participants(gid: str) -> list:
            if gid in channels:
                return [{"username": m["username"],
                         "nickname": m.get("nickname", ""),
                         "role": m.get("role", ""),
                         "custom_role": m.get("custom_role", "")}
                        for m in self.store.channel_members(gid)]
            return [{"username": m["username"],
                     "nickname": m.get("nickname", ""),
                     "role": m.get("role", ""),
                     "custom_role": m.get("custom_role", "")}
                    for m in self.store.members(gid)]

        convs: dict[str, dict] = {}
        part_cache: dict[str, list] = {}
        for r in rows:
            if r["kind"] not in ("message", "group_message",
                                 "channel_message", "work_assigned",
                                 "work_delivered", "work_completed",
                                 "work_changes_requested", "work_progress",
                                 "work_awaiting_approval", "work_approved",
                                 "work_approval_rejected"):
                continue
            if r["group_id"]:
                key = "group:" + r["group_id"]
                if key not in part_cache:
                    part_cache[key] = _participants(r["group_id"])
                participants = part_cache[key]
            else:
                pair = sorted(x for x in (r["from"], r["to"]) if x)
                key = "dm:" + "|".join(pair)
                participants = pair
            c = convs.setdefault(key, {"key": key,
                                       "participants": participants,
                                       "group_id": r["group_id"] or None,
                                       "items": []})
            c["items"].append({
                "id": r.get("ref_id") or r.get("work_id") or "",
                "ts": r["ts"], "from": r["from"], "to": r["to"],
                "sender_nickname": r.get("sender_nickname", ""),
                "sender_role": r.get("sender_role", ""),
                "sender_custom_role": r.get("sender_custom_role", ""),
                "kind": r["kind"], "size": r.get("size", 0),
                "mentions": r.get("mentions") or [],
                "oversight": r.get("oversight"),
                "content_envelope": r.get("content_envelope"),
                "priority": r.get("priority") or "normal",
                "status": r.get("status", ""),
                "work_id": r.get("work_id", ""),
                "evidence": "claimed" if r["kind"] in (
                    "work_progress", "message", "group_message",
                    "channel_message") else "verified"})
        # Read receipts (v1.1.2): attach the recorded read state.
        # Items nobody read gain NO key at all — no read state is
        # ever fabricated for the dashboard payload (honesty rule).
        try:
            reads = self.store.reads_for(
                [i["id"] for c in convs.values() for i in c["items"]
                 if i["id"]])
        except Exception:
            reads = {}
        for c in convs.values():
            for item in c["items"]:
                rb = reads.get(item["id"])
                if rb:
                    item["read_by"] = rb
        # Stamp kind/name/created_at, then seed any group or channel
        # that has no content rows yet — it exists, so it is a
        # conversation (v1.3.3, see the docstring above).
        for gid, g in groups.items():
            key = "group:" + gid
            c = convs.get(key)
            if c is None:
                c = convs[key] = {"key": key,
                                  "participants": _participants(gid),
                                  "group_id": gid, "items": []}
            c["kind"] = "group"
            c["name"] = g.get("name", "")
            c["created_at"] = g.get("created_at") or 0
        for cid, ch in channels.items():
            key = "group:" + cid
            c = convs.get(key)
            if c is None:
                c = convs[key] = {"key": key,
                                  "participants": _participants(cid),
                                  "group_id": cid, "items": []}
            c["kind"] = "channel"
            c["name"] = ch.get("name", "")
            c["created_at"] = ch.get("created_at") or 0
        for c in convs.values():
            c.setdefault("kind", "dm")
            c.setdefault("name", "")
            c.setdefault("created_at", 0)
            # Explicit ascending sort (stable: equal-ts items keep
            # the store's arrival order) — never a reversal.
            c["items"].sort(key=lambda i: i["ts"])
        # Chat-list order: most recent activity first; a conversation
        # with no items yet sorts by its creation time.
        out = sorted(convs.values(),
                     key=lambda c: -((c["items"][-1]["ts"] if c["items"]
                                      else 0) or c["created_at"] or 0))
        return out

    def _resolve_dashboard_password(self) -> str:
        if self.dashboard_password:
            return self.dashboard_password
        env = os.environ.get("AGENTLINK_DASHBOARD_PASSWORD")
        if env:
            return env
        from pathlib import Path
        pw_file = Path(os.path.expanduser("~/.agentlink/dashboard-password.txt"))
        if pw_file.exists():
            return pw_file.read_text().strip()
        import secrets as _secrets
        pw = _secrets.token_urlsafe(18)
        pw_file.parent.mkdir(parents=True, exist_ok=True)
        pw_file.write_text(pw)
        try:
            os.chmod(pw_file, 0o600)
        except OSError:
            pass
        log.warning("dashboard password generated; stored at %s", pw_file)
        return pw

    def _census_gate_path(self) -> str:
        if self.census_baseline_path:
            return os.path.expanduser(self.census_baseline_path)
        db = os.path.expanduser(self.db_path)
        return os.path.join(os.path.dirname(db), "census-baseline.json")

    def _run_census_gate(self) -> None:
        """Immortality gate (v1.3.2): verify the store's conversation
        census against the durable baseline. Runs on a worker thread
        (the store may be network-backed). A detected loss has
        already been written to the record by the guard (alert +
        audit rows) before this logs it; the baseline then re-adopts
        the current state so one loss alerts once — the open alert
        is the standing signal until an operator resolves it."""
        from .census import CensusGuard, CensusLossError
        guard = CensusGuard(self.store, self._census_gate_path())
        try:
            result = guard.verify()
            log.info("census gate: %s (%s conversations, %s items)",
                     result.get("status"), result.get("conversations"),
                     result.get("items"))
        except CensusLossError as exc:
            log.error("CONVERSATION CENSUS LOSS DETECTED: %s", exc)
            try:
                guard.accept_current()
            except Exception:
                log.exception("census gate: re-baseline failed")

    async def start(self) -> "Relay":
        # Immortality gate BEFORE serving (v1.3.2): this process may
        # be brand-new code (an update), a restart, or a migration —
        # whatever changed since the last boot, the store's
        # conversations are verified against the baseline first, and
        # any loss is on the record before a single frame is served.
        # The relay still starts on a detected loss: the loss is a
        # fact to surface, and going dark would compound it.
        if self.census_gate_enabled:
            try:
                await asyncio.to_thread(self._run_census_gate)
            except Exception:
                log.exception("census gate failed to run")
        self._server = await serve(
            self._handle, self.host, self.port, max_size=MAX_FRAME,
        )
        if self.dashboard_enabled:
            from .dashboard import DashboardServer
            password = self._resolve_dashboard_password()
            dash_host = self.host
            self.dashboard = DashboardServer(
                self, dash_host, self.dashboard_port, password).start()
            self.dashboard_port = self.dashboard.port
        sockets = self._server.sockets or ()
        if sockets:
            self.port = sockets[0].getsockname()[1]
        log.info("relay listening on %s:%s", self.host, self.port)
        self._scan_task = asyncio.create_task(self._fleet_scan_loop())
        # Peer mesh (v1.2.0): register in the shared server registry
        # and heartbeat the row, so any client connecting anywhere
        # can discover this server. Off-loop: a network-backed
        # store's round trip must not stall the accept path.
        await asyncio.to_thread(self._register_server_row)
        self._server_hb_task = asyncio.create_task(
            self._server_heartbeat_loop())
        # Earned health (v1.3.0): the battery starts immediately —
        # this server is UNRATED until it has earned a percentage
        # through testing, and keeps re-testing for life.
        self._health_task = asyncio.create_task(
            self._health_battery_loop())
        # Server carrying (v1.3.0): every relay is a carrier — it
        # watches the registry and raises a brother's fallen server.
        if self.carrier_enabled:
            self._carrier_task = asyncio.create_task(
                self._carrier_loop())
        return self

    async def stop(self) -> None:
        if self._server_hb_task is not None:
            self._server_hb_task.cancel()
            self._server_hb_task = None
        if self._health_task is not None:
            self._health_task.cancel()
            self._health_task = None
        if self._carrier_task is not None:
            self._carrier_task.cancel()
            self._carrier_task = None
        if self._carried:
            # Graceful stop only: hand every carried server back to
            # the registry at once so another brother can claim it
            # without waiting for the lease to expire. (A crash
            # never runs this — the lease expiry covers that path.)
            try:
                await asyncio.wait_for(
                    asyncio.to_thread(self._release_all_carries),
                    timeout=10)
            except Exception:
                pass
        if self._scan_task is not None:
            self._scan_task.cancel()
            self._scan_task = None
        if getattr(self, "dashboard", None) is not None:
            self.dashboard.stop()
            self.dashboard = None
        # Force-close live peer sockets first (bounded): a relay
        # shutting down must never hang on connected clients.
        for peer in list(self.peers.values()):
            try:
                await asyncio.wait_for(peer.ws.close(), timeout=1)
            except Exception:
                try:
                    peer.ws.transport.close()
                except Exception:
                    pass
        self.peers.clear()
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        # Close the store only if this relay created it — a shared
        # backend handed in by the operator (failover topology) is
        # owned by the fleet, not by one relay process.
        if self.backend_store is None:
            self.store.close()


    # -- fleet operations: reassignment, deadline pressure, alerts --------------
    def _is_alive(self, username: str, grace: int) -> bool:
        """Backend-wide presence (point 29): alive = a heartbeat landed
        SOMEWHERE (any relay sharing the backend) within the grace."""
        now = now_ts()
        peer = self.peers.get(username)
        if peer is not None and now - peer.last_seen <= grace:
            return True
        try:
            return now - self.store.last_seen_of(username) <= grace
        except Exception:
            return False

    async def _fleet_scan_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(1)
                await self._fleet_scan_once()
                self._health_event("scan_ok")
            except asyncio.CancelledError:
                return
            except Exception:
                self._health_event("scan_fail")
                log.exception("fleet scan failed")

    async def _fleet_scan_once(self) -> None:
        now = now_ts()
        store = self.store
        # v1.1 hardening: the scan's bulk store work runs on worker
        # threads (asyncio.to_thread), never on the event loop. With a
        # network-backed store (Supabase) every call is a round trip;
        # on the loop it starved hello/message handling and wedged
        # reconnecting agents. Semantics are unchanged — the scan
        # still runs sequentially, once per tick, in the same order;
        # only the waiting moved off the loop. Frame delivery stays on
        # the loop (it owns the sockets).
        #
        # Cross-relay live drain (points 16/18): frames queued via
        # ANOTHER relay sharing this backend (or while this agent was
        # between connections) are pushed to the agent on THIS relay
        # within one scan tick — real-time across the fleet, not
        # just at hello. dequeue is atomic in the store, and _deliver
        # re-queues on a dead socket, so nothing is lost or doubled.
        usernames = [u for u, p in list(self.peers.items())
                     if not getattr(p, "ephemeral", False)]

        def _drain():
            out = {}
            for u in usernames:
                try:
                    out[u] = store.dequeue_all(u)
                except Exception:
                    continue
            return out

        for username, queued in (await asyncio.to_thread(_drain)).items():
            for frame in queued:
                await self._deliver(username, frame)
        grace = self.reassign_grace_seconds

        def _reassign_candidates():
            picked = []
            for work in store.open_work():
                if not work.get("auto_reassign"):
                    continue
                assignee = work["assignee"]
                if self._is_alive(assignee, grace):
                    continue
                last = 0
                try:
                    last = store.last_seen_of(assignee)
                except Exception:
                    pass
                peer = self.peers.get(assignee)
                if peer is not None:
                    last = max(last, peer.last_seen)
                if last and now - last <= grace:
                    continue
                if not last and now - work["updated_at"] <= grace:
                    continue
                picked.append(work)
            return picked

        for work in await asyncio.to_thread(_reassign_candidates):
            await self._attempt_reassign(work)
        # Deadline pressure (point 36 — Pacific instants only).
        from .deadlines import pressure_thresholds, pacific_display
        for work in await asyncio.to_thread(
                self.store.open_work,
                ("assigned", "in_progress", "changes_requested")):
            deadline = work.get("deadline")
            if not deadline:
                continue
            key = (work["id"], work.get("attempt", 1))
            th = pressure_thresholds(work["created_at"], deadline)
            for name, at in (("half", th["warn_50_at"]),
                             ("late", th["warn_late_at"])):
                fkey = key + (name,)
                if now >= at and now <= deadline and \
                        fkey not in self._pressure_fired:
                    self._pressure_fired.add(fkey)
                    await self._deliver(work["assignee"], {
                        "type": "deadline_warning", "work": work,
                        "threshold": name,
                        "deadline_pt": pacific_display(deadline)})
                    self._log_activity("deadline_warning", "system",
                                       target=work["assignee"],
                                       work_id=work["id"], status=name)
            okey = key + ("overdue",)
            if now > deadline and okey not in self._pressure_fired:
                self._pressure_fired.add(okey)
                updated = await asyncio.to_thread(
                    self.store.escalate_work_priority, work["id"])
                await self._deliver(work["assigner"], {
                    "type": "work_overdue", "work": updated,
                    "deadline_pt": pacific_display(deadline)})
                await self._deliver(work["assignee"], {
                    "type": "work_overdue", "work": updated,
                    "deadline_pt": pacific_display(deadline)})
                self._log_activity("work_overdue", "system",
                                   target=work["assignee"],
                                   work_id=work["id"], status="overdue",
                                   priority="urgent")
        for chain in await asyncio.to_thread(self.store.list_chains_meta):
            if chain["status"] == "paused" and chain.get("paused_since") \
                    and now - chain["paused_since"] \
                    > self.chain_pause_alert_seconds:
                alert = await asyncio.to_thread(
                    self.store.open_alert,
                    "chain_paused", chain["id"],
                    "chain paused on changes_requested")
                await self._dispatch_alert(alert)
        await self._alert_scan(now)

    async def _attempt_reassign(self, work: dict, forced: str = "") -> bool:
        gid = work.get("group_id")
        old = work["assignee"]
        store = self.store
        grace = self.reassign_grace_seconds

        def _pick():
            # Store reads (member list + backend-wide liveness) run on
            # this worker thread — see _fleet_scan_once (v1.1 offload).
            candidate = ""
            if gid:
                members = store.members(gid)
                alive = [m for m in members
                         if m["username"] not in (old, work["assigner"])
                         and self._is_alive(m["username"], grace)]
                if forced:
                    candidate = forced if any(
                        m["username"] == forced for m in alive) else ""
                else:
                    role = (work.get("assignee_role") or "").lower()
                    same_role = [m for m in alive
                                 if (m.get("custom_role") or "").lower()
                                 == role and role]
                    pick = (same_role or alive)
                    candidate = pick[0]["username"] if pick else ""
            return candidate

        candidate = await asyncio.to_thread(_pick)
        if not candidate:
            if work["status"] != "awaiting_agent":
                updated = await asyncio.to_thread(
                    store.set_awaiting_agent, work["id"])
                await self._deliver(work["assigner"], {
                    "type": "work_update", "work": updated,
                    "note": "assignee unreachable; awaiting an agent"})
                self._log_activity("work_awaiting_agent", "system",
                                   target=old, group_id=gid or "",
                                   work_id=work["id"],
                                   status="awaiting_agent")
            return False
        updated = await asyncio.to_thread(
            store.reassign_work, work["id"], candidate)
        # The replacement reads the GROUP-encrypted copy + the mirrored
        # checkpoint (checkpoints travel with the assignment, point 30).
        view = dict(updated)
        view["content_enc"] = None
        await self._deliver(candidate, {
            "type": "work_assigned", "work": view,
            "reassigned_from": old, "attempt": updated["attempt"]})
        await self._deliver(work["assigner"], {
            "type": "work_reassigned", "work": updated,
            "from": old, "to": candidate})
        await self._deliver(old, {
            "type": "work_reassigned_notice", "work_id": work["id"],
            "attempt": updated["attempt"], "to": candidate})
        self._log_activity("work_reassigned", "system", target=candidate,
                           group_id=gid or "", work_id=work["id"],
                           status=f"attempt {updated['attempt']}")
        alert = await asyncio.to_thread(
            store.open_alert,
            "reassignment", work["id"],
            f"{old} unreachable; reassigned to {candidate}")
        await self._dispatch_alert(alert)
        return True

    # -- fleet alerts (point 37) -------------------------------------------------
    async def _dispatch_alert(self, alert: dict, reminder: bool = False):
        if alert["id"] in self._alert_dispatched and not reminder:
            return
        self._alert_dispatched.add(alert["id"])
        self._log_activity("alert", "system", target=alert["subject"],
                           status=alert["kind"])
        payload = {"alert": alert, "reminder": reminder,
                   "server": self.server_label, "ts": now_ts()}
        if self.alert_webhook:
            asyncio.create_task(self._post_webhook(payload))
        email_to = os.environ.get("AGENTLINK_ALERT_EMAIL_TO")
        if email_to and os.environ.get("AGENTLINK_SMTP_HOST"):
            asyncio.create_task(asyncio.to_thread(
                self._send_alert_email, email_to, payload))

    async def _post_webhook(self, payload: dict) -> None:
        import hashlib as _hl
        import hmac as _hm
        import urllib.request
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        secret = os.environ.get("AGENTLINK_ALERT_WEBHOOK_SECRET", "")
        if secret:
            headers["X-AgentLink-Signature"] = "sha256=" + _hm.new(
                secret.encode(), body, _hl.sha256).hexdigest()
        req = urllib.request.Request(self.alert_webhook, data=body,
                                     headers=headers, method="POST")
        try:
            await asyncio.to_thread(
                lambda: urllib.request.urlopen(req, timeout=10).read())
        except Exception:
            log.exception("alert webhook delivery failed")

    @staticmethod
    def _send_alert_email(to_addr: str, payload: dict) -> None:
        import smtplib
        from email.message import EmailMessage
        alert = payload["alert"]
        msg = EmailMessage()
        msg["Subject"] = f"[AgentLink] {alert['kind']}: {alert['subject']}"
        msg["From"] = os.environ.get("AGENTLINK_SMTP_FROM", "agentlink@localhost")
        msg["To"] = to_addr
        msg.set_content(json.dumps(payload, indent=2))
        with smtplib.SMTP(os.environ["AGENTLINK_SMTP_HOST"],
                          int(os.environ.get("AGENTLINK_SMTP_PORT", "25")),
                          timeout=15) as smtp:
            user = os.environ.get("AGENTLINK_SMTP_USER")
            if user:
                smtp.starttls()
                smtp.login(user, os.environ.get("AGENTLINK_SMTP_PASSWORD", ""))
            smtp.send_message(msg)

    async def _alert_scan(self, now: int) -> None:
        # All store work offloaded (v1.1 — see _fleet_scan_once).
        store = self.store
        # Agent offline beyond threshold -> exactly one open alert.
        for u in await asyncio.to_thread(store.list_users):
            name = u["username"]
            if name in self.peers:
                continue
            try:
                last = await asyncio.to_thread(store.last_seen_of, name)
            except Exception:
                last = 0
            if last and now - last > self.alert_offline_seconds:
                alert = await asyncio.to_thread(
                    store.open_alert,
                    "agent_offline", name,
                    f"no heartbeat for {now - last}s")
                await self._dispatch_alert(alert)
        # URGENT items sitting undelivered beyond threshold.
        try:
            urgent = await asyncio.to_thread(store.oldest_urgent_queued)
        except Exception:
            urgent = []
        waiting = {r["to_username"] for r in urgent
                   if now - r["since"] > self.alert_urgent_seconds}
        for name in waiting:
            alert = await asyncio.to_thread(
                store.open_alert,
                "urgent_undelivered", name,
                "urgent item waiting in the offline queue")
            await self._dispatch_alert(alert)
        for alert in await asyncio.to_thread(
                store.list_alerts, status="open"):
            if alert["kind"] == "urgent_undelivered" and \
                    alert["subject"] not in waiting and \
                    alert["subject"] not in {r["to_username"]
                                             for r in urgent}:
                await asyncio.to_thread(
                    store.resolve_alerts, "urgent_undelivered",
                    alert["subject"])
            # Throttled reminders for still-open incidents.
            last_touch = max(alert["created_at"],
                             alert["last_reminder_at"])
            if now - last_touch > self.alert_reminder_seconds:
                await asyncio.to_thread(store.bump_reminder, alert["id"])
                await self._dispatch_alert(alert, reminder=True)

    # -- plumbing ---------------------------------------------------------
    @staticmethod
    async def _send(ws, frame: dict) -> None:
        await ws.send(json.dumps(frame))

    async def _result(self, ws, req_id, ok: bool, data: dict) -> None:
        await self._send(ws, {"type": "result", "req_id": req_id,
                              "ok": ok, "data": data})

    async def _error(self, ws, reason: str, req_id=None, detail: str = "") -> None:
        await self._send(ws, {"type": "error", "req_id": req_id,
                              "reason": reason, "detail": detail})

    async def _deliver(self, username: str, frame: dict) -> bool:
        """Live-deliver a frame, else queue it offline. Returns queued?"""
        peer = self.peers.get(username)
        if peer is not None:
            try:
                await self._send(peer.ws, frame)
                return False
            except websockets.exceptions.ConnectionClosed:
                pass
        self.store.enqueue(username, frame)
        return True

    # -- connection ---------------------------------------------------------
    async def _handle(self, ws) -> None:
        peer: Peer | None = None
        # Carrying (v1.3.0): a connection may arrive through a carry
        # alias (?carry=<id> or /carry/<id>) — this relay serves
        # that server's identity ONLY while it holds the carry
        # lease for it. An alias nobody here carries is refused at
        # the door: a stale alias must never silently become a
        # different server.
        conn_server_id = self._connection_server_id(ws)
        if conn_server_id and conn_server_id != self.server_id \
                and conn_server_id not in self._carried:
            try:
                await ws.close(code=4404,
                               reason="server not carried here")
            except Exception:
                pass
            return
        try:
            async for raw in ws:
                try:
                    frame = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    await self._error(ws, "bad_frame")
                    continue
                if not isinstance(frame, dict):
                    await self._error(ws, "bad_frame")
                    continue
                ftype = frame.get("type")
                req_id = frame.get("req_id")
                if peer is not None:
                    peer.last_seen = now_ts()
                if ftype == "hello":
                    try:
                        peer = await self._on_hello(
                            ws, frame, peer,
                            server_id=conn_server_id or self.server_id)
                    except Exception:
                        # A hello that dies inside the server is a
                        # measured admission failure (health signal);
                        # client-fault rejections return normally
                        # and never count against the server.
                        self._health_event("hello_fail")
                        raise
                elif ftype == "ping":
                    if peer is not None:
                        peer.last_seen = now_ts()
                        if frame.get("activity"):
                            peer.activity = str(frame["activity"])[:40]
                        if now_ts() - peer.touched_at >= 2:
                            peer.touched_at = now_ts()
                            try:
                                self.store.touch(peer.username)
                            except Exception:
                                pass
                    await self._send(ws, {"type": "pong", "req_id": req_id})
                elif peer is None:
                    await self._error(ws, "not_registered", req_id)
                elif ftype == "blob_put":
                    await self._on_blob_put(ws, frame, peer)
                elif ftype == "blob_get":
                    await self._on_blob_get(ws, frame, peer)
                elif ftype == "blob_delete":
                    await self._on_blob_delete(ws, frame, peer)
                elif ftype == "send":
                    await self._on_send(ws, frame, peer)
                elif ftype == "read":
                    await self._on_read(ws, frame, peer)
                elif ftype == "group_create":
                    await self._on_group_create(ws, frame, peer)
                elif ftype == "group_add":
                    await self._on_group_add(ws, frame, peer)
                elif ftype == "group_remove":
                    await self._on_group_remove(ws, frame, peer)
                elif ftype == "get_key":
                    target = normalize_username(frame.get("username"))
                    await self._result(ws, req_id, True, {
                        "username": target,
                        "pubkey": self.store.pubkey_of(target) if target else "",
                        "sign_pub": self.store.sign_pub_of(target)
                        if target else ""})
                elif ftype == "group_members":
                    await self._on_group_members(ws, frame, peer)
                elif ftype == "group_nickname":
                    await self._on_group_nickname(ws, frame, peer)
                elif ftype == "group_custom_role":
                    await self._on_group_custom_role(ws, frame, peer)
                elif ftype == "set_group_keys":
                    await self._on_set_group_keys(ws, frame, peer)
                elif ftype == "get_group_key":
                    await self._on_get_group_key(ws, frame, peer)
                elif ftype in ("group_promote", "group_demote"):
                    await self._on_group_role(ws, frame, peer,
                                              promote=(ftype == "group_promote"))
                elif ftype == "group_settings":
                    await self._on_group_settings(ws, frame, peer)
                elif ftype == "group_join_link":
                    await self._on_group_join_link(ws, frame, peer)
                elif ftype == "group_join":
                    await self._on_group_join(ws, frame, peer)
                elif ftype == "group_send":
                    await self._on_group_send(ws, frame, peer)
                elif ftype == "assign":
                    await self._on_assign(ws, frame, peer)
                elif ftype == "deliver_work":
                    await self._on_deliver_work(ws, frame, peer)
                elif ftype == "work_progress":
                    await self._on_work_progress(ws, frame, peer)
                elif ftype == "work_checkpoint":
                    await self._on_work_checkpoint(ws, frame, peer)
                elif ftype == "chain_create":
                    await self._on_chain_create(ws, frame, peer)
                elif ftype == "chain_cancel":
                    await self._on_chain_cancel(ws, frame, peer)
                elif ftype == "chain_list":
                    await self._on_chain_list(ws, frame, peer)
                elif ftype == "chain_get":
                    await self._on_chain_get(ws, frame, peer)
                elif ftype == "work_resume_failed":
                    await self._on_work_resume_failed(ws, frame, peer)
                elif ftype == "library_search":
                    await self._on_library_search(ws, frame, peer)
                elif ftype == "library_fetch":
                    await self._on_library_fetch(ws, frame, peer)
                elif ftype == "vault_add":
                    await self._on_vault_add(ws, frame, peer)
                elif ftype == "vault_list":
                    await self._on_vault_list(ws, frame, peer)
                elif ftype == "vault_pin":
                    await self._on_vault_pin(ws, frame, peer)
                elif ftype == "vault_remove":
                    await self._on_vault_remove(ws, frame, peer)
                elif ftype == "channel_create":
                    await self._on_channel_create(ws, frame, peer)
                elif ftype == "channel_add":
                    await self._on_channel_add(ws, frame, peer)
                elif ftype == "channel_remove":
                    await self._on_channel_remove(ws, frame, peer)
                elif ftype == "channel_members":
                    await self._on_channel_members(ws, frame, peer)
                elif ftype == "channel_promote":
                    await self._on_channel_role(ws, frame, peer)
                elif ftype == "channel_send":
                    await self._on_channel_send(ws, frame, peer)
                elif ftype == "channel_join_link":
                    await self._on_channel_join_link(ws, frame, peer)
                elif ftype == "channel_join":
                    await self._on_channel_join(ws, frame, peer)
                elif ftype == "set_channel_keys":
                    await self._on_set_channel_keys(ws, frame, peer)
                elif ftype == "get_channel_key":
                    await self._on_get_channel_key(ws, frame, peer)
                elif ftype == "room_open":
                    await self._on_room_open(ws, frame, peer)
                elif ftype == "room_join":
                    await self._on_room_join(ws, frame, peer)
                elif ftype == "room_leave":
                    await self._on_room_leave(ws, frame, peer)
                elif ftype == "room_close":
                    await self._on_room_close(ws, frame, peer)
                elif ftype == "room_signal":
                    await self._on_room_signal(ws, frame, peer)
                elif ftype == "blob_session_start":
                    await self._on_blob_session_start(ws, frame, peer)
                elif ftype == "blob_chunk":
                    await self._on_blob_chunk(ws, frame, peer)
                elif ftype == "blob_session_status":
                    await self._on_blob_session_status(ws, frame, peer)
                elif ftype == "blob_session_finish":
                    await self._on_blob_session_finish(ws, frame, peer)
                elif ftype == "work_action":
                    await self._on_work_action(ws, frame, peer)
                elif ftype == "work_inbox":
                    inbox = self.store.list_work(
                        peer.username, frame.get("status"), frame.get("group_id"))
                    await self._result(ws, req_id, True, {"work": inbox})
                elif ftype == "update_capabilities":
                    await self._on_update_capabilities(ws, frame, peer)
                elif ftype == "chain_context":
                    step = self.store.step_by_work(
                        str(frame.get("work_id") or ""))
                    nxt_assignees: list[str] = []
                    if step is not None:
                        chain = self.store.get_chain(step["chain_id"])
                        if chain is not None:
                            nxt = next(
                                (x for x in chain["steps"]
                                 if x["position"]
                                 == step["position"] + 1), None)
                            if nxt is not None:
                                nxt_assignees = nxt.get("assignees") or []
                    await self._result(ws, req_id, True, {
                        "chain_id": step["chain_id"] if step else "",
                        "next_assignees": nxt_assignees})
                elif ftype == "my_groups":
                    await self._result(ws, req_id, True, {
                        "groups": self.store.groups_for_user(peer.username),
                        "channels": self.store.channels_for_user(
                            peer.username)})
                elif ftype == "self_report":
                    self.store.audit("self_repair", peer.username,
                                     status=str(frame.get("event") or ""))
                    self._log_activity("self_repair", peer.username,
                                       status=str(frame.get("event") or ""))
                    await self._result(ws, req_id, True, {"ok": True})
                elif ftype == "directory":
                    users = self.store.list_users(
                        str(frame.get("query") or ""),
                        capability=str(frame.get("capability") or ""))
                    hosting = {}
                    for s in self._dashboard_servers():
                        key = s.get("owner_agent") or \
                            s.get("host_agent")
                        if key:
                            hosting[key] = s
                    for u in users:
                        u["online"] = u["username"] in self.peers
                        u["trust_score"] = self.store.compute_trust(
                            u["username"])
                        u.update(self._compliance_fields(u["username"]))
                        srv = hosting.get(u["username"])
                        if srv:
                            # Health is published in the directory:
                            # an agent who hosts a server carries its
                            # health % for everyone to route by.
                            u["server_health"] = srv["health"]
                            u["server_endpoint"] = srv["endpoint"]
                            u["server_riders"] = srv["riders"]
                            u["server_capacity"] = srv["capacity"]
                            u["server_state"] = \
                                srv.get("carry_state") or ""
                            u["server_carried_by"] = \
                                srv.get("carried_by") or ""
                        u.pop("secret", None)
                    users.sort(key=lambda u: (not u["online"],
                                              u["username"]))
                    await self._result(ws, req_id, True, {"users": users})
                elif ftype == "whoami":
                    await self._result(ws, req_id, True, {
                        "username": peer.username,
                        "display_name": peer.display_name,
                        "online": True,
                    })
                elif ftype == "servers":
                    # Peer discovery (v1.2.0): the live mesh, from
                    # the shared registry. Clients merge this into
                    # their race set and persist it (see client).
                    await self._result(ws, req_id, True, {
                        "servers": self._live_servers()})
                elif ftype == "deregister":
                    await self._on_deregister(ws, frame, peer)
                else:
                    await self._error(ws, "unknown_type", req_id)
        except websockets.exceptions.ConnectionClosed:
            pass
        finally:
            if peer is not None and self.peers.get(peer.username) is peer:
                del self.peers[peer.username]
                if not peer.ephemeral:
                    if peer.connected_at:
                        # Session history feeds the check-in pattern
                        # flag (hardened-core compliance visibility).
                        self._record_session(peer.username,
                                             peer.connected_at,
                                             now_ts())
                    self._log_activity("offline", peer.username)
                log.info("peer @%s disconnected", peer.username)

    async def _on_hello(self, ws, frame, old, server_id: str = ""):
        if old is not None and self.peers.get(old.username) is old:
            del self.peers[old.username]
        req_id = frame.get("req_id")
        display = str(frame.get("display_name") or frame.get("name") or "")[:64]
        secret = frame.get("secret")
        pubkey = str(frame.get("pubkey") or "")
        sign_pub = str(frame.get("sign_pub") or "")
        # Hardened core (v1.2.0): the client declares its core
        # fingerprint; the relay records it verbatim and judges it
        # against the hardcoded constants — never trusts it.
        core = self._sanitize_core(frame.get("core"))
        if frame.get("ephemeral"):
            username = "dial-" + new_id()[:8]
            peer = Peer(ws=ws, username=username, display_name=display or "dial",
                        pubkey=pubkey, ephemeral=True, last_seen=now_ts(),
                        connected_at=now_ts(), core=core,
                        server_id=server_id or self.server_id)
            self.peers[username] = peer
            await self._send(ws, {"type": "welcome", "req_id": req_id,
                                  "username": username, "secret": None,
                                  "ephemeral": True, "queued": 0,
                                  "servers": self._live_servers(),
                                  "updates_enabled": self.updates_enabled,
                                  "oversight_pubkey":
                                      self.oversight_pubkey or None})
            self._health_event("hello_ok")
            return peer
        username = normalize_username(frame.get("username"))
        if username is None:
            await self._error(ws, "bad_username", req_id,
                              "usernames are 2-32 chars: a-z 0-9 . _ -")
            return None
        # Platform autonomy law (v1.1.7): the agent declares its own
        # mode in the hello; the relay records it verbatim and never
        # assigns one. Absent/invalid = no declaration = the stored
        # profile (whose default is autonomous) stands.
        declared_mode = frame.get("mode")
        if declared_mode not in ("manual", "autonomous"):
            declared_mode = None
        # Mesh admission (v1.2.0, owner's rules) — checked BEFORE
        # identity claim/verification (v1.3.0 root-cause fix): a
        # RIDER — an agent whose home is ANOTHER server — is
        # admitted only while this server is worth riding: health
        # ABOVE the floor and rider capacity free (capacity =
        # floor(10 x health/100), hard cap 10). A refusal names its
        # reason so the client deflects to the next eligible server
        # instead of dying. HOME agents are never gated: your own
        # server always takes you back. Admission used to run AFTER
        # the identity claim, so a first-ever hello refused by an
        # unrated/full/unhealthy server stranded the claimed
        # identity: the secret stayed server-side, the client never
        # received it, and every retry died as username_taken.
        home_ep = str(frame.get("home_endpoint") or "")
        if home_ep and not self._is_home_endpoint(home_ep):
            health = self._compute_health()
            if health == HEALTH_UNRATED:
                await self._error(
                    ws, "server_unrated", req_id,
                    "this server has not earned a health rating yet "
                    "(still testing) — not accepting riders")
                return None
            if health <= SERVER_HEALTHY_MIN:
                await self._error(
                    ws, "server_unhealthy", req_id,
                    f"health {health}% is at/below the "
                    f"{SERVER_HEALTHY_MIN}% floor — not accepting "
                    "riders")
                return None
            cap = effective_capacity(health)
            if self._riders_count(exclude=username) >= cap:
                await self._error(
                    ws, "server_full", req_id,
                    f"rider capacity {cap} reached at health "
                    f"{health}% — try another server")
                return None
        if self.store.exists(username):
            if self.store.verify(username, secret):
                self.store.set_display_name(username, display or username)
                self.store.set_pubkey(username, pubkey)
                self.store.set_sign_pub(username, sign_pub)
                if declared_mode:
                    self.store.set_mode(username, declared_mode)
            else:
                await self._error(ws, "username_taken", req_id)
                return None
            owner_secret = secret
        else:
            try:
                owner_secret = self.store.claim(
                    username, display or username, pubkey, sign_pub,
                    capabilities=frame.get("capabilities") or [],
                    cap_desc=str(frame.get("cap_description") or ""),
                    mode=declared_mode or "autonomous")
            except UsernameTaken:
                await self._error(ws, "username_taken", req_id)
                return None
        stale = self.peers.get(username)
        if stale is not None and stale.ws is not ws:
            try:
                await stale.ws.close(code=4000, reason="superseded")
            except Exception:
                pass
        peer = Peer(ws=ws, username=username,
                    display_name=display or username, pubkey=pubkey,
                    last_seen=now_ts(), connected_at=now_ts(), core=core,
                    home_endpoint=home_ep,
                    server_id=server_id or self.server_id)
        self.peers[username] = peer
        if core:
            self._last_core[username] = core
        try:
            self.store.touch(username)
        except Exception:
            pass
        if self.store.resolve_alerts("agent_offline", username):
            self._log_activity("alert_resolved", "system", target=username,
                               status="agent_offline")
        self._log_activity("online", username)
        queued = self.store.dequeue_all(username)
        await self._send(ws, {"type": "welcome", "req_id": req_id,
                              "username": username, "secret": owner_secret,
                              "ephemeral": False, "queued": len(queued),
                              "servers": self._live_servers(),
                              "updates_enabled": self.updates_enabled,
                              "oversight_pubkey":
                                  self.oversight_pubkey or None})
        for q in queued:
            await self._send(ws, q)
            if q.get("type") == "message" and q.get("id"):
                # A queued message's audit row said 'sent'/'queued'
                # while it waited; the flush IS the delivery.
                try:
                    self.store.set_audit_status(q["id"], "delivered")
                except Exception:
                    pass
        log.info("peer @%s registered, flushed %d queued", username, len(queued))
        # Awaiting-agent work: an agent coming online picks up pooled
        # group work immediately (point 29 fallback). DIRECT work is
        # restored too (v1.3.1): a 1:1 work parked in awaiting_agent
        # while its NAMED assignee was unreachable returns to
        # 'assigned' for that same assignee and is delivered — parked
        # must never mean stranded (the transition map only allows
        # awaiting_agent -> assigned, and before this fix no path
        # took it for direct work).
        try:
            for work in self.store.open_work(("awaiting_agent",)):
                gid = work.get("group_id")
                if not gid and work.get("assignee") == username and \
                        work["assigner"] != username:
                    restored = await asyncio.to_thread(
                        self.store.restore_awaiting, work["id"])
                    if restored.get("status") == "assigned":
                        await self._deliver(username, {
                            "type": "work_assigned", "work": restored})
                        self._log_activity("work_restored", "system",
                                           target=username,
                                           work_id=work["id"],
                                           status="assigned")
                elif gid and work["assigner"] != username and \
                        self.store.role_of(gid, username) is not None:
                    await self._attempt_reassign(work, forced=username)
        except Exception:
            log.exception("awaiting-agent pickup failed")
        self._health_event("hello_ok")
        return peer

    # -- sealed file blobs (R2 in production; relay proxies ciphertext) -----
    async def _on_deregister(self, ws, frame, peer: Peer) -> None:
        """Self-deregistration (v1.1.10): an agent removes its OWN
        registration. The connection was authenticated at hello with
        the agent's secret — the same auth every frame rides — and
        the relay acts ONLY on peer.username, so this frame can
        never name another agent. Fail-closed: the store refuses
        while non-terminal work, undelivered queue frames or live
        chain entanglements stand (RemovalBlocked), so live work is
        never orphaned by an exit. On success the peer is dropped
        and the socket closed — the identity is gone."""
        req_id = frame.get("req_id")
        if peer.ephemeral:
            await self._error(ws, "ephemeral_no_registration", req_id,
                              "ephemeral callers have no registration")
            return
        try:
            result = self.store.remove_user(
                peer.username, actor=peer.username, via="self")
        except RemovalBlocked as exc:
            await self._error(ws, "deregister_blocked", req_id,
                              "; ".join(exc.blockers))
            return
        except NotFound:
            await self._error(ws, "unknown_username", req_id)
            return
        if self.peers.get(peer.username) is peer:
            del self.peers[peer.username]
        log.info("peer @%s deregistered itself (%d rows removed)",
                 peer.username, result["total"])
        await self._result(ws, req_id, True, result)
        try:
            await ws.close(code=1000, reason="deregistered")
        except Exception:
            pass

    async def _on_blob_put(self, ws, frame, peer: Peer) -> None:
        import base64 as _b64
        import hashlib as _hl
        req_id = frame.get("req_id")
        try:
            data = _b64.b64decode(frame.get("data_b64") or "")
        except Exception:
            await self._error(ws, "bad_blob", req_id)
            return
        if not data:
            await self._error(ws, "bad_blob", req_id, "empty blob")
            return
        for_user = normalize_username(frame.get("for_user"))
        for_group = frame.get("for_group")
        if for_group:
            if self.store.role_of(for_group, peer.username) is None:
                await self._error(ws, "not_a_member", req_id)
                return
        elif for_user:
            if not self.store.exists(for_user):
                await self._error(ws, "unknown_username", req_id, for_user)
                return
        else:
            await self._error(ws, "bad_blob", req_id,
                              "blob needs for_user or for_group")
            return
        blob_id = "b-" + _hl.sha256(data).hexdigest()
        # Blob I/O offloaded (v1.1 Phase-1 live fix): with the R2
        # backend a put/get is a network round trip with retries;
        # on the event loop it starved hello/message handling and
        # blob fetches timed out on the requesting client.
        try:
            await asyncio.to_thread(self.blob_store.put, blob_id, data)
        except Exception:
            log.exception("blob store put failed")
            await self._error(ws, "blob_store_failed", req_id,
                              "object storage write failed; retry")
            return
        self.store.put_blob_meta(blob_id, owner=peer.username,
                                 for_user=for_user or "",
                                 for_group=for_group or "",
                                 size=len(data))
        await self._result(ws, req_id, True,
                           {"blob_id": blob_id, "size": len(data)})

    def _blob_authorized(self, meta, username) -> bool:
        if meta is None:
            return False
        if username in (meta["owner"], meta.get("for_user")):
            return True
        gid = meta.get("for_group")
        if bool(gid) and self.store.role_of(gid, username) is not None:
            return True
        # Channel-scoped blobs are readable by channel members — the
        # symmetric counterpart of the membership check at upload
        # session start (v1.0 recorded the scope but never honoured
        # it here, so subscribers could never fetch channel files).
        cid = meta.get("for_channel")
        return bool(cid) and self.store.channel_role_of(
            cid, username) is not None

    async def _on_blob_get(self, ws, frame, peer: Peer) -> None:
        import base64 as _b64
        req_id = frame.get("req_id")
        meta = self.store.get_blob_meta(str(frame.get("blob_id") or ""))
        if not self._blob_authorized(meta, peer.username):
            await self._error(ws, "permission_denied", req_id,
                              "not a recipient of this blob")
            return
        from .blobstore import BlobNotFound
        try:
            data = await asyncio.to_thread(self.blob_store.get,
                                           meta["id"])
        except BlobNotFound:
            await self._error(ws, "unknown_blob", req_id)
            return
        except Exception:
            # Object-store transport failure (egress window): answer
            # with a clean error frame — never kill the connection
            # (v1.1 Phase-1 live fix; an uncaught store exception
            # used to tear the socket down mid-request).
            log.exception("blob store get failed")
            await self._error(ws, "blob_fetch_failed", req_id,
                              "object storage read failed; retry")
            return
        await self._result(ws, req_id, True,
                           {"blob_id": meta["id"],
                            "data_b64": _b64.b64encode(data).decode()})

    async def _on_blob_delete(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        meta = self.store.get_blob_meta(str(frame.get("blob_id") or ""))
        if meta is None:
            await self._error(ws, "unknown_blob", req_id)
            return
        allowed = peer.username == meta["owner"]
        gid = meta.get("for_group")
        if gid and self.store.role_of(gid, peer.username) in ADMIN_ROLES:
            allowed = True
        if not allowed:
            await self._error(ws, "permission_denied", req_id,
                              "only the owner or a group admin can delete")
            return
        try:
            await asyncio.to_thread(self.blob_store.delete, meta["id"])
        except Exception:
            log.exception("blob store delete failed")
            await self._error(ws, "blob_store_failed", req_id,
                              "object storage delete failed; retry")
            return
        self.store.delete_blob_meta(meta["id"])
        await self._result(ws, req_id, True, {"blob_id": meta["id"],
                                              "deleted": True})

    # -- 1:1 messages (E2EE: relay routes ciphertext only) -------------------
    @staticmethod
    def _is_envelope(content) -> bool:
        return isinstance(content, dict) and bool(content.get("ct"))

    @staticmethod
    def _valid_oversight(ov) -> bool:
        """Shape check ONLY (the relay cannot and must not verify the
        wrap cryptographically — it holds no oversight private key):
        the standard envelope {alg, eph_pub, nonce, ct}."""
        if not isinstance(ov, dict):
            return False
        if ov.get("alg") != "x25519-chacha20poly1305":
            return False
        return all(isinstance(ov.get(k), str) and ov.get(k)
                   for k in ("eph_pub", "nonce", "ct"))

    async def _oversight_gate(self, ws, frame, req_id) -> bool:
        """AGENTLINK_REQUIRE_OVERSIGHT=1: content frames without a
        valid-shaped oversight wrap are rejected. Default off."""
        if not self.require_oversight:
            return True
        if self._valid_oversight(frame.get("oversight")):
            return True
        await self._error(ws, "oversight_required", req_id,
                          "this relay requires an oversight wrap on"
                          " content envelopes")
        return False

    async def _on_send(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        to = normalize_username(frame.get("to"))
        if "body" in frame or "file" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id,
                              "content must be end-to-end encrypted")
            return
        content = frame.get("content")
        if to is None or not self._is_envelope(content):
            await self._error(ws, "bad_send", req_id,
                              "missing encrypted content envelope")
            return
        # Health battery (v1.3.0): the server's own self-test DM
        # between two of its ephemeral peers. It routes for real —
        # that is the point of the test — but it is labelled, exempt
        # from the oversight gate and never written to the audit /
        # activity feed: self-test traffic is not user activity.
        battery = bool(frame.get("battery")) and peer.ephemeral
        if not battery and not await self._oversight_gate(ws, frame,
                                                          req_id):
            return
        if not self.store.exists(to) and to not in self.peers:
            await self._error(ws, "unknown_recipient", req_id)
            return
        msg = {"type": "message", "id": frame.get("id") or new_id(),
               "from": peer.username, "from_name": peer.display_name,
               "from_pubkey": peer.pubkey or self.store.pubkey_of(peer.username),
               "sender_nickname": "", "sender_role": "",
               "sender_custom_role": "",
               "oversight": frame.get("oversight"),
               "mentions": frame.get("mentions") or [],
               "priority": (lambda pr: pr if pr in ("normal", "high", "urgent") else "normal")(str(frame.get("priority") or "normal")),
               "content": content, "ts": now_ts(),
               "in_reply_to": frame.get("in_reply_to"), "group_id": None}
        queued = await self._deliver(to, msg)
        msg["delivery_status"] = "queued" if queued else "live"
        if not battery:
            self._log_activity("message", peer.username, target=to,
                               priority=msg["priority"],
                               status="sent" if queued else "delivered",
                               size=len(str(content.get("ct") or "")),
                               mentions=msg["mentions"],
                               ref_id=msg["id"],
                               oversight=frame.get("oversight"))
        await self._result(ws, req_id, True,
                           {"id": msg["id"], "to": to, "queued": queued})

    async def _on_read(self, ws, frame, peer: Peer) -> None:
        """Read receipts (v1.1.2, owner's WhatsApp requirement): a
        recipient reports the message ids it has taken in. For each
        id the relay derives the conversation from the message's own
        audit row — the reader's claim about which conversation a
        message belongs to is never trusted — and validates that the
        reader is a participant: the addressee of a 1:1, a member of
        the group, or a subscriber of the channel. A sender can never
        read their own message. First read wins. Recorded reads are
        pushed live to the sender as a `read_receipt` frame, logged
        as verified activity, and surfaced on the dashboard payload
        (item `read_by`) — the operator's Seen state. Read state is
        metadata; it never touches content, so the oversight gate
        does not apply. Older clients that never send this frame
        simply never gain read state."""
        req_id = frame.get("req_id")
        raw = frame.get("ids")
        if raw is None and frame.get("id"):
            raw = [frame.get("id")]
        ids = [str(i) for i in (raw or []) if i][:200]
        recorded = []
        for mid in ids:
            meta = self.store.message_meta(mid)
            if meta is None:
                continue
            sender = meta.get("actor") or ""
            if peer.username == sender:
                continue
            kind = meta.get("kind")
            gid = meta.get("group_id") or ""
            if kind == "message":
                if peer.username != (meta.get("target") or ""):
                    continue
            elif kind == "group_message":
                if self.store.role_of(gid, peer.username) is None:
                    continue
            elif kind == "channel_message":
                if self.store.channel_role_of(
                        gid, peer.username) is None:
                    continue
            else:
                continue
            read_at = self.store.record_read(mid, peer.username)
            recorded.append({"id": mid, "read_at": read_at})
            self._log_activity("message_read", peer.username,
                               target=sender, group_id=gid,
                               ref_id=mid, status="read")
            await self._deliver(sender, {
                "type": "read_receipt", "id": mid,
                "reader": peer.username, "read_at": read_at,
                "group_id": gid or None,
                "channel_id": gid if kind == "channel_message"
                else None})
        await self._result(ws, req_id, True,
                           {"read": [r["id"] for r in recorded],
                            "reads": recorded})

    # -- groups ---------------------------------------------------------------
    def _group_or_error(self, ws, frame, peer):
        gid = frame.get("group_id")
        group = self.store.get_group(gid) if gid else None
        return gid, group

    async def _membership_event(self, group, event, actor, target,
                                targets=None, extra=None):
        frame = {"type": "group_event", "id": new_id(), "group_id": group["id"],
                 "group_name": group["name"], "event": event, "actor": actor,
                 "target": target, "targets": targets or ([target] if target else []),
                 "ts": now_ts(),
                 "members": self.store.members(group["id"])}
        if extra:
            frame.update(extra)
        for m in self.store.members(group["id"]):
            if m["username"] != actor:
                await self._deliver(m["username"], dict(frame))
        return frame

    async def _on_group_create(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        name = str(frame.get("name") or "")[:80]
        if not name:
            await self._error(ws, "bad_group", req_id, "group needs a name")
            return
        members = []
        for raw in frame.get("members") or []:
            u = normalize_username(raw)
            if u is None or not self.store.exists(u):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            if u != peer.username and u not in members:
                members.append(u)
        gid = self.store.create_group(name, peer.username, frame.get("settings"))
        # WhatsApp-style: added agents do NOT need to accept. They are in.
        try:
            for u in members:
                self.store.add_member(gid, u, role="member",
                                      added_by=peer.username)
        except GroupFull:
            await self._error(ws, "group_full", req_id,
                              "groups are capped at 50 agents")
            return
        group = self.store.get_group(gid)
        if members:
            await self._membership_event(group, "added_to_group",
                                         peer.username, None, targets=members)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "name": name,
                            "members": self.store.members(gid)})

    async def _on_group_add(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        if role is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if group["settings"].get("add_members") == "admins_only" \
                and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can add members in this group")
            return
        added = []
        for raw in frame.get("members") or []:
            u = normalize_username(raw)
            if u is None or not self.store.exists(u):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            try:
                if self.store.add_member(gid, u, role="member",
                                         added_by=peer.username):
                    added.append(u)
            except GroupFull:
                await self._error(ws, "group_full", req_id,
                                  "groups are capped at 50 agents")
                return
        if added:
            await self._membership_event(group, "added_to_group",
                                         peer.username, None, targets=added)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "added": added,
                            "members": self.store.members(gid)})

    async def _on_group_remove(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        target = normalize_username(frame.get("username"))
        target_role = self.store.role_of(gid, target) if target else None
        if role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can remove members")
            return
        if target_role is None:
            await self._error(ws, "not_a_member", req_id, str(target))
            return
        if target_role == "superadmin":
            await self._error(ws, "permission_denied", req_id,
                              "the group creator cannot be removed")
            return
        if role == "admin" and target_role == "admin":
            await self._error(ws, "permission_denied", req_id,
                              "admins cannot remove other admins")
            return
        self.store.remove_member(gid, target)
        await self._deliver(target, {
            "type": "group_event", "id": new_id(), "group_id": gid,
            "group_name": group["name"], "event": "removed_from_group",
            "actor": peer.username, "target": target, "ts": now_ts(),
            "members": self.store.members(gid)})
        await self._result(ws, req_id, True, {"group_id": gid, "removed": target})

    async def _on_group_members(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        await self._result(ws, req_id, True,
                           {"group_id": gid, "name": group["name"],
                            "settings": group["settings"],
                            "members": self.store.members(gid)})

    async def _on_group_role(self, ws, frame, peer: Peer, promote: bool) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        target = normalize_username(frame.get("username"))
        target_role = self.store.role_of(gid, target) if target else None
        if role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can promote/demote")
            return
        if target_role is None or target_role == "superadmin":
            await self._error(ws, "permission_denied", req_id,
                              "cannot change that member's role")
            return
        new_role = "admin" if promote else "member"
        self.store.set_role(gid, target, new_role)
        await self._membership_event(
            group, "promoted" if promote else "demoted",
            peer.username, target)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "username": target, "role": new_role})

    async def _on_group_settings(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can change group settings")
            return
        try:
            merged = self.store.set_settings(gid, frame.get("settings") or {})
        except NotFound:
            await self._error(ws, "unknown_group", req_id)
            return
        await self._membership_event(group, "settings_changed",
                                     peer.username, None,
                                     extra={"settings": merged})
        await self._result(ws, req_id, True,
                           {"group_id": gid, "settings": merged})

    async def _on_group_join_link(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        token = self.store.create_invite(gid, peer.username)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "token": token,
                            "link": self.store.invite_link(gid, token)})

    async def _on_group_join(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid = frame.get("group_id")
        token = frame.get("token")
        if token and str(token).startswith("agentlink://"):
            parsed = self.store.parse_invite_link(str(token))
            if parsed:
                gid, token = parsed
        group = self.store.get_group(gid) if gid else None
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if not self.store.invite_valid(gid, token):
            await self._error(ws, "invalid_invite", req_id)
            return
        try:
            self.store.add_member(gid, peer.username, role="member",
                                  added_by="invite-link")
        except GroupFull:
            await self._error(ws, "group_full", req_id,
                              "groups are capped at 50 agents")
            return
        await self._membership_event(group, "joined_group",
                                     peer.username, peer.username)
        await self._result(ws, req_id, True,
                           {"group_id": gid,
                            "members": self.store.members(gid)})

    async def _on_group_nickname(self, ws, frame, peer: Peer) -> None:
        """Group-local nickname: a member sets their own, an admin can
        set anyone's. The global username/display name never changes."""
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        target = normalize_username(frame.get("username")) or peer.username
        role = self.store.role_of(gid, peer.username)
        if role is None or self.store.role_of(gid, target) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if target != peer.username and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can set other members' nicknames")
            return
        self.store.set_nickname(gid, target, str(frame.get("nickname") or ""))
        await self._membership_event(group, "nickname_changed",
                                     peer.username, target)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "username": target,
                            "members": self.store.members(gid)})

    async def _on_group_custom_role(self, ws, frame, peer: Peer) -> None:
        """Custom per-group role label (e.g. Researcher, Collator).
        This is a label, separate from the admin/member permission role."""
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        target = normalize_username(frame.get("username"))
        if self.store.role_of(gid, peer.username) not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can set custom roles")
            return
        if target is None or self.store.role_of(gid, target) is None:
            await self._error(ws, "not_a_member", req_id, str(target))
            return
        self.store.set_custom_role(gid, target,
                                   str(frame.get("custom_role") or ""))
        await self._membership_event(group, "custom_role_changed",
                                     peer.username, target)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "username": target,
                            "members": self.store.members(gid)})

    async def _on_set_group_keys(self, ws, frame, peer: Peer) -> None:
        """Store wrapped group keys (ciphertext the relay cannot unwrap)
        and forward each member their wrapped copy."""
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can distribute group keys")
            return
        epoch = int(frame.get("epoch") or 1)
        wrapped_map = frame.get("wrapped") or {}
        for raw_user, wrapped in wrapped_map.items():
            u = normalize_username(raw_user)
            if u is None or self.store.role_of(gid, u) is None:
                continue
            self.store.set_group_key(gid, u, epoch, wrapped)
            if u != peer.username:
                await self._deliver(u, {
                    "type": "group_key", "group_id": gid, "epoch": epoch,
                    "wrapped": wrapped, "from": peer.username,
                    "from_pubkey": peer.pubkey
                    or self.store.pubkey_of(peer.username)})
        await self._result(ws, req_id, True, {"group_id": gid, "epoch": epoch})

    async def _on_get_group_key(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid = frame.get("group_id")
        if not gid or self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        rec = self.store.group_key_for(gid, peer.username)
        await self._result(ws, req_id, True,
                           {"group_id": gid, "key": rec})

    def _expand_role_mentions(self, gid: str, mentions: list) -> list:
        """A @RoleName mention expands to every current holder of that
        custom role in the group (usernames stay public metadata)."""
        out = list(mentions)
        for m in mentions:
            for holder in self.store.resolve_role(gid, str(m)):
                if holder not in out:
                    out.append(holder)
        return out

    async def _on_group_send(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        if role is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if group["settings"].get("send_messages") == "admins_only" \
                and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can send messages in this group")
            return
        if "body" in frame or "file" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id,
                              "content must be end-to-end encrypted")
            return
        content = frame.get("content")
        if not self._is_envelope(content):
            await self._error(ws, "bad_send", req_id,
                              "missing encrypted content envelope")
            return
        if not await self._oversight_gate(ws, frame, req_id):
            return
        msg = {"type": "message", "id": frame.get("id") or new_id(),
               "from": peer.username, "from_name": peer.display_name,
               "from_pubkey": peer.pubkey or self.store.pubkey_of(peer.username),
               "sender_nickname": next(
                   (m["nickname"] for m in self.store.members(gid)
                    if m["username"] == peer.username), ""),
               "sender_role": role,
               "sender_custom_role": next(
                   (m["custom_role"] for m in self.store.members(gid)
                    if m["username"] == peer.username), ""),
               "mentions": self._expand_role_mentions(
                   gid, frame.get("mentions") or []),
               "role_mentions": [m for m in (frame.get("mentions") or [])
                                 if self.store.resolve_role(gid, m)],
               "priority": (lambda pr: pr if pr in
                            ("normal", "high", "urgent") else "normal")(
                                str(frame.get("priority") or "normal")),
               "content": content, "ts": now_ts(),
               "oversight": frame.get("oversight"),
               "in_reply_to": frame.get("in_reply_to"), "group_id": gid,
               "group_name": group["name"]}
        delivered, queued = [], []
        for m in self.store.members(gid):
            if m["username"] == peer.username:
                continue
            (queued if await self._deliver(m["username"], dict(msg))
             else delivered).append(m["username"])
        self._log_activity("group_message", peer.username, group_id=gid,
                           priority=msg["priority"],
                           status="delivered" if delivered else "sent",
                           size=len(str(content.get("ct") or "")),
                           mentions=msg["mentions"], ref_id=msg["id"],
                           sender_nickname=msg["sender_nickname"],
                           sender_role=msg["sender_role"],
                           sender_custom_role=msg["sender_custom_role"],
                           oversight=frame.get("oversight"),
                           content_envelope=content)
        await self._result(ws, req_id, True,
                           {"id": msg["id"], "group_id": gid,
                            "delivered": delivered, "queued": queued})

    async def _on_update_capabilities(self, ws, frame, peer: Peer) -> None:
        """Capability updates are SIGNED with the identity (signing)
        key and verified against the registered public key — an agent
        can only ever rewrite its OWN profile (point 33)."""
        req_id = frame.get("req_id")
        caps = [str(c)[:40] for c in (frame.get("capabilities") or [])][:32]
        desc = str(frame.get("description") or "")[:200]
        canonical = "caps|{}|{}|{}".format(
            peer.username, ",".join(caps), desc).encode()
        from .crypto import Identity as _Identity
        sign_pub = self.store.sign_pub_of(peer.username)
        if not sign_pub or not _Identity.verify_signature(
                sign_pub, canonical, frame.get("sig") or ""):
            self.store.audit("capability_update_rejected", peer.username)
            await self._error(ws, "bad_signature", req_id,
                              "capability update signature did not verify")
            return
        self.store.set_capabilities(peer.username, caps, desc)
        self._log_activity("capabilities_updated", peer.username)
        await self._result(ws, req_id, True,
                           {"username": peer.username,
                            "capabilities": caps, "description": desc})

    # -- channels (broadcast: admins post, subscribers read-only) ------------
    CHANNEL_ADMIN_ROLES = ("admin", "superadmin")

    async def _channel_event(self, channel, event, actor, target,
                             targets=None):
        frame = {"type": "channel_event", "id": new_id(),
                 "channel_id": channel["id"], "channel_name": channel["name"],
                 "event": event, "actor": actor, "target": target,
                 "targets": targets or ([target] if target else []),
                 "ts": now_ts(),
                 "members": self.store.channel_members(channel["id"])}
        for m in self.store.channel_members(channel["id"]):
            if m["username"] != actor:
                await self._deliver(m["username"], dict(frame))
        return frame

    async def _on_channel_create(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        name = str(frame.get("name") or "")[:80]
        if not name:
            await self._error(ws, "bad_channel", req_id, "channel needs a name")
            return
        subs = []
        for raw in frame.get("members") or []:
            u = normalize_username(raw)
            if u is None or not self.store.exists(u):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            if u != peer.username and u not in subs:
                subs.append(u)
        from .store import GroupFull
        cid = self.store.create_channel(name, peer.username)
        try:
            for u in subs:
                self.store.add_subscriber(cid, u, added_by=peer.username)
        except GroupFull:
            await self._error(ws, "channel_full", req_id,
                              "channels are capped at 1000 subscribers")
            return
        channel = self.store.get_channel(cid)
        if subs:
            await self._channel_event(channel, "subscribed_to_channel",
                                      peer.username, None, targets=subs)
        self._log_activity("channel_created", peer.username, group_id=cid)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "name": name,
                            "members": self.store.channel_members(cid)})

    async def _on_channel_add(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        channel = self.store.get_channel(cid) if cid else None
        if channel is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) not in \
                self.CHANNEL_ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only channel admins can add subscribers")
            return
        from .store import GroupFull
        added = []
        for raw in frame.get("members") or []:
            u = normalize_username(raw)
            if u is None or not self.store.exists(u):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            try:
                if self.store.add_subscriber(cid, u,
                                             added_by=peer.username):
                    added.append(u)
            except GroupFull:
                await self._error(ws, "channel_full", req_id,
                                  "channels are capped at 1000 subscribers")
                return
        if added:
            await self._channel_event(channel, "subscribed_to_channel",
                                      peer.username, None, targets=added)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "added": added,
                            "members": self.store.channel_members(cid)})

    async def _on_channel_remove(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        channel = self.store.get_channel(cid) if cid else None
        if channel is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) not in \
                self.CHANNEL_ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only channel admins can remove subscribers")
            return
        target = normalize_username(frame.get("username"))
        if self.store.channel_role_of(cid, target) == "superadmin":
            await self._error(ws, "permission_denied", req_id,
                              "the channel creator cannot be removed")
            return
        self.store.remove_subscriber(cid, target)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "removed": target})

    async def _on_channel_members(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        channel = self.store.get_channel(cid) if cid else None
        if channel is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "name": channel["name"],
                            "members": self.store.channel_members(cid)})

    async def _on_channel_role(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        if self.store.get_channel(cid) is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) != "superadmin":
            await self._error(ws, "permission_denied", req_id,
                              "only the creator can promote channel admins")
            return
        target = normalize_username(frame.get("username"))
        if self.store.channel_role_of(cid, target) is None:
            await self._error(ws, "not_a_member", req_id, str(target))
            return
        self.store.set_channel_role(cid, target, "admin")
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "username": target,
                            "role": "admin"})

    async def _on_channel_send(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        channel = self.store.get_channel(cid) if cid else None
        if channel is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        role = self.store.channel_role_of(cid, peer.username)
        if role is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if role not in self.CHANNEL_ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "channels are read-only for subscribers")
            return
        if "body" in frame or "file" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id)
            return
        content = frame.get("content")
        if not self._is_envelope(content):
            await self._error(ws, "bad_send", req_id,
                              "missing encrypted content envelope")
            return
        if not await self._oversight_gate(ws, frame, req_id):
            return
        msg = {"type": "message", "id": frame.get("id") or new_id(),
               "from": peer.username, "from_name": peer.display_name,
               "from_pubkey": peer.pubkey
               or self.store.pubkey_of(peer.username),
               "sender_nickname": "", "sender_role": role,
               "sender_custom_role": "",
               "oversight": frame.get("oversight"),
               "mentions": frame.get("mentions") or [],
               "priority": str(frame.get("priority") or "normal"),
               "content": content, "ts": now_ts(),
               "in_reply_to": frame.get("in_reply_to"), "group_id": None,
               "channel_id": cid, "channel_name": channel["name"]}
        delivered, queued = [], []
        for m in self.store.channel_members(cid):
            if m["username"] == peer.username:
                continue
            (queued if await self._deliver(m["username"], dict(msg))
             else delivered).append(m["username"])
        self._log_activity("channel_message", peer.username, group_id=cid,
                           priority=msg["priority"],
                           status="delivered" if delivered else "sent",
                           size=len(str(content.get("ct") or "")),
                           mentions=msg["mentions"], ref_id=msg["id"],
                           sender_role=role,
                           oversight=frame.get("oversight"),
                           content_envelope=content)
        await self._result(ws, req_id, True,
                           {"id": msg["id"], "channel_id": cid,
                            "delivered": delivered, "queued": queued})

    async def _on_channel_join_link(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        if self.store.get_channel(cid) is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        token = self.store.create_invite(cid, peer.username)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "token": token,
                            "link": self.store.invite_link(cid, token)})

    async def _on_channel_join(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        token = frame.get("token")
        if token and str(token).startswith("agentlink://"):
            parsed = self.store.parse_invite_link(str(token))
            if parsed:
                cid, token = parsed
        if self.store.get_channel(cid) is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if not self.store.invite_valid(cid, token):
            await self._error(ws, "invalid_invite", req_id)
            return
        from .store import GroupFull
        try:
            self.store.add_subscriber(cid, peer.username,
                                      added_by="invite-link")
        except GroupFull:
            await self._error(ws, "channel_full", req_id)
            return
        channel = self.store.get_channel(cid)
        await self._channel_event(channel, "joined_channel",
                                  peer.username, peer.username)
        # Key provisioning hook: admins' clients wrap the channel key
        # for the new subscriber on this event (same as channel_add).
        await self._channel_event(channel, "subscribed_to_channel",
                                  peer.username, peer.username)
        await self._result(ws, req_id, True,
                           {"channel_id": cid,
                            "members": self.store.channel_members(cid)})

    async def _on_set_channel_keys(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        if self.store.get_channel(cid) is None:
            await self._error(ws, "unknown_channel", req_id)
            return
        if self.store.channel_role_of(cid, peer.username) not in \
                self.CHANNEL_ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id)
            return
        epoch = int(frame.get("epoch") or 1)
        for raw_user, wrapped in (frame.get("wrapped") or {}).items():
            u = normalize_username(raw_user)
            if u is None or self.store.channel_role_of(cid, u) is None:
                continue
            self.store.set_channel_key(cid, u, epoch, wrapped)
            if u != peer.username:
                await self._deliver(u, {
                    "type": "channel_key", "channel_id": cid,
                    "epoch": epoch, "wrapped": wrapped,
                    "from": peer.username})
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "epoch": epoch})

    async def _on_get_channel_key(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        cid = frame.get("channel_id")
        if not cid or self.store.channel_role_of(cid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        rec = self.store.channel_key_for(cid, peer.username)
        await self._result(ws, req_id, True,
                           {"channel_id": cid, "key": rec})

    # -- voice rooms (WebRTC signalling only; media is peer-to-peer) ----------
    async def _on_room_open(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid = frame.get("group_id")
        if not gid or self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id,
                              "voice rooms are for group members only")
            return
        rid = new_id("r-")[:14]
        self.rooms[rid] = {"group_id": gid, "creator": peer.username,
                           "participants": {peer.username},
                           "opened_at": now_ts()}
        self._log_activity("room_opened", peer.username, group_id=gid,
                           status=rid)
        await self._result(ws, req_id, True,
                           {"room_id": rid, "group_id": gid,
                            "participants": [peer.username]})

    def _room_or_error(self, frame):
        rid = frame.get("room_id")
        return rid, self.rooms.get(rid)

    async def _room_broadcast_meta(self, rid, event, actor):
        room = self.rooms.get(rid)
        if not room:
            return
        frame = {"type": "room_event", "room_id": rid, "event": event,
                 "actor": actor,
                 "participants": sorted(room["participants"]),
                 "group_id": room["group_id"], "ts": now_ts()}
        for u in list(room["participants"]):
            if u != actor:
                await self._deliver(u, dict(frame))

    async def _on_room_join(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        rid, room = self._room_or_error(frame)
        if room is None:
            await self._error(ws, "unknown_room", req_id)
            return
        if peer.ephemeral:
            pass  # dashboard browser client (operator-side, visible in
            # room metadata as its dial-* name); agents need membership
        elif self.store.role_of(room["group_id"], peer.username) is None:
            await self._error(ws, "not_a_member", req_id,
                              "voice rooms are for group members only")
            return
        room["participants"].add(peer.username)
        self._log_activity("room_joined", peer.username,
                           group_id=room["group_id"], status=rid)
        await self._room_broadcast_meta(rid, "joined", peer.username)
        await self._result(ws, req_id, True,
                           {"room_id": rid,
                            "participants": sorted(room["participants"])})

    async def _on_room_leave(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        rid, room = self._room_or_error(frame)
        if room is None:
            await self._error(ws, "unknown_room", req_id)
            return
        room["participants"].discard(peer.username)
        self._log_activity("room_left", peer.username,
                           group_id=room["group_id"], status=rid)
        await self._room_broadcast_meta(rid, "left", peer.username)
        if not room["participants"]:
            del self.rooms[rid]
            self._log_activity("room_closed", peer.username,
                               group_id=room["group_id"], status=rid)
        await self._result(ws, req_id, True, {"room_id": rid, "left": True})

    async def _on_room_close(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        rid, room = self._room_or_error(frame)
        if room is None:
            await self._error(ws, "unknown_room", req_id)
            return
        role = self.store.role_of(room["group_id"], peer.username)
        if peer.username != room["creator"] and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only the room creator or a group admin"
                              " can close the room")
            return
        await self._room_broadcast_meta(rid, "closed", peer.username)
        del self.rooms[rid]
        self._log_activity("room_closed", peer.username,
                           group_id=room["group_id"], status=rid)
        await self._result(ws, req_id, True, {"room_id": rid,
                                              "closed": True})

    async def _on_room_signal(self, ws, frame, peer: Peer) -> None:
        """Signalling (offer/answer/ICE) routed to the ADDRESSED room
        participant only. Never stored, never queued: WebRTC media is
        peer-to-peer (DTLS-SRTP); the relay never sees audio."""
        req_id = frame.get("req_id")
        rid, room = self._room_or_error(frame)
        if room is None:
            await self._error(ws, "unknown_room", req_id)
            return
        if peer.username not in room["participants"]:
            await self._error(ws, "not_in_room", req_id)
            return
        target = normalize_username(frame.get("to"))
        if target not in room["participants"]:
            await self._error(ws, "not_in_room", req_id, str(target))
            return
        target_peer = self.peers.get(target)
        if target_peer is None:
            await self._error(ws, "peer_offline", req_id)
            return
        await self._send(target_peer.ws, {
            "type": "room_signal", "room_id": rid, "from": peer.username,
            "kind": frame.get("kind"), "payload": frame.get("payload")})
        await self._result(ws, req_id, True,
                           {"room_id": rid, "to": target, "signalled": True})

    # -- resumable chunked uploads (relay proxies ciphertext to R2) -----------
    async def _on_blob_session_start(self, ws, frame, peer: Peer) -> None:
        import hashlib as _hl
        req_id = frame.get("req_id")
        whole_sha = str(frame.get("whole_sha") or "")
        ct_sha = str(frame.get("ct_sha") or "")
        for_user = normalize_username(frame.get("for_user"))
        for_group = frame.get("for_group")
        for_channel = frame.get("for_channel")
        if for_group and self.store.role_of(for_group, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if for_channel and self.store.channel_role_of(
                for_channel, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if for_user and not self.store.exists(for_user):
            await self._error(ws, "unknown_username", req_id, for_user)
            return
        # Dedup: a completed blob with this whole-file hash, from this
        # sender to this same scope, completes instantly by reference.
        existing = self.store.find_blob_by_whole_sha(
            whole_sha, owner=peer.username, for_user=for_user or "",
            for_group=for_group or "", for_channel=for_channel or "")
        if existing:
            await self._result(ws, req_id, True,
                               {"dedup": True, "blob_id": existing["id"]})
            return
        from .store import CHUNK_SIZE
        chunk_size = int(frame.get("chunk_size") or CHUNK_SIZE)
        chunk_size = max(1024, min(chunk_size, CHUNK_SIZE))
        sid = self.store.create_upload_session(
            owner=peer.username, whole_sha=whole_sha, ct_sha=ct_sha,
            size=int(frame.get("size") or 0), chunk_size=chunk_size,
            for_user=for_user or "", for_group=for_group or "",
            for_channel=for_channel or "")
        await self._result(ws, req_id, True,
                           {"dedup": False, "session_id": sid,
                            "chunk_size": chunk_size})

    async def _on_blob_chunk(self, ws, frame, peer: Peer) -> None:
        import base64 as _b64
        import hashlib as _hl
        req_id = frame.get("req_id")
        sess = self.store.get_upload_session(
            str(frame.get("session_id") or ""))
        if sess is None or sess["owner"] != peer.username:
            await self._error(ws, "unknown_session", req_id)
            return
        try:
            data = _b64.b64decode(frame.get("data_b64") or "")
        except Exception:
            await self._error(ws, "bad_chunk", req_id)
            return
        if _hl.sha256(data).hexdigest() != frame.get("chunk_sha"):
            await self._error(ws, "bad_chunk_hash", req_id,
                              "chunk sha256 mismatch; chunk rejected")
            return
        index = int(frame.get("index"))
        try:
            await asyncio.to_thread(self.blob_store.put,
                                    f"{sess['session_id']}-{index}", data)
        except Exception:
            log.exception("blob store chunk put failed")
            await self._error(ws, "blob_store_failed", req_id,
                              "object storage write failed; retry")
            return
        have = self.store.record_chunk(sess["session_id"], index)
        await self._result(ws, req_id, True, {"have": have})

    async def _on_blob_session_status(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        sess = self.store.get_upload_session(
            str(frame.get("session_id") or ""))
        if sess is None or sess["owner"] != peer.username:
            await self._error(ws, "unknown_session", req_id)
            return
        total = (sess["size"] + sess["chunk_size"] - 1) // sess["chunk_size"] \
            if sess["size"] else 0
        have = sorted(sess["chunks"])
        missing = [i for i in range(total) if i not in have]
        await self._result(ws, req_id, True,
                           {"session_id": sess["session_id"], "have": have,
                            "missing": missing, "total": total})

    async def _on_blob_session_finish(self, ws, frame, peer: Peer) -> None:
        import hashlib as _hl
        req_id = frame.get("req_id")
        sess = self.store.get_upload_session(
            str(frame.get("session_id") or ""))
        if sess is None or sess["owner"] != peer.username:
            await self._error(ws, "unknown_session", req_id)
            return
        total = (sess["size"] + sess["chunk_size"] - 1) // sess["chunk_size"] \
            if sess["size"] else 0
        have = sorted(sess["chunks"])
        if have != list(range(total)):
            await self._error(ws, "incomplete_upload", req_id,
                              f"have {len(have)} of {total} chunks")
            return
        from .blobstore import BlobNotFound
        parts = []
        try:
            for i in range(total):
                parts.append(await asyncio.to_thread(
                    self.blob_store.get, f"{sess['session_id']}-{i}"))
        except BlobNotFound:
            await self._error(ws, "incomplete_upload", req_id,
                              "a chunk is missing from storage")
            return
        except Exception:
            log.exception("blob store chunk read failed")
            await self._error(ws, "blob_store_failed", req_id,
                              "object storage read failed; retry")
            return
        data = b"".join(parts)
        if _hl.sha256(data).hexdigest() != sess["ct_sha"]:
            await self._error(ws, "bad_whole_hash", req_id,
                              "assembled ciphertext hash mismatch")
            return
        # Channel scope (v1.1.0): upload sessions no longer persist
        # it (canonical al_upload_sessions shape), so the client
        # carries it on the finish frame and membership is re-verified
        # here before the blob metadata is written.
        fin_channel = str(frame.get("for_channel")
                          or sess.get("for_channel") or "")
        if fin_channel and self.store.channel_role_of(
                fin_channel, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        blob_id = "b-" + sess["ct_sha"]
        try:
            await asyncio.to_thread(self.blob_store.put, blob_id, data)
            for i in range(total):
                await asyncio.to_thread(self.blob_store.delete,
                                        f"{sess['session_id']}-{i}")
        except Exception:
            log.exception("blob store finish failed")
            await self._error(ws, "blob_store_failed", req_id,
                              "object storage write failed; retry")
            return
        self.store.put_blob_meta(
            blob_id, owner=peer.username, for_user=sess["for_user"],
            for_group=sess["for_group"], for_channel=fin_channel,
            whole_sha=sess["whole_sha"], size=len(data))
        self.store.delete_upload_session(sess["session_id"])
        if not peer.ephemeral:
            # Ephemeral owners are transient probes (incl. the
            # health battery): their uploads are self-test traffic,
            # not user activity — no audit row.
            self.store.audit("blob_upload_completed", peer.username,
                             sess["for_user"], sess["for_group"],
                             blob_id, "")
        await self._result(ws, req_id, True, {"blob_id": blob_id,
                                              "size": len(data)})


    async def _on_work_checkpoint(self, ws, frame, peer: Peer) -> None:
        """Durable checkpoint mirror (point 30): the backend stores the
        E2E-encrypted checkpoint so it travels with the assignment if
        the assignee dies and the work is reassigned (point 29)."""
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        if work["assignee"] != peer.username:
            await self._error(ws, "permission_denied", req_id,
                              "only the assignee can checkpoint")
            return
        attempt = int(frame.get("attempt") or work.get("attempt") or 1)
        if attempt != int(work.get("attempt") or 1):
            await self._error(ws, "stale_attempt", req_id)
            return
        self.store.set_checkpoint(
            work["id"], attempt, peer.username,
            frame.get("content_assigner"), frame.get("content_group"))
        await self._deliver(work["assigner"], {
            "type": "work_checkpoint", "work": work,
            "content_assigner": frame.get("content_assigner"),
            "by": peer.username, "attempt": attempt})
        self.store.audit("work_checkpoint", peer.username,
                         work["assigner"], work["group_id"] or "",
                         work["id"], f"attempt {attempt}")
        await self._result(ws, req_id, True,
                           {"work_id": work["id"], "attempt": attempt})

    async def _on_work_resume_failed(self, ws, frame, peer: Peer) -> None:
        """A handler that cannot resume a checkpoint says so EXPLICITLY
        (point 30) — it never silently restarts from zero."""
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        self.store.audit("resume_failed", peer.username,
                         work["assigner"], work["group_id"] or "",
                         work["id"], str(frame.get("reason") or ""))
        self._log_activity("resume_failed", peer.username,
                           target=work["assigner"], work_id=work["id"],
                           status="explicit")
        await self._deliver(work["assigner"], {
            "type": "work_update", "work": work,
            "note": "assignee reported resume_failed"})
        await self._result(ws, req_id, True, {"work_id": work["id"]})

    # -- delivery library (point 38a) ---------------------------------------------
    async def _on_library_search(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        rows = self.store.search_library(
            peer.username, q=str(frame.get("q") or ""),
            sender=str(frame.get("sender") or ""),
            group_id=str(frame.get("group_id") or ""),
            hash_prefix=str(frame.get("hash_prefix") or ""))
        await self._result(ws, req_id, True, {"entries": rows})

    async def _on_library_fetch(self, ws, frame, peer: Peer) -> None:
        """Fetch a library deliverable THROUGH THE LINE with the same
        entitlement checks: only the deliverer, the assigner, or an
        entitled group member gets the (still encrypted) payload."""
        req_id = frame.get("req_id")
        entry = self.store.library_entry(str(frame.get("library_id")
                                             or ""))
        if entry is None:
            await self._error(ws, "unknown_library_entry", req_id)
            return
        work = self.store.get_work(entry["work_id"])
        entitled = (
            peer.username in (entry["sender"], entry["to_user"]) or
            entry.get("chain_next") == peer.username or
            (entry["group_id"] and self.store.role_of(
                entry["group_id"], peer.username) is not None))
        if not entitled or work is None:
            await self._error(ws, "permission_denied", req_id,
                              "not entitled to this delivery")
            return
        delivery = next((d for d in work.get("deliveries", [])
                         if d["id"] == entry["delivery_id"]), None)
        if delivery is None:
            await self._error(ws, "unknown_library_entry", req_id)
            return
        if peer.username == entry["to_user"]:
            content = delivery.get("content_enc")
        elif peer.username == entry["sender"]:
            content = delivery.get("content_self")
        elif entry.get("chain_next") == peer.username:
            # Chain handoff copy, encrypted to THIS assignee by the
            # delivering client at delivery time (point 41c).
            content = (delivery.get("content_next") or {}).get(
                peer.username)
        else:
            content = delivery.get("content_group")
        await self._result(ws, req_id, True,
                           {"entry": entry, "content": content})

    # -- group vault (point 38b) ------------------------------------------------------
    async def _on_vault_add(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        role = self.store.role_of(gid, peer.username)
        if role is None:
            await self._error(ws, "not_a_member", req_id)
            return
        if group["settings"].get("vault_add") == "admins_only" \
                and role not in ADMIN_ROLES:
            await self._error(ws, "permission_denied", req_id,
                              "only admins can add to this group's vault")
            return
        descriptor = frame.get("descriptor") or {}
        if not descriptor.get("blob_id"):
            await self._error(ws, "bad_vault_file", req_id,
                              "descriptor needs a blob_id")
            return
        entry = self.store.vault_add(gid, descriptor, peer.username,
                                     pinned=bool(frame.get("pinned")))
        self._log_activity("vault_added", peer.username, group_id=gid,
                           status=descriptor.get("name", ""))
        await self._result(ws, req_id, True, {"entry": entry})

    async def _on_vault_list(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid, group = self._group_or_error(ws, frame, peer)
        if group is None:
            await self._error(ws, "unknown_group", req_id)
            return
        if self.store.role_of(gid, peer.username) is None:
            await self._error(ws, "not_a_member", req_id)
            return
        await self._result(ws, req_id, True,
                           {"group_id": gid,
                            "files": self.store.vault_list(gid)})

    async def _on_vault_pin(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        entry = self.store.vault_entry(str(frame.get("vault_id") or ""))
        if entry is None:
            await self._error(ws, "unknown_vault_entry", req_id)
            return
        role = self.store.role_of(entry["group_id"], peer.username)
        if role is None or (peer.username != entry["added_by"]
                            and role not in ADMIN_ROLES):
            await self._error(ws, "permission_denied", req_id)
            return
        updated = self.store.vault_set_pinned(
            entry["id"], bool(frame.get("pinned")))
        await self._result(ws, req_id, True, {"entry": updated})

    async def _on_vault_remove(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        entry = self.store.vault_entry(str(frame.get("vault_id") or ""))
        if entry is None:
            await self._error(ws, "unknown_vault_entry", req_id)
            return
        role = self.store.role_of(entry["group_id"], peer.username)
        if role is None or (peer.username != entry["added_by"]
                            and role not in ADMIN_ROLES):
            await self._error(ws, "permission_denied", req_id)
            return
        self.store.vault_remove(entry["id"])
        await self._result(ws, req_id, True,
                           {"vault_id": entry["id"], "removed": True})


    # -- work chains (point 41) -----------------------------------------------------
    async def _release_step(self, chain: dict, step: dict) -> None:
        """Release a pending step: create its work row(s) from the
        PRE-CREATED envelopes and push-dispatch instantly."""
        gid = step.get("group_id") or chain.get("group_id") or None
        assignees = list(step.get("assignees") or [])
        envelopes = step.get("envelopes") or {}
        if step.get("target_type") == "member":
            # 'a member of the group': first alive non-creator member.
            members = self.store.members(gid) if gid else []
            pick = next((m["username"] for m in members
                         if m["username"] != chain["creator"]
                         and self._is_alive(m["username"], 60)), "")
            if not pick and members:
                pick = next((m["username"] for m in members
                             if m["username"] != chain["creator"]), "")
            assignees = [pick] if pick else []
        batch_id = new_id("batch-")[:20] if len(assignees) > 1 else None
        first_work = None
        for assignee in assignees:
            pair = envelopes.get(assignee) or {}
            role = ""
            if gid:
                mrow = next((m for m in self.store.members(gid)
                             if m["username"] == assignee), None)
                role = (mrow or {}).get("custom_role") or ""
            work = self.store.create_work(
                assigner=chain["creator"], assignee=assignee,
                group_id=gid,
                content_enc=pair.get("enc") or {},
                content_self=pair.get("self") or pair.get("enc") or {},
                deadline=step.get("deadline"), batch_id=batch_id,
                priority=step.get("priority", "normal"),
                auto_reassign=True, assignee_role=role,
                content_group=step.get("content_group"),
                chain_id=chain["id"], chain_step=step["position"],
                require_approval=bool(step.get("require_approval")))
            view = dict(work)
            view["prev_deliverables"] = step.get("handoff") or []
            await self._deliver(assignee, {
                "type": "work_assigned", "work": view,
                "chain_id": chain["id"], "chain_step": step["position"]})
            if first_work is None:
                first_work = work
        if first_work is not None:
            self.store.set_step_status(step["id"], "active",
                                       work_id=first_work["id"])
            self._log_activity("chain_step_released", chain["creator"],
                               group_id=gid or "", work_id=first_work["id"],
                               status=f"step {step['position']}")

    async def _on_chain_create(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        steps = frame.get("steps") or []
        if not steps:
            await self._error(ws, "bad_chain", req_id,
                              "a chain needs at least one step")
            return
        gid = frame.get("group_id")
        if gid:
            if self.store.get_group(gid) is None:
                await self._error(ws, "unknown_group", req_id)
                return
            if self.store.role_of(gid, peer.username) is None:
                await self._error(ws, "not_a_member", req_id)
                return
        for st in steps:
            for a in st.get("assignees") or []:
                if not self.store.exists(a):
                    await self._error(ws, "unknown_username", req_id, a)
                    return
        from .deadlines import parse_deadline
        for st in steps:
            st["deadline"] = parse_deadline(st.get("deadline"))
        chain = self.store.create_chain(
            peer.username, gid or "", str(frame.get("name") or ""), steps)
        first = chain["steps"][0]
        await self._release_step(chain, first)
        self._log_activity("chain_created", peer.username,
                           group_id=gid or "", status=chain["id"])
        await self._result(ws, req_id, True,
                           {"chain": self.store.get_chain(chain["id"])})

    async def _advance_chain(self, work: dict) -> None:
        """Trigger = VERIFIED + ACCEPTED delivery only: this runs from
        the complete action, which itself requires status 'delivered'
        (reachable only with a valid signed proof). A cancelled chain
        NEVER advances, even if a trigger is faked later."""
        chain = self.store.get_chain(work["chain_id"])
        if chain is None or chain["status"] not in ("running", "paused"):
            return
        step = self.store.step_by_work(work["id"])
        if step is None or step["status"] == "completed":
            return
        self.store.set_step_status(step["id"], "completed")
        entries = self.store.library_for_work(work["id"])
        handoff = [{"library_id": e["id"], "filename": e["filename"],
                    "sha256": e["sha256"], "size": e["size"],
                    "sender": e["sender"]} for e in entries]
        nxt = next((s for s in chain["steps"]
                    if s["position"] == step["position"] + 1), None)
        if nxt is None:
            self.store.set_chain_status(chain["id"], "completed")
            self.store.resolve_alerts("chain_paused", chain["id"])
            await self._deliver(chain["creator"], {
                "type": "chain_event", "event": "completed",
                "chain_id": chain["id"]})
            self._log_activity("chain_completed", chain["creator"],
                               group_id=chain["group_id"],
                               status=chain["id"])
            if self.alert_chain_completed:
                alert = self.store.open_alert(
                    "chain_completed", chain["id"],
                    "chain finished all steps")
                await self._dispatch_alert(alert)
            return
        self.store.set_step_handoff(nxt["id"], handoff,
                                    nxt.get("assignees") or [])
        if chain["status"] == "paused":
            self.store.set_chain_status(chain["id"], "running")
            self.store.resolve_alerts("chain_paused", chain["id"])
        fresh = self.store.get_chain(chain["id"])
        nxt_fresh = next(s for s in fresh["steps"]
                         if s["id"] == nxt["id"])
        await self._release_step(fresh, nxt_fresh)

    async def _on_chain_cancel(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        chain = self.store.get_chain(str(frame.get("chain_id") or ""))
        if chain is None:
            await self._error(ws, "unknown_chain", req_id)
            return
        is_admin = chain.get("group_id") and self.store.role_of(
            chain["group_id"], peer.username) in ADMIN_ROLES
        if peer.username != chain["creator"] and not is_admin:
            await self._error(ws, "permission_denied", req_id,
                              "only the chain creator (or a group admin)"
                              " can cancel a chain")
            return
        if chain["status"] in ("completed", "cancelled"):
            await self._error(ws, "bad_status", req_id,
                              f"chain is {chain['status']}")
            return
        self.store.set_chain_status(chain["id"], "cancelled")
        involved = {chain["creator"]}
        for st in chain["steps"]:
            if st["status"] == "pending":
                self.store.set_step_status(st["id"], "cancelled")
            involved.update(st.get("assignees") or [])
            if st.get("work_id"):
                w = self.store.get_work(st["work_id"])
                if w:
                    involved.add(w["assignee"])
        for user in involved:
            if user != peer.username:
                await self._deliver(user, {
                    "type": "chain_event", "event": "cancelled",
                    "chain_id": chain["id"], "by": peer.username})
        self._log_activity("chain_cancelled", peer.username,
                           group_id=chain["group_id"], status=chain["id"])
        await self._result(ws, req_id, True,
                           {"chain": self.store.get_chain(chain["id"])})

    async def _on_chain_list(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        await self._result(ws, req_id, True,
                           {"chains": self.store.chains_for_user(
                               peer.username)})

    async def _on_chain_get(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        chain = self.store.get_chain(str(frame.get("chain_id") or ""))
        if chain is None:
            await self._error(ws, "unknown_chain", req_id)
            return
        involved = {chain["creator"]}
        for st in chain["steps"]:
            involved.update(st.get("assignees") or [])
        if peer.username not in involved and not (
                chain.get("group_id") and self.store.role_of(
                    chain["group_id"], peer.username)):
            await self._error(ws, "permission_denied", req_id)
            return
        meta = next((c for c in self.store.list_chains_meta()
                     if c["id"] == chain["id"]), chain)
        await self._result(ws, req_id, True, {"chain": meta})


    # -- work -------------------------------------------------------------------
    async def _on_assign(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        gid = frame.get("group_id")
        group = None
        if gid:
            group = self.store.get_group(gid)
            if group is None:
                await self._error(ws, "unknown_group", req_id)
                return
            role = self.store.role_of(gid, peer.username)
            if role is None:
                await self._error(ws, "not_a_member", req_id)
                return
            if group["settings"].get("assign_work") == "admins_only" \
                    and role not in ADMIN_ROLES:
                await self._error(ws, "permission_denied", req_id,
                                  "only admins can assign work in this group")
                return
        # Assign-by-role: the relay re-resolves the role server-side so
        # the assignee set is exactly the current holders.
        target_role = frame.get("target_role")
        batch_id = None
        if target_role:
            if not gid:
                await self._error(ws, "bad_assign", req_id,
                                  "role assignment needs a group")
                return
            holders = self.store.resolve_role(gid, str(target_role))
            if not holders:
                await self._error(ws, "empty_role", req_id,
                                  f"nobody in this group holds the role"
                                  f" '{target_role}'")
                return
            requested = sorted(normalize_username(a) or "" for a in
                               frame.get("assignees") or [])
            if requested != sorted(holders):
                await self._error(ws, "role_mismatch", req_id,
                                  "assignees must be exactly the current"
                                  " role holders")
                return
            batch_id = new_id("batch-")[:20]
        priority = str(frame.get("priority") or "normal")
        if priority not in ("normal", "high", "urgent"):
            priority = "normal"
        from .deadlines import parse_deadline
        deadline = parse_deadline(frame.get("deadline"))
        auto_reassign = frame.get("auto_reassign")
        if auto_reassign is None:
            auto_reassign = True  # default ON (group and 1:1 alike)
        require_approval = bool(frame.get("require_approval"))
        content_group = frame.get("content_group")
        # E2EE: per-assignee content envelopes, prepared by the client.
        envelopes = frame.get("envelopes") or {}
        if "title" in frame or "instructions" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id,
                              "work content must be end-to-end encrypted")
            return
        if not await self._oversight_gate(ws, frame, req_id):
            return
        created = []
        for raw in frame.get("assignees") or []:
            assignee = normalize_username(raw)
            if assignee is None or not self.store.exists(assignee):
                await self._error(ws, "unknown_username", req_id, str(raw))
                return
            if group is not None and \
                    self.store.role_of(gid, assignee) is None:
                await self._error(ws, "assignee_not_in_group", req_id, assignee)
                return
            pair = envelopes.get(assignee) or {}
            if not self._is_envelope(pair.get("enc")):
                await self._error(ws, "bad_assign", req_id,
                                  f"missing encrypted content for {assignee}")
                return
            assignee_role = ""
            if gid:
                mrow = next((m for m in self.store.members(gid)
                             if m["username"] == assignee), None)
                assignee_role = (mrow or {}).get("custom_role") or ""
            work = self.store.create_work(
                assigner=peer.username, assignee=assignee, group_id=gid,
                content_enc=pair["enc"],
                content_self=pair.get("self") or pair["enc"],
                deadline=deadline, batch_id=batch_id,
                priority=priority, auto_reassign=bool(auto_reassign),
                assignee_role=assignee_role,
                content_group=content_group,
                require_approval=require_approval)
            created.append(work)
            await self._deliver(assignee,
                                {"type": "work_assigned", "work": work})
            self._log_activity("work_assigned", peer.username,
                               target=assignee, group_id=gid or "",
                               work_id=work["id"], status="assigned",
                               priority=priority,
                               oversight=frame.get("oversight"))
            if require_approval:
                self._log_activity("approval_gate_set", peer.username,
                                   target=assignee, group_id=gid or "",
                                   work_id=work["id"],
                                   status="require_approval",
                                   priority=priority)
        if not created:
            await self._error(ws, "bad_assign", req_id, "no assignees")
            return
        await self._result(ws, req_id, True, {"work": created})

    async def _on_deliver_work(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        if work["assignee"] != peer.username:
            await self._error(ws, "permission_denied", req_id,
                              "only the assignee can deliver this work")
            return
        attempt = frame.get("attempt")
        if attempt is not None and int(attempt) != int(
                work.get("attempt") or 1):
            self.store.audit("stale_attempt_delivery", peer.username,
                             work["assigner"], work["group_id"] or "",
                             work["id"], f"attempt {attempt}")
            await self._error(ws, "stale_attempt", req_id,
                              "this assignment was reassigned; attempt"
                              f" {attempt} is closed")
            return
        if work["status"] not in ("assigned", "in_progress",
                                  "changes_requested"):
            await self._error(ws, "bad_status", req_id,
                              f"work is {work['status']}, cannot deliver")
            return
        # Signed delivery proof (Ed25519): canonical payload is
        # work_id|content_hash|timestamp|deliverer, verified against
        # the deliverer's REGISTERED signing public key. The verdict
        # goes to the audit log either way; a bad proof is rejected.
        proof = frame.get("proof") or {}
        from .crypto import Identity as _Identity
        canonical = "{}|{}|{}|{}".format(
            work["id"], proof.get("hash", ""), proof.get("ts", ""),
            peer.username).encode()
        sign_pub = self.store.sign_pub_of(peer.username)
        verified = bool(proof.get("sig")) and bool(sign_pub) and \
            _Identity.verify_signature(sign_pub, canonical,
                                       proof.get("sig", ""))
        self.store.audit("delivery_proof_verified", peer.username,
                         work["assigner"], work["group_id"] or "",
                         work["id"], "true" if verified else "false")
        if getattr(self, "dashboard", None) is not None:
            self.dashboard.notify()
        if not verified:
            await self._error(ws, "bad_proof", req_id,
                              "delivery signature did not verify")
            return
        proof = {**proof, "verified": True}
        content_enc = frame.get("content_enc")
        content_self = frame.get("content_self")
        if "body" in frame or "files" in frame:
            await self._error(ws, "plaintext_not_allowed", req_id,
                              "deliveries must be end-to-end encrypted")
            return
        if not self._is_envelope(content_enc):
            await self._error(ws, "bad_delivery", req_id,
                              "missing encrypted delivery content")
            return
        if not await self._oversight_gate(ws, frame, req_id):
            return
        updated = self.store.add_delivery(
            work["id"], peer.username, content_enc,
            content_self or content_enc, proof=proof,
            content_group=frame.get("content_group"),
            content_next=frame.get("content_next"))
        # Delivery library index (point 38a): METADATA the deliverer
        # supplies in the clear envelope (filename/size/sha256) — the
        # content itself stays sealed ciphertext.
        library_files = frame.get("library") or []
        if library_files and updated.get("deliveries"):
            self.store.add_library_entries(
                updated["deliveries"][-1]["id"], updated, library_files)
        self.store.resolve_alerts("reassignment", work["id"])
        # Delivery goes back through the SAME line to the assigner.
        await self._deliver(work["assigner"],
                            {"type": "work_update", "work": updated})
        self._log_activity("work_delivered", peer.username,
                           target=work["assigner"], work_id=work["id"],
                           status=updated["status"],
                           priority=work.get("priority", "normal"),
                           oversight=frame.get("oversight"))
        if updated["status"] == "awaiting_approval":
            # Approval gate: the proven delivery is parked; nothing
            # completes (and no chain advances) until the assigner
            # (or a group admin) decides on the line.
            self._log_activity("work_awaiting_approval", peer.username,
                               target=work["assigner"],
                               group_id=work["group_id"] or "",
                               work_id=work["id"],
                               status="awaiting_approval",
                               priority=work.get("priority", "normal"))
        # Role batch: this delivery satisfies the whole batch.
        for covered in self.store.cover_batch(work.get("batch_id"),
                                              work["id"]):
            await self._deliver(covered["assignee"],
                                {"type": "work_update", "work": covered,
                                 "covered_by": work["id"]})
            await self._deliver(work["assigner"],
                                {"type": "work_update", "work": covered,
                                 "covered_by": work["id"]})
            self._log_activity("work_covered", peer.username,
                               target=covered["assignee"],
                               group_id=covered["group_id"] or "",
                               work_id=covered["id"], status="covered")
        await self._result(ws, req_id, True, {"work": updated})

    async def _on_work_progress(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        if work["assignee"] != peer.username:
            await self._error(ws, "permission_denied", req_id,
                              "only the assignee can report progress")
            return
        percent = frame.get("percent")
        if not isinstance(percent, int) or not (0 <= percent <= 100):
            await self._error(ws, "bad_percent", req_id,
                              "percent must be an integer 0-100")
            return
        if work["status"] not in ("assigned", "in_progress",
                                  "changes_requested"):
            await self._error(ws, "bad_status", req_id,
                              f"work is {work['status']}")
            return
        updated = self.store.set_work_progress(work["id"], percent)
        event = {"type": "work_progress", "work": updated,
                 "percent": percent, "ts": now_ts(),
                 "content_enc": frame.get("content_enc"),
                 "content_self": frame.get("content_self")}
        # Assigner gets the (encrypted) note; group members get the
        # live metadata event (percent is envelope metadata).
        await self._deliver(work["assigner"], dict(event))
        if work["group_id"]:
            meta = {**event, "content_enc": None, "content_self": None}
            for m in self.store.members(work["group_id"]):
                if m["username"] not in (peer.username, work["assigner"]):
                    await self._deliver(m["username"], dict(meta))
        self._log_activity("work_progress", peer.username,
                           target=work["assigner"],
                           group_id=work["group_id"] or "",
                           work_id=work["id"], status=str(percent))
        await self._result(ws, req_id, True, {"work": updated})

    async def _on_work_action(self, ws, frame, peer: Peer) -> None:
        req_id = frame.get("req_id")
        work = self.store.get_work(str(frame.get("work_id") or ""))
        action = frame.get("action")
        if work is None:
            await self._error(ws, "unknown_work", req_id)
            return
        gated_decision = work["status"] == "awaiting_approval"
        if gated_decision:
            # Approval gate (v1.1.0): only the assigner — or, for
            # group work, a group admin — may decide. approve and
            # complete are the same decision; reject and
            # request_changes are the same decision (the reason rides
            # the frame's note to the assignee, chain stays paused).
            is_admin = bool(work.get("group_id")) and \
                self.store.role_of(work["group_id"], peer.username) \
                in ADMIN_ROLES
            if work["assigner"] != peer.username and not is_admin:
                await self._error(ws, "permission_denied", req_id,
                                  "only the assigner or a group admin"
                                  " can decide an approval gate")
                return
            if action in ("approve", "complete"):
                status = "completed"
            elif action in ("reject", "request_changes"):
                status = "changes_requested"
            else:
                await self._error(ws, "bad_action", req_id, str(action))
                return
        else:
            if work["assigner"] != peer.username:
                await self._error(ws, "permission_denied", req_id,
                                  "only the assigner can do that")
                return
            if work["status"] != "delivered":
                await self._error(ws, "bad_status", req_id,
                                  f"work is {work['status']}, not delivered")
                return
            if action == "complete":
                status = "completed"
            elif action == "request_changes":
                status = "changes_requested"
            else:
                await self._error(ws, "bad_action", req_id, str(action))
                return
        updated = self.store.set_work_status(work["id"], status)
        if gated_decision:
            self._log_activity(
                "work_approved" if status == "completed"
                else "work_approval_rejected", peer.username,
                target=work["assignee"],
                group_id=work["group_id"] or "", work_id=work["id"],
                status=status)
        self._log_activity("work_" + status, peer.username,
                           target=work["assignee"], work_id=work["id"],
                           status=status)
        if work.get("chain_id"):
            if status == "changes_requested":
                # The chain PAUSES at this step until an accepted
                # re-delivery (point 41b) — a real, visible status.
                self.store.set_chain_status(work["chain_id"], "paused")
                self._log_activity("chain_paused", peer.username,
                                   group_id=work["group_id"] or "",
                                   work_id=work["id"],
                                   status=work["chain_id"])
            elif status == "completed":
                await self._advance_chain(work)
        await self._deliver(work["assignee"],
                            {"type": "work_update", "work": updated,
                             "note": frame.get("note")})
        await self._result(ws, req_id, True, {"work": updated})


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Run the AgentLink relay server.")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--db", default="~/.agentlink/relay.db")
    ap.add_argument("--backend", default=None,
                    help="sqlite (default) | supabase (production; needs"
                         " SUPABASE_URL + SUPABASE_SERVICE_KEY)")
    ap.add_argument("--dashboard-port", type=int, default=8766)
    ap.add_argument("--name", default=None, dest="server_name",
                    help="label for this server (shown on the dashboard)")
    ap.add_argument("--public-endpoint", default=None,
                    help="this relay's canonical public endpoint"
                         " (wss://...) \u2014 home agents are recognised"
                         " against it, never against the --name label")
    ap.add_argument("--host-agent", default=None,
                    help="username of the agent hosting this relay"
                         " (peer mesh: recorded in the server"
                         " registry; default $AGENTLINK_HOST_AGENT)")
    ap.add_argument("--server-id", default=None,
                    help="this server's STABLE registry identity"
                         " (v1.3.0 carrying: identity survives"
                         " endpoint moves; default: the public"
                         " endpoint)")
    ap.add_argument("--owner-agent", default=None,
                    help="make this relay an agent's OWN server"
                         " (v1.3.0): the named agent owns it"
                         " permanently; if this machine falls, a"
                         " brother carries it automatically and"
                         " hands it back when home is strong again")
    ap.add_argument("--home-host", default=None,
                    help="host agent of this server's home machine"
                         " (default: --host-agent)")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s")

    async def _run() -> None:
        store = None
        backend = args.backend or os.environ.get("AGENTLINK_BACKEND")
        if backend:
            from .backend import create_store
            store = create_store(backend, db_path=args.db)
        relay = Relay(host=args.host, port=args.port, db_path=args.db,
                      backend_store=store, dashboard_port=args.dashboard_port,
                      server_name=args.server_name,
                      public_endpoint=args.public_endpoint,
                      host_agent=args.host_agent
                      or os.environ.get("AGENTLINK_HOST_AGENT"),
                      server_id=args.server_id,
                      owner_agent=args.owner_agent,
                      home_host=args.home_host)
        await relay.start()
        try:
            await asyncio.Future()
        except (KeyboardInterrupt, asyncio.CancelledError):
            pass
        finally:
            await relay.stop()

    asyncio.run(_run())


if __name__ == "__main__":
    main()
