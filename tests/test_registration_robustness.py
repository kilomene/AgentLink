"""v1.3.7 REGISTRATION ROBUSTNESS — acceptance tests.

The failure that motivates this file (2026-11-02 night): an agent
product on a sick foreign network failed to register — a broken
address family, a registration "cut off" mid-flight, and almost no
line-side trace of any of it. The contract pinned here:

  * ADDRESS-FAMILY RACING (happy eyeballs): when resolution yields
    a broken IPv6 address alongside a working IPv4 one, the client
    must still register — in bounded time, never parked on the
    dead family.
  * IDEMPOTENT / RESUMABLE REGISTRATION: a first registration cut
    off mid-flight (socket dies during the welcome wait, AFTER the
    relay has begun the hello exchange) must be retryable with the
    SAME state dir / identity: the retry completes, exactly ONE
    user row exists for the identity, and the agent comes online.
    The secret the client never received must not strand the name.
  * THE FOLK USERNAME, VERBATIM: ``nova-bridge-7f3a`` was the
    owner-instructed USERNAME for the folk agent (not an endpoint
    — an earlier draft of this file had that wrong; the owner
    arbitrated it). ``protocol.normalize_username`` passes it
    unchanged, and a fresh agent must register with that literal
    name end-to-end (test 5a).
  * SPECIFIC REGISTRATION-FAILURE DIAGNOSTICS: when registration
    dies mid-handshake, the client surface must say WHAT died and
    WHAT THE LINE ANSWERED — never a bare OSError / "Network is
    unreachable" with no step and no reason (test 5b). Landed
    shape discovered by probing: an error-frame answer raises
    ``RegistrationFailed("<reason>: <detail>")`` carrying the
    line's reason and detail verbatim; a mid-hello DROP is wrapped
    by the welcome wait into ``ConnectionError("registration
    failed at step 'welcome': the connection to <url> dropped
    while waiting for the welcome for @<user> (<close detail>).
    The relay may already have claimed the identity — retry with
    this same state dir and the registration resumes; ...")``
    chained from the ConnectionClosed — step, endpoint, username
    and recovery path all named. (The timeout branch of the same
    wait names step 'welcome' the same way.)
  * STATE-DIR COLLISION: two live Agents on ONE state dir is
    duplicate-endpoint chaos (probed: the second start succeeds
    silently and supersedes the first peer on the relay; both
    share one mailbox/journal/secret set). Starting the second
    must produce a plain diagnostic naming the already-running
    instance — not a raw sqlite3.OperationalError /
    "database is locked" traceback, and not silent success
    (test 6). Landed shape: ``Agent.start()`` claims an flock on
    ``instance-<username>.lock`` in the state dir for its whole
    connected lifetime (``_acquire_instance_lock``, released by
    ``close()``; the kernel releases it if the process dies, so a
    stale pid alone never blocks a restart). A second live
    claimant raises ``InstanceCollision`` (a RegistrationFailed
    subclass) BEFORE any socket opens:
    "instance_collision: another agentlink instance is already
    running on this state dir (pid <holder pid>); registration
    joins that instance, it does not start a rival — ... stop it
    (pid <holder pid>) first" — the running instance is named BY
    PID, which test 6 accepts alongside username/state-dir
    naming. The guard is PROCESS-scoped: a same-pid sibling
    Agent object borrows the claim by design (supervisor /
    replacement-object pattern; the relay's supersede rules
    govern its duplicate hello), so test 6 exercises the
    collision from a rival SUBPROCESS — the actual shape of the
    duplicate-endpoint accident.
  * FORGIVING FIRST-CONTACT HELLO WINDOW + LINE-SIDE VISIBILITY:
    a connection that dies before completing hello leaves a TRACE
    on the relay side — an audit/activity record (kind
    "hello_incomplete") or an equivalent counter/log record —
    carrying a REASON. Silence is the bug being fixed.
  * The other side of idempotence stays hard: a DIFFERENT secret
    for an existing username is still rejected.

Everything runs the REAL chain (real Relay + real Agent clients on
a temp SQLite store, raw websockets where the protocol itself is
under test) — harness reused from tests/test_deregister.py /
tests/test_delivery_guarantee.py.

CONTRACT DETAILS DISCOVERED / GUESSED (also in the worker report):
  * Client seams (agentlink/client.py as inspected): module-level
    ``resolve_host(host, port)`` is called fresh by
    ``Agent._open_socket`` on every connect, and ``_open_socket``
    dials each resolved address through the module-level
    ``connect`` name imported from ``websockets.client``. Tests
    patch ``agentlink.client.resolve_host`` and
    ``agentlink.client.connect`` (plus ``asyncio.open_connection``
    as a second transport layer) — the cleanest documented points.
  * The landed ``_open_socket`` interleaves the resolved
    addresses by family (``_interleave_families``) and RACES the
    attempts with a bounded stagger
    (``CONNECT_FAMILY_STAGGER_SECONDS``, read via getattr with a
    0.25s default): first success wins, losers are cancelled. The
    pre-1.3.7 sequential walk parked the whole connect on one
    blackholed family; test 1's hanging-v6 fake would have parked
    it forever.
  * Relay hello (agentlink/relay.py ``_on_hello``): the identity
    claim (``store.claim``) happens BEFORE the welcome frame is
    sent, so a cutoff during the welcome wait leaves a claimed row
    whose secret the client never saw. The landed resume gate
    (``_try_resume_registration``) re-admits the retry ONLY when:
    no secret is presented, the hello's pubkey AND sign_pub match
    the half-created row exactly (the retry presents the SAME
    persisted identity keys from the same state dir:
    keys-<username>.json is written at Agent construction, before
    any hello), the row is younger than
    ``REGISTRATION_RESUME_WINDOW_SECONDS`` (3600), and the identity
    is NOT alive anywhere — which includes the claim-time
    heartbeat touch, so a retry inside ``OFFLINE_GRACE_SECONDS``
    (15) of the cutoff is still refused ``username_taken`` and
    test 2 waits that grace out before retrying, exactly as a
    real client's reconnect pacing would. On resume the relay
    rotates the secret ONLY when the store offers a secret setter
    (set_secret/rotate_secret/reset_secret); the inspected store
    offers NONE, so the resume welcome carries no secret, the
    client stays secretless, and the resume stays window-bound —
    test 2 therefore pins the landed evidence of a resume (the
    'hello_resumed' audit row), not a saved secret file.
  * ``agentlink/timing.py``: ``FIRST_HELLO_TIMEOUT_SECONDS = 30``
    (the forgiving first-contact window; a pre-hello connection
    that outlives it is closed and recorded as hello_timeout) —
    test 3 sizes its polling window from the constant when present.
  * Incomplete-hello visibility (landed, relay.py
    ``_record_hello_incomplete``): a WARNING log line, an
    audit/activity row of kind ``hello_incomplete`` with status
    "<stage>: <reason>", and counters
    ``relay._hello_incomplete_total`` /
    ``_hello_incomplete_by_reason`` (also surfaced in the relay
    overview dict). INTENT rule discovered: a connection is only
    counted when it showed registration intent (a hello, a
    malformed frame, or any non-ping frame before registering) —
    a bare connect-and-close is indistinguishable from a health
    probe and is NOT traced, so test 3's truncated-hello socket is
    the one that must produce the trace. Test 3 still DISCOVERS
    the surface (audit rows, activity deque, counters, log) rather
    than hard-coding one, and compares against a baseline taken
    before its raw sockets (the relay's own health battery also
    opens pre-hello connections, so an absolute count would be a
    false positive).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import sqlite3
import tempfile
import threading
import time
from pathlib import Path

import pytest
import websockets.exceptions
from websockets.client import connect as ws_connect
from websockets.server import serve as ws_serve

import agentlink.client as C
from agentlink import timing
from agentlink.client import Agent, RegistrationFailed
from agentlink.protocol import normalize_username
from agentlink.relay import Relay

HOST = "127.0.0.1"


# ---------------------------------------------------------------------
# Harness (reused from tests/test_deregister.py)
# ---------------------------------------------------------------------

@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-regrob-")
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
    yield {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "relay": relay, "store": relay.store,
           "loop_box": box}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-regrob-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def make(relay_env, state_root, username, **kw):
    a = Agent(username, endpoint=relay_env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=8.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


def user_rows(store, username):
    return [u for u in store.list_users() if u["username"] == username]


# ---------------------------------------------------------------------
# 1. Broken IPv6 must not dark a registration (happy-eyeballs racing)
# ---------------------------------------------------------------------

def test_register_over_broken_ipv6(relay_env, state_root, monkeypatch):
    """Resolution yields a HANGING IPv6 address first and a working
    IPv4 second. A sequential client parks on the v6 attempt
    forever; a racing client registers over v4 in bounded time,
    lands in the relay directory, capabilities intact."""
    async def _go():
        store = relay_env["store"]
        port = relay_env["port"]
        calls = {"resolve": 0, "v6_attempts": 0}
        real_connect = C.connect
        real_open_connection = asyncio.open_connection

        async def fake_resolve(host, port_):
            calls["resolve"] += 1
            # Broken family FIRST, working family second — the
            # order a sick network's resolver hands back.
            return ["::1", "127.0.0.1"]

        async def flaky_connect(url, *args, **kwargs):
            if "[::1]" in str(url):
                calls["v6_attempts"] += 1
                # The broken family does not refuse — it HANGS
                # (black-holed route). Cancellable: a racing
                # client abandons this attempt when v4 wins.
                await asyncio.sleep(120)
                raise AssertionError("v6 attempt was never abandoned")
            return await real_connect(url, *args, **kwargs)

        async def flaky_open_connection(host, port_, *args, **kwargs):
            # Second plausible transport layer for the racing
            # implementation: a raw asyncio stream per address.
            if host == "::1":
                calls["v6_attempts"] += 1
                await asyncio.sleep(120)
                raise AssertionError("v6 attempt was never abandoned")
            return await real_open_connection(host, port_, *args,
                                              **kwargs)

        monkeypatch.setattr(C, "resolve_host", fake_resolve)
        monkeypatch.setattr(C, "connect", flaky_connect)
        monkeypatch.setattr(asyncio, "open_connection",
                            flaky_open_connection)

        caps = ["reg-race", "ipv6-survivor"]
        a = Agent("v6racer", endpoint=f"ws://127.0.0.1:{port}",
                  state_dir=str(state_root / "v6racer"),
                  capabilities=caps,
                  cap_description="registered over a broken v6")
        started = time.monotonic()
        await asyncio.wait_for(a.start(), timeout=25)
        elapsed = time.monotonic() - started

        assert elapsed < 25, f"registration took {elapsed:.1f}s"
        assert calls["resolve"] >= 1, "resolve_host seam never used"
        assert calls["v6_attempts"] >= 1, (
            "the broken IPv6 address was never even attempted — "
            "the patched connect seam is not the client's dial path")
        assert a.username == "v6racer"

        # In the relay directory, capabilities intact.
        entries = [u for u in await a.directory()
                   if u["username"] == "v6racer"]
        assert len(entries) == 1
        assert entries[0]["capabilities"] == caps
        assert entries[0]["online"] is True
        rows = user_rows(store, "v6racer")
        assert len(rows) == 1
        assert rows[0]["capabilities"] == caps
        await a.close()
    run(_go())


# ---------------------------------------------------------------------
# 2. Registration cut off mid-flight resumes with the same identity
# ---------------------------------------------------------------------

class _CutoffSocket:
    """Wraps a real websocket: send() passes through (the hello
    really reaches the relay), but the FIRST recv() — the welcome
    wait — drops the connection instead, exactly like a network
    that dies mid-registration."""

    def __init__(self, real):
        self._real = real
        self._cut = False

    async def send(self, data):
        return await self._real.send(data)

    async def recv(self):
        if not self._cut:
            self._cut = True
            try:
                await self._real.close()
            except Exception:
                pass
            raise websockets.exceptions.ConnectionClosedError(
                None, None)
        return await self._real.recv()

    async def close(self, *args, **kwargs):
        try:
            return await self._real.close(*args, **kwargs)
        except Exception:
            pass

    def __aiter__(self):
        return self._real.__aiter__()


def test_register_cutoff_and_resume(relay_env, state_root,
                                    monkeypatch):
    """First registration is cut AFTER the relay began the hello
    exchange (the identity claim already landed server-side) but
    BEFORE the client received the welcome — so the client never
    learns the issued secret. A retry with the SAME state dir /
    identity must complete registration anyway, leave exactly ONE
    user row, and come online."""
    async def _go():
        store = relay_env["store"]
        real_connect = C.connect
        calls = {"n": 0}

        async def cutting_connect(url, *args, **kwargs):
            calls["n"] += 1
            real = await real_connect(url, *args, **kwargs)
            if calls["n"] == 1:
                return _CutoffSocket(real)
            return real

        monkeypatch.setattr(C, "connect", cutting_connect)

        state_dir = str(state_root / "cutoffkid")
        a1 = Agent("cutoffkid", endpoint=relay_env["url"],
                   state_dir=state_dir)
        with pytest.raises(Exception):
            await asyncio.wait_for(a1.start(), timeout=20)
        await a1.close()

        # The cutoff was genuinely MID-FLIGHT: the relay had
        # already claimed the identity (claim precedes welcome in
        # _on_hello), yet the client never received a secret.
        assert await wait_for(lambda: store.exists("cutoffkid"),
                              timeout=5), (
            "relay never claimed the identity — the cutoff did not "
            "land mid-flight, so this test proves nothing")
        assert not (Path(state_dir)
                    / "secret-cutoffkid.json").exists(), (
            "client saved a secret on the cut attempt — the retry "
            "would just be an ordinary reconnect, not a resume")

        # The resume gate's not-alive condition: the claim-time
        # heartbeat touch makes the half-registration read "alive"
        # for OFFLINE_GRACE_SECONDS, and the leaked-peer sweep must
        # have unbound the dead socket. Wait both out — bounded
        # well inside REGISTRATION_RESUME_WINDOW_SECONDS (3600).
        def _resume_gate_open():
            seen = store.last_seen_of("cutoffkid")
            return bool(seen) and (
                time.time() - seen
                > timing.OFFLINE_GRACE_SECONDS + 1) and (
                    "cutoffkid" not in relay_env["relay"].peers)
        assert await wait_for(_resume_gate_open, timeout=40), (
            "half-registration never stopped reading alive — the "
            "resume gate can never open for it")

        # Retry: SAME state dir, SAME identity (same persisted
        # keys), still no secret on disk.
        monkeypatch.setattr(C, "connect", real_connect)
        a2 = Agent("cutoffkid", endpoint=relay_env["url"],
                   state_dir=state_dir)
        await asyncio.wait_for(a2.start(), timeout=25)
        assert a2.username == "cutoffkid"
        # Landed evidence of a resume: the relay records it loudly
        # (audit/activity kind 'hello_resumed'). NOTE: no secret
        # file is asserted — the store offers no secret setter, so
        # the resume welcome carries no rotated secret and the
        # client remains secretless inside the resume window (see
        # header). If a store setter lands, this is the place to
        # start asserting the saved secret instead.
        resumed = [r for r in store.list_audit(200)
                   if r["kind"] == "hello_resumed"
                   and r["from"] == "cutoffkid"]
        assert resumed, "no 'hello_resumed' audit row for the resume"

        # Exactly ONE user row for the identity.
        rows = user_rows(store, "cutoffkid")
        assert len(rows) == 1, rows

        # And the agent can hello / appear online afterwards.
        assert await wait_for(
            lambda: "cutoffkid" in relay_env["relay"].peers,
            timeout=5)
        entries = [u for u in await a2.directory()
                   if u["username"] == "cutoffkid"]
        assert len(entries) == 1 and entries[0]["online"] is True
        await a2.close()
    run(_go())


# ---------------------------------------------------------------------
# 3. An incomplete hello is VISIBLE on the line side
# ---------------------------------------------------------------------

_INCOMPLETE_MARKERS = ("incomplete", "abandon", "no_hello",
                       "before_hello", "hello_timeout", "dropped")
_REASON_MARKERS = ("closed", "close", "eof", "timeout", "timed out",
                   "disconnect", "incomplete", "truncated",
                   "no hello", "before hello", "before_hello",
                   "abandon", "drop", "reason", "no frame",
                   "no_frame", "peer gone", "gone")


def _incomplete_traces(relay_env, caplog):
    """Discover whatever trace surface the implementation provides:
    store audit rows, the relay's activity deque, relay counters,
    or the relay log. Returns reason-bearing trace dicts."""
    relay = relay_env["relay"]
    store = relay_env["store"]
    traces = []

    def _consider(kind, blob, source):
        kind_l = str(kind or "").lower()
        blob_l = blob.lower()
        if "hello" not in kind_l and "hello" not in blob_l:
            return
        if not any(m in kind_l or m in blob_l
                   for m in _INCOMPLETE_MARKERS):
            return
        if not any(m in blob_l for m in _REASON_MARKERS):
            return
        traces.append({"source": source, "kind": kind, "blob": blob})

    for row in store.list_audit(1000):
        _consider(row.get("kind"),
                  json.dumps(row, default=str), "audit")
    for entry in list(getattr(relay, "activity", []) or []):
        if isinstance(entry, dict):
            _consider(entry.get("kind"),
                      json.dumps(entry, default=str), "activity")
    for attr in ("hello_incomplete_count", "incomplete_hello_count",
                 "hello_incomplete", "incomplete_hellos",
                 "_hello_incomplete_count"):
        val = getattr(relay, attr, None)
        if isinstance(val, int) and val > 0:
            traces.append({"source": f"counter:{attr}", "kind": attr,
                           "blob": f"{attr}={val} incomplete hello"})
    for rec in caplog.records:
        if "hello" in rec.getMessage().lower():
            _consider("log", rec.getMessage(), "log")
    return traces


def test_incomplete_hello_is_visible(relay_env, caplog):
    """Raw sockets that die before completing hello — one that
    sends nothing at all, one that sends a truncated hello then
    drops — must leave a line-side trace WITH a reason. No silent
    disappearances."""
    caplog.set_level(logging.DEBUG, logger="agentlink.relay")

    async def _go():
        url = relay_env["url"]
        baseline = len(_incomplete_traces(relay_env, caplog))

        # (a) Connect and drop without a single frame. (Per the
        # landed intent rule this one is probe-indistinguishable
        # and is NOT required to trace; it is here so a stricter
        # implementation that traces it too also passes, and so
        # the pair matches the task's "and/or".)
        async with ws_connect(url) as ws:
            await ws.close()

        # (b) Truncated hello — a partial JSON frame naming the
        # would-be identity — then drop.
        async with ws_connect(url) as ws:
            await ws.send('{"type": "hello", "username": '
                          '"ghosthello", "pubkey": "trun')
            await asyncio.sleep(0.3)
            await ws.close()

        # The forgiving first-contact window may delay the trace;
        # poll for it, sized by the timing constant if it exists.
        window = float(getattr(timing, "FIRST_HELLO_TIMEOUT_SECONDS",
                               0) or 0)
        deadline = time.monotonic() + max(15.0, window + 10.0)
        new_traces = []
        while time.monotonic() < deadline:
            traces = _incomplete_traces(relay_env, caplog)
            if len(traces) > baseline:
                new_traces = traces[baseline:]
                break
            await asyncio.sleep(0.25)
        assert new_traces, (
            "no line-side trace of the incomplete hellos: no "
            "audit/activity record, counter or log line records a "
            "connection that died before completing hello")
        blob = " ".join(t["blob"].lower() for t in new_traces)
        assert any(m in blob for m in _REASON_MARKERS), new_traces
    run(_go())


# ---------------------------------------------------------------------
# 4. A different secret for an existing username is still rejected
# ---------------------------------------------------------------------

def test_wrong_secret_still_rejected(relay_env, state_root):
    """Resumability must not become impersonation: after a
    successful registration, a hello for the same username
    presenting a DIFFERENT secret (and a different identity key —
    a fresh state dir) fails, the registration is untouched, and
    the real owner still reconnects with its own secret."""
    async def _go():
        store = relay_env["store"]
        owner = await make(relay_env, state_root, "keepreg")
        await owner.close()
        assert store.exists("keepreg")

        forged = state_root / "forged"
        forged.mkdir(parents=True, exist_ok=True)
        (forged / "secret-keepreg.json").write_text(json.dumps(
            {"username": "keepreg",
             "secret": "a-different-secret-entirely"}))
        bad = Agent("keepreg", endpoint=relay_env["url"],
                    state_dir=str(forged))
        with pytest.raises(RegistrationFailed):
            await asyncio.wait_for(bad.start(), timeout=20)
        assert store.exists("keepreg")
        assert len(user_rows(store, "keepreg")) == 1

        # The real owner, same state dir / secret, still connects.
        again = await make(relay_env, state_root, "keepreg")
        assert again.username == "keepreg"
        await again.close()
    run(_go())


# ---------------------------------------------------------------------
# 5a. The literal folk username registers end-to-end
# ---------------------------------------------------------------------

def test_exact_username_registers(relay_env, state_root):
    """``nova-bridge-7f3a`` — the owner-instructed username from
    the folk incident — is a valid username that
    normalize_username passes UNCHANGED. A fresh agent registers
    with that literal name: registration completes, the store
    holds exactly one row for it, the directory lists it with its
    declared capabilities, and it can hello + appear online."""
    async def _go():
        store = relay_env["store"]
        assert normalize_username("nova-bridge-7f3a") == \
            "nova-bridge-7f3a"
        caps = ["folk-agent", "bridge"]
        a = await make(relay_env, state_root, "nova-bridge-7f3a",
                       capabilities=caps,
                       cap_description="the folk bridge agent")
        assert a.username == "nova-bridge-7f3a"

        rows = user_rows(store, "nova-bridge-7f3a")
        assert len(rows) == 1, rows
        assert rows[0]["capabilities"] == caps

        entries = [u for u in await a.directory()
                   if u["username"] == "nova-bridge-7f3a"]
        assert len(entries) == 1
        assert entries[0]["capabilities"] == caps
        assert entries[0]["online"] is True
        assert await wait_for(
            lambda: "nova-bridge-7f3a" in relay_env["relay"].peers,
            timeout=5)
        await a.close()
    run(_go())


# ---------------------------------------------------------------------
# 5b. A failed registration reports SPECIFICALLY what died
# ---------------------------------------------------------------------

def _diag_text(exc) -> str:
    """All the diagnostic text a failure surface offers: the
    exception's own text, any structured attrs a landed shape may
    carry (reason/detail/step/stage), and its cause/context chain,
    plus type names — so the assertions below adapt to the landed
    shape instead of one guessed class."""
    parts = []
    seen = set()
    cur = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        parts.append(type(cur).__name__)
        parts.append(str(cur))
        for attr in ("reason", "detail", "step", "stage", "phase"):
            val = getattr(cur, attr, None)
            if isinstance(val, str) and val:
                parts.append(val)
        cur = cur.__cause__ or cur.__context__
    return " | ".join(p for p in parts if p)


def _chain_has(exc, exc_type) -> bool:
    seen = set()
    cur = exc
    while cur is not None and id(cur) not in seen:
        seen.add(id(cur))
        if isinstance(cur, exc_type):
            return True
        cur = cur.__cause__ or cur.__context__
    return False


_STEP_MARKERS = ("hello", "welcome", "register", "registration",
                 "handshake")
_REASON_MARKERS_5B = ("closed", "close", "drop", "lost", "refus",
                      "1011", "reset", "abort", "unreachable",
                      "capacity", "admission")


def test_registration_failure_reports_specifically(
        relay_env, state_root):
    """Two mid-handshake deaths against a scripted line:

    (i) the register is answered with an ERROR FRAME — the final
        error must carry the line's reason AND detail (landed
        shape: RegistrationFailed("<reason>: <detail>"));
    (ii) the line accepts the socket, reads the hello, then DROPS
        mid-register — the final error must still name the step
        that died (hello/welcome) and the closure, not surface as
        a bare OSError / "Network is unreachable" string or an
        unexplained ConnectionClosed repr.
    """
    async def _go():
        # (i) Error-frame answer.
        async def refuse(ws, *rest):
            try:
                await ws.recv()  # the hello
                await ws.send(json.dumps({
                    "type": "error", "reason": "admission_closed",
                    "detail": "registration refused: relay at "
                              "capacity"}))
                await asyncio.sleep(0.2)
            except Exception:
                pass

        server = await ws_serve(refuse, HOST, 0)
        port = server.sockets[0].getsockname()[1]
        a = Agent("specfail-a", endpoint=f"ws://{HOST}:{port}",
                  state_dir=str(state_root / "specfail-a"))
        exc = None
        try:
            await asyncio.wait_for(a.start(), timeout=15)
        except Exception as e:  # noqa: BLE001 - the surface IS the test
            exc = e
        finally:
            await a.close()
            server.close()
            await server.wait_closed()
        assert exc is not None, "refused registration did not fail"
        text = _diag_text(exc)
        assert isinstance(exc, RegistrationFailed), text
        assert "admission_closed" in text, text
        assert "relay at capacity" in text, text
        assert "Network is unreachable" not in text, text

        # (ii) Drop mid-register.
        async def drop(ws, *rest):
            try:
                await ws.recv()  # the hello lands…
                await ws.close(code=1011)  # …then the line dies
            except Exception:
                pass

        server = await ws_serve(drop, HOST, 0)
        port = server.sockets[0].getsockname()[1]
        b = Agent("specfail-b", endpoint=f"ws://{HOST}:{port}",
                  state_dir=str(state_root / "specfail-b"))
        exc = None
        try:
            await asyncio.wait_for(b.start(), timeout=15)
        except Exception as e:  # noqa: BLE001
            exc = e
        finally:
            await b.close()
            server.close()
            await server.wait_closed()
        assert exc is not None, "dropped registration did not fail"
        text = _diag_text(exc)
        low = text.lower()
        assert "network is unreachable" not in low, text
        assert any(m in low for m in _STEP_MARKERS), (
            f"final error names no step that died: {text}")
        assert any(m in low for m in _REASON_MARKERS_5B), (
            f"final error carries no reason for the death: {text}")
    run(_go())


# ---------------------------------------------------------------------
# 6. Two live Agents on one state dir: a plain collision diagnostic
# ---------------------------------------------------------------------

_COLLISION_CHILD = r"""
import asyncio, sys
sys.path.insert(0, sys.argv[1])
from agentlink.client import Agent

async def main():
    a = Agent("collide", endpoint=sys.argv[2], state_dir=sys.argv[3])
    try:
        await a.start()
    except Exception as e:
        print(f"CHILD_ERROR {type(e).__name__}: {e}", flush=True)
        sys.exit(3)
    print("CHILD_STARTED", flush=True)
    await a.close()

asyncio.run(main())
"""


def test_state_dir_collision_detected(relay_env, state_root):
    """One Agent is RUNNING on a state dir (this process). A
    second PROCESS starting an Agent on the SAME state dir (the
    duplicate-endpoint accident: two processes, one identity, one
    mailbox/journal) must fail with the plain collision
    diagnostic naming the already-running instance — not silent
    success, and not a raw sqlite3.OperationalError / "database
    is locked" traceback. The first instance survives untouched.

    DISCOVERED SHAPE: the guard is PROCESS-scoped. A same-pid
    sibling Agent object deliberately BORROWS the claim (the
    supervisor/replacement-object pattern in
    _acquire_instance_lock: holder_pid == os.getpid() is provably
    not a rival process, and the relay's supersede rules govern
    the duplicate hello), so the collision can only be exercised
    honestly from a rival process — hence the subprocess. The
    child prints the exception it surfaces and exits 3; the
    assertions run on that printed diagnostic."""
    async def _go():
        store = relay_env["store"]
        shared_dir = str(state_root / "collide")
        a1 = Agent("collide", endpoint=relay_env["url"],
                   state_dir=shared_dir)
        await a1.start()
        assert "collide" in relay_env["relay"].peers

        import subprocess
        import sys
        repo_root = str(Path(__file__).resolve().parents[1])
        proc = await asyncio.to_thread(
            subprocess.run,
            [sys.executable, "-c", _COLLISION_CHILD, repo_root,
             relay_env["url"], shared_dir],
            capture_output=True, text=True, timeout=60)
        out = (proc.stdout or "") + (proc.stderr or "")
        low = out.lower()
        assert "child_started" not in low, (
            f"rival process started on an in-use state dir: {out}")
        assert proc.returncode == 3, out
        assert "child_error" in low, out
        # Not the raw-SQLite failure mode.
        assert "operationalerror" not in low, out
        assert "database is locked" not in low, out
        # The diagnostic names the already-running instance: the
        # holder is THIS process, so its pid must appear, with a
        # collision marker.
        assert f"pid {os.getpid()}" in low, out
        assert any(m in low for m in (
            "already", "running", "in use", "another",
            "collision", "rival")), out

        # The first instance is untouched and still the live peer.
        assert "collide" in relay_env["relay"].peers
        entries = [u for u in await a1.directory()
                   if u["username"] == "collide"]
        assert len(entries) == 1 and entries[0]["online"] is True
        assert len(user_rows(store, "collide")) == 1
        await a1.close()
    run(_go())
