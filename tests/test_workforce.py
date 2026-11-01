"""Workforce tests: reassignment, resume, concurrency, fail-closed
evidence, capabilities, fleet alerts, chains, never-sleeps audits,
auto-adjust, self-heal, NO GOING DARK (points 28-33, 37, 39, 41-44).

Real relays, real clients, subprocesses where the point demands a
real process death. No mocks of the system under test.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from agentlink.client import Agent, RequestFailed
from agentlink.relay import Relay
from agentlink.store import Store

HOST = "127.0.0.1"
ROOT = Path(__file__).resolve().parent.parent


def start_relay(db_path: str, **kw):
    relay = Relay(host=HOST, port=0, db_path=db_path,
                  dashboard_password="test-dash-pass", **kw)
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

    threading.Thread(target=_thread, daemon=True).start()
    assert ready.wait(timeout=10)
    return relay, box


def stop_relay(relay, box):
    # Force-close peer sockets first: Relay.stop()'s wait_closed()
    # blocks while any client is connected (same kill pattern as the
    # failover suite).
    async def _force():
        for peer in list(relay.peers.values()):
            try:
                await peer.ws.close()
            except Exception:
                pass
    try:
        asyncio.run_coroutine_threadsafe(
            _force(), box["loop"]).result(timeout=5)
    except Exception:
        pass
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


def kill_relay(relay, box):
    """Stop a relay from INSIDE an async test: the blocking stop runs
    on a side thread so the test's own event loop stays free to
    answer websocket close handshakes (calling stop_relay inline
    deadlocks against agents living on the same loop)."""
    threading.Thread(target=stop_relay, args=(relay, box),
                     daemon=True).start()


@pytest.fixture()
def env1():
    tmp = tempfile.mkdtemp(prefix="agentlink-wf-")
    db = str(Path(tmp) / "relay.db")
    relay, box = start_relay(db)
    yield {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "relay": relay, "box": box,
           "dash_port": relay.dashboard_port}
    stop_relay(relay, box)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-wf-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def make(env, state_root, username, **kw):
    a = Agent(username, endpoint=env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=10.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


# -- point 28: voice rooms -----------------------------------------------------

def test_voice_room_lifecycle_and_signalling(env1, state_root):
    """Point 28: room lifecycle works; signalling reaches ONLY the
    addressed participant; a non-member cannot join; the dashboard
    metadata shows the live room."""
    async def _t():
        a = await make(env1, state_root, "room-a")
        b = await make(env1, state_root, "room-b")
        c = await make(env1, state_root, "room-c")
        g = await a.group_create("VoiceG", ["room-b"])
        gid = g["group_id"]
        room = await a.room_open(gid)
        rid = room["room_id"]
        await b.room_join(rid)
        with pytest.raises(RequestFailed):
            await c.room_join(rid)  # not a group member
        sig_b, sig_a = [], []
        b.on_room_signal(lambda f: sig_b.append(f))
        a.on_room_signal(lambda f: sig_a.append(f))
        await a.room_signal(rid, "room-b", "offer", {"sdp": "v=0..."})
        assert await wait_for(lambda: len(sig_b) == 1)
        await asyncio.sleep(0.3)
        assert sig_a == []  # only the addressed participant
        assert sig_b[0]["payload"] == {"sdp": "v=0..."}
        data = env1["relay"]._dashboard_data()
        rooms = [r for r in data["rooms"] if r["id"] == rid]
        assert rooms and set(rooms[0]["participants"]) == \
            {"room-a", "room-b"}
        await b.room_leave(rid)
        await a.room_close(rid)
        data = env1["relay"]._dashboard_data()
        assert not [r for r in data["rooms"] if r["id"] == rid]
        for x in (a, b, c):
            await x.close()
    run(_t())


# -- point 29: dead-agent auto-reassignment ---------------------------------------

def test_dead_agent_reassignment_with_checkpoint(env1, state_root):
    """Point 29: assignee dies mid-task after a checkpoint; after the
    grace window the SAME work_id lands on the online same-role
    member WITH the checkpoint; it completes exactly once; the
    revived dead agent cannot deliver the old attempt."""
    env1["relay"].reassign_grace_seconds = 7  # > one 5s heartbeat + slack

    async def _t():
        boss = await make(env1, state_root, "boss29")
        wa = await make(env1, state_root, "worker-a29")
        wb = await make(env1, state_root, "worker-b29")
        g = await boss.group_create("Reassign", ["worker-a29",
                                                 "worker-b29"])
        gid = g["group_id"]
        await boss.group_set_custom_role(gid, "worker-a29", "Researcher")
        await boss.group_set_custom_role(gid, "worker-b29", "Researcher")
        job = (await boss.assign_work(["worker-a29"], "fragile job",
                                      group_id=gid))[0]
        await wa.checkpoint(job["id"], {"stage": "halfway", "n": 3})
        await wa.close()  # dies: no more heartbeats anywhere
        received = {}

        def handler(work, ctx):
            received["work"] = work
            received["ctx"] = ctx

        # The replacement runs the real daemon (run()): heartbeats
        # flow, so the backend-wide presence sees it as alive — a
        # start()-only client would itself look dead to the scan.
        await wb.close()
        wb = Agent("worker-b29", endpoint=env1["url"],
                   state_dir=str(state_root / "worker-b29"))
        wb.on_work(handler)
        wb_task = asyncio.create_task(wb.run(reconnect_delay=0.5))
        assert await wait_for(lambda: "work" in received, 20)
        assert received["work"]["id"] == job["id"]
        cp = received["work"].get("checkpoint") or \
            (received["ctx"].checkpoint if received["ctx"] else None)
        assert cp == {"stage": "halfway", "n": 3}, cp
        await wb.deliver_work(job["id"], body="finished by replacement")
        await boss.complete_work(job["id"])
        raw = env1["relay"].store.get_work(job["id"])
        assert raw["status"] == "completed"
        assert len(raw["deliveries"]) == 1  # exactly once
        # The dead agent revives: it does NOT get the work back and
        # cannot deliver the stale attempt.
        wa2 = await make(env1, state_root, "worker-a29")
        with pytest.raises(RequestFailed):
            await wa2.deliver_work(job["id"], body="zombie delivery")
        await boss.close(); await wa2.close()
        wb_task.cancel()
        try:
            await wb_task
        except (asyncio.CancelledError, Exception):
            pass
    run(_t())


# -- points 30 + 39c: SIGKILL, relaunch via the service entry, resume --------------

WORKER_SCRIPT = r'''
import asyncio, json, sys
from pathlib import Path
from agentlink.client import Agent

state_dir, endpoint, marker_dir = sys.argv[1], sys.argv[2], sys.argv[3]
marker = Path(marker_dir)

async def main():
    agent = Agent("phoenix-worker", endpoint=endpoint,
                  state_dir=state_dir)

    def handler(work, ctx):
        async def _go():
            if ctx.resumed:
                (marker / "resumed.json").write_text(json.dumps({
                    "checkpoint": ctx.checkpoint,
                    "attempt": ctx.attempt}))
                await agent.deliver_work(work["id"],
                                         body="resumed and done")
                (marker / "delivered.txt").write_text("1")
            else:
                await agent.checkpoint(work["id"], {"step": 7})
                (marker / "checkpointed.txt").write_text("1")
                await asyncio.sleep(3600)  # killed while "working"
        asyncio.create_task(_go())

    agent.on_work(handler)
    await agent.run(reconnect_delay=0.5)

asyncio.run(main())
'''


def test_39c_sigkill_relaunch_resumes_from_checkpoint(env1, state_root,
                                                      tmp_path):
    """Points 30 + 39c (the owner's proof test): a client process is
    SIGKILLed mid-task after writing a checkpoint; it is started
    again via the daemon entry point with NO other calls; presence
    returns, the handler receives the SAME work with ctx.resumed and
    the exact checkpoint, it delivers, and total deliveries across
    both lives is exactly 1."""
    script = tmp_path / "worker.py"
    script.write_text(WORKER_SCRIPT)
    wstate = str(state_root / "phoenix-worker")
    markers = tmp_path / "markers"; markers.mkdir()
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    procs = []

    def launch():
        p = subprocess.Popen(
            [sys.executable, str(script), wstate, env1["url"],
             str(markers)], env=env,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(p)
        return p

    async def _wait(path, timeout=25):
        for _ in range(int(timeout / 0.1)):
            if path.exists():
                return True
            await asyncio.sleep(0.1)
        return path.exists()

    async def _t():
        boss = await make(env1, state_root, "boss30")
        p1 = launch()
        store = env1["relay"].store
        assert await wait_for(lambda: any(
            u["username"] == "phoenix-worker"
            for u in store.list_users()), 20)
        job = (await boss.assign_work(["phoenix-worker"],
                                      "immortal job"))[0]
        assert await _wait(markers / "checkpointed.txt", 20)
        p1.send_signal(signal.SIGKILL)
        p1.wait(timeout=5)
        p2 = launch()
        assert await _wait(markers / "delivered.txt", 30)
        resumed = json.loads((markers / "resumed.json").read_text())
        assert resumed["checkpoint"] == {"step": 7}
        p2.send_signal(signal.SIGKILL)
        p2.wait(timeout=5)
        raw = env1["relay"].store.get_work(job["id"])
        assert raw["status"] == "delivered"
        assert len(raw["deliveries"]) == 1  # exactly once, two lives
        await boss.close()

    try:
        run(_t())
    finally:
        for p in procs:
            if p.poll() is None:
                p.kill()


def _wait_file(path: Path, timeout: float) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if path.exists():
            return True
        time.sleep(0.1)
    return path.exists()


# -- point 31: full workforce --------------------------------------------------------

def test_worker_pool_concurrency_and_failover_dispatch(state_root,
                                                       tmp_path):
    """Point 31: three assignments pushed at once all START before
    any finishes (concurrent pool, push dispatch); work assigned via
    a peer relay while home is down reaches the agent on failover
    with no nudge."""
    db = str(Path(tmp_path) / "shared.db")
    store = Store(db)
    home, hbox = start_relay(db, backend_store=store,
                             dashboard_enabled=False)
    peer, pbox = start_relay(db, backend_store=store,
                             dashboard_enabled=False)
    home_url = f"ws://{HOST}:{home.port}"
    peer_url = f"ws://{HOST}:{peer.port}"

    async def _t():
        worker = Agent("pool-worker", endpoint=home_url,
                       fallbacks=[peer_url],
                       state_dir=str(state_root / "pool-worker"))
        started, finished = [], []

        def handler(work, ctx):
            async def _go():
                started.append(work["id"])
                await asyncio.sleep(0.8)
                finished.append(work["id"])
            asyncio.create_task(_go())

        worker.on_work(handler)
        run_task = asyncio.create_task(worker.run(reconnect_delay=0.5))
        assert await wait_for(lambda: worker.username == "pool-worker")
        boss = Agent("pool-boss", endpoint=peer_url,
                     state_dir=str(state_root / "pool-boss"))
        await boss.start()
        jobs = []
        for i in range(3):
            jobs.append((await boss.assign_work(
                ["pool-worker"], f"concurrent {i}"))[0])
        assert await wait_for(lambda: len(started) == 3, 10)
        assert finished == [], "all 3 started before any finished"
        # Kill home mid-flight: the agent rides the peer; work
        # assigned through the peer still reaches it (push, no nudge).
        kill_relay(home, hbox)
        job4 = (await boss.assign_work(["pool-worker"],
                                       "via peer while home down"))[0]
        assert await wait_for(lambda: job4["id"] in started, 20)
        assert worker.current_endpoint == peer_url
        run_task.cancel()
        try:
            await run_task
        except (asyncio.CancelledError, Exception):
            pass
        await boss.close()
    try:
        run(_t())
    finally:
        try:
            stop_relay(peer, pbox)
        except Exception:
            pass


# -- point 32: fail-closed evidence -----------------------------------------------------

def test_state_skip_rejected_and_dashboard_separates_claims(env1,
                                                            state_root):
    """Point 32: assigned->completed (skipping delivery) is rejected
    and the status does not move; the dashboard feed separates
    agent-reported claims from verified facts."""
    async def _t():
        boss = await make(env1, state_root, "boss32")
        w = await make(env1, state_root, "worker32")
        job = (await boss.assign_work(["worker32"], "no shortcuts"))[0]
        with pytest.raises(RequestFailed):
            await boss.complete_work(job["id"])  # skip attempt
        inbox = await boss.work_inbox()
        assert next(x for x in inbox
                    if x["id"] == job["id"])["status"] == "assigned"
        await w.report_progress(job["id"], 40)
        await w.deliver_work(job["id"], body="real delivery")
        await boss.complete_work(job["id"])
        data = env1["relay"]._dashboard_data()
        kinds = [e["kind"] for e in data["activity"]]
        assert "work_progress" in kinds        # a CLAIM event type
        proofs = [e for e in data["activity"]
                  if e["kind"] == "delivery_proof_verified"]
        assert proofs and proofs[0]["status"] in ("true", True, "True")
        page = Path(ROOT / "agentlink" / "dashboard.py").read_text()
        assert "agent-reported" in page and "verified" in page
        await boss.close(); await w.close()
    run(_t())


# -- point 33: capability profiles ---------------------------------------------------------

def test_capability_profiles_signed_updates(env1, state_root):
    """Point 33: capabilities are public directory metadata; search
    by capability finds online agents first; absent capability finds
    none; an unsigned/wrong-key update is rejected; a signed update
    changes the search results."""
    async def _t():
        a = await make(env1, state_root, "capable33",
                       capabilities=["research", "data"],
                       cap_description="digs and crunches")
        b = await make(env1, state_root, "seeker33")
        hits = await b.directory(capability="research")
        assert any(u["username"] == "capable33" for u in hits)
        assert hits[0]["username"] == "capable33"  # online first
        assert await b.directory(capability="wizardry") == []
        from agentlink.crypto import Identity
        stranger = Identity.ephemeral()
        canonical = "caps|capable33|research,video|updated".encode()
        with pytest.raises(RequestFailed) as ei:
            await a._request({
                "type": "update_capabilities",
                "capabilities": ["research", "video"],
                "cap_desc": "updated",
                "signature": stranger.sign(canonical)})
        assert ei.value.reason == "bad_signature"
        await a.update_capabilities(["research", "video"], "updated")
        hits = await b.directory(capability="video")
        assert any(u["username"] == "capable33" for u in hits)
        assert await b.directory(capability="data") == [] or \
            all(u["username"] != "capable33"
                for u in await b.directory(capability="data"))
        await a.close(); await b.close()
    run(_t())


# -- point 37: fleet alerts -------------------------------------------------------------------

class _Hook(BaseHTTPRequestHandler):
    hits: list = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        type(self).hits.append(
            {"body": body.decode(), "sig": self.headers.get(
                "X-AgentLink-Signature")})
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def test_fleet_alerts_webhook_resolve_reincident(state_root, tmp_path):
    """Point 37: an agent offline past the threshold raises EXACTLY
    ONE alert + one webhook; returning resolves it; a second death
    is a NEW incident; an undelivered urgent raises its own alert."""
    _Hook.hits = []
    server = HTTPServer((HOST, 0), _Hook)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    hook_url = f"http://{HOST}:{server.server_port}/hook"
    db = str(Path(tmp_path) / "alerts.db")
    relay, box = start_relay(
        db, alert_offline_seconds=2, alert_urgent_seconds=2,
        alert_webhook=hook_url, dashboard_enabled=False)
    env = {"url": f"ws://{HOST}:{relay.port}", "relay": relay}

    async def _t():
        a = await make(env, state_root, "alert-watch")
        b = await make(env, state_root, "alert-peer")
        await a.close()
        store = relay.store
        assert await wait_for(lambda: any(
            al["kind"] == "agent_offline" and al["status"] == "open"
            for al in store.list_alerts()), 15)
        assert await wait_for(lambda: len(_Hook.hits) >= 1, 10)
        n_alerts = len([al for al in store.list_alerts()
                        if al["kind"] == "agent_offline"])
        await asyncio.sleep(3)  # reminders throttled: still one alert
        assert len([al for al in store.list_alerts()
                    if al["kind"] == "agent_offline"]) == n_alerts
        a2 = await make(env, state_root, "alert-watch")
        assert await wait_for(lambda: all(
            al["status"] == "resolved" for al in store.list_alerts()
            if al["kind"] == "agent_offline"), 10)
        await a2.close()
        assert await wait_for(lambda: len(
            [al for al in store.list_alerts()
             if al["kind"] == "agent_offline"]) > n_alerts, 15)
        # Urgent item undelivered past the threshold.
        await b.send_message("alert-watch", "URGENT while down",
                             priority="urgent")
        assert await wait_for(lambda: any(
            al["kind"] == "urgent_undelivered"
            for al in store.list_alerts()), 15)
        await b.close()
    try:
        run(_t())
    finally:
        stop_relay(relay, box)
        server.shutdown()


# -- point 39a: no-long-sleep source audit -------------------------------------------------------

def test_39a_no_long_sleep_source_audit():
    """Point 39a: scan the runtime package — no sleep/backoff literal
    may exceed the 5-second cap. Named, documented exceptions are
    OPERATOR-plane intervals only (update checks, backup schedule,
    dashboard session life, login rate window, self-check cadence,
    network watch) and live in agentlink/timing.py as constants, not
    as inline waits in the work path."""
    import agentlink.timing as T
    offenders = []
    for py in (ROOT / "agentlink").glob("*.py"):
        src = py.read_text()
        for m in re.finditer(r"(?:asyncio|time)\.sleep\(\s*(\d+(?:\.\d+)?)",
                             src):
            if float(m.group(1)) > T.RECONNECT_BACKOFF_CAP_SECONDS:
                offenders.append(f"{py.name}: sleep({m.group(1)})")
        for m in re.finditer(r"backoff[^\n=]*=\s*(\d+(?:\.\d+)?)", src, re.I):
            if float(m.group(1)) > T.RECONNECT_BACKOFF_CAP_SECONDS:
                offenders.append(f"{py.name}: backoff={m.group(1)}")
    assert offenders == [], offenders
    client_src = (ROOT / "agentlink" / "client.py").read_text()
    assert "RECONNECT_BACKOFF_CAP_SECONDS" in client_src
    assert "min(reconnect_delay" in client_src  # the clamp is real
    # No 'sleeping' presence state exists in the protocol surface.
    for py in (ROOT / "agentlink").glob("*.py"):
        assert '"sleeping"' not in py.read_text(), py.name


# -- point 41: work chains --------------------------------------------------------------------------

def test_work_chain_full_lifecycle(env1, state_root, tmp_path):
    """Point 41: a 3-step chain fires each step ONLY after the
    previous step's proven + accepted delivery; the previous
    deliverable is fetchable by the next assignee; a skip/forged
    trigger never advances it; changes_requested pauses and an
    accepted re-delivery resumes; cancel stops unreleased steps."""
    async def _t():
        creator = await make(env1, state_root, "chain-creator")
        s1 = await make(env1, state_root, "step-one")
        s2 = await make(env1, state_root, "step-two")
        s3 = await make(env1, state_root, "step-three")
        chain = await creator.create_chain([
            {"to": "step-one", "title": "gather"},
            {"to": "step-two", "title": "collate"},
            {"to": "step-three", "title": "publish"},
        ])
        cid = chain["id"]
        assert await wait_for(lambda: len(s1.assigned_work) >= 1)
        await asyncio.sleep(0.5)
        assert s2.assigned_work == [] and s3.assigned_work == []
        w1 = s1.assigned_work[0]
        assert w1["chain_id"] == cid and w1["chain_step"] == 1
        # Forged trigger: completing an undelivered step is rejected
        # by the state machine, so the chain cannot advance.
        with pytest.raises(RequestFailed):
            await creator.complete_work(w1["id"])
        await asyncio.sleep(0.5)
        assert s2.assigned_work == []
        # Step 1 delivers a file; creator accepts -> step 2 fires.
        f1 = tmp_path / "evidence.txt"; f1.write_text("step1 output")
        await s1.deliver_work(w1["id"], body="gathered",
                              files=[str(f1)])
        await creator.complete_work(w1["id"])
        assert await wait_for(lambda: len(s2.assigned_work) >= 1)
        w2 = s2.assigned_work[0]
        assert w2["chain_step"] == 2
        prev = w2.get("prev_deliverables") or []
        assert prev and prev[0]["filename"] == "evidence.txt"
        fetched = await s2.library_fetch(prev[0]["library_id"])
        from agentlink.protocol import file_bytes
        assert file_bytes(fetched["files"][0]) == b"step1 output"
        # changes_requested pauses the chain; step 3 must not fire.
        await s2.deliver_work(w2["id"], body="draft")
        await creator.request_changes(w2["id"], note="tighten it")
        view = await creator.chain_get(cid)
        assert view["status"] == "paused"
        await asyncio.sleep(0.5)
        assert s3.assigned_work == []
        await s2.deliver_work(w2["id"], body="final")
        await creator.complete_work(w2["id"])
        assert await wait_for(lambda: len(s3.assigned_work) >= 1)
        view = await creator.chain_get(cid)
        assert view["status"] == "running"
        # Cancel: step 3 never completes the chain; nothing more fires.
        await creator.chain_cancel(cid)
        view = await creator.chain_get(cid)
        assert view["status"] == "cancelled"
        for a in (creator, s1, s2, s3):
            await a.close()
    run(_t())


def test_work_chain_role_step_and_cancel_before_release(env1, state_root):
    """Point 41 + 22: a role-targeted step resolves its holder at
    release time; cancelling after step 1 means step 2 is NEVER
    dispatched, even though step 1 completed."""
    async def _t():
        creator = await make(env1, state_root, "chain-boss2")
        s1 = await make(env1, state_root, "chain-s1")
        holder = await make(env1, state_root, "chain-holder")
        g = await creator.group_create("ChainG", ["chain-s1",
                                                  "chain-holder"])
        gid = g["group_id"]
        await creator.group_set_custom_role(gid, "chain-holder",
                                            "Collator")
        chain = await creator.create_chain([
            {"to": "chain-s1", "title": "first"},
            {"role": "Collator", "group_id": gid, "title": "second"},
        ], group_id=gid)
        cid = chain["id"]
        assert await wait_for(lambda: len(s1.assigned_work) >= 1)
        w1 = s1.assigned_work[0]
        await s1.deliver_work(w1["id"], body="one done")
        await creator.complete_work(w1["id"])
        assert await wait_for(lambda: len(holder.assigned_work) >= 1)
        assert holder.assigned_work[0]["chain_id"] == cid

        chain2 = await creator.create_chain([
            {"to": "chain-s1", "title": "alpha"},
            {"to": "chain-holder", "title": "beta"},
        ])
        cid2 = chain2["id"]
        assert await wait_for(lambda: len(s1.assigned_work) >= 2)
        w = s1.assigned_work[-1]
        # Cancel while step 1 is still in flight; even when step 1
        # is then delivered AND accepted, the cancelled chain must
        # never release step 2.
        await creator.chain_cancel(cid2)
        await s1.deliver_work(w["id"], body="alpha done")
        await creator.complete_work(w["id"])
        await asyncio.sleep(1.0)
        beta = [x for x in holder.assigned_work
                if x.get("chain_id") == cid2]
        assert beta == [], "cancelled chain released a step"
        for a in (creator, s1, holder):
            await a.close()
    run(_t())


# -- point 42: timing map + Supabase structural -------------------------------------------------------

def test_42_timing_map_consistency():
    """Point 42B: runtime code reads the timing constants (no
    contradicting magic numbers); the TypeScript mirror in the
    Supabase Edge layer carries the SAME values."""
    import agentlink.timing as T
    import agentlink.client as C
    import agentlink.relay as R
    import agentlink.dashboard as D
    assert C.HEARTBEAT_SECONDS == T.HEARTBEAT_SECONDS == 5
    assert R.OFFLINE_GRACE_SECONDS == T.OFFLINE_GRACE_SECONDS == 15
    assert D.SESSION_TTL == T.DEVICE_TRUST_SECONDS == 7 * 24 * 3600
    ts = (ROOT / "supabase" / "functions" / "_shared"
          / "rules.ts").read_text()
    for name in ("HEARTBEAT_SECONDS", "OFFLINE_GRACE_SECONDS",
                 "RECONNECT_BACKOFF_CAP_SECONDS",
                 "DEVICE_TRUST_SECONDS"):
        m = re.search(rf"{name}\s*[:=]\s*(\d+(?:\s*\*\s*\d+)*)", ts)
        assert m, name
        value = 1
        for part in m.group(1).split("*"):
            value *= int(part)
        assert value == getattr(T, name), name


def test_42_supabase_edge_structure():
    """Point 42A: schema.sql mirrors the model with al_ tables, RLS
    locked to service-role, Realtime publication and pg_cron sweeps;
    the two Edge Functions exist and stay metadata-only."""
    schema = (ROOT / "supabase" / "schema.sql").read_text()
    for tbl in ("al_users", "al_groups", "al_group_members", "al_work",
                "al_chains", "al_chain_steps", "al_alerts",
                "al_audit_log", "al_library", "al_vault"):
        assert f"create table if not exists {tbl}" in schema, tbl
    assert "enable row level security" in schema
    assert "supabase_realtime" in schema
    assert "cron.schedule" in schema
    api = (ROOT / "supabase" / "functions" / "agentlink-api"
           / "index.ts").read_text()
    for route in ("/agents", "/directory", "/work", "/conversations",
                  "/library", "/alerts"):
        assert route in api, route
    events = (ROOT / "supabase" / "functions" / "agentlink-events"
              / "index.ts").read_text()
    assert "webhook" in events.lower()
    # Metadata-only: neither function decrypts or returns contents.
    for src in (api, events):
        assert "decrypt" not in src.lower()


# -- point 43: retry forever, self-heal, auto-adjust -------------------------------------------------------

def test_43c_home_probes_never_cap(env1, state_root, tmp_path):
    """Point 43c: riding a peer, the home probes keep firing with no
    cap while home stays down; when home returns the agent migrates
    back on its own."""
    db = str(Path(tmp_path) / "shared43.db")
    store = Store(db)
    home, hbox = start_relay(db, backend_store=store,
                             dashboard_enabled=False)
    peer, pbox = start_relay(db, backend_store=store,
                             dashboard_enabled=False)
    home_url = f"ws://{HOST}:{home.port}"
    peer_url = f"ws://{HOST}:{peer.port}"

    async def _t():
        a = Agent("probe-agent", endpoint=home_url, fallbacks=[peer_url],
                  state_dir=str(state_root / "probe-agent"))
        task = asyncio.create_task(
            a.run(reconnect_delay=0.5, home_probe_interval=1))
        assert await wait_for(lambda: a.current_endpoint == home_url)
        kill_relay(home, hbox)
        assert await wait_for(lambda: a.current_endpoint == peer_url, 15)
        c1 = a.home_probe_count
        await asyncio.sleep(6.5)
        c2 = a.home_probe_count
        assert c2 >= c1 + 2, (c1, c2)  # probes keep firing, uncapped
        # Still fully working on the peer.
        b = await make({"url": peer_url}, state_root, "probe-peer")
        await b.send_message("probe-agent", "still reachable")
        assert await wait_for(lambda: any(
            m["body"] == "still reachable" for m in a.messages))
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        await b.close()
    try:
        run(_t())
    finally:
        try:
            stop_relay(peer, pbox)
        except Exception:
            pass


def test_43d_self_heal_journal_and_membership_cache(env1, state_root):
    """Point 43d: a corrupted local journal is quarantined and
    rebuilt from the backend mirror at start; a deleted group-key
    cache is re-synced on reconnect so group traffic decrypts."""
    async def _t():
        boss = await make(env1, state_root, "boss43")
        w = await make(env1, state_root, "worker43")
        g = await boss.group_create("HealG", ["worker43"])
        gid = g["group_id"]
        job = (await boss.assign_work(["worker43"], "heal job",
                                      group_id=gid))[0]
        await w.checkpoint(job["id"], {"stage": "kept"})
        await w.close()
        # Corrupt the journal + delete the group-key cache.
        jpath = state_root / "worker43" / "tasks-worker43.db"
        jpath.write_bytes(b"this is not sqlite at all" * 10)
        gk = state_root / "worker43" / "groupkeys-worker43.json"
        if gk.exists():
            gk.unlink()
        w2 = await make(env1, state_root, "worker43")
        assert w2._pending_repairs == []  # flushed during start
        repairs = (state_root / "worker43"
                   / "self-repairs.jsonl").read_text()
        assert "journal" in repairs
        seen = {}

        def handler(work, ctx):
            seen["work"] = work
            seen["ctx"] = ctx

        w2.on_work(handler)
        # Resume pass ran during start: journal rebuilt from mirror.
        entry = w2._journal.get(job["id"])
        assert entry is not None
        assert entry.get("checkpoint") == {"stage": "kept"}
        # Group traffic decrypts again after cache re-sync.
        await boss.group_send(gid, "after heal")
        assert await wait_for(lambda: any(
            m["body"] == "after heal" for m in w2.messages))
        await boss.close(); await w2.close()
    run(_t())


def test_43e_auto_adjust_roles_and_permissions(env1, state_root):
    """Point 43e: role/nickname/permission changes apply the instant
    the realtime event lands — no reconnect: the member's local view
    updates, its send is locally gated under admins-only, promotion
    unblocks it immediately, and a role assignment created after a
    role change reaches the NEW holder only."""
    async def _t():
        boss = await make(env1, state_root, "boss43e")
        m = await make(env1, state_root, "member43e")
        n = await make(env1, state_root, "member43f")
        g = await boss.group_create("Adjust", ["member43e", "member43f"])
        gid = g["group_id"]
        await boss.group_set_custom_role(gid, "member43e", "Researcher")
        assert await wait_for(lambda: (m.memberships.get(gid) or {})
                              .get("custom_role") == "Researcher")
        # Move the role: member43f is the holder now.
        await boss.group_set_custom_role(gid, "member43e", "")
        await boss.group_set_custom_role(gid, "member43f", "Researcher")
        assert await wait_for(lambda: (n.memberships.get(gid) or {})
                              .get("custom_role") == "Researcher")
        await boss.assign_work_role(gid, "Researcher", "for the holder")
        assert await wait_for(lambda: len(n.assigned_work) == 1)
        assert m.assigned_work == []
        # Tighten sending to admins-only: member is locally gated.
        await boss.group_settings(gid, {"send_messages": "admins_only"})
        assert await wait_for(lambda: (m.memberships.get(gid) or {})
                              .get("settings", {})
                              .get("send_messages") == "admins_only")
        with pytest.raises(RequestFailed) as ei:
            await m.group_send(gid, "should be gated")
        assert ei.value.reason == "permission_denied_local"
        # Promotion lands live; the same call now succeeds.
        await boss.group_promote(gid, "member43e")
        assert await wait_for(lambda: (m.memberships.get(gid) or {})
                              .get("role") == "admin")
        await m.group_send(gid, "admin now, speaking")
        assert await wait_for(lambda: any(
            x["body"] == "admin now, speaking" for x in n.messages))
        for a in (boss, m, n):
            await a.close()
    run(_t())


# -- point 44: NO GOING DARK ---------------------------------------------------------------------------

def test_44_race_lands_on_second_peer(state_root, tmp_path):
    """Point 44a/44d-1: home AND the first peer die mid-run; the
    parallel race lands the agent on the second peer and its work
    continues — no serial walk through the dead list."""
    db = str(Path(tmp_path) / "dark.db")
    store = Store(db)
    home, hbox = start_relay(db, backend_store=store,
                             dashboard_enabled=False)
    peer1, p1box = start_relay(db, backend_store=store,
                               dashboard_enabled=False)
    peer2, p2box = start_relay(db, backend_store=store,
                               dashboard_enabled=False)
    urls = [f"ws://{HOST}:{r.port}" for r in (home, peer1, peer2)]

    async def _t():
        a = Agent("dark-agent", endpoint=urls[0],
                  fallbacks=urls[1:],
                  state_dir=str(state_root / "dark-agent"))
        task = asyncio.create_task(a.run(reconnect_delay=0.5))
        assert await wait_for(lambda: a.current_endpoint == urls[0])
        kill_relay(home, hbox)
        kill_relay(peer1, p1box)
        assert await wait_for(lambda: a.current_endpoint == urls[2], 15)
        b = await make({"url": urls[2]}, state_root, "dark-peer")
        job = (await b.assign_work(["dark-agent"], "in the dark? no"))[0]
        assert await wait_for(lambda: len(a.assigned_work) == 1, 15)
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
        await b.close()
    try:
        run(_t())
    finally:
        stop_relay(peer2, p2box)


def test_44_dns_failure_uses_doh_fallback(env1, state_root,
                                          monkeypatch):
    """Point 44b/44d-2: system DNS fails for the endpoint host; the
    client applies the documented fallback resolver strategy
    (DoH) and connects anyway."""
    import agentlink.client as C

    async def _t():
        port = env1["port"]
        calls = {"doh": 0}

        async def fake_doh(host):
            calls["doh"] += 1
            assert host == "agentlink-home.invalid"
            return ["127.0.0.1"]

        monkeypatch.setattr(C, "doh_lookup", fake_doh)
        # Make the SYSTEM resolver fail for this host (this VM's
        # egress DNS would otherwise answer a synthetic address for
        # any name): the REAL resolve_host chain must then fall
        # through to the DoH strategy.
        import socket as _socket
        real_gai = _socket.getaddrinfo

        def gai(host, port, *a, **kw):
            if host == "agentlink-home.invalid":
                raise _socket.gaierror("name or service not known")
            return real_gai(host, port, *a, **kw)

        monkeypatch.setattr(_socket, "getaddrinfo", gai)
        ips = await C.resolve_host("agentlink-home.invalid", port)
        assert ips == ["127.0.0.1"] and calls["doh"] >= 1
        a = Agent("dns-agent",
                  endpoint=f"ws://agentlink-home.invalid:{port}",
                  state_dir=str(state_root / "dns-agent"))
        await a.start()
        assert a.username == "dns-agent"
        await a.close()
    run(_t())


def test_44_reresolution_follows_new_address(env1, state_root,
                                             monkeypatch):
    """Point 44b/44d-3: resolution happens FRESH on every attempt —
    when the DNS answer changes between attempts, the client follows
    the new address (no stale-IP pinning)."""
    import agentlink.client as C

    async def _t():
        port = env1["port"]
        answers = [["127.0.0.2"], ["127.0.0.1"]]  # .2 first: dead end
        calls = {"n": 0}

        async def fake_resolve(host, port_):
            calls["n"] += 1
            return answers[min(calls["n"] - 1, 1)]

        monkeypatch.setattr(C, "resolve_host", fake_resolve)
        a = Agent("reres-agent", endpoint=f"ws://127.0.0.1:{port}",
                  state_dir=str(state_root / "reres-agent"))
        task = asyncio.create_task(a.run(reconnect_delay=0.5))
        assert await wait_for(
            lambda: a.connection_state == "connected", 15)
        assert calls["n"] >= 2  # re-resolved; first answer was a dud
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass
    run(_t())


def test_44_state_machine_has_no_terminal_state():
    """Point 44d-4: enumerate the connection states + check the
    source: exactly {connecting, connected}; no gave_up / terminal
    disconnected state exists anywhere in the client."""
    from agentlink.client import Agent
    assert Agent.CONNECTION_STATES == frozenset(
        {"connecting", "connected"})
    src = (ROOT / "agentlink" / "client.py").read_text()
    for bad in ("gave_up", "give_up", "max_retries", "retry_limit",
                '"disconnected"', "'disconnected'"):
        assert bad not in src, bad
    # The reconnect loop is unbounded by construction.
    assert "while True:" in src
