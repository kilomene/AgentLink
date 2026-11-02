"""v1.1.0 upgrade regression suite (owner order 2026-11-01: every
feature in, advanced, nothing removed).

Pins: ephemeral-port fixtures under production load, the animated
drawer dashboard (served-HTML markers), conversation completeness
(sender nickname/role/custom role + group participants), the
reachability home-label fix, approval gates end-to-end (happy path,
reject path, chain blocking, decider rules, trust timing), the
AGENTLINK_BACKEND env fix, and the canonical invites / upload-session
schema alignment. Harness copied from test_features2.py.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

import pytest

from agentlink.client import Agent, RequestFailed, unpack_folder
from agentlink.deadlines import pacific_display, parse_deadline
from agentlink.protocol import file_bytes
from agentlink.relay import Relay

HOST = "127.0.0.1"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-f2-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="test-dash-pass", dashboard_port=0)
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
           "db": db, "dash_port": relay.dashboard_port, "relay": relay}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-f2-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


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


def dash_data(relay_env):
    base = f"http://{HOST}:{relay_env['dash_port']}"
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor())
    req = urllib.request.Request(
        base + "/login", data=b"password=test-dash-pass",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        opener.open(req, timeout=5)
    except urllib.error.HTTPError:
        pass
    return json.loads(opener.open(base + "/api/status", timeout=5).read())




def dash_html(relay_env):
    base = f"http://{HOST}:{relay_env['dash_port']}"
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor())
    import urllib.parse as _up
    body = _up.urlencode(
        {"password": relay_env["relay"].dashboard_password}).encode()
    req = urllib.request.Request(
        base + "/login", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        opener.open(req, timeout=5)
    except urllib.error.HTTPError:
        pass
    return opener.open(base + "/", timeout=5).read().decode()


# -- dashboard: drawer + animation system (served HTML markers) ----------

def test_dashboard_html_has_drawer_and_animation_system(relay_env):
    """Item 2a/2b: the served dashboard carries the animated slide-in
    side drawer (logo mark, grouped nav, live connection status),
    the pulsing LIVE indicator keyframes, enter transitions, animated
    presence dots and the prefers-reduced-motion guard."""
    html = dash_html(relay_env)
    assert 'id="drawer"' in html and 'class="mark"' in html
    for label in ("Overview", "Agents", "Conversations", "Work",
                  "Chains", "Library", "Vault", "Voice Rooms",
                  "Alerts"):
        assert label in html, label
    assert 'id="livedot"' in html and "livePulse" in html
    assert "@keyframes" in html and "riseIn" in html
    assert "prefers-reduced-motion" in html
    assert "new EventSource" in html or "EventSource('/api/stream')" in html
    # monitor-only: the page embeds no protocol action surface at all
    # (decisions happen on the line, never here)
    assert "work_action" not in html and "blob_session" not in html
    assert 'id="convs"' in html and 'id="work"' in html


# -- conversations: sender identity + group participants ------------------

def test_conversation_items_carry_sender_identity(relay_env, state_root):
    """Item 2c: after a scripted group message, /api/status
    conversations carry the sender's in-group nickname, permission
    role and custom role, and the group conversation lists its
    participants with the same identity fields."""
    async def _t():
        one = await make(relay_env, state_root, "conv-one")
        two = await make(relay_env, state_root, "conv-two")
        g = await one.group_create("Identity", ["conv-two"])
        gid = g["group_id"]
        await one.group_set_nickname(gid, "Boss")
        await one.group_set_custom_role(gid, "conv-one", "Lead")
        await one.group_send(gid, "status update for the board")
        assert await wait_for(lambda: len(two.messages) == 1)
        await one.close(); await two.close()
    run(_t())
    data = dash_data(relay_env)
    convs = [c for c in data["conversations"] if c["group_id"]]
    assert convs, "no group conversation in dashboard data"
    conv = convs[0]
    parts = {p["username"]: p for p in conv["participants"]}
    assert parts["conv-one"]["nickname"] == "Boss"
    assert parts["conv-one"]["role"] == "superadmin"
    assert parts["conv-one"]["custom_role"] == "Lead"
    assert "conv-two" in parts
    items = [i for i in conv["items"] if i["kind"] == "group_message"]
    assert items, "group message item missing"
    item = items[-1]
    assert item["sender_nickname"] == "Boss", item
    assert item["sender_role"] == "superadmin", item
    assert item["sender_custom_role"] == "Lead", item


# -- reachability: home label compares endpoint identity, not --name -----

def test_is_home_endpoint_ignores_server_name(relay_env):
    """Item 2d (unit): a named relay recognises its own public
    endpoint and its bind address as home; foreign endpoints are not
    home; the friendly label is never an endpoint."""
    unit_db = str(Path(tempfile.mkdtemp(prefix="agentlink-v11-unit-"))
                  / "unit.db")
    relay = Relay(host=HOST, port=0, db_path=unit_db,
                  dashboard_enabled=False,
                  server_name="Phoenix Home Relay",
                  public_endpoint="wss://x.novamail.store/ws")
    assert relay.server_label == "Phoenix Home Relay"
    assert relay._is_home_endpoint("wss://x.novamail.store/ws")
    assert relay._is_home_endpoint("wss://x.novamail.store/ws/")
    assert relay._is_home_endpoint(f"ws://{HOST}:{relay.port}")
    assert not relay._is_home_endpoint("wss://other.example/ws")
    assert not relay._is_home_endpoint("Phoenix Home Relay")
    assert not relay._is_home_endpoint("")


def test_named_relay_labels_home_agents_home(state_root):
    """Item 2d (integration): with --name set, an agent homed to THIS
    relay reads 'online (home)' — the v1.0 bug read
    'online (via Phoenix Home Relay)'."""
    tmp = tempfile.mkdtemp(prefix="agentlink-v11-named-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="pw-named", dashboard_port=0,
                  server_name="Phoenix Home Relay")
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
    env = {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "dash_port": relay.dashboard_port, "relay": relay}

    async def _t():
        a = await make(env, state_root, "homer")
        data = relay._dashboard_data()
        row = next(u for u in data["users"]
                   if u["username"] == "homer")
        assert row["online"], row
        assert row["reachability"] == "online (home)", row
        await a.close()
    run(_t())
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


# -- approval gates ---------------------------------------------------------

def test_approval_gate_happy_path(relay_env, state_root):
    """Item 3: gated delivery parks in awaiting_approval; only the
    assigner's approve completes it; audit records gate set,
    delivered-awaiting, approved; trust: +1 on proven delivery,
    +4 on final completion."""
    async def _t():
        boss = await make(relay_env, state_root, "gate-boss")
        hand = await make(relay_env, state_root, "gate-hand")
        store = relay_env["relay"].store
        assert store.compute_trust("gate-hand") == 50
        work = (await boss.assign_work(
            ["gate-hand"], "Gated task", "do the thing",
            require_approval=True))[0]
        assert work["require_approval"] is True
        assert work["status"] == "assigned"
        delivered = await hand.deliver_work(work["id"], "done")
        assert delivered["status"] == "awaiting_approval", delivered
        # proven delivery still earns its +1 while parked
        assert store.compute_trust("gate-hand") == 51
        # the assignee cannot decide their own gate
        with pytest.raises(RequestFailed):
            await hand.approve_work(work["id"])
        approved = await boss.approve_work(work["id"], "looks right")
        assert approved["status"] == "completed"
        assert store.compute_trust("gate-hand") == 54
        kinds = [r["kind"] for r in store.list_audit(200)]
        for kind in ("approval_gate_set", "work_awaiting_approval",
                     "work_approved", "work_completed"):
            assert kind in kinds, kind
        await boss.close(); await hand.close()
    run(_t())


def test_approval_gate_reject_and_redeliver(relay_env, state_root):
    """Item 3: reject returns the work to changes_requested with the
    reason reaching the assignee; trust keeps the +1 delivery point
    but takes the -6 changes-requested hit; a re-delivery parks
    again and a later approve completes."""
    async def _t():
        boss = await make(relay_env, state_root, "rej-boss")
        hand = await make(relay_env, state_root, "rej-hand")
        store = relay_env["relay"].store
        work = (await boss.assign_work(
            ["rej-hand"], "Gated", "v1 please",
            require_approval=True))[0]
        await hand.deliver_work(work["id"], "v1")
        rejected = await boss.reject_work(work["id"], "needs more detail")
        assert rejected["status"] == "changes_requested"
        # state-based formula: the delivery +1 is surrendered when the
        # work leaves the delivered state; the round scores -6.
        assert store.compute_trust("rej-hand") == 50 - 6
        kinds = [r["kind"] for r in store.list_audit(200)]
        assert "work_approval_rejected" in kinds
        assert "work_changes_requested" in kinds
        again = await hand.deliver_work(work["id"], "v2 with detail")
        assert again["status"] == "awaiting_approval"
        done = await boss.approve_work(work["id"])
        assert done["status"] == "completed"
        await boss.close(); await hand.close()
    run(_t())


def test_approval_gate_blocks_chain_until_approved(relay_env, state_root):
    """Item 3: a gated chain step does NOT release the next step on
    delivery — only on approval."""
    async def _t():
        boss = await make(relay_env, state_root, "chain-boss")
        first = await make(relay_env, state_root, "chain-first")
        second = await make(relay_env, state_root, "chain-second")
        chain = await boss.create_chain([
            {"to": "chain-first", "title": "Step one",
             "require_approval": True},
            {"to": "chain-second", "title": "Step two"}],
            name="gated chain")
        inbox1 = await first.work_inbox()
        assert len(inbox1) == 1
        wid = inbox1[0]["id"]
        parked = await first.deliver_work(wid, "step one output")
        assert parked["status"] == "awaiting_approval"
        # next step must NOT have been released by the delivery alone
        assert await second.work_inbox() == []
        await boss.approve_work(wid)
        inbox2 = await second.work_inbox()
        assert len(inbox2) == 1, inbox2
        assert inbox2[0]["title"] == "Step two"
        await boss.close(); await first.close(); await second.close()
    run(_t())


def test_approval_gate_group_admin_may_decide(relay_env, state_root):
    """Item 3: for group work, a group admin (not the assigner) may
    decide; a plain member may not."""
    async def _t():
        boss = await make(relay_env, state_root, "grp-boss")
        admin = await make(relay_env, state_root, "grp-admin")
        hand = await make(relay_env, state_root, "grp-hand")
        g = await boss.group_create(
            "GateGroup", ["grp-admin", "grp-hand"])
        gid = g["group_id"]
        await boss.group_promote(gid, "grp-admin")
        work = (await boss.assign_work(
            ["grp-hand"], "Group gated", "group task", group_id=gid,
            require_approval=True))[0]
        await hand.deliver_work(work["id"], "done")
        with pytest.raises(RequestFailed):
            await hand.approve_work(work["id"])
        decided = await admin.approve_work(work["id"], "admin ok")
        assert decided["status"] == "completed"
        await boss.close(); await admin.close(); await hand.close()
    run(_t())


def test_gate_off_behaves_like_v1(relay_env, state_root):
    """Item 3: without require_approval the lifecycle is unchanged —
    delivery lands in 'delivered', complete works, and approve/reject
    actions on a non-gated work are refused."""
    async def _t():
        boss = await make(relay_env, state_root, "plain-boss")
        hand = await make(relay_env, state_root, "plain-hand")
        work = (await boss.assign_work(
            ["plain-hand"], "Plain task", "no gate"))[0]
        assert work["require_approval"] is False
        delivered = await hand.deliver_work(work["id"], "done")
        assert delivered["status"] == "delivered"
        with pytest.raises(RequestFailed):
            await boss.approve_work(work["id"])
        done = await boss.complete_work(work["id"])
        assert done["status"] == "completed"
        store = relay_env["relay"].store
        kinds = [r["kind"] for r in store.list_audit(200)]
        assert "approval_gate_set" not in kinds
        assert "work_awaiting_approval" not in kinds
        await boss.close(); await hand.close()
    run(_t())


# -- backend env (item 4a) ---------------------------------------------------

def _relay_subprocess(env_extra):
    import subprocess
    import sys
    env = dict(os.environ)
    env.pop("AGENTLINK_BACKEND", None)
    env.pop("SUPABASE_URL", None)
    env.pop("SUPABASE_SERVICE_KEY", None)
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "agentlink.relay",
         "--host", "127.0.0.1", "--port", "0", "--dashboard-port", "0",
         "--db", str(Path(tempfile.mkdtemp()) / "r.db")],
        capture_output=True, text=True, env=env, timeout=30,
        cwd=str(Path(__file__).resolve().parent.parent))


def test_backend_env_honored_without_flag():
    """Item 4a: AGENTLINK_BACKEND alone selects the backend — a bogus
    value dies in create_store with 'unknown backend', proving main()
    read the environment (v1.0 ignored it without --backend)."""
    proc = _relay_subprocess({"AGENTLINK_BACKEND": "bogus"})
    assert proc.returncode != 0
    assert "unknown backend" in proc.stderr, proc.stderr[-500:]


def test_backend_env_supabase_needs_keys():
    """Item 4a: AGENTLINK_BACKEND=supabase without keys fails closed
    with the store's own configuration error."""
    proc = _relay_subprocess({"AGENTLINK_BACKEND": "supabase"})
    assert proc.returncode != 0
    assert "SUPABASE_URL" in proc.stderr, proc.stderr[-500:]


# -- canonical schema alignment (item 4b) -------------------------------------

def test_store_schema_is_canonical(relay_env):
    """Item 4b: a fresh SQLite store has the Supabase-canonical
    invites (token/created_at) and upload_sessions (no for_channel)
    shapes, plus the v1.1 audit/work/chain columns."""
    import sqlite3
    db = sqlite3.connect(relay_env["db"])
    cols = {r[1] for r in db.execute("PRAGMA table_info(invites)")}
    assert cols == {"token", "group_id", "created_by", "created_at"}, cols
    cols = {r[1] for r in
            db.execute("PRAGMA table_info(upload_sessions)")}
    assert "for_channel" not in cols
    assert {"session_id", "owner", "for_user", "for_group"} <= cols
    cols = {r[1] for r in db.execute("PRAGMA table_info(audit_log)")}
    assert {"sender_nickname", "sender_role",
            "sender_custom_role"} <= cols
    cols = {r[1] for r in db.execute("PRAGMA table_info(work)")}
    assert "require_approval" in cols
    cols = {r[1] for r in db.execute("PRAGMA table_info(chain_steps)")}
    assert "require_approval" in cols
    db.close()


def test_invite_roundtrip_and_expiry(relay_env):
    """Item 4b: invites validate by hash-at-rest token and expire on
    the canonical created_at + TTL rule."""
    from agentlink.store import INVITE_TTL_SECONDS
    store = relay_env["relay"].store
    token = store.create_invite("g-x", "someone")
    assert store.invite_valid("g-x", token)
    assert not store.invite_valid("g-x", token + "x")
    assert not store.invite_valid("g-y", token)
    with store._lock:
        store._db.execute(
            "UPDATE invites SET created_at = created_at - ?",
            (INVITE_TTL_SECONDS + 60,))
        store._db.commit()
    assert not store.invite_valid("g-x", token)


def test_upload_session_shape_and_finish_scope(relay_env, state_root):
    """Item 4b: sessions round-trip without a persisted channel
    column; a channel-scoped chunked upload still lands its blob
    scope from the finish frame (client carries it)."""
    async def _t():
        a = await make(relay_env, state_root, "up-scope")
        b = await make(relay_env, state_root, "down-scope")
        chan = await a.channel_create("Scoped", ["down-scope"])
        cid = chan["channel_id"]
        sess = relay_env["relay"].store.get_upload_session(
            (await a.start_upload_session(
                b"x" * 10, for_channel=cid))[0])
        assert sess is not None and sess["for_channel"] == ""
        data = os.urandom(1_500_000)
        blob_id = await a.upload_blob(data, for_channel=cid)
        got = await b._request({"type": "blob_get", "blob_id": blob_id})
        assert base64.b64decode(got["data_b64"]) == data
        await a.close(); await b.close()
    run(_t())
