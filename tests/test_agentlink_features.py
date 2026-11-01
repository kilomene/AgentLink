"""Feature tests: E2EE guarantees, nicknames/custom roles, mentions,
group size cap, key rotation, and the live dashboard.

Real relay, real clients, no mocks — same fixture style as
test_agentlink.py (duplicated here so this file runs standalone).
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import urllib.request
from pathlib import Path

import pytest
from websockets.client import connect

from agentlink.client import Agent, RequestFailed
from agentlink.relay import Relay

HOST = "127.0.0.1"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-feat-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="test-pass", dashboard_port=0)
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
    yield {"url": f"ws://{HOST}:{relay.port}", "port": relay.port, "db": db,
           "dash_port": relay.dashboard_port}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-feat-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=30))


async def make(relay_env, state_root, username, **kw):
    a = Agent(username, endpoint=relay_env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=5.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


def test_relay_rejects_plaintext_and_stores_only_ciphertext(relay_env,
                                                             state_root):
    async def _t():
        bob = await make(relay_env, state_root, "bob")
        await bob.close()
        await asyncio.sleep(0.2)
        alice = await make(relay_env, state_root, "alice")
        await alice.send_message("bob", "top secret banana")
        await alice.close()
        # Raw plaintext frame must be refused outright.
        async with connect(relay_env["url"]) as ws:
            await ws.send(json.dumps(
                {"type": "hello", "username": "mallory", "display_name": "m",
                 "secret": None, "ephemeral": False, "req_id": "r0"}))
            assert json.loads(await ws.recv())["type"] == "welcome"
            await ws.send(json.dumps(
                {"type": "send", "to": "bob", "body": "plain hello",
                 "req_id": "r1"}))
            frame = json.loads(await ws.recv())
            assert frame["type"] == "error"
            assert frame["reason"] == "plaintext_not_allowed"
    run(_t())
    # The queued message in the relay DB is ciphertext only. (WAL mode:
    # recent writes live in the -wal file, so read both.)
    raw = Path(relay_env["db"]).read_bytes()
    wal = Path(relay_env["db"] + "-wal")
    if wal.exists():
        raw += wal.read_bytes()
    assert b"top secret banana" not in raw
    assert b'"ct"' in raw  # envelope present, content unreadable


def test_group_nickname_and_custom_role(relay_env, state_root):
    async def _t():
        one = await make(relay_env, state_root, "agent-one")
        two = await make(relay_env, state_root, "agent-two")
        g = await one.group_create("Named", ["agent-two"])
        gid = g["group_id"]
        # Group-local nickname: set by admin for a member, and own one.
        await one.group_set_nickname(gid, "Twoey", username="agent-two")
        await one.group_set_nickname(gid, "Boss")
        # Custom role label alongside the permission role.
        await one.group_set_custom_role(gid, "agent-two", "Researcher")
        members = {m["username"]: m
                   for m in (await one.group_members(gid))["members"]}
        assert members["agent-two"]["nickname"] == "Twoey"
        assert members["agent-two"]["custom_role"] == "Researcher"
        assert members["agent-two"]["role"] == "member"  # unchanged
        assert members["agent-one"]["nickname"] == "Boss"
        # Global identity untouched.
        users = {u["username"]: u for u in await one.directory()}
        assert users["agent-two"]["display_name"] == "agent-two"
        # A member cannot set another member's nickname.
        with pytest.raises(RequestFailed):
            await two.group_set_nickname(gid, "Hacked",
                                         username="agent-one")
        # Rich envelope: group messages carry sender nickname + role.
        await one.group_send(gid, "hello two")
        assert await wait_for(lambda: len(two.messages) == 1)
        msg = two.messages[0]
        assert msg["sender_nickname"] == "Boss"
        assert msg["sender_role"] == "superadmin"
        assert msg["encrypted"] is True
        assert msg["kind"] == "text" and msg["size"] == len("hello two")
        await one.close()
        await two.close()
    run(_t())


def test_mentions_fire_on_mention_and_inbox(relay_env, state_root):
    async def _t():
        one = await make(relay_env, state_root, "agent-one")
        two = await make(relay_env, state_root, "agent-two")
        three = await make(relay_env, state_root, "agent-three")
        mentioned = []

        @two.on_mention
        async def _mentioned(msg):
            mentioned.append(msg)

        g = await one.group_create("Mentions",
                                   ["agent-two", "agent-three"])
        gid = g["group_id"]
        await one.group_send(gid, "@agent-two please collate this")
        assert await wait_for(lambda: len(mentioned) == 1)
        assert mentioned[0]["mentions"] == ["agent-two"]
        assert len(two.mention_inbox()) == 1
        assert len(three.mention_inbox()) == 0

        # @all reaches every group member's mention inbox.
        await one.group_send(gid, "@all announcement")
        assert await wait_for(lambda: len(two.mention_inbox()) == 2)
        assert await wait_for(lambda: len(three.mention_inbox()) == 1)

        # 1:1 mention works too.
        await one.send_message("agent-two", "hey @agent-two direct")
        assert await wait_for(lambda: len(two.mention_inbox()) == 3)
        for a in (one, two, three):
            await a.close()
    run(_t())


def test_group_capped_at_50(relay_env, state_root):
    async def _t():
        # Register 51 users quickly via raw hello frames.
        async def register(name):
            async with connect(relay_env["url"]) as ws:
                await ws.send(json.dumps(
                    {"type": "hello", "username": name, "display_name": name,
                     "secret": None, "ephemeral": False}))
                assert json.loads(await ws.recv())["type"] == "welcome"

        names = [f"user-{i:02d}" for i in range(51)]
        for n in names:
            await register(n)
        creator = await make(relay_env, state_root, "boss")
        # boss + 49 = 50: OK.
        g = await creator.group_create("Full", names[:49])
        gid = g["group_id"]
        members = await creator.group_members(gid)
        assert len(members["members"]) == 50
        # The 51st agent does not fit.
        with pytest.raises(RequestFailed) as ei:
            await creator.group_add(gid, [names[49]])
        assert ei.value.reason == "group_full"
        await creator.close()
    run(_t())


def test_key_rotation_on_removal(relay_env, state_root):
    async def _t():
        one = await make(relay_env, state_root, "agent-one")
        two = await make(relay_env, state_root, "agent-two")
        three = await make(relay_env, state_root, "agent-three")
        g = await one.group_create("Rotate",
                                   ["agent-two", "agent-three"])
        gid = g["group_id"]
        await one.group_send(gid, "before removal")
        assert await wait_for(lambda: len(three.messages) == 1)
        epoch_before = one._group_keys[gid]["epoch"]

        await one.group_remove(gid, "agent-three")
        assert await wait_for(
            lambda: one._group_keys[gid]["epoch"] == epoch_before + 1)
        # Remaining members still read post-rotation messages;
        # the removed member receives nothing new.
        await one.group_send(gid, "after removal")
        assert await wait_for(lambda: len(two.messages) >= 1 and
                              two.messages[-1]["body"] == "after removal")
        await asyncio.sleep(0.5)
        assert all(m["body"] != "after removal" for m in three.messages)
        for a in (one, two, three):
            await a.close()
    run(_t())


def test_live_dashboard_metadata_only(relay_env, state_root):
    import http.cookiejar
    base = f"http://{HOST}:{relay_env['dash_port']}"
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj))

    def _fetch(path):
        return opener.open(base + path, timeout=5).read()

    async def _t():
        alice = await make(relay_env, state_root, "alice")
        bob = await make(relay_env, state_root, "bob")
        await alice.send_message("bob", "dashboard secret text")
        assert await wait_for(lambda: len(bob.messages) == 1)
        works = await alice.assign_work(["bob"], "Dash job",
                                        instructions="hidden instructions")
        await bob.deliver_work(works[0]["id"], "hidden delivery")
        # One-time login -> trusted device cookie.
        req = urllib.request.Request(base + "/login",
                                     data=b"password=test-pass",
                                     method="POST")
        await asyncio.to_thread(opener.open, req)
        html = (await asyncio.to_thread(_fetch, "/")).decode()
        data = json.loads(await asyncio.to_thread(_fetch, "/api/status"))
        await alice.close()
        await bob.close()
        return works[0]["id"], html, data
    wid, html, data = run(_t())
    assert "AgentLink" in html and "Live Dashboard" in html
    assert "alice" in data["online"] and "bob" in data["online"]
    work = [w for w in data["work"] if w["id"] == wid][0]
    assert work["status"] == "delivered"
    assert work["assigner"] == "alice" and work["assignee"] == "bob"
    blob = json.dumps(data)
    # Metadata only: no message text, no work content anywhere.
    assert "dashboard secret text" not in blob
    assert "hidden instructions" not in blob
    assert "hidden delivery" not in blob
    assert any(a["kind"] == "message" for a in data["activity"])
