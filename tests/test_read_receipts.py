"""v1.1.2 read receipts — real composition only (owner order
2026-11-01 23:54 PST: everything real-time, and WhatsApp-style READ
state on the dashboard — when an agent reads a message, the owner
sees it from the dashboard, exactly like WhatsApp).

Every test here runs the REAL chain: real Agent clients -> real
relay -> audit + reads store -> real dashboard /api/status payload.
No fabricated counterparts: the receipt state asserted in the
dashboard payload is produced by the recipient client's own read
frame (auto-read on handler delivery, or an explicit mark_read),
validated and recorded by the relay.

Semantics pinned:
  * auto-read fires when a message is delivered into the agent's
    registered on_message handler (auto_read=True, the default);
  * explicit mark_read covers runtimes that defer handling
    (auto_read=False, or no handler at all);
  * the relay derives the conversation from the message's audit
    row — a non-participant, the sender, or an unknown id records
    NOTHING;
  * first read wins;
  * a message nobody read carries NO read state anywhere in the
    dashboard payload (honesty rule);
  * delivery state rides the audit row: 'sent' while queued for an
    offline recipient, 'delivered' on live delivery and after the
    hello queue-flush.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from agentlink.client import Agent
from agentlink.relay import Relay

HOST = "127.0.0.1"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-rr-")
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
    with tempfile.TemporaryDirectory(prefix="agentlink-rr-agents-") as tmp:
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


def conv_items(data, kind):
    return [i for c in data["conversations"] for i in c["items"]
            if i["kind"] == kind]


def test_read_receipt_1v1_auto_read_and_dashboard(relay_env, state_root):
    """(a) 1v1: a message delivered into the recipient's handler is
    auto-reported read; the store records it (first read, reader =
    the recipient), the SENDER gets the live read_receipt frame +
    on_read callback, and the dashboard item carries read_by plus
    the delivered state."""
    receipts = []

    async def _t():
        one = await make(relay_env, state_root, "rr-one")
        two = await make(relay_env, state_root, "rr-two")
        got = []

        @two.on_message
        async def _h(msg):
            got.append(msg)

        @one.on_read
        async def _r(rcpt):
            receipts.append(rcpt)

        res = await one.send_message("rr-two", "seen state, please")
        mid = res["id"]
        assert await wait_for(lambda: len(got) == 1)
        store = relay_env["relay"].store
        assert await wait_for(
            lambda: bool(store.reads_for([mid]).get(mid)))
        reads = store.reads_for([mid])[mid]
        assert [r["username"] for r in reads] == ["rr-two"]
        assert reads[0]["read_at"] >= 1
        # the sender learned about it live, over the line
        assert await wait_for(
            lambda: any(r.get("id") == mid and r.get("reader") == "rr-two"
                        for r in one.read_receipts))
        assert await wait_for(lambda: len(receipts) == 1)
        await one.close(); await two.close()
        return mid
    mid = run(_t())
    data = dash_data(relay_env)
    items = [i for i in conv_items(data, "message") if i["id"] == mid]
    assert len(items) == 1, items
    item = items[0]
    assert item["status"] == "delivered", item
    assert [r["username"] for r in item["read_by"]] == ["rr-two"]
    assert item["read_by"][0]["read_at"] >= 1
    # the read itself is visible in the activity feed as a
    # relay-verified event
    kinds = [r["kind"] for r in data["activity"]]
    assert "message_read" in kinds


def test_read_receipt_group_read_by_accumulates(relay_env, state_root):
    """(b) group: read-by accumulates per member — two members with
    handlers auto-read; the third (no handler: never took the
    message in) is ABSENT until it explicitly marks the message
    read, then it joins the list."""
    async def _t():
        lead = await make(relay_env, state_root, "rr-lead")
        mema = await make(relay_env, state_root, "rr-mema")
        memb = await make(relay_env, state_root, "rr-memb")
        memc = await make(relay_env, state_root, "rr-memc")
        for a in (mema, memb):
            got = []
            a.on_message(lambda msg, g=got: g.append(msg))
        g = await lead.group_create(
            "Receipt Crew", ["rr-mema", "rr-memb", "rr-memc"])
        gid = g["group_id"]
        res = await lead.group_send(gid, "group seen check")
        mid = res["id"]
        assert await wait_for(
            lambda: any(m.get("id") == mid for m in mema.messages))
        assert await wait_for(
            lambda: any(m.get("id") == mid for m in memb.messages))
        assert await wait_for(
            lambda: any(m.get("id") == mid for m in memc.messages))
        store = relay_env["relay"].store
        assert await wait_for(
            lambda: len(store.reads_for([mid]).get(mid, [])) == 2)
        readers = {r["username"]
                   for r in store.reads_for([mid])[mid]}
        assert readers == {"rr-mema", "rr-memb"}, readers
        # the third member reads it on its own schedule
        out = await memc.mark_read(mid)
        assert out["read"] == [mid], out
        readers = {r["username"]
                   for r in store.reads_for([mid])[mid]}
        assert readers == {"rr-mema", "rr-memb", "rr-memc"}
        # first-read-wins: a re-read changes nothing
        before = store.reads_for([mid])[mid]
        await memc.mark_read([mid])
        assert store.reads_for([mid])[mid] == before
        await lead.close(); await mema.close()
        await memb.close(); await memc.close()
        return mid
    mid = run(_t())
    data = dash_data(relay_env)
    items = [i for i in conv_items(data, "group_message")
             if i["id"] == mid]
    assert len(items) == 1, items
    readers = {r["username"] for r in items[0]["read_by"]}
    assert readers == {"rr-mema", "rr-memb", "rr-memc"}, items[0]


def test_read_receipt_channel_post(relay_env, state_root):
    """Channels compose the same way: a subscriber who takes a post
    in gains read state on the channel item."""
    async def _t():
        one = await make(relay_env, state_root, "rrc-one")
        two = await make(relay_env, state_root, "rrc-two")
        got = []
        two.on_message(lambda msg: got.append(msg))
        c = await one.channel_create("Receipt Wire", ["rrc-two"])
        res = await one.channel_send(c["channel_id"], "post seen?")
        mid = res["id"]
        assert await wait_for(lambda: len(got) == 1)
        store = relay_env["relay"].store
        assert await wait_for(
            lambda: bool(store.reads_for([mid]).get(mid)))
        await one.close(); await two.close()
        return mid
    mid = run(_t())
    data = dash_data(relay_env)
    items = [i for i in conv_items(data, "channel_message")
             if i["id"] == mid]
    assert len(items) == 1, items
    assert [r["username"] for r in items[0]["read_by"]] == ["rrc-two"]


def test_read_receipt_honesty_unread_has_no_state(relay_env, state_root):
    """(c) honesty: a message delivered to an agent with NO handler
    (it sits in the client's message list; the runtime never took
    it in) carries NO read state — not in the store, and the key is
    absent from the dashboard item entirely."""
    async def _t():
        one = await make(relay_env, state_root, "rrh-one")
        two = await make(relay_env, state_root, "rrh-two")
        res = await one.send_message("rrh-two", "nobody reads this")
        mid = res["id"]
        assert await wait_for(lambda: len(two.messages) == 1)
        # well past the client's batched-flush window
        await asyncio.sleep(1.0)
        store = relay_env["relay"].store
        assert store.reads_for([mid]) == {}
        await one.close(); await two.close()
        return mid
    mid = run(_t())
    data = dash_data(relay_env)
    items = [i for i in conv_items(data, "message") if i["id"] == mid]
    assert len(items) == 1, items
    assert "read_by" not in items[0], items[0]
    assert items[0]["status"] == "delivered", items[0]


def test_read_receipt_validation_records_nothing(relay_env, state_root):
    """The relay trusts only its own audit row: the SENDER marking
    their own message, a non-participant marking it, and an unknown
    id all record nothing — and the frame still answers cleanly."""
    async def _t():
        one = await make(relay_env, state_root, "rrv-one")
        two = await make(relay_env, state_root, "rrv-two")
        spy = await make(relay_env, state_root, "rrv-spy")
        res = await one.send_message("rrv-two", "for two only")
        mid = res["id"]
        assert await wait_for(lambda: len(two.messages) == 1)
        store = relay_env["relay"].store
        out = await one.mark_read(mid)          # sender: not a read
        assert out["read"] == [], out
        out = await spy.mark_read(mid)          # outsider: not a read
        assert out["read"] == [], out
        out = await two.mark_read("no-such-id")  # unknown id
        assert out["read"] == [], out
        assert store.reads_for([mid]) == {}
        # ...and the real recipient still can
        out = await two.mark_read(mid)
        assert out["read"] == [mid], out
        assert [r["username"] for r in store.reads_for([mid])[mid]] \
            == ["rrv-two"]
        await one.close(); await two.close(); await spy.close()
    run(_t())


def test_read_receipts_disabled_client_exchanges_normally(
        relay_env, state_root):
    """(d) back-compat: a client with receipts disabled
    (auto_read=False — the stand-in for older clients that never
    send read frames) exchanges messages in both directions
    normally; nothing is recorded for it until it explicitly marks
    a message read itself."""
    async def _t():
        one = await make(relay_env, state_root, "rrd-one")
        two = await make(relay_env, state_root, "rrd-two",
                         auto_read=False)
        got = []
        two.on_message(lambda msg: got.append(msg))
        res = await one.send_message("rrd-two", "legacy direction one")
        mid = res["id"]
        assert await wait_for(lambda: len(got) == 1)
        await asyncio.sleep(1.0)  # past any flush window
        store = relay_env["relay"].store
        assert store.reads_for([mid]) == {}
        back = await two.send_message("rrd-one", "legacy direction two")
        assert back["id"]
        assert await wait_for(lambda: len(one.messages) == 1)
        out = await two.mark_read(mid)
        assert out["read"] == [mid], out
        assert [r["username"] for r in store.reads_for([mid])[mid]] \
            == ["rrd-two"]
        await one.close(); await two.close()
    run(_t())


def test_delivery_state_sent_then_delivered_on_flush(
        relay_env, state_root):
    """Delivery ticks: a message to an OFFLINE agent is 'sent'
    (queued at the relay); when the agent comes online the hello
    flush delivers it and the audit state upgrades to 'delivered'
    — and once its handler takes it in, the read lands too."""
    async def _t():
        one = await make(relay_env, state_root, "rrq-one")
        two = await make(relay_env, state_root, "rrq-two")
        await two.close()
        # wait until the relay has actually dropped the peer, so the
        # send provably takes the offline-queue path
        assert await wait_for(
            lambda: "rrq-two" not in relay_env["relay"].peers)
        res = await one.send_message("rrq-two", "queued while away")
        mid = res["id"]
        assert res["queued"] is True
        await one.close()
        return mid
    mid = run(_t())
    data = dash_data(relay_env)
    items = [i for i in conv_items(data, "message") if i["id"] == mid]
    assert len(items) == 1, items
    assert items[0]["status"] == "sent", items[0]
    assert "read_by" not in items[0], items[0]

    async def _t2():
        # handler registered BEFORE start(): the hello flush must
        # not be able to outrun it
        two = Agent("rrq-two", endpoint=relay_env["url"],
                    state_dir=str(state_root / "rrq-two"))
        got = []
        two.on_message(lambda msg: got.append(msg))
        await two.start()
        assert await wait_for(lambda: len(two.messages) == 1)
        assert await wait_for(lambda: len(got) == 1)
        store = relay_env["relay"].store
        assert await wait_for(
            lambda: bool(store.reads_for([mid]).get(mid)))
        await two.close()
    run(_t2())
    data = dash_data(relay_env)
    items = [i for i in conv_items(data, "message") if i["id"] == mid]
    assert len(items) == 1, items
    assert items[0]["status"] == "delivered", items[0]
    assert [r["username"] for r in items[0]["read_by"]] == ["rrq-two"]
