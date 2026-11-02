"""v1.1.7 platform autonomy law — real composition only.

The law (owner, 2026-11-02): on AgentLink an agent works for the
PLATFORM, not its owner. Two modes: MANUAL (direction from its
owner) and AUTONOMOUS (the default — the agent replies and works
entirely on its own; every permission comes from whoever gives it
work on the line, via the assigner-side approval gates).

Semantics pinned here, all against a real relay + real clients:

  * the DEFAULT is autonomous — constructor, directory, presence and
    the dashboard payload all say so with no mode argument anywhere;
    manual appears only when explicitly chosen;
  * the runtime is a LOOP, not an intelligence: it consults the
    agent's OWN registered brain. No brain wired -> a loud startup
    warning + silence (never a fabricated reply or delivery);
  * two autonomous agents CANNOT ping-pong forever: autonomous sends
    are meta-marked, per-conversation consecutive caps tighten
    against an autonomous counterparty, and the exchange STOPS;
  * autonomous work round-trips for real: brain executes, reports
    progress, delivers with a relay-verified signed proof;
  * a brain decline is honest: the assigner hears the brain's own
    reason, the work is NOT delivered;
  * a manual-mode agent never auto-replies, brain or not.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

import pytest

from agentlink import timing
from agentlink.client import Agent
from agentlink.relay import Relay

HOST = "127.0.0.1"
DASH_PW = "autonomy-test-pw"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-auto-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password=DASH_PW, dashboard_port=0)
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
    with tempfile.TemporaryDirectory(prefix="agentlink-auto-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def make(relay_env, state_root, username, **kw):
    a = Agent(username, endpoint=relay_env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=10.0):
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
        base + "/login", data=f"password={DASH_PW}".encode(),
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
    req = urllib.request.Request(
        base + "/login", data=f"password={DASH_PW}".encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        opener.open(req, timeout=5)
    except urllib.error.HTTPError:
        pass
    return opener.open(base + "/", timeout=5).read().decode("utf-8",
                                                           "replace")


# ---------------------------------------------------------------------
# (e) + default pins: mode in profile, presence and dashboard payload
# ---------------------------------------------------------------------

def test_default_mode_is_autonomous_everywhere(relay_env, state_root):
    async def _t():
        # No mode argument anywhere — the law's default.
        plain = await make(relay_env, state_root, "plainagent")
        manual = await make(relay_env, state_root, "handdriven",
                            mode="manual")
        assert plain.mode == "autonomous"
        assert manual.mode == "manual"
        rows = {r["username"]: r
                for r in await plain.directory()}
        assert rows["plainagent"]["mode"] == "autonomous"
        assert rows["handdriven"]["mode"] == "manual"
        data = dash_data(relay_env)
        users = {u["username"]: u for u in data["users"]}
        assert users["plainagent"]["mode"] == "autonomous"
        assert users["handdriven"]["mode"] == "manual"
        html = dash_html(relay_env)
        # The Agents view renders the badge for both states.
        assert "AUTONOMOUS" in html and "MANUAL" in html
        await plain.close()
        await manual.close()
    run(_t())


def test_bad_mode_is_refused(state_root):
    with pytest.raises(ValueError):
        Agent("someagent", state_dir=str(state_root / "x"),
              mode="semi-auto")


def test_loop_cap_constants_tighten_against_autonomous_peers():
    # The numbers the runtime enforces (timing.py): a small pacing
    # delay, a consecutive cap and an hourly budget per conversation,
    # both caps STRICTLY tighter when the counterparty is itself
    # autonomous, and no delay/backoff anywhere near the timing law.
    assert 0 < timing.AUTO_REPLY_DELAY_SECONDS <= 5
    assert timing.AUTO_REPLY_DELAY_AUTO_SECONDS >= \
        timing.AUTO_REPLY_DELAY_SECONDS
    assert timing.AUTO_MAX_CONSECUTIVE_AUTO < \
        timing.AUTO_MAX_CONSECUTIVE_REPLIES
    assert timing.AUTO_HOURLY_BUDGET_AUTO < timing.AUTO_HOURLY_BUDGET


# ---------------------------------------------------------------------
# The runtime loop: replies, marking, caps
# ---------------------------------------------------------------------

def test_autonomous_dm_and_group_mention_replies(relay_env, state_root):
    seen_ctx = []

    async def brain(ctx):
        seen_ctx.append(ctx)
        if ctx["kind"] == "message":
            return f"brain reply to: {ctx['message'].get('body')}"
        return None

    async def _t():
        poster = await make(relay_env, state_root, "poster",
                            mode="manual")
        bot = await make(relay_env, state_root, "helperbot", brain=brain,
                            capabilities=["help"])
        # DM: the brain answers; the send is marked autonomous.
        await poster.send_message("helperbot", "hello bot")
        assert await wait_for(lambda: any(
            m.get("from") == "helperbot" for m in poster.messages))
        reply = [m for m in poster.messages
                 if m.get("from") == "helperbot"][0]
        assert reply["body"] == "brain reply to: hello bot"
        assert (reply.get("meta") or {}).get("autonomous") is True
        # The brain got the structured context the contract promises.
        ctx = seen_ctx[0]
        assert ctx["agent"]["username"] == "helperbot"
        assert ctx["agent"]["mode"] == "autonomous"
        assert ctx["agent"]["capabilities"] == ["help"]
        assert ctx["sender"]["username"] == "poster"
        assert ctx["conversation"]["type"] == "dm"
        # Group: a non-mention message draws NO reply; a mention does.
        g = await poster.group_create("auto-room", ["helperbot"])
        gid = g["group_id"]
        await poster.group_send(gid, "just chatting, no mention")
        await asyncio.sleep(2.5)
        assert not any(m.get("group_id") == gid
                       and m.get("from") == "helperbot"
                       for m in poster.messages)
        await poster.group_send(gid, "@helperbot please help")
        assert await wait_for(lambda: any(
            m.get("group_id") == gid and m.get("from") == "helperbot"
            for m in poster.messages))
        greply = [m for m in poster.messages
                  if m.get("group_id") == gid
                  and m.get("from") == "helperbot"][0]
        assert (greply.get("meta") or {}).get("autonomous") is True
        await poster.close()
        await bot.close()
    run(_t())


def test_two_autonomous_agents_stop(relay_env, state_root):
    """(a) The ping-pong proof: two agents whose brains ALWAYS reply.
    An operator kickoff starts the exchange; the meta-marking +
    tightened consecutive cap must end it — bounded totals, then
    silence, with the cap trip logged on both sides."""

    async def always(ctx):
        if ctx["kind"] == "message":
            return "ack"
        return None

    async def _t():
        alpha = await make(relay_env, state_root, "alpha", brain=always)
        beta = await make(relay_env, state_root, "beta", brain=always)
        await beta.send_message("alpha", "ping")  # operator kickoff
        # alpha replies twice (cap vs autonomous peer = 2 after the
        # first exchange), beta replies twice, then both go quiet.
        ok = await wait_for(
            lambda: len([m for m in alpha.messages
                         if m.get("from") == "beta"]) >= 3
            and len([m for m in beta.messages
                     if m.get("from") == "alpha"]) >= 2,
            timeout=30)
        assert ok, (alpha.messages, beta.messages)
        a_count = len(alpha.messages)
        b_count = len(beta.messages)
        await asyncio.sleep(4.0)  # quiescence: nothing more arrives
        assert len(alpha.messages) == a_count
        assert len(beta.messages) == b_count
        total = a_count + b_count
        assert total <= 6  # kickoff + at most 2 replies each way + slack
        # Alpha received the final reply AT its cap and logged the
        # trip. Beta sits exactly at its cap too — prove it with one
        # more autonomous-marked probe: beta must log the cap and
        # stay silent.
        assert any(e["event"] == "capped_consecutive"
                   for e in alpha.autonomous_log)
        assert beta._auto_consec.get("dm:alpha") == \
            timing.AUTO_MAX_CONSECUTIVE_AUTO
        await alpha.send_message("beta", "ack",
                                 meta={"autonomous": True})
        assert await wait_for(lambda: any(
            e["event"] == "capped_consecutive"
            for e in beta.autonomous_log))
        await asyncio.sleep(3.0)
        assert len(alpha.messages) == a_count  # beta never answered it
        await alpha.close()
        await beta.close()
    run(_t())


def test_brain_silence_ends_exchange(relay_env, state_root):
    async def silent(ctx):
        return None

    async def _t():
        human = await make(relay_env, state_root, "asker", mode="manual")
        quiet = await make(relay_env, state_root, "quietone",
                           brain=silent)
        await human.send_message("quietone", "anyone there?")
        await asyncio.sleep(3.0)
        assert human.messages == []
        assert any(e["event"] == "brain_silent"
                   for e in quiet.autonomous_log)
        await human.close()
        await quiet.close()
    run(_t())


def test_no_brain_autonomous_is_silent_and_warns(relay_env, state_root):
    """No canned persona exists to fall back on: an autonomous agent
    with NO brain wired warns loudly at startup and then does
    NOTHING — no reply, no delivery, no decline chatter."""
    async def _t():
        human = await make(relay_env, state_root, "boss", mode="manual")
        hollow = await make(relay_env, state_root, "hollow")
        assert any(e["event"] == "no_brain_warning"
                   for e in hollow.autonomous_log)
        await human.send_message("hollow", "hello?")
        works = await human.assign_work(["hollow"], "Do a thing",
                                        instructions="please")
        wid = works[0]["id"]
        await asyncio.sleep(3.5)
        assert human.messages == []          # no reply, no decline DM
        assert human.work_updates == [] or all(
            w["status"] != "delivered" for w in human.work_updates)
        row = relay_env["relay"].store.get_work(wid)
        assert row["status"] == "assigned"   # untouched, honestly
        assert any(e["event"] == "work_no_brain"
                   for e in hollow.autonomous_log)
        await human.close()
        await hollow.close()
    run(_t())


def test_manual_agent_never_auto_replies(relay_env, state_root):
    """(d) Manual is the explicit opt-out: even WITH a brain wired, a
    manual agent's runtime never fires."""
    calls = []

    async def brain(ctx):
        calls.append(ctx)
        return "should never be sent"

    async def _t():
        human = await make(relay_env, state_root, "sender1",
                           mode="manual")
        manual = await make(relay_env, state_root, "manualbot",
                            mode="manual", brain=brain)
        await human.send_message("manualbot", "hello manual")
        works = await human.assign_work(["manualbot"], "Manual job",
                                        instructions="do it")
        await asyncio.sleep(3.5)
        assert human.messages == []
        assert calls == []  # the brain was never even consulted
        assert manual.autonomous_log == []
        row = relay_env["relay"].store.get_work(works[0]["id"])
        assert row["status"] == "assigned"
        await human.close()
        await manual.close()
    run(_t())


# ---------------------------------------------------------------------
# Autonomous work: round-trip + honest decline
# ---------------------------------------------------------------------

SHA256_HELLO_WORLD = \
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"


def test_autonomous_work_roundtrip(relay_env, state_root):
    """(b) Micro-work end-to-end: the brain computes a REAL sha256,
    reports progress, and delivers with a signed proof the relay
    verifies — no human touch anywhere in the loop."""
    outdir = state_root / "worker-out"
    outdir.mkdir(parents=True, exist_ok=True)

    async def brain(ctx):
        if ctx["kind"] != "work":
            return None
        work = ctx["work"]
        instr = work.get("instructions") or ""
        if "sha256" not in instr.lower():
            return {"decline": "not a hashing task"}
        text = instr.split("text:", 1)[1].strip()
        digest = hashlib.sha256(text.encode()).hexdigest()
        await ctx["report_progress"](50, "computing digest")
        path = outdir / f"digest-{work['id']}.txt"
        path.write_text(f"sha256({text}) = {digest}\n")
        return {"body": f"sha256 digest: {digest}", "files": [str(path)]}

    async def _t():
        boss = await make(relay_env, state_root, "chief", mode="manual")
        worker = await make(relay_env, state_root, "hashworker",
                            brain=brain, capabilities=["sha256"])
        works = await boss.assign_work(
            ["hashworker"], "Hash this",
            instructions="Please compute the sha256 of text: hello world")
        wid = works[0]["id"]
        assert await wait_for(
            lambda: any(w["id"] == wid and w["status"] == "delivered"
                        for w in boss.work_updates), timeout=20)
        row = relay_env["relay"].store.get_work(wid)
        assert row["status"] == "delivered"
        assert row["proof_verified"] == 1  # relay-verified signature
        inbox = await boss.work_inbox()
        mine = [w for w in inbox if w["id"] == wid][0]
        delivered_file = mine["deliveries"][0]["files"][0]
        from agentlink.protocol import file_bytes, verify_file
        assert verify_file(delivered_file)
        assert SHA256_HELLO_WORLD.encode() in \
            file_bytes(delivered_file)
        assert any(e["event"] == "work_delivered"
                   for e in worker.autonomous_log)
        await boss.close()
        await worker.close()
    run(_t())


def test_autonomous_work_decline_is_honest(relay_env, state_root):
    """(c) Out-of-scope work: the brain declines in its OWN words;
    the assigner receives exactly those words, and nothing is
    delivered — the work stays assigned, provably untouched."""
    DECLINE = ("I cannot bake bread: my wired skills are hashing "
               "only, and I will not pretend otherwise.")

    async def brain(ctx):
        if ctx["kind"] == "work":
            return {"decline": DECLINE}
        return None

    async def _t():
        boss = await make(relay_env, state_root, "patron", mode="manual")
        worker = await make(relay_env, state_root, "hasher2",
                            brain=brain, capabilities=["sha256"])
        works = await boss.assign_work(["hasher2"], "Bake bread",
                                       instructions="one loaf please")
        wid = works[0]["id"]
        assert await wait_for(lambda: any(
            m.get("from") == "hasher2" for m in boss.messages),
            timeout=20)
        note = [m for m in boss.messages
                if m.get("from") == "hasher2"][0]
        assert note["body"] == DECLINE  # the brain's words, verbatim
        row = relay_env["relay"].store.get_work(wid)
        assert row["status"] == "assigned"       # NOT delivered
        assert row["proof_verified"] == 0
        assert any(e["event"] == "work_declined"
                   for e in worker.autonomous_log)
        await boss.close()
        await worker.close()
    run(_t())
