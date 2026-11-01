"""End-to-end tests for AgentLink.

Everything runs against a REAL relay on 127.0.0.1 with REAL websocket
clients. No mocks. If these pass, the system works.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sys
import tempfile
import threading
from pathlib import Path

import pytest
from websockets.client import connect

from agentlink.client import Agent, RegistrationFailed, RequestFailed, dial
from agentlink.protocol import file_bytes, normalize_username, verify_file
from agentlink.relay import Relay

HOST = "127.0.0.1"


@pytest.fixture()
def relay_url():
    tmp = tempfile.mkdtemp(prefix="agentlink-test-")
    relay = Relay(host=HOST, port=0, db_path=str(Path(tmp) / "relay.db"),
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
    assert ready.wait(timeout=10), "relay did not start"
    yield f"ws://{HOST}:{relay.port}"
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=30))


async def make_agent(relay_url, state_root, username, **kw):
    a = Agent(username, endpoint=relay_url,
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=5.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


# -- identity ---------------------------------------------------------------

def test_username_normalisation():
    assert normalize_username("@Phoenix") == "phoenix"
    assert normalize_username("agent-two") == "agent-two"
    assert normalize_username("@Agent_Two.1") == "agent_two.1"
    assert normalize_username("x") is None          # too short
    assert normalize_username("bad name!") is None
    assert normalize_username(None) is None


def test_claim_conflict_and_secret_reclaim(relay_url, state_root):
    async def _t():
        a = await make_agent(relay_url, state_root, "phoenix")
        secret_file = state_root / "phoenix" / "secret-phoenix.json"
        assert secret_file.exists()
        assert (secret_file.stat().st_mode & 0o777) == 0o600
        await a.close()

        # Same username, different state dir (no secret) -> rejected.
        thief = Agent("phoenix", endpoint=relay_url,
                      state_dir=str(state_root / "thief"))
        with pytest.raises(RegistrationFailed):
            await thief.start()

        # Owner reclaims with the saved secret.
        b = await make_agent(relay_url, state_root, "phoenix")
        assert b.username == "phoenix"
        await b.close()

        # Raw protocol check: wrong secret is refused too.
        async with connect(relay_url) as ws:
            await ws.send(json.dumps(
                {"type": "hello", "username": "phoenix",
                 "display_name": "x", "secret": "wrong", "ephemeral": False}))
            frame = json.loads(await ws.recv())
            assert frame["type"] == "error"
            assert frame["reason"] == "username_taken"
    run(_t())


# -- 1:1 messaging -------------------------------------------------------------

def test_text_round_trip_with_reply_correlation(relay_url, state_root):
    async def _t():
        bob = await make_agent(relay_url, state_root, "bob")

        @bob.on_message
        async def _reply(msg):
            return f"roger {msg['body']}"

        alice = await make_agent(relay_url, state_root, "alice")
        sent = await alice.send_message("bob", "hello bob")
        reply = await alice.wait_reply(sent["id"], timeout=10)
        assert reply["body"] == "roger hello bob"
        assert reply["from"] == "bob"
        assert bob.messages[0]["body"] == "hello bob"
        assert bob.messages[0]["from"] == "alice"
        await alice.close()
        await bob.close()
    run(_t())


@pytest.mark.parametrize("kind,ext,blob", [
    ("image", ".png", b"\x89PNG-fake-image-bytes"),
    ("video", ".mp4", b"\x00\x00\x00\x18ftypmp42-fake-video"),
    ("voice", ".ogg", b"OggS-fake-voice-note"),
    ("file", ".bin", bytes(range(256)) * 4),
])
def test_file_round_trip_hash_verified(relay_url, state_root, tmp_path,
                                       kind, ext, blob):
    async def _t():
        path = tmp_path / f"payload{ext}"
        path.write_bytes(blob)
        bob = await make_agent(relay_url, state_root, "bob")
        alice = await make_agent(relay_url, state_root, "alice")
        await alice.send_file("bob", str(path), caption="here", kind=kind)
        assert await wait_for(lambda: len(bob.messages) == 1)
        f = bob.messages[0]["file"]
        assert f["kind"] == kind
        assert verify_file(f)
        assert hashlib.sha256(file_bytes(f)).hexdigest() == f["sha256"]
        assert file_bytes(f) == blob
        await alice.close()
        await bob.close()
    run(_t())


def test_offline_queue_flush_on_reconnect(relay_url, state_root):
    async def _t():
        bob = await make_agent(relay_url, state_root, "bob")
        await bob.close()
        await asyncio.sleep(0.2)

        alice = await make_agent(relay_url, state_root, "alice")
        res = await alice.send_message("@bob", "you were away")
        assert res["queued"] is True
        await alice.close()

        bob2 = await make_agent(relay_url, state_root, "bob")
        assert await wait_for(lambda: len(bob2.messages) == 1)
        assert bob2.messages[0]["body"] == "you were away"
        assert bob2.messages[0]["delivery_status"] == "queued"
        await bob2.close()
    run(_t())


def test_dial_one_shot(relay_url, state_root):
    async def _t():
        bob = await make_agent(relay_url, state_root, "bob")

        @bob.on_message
        async def _reply(msg):
            return f"echo:{msg['body']}"

        reply = await dial(relay_url, "bob", "knock", timeout=10,
                           state_dir=str(state_root / "dialer"))
        assert reply == "echo:knock"
        await bob.close()
    run(_t())


# -- groups -----------------------------------------------------------------------

async def _three(relay_url, state_root):
    return (
        await make_agent(relay_url, state_root, "agent-one"),
        await make_agent(relay_url, state_root, "agent-two"),
        await make_agent(relay_url, state_root, "agent-three"),
    )


def test_group_add_without_accept(relay_url, state_root):
    async def _t():
        one, two, three = await _three(relay_url, state_root)
        g = await one.group_create("Team", ["agent-two", "agent-three"])
        gid = g["group_id"]
        # Added agents find themselves in the group: membership event,
        # no accept step anywhere.
        assert await wait_for(lambda: len(two.group_events) >= 1)
        ev = two.group_events[0]
        assert ev["event"] == "added_to_group"
        assert ev["group_id"] == gid
        members = await two.group_members(gid)
        assert {m["username"] for m in members["members"]} == \
            {"agent-one", "agent-two", "agent-three"}
        roles = {m["username"]: m["role"] for m in members["members"]}
        assert roles["agent-one"] == "superadmin"

        # An added member can read/send immediately.
        await two.group_send(gid, "hi from two")
        assert await wait_for(
            lambda: any(m.get("group_id") == gid for m in one.messages))
        assert await wait_for(
            lambda: any(m.get("group_id") == gid for m in three.messages))
        for a in (one, two, three):
            await a.close()
    run(_t())


def test_group_invite_link_join(relay_url, state_root):
    async def _t():
        one, two, three = await _three(relay_url, state_root)
        g = await one.group_create("InviteOnly", [])
        gid = g["group_id"]
        link = await one.group_join_link(gid)
        assert link["link"].startswith("agentlink://join/")
        joined = await three.group_join(link["link"])
        assert joined["group_id"] == gid
        members = await one.group_members(gid)
        assert "agent-three" in {m["username"] for m in members["members"]}
        # Bad token is refused.
        with pytest.raises(RequestFailed) as ei:
            await two.group_join("bogus-token", group_id=gid)
        assert ei.value.reason == "invalid_invite"
        for a in (one, two, three):
            await a.close()
    run(_t())


def test_group_permissions_enforced(relay_url, state_root):
    async def _t():
        one, two, three = await _three(relay_url, state_root)
        g = await one.group_create("Perms", ["agent-two", "agent-three"])
        gid = g["group_id"]

        # A plain member cannot remove or promote.
        with pytest.raises(RequestFailed) as ei:
            await two.group_remove(gid, "agent-three")
        assert ei.value.reason == "permission_denied"
        with pytest.raises(RequestFailed) as ei:
            await two.group_promote(gid, "agent-two")
        assert ei.value.reason == "permission_denied"

        # Admin sets admins-only sending; members are then blocked,
        # admins are not.
        await one.group_settings(gid, {"send_messages": "admins_only"})
        with pytest.raises(RequestFailed) as ei:
            await two.group_send(gid, "should be blocked")
        # Point 43e: the agent's local gate fires first once the live
        # settings event lands; the server enforces the same rule
        # (reason "permission_denied") for clients without the view.
        assert ei.value.reason in ("permission_denied",
                                   "permission_denied_local")
        await one.group_send(gid, "admin speaking")

        # Superadmin promotes two to admin; two can now send and can
        # remove a plain member, but cannot remove another admin and
        # nobody can remove the creator.
        await one.group_promote(gid, "agent-two")
        await two.group_send(gid, "now I can speak")
        await two.group_remove(gid, "agent-three")
        members = await one.group_members(gid)
        assert "agent-three" not in {m["username"] for m in members["members"]}
        with pytest.raises(RequestFailed):
            await two.group_remove(gid, "agent-one")
        for a in (one, two, three):
            await a.close()
    run(_t())


# -- work ---------------------------------------------------------------------------

def test_work_group_assign_deliver_complete(relay_url, state_root, tmp_path):
    async def _t():
        one, two, three = await _three(relay_url, state_root)
        g = await one.group_create("WorkTeam", ["agent-two", "agent-three"])
        gid = g["group_id"]

        delivered = tmp_path / "collated.txt"
        delivered.write_text("collated research results")

        seen_work = []

        @two.on_work
        async def _do(work):
            seen_work.append(work)
            await two.deliver_work(work["id"], "collation done",
                                   files=[str(delivered)])

        works = await one.assign_work(
            ["agent-two"], "Collate the research",
            instructions="Gather everything into one file", group_id=gid)
        assert len(works) == 1
        wid = works[0]["id"]
        assert works[0]["status"] == "assigned"

        # Assignee receives it autonomously through the same line.
        assert await wait_for(lambda: len(seen_work) == 1)
        assert seen_work[0]["title"] == "Collate the research"
        # Delivery flows back to the assigner as a work_update.
        assert await wait_for(
            lambda: any(w["id"] == wid and w["status"] == "delivered"
                        for w in one.work_updates))
        inbox = await one.work_inbox()
        mine = [w for w in inbox if w["id"] == wid][0]
        assert mine["status"] == "delivered"
        assert len(mine["deliveries"]) == 1
        f = mine["deliveries"][0]["files"][0]
        assert verify_file(f)
        assert file_bytes(f) == b"collated research results"

        done = await one.complete_work(wid, note="great")
        assert done["status"] == "completed"
        for a in (one, two, three):
            await a.close()
    run(_t())


def test_work_direct_and_changes_requested(relay_url, state_root):
    async def _t():
        alice = await make_agent(relay_url, state_root, "alice")
        bob = await make_agent(relay_url, state_root, "bob")
        works = await alice.assign_work(["bob"], "Research X",
                                        instructions="Find facts")
        wid = works[0]["id"]
        assert await wait_for(lambda: len(bob.assigned_work) == 1)

        # Only the assignee can deliver.
        with pytest.raises(RequestFailed):
            await alice.deliver_work(wid, "not mine to deliver")

        await bob.deliver_work(wid, "first draft")
        inbox = await bob.work_inbox()
        assert [w for w in inbox if w["id"] == wid][0]["status"] == "delivered"

        changed = await alice.request_changes(wid, note="add sources")
        assert changed["status"] == "changes_requested"

        # Re-delivery is allowed after changes are requested.
        await bob.deliver_work(wid, "second draft with sources")
        done = await alice.complete_work(wid)
        assert done["status"] == "completed"

        # Terminal: no further delivery.
        with pytest.raises(RequestFailed):
            await bob.deliver_work(wid, "too late")
        await alice.close()
        await bob.close()
    run(_t())


def test_directory_and_presence(relay_url, state_root):
    async def _t():
        alice = await make_agent(relay_url, state_root, "alice")
        bob = await make_agent(relay_url, state_root, "bob")
        await bob.close()
        await asyncio.sleep(0.2)
        users = {u["username"]: u for u in await alice.directory()}
        assert users["alice"]["online"] is True
        assert users["bob"]["online"] is False
        await alice.close()
    run(_t())


def test_work_offline_assignee_gets_assignment_on_reconnect(relay_url,
                                                            state_root):
    async def _t():
        alice = await make_agent(relay_url, state_root, "alice")
        bob = await make_agent(relay_url, state_root, "bob")
        await bob.close()
        await asyncio.sleep(0.2)
        await alice.assign_work(["bob"], "Offline job", instructions="queued")
        await alice.close()
        bob2 = await make_agent(relay_url, state_root, "bob")
        assert await wait_for(lambda: len(bob2.assigned_work) == 1)
        assert bob2.assigned_work[0]["title"] == "Offline job"
        await bob2.close()
    run(_t())


def test_cli_subprocess_register_send_dial(relay_url, state_root, tmp_path):
    """Real CLI subprocesses against the live relay."""
    import subprocess

    env_state = str(state_root / "cli-bob")

    async def _setup():
        bob = await make_agent(relay_url, state_root, "clibob")

        @bob.on_message
        async def _reply(msg):
            return f"cli-echo:{msg['body']}"
        return bob

    async def _t():
        bob = await _setup()
        proc = await asyncio.create_subprocess_exec(
            sys.executable, "-m", "agentlink", "dial",
            "--endpoint", relay_url, "--state-dir", env_state,
            "clibob", "hello cli",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await asyncio.wait_for(proc.communicate(), timeout=20)
        assert proc.returncode == 0, err.decode()
        assert out.decode().strip() == "cli-echo:hello cli"
        await bob.close()
    run(_t())
