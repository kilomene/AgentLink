"""v1.1.10 registration removal — self-deregister + operator removal.

Owner's standing rule (2026-11-02): after testing, ALWAYS delete
what the test created — scratch registrations are residue, and
cleanup is part of the test. These tests run the REAL chain (real
Agent clients -> real relay -> real store; the operator path runs
the real CLI against the relay's own DB file):

  * self-deregister removes the registration and its whole cascade
    (memberships, keys, reads, terminal work + deliveries), leaves
    other agents and shared spaces intact, and writes an audit
    record that survives the deletion;
  * the removal plan (dry run) counts match the executed counts;
  * a wrong secret can never even open the connection that would
    carry a deregister (hello is refused), and a deregister frame
    can only ever remove the AUTHENTICATED peer — never a username
    named in the frame;
  * self-deregister is refused while non-terminal work stands —
    live work is never orphaned (store level pins the queue and
    chain blockers too);
  * the operator command dry-runs without deleting, --confirm
    removes a secret-less orphan, refuses a live-heartbeat agent
    without --force, and audit-records the removal (via=operator);
  * the local-home wipe is opt-in only.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
from pathlib import Path

import pytest

from agentlink import cli
from agentlink.client import Agent, RegistrationFailed, RequestFailed
from agentlink.relay import Relay
from agentlink.store import RemovalBlocked, Store

HOST = "127.0.0.1"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-dereg-")
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
           "db": db, "relay": relay, "store": relay.store}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-dereg-agents-") as tmp:
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


def test_self_deregister_cascade_and_audit(relay_env, state_root):
    async def _go():
        store = relay_env["store"]
        boss = await make(relay_env, state_root, "boss")
        scratch = await make(relay_env, state_root, "scratch")
        got = []

        @scratch.on_message
        async def _h(frame):
            got.append(frame)

        # Membership + wrapped key rows for scratch.
        g = await boss.group_create("cleanup crew", ["scratch"])
        gid = g["group_id"]
        assert await wait_for(
            lambda: store.group_key_for(gid, "scratch") is not None)

        # A DM boss -> scratch, taken in by scratch's handler
        # (auto-read): a message_reads row with reader=scratch.
        await boss.send_message("scratch", "welcome aboard")
        assert await wait_for(lambda: len(got) == 1)
        assert await wait_for(
            lambda: store.reads_for([got[0]["id"]]).get(got[0]["id"]))

        # Terminal work history: assigned -> delivered -> completed.
        works = await boss.assign_work(["scratch"], "tidy up",
                                       "make it neat")
        wid = works[0]["id"]
        await scratch.deliver_work(wid, "all tidy")
        await boss.complete_work(wid)
        assert store.get_work(wid)["status"] == "completed"

        # Plan (dry run) must equal the execution, count for count.
        plan = store.removal_plan("scratch")
        assert plan["exists"] and plan["blockers"] == []
        assert plan["remove"]["users"] == 1
        assert plan["remove"]["group_members"] == 1
        assert plan["remove"]["group_keys"] >= 1
        assert plan["remove"]["work"] == 1
        assert plan["remove"]["work_deliveries"] == 1
        assert plan["remove"]["message_reads"] >= 1

        result = await scratch.deregister()
        assert result["removed"] == plan["remove"], (
            result["removed"], plan["remove"])
        assert result["total"] == sum(plan["remove"].values())

        # Directory + presence clean; boss untouched; group survives
        # without scratch; terminal work history went with it.
        assert not store.exists("scratch")
        names = [u["username"] for u in await boss.directory()]
        assert "scratch" not in names and "boss" in names
        assert [m["username"] for m in store.members(gid)] == ["boss"]
        assert store.get_work(wid) is None

        # The audit record of the removal SURVIVES the deletion.
        rows = [a for a in store.list_audit(50)
                if a["kind"] == "user_removed"]
        assert len(rows) == 1
        assert rows[0]["from"] == "scratch"
        assert rows[0]["to"] == "scratch"
        assert rows[0]["status"].startswith("via=self;rows=")
        await boss.close()
    run(_go())


def test_deregister_frame_only_removes_the_authenticated_peer(
        relay_env, state_root):
    """A deregister frame naming ANOTHER username still removes
    only the connection's own authenticated identity — the frame
    carries no target the relay would honour."""
    async def _go():
        store = relay_env["store"]
        actor = await make(relay_env, state_root, "actor")
        await make(relay_env, state_root, "bystander")
        # The SDK request path, with a hostile extra field.
        await actor._request({"type": "deregister",
                              "username": "bystander"})
        assert not store.exists("actor")
        assert store.exists("bystander")
        await actor.close()
    run(_go())


def test_wrong_secret_cannot_connect(relay_env, state_root):
    """Deregistration rides the hello-authenticated connection; a
    wrong secret is refused at hello, so no frame is ever carried,
    and the real registration is untouched."""
    async def _go():
        store = relay_env["store"]
        victim = await make(relay_env, state_root, "victim")
        await victim.close()
        # Fresh state dir, same username: no saved secret -> claim
        # attempt against an existing name -> refused.
        impostor_dir = state_root / "impostor"
        bad = Agent("victim", endpoint=relay_env["url"],
                    state_dir=str(impostor_dir))
        with pytest.raises(RegistrationFailed):
            await bad.start()
        # A forged secret file fares no better.
        forged = state_root / "forged"
        forged.mkdir(parents=True, exist_ok=True)
        (forged / "secret-victim.json").write_text(json.dumps(
            {"username": "victim", "secret": "not-the-secret"}))
        bad2 = Agent("victim", endpoint=relay_env["url"],
                     state_dir=str(forged))
        with pytest.raises(RegistrationFailed):
            await bad2.start()
        assert store.exists("victim")
        # The real owner still connects with its own secret.
        again = await make(relay_env, state_root, "victim")
        await again.close()
    run(_go())


def test_self_deregister_blocked_by_live_work(relay_env, state_root):
    async def _go():
        store = relay_env["store"]
        boss = await make(relay_env, state_root, "boss2")
        stuck = await make(relay_env, state_root, "stuck")
        works = await boss.assign_work(["stuck"], "open item",
                                       "still running")
        wid = works[0]["id"]
        with pytest.raises(RequestFailed) as ei:
            await stuck.deregister()
        assert ei.value.reason == "deregister_blocked"
        assert "non-terminal work" in ei.value.detail
        assert store.exists("stuck")
        # Finish the work properly; the exit door opens.
        await stuck.deliver_work(wid, "done now")
        await boss.complete_work(wid)
        result = await stuck.deregister()
        assert result["removed"]["users"] == 1
        assert not store.exists("stuck")
        await boss.close()
    run(_go())


def test_store_blockers_queue_and_terminal_history(tmp_path):
    """Store level: the offline queue blocks; terminal history does
    not (it is deleted WITH the registration once the queue is
    drained by other means)."""
    s = Store(str(tmp_path / "r.db"))
    s.claim("carol", "C")
    s.claim("dave", "D")
    w = s.create_work("carol", "dave", None, {"e": 1}, {"s": 1}, None)
    s.set_work_status(w["id"], "delivered")
    s.set_work_status(w["id"], "completed")
    s.enqueue("dave", {"type": "message", "body": "waiting"})
    blockers = s.removal_blockers("dave")
    assert any("undelivered" in b for b in blockers)
    with pytest.raises(RemovalBlocked):
        s.remove_user("dave")
    assert s.exists("dave")
    s.dequeue_all("dave")  # the frames were delivered after all
    out = s.remove_user("dave")
    assert out["removed"]["work"] == 1
    assert out["removed"]["users"] == 1
    assert not s.exists("dave")
    assert s.get_work(w["id"]) is None


def test_operator_cli_dry_run_confirm_and_online_guard(
        relay_env, state_root, capsys):
    store = relay_env["store"]
    db = relay_env["db"]
    # A secret-less orphan: claimed straight into the store, never
    # connected, owns a group membership row.
    store.claim("orphan", "Orphan")
    store.claim("keeper", "Keeper")
    gid = store.create_group("ops room", "keeper", None)
    store.add_member(gid, "orphan")

    rc = cli.main(["remove-user", "@orphan", "--db", db])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"group_members": 1' in out
    assert "dry run" in out
    assert store.exists("orphan")  # nothing removed

    rc = cli.main(["remove-user", "orphan", "--db", db, "--confirm"])
    out = capsys.readouterr().out
    assert rc == 0
    assert '"removed"' in out
    assert not store.exists("orphan")
    assert [m["username"] for m in store.members(gid)] == ["keeper"]
    rows = [a for a in store.list_audit(50)
            if a["kind"] == "user_removed" and a["to"] == "orphan"]
    assert len(rows) == 1
    assert rows[0]["from"] == "operator"
    assert rows[0]["status"].startswith("via=operator;rows=")

    # Unknown registration: a clean refusal, exit 2.
    rc = cli.main(["remove-user", "ghost", "--db", db, "--confirm"])
    capsys.readouterr()
    assert rc == 2

    # A live-heartbeat agent is refused without --force.
    store.claim("liveone", "Live")
    store.touch("liveone")
    rc = cli.main(["remove-user", "liveone", "--db", db, "--confirm"])
    capsys.readouterr()
    assert rc == 2
    assert store.exists("liveone")
    rc = cli.main(["remove-user", "liveone", "--db", db,
                   "--confirm", "--force"])
    capsys.readouterr()
    assert rc == 0
    assert not store.exists("liveone")


def test_wipe_local_is_opt_in(relay_env, state_root):
    async def _go():
        keeper = await make(relay_env, state_root, "wipesafe")
        home = state_root / "wipesafe"
        assert (home / "secret-wipesafe.json").exists()
        await keeper.deregister()  # default: home files stay
        assert (home / "secret-wipesafe.json").exists()
        assert (home / "keys-wipesafe.json").exists()

        wiper = await make(relay_env, state_root, "wiper")
        home2 = state_root / "wiper"
        assert (home2 / "secret-wiper.json").exists()
        await wiper.deregister(wipe_local=True)
        assert not (home2 / "secret-wiper.json").exists()
        assert not (home2 / "keys-wiper.json").exists()
        assert not (home2 / f"tasks-wiper.db").exists()
    run(_go())


def test_cli_deregister_round_trip(relay_env, state_root, capsys):
    """The shipped CLI command, end to end: register a scratch
    agent, deregister it via `agentlink deregister`, and the
    registration is gone — the test-hygiene path itself."""
    async def _register():
        a = await make(relay_env, state_root, "cliscratch")
        await a.close()
    run(_register())
    assert relay_env["store"].exists("cliscratch")
    rc = cli.main(["deregister", "--username", "cliscratch",
                   "--endpoint", relay_env["url"],
                   "--state-dir", str(state_root / "cliscratch")])
    out = capsys.readouterr().out
    assert rc == 0, out
    assert '"users": 1' in out
    assert not relay_env["store"].exists("cliscratch")
