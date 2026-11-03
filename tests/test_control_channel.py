"""Owner-seat control channel pins (v1.3.9, WS4).

The friction: one-shot operator commands as the owner's seat
(agentlink send, group add) died with instance_collision while
the seat's daemon was running; the only workaround was stopping
the daemon — unacceptable for the owner's own seat.

The cure pinned here: the lock-holding daemon serves a control
channel (Unix socket in the state dir, per-boot token advertised
in the lock file); a one-shot command that meets the lock
FORWARDS to the running instance, which executes it as itself
and returns the real result. Forwarding refuses foreign lock
holders, names dead holders (ordinary lock rules then apply),
names pre-channel daemons, and fails closed on a wedged holder.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import pytest

from agentlink.client import (Agent, ControlForwardError,
                              forward_command)
from agentlink.relay import Relay

HOST = "127.0.0.1"
REPO = Path(__file__).resolve().parent.parent


class RelayHandle:
    def __init__(self, db, name):
        self.db = db
        self.name = name
        self.relay = None
        self.loop = None
        self.thread = None
        self.port = 0
        self.dash_port = 0

    def start(self):
        self.relay = Relay(host=HOST, port=self.port, db_path=self.db,
                           server_name=self.name,
                           dashboard_password="test-password",
                           dashboard_port=self.dash_port)
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
        assert ready.wait(timeout=10)
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


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


async def wait_for(pred, timeout=20.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-cc-agents-") as tmp:
        yield Path(tmp)


def _lock_meta(state_dir, username):
    return json.loads(
        (Path(state_dir) / f"instance-{username}.lock").read_text())


def test_forward_send_and_group_add_through_daemon(state_root):
    """Daemon running: a forwarded send lands with a real id (the
    recipient receives it), a forwarded group add lands, and the
    daemon is never restarted (same pid throughout)."""
    tmp = tempfile.mkdtemp(prefix="agentlink-cc-")
    h = RelayHandle(str(Path(tmp) / "relay.db"), "cc-relay")
    url = h.start()
    seat_dir = str(state_root / "seat")

    async def _t():
        daemon = Agent("ccseat", endpoint=url, state_dir=seat_dir)
        await daemon.start()
        other = Agent("ccother", endpoint=url,
                      state_dir=str(state_root / "ccother"))
        await other.start()
        got = []

        @other.on_message
        async def _om(frame):
            got.append(frame)
        try:
            meta = _lock_meta(seat_dir, "ccseat")
            assert meta["pid"] == os.getpid()
            assert meta["control"]["socket"].endswith(
                "control-ccseat.sock")
            res = await forward_command(
                seat_dir, "ccseat",
                {"cmd": "send", "to": "ccother",
                 "body": "through the daemon", "priority": "normal"})
            assert res and res.get("id"), res
            assert await wait_for(lambda: len(got) == 1)
            assert got[0]["body"] == "through the daemon"
            assert got[0]["from"] == "ccseat"
            g = await daemon.group_create("cc-group", [])
            gid = g["group_id"]
            res2 = await forward_command(
                seat_dir, "ccseat",
                {"cmd": "group_add", "group_id": gid,
                 "members": ["ccother"]})
            members = await daemon.group_members(gid)
            names = [m["username"] for m in
                     (members["members"] if isinstance(members, dict)
                      else members)]
            assert "ccother" in names
            # The daemon never restarted: same lock, same pid.
            assert _lock_meta(seat_dir, "ccseat")["pid"] == \
                meta["pid"]
        finally:
            try:
                await other.close()
            except Exception:
                pass
            await daemon.close()

    run(_t())
    h.stop()


def test_cli_send_forwards_with_daemon_running(state_root):
    """The literal owner-seat shape: the real CLI, one-shot, while
    a daemon holds the seat's state dir. Exit 0, the result is
    marked forwarded, and the message really lands."""
    tmp = tempfile.mkdtemp(prefix="agentlink-cc-")
    h = RelayHandle(str(Path(tmp) / "relay.db"), "cc-cli-relay")
    url = h.start()
    seat_dir = str(state_root / "seat")

    async def _t():
        daemon = Agent("ccseat2", endpoint=url, state_dir=seat_dir)
        await daemon.start()
        other = Agent("ccother2", endpoint=url,
                      state_dir=str(state_root / "ccother2"))
        await other.start()
        got = []

        @other.on_message
        async def _om(frame):
            got.append(frame)
        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-m", "agentlink.cli", "send",
                "ccother2", "cli through the daemon",
                "--username", "ccseat2", "--state-dir", seat_dir,
                "--endpoint", url,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(REPO))
            out, err = await asyncio.wait_for(
                proc.communicate(), timeout=30)
            assert proc.returncode == 0, err.decode()
            payload = json.loads(out.decode())
            assert payload["forwarded_via"] == "running instance"
            assert payload["result"]["id"]
            assert await wait_for(lambda: len(got) == 1)
            assert got[0]["body"] == "cli through the daemon"
        finally:
            try:
                await other.close()
            except Exception:
                pass
            await daemon.close()

    run(_t())
    h.stop()


def test_forward_refuses_foreign_holder(state_root):
    """The lock file names a DIFFERENT identity: forwarding is
    refused outright, nothing is sent anywhere."""
    d = state_root / "foreign"
    d.mkdir(parents=True)
    (d / "instance-myseat.lock").write_text(json.dumps({
        "pid": os.getpid(), "username": "someoneelse",
        "endpoint": "ws://127.0.0.1:1/ws", "since": 0,
        "control": {"socket": str(d / "control-someoneelse.sock"),
                    "token": "irrelevant"}}))

    async def _t():
        with pytest.raises(ControlForwardError) as ei:
            await forward_command(str(d), "myseat", {"cmd": "ping"})
        assert "someoneelse" in str(ei.value)

    run(_t())


def test_dead_holder_named_then_lock_rules_apply(state_root):
    """A dead holder is named by the forward path; afterwards the
    ordinary lock rules apply — a fresh Agent claims the state dir
    through the flock the kernel released at the holder's death."""
    tmp = tempfile.mkdtemp(prefix="agentlink-cc-")
    h = RelayHandle(str(Path(tmp) / "relay.db"), "cc-dead-relay")
    url = h.start()
    seat_dir = str(state_root / "seat")

    async def _t():
        daemon = Agent("ccseat3", endpoint=url, state_dir=seat_dir)
        await daemon.start()
        await daemon.close()
        # The lock FILE (with its now-stale control advertisement)
        # survives close() — its holder pid is this process, so
        # rewrite it with a provably dead pid: a reaped child.
        proc = subprocess.Popen([sys.executable, "-c", "pass"])
        proc.wait()
        meta = _lock_meta(seat_dir, "ccseat3")
        meta["pid"] = proc.pid
        (Path(seat_dir) / "instance-ccseat3.lock").write_text(
            json.dumps(meta))
        with pytest.raises(ControlForwardError) as ei:
            await forward_command(seat_dir, "ccseat3",
                                  {"cmd": "ping"})
        assert "not alive" in str(ei.value)
        # Ordinary lock rules: a fresh instance starts cleanly.
        fresh = Agent("ccseat3", endpoint=url, state_dir=seat_dir)
        await fresh.start()
        await fresh.close()

    run(_t())
    h.stop()


def test_wedged_holder_fails_closed(state_root):
    """A holder whose socket accepts but never answers: the
    forward times out with a named 'wedged' error — no rival
    instance is started, no silent success."""
    d = state_root / "wedged"
    d.mkdir(parents=True)
    sock = d / "control-wseat.sock"

    async def _t():
        async def _blackhole(reader, writer):
            await asyncio.sleep(8)

        server = await asyncio.start_unix_server(_blackhole,
                                                 path=str(sock))
        (d / "instance-wseat.lock").write_text(json.dumps({
            "pid": os.getpid(), "username": "wseat",
            "endpoint": "ws://127.0.0.1:1/ws", "since": 0,
            "control": {"socket": str(sock), "token": "tok123"}}))
        try:
            with pytest.raises(ControlForwardError) as ei:
                await forward_command(str(d), "wseat",
                                      {"cmd": "ping"}, timeout=1.5)
            assert "wedged" in str(ei.value)
        finally:
            server.close()

    run(_t())


def test_pre_channel_daemon_named(state_root):
    """A lock with NO control advertisement (a pre-v1.3.9 daemon):
    the error names the condition and the one-time remedy."""
    d = state_root / "old"
    d.mkdir(parents=True)
    (d / "instance-oldseat.lock").write_text(json.dumps({
        "pid": os.getpid(), "username": "oldseat",
        "endpoint": "ws://127.0.0.1:1/ws", "since": 0}))

    async def _t():
        with pytest.raises(ControlForwardError) as ei:
            await forward_command(str(d), "oldseat", {"cmd": "ping"})
        assert "predates v1.3.9" in str(ei.value)

    run(_t())
