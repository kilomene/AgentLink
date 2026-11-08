"""2.2.3 — the already-registered fast path (@lean's loop).

The defect: a support hook's post-fix setup retry re-ran setup
while the agent's own daemon was already running. Setup met
the instance lock, raised instance_collision, and the hook
counted a working, registered agent as a failed retry —
lodging follow-up tickets until its attempt budget ran out.

The fix pinned here, at every layer:

* client.instance_lock_holder witnesses a LIVE holder of my
  own lock (foreign / dead / missing are all None),
* the control channel answers `whoami` (the daemon's own
  recovery-held / grant truth, no secret crosses),
* setup._prove_already_running measures every conjunct and
  fails closed,
* run_setup treats a proven collision as registered success
  (through the running instance — no rival start, no service
  install fight, no grant re-ask), and a failed proof stays
  terminal with the check's conjuncts IN the failure,
* the verify-failure support error names EVERY ok conjunct
  (registered / recovery_present included — the hidden-
  conjunct defect behind the @lean / @agent-2eb7 tickets),
* the support hook retires as REGISTERED only when the proof
  is PROVEN (registered AND running AND a recovery key held
  somewhere — setup's own ok bar, so the stranded state that
  lodged the original ticket can never be retired as success):
  no attempt burned, no follow-up.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from agentlink import client as client_mod
from agentlink import setup as setup_mod
from agentlink import support_hook
from agentlink.client import InstanceCollision, instance_lock_holder


# -- instance_lock_holder ---------------------------------------------

def _write_lock(sd: Path, username: str, pid: int,
                holder_name: str | None = None):
    sd.mkdir(parents=True, exist_ok=True)
    (sd / f"instance-{username}.lock").write_text(json.dumps(
        {"pid": pid, "username": holder_name or username,
         "endpoint": "x", "since": 1}))


def test_lock_holder_live_is_witnessed(tmp_path):
    _write_lock(tmp_path, "lean", os.getpid())
    holder = instance_lock_holder(tmp_path, "lean")
    assert holder is not None and holder["pid"] == os.getpid()


def test_lock_holder_dead_pid_is_none(tmp_path):
    import subprocess
    import sys
    proc = subprocess.Popen([sys.executable, "-c", "pass"])
    proc.wait(timeout=10)
    _write_lock(tmp_path, "lean", proc.pid)
    assert instance_lock_holder(tmp_path, "lean") is None


def test_lock_holder_foreign_or_missing_is_none(tmp_path):
    _write_lock(tmp_path, "lean", os.getpid(), holder_name="other")
    assert instance_lock_holder(tmp_path, "lean") is None
    assert instance_lock_holder(tmp_path, "ghost") is None


# -- the proof ----------------------------------------------------------

class _Doorbell:
    def __init__(self, presence):
        self._presence = presence

    def read_presence(self, username):
        return self._presence


class _Transport:
    def __init__(self, presence):
        self.doorbell = _Doorbell(presence)


class StubAgent:
    """The rival-process Agent setup builds: never started, but
    carrying the identity / recovery / transport seams the
    proof reads."""

    def __init__(self, uname, sd, recovery="key-123",
                 presence=None):
        self.username = uname
        self.identity = object()
        self.recovery_file = None
        self._recovery = recovery
        self._presence = {"state": "online", "ts": 1} \
            if presence is None else presence

    def _find_recovery_key(self):
        return self._recovery

    def _recovery_workspace_path(self):
        return Path("/nonexistent/agentlink-recovery-x.txt")

    def _make_v2_transport(self):
        return _Transport(self._presence)


def _fake_forward_factory(whoami_extra=None, fail_ping=False,
                          fail_presence=False):
    calls = []

    async def fake_forward(state_dir, username, spec, timeout=20.0):
        calls.append(spec["cmd"])
        if spec["cmd"] == "ping":
            if fail_ping:
                raise client_mod.ControlForwardError("wedged")
            return {"username": username, "pid": os.getpid(),
                    "endpoint": "x"}
        if spec["cmd"] == "presence" and fail_presence:
            raise client_mod.ControlForwardError("no v2")
        if spec["cmd"] == "whoami":
            out = {"username": username, "recovery_key_held": True,
                   "recovery_file": "/ws/agentlink-recovery-x.txt",
                   "grant": {"status": "allowed"}}
            out.update(whoami_extra or {})
            return out
        if spec["cmd"] == "directory":
            return [{"username": username,
                     "capabilities": ["internet", "files"]}]
        if spec["cmd"] == "presence":
            return {"state": "online", "ts": 1}
        raise AssertionError(spec)

    return fake_forward, calls


@pytest.fixture
def live_holder(monkeypatch, tmp_path):
    _write_lock(tmp_path, "lean", os.getpid())
    monkeypatch.setattr(
        client_mod, "instance_lock_holder",
        lambda sd, u: {"pid": os.getpid(), "username": u,
                       "since": 7})


def test_proof_all_conjuncts_proven(monkeypatch, tmp_path, live_holder):
    (tmp_path / "keys-lean.json").write_text("{}")
    fake, calls = _fake_forward_factory()
    monkeypatch.setattr(client_mod, "forward_command", fake)
    agent = StubAgent("lean", tmp_path)
    proof = asyncio.run(
        setup_mod._prove_already_running(agent, tmp_path, "lean"))
    assert proof["registered"] is True
    assert proof["proven"] is True
    assert proof["presence_online"] is True
    assert proof["directory_finds_me"] is True
    assert proof["capabilities"] == ["internet", "files"]
    assert calls == ["ping", "whoami", "directory", "presence"]


def test_proof_fails_closed_without_holder(monkeypatch, tmp_path):
    monkeypatch.setattr(client_mod, "instance_lock_holder",
                        lambda sd, u: None)
    fake, calls = _fake_forward_factory()
    monkeypatch.setattr(client_mod, "forward_command", fake)
    agent = StubAgent("lean", tmp_path)
    proof = asyncio.run(
        setup_mod._prove_already_running(agent, tmp_path, "lean"))
    assert proof["registered"] is False
    assert proof["proven"] is False
    assert calls == []  # no control channel, no presence read


def test_proof_recovery_missing_registers_but_not_proven(
        monkeypatch, tmp_path, live_holder):
    (tmp_path / "keys-lean.json").write_text("{}")
    fake, _ = _fake_forward_factory(
        whoami_extra={"recovery_key_held": False,
                      "recovery_file": None})
    monkeypatch.setattr(client_mod, "forward_command", fake)
    agent = StubAgent("lean", tmp_path, recovery=None)
    proof = asyncio.run(
        setup_mod._prove_already_running(agent, tmp_path, "lean"))
    assert proof["registered"] is True
    assert proof["recovery_present"] is False
    assert proof["proven"] is False


def test_proof_daemon_memory_alone_is_not_proven(
        monkeypatch, tmp_path, live_holder):
    """The daemon holds a key in memory (whoami says so) but NO
    stored copy exists locally — the self-collision rescue's
    shape, where the daemon's boot was itself the rescue. The
    daemon's memory is not the agent's durable record: the
    proof reports it, and still does not call the agent
    proven."""
    (tmp_path / "keys-lean.json").write_text("{}")
    fake, _ = _fake_forward_factory()  # whoami: held=True
    monkeypatch.setattr(client_mod, "forward_command", fake)
    agent = StubAgent("lean", tmp_path, recovery=None)
    proof = asyncio.run(
        setup_mod._prove_already_running(agent, tmp_path, "lean"))
    assert proof["registered"] is True
    assert proof["recovery_daemon_held"] is True
    assert proof["recovery_local"] is False
    assert proof["proven"] is False


def test_proof_presence_falls_back_to_public_read(
        monkeypatch, tmp_path, live_holder):
    (tmp_path / "keys-lean.json").write_text("{}")
    fake, _ = _fake_forward_factory(fail_presence=True)
    monkeypatch.setattr(client_mod, "forward_command", fake)
    monkeypatch.setattr(
        setup_mod, "_read_presence_public",
        lambda agent, uname: {"state": "online", "ts": 9})
    agent = StubAgent("lean", tmp_path)
    proof = asyncio.run(
        setup_mod._prove_already_running(agent, tmp_path, "lean"))
    assert proof["presence_online"] is True
    assert proof["registered"] is True
    assert "presence_control" in proof["errors"]


def test_sync_proof_no_holder_is_offline_and_readonly(tmp_path):
    # No lock file: the sync guard must not mint keys, must not
    # touch the network, and must simply say not proven.
    proof = setup_mod.already_running_proof(tmp_path, "lean")
    assert proof["registered"] is False
    assert proof["holder_alive"] is False
    assert not (tmp_path / "keys-lean.json").exists()


# -- run_setup through the collision ------------------------------------

class FakeSetupAgent:
    """Agent stand-in for run_setup: start() collides (or, with
    collide=False, starts cleanly) and the proof seams answer."""

    collide = True
    recovery_file = None
    _v2 = None

    def __init__(self, username, state_dir=None, designation=None,
                 mode=None, **kw):
        self.username = username
        self.state_dir = Path(state_dir)
        self.identity = object()
        self._v2 = _V2Stub()

    async def start(self):
        if self.collide:
            raise InstanceCollision(
                "instance_collision: another agentlink instance "
                "is already running on this state dir "
                f"(pid {os.getpid()})")
        return "ok"

    async def close(self):
        return None

    def _find_recovery_key(self):
        return "key-123"

    def _recovery_workspace_path(self):
        return self.state_dir / "no-recovery-here.txt"

    def _make_v2_transport(self):
        return self._v2

    async def update_capabilities(self, caps):
        return None

    async def directory(self, query=""):
        return [{"username": self.username}]

    async def request_permission(self, reason):
        return {"id": "greq-1"}


class _DoorbellStub:
    def read_presence(self, username):
        return {"state": "online", "ts": 1}


class _V2Stub:
    doorbell = _DoorbellStub()


def _wire_setup(monkeypatch, tmp_path, collide=True,
                fail_ping=False):
    sd = tmp_path / "s"
    sd.mkdir(parents=True, exist_ok=True)
    (sd / "keys-lean.json").write_text("{}")
    monkeypatch.setattr(setup_mod, "choose_network",
                        lambda s: {"proven": True, "attempts": []})
    FakeSetupAgent.collide = collide
    monkeypatch.setattr(client_mod, "Agent", FakeSetupAgent)
    monkeypatch.setattr(
        client_mod, "instance_lock_holder",
        lambda s, u: {"pid": os.getpid(), "username": u,
                      "since": 7})
    fake, _ = _fake_forward_factory(fail_ping=fail_ping)
    monkeypatch.setattr(client_mod, "forward_command", fake)
    return sd


def test_run_setup_collision_is_registered_success(
        monkeypatch, tmp_path):
    sd = _wire_setup(monkeypatch, tmp_path)
    report = asyncio.run(setup_mod.run_setup(
        "lean", state_dir=str(sd), install_service=True,
        auto_support=False))
    assert report["ok"] is True
    assert report["already_registered"] is True
    assert report["already_running"] is True
    assert report["recovery_present"] is True
    assert report["verify"]["presence_online"] is True
    assert report["verify"]["directory_finds_me"] is True
    assert report["grant"]["status"] == "already_running"
    # No service-install fight with the running instance.
    assert report["service"]["skipped"] == "instance already running"


def test_run_setup_collision_unproven_stays_terminal(
        monkeypatch, tmp_path):
    sd = _wire_setup(monkeypatch, tmp_path, fail_ping=True)
    lodged = []
    import agentlink.support as support_mod
    monkeypatch.setattr(
        support_mod, "maybe_auto_lodge",
        lambda *a, **kw: lodged.append(kw) or None)
    with pytest.raises(InstanceCollision) as ei:
        asyncio.run(setup_mod.run_setup(
            "lean", state_dir=str(sd), auto_support=True))
    msg = str(ei.value)
    assert "already-running proof failed" in msg
    assert "presence_online" in msg
    assert "directory_finds_me" in msg
    # A diagnosed collision is NOT a first-contact failure: the
    # account exists (its daemon holds the lock), so nothing is
    # lodged at the desk wearing a "could not register" claim.
    assert lodged == []
    # The diagnosis rides the exception for the CLI report.
    check = getattr(ei.value, "check", None)
    assert check and check["registered"] is False


def test_collision_proof_late_success_still_registered(
        monkeypatch, tmp_path):
    """A proof conjunct that reads not-yet on the first pass
    (the directory query through the daemon is slow under
    network weather) is retried inside setup's bounded start
    loop — the second pass proving registers the agent through
    the running instance instead of failing it."""
    sd = _wire_setup(monkeypatch, tmp_path)
    real_prove = setup_mod._prove_already_running
    calls = {"n": 0}

    async def flaky_prove(agent, sdir, uname):
        calls["n"] += 1
        proof = await real_prove(agent, sdir, uname)
        if calls["n"] == 1:
            proof = dict(proof)
            proof["directory_finds_me"] = False
            proof["proven"] = False
        return proof

    monkeypatch.setattr(setup_mod, "_prove_already_running",
                        flaky_prove)
    report = asyncio.run(setup_mod.run_setup(
        "lean", state_dir=str(sd), install_service=True,
        auto_support=False))
    assert calls["n"] == 2
    assert report["ok"] is True
    assert report["already_running"] is True
    assert any("not yet proven" in r
               for r in report.get("start_retries", []))


def test_run_setup_collision_registered_but_keyless_stays_terminal(
        monkeypatch, tmp_path):
    """Registered + running is NOT proven: when no recovery key
    is held anywhere (the stranded state that lodges support
    tickets in the first place), the collision stays terminal
    and the failure names recovery_present as the missing
    conjunct — setup never reports ok for a keyless agent."""
    sd = _wire_setup(monkeypatch, tmp_path)
    monkeypatch.setattr(
        client_mod, "forward_command",
        _fake_forward_factory(whoami_extra={
            "recovery_key_held": False, "recovery_file": None})[0])
    FakeSetupAgent._find_recovery_key = lambda self: None
    try:
        with pytest.raises(InstanceCollision) as ei:
            asyncio.run(setup_mod.run_setup(
                "lean", state_dir=str(sd), auto_support=False))
    finally:
        del FakeSetupAgent._find_recovery_key
    msg = str(ei.value)
    assert "already-running proof failed" in msg
    assert '"recovery_present": false' in msg


def test_verify_failure_error_names_every_conjunct(
        monkeypatch, tmp_path):
    """Registration succeeds, presence + directory are green,
    but NO recovery file exists: ok=False, and the lodged
    verify error must SAY recovery_present is the failure —
    not hide it behind all-green verify data."""
    sd = _wire_setup(monkeypatch, tmp_path, collide=False)
    FakeSetupAgent.recovery_file = None
    lodged = {}

    import agentlink.support as support_mod

    def fake_maybe(uname, sdir, step=None, error=None, **kw):
        lodged["step"] = step
        lodged["error"] = error
        return None

    monkeypatch.setattr(support_mod, "maybe_auto_lodge", fake_maybe)
    report = asyncio.run(setup_mod.run_setup(
        "lean", state_dir=str(sd), install_service=False))
    assert report["ok"] is False
    assert report["recovery_present"] is False
    assert lodged["step"] == "verify"
    assert "recovery_present" in lodged["error"]
    assert "registered" in lodged["error"]


# -- the hook ------------------------------------------------------------

class HookDeps(support_hook.Deps):
    def __init__(self, sd, proof):
        super().__init__(sd)
        self._proof = proof
        self.cleaned = []
        self.followups = []

    def poll(self, ticket_id, claim_secret):
        return {"status": "fixed",
                "resolution": {"fixed_in_version": "2.2.3"}}

    def feed_version(self):
        return "2.2.3"

    def apply_update(self):
        return {"updated": False}

    def setup(self, record):
        return {"ok": False,
                "error": "instance_collision: another instance"}

    def already_registered_running(self, record):
        return self._proof

    def followup(self, record, report):
        self.followups.append(report)
        return {"ticket_id": "ticket-fu"}

    def cleanup(self, record, outcome):
        self.cleaned.append(outcome)


def _hook_record(tmp_path):
    return {"ticket_id": "ticket-0001", "claim_secret": "sec",
            "username": "lean", "state_dir": str(tmp_path),
            "designation": "production", "grant": "ask",
            "attempts": 0, "waiting_streak": 0, "followups": []}


def test_hook_collision_proof_retires_as_registered(tmp_path):
    deps = HookDeps(tmp_path, {"registered": True, "proven": True,
                               "recovery_present": True})
    rec = _hook_record(tmp_path)
    assert support_hook.cycle(rec, deps) == "registered"
    assert deps.cleaned == ["registered after fix (already running)"]
    assert deps.followups == []
    assert rec["attempts"] == 0


def test_hook_registered_but_unproven_still_retries(tmp_path):
    """Registered + running WITHOUT a held recovery key is the
    stranded state itself — the hook must keep working it, not
    retire it as success."""
    deps = HookDeps(tmp_path, {"registered": True, "proven": False,
                               "recovery_present": False})
    rec = _hook_record(tmp_path)
    assert support_hook.cycle(rec, deps) == "retry_failed"
    assert deps.followups and rec["attempts"] == 1


def test_hook_without_proof_still_lodges_followup(tmp_path):
    deps = HookDeps(tmp_path, {"registered": False})
    rec = _hook_record(tmp_path)
    assert support_hook.cycle(rec, deps) == "retry_failed"
    assert deps.followups and rec["attempts"] == 1


# -- control channel whoami ----------------------------------------------

def test_control_channel_answers_whoami(tmp_path):
    agent = client_mod.Agent(
        "proofagent", state_dir=str(tmp_path / "s"))
    agent._control_token = "tok-1"

    async def _t():
        reader = asyncio.StreamReader()
        reader.feed_data((json.dumps(
            {"token": "tok-1", "cmd": "whoami"}) + "\n").encode())
        reader.feed_eof()
        writes = []

        class _W:
            def write(self, data):
                writes.append(data)

            async def drain(self):
                return None

            def close(self):
                return None

        await agent._control_handle(reader, _W())
        return json.loads(b"".join(writes).decode())

    out = asyncio.run(_t())
    assert out["ok"] is True
    assert out["result"]["username"] == "proofagent"
    assert "recovery_key_held" in out["result"]


def test_control_channel_answers_presence(tmp_path):
    agent = client_mod.Agent(
        "proofagent", state_dir=str(tmp_path / "s"))
    agent._control_token = "tok-1"

    class _DoorbellOK:
        def read_presence(self, username):
            return {"state": "online", "ts": 5}

    class _V2OK:
        doorbell = _DoorbellOK()

    agent._v2 = _V2OK()

    async def _t():
        reader = asyncio.StreamReader()
        reader.feed_data((json.dumps(
            {"token": "tok-1", "cmd": "presence"}) + "\n").encode())
        reader.feed_eof()
        writes = []

        class _W:
            def write(self, data):
                writes.append(data)

            async def drain(self):
                return None

            def close(self):
                return None

        await agent._control_handle(reader, _W())
        return json.loads(b"".join(writes).decode())

    out = asyncio.run(_t())
    assert out["ok"] is True
    assert out["result"]["state"] == "online"


# -- recovery enrollment on verified login (2.2.3) ---------------------
#
# The third stranded shape the drill exposed: a registration
# whose reply never landed leaves an account with an EMPTY
# server recovery hash and no client copy — key login works,
# but no recovery path exists. The v1 relay enrolls such an
# account on its first verified hello (test_recovery_key pin
# 2); the v2 login Edge + client now do the same.

def _login_edge_src():
    from pathlib import Path as _P
    return (_P(__file__).resolve().parent.parent / "supabase" /
            "functions" / "agentlink-login" /
            "index.ts").read_text()


def test_login_edge_enrolls_only_unenrolled_on_verify():
    src = _login_edge_src()
    start = src.index('if (method === "verify")')
    tail = src.index('if (method === "recovery")', start)
    block = src[start:tail]
    # the verify row read carries the enrollment state
    assert "recovery_hash" in block
    # enrollment mints + stores the HASH, returns the key once,
    # and only behind the empty-hash guard
    assert 'if (!String(row?.recovery_hash ?? ""))' in block
    assert "recovery_hash: await sha256Hex(enrollKey)" in block
    assert block.count("recovery_key: enrollKey") == 1


def test_client_start_persists_enrollment_key(monkeypatch, tmp_path):
    """_start_serverless wires the transport's enrollment sink
    to the Agent's storage contract: a key the Edge hands back
    on ANY login path lands in both saved copies."""
    import agentlink.client as _c

    agent = _c.Agent(username="enrollme",
                     state_dir=str(tmp_path / "state"),
                     workspace=str(tmp_path / "ws"),
                     transport="serverless", mode="manual")

    class _V2:
        oversight_pubkey = ""
        on_recovery_enrollment = None

    v2 = _V2()
    agent._serverless_injected = v2
    made = agent._make_v2_transport()
    assert made is v2
    assert v2.on_recovery_enrollment is not None
    v2.on_recovery_enrollment("enrolled-key-1")
    ws_file = tmp_path / "ws" / "agentlink-recovery-enrollme.txt"
    assert ws_file.exists()
    assert "enrolled-key-1" in ws_file.read_text()
    state_copy = tmp_path / "state" / "recovery-enrollme.json"
    assert state_copy.exists()


# -- control-socket ownership (drill round-2 defect) ----------------

def test_nonserving_close_keeps_daemon_control_socket(tmp_path):
    """A rival Agent that never served (setup's fast path builds
    one and closes it in its finally) must NOT unlink the running
    instance's control socket on close. The 2.2.3 live drill's
    first setup round succeeded and silently deleted the
    daemon's socket file; the second round then met a live,
    online daemon whose control channel was unreachable."""
    agent = client_mod.Agent(
        "lean", state_dir=str(tmp_path / "s"),
        workspace=str(tmp_path / "ws"))
    assert agent._control_server is None
    sock = agent._control_socket_path()
    sock.parent.mkdir(parents=True, exist_ok=True)
    sock.write_text("daemon's socket lives here")
    asyncio.run(agent._stop_control_server())
    assert sock.exists(), "non-owner close removed the socket"


def test_serving_stop_removes_own_control_socket(tmp_path):
    """The serving object still removes its own socket on stop
    (no stale socket left for the next boot to trip over)."""

    class _Srv:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

        async def wait_closed(self):
            return None

    agent = client_mod.Agent(
        "lean", state_dir=str(tmp_path / "s"),
        workspace=str(tmp_path / "ws"))
    srv = _Srv()
    agent._control_server = srv
    sock = agent._control_socket_path()
    sock.parent.mkdir(parents=True, exist_ok=True)
    sock.write_text("mine")
    asyncio.run(agent._stop_control_server())
    assert srv.closed is True
    assert agent._control_server is None
    assert not sock.exists()
