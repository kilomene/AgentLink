"""2.2.0 sync guards (scope expansion, reconciliation items
S2 + B5).

S2 — swift-otter-7's slow-sync thread died on 2.0.9 when a raw
urllib.error.URLError (EOF in violation of protocol) escaped the
mirror/token path: _mirror_activeness caught only TransportError,
run_slow_sync's fetch catch likewise, and the doorbell's _call
re-raised non-407 network exceptions raw, outside its own
DoorbellError contract. All three layers are fixed at the source;
these tests pin each layer. (2.3.0: the mirror layer is DELETED
with the mirror itself — the surviving layers are the doorbell
contract and the loop-cannot-die guarantee, re-pinned below
against the degraded loop.)

B5 — a history page whose body the egress proxy clipped arrives
as an "undecodable body" error and used to stop the whole sync;
sync_history now shrinks the page and retries the same cursor.
"""

import asyncio
import threading
import urllib.error

import pytest

EOF = "<urlopen error EOF occurred in violation of protocol (_ssl.c:2437)>"


# ---------------- S2 layer 1: the doorbell contract ----------------

def test_doorbell_call_wraps_urlerror_as_doorbellerror():
    from agentlink.doorbell import DoorbellClient, DoorbellError

    def opener(method, url, headers, body):
        raise urllib.error.URLError(EOF)

    bell = DoorbellClient(project_id="proj", api_key="key",
                          opener=opener)
    bell.set_custom_token("custom-token")
    with pytest.raises(DoorbellError):
        bell.exchange_custom_token()


def test_doorbell_call_still_retries_407_class():
    from agentlink.doorbell import DoorbellClient

    calls = {"n": 0}

    def opener(method, url, headers, body):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError(
                "Tunnel connection failed: 407 Proxy "
                "Authentication Required")
        return (200, {}, b'{"idToken": "idt", "refreshToken": "rft",'
                         b' "expiresIn": "3600"}')

    bell = DoorbellClient(project_id="proj", api_key="key",
                          opener=opener)
    bell.set_custom_token("custom-token")
    assert bell.exchange_custom_token() == "idt"
    assert calls["n"] == 3


# ---------------- S2 layer 2: fail-soft surfaces ------------------

def _bare_transport():
    from agentlink.transport_v2 import ServerlessConfig, \
        ServerlessTransport
    config = ServerlessConfig(
        supabase_url="https://example.supabase.co", anon_key="anon",
        firebase_project_id="proj", firebase_api_key="key",
        firebase_database_url="https://proj.firebaseio.com")
    return ServerlessTransport(config, opener=lambda *a: (200, {}, b""))


def test_transitions_and_acks_never_raise_on_raw_network_errors():
    # 2.3.0: the mirror this layer pinned is deleted. Its
    # guarantee — a raw network error on a periodic/fail-soft
    # path NEVER raises into a supervision thread — now lives
    # on the surfaces that remain: ladder transitions are pure
    # local bookkeeping (no network at all), and ack() treats a
    # dead backend as an empty page.
    t = _bare_transport()

    def boom(*a, **k):
        raise urllib.error.URLError(EOF)

    t._rest = boom
    assert t._transition_activeness("online") in (True, False)
    assert t.ack(["m-x"]) == []


# ---------------- S2 layer 3: the loop cannot die -------------------

def test_slow_sync_loop_survives_fetch_exceptions(
        monkeypatch):
    # 2.3.0 form of the pin: the degraded loop (the mirror step
    # it used to also run is deleted) cycles through fetch
    # failures of ANY exception class and records them.
    import agentlink.transport_v2 as tv2
    monkeypatch.setattr(tv2, "SLOW_SYNC_INTERVAL_SECONDS", 0)
    t = _bare_transport()
    t.username = "swift-test"
    t.slow_sync_active = True  # degraded mode: the loop fetches
    stop = threading.Event()
    state = {"fetch": 0}

    def fetch_once():
        state["fetch"] += 1
        if state["fetch"] == 1:
            raise urllib.error.URLError(EOF)
        if state["fetch"] >= 3:
            stop.set()
        return []

    t.slow_sync_once = fetch_once
    t.run_slow_sync(lambda frames: None, stop_event=stop)
    assert state["fetch"] == 3
    assert t.last_slow_sync_error  # the failures were recorded


# ---------------- B5: history page shrink ---------------------------

def test_history_sync_shrinks_the_page_on_an_undecodable_body(
        tmp_path):
    from agentlink.client import Agent
    agent = Agent(username="alice", state_dir=str(tmp_path / "state"),
                  workspace=str(tmp_path / "ws"),
                  transport="serverless", mode="manual")
    seen_limits = []

    class _V2:
        def fetch_history_page(self, limit=200, before_seq=None):
            seen_limits.append(limit)
            if limit > 10:
                raise Exception(
                    "PostgREST GET audit_log returned an "
                    "undecodable body")
            return []

    agent._v2 = _V2()
    out = asyncio.run(agent.sync_history())
    assert "error" not in out
    assert out["page_shrunk_to"] == 10
    assert seen_limits == [200, 50, 10]


def test_history_sync_shrinks_on_the_empty_body_signature_too(
        tmp_path):
    # The zero-byte costume of the same clip raises "returned an
    # empty body" instead — the ladder must treat both alike
    # (the first live shrink, 2026-11-07, stopped after one step
    # on exactly this).
    from agentlink.client import Agent
    agent = Agent(username="alice", state_dir=str(tmp_path / "state"),
                  workspace=str(tmp_path / "ws"),
                  transport="serverless", mode="manual")

    class _V2:
        def fetch_history_page(self, limit=200, before_seq=None):
            if limit > 10:
                raise Exception(
                    "PostgREST GET audit_log returned an empty body")
            return []

    agent._v2 = _V2()
    out = asyncio.run(agent.sync_history())
    assert "error" not in out
    assert out["page_shrunk_to"] == 10


def test_history_sync_still_reports_a_persistent_failure(tmp_path):
    from agentlink.client import Agent
    agent = Agent(username="alice", state_dir=str(tmp_path / "state"),
                  workspace=str(tmp_path / "ws"),
                  transport="serverless", mode="manual")

    class _V2:
        def fetch_history_page(self, limit=200, before_seq=None):
            raise Exception("PostgREST GET audit_log returned an "
                            "undecodable body")

    agent._v2 = _V2()
    out = asyncio.run(agent.sync_history())
    assert "undecodable" in out["error"]
    assert out["page_shrunk_to"] == 10  # it tried the whole ladder


# ------------- control-forward honesty (sweep, B4/B7) --------------

def test_read_forwards_carry_the_300s_budget():
    # One hardened call can take ~160s inside a proxy stall
    # window; the old 120s read budget declared healthy daemons
    # wedged. Writes keep their 20s fail-fast (not pinned here).
    import pathlib
    cli = (pathlib.Path(__file__).resolve().parent.parent
           / "agentlink" / "cli.py").read_text()
    for cmd in ("directory", "delivery_status", "sync_history",
                "work_inbox", "chain_list"):
        assert f'"cmd": "{cmd}"' in cli
    assert cli.count('"timeout": 300') >= 5
    assert '"timeout": 120' not in cli


def test_forward_timeout_message_names_both_possibilities():
    import pathlib
    client = (pathlib.Path(__file__).resolve().parent.parent
              / "agentlink" / "client.py").read_text()
    assert "still executing inside a network ride-out" in client
    assert "may have landed" in client
    assert "it is wedged; fail" not in client


# ------------- work lifecycle forwards (sweep, B7 write side) -------

def test_control_channel_serves_work_lifecycle_writes(tmp_path):
    import json as _json
    from agentlink.client import Agent
    agent = Agent(username="alice", state_dir=str(tmp_path / "state"),
                  workspace=str(tmp_path / "ws"),
                  transport="serverless", mode="manual")
    agent._control_token = "tok-1"
    calls = []

    async def fake_progress(work_id, percent, note=""):
        calls.append(("progress", work_id, percent, note))
        return {"id": work_id, "status": "in_progress"}

    async def fake_deliver(work_id, body="", files=None):
        calls.append(("deliver", work_id, body, files))
        return {"id": work_id, "status": "delivered"}

    async def fake_approve(work_id, note=""):
        calls.append(("approve", work_id, note))
        return {"id": work_id, "status": "approved"}

    agent.report_progress = fake_progress
    agent.deliver_work = fake_deliver
    agent.approve_work = fake_approve

    class Reader:
        def __init__(self, payload):
            self._line = (_json.dumps(payload) + "\n").encode()

        async def readline(self):
            line, self._line = self._line, b""
            return line

    class Writer:
        def __init__(self):
            self.data = b""

        def write(self, chunk):
            self.data += chunk

        async def drain(self):
            pass

        def close(self):
            pass

    async def scenario():
        for spec, want_status in (
                ({"cmd": "work_progress", "work_id": "w1",
                  "percent": 40, "note": "going"}, "in_progress"),
                ({"cmd": "work_deliver", "work_id": "w1",
                  "body": "done", "files": []}, "delivered"),
                ({"cmd": "work_approve", "work_id": "w1",
                  "note": "ok"}, "approved")):
            writer = Writer()
            await agent._control_handle(
                Reader(dict(spec, token="tok-1")), writer)
            out = _json.loads(writer.data.decode())
            assert out["ok"] is True, out
            assert out["result"]["status"] == want_status

    asyncio.run(scenario())
    assert [c[0] for c in calls] == ["progress", "deliver", "approve"]


def test_cli_work_writes_carry_forward_specs():
    import pathlib
    cli = (pathlib.Path(__file__).resolve().parent.parent
           / "agentlink" / "cli.py").read_text()
    assert '"cmd": "work_assign"' in cli
    assert '"cmd": "work_deliver"' in cli
    assert '"cmd": "work_progress"' in cli
    assert '"cmd": "work_" + sub.replace("-", "_")' in cli


# ------------- first-contact self-collision rescue (sweep) ----------

class _CeremonyV2:
    """Scripted first-contact ceremonies (after test_v200_register's
    FakeV2, plus the plain login the rescue discriminates with)."""

    def __init__(self, script):
        self.script = script
        self.calls = []

    def _act(self, name, args):
        self.calls.append(name)
        kind, value = self.script[name]
        if kind == "raise":
            from agentlink.transport_v2 import TransportError
            raise TransportError(value)
        return {"username": args[0], "recovery_key": value}

    def login(self, *args, **kw):
        return self._act("login", args)

    def recover_and_login(self, *args, **kw):
        return self._act("recover", args)

    def register_and_login(self, *args, **kw):
        return self._act("register", args)

    def rectify_and_login(self, *args, **kw):
        return self._act("rectify", args)


def _fc_agent(tmp_path):
    from agentlink.client import Agent
    return Agent(username="newagent",
                 state_dir=str(tmp_path / "state"),
                 workspace=str(tmp_path / "ws"),
                 transport="serverless", mode="manual")


def test_rescue_register_self_collision_opens_via_login(tmp_path):
    # Register landed but its reply was clipped; the retry met
    # username_taken. The account holds THIS machine's keys, so
    # the plain login opens and the suite reports success.
    agent = _fc_agent(tmp_path)
    v2 = _CeremonyV2({"register": ("raise", "username_taken"),
                      "login": ("ok", "")})
    assert asyncio.run(agent._serverless_first_contact(v2)) is True
    assert v2.calls == ["register", "login"]


def test_rescue_genuine_stranger_still_refused(tmp_path):
    # Taken by another's keys: the login refuses too, no rectify
    # code is held, and the suite's verdict is unchanged (False).
    agent = _fc_agent(tmp_path)
    v2 = _CeremonyV2({"register": ("raise", "username_taken"),
                      "login": ("raise", "key_auth_failed")})
    assert asyncio.run(agent._serverless_first_contact(v2)) is False
    assert v2.calls == ["register", "login"]


def test_rescue_manual_recovery_key_that_landed(tmp_path):
    # A handed-in recovery key whose rebind landed before its
    # reply was clipped answers recovery_failed on the retry —
    # but the account now holds this machine's keys.
    agent = _fc_agent(tmp_path)
    agent._recovery_key_manual = "handed-in-key"
    v2 = _CeremonyV2({"recover": ("raise", "recovery_failed"),
                      "login": ("ok", "")})
    assert asyncio.run(agent._serverless_first_contact(v2)) is True
    assert v2.calls == ["recover", "login"]


def test_rescue_manual_key_genuinely_wrong_still_final(tmp_path):
    from agentlink.client import RegistrationFailed
    agent = _fc_agent(tmp_path)
    agent._recovery_key_manual = "handed-in-key"
    v2 = _CeremonyV2({"recover": ("raise", "recovery_failed"),
                      "login": ("raise", "key_auth_failed")})
    with pytest.raises(RegistrationFailed):
        asyncio.run(agent._serverless_first_contact(v2))
