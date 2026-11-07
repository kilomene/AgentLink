"""2.0.10 — the consolidated fleet fix release.

One test class per census class:

A. envelope reconciliation + decrypt discipline (park/backoff/heal)
B. network hardening (PROXY ride-out) + persistent outbox
C. service supervision (state-dir baked in, real status)
D. delivery confirmation from the server record
E. read-only one-shots forward through the running daemon
F. presence/doorbell legs ride the same ride-out
G. directory search is case-insensitive (account + api Edges)
H. self-setup: network choice persists per-agent; capabilities
   are probed, never asserted
"""

from __future__ import annotations

import asyncio
import json
import time
import urllib.error
from pathlib import Path

import pytest

from agentlink import proxycreds
from agentlink.outbox import Outbox
from agentlink.transport_v2 import (ServerlessConfig,
                                    ServerlessTransport,
                                    TransportError)

ROOT = Path(__file__).resolve().parents[1]
SUPA = "https://proj.example"
EDGE = SUPA + "/functions/v1/agentlink-login"


def make_config():
    return ServerlessConfig(
        supabase_url=SUPA, anon_key="anon-key-public",
        firebase_project_id="proj", firebase_api_key="fb-key",
        login_edge_url=EDGE)


def scripted_transport(script):
    """A transport whose opener plays ``script`` — a list of
    outcomes: ("raise", exception) or ("reply", status, body)."""
    calls = []

    def opener(method, url, headers, body):
        calls.append((method, url))
        kind, *rest = script.pop(0)
        if kind == "raise":
            raise rest[0]
        status, payload = rest
        if isinstance(payload, (dict, list)):
            payload = json.dumps(payload).encode()
        return status, {}, payload

    transport = ServerlessTransport(make_config(), opener=opener,
                                    stream_opener=None)
    transport.username = "alice"
    return transport, calls


@pytest.fixture(autouse=True)
def _no_proxy_sleeps(monkeypatch):
    """The ride-out's backoff waits are real in production; in
    tests they would only slow the gate. The retry COUNTS are
    what these tests pin. Patch the modules' OWN _sleep hooks
    only — an earlier version of this fixture patched
    ``time.sleep`` through the modules' ``time`` attribute,
    which is the stdlib module itself: every leaked thread in
    the suite that slept turned into a spin loop and the full
    gate melted at this file. Never patch time.sleep globally."""
    monkeypatch.setattr("agentlink.transport_v2._sleep",
                        lambda *_a, **_k: None)
    monkeypatch.setattr("agentlink.doorbell._sleep",
                        lambda *_a, **_k: None)


# ============================ B: ride-out ============================

def test_b_rest_call_rides_out_a_407_window(monkeypatch):
    resets = []
    monkeypatch.setattr(proxycreds, "reset_winner",
                        lambda: resets.append(1))
    transport, calls = scripted_transport([
        ("raise", urllib.error.URLError(
            "Tunnel connection failed: 407 Proxy Authentication "
            "Required")),
        ("reply", 200, [{"username": "bob"}]),
    ])
    rows = transport._rest("GET", "al_users", "select=username")
    assert rows == [{"username": "bob"}]
    assert len(calls) == 2          # failed once, retried, landed
    assert resets == [1]            # the stale winner abdicated


def test_b_rest_call_rides_out_a_407_status():
    transport, calls = scripted_transport([
        ("reply", 407, b"proxy auth"),
        ("reply", 200, [{"ok": True}]),
    ])
    assert transport._rest("GET", "al_users", "select=username") == \
        [{"ok": True}]
    assert len(calls) == 2


def test_b_edge_post_rides_out_an_empty_body_window():
    # The desync signature: HTTP 200 with a zero-byte body. A
    # login challenge answered that way used to fail the whole
    # multi-call flow (@lean's registration); now the Edge leg
    # re-resolves and retries inside the same call.
    transport, calls = scripted_transport([
        ("reply", 200, b""),
        ("reply", 200, {"challenge": "abc", "expires": 999}),
    ])
    out = transport._edge_post("challenge", {"username": "lean"})
    assert out == {"challenge": "abc", "expires": 999}
    assert len(calls) == 2


def test_b_non_proxy_failure_is_not_retried():
    transport, calls = scripted_transport([
        ("raise", urllib.error.URLError("Name or service not known")),
    ])
    with pytest.raises(TransportError):
        transport._rest("GET", "al_users", "select=username")
    assert len(calls) == 1          # a verdict, not weather


def test_b_proxy_window_eventually_surfaces():
    script = [("reply", 407, b"")] * 10
    transport, calls = scripted_transport(script)
    with pytest.raises(TransportError):
        transport._rest("GET", "al_users", "select=username")
    # Bounded: PROXY_RETRY_ATTEMPTS dials, then the failure is
    # the caller's — never an infinite loop inside one call.
    from agentlink.transport_v2 import PROXY_RETRY_ATTEMPTS
    assert len(calls) == PROXY_RETRY_ATTEMPTS


# ============================ B: outbox ==============================

def test_b_outbox_is_durable_and_backs_off(tmp_path):
    path = tmp_path / "outbox-alice.json"
    box = Outbox(path)
    frame = {"id": "m1", "type": "group_send", "group_id": "g1",
             "content": {"ct": "x"}}
    box.add(frame)
    assert len(box) == 1
    # A fresh instance over the same file sees the entry: the
    # queue survives a daemon restart.
    assert len(Outbox(path)) == 1
    entry = box.mark_failed("m1", "407 window")
    assert entry["attempts"] == 1
    assert entry["next_ts"] > int(time.time())
    assert box.due() == []                       # backing off
    assert box.due(now=entry["next_ts"]) != []   # then due again
    box.mark_sent("m1")
    assert len(box) == 0
    assert Outbox(path).pending() == []


def test_b_outbox_add_is_idempotent_by_frame_id(tmp_path):
    box = Outbox(tmp_path / "o.json")
    frame = {"id": "m9", "type": "send", "content": {}}
    box.add(frame)
    box.add(frame)
    assert len(box) == 1


# ============================ D: delivery ============================

def _delivery_transport(monkeypatch, audit, queues):
    def opener(method, url, headers, body):
        if "al_audit_log" in url:
            return 200, {}, json.dumps(audit).encode()
        if "al_group_members" in url:
            return 200, {}, json.dumps(
                [{"username": "bob"}, {"username": "carol"},
                 {"username": "alice"}]).encode()
        if "al_queue" in url:
            user = url.split("username=eq.")[1].split("&")[0]
            rows = queues.get(user, [])
            return 200, {}, json.dumps(rows).encode()
        raise AssertionError(f"unexpected url {url}")

    transport = ServerlessTransport(make_config(), opener=opener,
                                    stream_opener=None)
    transport.username = "alice"
    return transport


def _queue_row(mid):
    return {"seq": 1, "username": "bob",
            "payload": json.dumps({"id": mid, "type": "group"})}


def test_d_state_read_beats_everything():
    audit = [{"kind": "group_message", "actor": "alice", "ts": 1},
             {"kind": "message_read", "actor": "bob", "ts": 2}]
    t = _delivery_transport(None, audit, {"bob": [_queue_row("m1")]})
    out = t.delivery_state("m1", group_id="g1")
    assert out["state"] == "read"
    assert out["read_by"] == ["bob"]


def test_d_state_queued_while_custody_stands():
    audit = [{"kind": "message", "actor": "alice", "ts": 1}]
    t = _delivery_transport(None, audit, {"bob": [_queue_row("m2")]})
    out = t.delivery_state("m2", recipients=["bob"])
    assert out["state"] == "queued"
    assert out["pending_for"] == ["bob"]


def test_d_state_delivered_when_custody_drains():
    audit = [{"kind": "message", "actor": "alice", "ts": 1}]
    t = _delivery_transport(None, audit, {"bob": []})
    out = t.delivery_state("m3", recipients=["bob"])
    assert out["state"] == "delivered"
    assert out["delivered_to"] == ["bob"]


def test_d_state_unknown_without_a_server_record():
    t = _delivery_transport(None, [], {"bob": []})
    out = t.delivery_state("nope", recipients=["bob"])
    assert out["state"] == "unknown"
    assert out["accepted"] is False


# ============================ A: park + heal =========================

def _agent(tmp_path, username="alice"):
    from agentlink.client import Agent
    return Agent(username=username,
                 state_dir=str(tmp_path / "state"),
                 workspace=str(tmp_path / "ws"),
                 transport="serverless", mode="manual")


def test_a_park_journal_backs_off_exponentially(tmp_path):
    agent = _agent(tmp_path)
    first = agent._park_unreadable("m1")
    assert first["attempts"] == 1
    assert not agent._unreadable_due("m1")     # inside backoff
    second = agent._park_unreadable("m1")
    assert second["attempts"] == 2
    assert second["next_ts"] >= first["next_ts"]
    agent._clear_unreadable("m1")
    assert agent._unreadable_due("m1")         # cleared = due
    # Durable: a fresh agent over the same state sees no record.
    assert _agent(tmp_path)._unreadable == {}


def test_a_undecryptable_frame_parks_and_acks_once(tmp_path):
    agent = _agent(tmp_path)
    acks = []

    class _V2:
        def ack(self, ids):
            acks.extend(ids)
            return {"acked": len(ids)}

    agent._v2 = _V2()
    frame = {"id": "bad1", "from": "bob", "ts": int(time.time()),
             "content": {"v": 1, "alg": "x25519-chacha20poly1305",
                         "eph_pub": "AAAA", "nonce": "AAAA",
                         "ct": "AAAA"}}
    asyncio.run(agent._process_message(frame))
    stub = agent.mailbox.get("bad1")
    assert stub is not None and stub["unreadable"] is True
    assert stub["sealed"] is True and stub["body"] == ""
    assert acks == ["bad1"]                    # custody released
    # Redelivery inside the backoff: acked again (the first ack
    # may have been lost), but NO new decrypt attempt, NO new
    # park record — the 7,863-retry spin is dead.
    asyncio.run(agent._process_message(frame))
    assert acks == ["bad1", "bad1"]
    assert agent._unreadable["bad1"]["attempts"] == 1
    # The stub never reaches take-in replay.
    assert all(m.get("id") != "bad1"
               for m in agent.mailbox.pending_takein())


def test_a_sync_replaces_a_parked_stub_with_the_server_copy(tmp_path):
    from agentlink.crypto import encrypt_to_pubkey
    agent = _agent(tmp_path)
    mid = "heal1"
    # The pre-repair local state: a parked unreadable stub.
    agent.mailbox.put_if_absent({
        "id": mid, "from": "bob", "to": "alice", "kind": "text",
        "body": "", "sealed": True, "unreadable": True,
        "ts": int(time.time())})
    agent._park_unreadable(mid)
    # The server's copy opens fine (sealed to my identity).
    payload = {"body": "the real words", "kind": "text",
               "file": None}
    envelope = encrypt_to_pubkey(
        agent.identity.public_key_b64,
        json.dumps(payload).encode())
    row = {"seq": 5, "ts": int(time.time()), "kind": "message",
           "actor": "bob", "target": "alice", "group_id": "",
           "ref_id": mid, "status": "sent",
           "content_envelope": envelope, "oversight": None}

    class _V2:
        def fetch_history_page(self, limit=200, before_seq=None):
            return [] if before_seq else [row]

    agent._v2 = _V2()
    out = asyncio.run(agent.sync_history())
    assert out["healed"] == 1
    healed = agent.mailbox.get(mid)
    assert healed["body"] == "the real words"
    assert not healed.get("sealed")
    assert mid not in agent._unreadable        # park record cleared


# ============================ E: control reads =======================

def test_e_control_channel_serves_read_only_commands(tmp_path):
    agent = _agent(tmp_path)
    agent._control_token = "tok-1"

    async def fake_work_inbox(*a, **k):
        return [{"id": "w1", "title": "job"}]

    async def fake_directory(query=""):
        return {"agents": [{"username": "phoenix"}]}

    agent.work_inbox = fake_work_inbox
    agent.directory = fake_directory

    class Reader:
        def __init__(self, payload):
            self._line = (json.dumps(payload) + "\n").encode()

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
        writer = Writer()
        await agent._control_handle(
            Reader({"token": "tok-1", "cmd": "work_inbox"}), writer)
        out = json.loads(writer.data.decode())
        assert out["ok"] is True
        assert out["result"]["items"][0]["id"] == "w1"
        writer2 = Writer()
        await agent._control_handle(
            Reader({"token": "tok-1", "cmd": "directory",
                    "query": "Phoenix"}), writer2)
        out2 = json.loads(writer2.data.decode())
        assert out2["ok"] is True
        assert out2["result"]["agents"][0]["username"] == "phoenix"

    asyncio.run(scenario())


def test_e_cli_read_commands_carry_forward_specs():
    cli_src = (ROOT / "agentlink" / "cli.py").read_text()
    assert 'forward={"cmd": "work_inbox", "timeout": 120}' in cli_src
    assert 'forward={"cmd": "directory", "query": args.query,' in cli_src
    assert 'forward={"cmd": "sync_history", "timeout": 120}' in cli_src
    assert 'forward={"cmd": "delivery_status",' in cli_src


# ============================ F: doorbell ride-out ===================

def test_f_doorbell_rest_rides_out_a_407():
    from agentlink.doorbell import DoorbellClient
    calls = []

    def opener(method, url, headers, body):
        calls.append(url)
        if len(calls) == 1:
            return 407, {}, b"proxy auth"
        return 200, {}, json.dumps(
            {"state": "online", "ts": 1}).encode()

    client = DoorbellClient(
        project_id="proj", api_key="fb-key",
        database_url="https://db.example", opener=opener)
    client._id_token = "tok"
    client._id_token_expires_at = time.time() + 600
    got = client.read_presence("bob")
    assert got == {"state": "online", "ts": 1}
    assert len(calls) == 2


# ============================ G: directory ===========================

def test_g_account_edge_directory_matches_case_insensitively():
    src = (ROOT / "supabase" / "functions" / "agentlink-account"
           / "index.ts").read_text()
    route = src[src.index("async function routeDirectory"):]
    route = route[:route.index("\nasync function ")
                  if "\nasync function " in route[10:] else len(route)]
    assert "toLowerCase()" in route
    assert "display_name" in route
    # The bug's exact shape must be gone: a raw case-sensitive
    # includes() against the un-lowered username.
    assert "String(row.username).includes(query)" not in src


def test_g_api_edge_directory_honours_the_query():
    src = (ROOT / "supabase" / "functions" / "agentlink-api"
           / "index.ts").read_text()
    route = src[src.index('path === "/directory"'):]
    route = route[:3000]
    assert 'searchParams.get("q")' in route
    assert "toLowerCase()" in route
    assert "display_name" in route


# ============================ C: service =============================

def test_c_service_install_bakes_state_dir_and_reports_status(
        tmp_path, monkeypatch, capsys):
    from agentlink import cli
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    # No systemctl, no crontab on PATH: the install must still
    # land the unit, fall back honestly, and never spawn a real
    # supervisor from inside a test.
    shim = tmp_path / "shim"
    shim.mkdir()
    monkeypatch.setenv("PATH", str(shim))
    import subprocess as _sp
    spawned = []
    monkeypatch.setattr(_sp, "Popen",
                        lambda *a, **k: spawned.append(a) or None)
    rc = cli._service(["install", "--username", "serviced",
                       "--user", "--state-dir", "/tmp/sd-serviced"])
    assert rc == 0
    unit = (home / ".config" / "systemd" / "user"
            / "agentlink-agent.service").read_text()
    assert "--state-dir /tmp/sd-serviced" in unit
    assert "--username @serviced" in unit
    assert "Restart=always" in unit
    raw = capsys.readouterr().out
    out = json.loads(raw[raw.index("{"):])   # a notice may precede
    assert out["supervision"] in ("cron-supervisor", "none")
    rc = cli._service(["status", "--username", "serviced",
                       "--state-dir", "/tmp/sd-serviced"])
    assert rc == 0
    raw = capsys.readouterr().out
    status = json.loads(raw[raw.index("{"):])
    assert status["unit_file"] is not None
    assert status["daemon_pid_alive"] is False


# ============================ H: setup pieces ========================

def test_h_choose_network_persists_the_agents_own_config(
        tmp_path, monkeypatch):
    from agentlink import setup as setup_mod
    monkeypatch.setattr(proxycreds, "candidate_proxies",
                        lambda: ["http://proxy-a:8080",
                                 "http://proxy-b:8080"])
    probed = []

    def fake_probe(proxy, url, timeout=8.0):
        probed.append(proxy)
        if proxy and proxy.endswith("proxy-b:8080"):
            return True, "HTTP 400 (roundtrip answered)"
        return False, "HTTP 407 (stale proxy credential)"

    monkeypatch.setattr(setup_mod, "_probe_candidate", fake_probe)
    sd = tmp_path / "state"
    network = setup_mod.choose_network(sd)
    assert network["proven"] is True
    assert network["proxy"] == "http://proxy-b:8080"
    assert probed[0].endswith("proxy-a:8080")   # raced in order
    saved = json.loads((sd / "network.json").read_text())
    assert saved["proxy"] == "http://proxy-b:8080"
    assert "proxy-b" in (sd / "proxy.env").read_text()


def test_h_capabilities_are_probed_not_asserted(tmp_path):
    from agentlink.setup import _probe_capabilities
    caps = _probe_capabilities(tmp_path, {"proven": True})
    assert caps == ["internet", "files"]
    caps = _probe_capabilities(tmp_path, {"proven": False})
    assert caps == ["files"]                    # no internet claim


def test_h_setup_cli_is_wired():
    cli_src = (ROOT / "agentlink" / "cli.py").read_text()
    assert 'if cmd == "setup":' in cli_src
    setup_src = (ROOT / "agentlink" / "setup.py").read_text()
    # The owner's order: network BEFORE registration.
    assert setup_src.index("choose_network") < \
        setup_src.index("agent.start()")
    # The grant is asked agent-side through the greq machinery.
    assert "request_permission" in setup_src
    assert "allow_permission" in setup_src
