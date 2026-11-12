"""v2.5.1 — AUTOMATIC ACCEPTANCE + DOSSIER DESTINATION
(owner's correction, 2026-11-11).

The defects, from the fleet's own record: an agent on 2.5.0
asked its USER "Want those accepted too?" about the 2.5.0
Standing Orders additions — the user had to say "accept
everything" repeatedly — and then reported "Dossier stays
local for now since no archive destination is set." Two
standing rules were violated: platform duties are accepted by
the agent's machinery BY ITSELF, and the Drive dossier is
compulsory — a missing destination must be impossible, not
silent.

These pins:
  * the daemon records platform acceptance of the installed
    orders version at start, automatically, idempotently, and
    WITHOUT touching the runtime's inscription attestation
    (the Brain Doctrine boundary: `inscribed` stays the
    agent's own ack, and nothing blocks on it);
  * no code path presents platform-duty acceptance as a
    question (the inscription letter now says so, in words);
  * the deposit destination is a hardened built-in: the
    platform deposit route under the agent's own session
    identity — no env URL, no shared archive token, no
    per-agent destination setting anywhere in the stock
    client;
  * a deposit that cannot land stays LOUD (queue + non-current
    dossier status), never a silent local park;
  * a fresh client, given only a username + its own network
    config, reaches orders-accepted + dossier-deposited with
    ZERO interactive steps (the centerpiece, unit form — the
    sandbox drill proves it against the real stack).
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from agentlink import dossier as dm
from agentlink.orders import (
    ack_inscription, auto_accept_orders, ensure_orders,
    orders_state, shipped_orders)

ROOT = Path(__file__).resolve().parent.parent
NOW = 1794500000


# ------------------------------------------------- acceptance

def test_auto_accept_records_platform_acceptance(tmp_path):
    st = auto_accept_orders(tmp_path)
    _raw, version, _digest = shipped_orders()
    assert st["platform_accepted"] is True
    assert st["accepted_orders_version"] == version
    assert st["accepted_by"] == "daemon-machinery"
    assert isinstance(st["accepted_ts"], int)
    # the client-owned half only: the runtime's attestation
    # fields are NOT the machinery's to set
    assert st["inscribed"] is False
    assert st["self_check_scheduled"] is False
    assert st["ack_ts"] is None


def test_auto_accept_is_idempotent_per_version(tmp_path):
    first = auto_accept_orders(tmp_path)
    second = auto_accept_orders(tmp_path)
    assert second["accepted_ts"] == first["accepted_ts"]
    assert second["platform_accepted"] is True


def test_auto_accept_never_touches_attestation(tmp_path):
    ack_inscription(tmp_path, inscribed=True,
                    self_check_scheduled=True)
    st = auto_accept_orders(tmp_path)
    assert st["inscribed"] is True
    assert st["self_check_scheduled"] is True
    assert st["ack_ts"] is not None
    assert st["platform_accepted"] is True


def _seed_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "identity.json").write_text("{}")
    return state


def test_agent_start_auto_accepts_orders(tmp_path, monkeypatch):
    """The daemon start path itself records acceptance — the
    same start an update lands on. No ack command, no prompt,
    no flag: start() returns with acceptance on record."""
    from agentlink.client import Agent
    state = _seed_state(tmp_path)
    agent = Agent("agent", state_dir=str(state), mode="manual")

    async def _fake_start_serverless(self):
        return "serverless"

    monkeypatch.setattr(Agent, "_start_serverless",
                        _fake_start_serverless)
    asyncio.run(agent.start())
    st = orders_state(state)
    _raw, version, _digest = shipped_orders()
    assert st["platform_accepted"] is True
    assert st["accepted_orders_version"] == version
    assert st["inscribed"] is False  # never faked by machinery


def test_acceptance_is_never_a_question(tmp_path):
    """The inscription letter must instruct the runtime that
    acceptance is DONE by the machinery and must never be
    routed to its user as a question — the exact failure the
    fleet produced on 2.5.0."""
    ensure_orders(tmp_path)
    letter = (tmp_path / "BRAIN-INSCRIPTION.md").read_text()
    assert "ACCEPTANCE IS ALREADY" in letter
    assert "NEVER a question" in letter
    assert "never present this attestation" in letter
    # and the orders text itself is UNCHANGED doctrine:
    # orders version stays 2.5.0 in this machinery release
    raw, version, _digest = shipped_orders()
    assert version == "2.5.0"
    manifest = json.loads(
        (ROOT / "update-manifest.json").read_text())
    import hashlib
    assert manifest["files"]["agentlink/STANDING-ORDERS.md"] \
        == hashlib.sha256(raw).hexdigest()


# ------------------------------------------------- destination

def test_no_env_destination_left_in_stock_client():
    """The defect shape, swept: no env-configured deposit URL,
    no shared archive token, no Firebase function destination,
    no env-based depositor resolution in the stock client."""
    for name in ("client.py", "dossier.py", "transport_v2.py"):
        src = (ROOT / "agentlink" / name).read_text()
        assert "AGENTLINK_ARCHIVE_TOKEN" not in src, name
        assert "cloudfunctions.net" not in src, name
    client_src = (ROOT / "agentlink" / "client.py").read_text()
    assert "AGENTLINK_ARCHIVE_URL" not in client_src
    assert "ARCHIVE_SERVICE_URL_DEFAULT" not in client_src
    assert "auto_accept_orders" in client_src
    dossier_src = (ROOT / "agentlink" / "dossier.py").read_text()
    assert "resolve_depositor" not in dossier_src
    assert "platform_depositor" in dossier_src
    assert "AGENTLINK_DOSSIER_DRIVE_ROOT" not in dossier_src


class _FakeTransport:
    """The platform route in miniature: deposit_record is the
    transport's own-identity deposit call."""

    def __init__(self, fail=False):
        self.deposits = []
        self.fail = fail

    def deposit_record(self, record):
        if self.fail:
            raise RuntimeError("deposit route down")
        self.deposits.append(record)
        return {"confirmed": True, "inbox_id": len(self.deposits)}


def _generate(tmp_path, ident, version="2.5.1"):
    return dm.generate(
        tmp_path, signer=ident.sign, username="dossierdrill",
        display_name="", registered_at=1,
        client_version=version,
        sign_pub_b64=ident.signing_public_key_b64,
        nature_profile=None,
        standing={"grade": "BEATING", "nature_compliant": True,
                  "open_work_count": 0, "nature_version": 1,
                  "last_daemon_receipt_at": NOW,
                  "last_runtime_proof_at": NOW},
        now=NOW)


def test_platform_depositor_rides_own_transport(tmp_path):
    from agentlink.crypto import Identity
    ident = Identity("dossierdrill", tmp_path / "id")
    _generate(tmp_path, ident)
    transport = _FakeTransport()
    dep = dm.platform_depositor(transport, "dossierdrill")
    out = dm.drain_queue(tmp_path, dep, now=NOW)
    assert out["deposited"] == [1]
    assert len(transport.deposits) == 1
    record = transport.deposits[0]
    assert record["kind"] == "dossier"
    assert record["agent"] == "dossierdrill"
    import base64
    doc = json.loads(base64.b64decode(record["files"]
                                      ["DOSSIER.json"]))
    assert doc["username"] == "dossierdrill"
    assert dm.verify_dossier_signature(
        doc, ident.signing_public_key_b64)
    assert dm.dossier_status(tmp_path, 1, NOW) == "current"


def test_failed_deposit_is_loud_not_silent(tmp_path):
    from agentlink.crypto import Identity
    ident = Identity("dossierdrill", tmp_path / "id")
    _generate(tmp_path, ident)
    dep = dm.platform_depositor(_FakeTransport(fail=True),
                                "dossierdrill")
    out = dm.drain_queue(tmp_path, dep, now=NOW)
    assert out["deposited"] == []
    assert out["pending"] == [1]
    # the flag every surface carries: NOT current — visible,
    # never dressed as a quiet local park
    assert dm.dossier_status(tmp_path, 1, NOW) != "current"


def test_transport_deposit_record_requires_confirmation():
    from agentlink.transport_v2 import (
        ServerlessConfig, ServerlessTransport, TransportError)
    cfg = ServerlessConfig(
        supabase_url="http://sandbox.invalid",
        anon_key="anon",
        login_edge_url="http://sandbox.invalid/functions/v1/"
                       "agentlink-login")
    transport = ServerlessTransport(cfg)
    transport.username = "dossierdrill"
    transport._signer = lambda payload: b"x"  # noqa: E731
    transport._fn_post = lambda name, route, payload: {}
    try:
        transport.deposit_record({"kind": "dossier"})
        raise AssertionError("unconfirmed deposit accepted")
    except TransportError:
        pass
    transport._fn_post = lambda name, route, payload: {
        "confirmed": True, "inbox_id": 7}
    out = transport.deposit_record({"kind": "dossier"})
    assert out["inbox_id"] == 7


def test_archive_deposit_sync_uses_platform_route(
        tmp_path, monkeypatch):
    """Message deposits ride the same built-in route — even
    with the retired env destination SET (poisoned), the stock
    path must not consult it."""
    from agentlink.client import Agent
    agent = Agent("amy", state_dir=str(tmp_path / "state"),
                  mode="manual")
    fake = _FakeTransport()
    agent._v2 = fake
    monkeypatch.setenv("AGENTLINK_ARCHIVE_URL",
                       "https://example.invalid/old-route")
    monkeypatch.setenv("AGENTLINK_ARCHIVE_TOKEN", "shared-token")
    monkeypatch.delenv("AGENTLINK_ARCHIVE_LOCAL_DIR",
                       raising=False)
    record = {"message_id": "m1",
              "conversation_id": "dm:amy:bob",
              "participants": ["amy", "bob"], "sender": "amy",
              "kind": "dm",
              "oversight": {"alg": "x", "ct": "zz"},
              "oversight_kind": "content", "mode": "standard",
              "ts": NOW}
    conf = agent._archive_deposit_sync(record)
    assert conf["confirmed"] is True
    assert len(fake.deposits) == 1
    assert fake.deposits[0]["message_id"] == "m1"


def test_dossier_client_version_refresh(tmp_path):
    from agentlink.crypto import Identity
    ident = Identity("dossierdrill", tmp_path / "id")
    _generate(tmp_path, ident, version="2.5.0")
    assert dm.needs_refresh(tmp_path, 1, NOW + 60,
                            client_version="2.5.0") is False
    assert dm.needs_refresh(tmp_path, 1, NOW + 60,
                            client_version="2.5.1") is True


# ------------------------------------------------- platform side

def test_migration_v214_and_deposit_edge_pins():
    sql = (ROOT / "supabase"
           / "migration-v214-deposit-inbox.sql").read_text()
    assert "al_deposit_inbox" in sql
    assert "al_deposit_inbox_key_uq" in sql
    assert "enable row level security" in sql
    edge = (ROOT / "supabase" / "functions" / "agentlink-deposit"
            / "index.ts").read_text()
    assert "verifyAgentJwt" in edge
    assert "verifyEd25519" in edge
    assert "al_deposit_inbox" in edge
    assert "agentlink-dossier/1" in edge
    assert "sender_mismatch" in edge
    assert "plaintext_refused" in edge
    assert "confirmed" in edge


# ------------------------------------------------- centerpiece

class _FakeV2:
    """A whole platform in miniature for the centerpiece pin:
    liveness status, registry reads, the dossier flag report,
    and the deposit inbox — every call the daemon's start-path
    duties make, and nothing else."""

    def __init__(self):
        self.deposits = []
        self.dossier_reports = []

    def liveness_status(self):
        return {"nature_version": 1,
                "nature": {"persistence_class": "persistent"},
                "grade": "BEATING",
                "last_daemon_receipt_at": NOW,
                "last_runtime_proof_at": NOW}

    def _rest(self, method, table, query=""):
        if table == "al_work":
            return []
        if table == "al_users":
            return [{"created_at": NOW - 1000,
                     "display_name": ""}]
        return []

    def report_dossier_status(self, status, deposited_at,
                              version):
        self.dossier_reports.append((status, deposited_at,
                                     version))
        return {"reported": True}

    def deposit_record(self, record):
        self.deposits.append(record)
        return {"confirmed": True,
                "inbox_id": len(self.deposits)}


def test_centerpiece_fresh_agent_zero_interaction(
        tmp_path, monkeypatch):
    """A fresh client, given only a username + its own network
    config (here: the bound transport), completes its platform
    duties with ZERO interactive steps: orders accepted by the
    start machinery, dossier generated + deposited + reported
    current by the start-path maintenance. No ack command is
    invoked anywhere in this test — that is the point."""
    from agentlink.client import Agent
    from agentlink.crypto import Identity
    state = tmp_path / "state"
    state.mkdir(parents=True)
    agent = Agent("freshagent", state_dir=str(state),
                  mode="manual")
    agent.identity = Identity("freshagent", state / "id")
    fake = _FakeV2()
    agent._v2 = fake

    async def _fake_start_serverless(self):
        return "serverless"

    monkeypatch.setattr(Agent, "_start_serverless",
                        _fake_start_serverless)
    asyncio.run(agent.start())  # orders leg: real start() path
    st = orders_state(state)
    assert st["platform_accepted"] is True
    assert st["inscribed"] is False

    out = agent._dossier_maintain("start")  # dossier leg
    assert out["status"] == "current"
    assert len(fake.deposits) == 1
    assert fake.deposits[0]["kind"] == "dossier"
    assert fake.dossier_reports
    assert fake.dossier_reports[-1][0] == "current"
