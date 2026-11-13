"""v2.6.0 — PROVISIONING GRANT, client half (SPEC Part 2).

The server gates NEW-username registration on a one-time
provisioning grant. The client's duties, pinned here:

* when a grant is supplied (explicit / env / workspace drop-in,
  resolved in that order — the rectification code's shape), the
  registration request carries it as ``provisioning_grant``;
* when none is supplied, the registration request is unchanged
  (no key at all);
* the recovery reclaim NEVER carries a grant (gate exemption);
* a server refusal's named fault (provisioning_grant_required
  and friends) propagates verbatim — never swallowed.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentlink.transport_v2 import (ServerlessTransport,  # noqa: E402
                                    TransportError)


def _transport(captured, reply=None, error=None):
    t = ServerlessTransport.__new__(ServerlessTransport)
    t.username = ""
    t._decision_link = ""
    t._decision_detail = None
    t.client_version = ""

    def _pre(username, signer, client_version="",
             decision_link=None, decision_link_detail=None):
        t.username = username

    t._session_preamble = _pre

    def _edge(route, payload):
        captured.append((route, dict(payload)))
        if error is not None:
            raise error
        return reply or {"ok": True}

    t._edge_post = _edge
    t._adopt_tokens = lambda username, r: {"username": username}
    t.start_activeness = lambda: None
    return t


def test_register_carries_grant_when_supplied():
    cap = []
    t = _transport(cap)
    t.register_and_login("newagent", lambda b: "c2ln", "SP", "PK",
                         provisioning_grant="grant-token-123")
    route, payload = cap[0]
    assert route == "register"
    assert payload["provisioning_grant"] == "grant-token-123"


def test_register_omits_grant_when_not_supplied():
    cap = []
    t = _transport(cap)
    t.register_and_login("newagent", lambda b: "c2ln", "SP", "PK")
    _route, payload = cap[0]
    assert "provisioning_grant" not in payload


def test_reclaim_never_carries_grant():
    cap = []
    t = _transport(cap)
    t.recover_and_login("oldagent", lambda b: "c2ln",
                        "the-recovery-key", "SP", "PK")
    route, payload = cap[0]
    assert route == "recovery"
    assert "provisioning_grant" not in payload


def test_grant_refusal_fault_propagates_verbatim():
    cap = []
    err = TransportError(
        "login Edge register HTTP 403: provisioning_grant_required")
    t = _transport(cap, error=err)
    with pytest.raises(TransportError) as ei:
        t.register_and_login("newagent", lambda b: "c2ln",
                             "SP", "PK")
    assert "provisioning_grant_required" in str(ei.value)


def test_grant_resolution_order(tmp_path, monkeypatch):
    from agentlink.client import Agent
    a = Agent.__new__(Agent)
    a.ephemeral = False
    a.username = "newagent"
    a.workspace = tmp_path
    a._provisioning_grant_manual = None
    monkeypatch.delenv("AGENTLINK_PROVISIONING_GRANT",
                       raising=False)
    assert a._find_provisioning_grant() is None
    # workspace drop-in file
    (tmp_path / "agentlink-provisioning-newagent.txt").write_text(
        "provisioning_grant: file-token\n")
    assert a._find_provisioning_grant() == "file-token"
    # env beats the file
    monkeypatch.setenv("AGENTLINK_PROVISIONING_GRANT", "env-token")
    assert a._find_provisioning_grant() == "env-token"
    # explicit beats both
    a._provisioning_grant_manual = "flag-token"
    assert a._find_provisioning_grant() == "flag-token"


def test_client_first_contact_wires_the_grant():
    src = (ROOT / "agentlink" / "client.py").read_text()
    assert "provisioning_grant=(" in src
    assert "_find_provisioning_grant" in src
    # the refusal branch surfaces the named fault + support door
    assert "serverless_registration_refused" in src
    assert "support lodge" in src
    # reclaim call site in client.py passes no grant
    rec = src[src.index("v2.recover_and_login"):]
    rec = rec[:rec.index(")", 200) + 1]
    assert "provisioning_grant" not in rec
