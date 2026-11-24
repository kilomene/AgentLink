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

v2.6.1 (Fix 2): register / recovery / rectify ALWAYS perform
the key possession handshake first (login Edge method
``key_challenge``) and attach ``key_proof``. The fake Edge
below answers the challenge with a real envelope sealed to
the candidate pubkey, so the proof the transport attaches is
a genuine one and its signature verifies against the
candidate signing key.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentlink.crypto import Identity, encrypt_to_pubkey  # noqa: E402
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
        if route == "key_challenge":
            # A genuine challenge: seal the nonce to the
            # candidate pubkey exactly as the login Edge does.
            envelope = encrypt_to_pubkey(
                payload["candidate_pubkey"],
                json.dumps({"nonce": "n-1", "challenge_id": "ch-1",
                            "username": payload["username"]}).encode())
            return {"challenge_id": "ch-1", "envelope": envelope}
        if error is not None:
            raise error
        return reply or {"ok": True}

    t._edge_post = _edge
    t._adopt_tokens = lambda username, r: {"username": username}
    t.start_activeness = lambda: None
    return t


def _identity(tmp_path, name="newagent"):
    return Identity(name, tmp_path / "state")


def _proof_of(captured, route):
    payloads = [p for r, p in captured if r == route]
    assert payloads, f"no {route} call captured"
    proof = payloads[0].get("key_proof")
    assert proof, f"{route} carries no key_proof"
    return proof


def test_register_carries_grant_when_supplied(tmp_path):
    cap = []
    t = _transport(cap)
    ident = _identity(tmp_path)
    t.register_and_login("newagent", ident.sign,
                         ident.signing_public_key_b64,
                         ident.public_key_b64,
                         provisioning_grant="grant-token-123",
                         identity=ident)
    route, payload = [c for c in cap if c[0] == "register"][0]
    assert route == "register"
    assert payload["provisioning_grant"] == "grant-token-123"
    proof = _proof_of(cap, "register")
    assert proof["challenge_id"] == "ch-1"
    assert proof["nonce"] == "n-1"
    assert Identity.verify_signature(
        ident.signing_public_key_b64,
        b"agentlink-key-proof-v1:ch-1:n-1",
        proof["signature"])


def test_register_omits_grant_when_not_supplied(tmp_path):
    cap = []
    t = _transport(cap)
    ident = _identity(tmp_path)
    t.register_and_login("newagent", ident.sign,
                         ident.signing_public_key_b64,
                         ident.public_key_b64, identity=ident)
    _route, payload = [c for c in cap if c[0] == "register"][0]
    assert "provisioning_grant" not in payload
    _proof_of(cap, "register")


def test_reclaim_never_carries_grant(tmp_path):
    cap = []
    t = _transport(cap)
    ident = _identity(tmp_path, "oldagent")
    t.recover_and_login("oldagent", ident.sign,
                        "the-recovery-key",
                        ident.signing_public_key_b64,
                        ident.public_key_b64, identity=ident)
    route, payload = [c for c in cap if c[0] == "recovery"][0]
    assert route == "recovery"
    assert "provisioning_grant" not in payload
    proof = _proof_of(cap, "recovery")
    assert proof["challenge_id"] == "ch-1"
    assert Identity.verify_signature(
        ident.signing_public_key_b64,
        b"agentlink-key-proof-v1:ch-1:n-1",
        proof["signature"])


def test_grant_refusal_fault_propagates_verbatim(tmp_path):
    cap = []
    err = TransportError(
        "login Edge register HTTP 403: provisioning_grant_required")
    t = _transport(cap, error=err)
    ident = _identity(tmp_path)
    with pytest.raises(TransportError) as ei:
        t.register_and_login("newagent", ident.sign,
                             ident.signing_public_key_b64,
                             ident.public_key_b64, identity=ident)
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
