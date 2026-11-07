"""v2.0.8 — the registration door and the first-contact suite.

Two halves, pinned separately:

* The login Edge's ``register`` method (static pins on the
  shipped TypeScript): first-come claim of an unheld name, the
  recovery key returned ONCE and stored only as its SHA-256,
  a taken name refused with ``username_taken`` and nothing
  written, key material validated like the recovery rebind.

* The client's first-contact suite (client.py
  ``_serverless_first_contact``): when the key login refuses
  with key_auth_failed, a held recovery key reclaims FIRST, a
  free name registers, a taken name with no key is the only
  permanent refusal — and weather never poses as an identity
  verdict. The suite separates "no account" from "not your
  keys" by acting, never by guessing.
"""

import asyncio
import json
from pathlib import Path

import pytest

from agentlink import __version__
from agentlink.client import Agent, RegistrationFailed
from agentlink.transport_v2 import TransportError

ROOT = Path(__file__).resolve().parent.parent
FN_DIR = ROOT / "supabase" / "functions"


def _fn(name):
    return (FN_DIR / name / "index.ts").read_text()


# ------------------------------------------------------------ Edge pins

def _register_block(src):
    start = src.index('if (method === "register")')
    end = src.index('if (method === "unknown_method"', start) \
        if 'if (method === "unknown_method"' in src[start:] else None
    # the unknown-method return follows the register branch
    tail = src.index('return errorResponse(\n      "unknown_method"', start)
    return src[start:tail]


def test_login_edge_register_method_contract():
    src = _fn("agentlink-login")
    assert 'register: 10' in src  # its own rate-limit bucket
    block = _register_block(src)
    # first-come: existence is checked and a held name refuses
    assert "username_taken" in block
    assert "409" in block
    # key material validated exactly like the recovery rebind
    assert "isRawKey32(signPub)" in block
    assert "isRawKey32(pubkey)" in block
    # the account row is inserted with the issued key's HASH only
    assert "insertRow" in block
    assert "recovery_hash: await sha256Hex(newRecoveryKey)" in block
    # ... and the key itself is returned exactly once, in the reply
    assert block.count("recovery_key: newRecoveryKey") == 1
    assert "issueTokens" in block
    # designation honored at registration (v1.6.0 contract)
    assert 'body.designation === "test"' in block
    # the method router knows the new method
    assert "challenge, verify, recovery or register" in src


def test_login_edge_register_never_stores_plaintext_key():
    block = _register_block(_fn("agentlink-login"))
    row_at = block.index("const row")
    insert_at = block.index("insertRow")
    stored = block[row_at:insert_at]
    # the stored row carries the hash, never the key itself
    assert "recovery_hash" in stored
    assert "recovery_key" not in stored


def test_username_rules_match_protocol():
    # The Edge normalizes with the shared module's mirror of
    # protocol.normalize_username; the Python contract is the
    # source both sides quote.
    from agentlink.protocol import normalize_username
    assert normalize_username("@Folk_App") == "folk_app"
    assert normalize_username("bad name!") is None
    shared = (FN_DIR / "_shared" / "v200.ts").read_text()
    assert "normalizeUsername" in shared


# ------------------------------------------------------- client suite

class FakeV2:
    """A scripted stand-in for the v2 transport's ceremonies."""

    def __init__(self, script):
        self.script = script  # method name -> ("ok", key) | ("raise", text)
        self.calls = []

    def _act(self, name, args):
        self.calls.append((name, args))
        kind, value = self.script[name]
        if kind == "raise":
            raise TransportError(value)
        return {"username": args[0], "recovery_key": value}

    def recover_and_login(self, *args, **kw):
        return self._act("recover", args)

    def register_and_login(self, *args, **kw):
        return self._act("register", args)


def _agent(tmp_path):
    return Agent(username="newagent", state_dir=str(tmp_path / "state"),
                 workspace=str(tmp_path / "ws"), transport="serverless",
                 mode="manual")


def _run(agent, v2):
    return asyncio.run(agent._serverless_first_contact(v2))


def test_first_contact_registers_free_name_and_saves_key(tmp_path):
    agent = _agent(tmp_path)
    v2 = FakeV2({"register": ("ok", "issued-key-1")})
    assert _run(agent, v2) is True
    assert [c[0] for c in v2.calls] == ["register"]
    # the issued key landed under the storage contract: the
    # workspace copy exists and carries it
    ws_file = tmp_path / "ws" / "agentlink-recovery-newagent.txt"
    assert ws_file.exists()
    assert "issued-key-1" in ws_file.read_text()


def test_first_contact_taken_name_is_the_only_refusal(tmp_path):
    agent = _agent(tmp_path)
    v2 = FakeV2({"register": (
        "raise", "login Edge register HTTP 409: username_taken")})
    assert _run(agent, v2) is False
    assert [c[0] for c in v2.calls] == ["register"]


def test_first_contact_reclaims_with_held_key_before_register(tmp_path):
    agent = _agent(tmp_path)
    agent._save_recovery_key("held-key-1")  # both storage copies
    v2 = FakeV2({"recover": ("ok", "successor-key-2"),
                 "register": ("ok", "must-not-be-used")})
    assert _run(agent, v2) is True
    assert [c[0] for c in v2.calls] == ["recover"]
    # the reclaim presented the held key ...
    assert v2.calls[0][1][2] == "held-key-1"
    # ... and the successor replaced it in the workspace copy
    ws_file = tmp_path / "ws" / "agentlink-recovery-newagent.txt"
    assert "successor-key-2" in ws_file.read_text()
    assert "held-key-1" not in ws_file.read_text()


def test_first_contact_manual_key_refusal_is_final(tmp_path):
    agent = Agent(username="newagent", state_dir=str(tmp_path / "state"),
                  workspace=str(tmp_path / "ws"), transport="serverless",
                  mode="manual", recovery_key="wrong-key")
    v2 = FakeV2({"recover": (
                     "raise", "login Edge recovery HTTP 401: recovery_failed"),
                 "register": ("ok", "must-not-be-used")})
    with pytest.raises(RegistrationFailed):
        _run(agent, v2)
    # an explicitly handed-in key never falls through to a
    # registration attempt against the same name
    assert [c[0] for c in v2.calls] == ["recover"]


def test_first_contact_stale_discovered_key_falls_through(tmp_path):
    agent = _agent(tmp_path)
    agent._save_recovery_key("stale-key")
    v2 = FakeV2({"recover": (
                     "raise", "login Edge recovery HTTP 401: recovery_failed"),
                 "register": (
                     "raise", "login Edge register HTTP 409: username_taken")})
    # discovered-but-dead key: register gives the truthful answer
    assert _run(agent, v2) is False
    assert [c[0] for c in v2.calls] == ["recover", "register"]


def test_first_contact_weather_is_never_an_identity_verdict(tmp_path):
    agent = _agent(tmp_path)
    v2 = FakeV2({"register": (
        "raise", "login Edge register HTTP 405: method_not_allowed")})
    with pytest.raises(ConnectionError):
        _run(agent, v2)


def test_version_208():
    assert __version__ == "2.0.8"
