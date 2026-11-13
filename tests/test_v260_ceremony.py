"""v2.6.0 — ATTENDED INSTALL CEREMONY (SPEC Part 3).

Pins:
  * the nine steps run IN ORDER, each landing a receipt in
    ceremony-state.json; receipts 1-2 are unsigned
    ("pre-identity"), receipts from step 3 on are signed with
    the agent's identity key and verify;
  * a failure at step k halts with the named fault, steps > k
    never run, and the halt is notified to the operator surface;
  * resume starts at the failed step (landed steps are
    verified, never re-executed);
  * no skip path: a forged state claiming later steps landed
    is detected by the receipt signature check and halts the
    ceremony before anything executes;
  * step 8 refuses a non-stock platform verdict;
  * the ceremony module carries NO machine detection (the
    retired spec machinery stays retired);
  * the CLI shapes: `agentlink install` exits 0 only on a
    complete ceremony; `agentlink operator provisioning
    issue` prints the raw token exactly once.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentlink import ceremony  # noqa: E402
from agentlink.ceremony import CeremonyFault, CeremonyRunner  # noqa: E402
from agentlink.crypto import Identity  # noqa: E402
from agentlink.liveness import canonical_json  # noqa: E402

USERNAME = "ceremonyagent"


class FakeOps(ceremony.CeremonyOps):
    """A whole platform in miniature (the test_v251 fake
    pattern): a shared `platform` dict is the record the
    resume checks verify against, so a second FakeOps over
    the same platform + state dir resumes truthfully."""

    def __init__(self, username, state_dir,
                 provisioning_grant=None, designation="production",
                 platform=None, fail_at=None,
                 fail_fault="step_failed:FakeBoom"):
        self.username = username
        self.state_dir = Path(state_dir)
        self.grant = provisioning_grant
        self.platform = platform if platform is not None else {
            "registered": False, "recovery": False,
            "orders": False, "nature": False,
            "integrity": "stock", "deposited": False}
        self.fail_at = fail_at
        self.fail_fault = fail_fault
        self.calls: list[int] = []
        self.notices: list[str] = []
        self._identity = None

    # plumbing
    def _keys_path(self):
        return self.state_dir / f"keys-{self.username}.json"

    def identity(self):
        if not self._keys_path().exists():
            return None
        if self._identity is None:
            self._identity = Identity(self.username, self.state_dir)
        return self._identity

    def notify(self, state, event):
        self.notices.append(event)
        return {"ticket_id": "fake-ticket-1", "kind": event}

    def verify_step(self, step, receipt):
        p = self.platform
        return {1: True,
                2: (self.state_dir / "network.json").exists(),
                3: self._keys_path().exists(),
                4: p["registered"], 5: p["recovery"],
                6: p["orders"], 7: p["nature"],
                8: p["integrity"] == "stock",
                9: p["deposited"]}[step]

    def _act(self, step):
        self.calls.append(step)
        if self.fail_at == step:
            raise CeremonyFault(self.fail_fault, "injected fault")

    # the nine acts
    def step_env_check(self):
        self._act(1)
        return {"python_ok": True, "state_dir_writable": True,
                "clock_sane": True, "stored_as_spec": False}

    def step_network(self):
        self._act(2)
        (self.state_dir / "network.json").write_text("{}")
        return {"proven": True, "direct": True}

    def step_key_generation(self):
        self._act(3)
        self._identity = Identity(self.username, self.state_dir)
        from agentlink.dossier import key_fingerprint
        return {"keys_file": self._keys_path().name,
                "sign_key_fingerprint": key_fingerprint(
                    self._identity.signing_public_key_b64)}

    def step_registration(self):
        self._act(4)
        self.platform["registered"] = True
        return {"registered": True,
                "provisioning_grant_presented": bool(self.grant)}

    def step_recovery(self):
        self._act(5)
        self.platform["recovery"] = True
        return {"hash_registered": True,
                "possession": "server_hash_match"}

    def step_orders(self):
        self._act(6)
        self.platform["orders"] = True
        return {"installed": True, "platform_accepted": True,
                "accepted_by": "daemon-machinery",
                "runtime_inscription": "pending — the runtime's "
                                       "own act"}

    def step_nature(self):
        self._act(7)
        self.platform["nature"] = True
        return {"declared": True}

    def step_liveness_attestation(self):
        self._act(8)
        if self.platform["integrity"] != "stock":
            raise CeremonyFault(
                f"attestation_not_stock:{self.platform['integrity']}",
                "platform verdict is not stock")
        return {"runtime_proved": True, "build_integrity": "stock"}

    def step_dossier(self):
        self._act(9)
        self.platform["deposited"] = True
        return {"schema": "agentlink-dossier/2",
                "deposited": [1], "status": "current"}


def _run(tmp_path, ops=None, **kw):
    sd = tmp_path / "state"
    ops = ops or FakeOps(USERNAME, sd, **kw)
    state = CeremonyRunner(USERNAME, sd, ops).run()
    return state, ops, sd


# ---------------------------------------------------------- happy path

def test_steps_run_in_order_and_complete(tmp_path):
    state, ops, sd = _run(tmp_path, provisioning_grant="tok-1")
    assert ops.calls == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert state["complete"] is True
    assert state["fault"] is None
    assert ops.notices == ["ceremony_complete"]
    # the state on disk reads complete too (operator surface)
    on_disk = ceremony.load_state(sd)
    assert on_disk["complete"] is True
    receipts = on_disk["receipts"]
    assert [r["step"] for r in receipts] == list(range(1, 10))
    assert [r["name"] for r in receipts] == \
        [name for _n, name in ceremony.STEPS]
    assert all(r["ok"] for r in receipts)


def test_receipt_signing_shape(tmp_path):
    state, ops, _sd = _run(tmp_path)
    receipts = state["receipts"]
    # steps 1-2: pre-identity, unsigned, noted as such
    for r in receipts[:2]:
        assert r["sig"] is None
        assert r["note"] == "pre-identity"
    # steps 3+: signed with the identity key, and the
    # signatures verify over the canonical receipt body
    pub = ops.identity().signing_public_key_b64
    for r in receipts[2:]:
        assert r["sig"]
        assert Identity.verify_signature(
            pub, canonical_json(ceremony.receipt_body(r)).encode(),
            r["sig"])


# ---------------------------------------------------------- halt + resume

def test_failure_halts_with_named_fault(tmp_path):
    state, ops, _sd = _run(
        tmp_path, fail_at=4,
        fail_fault="grant_refused:provisioning_grant_expired")
    assert state["complete"] is False
    assert state["failed_step"] == 4
    assert state["fault"] == \
        "grant_refused:provisioning_grant_expired"
    # steps past the failure never ran
    assert ops.calls == [1, 2, 3, 4]
    assert ops.notices == ["ceremony_halt"]
    # the failed step's receipt is on record, marked not-ok
    failed = [r for r in state["receipts"] if not r["ok"]]
    assert len(failed) == 1 and failed[0]["step"] == 4
    assert failed[0]["detail"]["fault"] == \
        "grant_refused:provisioning_grant_expired"


def test_resume_starts_at_failed_step(tmp_path):
    sd = tmp_path / "state"
    platform = None
    ops1 = FakeOps(USERNAME, sd, fail_at=5,
                   fail_fault="recovery_key_missing")
    state1 = CeremonyRunner(USERNAME, sd, ops1).run()
    assert state1["failed_step"] == 5
    platform = ops1.platform
    # second run: fresh ops over the SAME platform + state dir
    ops2 = FakeOps(USERNAME, sd, platform=platform)
    state2 = CeremonyRunner(USERNAME, sd, ops2).run()
    assert state2["complete"] is True
    # steps 1-4 were verified from the record, NOT re-executed
    assert ops2.calls == [5, 6, 7, 8, 9]
    assert ops2.notices == ["ceremony_complete"]


def test_completed_ceremony_rerun_is_a_noop(tmp_path):
    state, ops, sd = _run(tmp_path)
    assert state["complete"] is True
    ops2 = FakeOps(USERNAME, sd, platform=ops.platform)
    state2 = CeremonyRunner(USERNAME, sd, ops2).run()
    assert state2["complete"] is True
    assert ops2.calls == []  # everything verified, nothing re-ran


# ---------------------------------------------------------- no skip path

def test_forged_state_is_detected_and_halts(tmp_path):
    sd = tmp_path / "state"
    sd.mkdir(parents=True)
    Identity(USERNAME, sd)  # real keys, forged receipts
    receipts = []
    for step, name in ceremony.STEPS:
        receipts.append({
            "step": step, "name": name, "ts": 1794500000,
            "ok": True, "detail": {"forged": True},
            "sig": None if step < 3 else "Zm9yZ2Vk"})
    (sd / "ceremony-state.json").write_text(json.dumps({
        "kind": ceremony.CEREMONY_KIND, "version": 1,
        "username": USERNAME, "complete": True,
        "receipts": receipts}))
    ops = FakeOps(USERNAME, sd)
    state = CeremonyRunner(USERNAME, sd, ops).run()
    assert state["complete"] is False
    assert state["fault"] == "state_signature_invalid"
    assert ops.calls == []  # nothing executed on a forged state


def test_gapped_state_is_detected(tmp_path):
    sd = tmp_path / "state"
    ops = FakeOps(USERNAME, sd)
    # land steps 1-3 for real, then hand-edit a step-9 receipt
    # out of sequence (unsigned steps can't fake a gap away)
    state = CeremonyRunner(USERNAME, sd,
                           FakeOps(USERNAME, sd, fail_at=4)).run()
    assert state["failed_step"] == 4
    raw = json.loads((sd / "ceremony-state.json").read_text())
    raw["receipts"] = [r for r in raw["receipts"] if r["ok"]]
    raw["receipts"].append({"step": 9, "name": "dossier",
                             "ts": 1794500000, "ok": True,
                             "detail": {}, "sig": "Zm9yZ2Vk"})
    (sd / "ceremony-state.json").write_text(json.dumps(raw))
    state2 = CeremonyRunner(USERNAME, sd, ops).run()
    assert state2["complete"] is False
    assert state2["fault"] in ("state_gap",
                               "state_signature_invalid")
    assert ops.calls == []


# ---------------------------------------------------------- step 8 verdict

def test_attestation_not_stock_fails_step_8(tmp_path):
    platform = {"registered": False, "recovery": False,
                "orders": False, "nature": False,
                "integrity": "modified", "deposited": False}
    state, ops, _sd = _run(tmp_path, platform=platform)
    assert state["complete"] is False
    assert state["failed_step"] == 8
    assert state["fault"] == "attestation_not_stock:modified"
    assert 9 not in ops.calls


# ---------------------------------------------------------- gate pins

def test_ceremony_module_has_no_machine_detection():
    src = (ROOT / "agentlink" / "ceremony.py").read_text()
    assert "detect_machine" not in src
    assert "psutil" not in src
    assert "import platform" not in src
    # the env check records booleans only — no snapshot fields
    assert "stored_as_spec" in src


def test_step_order_is_the_specs():
    assert [n for _s, n in ceremony.STEPS] == [
        "env-check", "network", "key-generation", "registration",
        "recovery", "orders", "nature", "liveness-attestation",
        "dossier"]


# ---------------------------------------------------------- CLI shapes

def test_cli_install_exit_zero_only_when_complete(
        tmp_path, monkeypatch, capsys):
    from agentlink import cli
    sd = tmp_path / "state"
    monkeypatch.setattr(ceremony, "RealOps", FakeOps)
    rc = cli.main(["install", "--username", USERNAME,
                   "--provisioning-grant", "tok-1",
                   "--state-dir", str(sd)])
    assert rc == 0
    rc = cli.main(["install", "--status", "--username", USERNAME,
                   "--state-dir", str(sd)])
    assert rc == 0


def test_cli_install_halt_exits_nonzero(tmp_path, monkeypatch):
    from agentlink import cli
    sd = tmp_path / "state"

    def _factory(username, state_dir, **kw):
        return FakeOps(username, state_dir, fail_at=2,
                       fail_fault="PROXY/no_egress_proven")

    monkeypatch.setattr(ceremony, "RealOps", _factory)
    rc = cli.main(["install", "--username", USERNAME,
                   "--provisioning-grant", "tok-1",
                   "--state-dir", str(sd)])
    assert rc == 1
    rc = cli.main(["install", "--status", "--username", USERNAME,
                   "--state-dir", str(sd)])
    assert rc == 1  # state exists, ceremony not complete


def test_cli_operator_issue_prints_token_once(
        tmp_path, monkeypatch, capsys):
    from agentlink import cli, operator
    monkeypatch.setattr(
        operator, "provisioning_issue",
        lambda username, ttl_hours=None: {
            "ok": True, "grant_id": "g-1", "username": username,
            "expires_at": 1794600000,
            "provisioning_grant": "raw-token-xyz"})
    rc = cli.main(["operator", "provisioning", "issue",
                   "--username", "newagent"])
    assert rc == 0
    out = capsys.readouterr().out
    assert out.count("raw-token-xyz") == 1


def test_cli_operator_revoke(tmp_path, monkeypatch, capsys):
    from agentlink import cli, operator
    seen = {}
    monkeypatch.setattr(
        operator, "provisioning_revoke",
        lambda username=None, grant_id=None:
            seen.update({"u": username, "g": grant_id})
            or {"ok": True, "revoked": 2})
    rc = cli.main(["operator", "provisioning", "revoke",
                   "--username", "newagent"])
    assert rc == 0
    assert seen == {"u": "newagent", "g": None}
    assert '"revoked": 2' in capsys.readouterr().out


def test_operator_credential_missing_is_named(monkeypatch):
    from agentlink import operator
    monkeypatch.delenv("AGENTLINK_OPERATOR_TOKEN", raising=False)
    with pytest.raises(operator.OperatorError) as ei:
        operator.provisioning_issue("newagent")
    assert ei.value.code == "operator_credential_missing"
