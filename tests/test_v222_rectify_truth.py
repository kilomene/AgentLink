"""2.2.2 — rectify truthfulness.

The @lean false success: `agentlink rectify` printed
{"rectified": true, "the code is burned — the NEW recovery
key is saved..."} for a run whose ceremony never presented
the code at all. Lean's keys were fine (only his recovery
FILE was lost at registration — the designed use of an
operator rectify), so the self-collision rescue's plain key
login opened the session first, the CLI reported a burn +
rebind + fresh recovery key that never happened, and the
agent on the ground could not tell which of his runs did
what when a later, weather-bent run really did burn the
code.

Pinned here:

* EXPLICIT INTENT WINS — an agent built for the rectify
  command (rectify_intent) presents a held code BEFORE the
  key-login rescue, in the taken branch and at start() level
  (_explicit_rectify_open presents it before the plain login
  itself). The rescue keeps its exact role wherever no
  explicit rectify was invoked (the S-4 neighbors stay
  green untouched).
* THE RECORD — the agent records which ceremony opened the
  session (session_ceremony) and whether a code was
  presented; the CLI claims "rectified" ONLY for a run whose
  rectify_and_login the Edge accepted.
* THE REPORT — exit 0 rectified; exit 2 opened-but-not-
  rectified (code unused / outcome unconfirmed / no code
  held — the report's "outcome" + note say exactly which);
  exit 1 failure. A refused code never produces success
  language, and no recovery-key claims are made for runs
  that saved none.
"""

import asyncio
import json
from pathlib import Path

import pytest

from agentlink import cli
from agentlink.client import Agent, RegistrationFailed
from agentlink.transport_v2 import TransportError


@pytest.fixture(autouse=True)
def _no_env_code(monkeypatch):
    # a stray env code would outrank the drop-in under test
    monkeypatch.delenv("AGENTLINK_RECTIFY_CODE", raising=False)


class _CeremonyV2:
    """Scripted ceremonies incl. the plain login the rescue
    discriminates with, plus rectify-code capture."""

    def __init__(self, script):
        self.script = script  # method -> ("ok", key) | ("raise", text)
        self.calls = []
        self.rectify_codes = []

    def _act(self, name, args):
        self.calls.append(name)
        if name == "rectify":
            self.rectify_codes.append(args[2])
        kind, value = self.script[name]
        if kind == "raise":
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


_TAKEN = ("raise", "login Edge register HTTP 409: username_taken")
_REFUSED = ("raise", "login Edge rectify HTTP 401: rectify_failed")
_KEYFAIL = ("raise", "login Edge verify HTTP 401: key_auth_failed")


def _agent(tmp_path, *, intent=False, code=None, dropin=None,
           name="newagent"):
    ws = tmp_path / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    if dropin is not None:
        (ws / f"agentlink-rectify-{name}.txt").write_text(dropin)
    return Agent(username=name, state_dir=str(tmp_path / "state"),
                 workspace=str(ws), transport="serverless",
                 mode="manual", rectify_code=code,
                 rectify_intent=intent)


def _run(agent, v2):
    return asyncio.run(agent._serverless_first_contact(v2))


def _dropin(tmp_path, name="newagent"):
    return tmp_path / "ws" / f"agentlink-rectify-{name}.txt"


# ------------------------------------------------- (a) lean's case

def test_a_explicit_rectify_presents_code_before_rescue(tmp_path):
    # Lean's exact scenario: this machine's keys DO open the
    # account (the rescue's login succeeds), only the recovery
    # file was lost, and the operator issued a code. Under
    # 2.2.1 the rescue swallowed the run and the CLI printed
    # a false "rectified". Now the code goes first.
    agent = _agent(tmp_path, intent=True, dropin="op-code-lean\n")
    v2 = _CeremonyV2({"register": _TAKEN, "login": ("ok", ""),
                      "rectify": ("ok", "fresh-key-a")})
    assert _run(agent, v2) is True
    # the code was consulted BEFORE the rescue — the login
    # never ran at all
    assert v2.calls == ["register", "rectify"]
    assert v2.rectify_codes == ["op-code-lean"]
    assert agent.session_ceremony == "rectified"
    assert agent._rectify_presented is True
    # the NEW recovery key landed under BOTH contract paths
    assert "fresh-key-a" in Path(
        agent._recovery_state_path()).read_text()
    assert "fresh-key-a" in Path(
        agent._recovery_workspace_path()).read_text()
    # the spent drop-in is gone
    assert not _dropin(tmp_path).exists()


def test_a2_explicit_open_presents_code_before_plain_login(tmp_path):
    # The start()-level ceremony: with keys that would open
    # the account directly, the code is still presented FIRST
    # — a plain login is never even attempted.
    agent = _agent(tmp_path, intent=True, code="op-code-lean")
    v2 = _CeremonyV2({"rectify": ("ok", "fresh-key-a2"),
                      "login": ("ok", "")})
    assert asyncio.run(
        agent._explicit_rectify_open(v2, "op-code-lean")) is True
    assert v2.calls == ["rectify"]
    assert agent.session_ceremony == "rectified"


# ------------------------------------------------- (c) stranded

@pytest.mark.parametrize("intent", [False, True])
def test_c_stranded_classic_rectify_still_works(tmp_path, intent):
    # The original 2.0.9 case: the account is bound to keys
    # this machine does not hold; the code restores it.
    agent = _agent(tmp_path, intent=intent, code="op-code-c")
    v2 = _CeremonyV2({"register": _TAKEN, "login": _KEYFAIL,
                      "rectify": ("ok", "fresh-key-c")})
    assert _run(agent, v2) is True
    assert agent.session_ceremony == "rectified"
    if intent:
        assert v2.calls == ["register", "rectify"]
    else:
        # unchanged 2.2.0 order: rescue tried first, refused,
        # then the code
        assert v2.calls == ["register", "login", "rectify"]
    assert "fresh-key-c" in Path(
        agent._recovery_workspace_path()).read_text()


# ------------------------------------------------- (d) refused

def test_d_code_refused_suite_verdict_and_no_claims(tmp_path):
    agent = _agent(tmp_path, intent=True, dropin="dead-code\n")
    v2 = _CeremonyV2({"register": _TAKEN, "rectify": _REFUSED,
                      "login": _KEYFAIL})
    assert _run(agent, v2) is False
    assert agent.session_ceremony is None
    assert agent._rectify_presented is True
    # a refusal makes no claims on disk: the drop-in is left
    # in place and no recovery key was written anywhere
    assert _dropin(tmp_path).exists()
    assert not Path(agent._recovery_workspace_path()).exists()
    assert not Path(agent._recovery_state_path()).exists()


def test_d2_code_refused_is_a_final_refusal_at_open(tmp_path):
    agent = _agent(tmp_path, intent=True, code="dead-code")
    v2 = _CeremonyV2({"rectify": _REFUSED, "login": _KEYFAIL})
    with pytest.raises(RegistrationFailed):
        asyncio.run(agent._explicit_rectify_open(v2, "dead-code"))
    assert agent.session_ceremony is None


def test_d3_refused_code_but_keys_open_is_unconfirmed(tmp_path):
    # The weather-bent ambiguity from lean's incident: the
    # code was presented, the ceremony call refused (a first
    # attempt may have landed and burned it), and the key
    # login opened the session. Opened — but NOT rectified,
    # and the record must say so.
    agent = _agent(tmp_path, intent=True, code="maybe-burned")
    v2 = _CeremonyV2({"register": _TAKEN, "rectify": _REFUSED,
                      "login": ("ok", "")})
    assert _run(agent, v2) is True
    assert v2.calls == ["register", "rectify", "login"]
    assert agent.session_ceremony == "key-login"
    assert agent._rectify_presented is True


# --------------------------------------- (e) the rescue, unchanged

def test_e_rescue_unchanged_when_no_explicit_rectify(tmp_path):
    # A drop-in code merely lying in the workspace does NOT
    # reorder anything for ordinary starts: the 2.2.0
    # self-collision rescue still wins, the code is never
    # presented (and stays unburned, file in place).
    agent = _agent(tmp_path, intent=False, dropin="op-code-e\n")
    v2 = _CeremonyV2({"register": _TAKEN, "login": ("ok", ""),
                      "rectify": ("ok", "must-not-be-used")})
    assert _run(agent, v2) is True
    assert v2.calls == ["register", "login"]
    assert v2.rectify_codes == []
    assert agent.session_ceremony == "key-login"
    assert agent._rectify_presented is False
    assert _dropin(tmp_path).exists()


# ------------------------------------------------- the CLI report

class _StubAgent:
    """Stands in for cli.Agent: a start() that lands wherever
    the scenario says, and a whoami() carrying the ceremony
    record the real agent would have produced."""
    kwargs = None

    def __init__(self, username, **kw):
        _StubAgent.kwargs = kw
        self._username = username

    async def start(self):
        if type(self)._start_error is not None:
            raise type(self)._start_error

    def whoami(self):
        return dict(type(self)._whoami)

    async def close(self):
        pass


def _run_cli_rectify(monkeypatch, capsys, tmp_path, *,
                     whoami=None, start_error=None, extra=()):
    _StubAgent._whoami = whoami or {}
    _StubAgent._start_error = start_error
    monkeypatch.setattr(cli, "Agent", _StubAgent)
    rc = cli.main(["rectify", "--username", "@lean",
                   "--state-dir", str(tmp_path / "st"),
                   "--workspace", str(tmp_path / "ws"), *extra])
    out = capsys.readouterr().out
    return rc, json.loads(out)


_BASE_WHOAMI = {"username": "lean", "endpoint": "serverless",
                "recovery_file": None}


def test_b_cli_no_code_plain_login_reported_as_itself(
        monkeypatch, capsys, tmp_path):
    rc, report = _run_cli_rectify(
        monkeypatch, capsys, tmp_path,
        whoami=dict(_BASE_WHOAMI, session_ceremony="plain",
                    rectify_presented=False, rectify_code_held=False))
    # the CLI wired the explicit intent into the agent ...
    assert _StubAgent.kwargs["rectify_intent"] is True
    # ... and reported a plain login as a plain login
    assert rc == 2
    assert report["rectified"] is False
    assert report["outcome"] == "already_open_no_code"
    assert report["session_opened_by"] == "plain"


def test_b2_cli_code_held_but_unused_reports_unused(
        monkeypatch, capsys, tmp_path):
    rc, report = _run_cli_rectify(
        monkeypatch, capsys, tmp_path,
        whoami=dict(_BASE_WHOAMI, session_ceremony="plain",
                    rectify_presented=False, rectify_code_held=True))
    assert rc == 2
    assert report["rectified"] is False
    assert report["outcome"] == "already_open_code_unused"
    assert "NOT presented" in report["note"]


def test_cli_rectified_true_for_a_real_rectification(
        monkeypatch, capsys, tmp_path):
    rc, report = _run_cli_rectify(
        monkeypatch, capsys, tmp_path,
        whoami=dict(_BASE_WHOAMI, session_ceremony="rectified",
                    rectify_presented=True, rectify_code_held=True,
                    recovery_file="/ws/agentlink-recovery-lean.txt"))
    assert rc == 0
    assert report["rectified"] is True
    assert report["outcome"] == "rectified"
    assert report["recovery_file"] == \
        "/ws/agentlink-recovery-lean.txt"


@pytest.mark.parametrize("ceremony", ["plain", "key-login",
                                      "registered", "recovered",
                                      None])
def test_cli_no_other_ceremony_is_ever_called_rectified(
        monkeypatch, capsys, tmp_path, ceremony):
    rc, report = _run_cli_rectify(
        monkeypatch, capsys, tmp_path,
        whoami=dict(_BASE_WHOAMI, session_ceremony=ceremony,
                    rectify_presented=False, rectify_code_held=False))
    assert rc == 2
    assert report["rectified"] is False


def test_cli_unconfirmed_when_code_presented_but_login_opened(
        monkeypatch, capsys, tmp_path):
    rc, report = _run_cli_rectify(
        monkeypatch, capsys, tmp_path,
        whoami=dict(_BASE_WHOAMI, session_ceremony="key-login",
                    rectify_presented=True, rectify_code_held=True))
    assert rc == 2
    assert report["rectified"] is False
    assert report["outcome"] == "rectify_unconfirmed"
    assert "UNCONFIRMED" in report["note"]


def test_d_cli_refused_code_is_a_failure_report(
        monkeypatch, capsys, tmp_path):
    rc, report = _run_cli_rectify(
        monkeypatch, capsys, tmp_path,
        start_error=RegistrationFailed(
            "serverless_rectify_refused: the rectification "
            "code presented for @lean did not verify"))
    assert rc == 1
    assert report["rectified"] is False
    assert "error" in report
