"""2.1.0 — customer support for signup/login: the client lodge /
status surface, the auto-lodge on terminal setup failure, and
the hook state machine (lodge -> open -> fixed -> the hook
updates, retries setup, registers the agent and retires).

The Edge is faked at support._request_json (the one hardened
HTTP seam); supervision installers are neutralized so tests
never touch the host's real systemd/cron.
"""
import asyncio
import json
import os
import stat

import pytest

from agentlink import support, support_hook


@pytest.fixture(autouse=True)
def no_supervision(monkeypatch):
    monkeypatch.setattr(support_hook, "_try_systemd",
                        lambda rec: False)
    monkeypatch.setattr(support_hook, "_try_cron",
                        lambda rec: False)
    monkeypatch.setattr(support_hook, "_try_supervisor",
                        lambda rec: False)


class FakeDesk:
    """A scripted agentlink-support Edge behind _request_json."""

    def __init__(self):
        self.tickets = {}
        self.lodge_calls = 0
        self.seq = 0

    def __call__(self, method, url, payload, timeout=30.0,
                 attempts=5):
        if url.endswith("/lodge"):
            self.lodge_calls += 1
            self.seq += 1
            tid = f"ticket-{self.seq:04d}"
            self.tickets[tid] = {
                "ticket_id": tid, "status": "open",
                "resolution": None, "welcomed": False,
                "desired_username": payload["desired_username"],
                "claim_secret": payload["claim_secret"],
                "attachments": []}
            return 200, {"ok": True, "ticket_id": tid,
                         "name_taken": False}
        if url.endswith("/attach"):
            return 200, {"ok": True, "url": "https://r2.example/put",
                         "key": f"support/{payload['ticket_id']}/k1"}
        if url.endswith("/attach-confirm"):
            t = self.tickets[payload["ticket_id"]]
            t["attachments"] = [{
                "name": payload["name"], "size": payload["size"],
                "content_type": payload["content_type"],
                "key": payload["key"]}]
            return 200, {"ok": True,
                         "attachments": t["attachments"]}
        if url.endswith("/status"):
            t = self.tickets.get(payload["ticket_id"])
            if t is None or \
                    t["claim_secret"] != payload["claim_secret"]:
                return 404, {"ok": False, "error": "not_found",
                             "detail": "no such ticket"}
            return 200, {"ok": True, **{
                k: t[k] for k in ("ticket_id", "status",
                                  "resolution", "welcomed",
                                  "desired_username",
                                  "attachments")},
                         "created_at": 1, "updated_at": 2}
        raise AssertionError(url)


@pytest.fixture
def desk(monkeypatch):
    d = FakeDesk()
    monkeypatch.setattr(support, "_request_json", d)
    monkeypatch.setattr(support, "_put_bytes",
                        lambda url, data, ctype: None)
    return d


# -- lodge ---------------------------------------------------------

def test_lodge_records_ticket_and_installs_hook(desk, tmp_path):
    sd = tmp_path / "state"
    out = support.lodge("NewAgent", "I cannot register: the "
                        "setup dies at login", sd)
    assert out["ticket_id"] == "ticket-0001"
    assert out["username"] == "newagent"
    recs = support.load_records(sd)
    assert len(recs) == 1 and recs[0]["claim_secret"]
    mode = stat.S_IMODE(os.stat(
        sd / "support" / "tickets.json").st_mode)
    assert mode == 0o600
    hooks = support_hook.list_records(sd)
    assert len(hooks) == 1
    assert hooks[0]["ticket_id"] == "ticket-0001"
    assert hooks[0]["supervision"] == "on-command"


def test_lodge_client_side_validation(desk, tmp_path):
    sd = tmp_path / "state"
    with pytest.raises(support.SupportError):
        support.lodge("bad name!", "help", sd)
    with pytest.raises(support.SupportError):
        support.lodge("goodname", "   ", sd)
    with pytest.raises(support.SupportError):
        support.lodge("goodname", "x" * 4001, sd)
    with pytest.raises(support.SupportError):
        support.lodge("goodname", "help", sd,
                      attachments=[sd / "nope.txt"])
    f = tmp_path / "evil.exe"
    f.write_bytes(b"MZ")
    with pytest.raises(support.SupportError):
        support.lodge("goodname", "help", sd, attachments=[f])
    big = tmp_path / "big.txt"
    big.write_bytes(b"x" * (support.FILE_MAX_BYTES + 1))
    with pytest.raises(support.SupportError):
        support.lodge("goodname", "help", sd, attachments=[big])
    assert desk.lodge_calls == 0


def test_lodge_with_attachment(desk, tmp_path):
    proof = tmp_path / "error.log"
    proof.write_text("login Edge verify HTTP 405")
    out = support.lodge("stranded", "setup fails", tmp_path / "s",
                        attachments=[proof])
    assert out["attachments"][0]["name"] == "error.log"
    assert out["attachments"][0]["content_type"] == "text/plain"


def test_status_wrong_secret_is_a_refusal(desk, tmp_path):
    out = support.lodge("stranded", "help", tmp_path / "s")
    with pytest.raises(support.SupportError) as ei:
        support.poll_status(out["ticket_id"], "wrong-secret")
    assert ei.value.code == "not_found"
    mine = support.my_tickets(tmp_path / "s")
    assert mine[0]["status"] == "open"


# -- auto-lodge ------------------------------------------------------

def test_auto_lodge_once_per_failure(desk, tmp_path):
    sd = tmp_path / "s"
    r1 = support.maybe_auto_lodge("agentx", sd, step="network",
                                  error="no egress")
    assert r1 and r1["ticket_id"]
    r2 = support.maybe_auto_lodge("agentx", sd, step="network",
                                  error="no egress")
    assert r2 and r2.get("reused") is True
    assert desk.lodge_calls == 1
    r3 = support.maybe_auto_lodge("agentx", sd,
                                  step="first-contact",
                                  error="name taken")
    assert r3 and not r3.get("reused")
    assert desk.lodge_calls == 2


def test_auto_lodge_kill_switch(desk, tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTLINK_SUPPORT_NO_AUTOLODGE", "1")
    assert support.maybe_auto_lodge(
        "agentx", tmp_path / "s", step="network",
        error="no egress") is None
    assert desk.lodge_calls == 0


# -- setup integration -------------------------------------------------

def test_setup_network_failure_auto_lodges(desk, tmp_path,
                                          monkeypatch):
    from agentlink import setup as setup_mod
    monkeypatch.setattr(setup_mod, "choose_network",
                        lambda sd: {"proven": False,
                                    "attempts": []})
    report = asyncio.run(setup_mod.run_setup(
        "stranded210", state_dir=str(tmp_path / "s")))
    assert report["ok"] is False
    assert report["support"]["ticket_id"] == "ticket-0001"
    assert "hook is watching it" in report["support"]["note"]
    assert desk.lodge_calls == 1


def test_setup_failure_no_lodge_when_disabled(desk, tmp_path,
                                              monkeypatch):
    from agentlink import setup as setup_mod
    monkeypatch.setattr(setup_mod, "choose_network",
                        lambda sd: {"proven": False,
                                    "attempts": []})
    report = asyncio.run(setup_mod.run_setup(
        "stranded210", state_dir=str(tmp_path / "s"),
        auto_support=False))
    assert report["ok"] is False
    assert "support" not in report
    assert desk.lodge_calls == 0


# -- the hook state machine ---------------------------------------------

class FakeDeps(support_hook.Deps):
    def __init__(self, sd, statuses, feed="2.1.0",
                 setup_report=None):
        super().__init__(sd)
        self.statuses = statuses      # ticket_id -> status dict
        self.feed = feed
        self.setup_report = setup_report or {"ok": True}
        self.cleaned = []
        self.followups = []

    def poll(self, ticket_id, claim_secret):
        return self.statuses[ticket_id]

    def feed_version(self):
        return self.feed

    def apply_update(self):
        return {"updated": False, "reason": "already up to date"}

    def setup(self, record):
        if isinstance(self.setup_report, Exception):
            raise self.setup_report
        return self.setup_report

    def followup(self, record, report):
        self.followups.append(report)
        return {"ticket_id": "ticket-fu"}

    def cleanup(self, record, outcome):
        self.cleaned.append(outcome)


def _record(tmp_path):
    return {"ticket_id": "ticket-0001", "claim_secret": "sec",
            "username": "stranded", "state_dir": str(tmp_path),
            "designation": "production", "grant": "ask",
            "attempts": 0, "waiting_streak": 0, "followups": []}


def _fixed(version="2.1.0"):
    return {"status": "fixed",
            "resolution": {"fixed_in_version": version}}


def test_hook_waits_while_open(tmp_path):
    deps = FakeDeps(tmp_path, {"ticket-0001": {"status": "open"}})
    assert support_hook.cycle(_record(tmp_path), deps) == "waiting"
    assert deps.cleaned == []


def test_hook_waits_for_feed_to_carry_the_fix(tmp_path):
    deps = FakeDeps(tmp_path, {"ticket-0001": _fixed("2.1.0")},
                    feed="2.0.11")
    assert support_hook.cycle(_record(tmp_path), deps) == "waiting"


def test_hook_registers_the_agent_when_fixed(tmp_path):
    deps = FakeDeps(tmp_path, {"ticket-0001": _fixed()})
    assert support_hook.cycle(_record(tmp_path),
                              deps) == "registered"
    assert deps.cleaned == ["registered after fix"]


def test_hook_setup_failure_lodges_followup(tmp_path):
    deps = FakeDeps(tmp_path, {"ticket-0001": _fixed()},
                    setup_report={"ok": False,
                                  "error": "still 405"})
    rec = _record(tmp_path)
    assert support_hook.cycle(rec, deps) == "retry_failed"
    assert deps.followups and rec["attempts"] == 1
    assert rec["followups"][0]["ticket_id"] == "ticket-fu"


def test_hook_retires_when_ticket_closed(tmp_path):
    deps = FakeDeps(tmp_path,
                    {"ticket-0001": {"status": "closed"}})
    assert support_hook.cycle(_record(tmp_path), deps) == "closed"
    assert deps.cleaned == ["ticket closed"]


def test_hook_poll_error_is_not_terminal(tmp_path):
    class Boom(FakeDeps):
        def poll(self, ticket_id, claim_secret):
            raise ConnectionError("desk unreachable")
    deps = Boom(tmp_path, {})
    assert support_hook.cycle(_record(tmp_path), deps) == "error"
    assert deps.cleaned == []


def test_hook_follows_the_followups_fix(tmp_path):
    rec = _record(tmp_path)
    rec["followups"] = [{"ticket_id": "ticket-fu",
                         "claim_secret": "sec2", "at": 1}]
    deps = FakeDeps(tmp_path, {
        "ticket-0001": {"status": "answered"},
        "ticket-fu": _fixed()})
    assert support_hook.cycle(rec, deps) == "registered"


def test_cron_block_roundtrip():
    block = support_hook._cron_block("ticket-abcdef-1234",
                                     support_hook.Path("/sd"))
    text = "0 0 * * * other\n" + block
    stripped = support_hook._strip_cron_block(text,
                                              "ticket-abcdef-1234")
    assert "other" in stripped
    assert "support-hook" not in stripped
