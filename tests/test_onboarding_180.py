"""v1.8.0 combined onboarding — regression pins.

PART A — AUTO DECISION LINK (owner's law: immediately after
registration the decision link verifies and wires ITSELF —
"not manually. not manually."):
  A1. An in-process decision handler wires with ZERO config and
      is VERIFIED at registration (the probe travelled the path;
      hello/store/dashboard all declare linked + mode + verified).
  A2. The convention endpoint wires (nonce-echoing endpoint on
      the convention URL is adopted); an endpoint that does NOT
      echo the probe nonce is NEVER adopted (shared-host safety).
  A3. Explicit config wins precedence (endpoint + callable both
      present -> the endpoint is the declared, used path).
  A4. A nothing-backed agent is pending in the payload AND its
      welcome; events queue; nothing is fabricated (no reply, no
      read-marking).
  A5. A mid-session self-check failure flips the state to
      pending truthfully — and recovery flips it back.

PART B — ONE-TIME ADMIN GRANT. As shipped in v1.8.0 these pins
covered the OPERATOR-issued, named-scope model; the owner
REJECTED that model the same day (2026-11-04) and v1.8.1
rebuilt it: the grant is requested by the agent and allowed by
THE AGENT'S OWN OWNER, agent-side, over the agent's whole
connector vault. The pins below were updated DELIBERATELY to
the corrected model (each change flagged in
drill-evidence/v181/observations.md); the full corrected-model
pin set lives in tests/test_onboarding_181.py.
  B1. Action without a grant is refused (and receipted).
  B2. Action under an owner-allowed grant succeeds through the
      agent's own host bridge (the test mailbox as a bridged
      fixture) and writes a VERIFIED signed receipt.
  B3. An action the connector does not declare — and a
      connector outside the agent's vault — is refused. (The
      v1.8.0 narrowed-scope refusal no longer exists: coverage
      is inventory-wide by the owner's design.)
  B4. An owner-side signed revoke refuses the next action
      immediately.
  B5. A red-line action queues for THE AGENT'S OWNER; the
      owner's agent-side decision executes it; the queue is
      auditable and the receipt ties to the approval.
  B6. A rate trip fails closed AND raises a fleet alert.
  B7. The activity report covers EXACTLY the receipts in the
      window (and renders as the owner's document).
  B8. A vault entry created under a grant carries its receipt id
      (through the oversight content envelope the dashboard
      reads).
  B9. A recovery reclaim re-binds the grant to the fresh key.
  B10. A different identity presenting the name gets no grant.
  B11. The dashboard has NO grant actions: the v1.8.0 POST
      endpoints answer 404, logged out AND logged in, and no
      grant can materialise through them.

Harness: the staging relay (SQLite, in-process) reused from
tests/test_decision_link.py.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from websockets.client import connect

import agentlink.client as client_module
import agentlink.grants as grants_module
from agentlink.client import Agent
from agentlink.crypto import Identity
from agentlink.grants import (TestMailboxAdapter, activity_report,
                              render_activity_markdown)
from agentlink.protocol import auth_challenge_payload
from agentlink.relay import Relay
from agentlink.timing import DECISION_CONVENTION_URL
from agentlink.vault import CredentialsVault

HOST = "127.0.0.1"
DASH_PW = "onboarding-test-pw"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-180-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password=DASH_PW, dashboard_port=0)
    ready = threading.Event()
    box: dict = {}

    def _thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        box["loop"] = loop

        async def _serve():
            await relay.start()
            ready.set()
            await asyncio.Future()

        try:
            loop.run_until_complete(_serve())
        except (RuntimeError, asyncio.CancelledError):
            pass

    t = threading.Thread(target=_thread, daemon=True)
    t.start()
    assert ready.wait(timeout=10)
    yield {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "dash_port": relay.dashboard_port, "relay": relay}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-180-agents-") as tmp:
        yield Path(tmp)


@pytest.fixture()
def dead_convention(monkeypatch):
    """Hermetic convention: point the convention URL at a dead
    port so NOTHING can be adopted from the host's real 18799
    (which belongs to a live probe agent on this machine)."""
    monkeypatch.setattr(client_module, "DECISION_CONVENTION_URL",
                        "http://127.0.0.1:1/decide")


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def make(relay_env, state_root, username, **kw):
    # Every test agent gets its OWN workspace under the state
    # root: the recovery-key workspace file must never leak into
    # the real workspace or across test identities.
    kw.setdefault("workspace", str(state_root / f"{username}-ws"))
    a = Agent(username, endpoint=relay_env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=10.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


def store_row(relay_env, username):
    rows = relay_env["relay"].store.list_users(query=username)
    return next((r for r in rows if r["username"] == username), None)


def detail_of(row):
    raw = (row or {}).get("decision_link_detail") or ""
    try:
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


# ---------------------------------------------------------------------
# HTTP decision endpoints for the pins
# ---------------------------------------------------------------------

class _Endpoint:
    """A decision endpoint. echo=True answers link_check probes
    WITH the probe nonce in the body (the convention adoption
    proof); echo=False decides without ever mentioning it."""

    def __init__(self, echo=True, reply="endpoint decided this",
                 port=0):
        self.echo = echo
        self.reply = reply
        self.requests: list[dict] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                try:
                    payload = json.loads(raw.decode("utf-8") or "{}")
                except Exception:
                    payload = {}
                outer.requests.append(payload)
                if payload.get("kind") == "link_check":
                    body = {"reply": "probe answered"}
                    if outer.echo:
                        body["link_check"] = payload.get("nonce")
                    data = json.dumps(body).encode()
                elif payload.get("kind") == "work":
                    data = json.dumps({"body": outer.reply}).encode()
                else:
                    data = json.dumps(outer.reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer((HOST, port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"http://{HOST}:{self.port}/decide"

    def close(self):
        self._server.shutdown()
        self._server.server_close()


# ---------------------------------------------------------------------
# PART A
# ---------------------------------------------------------------------

def test_a0_convention_url_is_the_standard():
    assert DECISION_CONVENTION_URL == "http://127.0.0.1:18799/decide"


def test_a1_in_process_handler_wires_zero_config(relay_env,
                                                 state_root,
                                                 dead_convention):
    seen: list[dict] = []

    async def decide(ctx):
        seen.append(ctx)
        if ctx.get("kind") == "message":
            return "in-process answer"
        return None

    async def _t():
        a = await make(relay_env, state_root, "linkproc",
                       decision_link=decide)
        try:
            st = a.decision_link_state
            assert st["mode"] == "in_process", st
            assert st["verified"] is True, st
            assert st["state"] == "linked", st
            # The probe really travelled the path at registration.
            assert any(c.get("kind") == "link_check" for c in seen)
            # whoami states it too.
            assert a.whoami()["decision_link"]["mode"] == "in_process"
            assert await wait_for(
                lambda: (store_row(relay_env, "linkproc") or {})
                .get("decision_link") == "linked")
            row = store_row(relay_env, "linkproc")
            det = detail_of(row)
            assert det.get("mode") == "in_process", det
            assert det.get("verified") is True, det
            # Dashboard payload carries the same facts.
            data = relay_env["relay"]._dashboard_data()
            u = next(x for x in data["users"]
                     if x["username"] == "linkproc")
            assert u["decision_link"] == "linked"
            assert u["decision_mode"] == "in_process"
            assert u["decision_verified"] is True
        finally:
            await a.close()

    run(_t())


def test_a2_convention_endpoint_wires_and_noecho_never_adopted(
        relay_env, state_root, monkeypatch):
    echo_ep = _Endpoint(echo=True)
    monkeypatch.setattr(client_module, "DECISION_CONVENTION_URL",
                        echo_ep.url)

    async def _t():
        a = await make(relay_env, state_root, "linkconv")
        try:
            st = a.decision_link_state
            assert st["mode"] == "convention", st
            assert st["verified"] is True, st
            assert a.decision_endpoint == echo_ep.url
            assert await wait_for(
                lambda: (store_row(relay_env, "linkconv") or {})
                .get("decision_link") == "linked")
            assert detail_of(store_row(relay_env, "linkconv")) \
                .get("mode") == "convention"
        finally:
            await a.close()

    run(_t())
    echo_ep.close()

    # A live endpoint that decides WITHOUT echoing the probe
    # nonce is somebody else's endpoint on a shared host: never
    # adopted, agent stays truthfully pending.
    noecho = _Endpoint(echo=False)
    monkeypatch.setattr(client_module, "DECISION_CONVENTION_URL",
                        noecho.url)

    async def _t2():
        b = await make(relay_env, state_root, "linknoecho")
        try:
            st = b.decision_link_state
            assert st["mode"] == "none", st
            assert st["verified"] is False, st
            assert b.decision_endpoint is None
            assert await wait_for(
                lambda: (store_row(relay_env, "linknoecho") or {})
                .get("decision_link") == "pending")
        finally:
            await b.close()

    run(_t2())
    noecho.close()


def test_a3_explicit_config_wins_precedence(relay_env, state_root,
                                            dead_convention):
    ep = _Endpoint(echo=True, reply="from the configured endpoint")
    calls: list[dict] = []

    async def decide(ctx):
        calls.append(ctx)
        return "from the callable"

    async def _t():
        a = await make(relay_env, state_root, "linkcfg",
                       decision_link=decide, decision_endpoint=ep.url)
        try:
            st = a.decision_link_state
            assert st["mode"] == "config", st
            assert st["verified"] is True, st
            # The check travelled the ENDPOINT (not the callable),
            # and so does a real decision.
            assert any(r.get("kind") == "link_check"
                       for r in ep.requests)
            out = await a._call_decision({"kind": "message"})
            assert out == "from the configured endpoint"
            assert not any(c.get("kind") == "message" for c in calls)
        finally:
            await a.close()

    run(_t())
    ep.close()


async def _raw_hello(url, username, identity, extra):
    """One raw hello (claim or key auth); returns the terminal
    frame (the welcome for a successful hello)."""
    async with connect(url) as ws:
        frame = {"type": "hello", "username": username,
                 "display_name": username, "secret": None,
                 "auth": "key", "ephemeral": False,
                 "pubkey": identity.public_key_b64,
                 "sign_pub": identity.signing_public_key_b64,
                 "capabilities": [], "mode": "autonomous"}
        frame.update(extra)
        await ws.send(json.dumps(frame))
        while True:
            got = json.loads(await asyncio.wait_for(ws.recv(), 10))
            if got.get("type") == "auth_challenge":
                payload = auth_challenge_payload(
                    got["nonce"], got["relay"], username,
                    got["expires"])
                await ws.send(json.dumps(
                    {"type": "auth_response",
                     "signature": identity.sign(payload)}))
                continue
            return got


def test_a4_nothing_backed_pending_in_welcome_and_payload(
        relay_env, state_root, dead_convention):
    async def _t():
        # The welcome itself carries the pending state + no grant.
        ident = Identity.ephemeral()
        welcome = await _raw_hello(
            relay_env["url"], "linknone", ident,
            {"decision_link": "pending",
             "decision_link_detail": {"mode": "none",
                                      "verified": False,
                                      "checked_at": int(time.time())}})
        assert welcome.get("type") == "welcome", welcome
        assert welcome.get("decision_link") == "pending", welcome
        assert welcome.get("grant") is None, welcome
        det = welcome.get("decision_link_detail") or {}
        assert det.get("mode") == "none", det
        assert det.get("verified") is False, det

        # A real nothing-backed client: pending everywhere, and a
        # DM is HELD — no reply is fabricated, nothing is read.
        a = await make(relay_env, state_root, "linkheld")
        b = await make(relay_env, state_root, "linksender",
                       decision_link=lambda ctx: "sender decides")
        try:
            assert a.decision_link_state["state"] == "pending"
            assert a.whoami()["grant"] is None
            assert await wait_for(
                lambda: (store_row(relay_env, "linkheld") or {})
                .get("decision_link") == "pending")
            res = await b.send_message("linkheld", "are you there?")
            mid = res["id"]
            await asyncio.sleep(2.0)
            # Nothing fabricated: no reply ever leaves the held
            # agent, and the message is never marked read.
            assert [m for m in b.messages
                    if m.get("from") == "linkheld"] == []
            store = relay_env["relay"].store
            assert store.reads_for([mid]) == {}
            # Held, not lost: it sits in the agent's own inbox.
            assert any(m.get("id") == mid for m in a.messages)
        finally:
            await a.close()
            await b.close()

    run(_t())


def test_a5_mid_session_failure_flips_and_recovers(
        relay_env, state_root, monkeypatch, dead_convention):
    monkeypatch.setattr(client_module,
                        "DECISION_LINK_RECHECK_SECONDS", 1)
    ep = _Endpoint(echo=True)
    port = ep.port

    async def _t():
        a = await make(relay_env, state_root, "linkflip",
                       decision_endpoint=ep.url)
        try:
            assert a.decision_link_state["verified"] is True
            assert await wait_for(
                lambda: (store_row(relay_env, "linkflip") or {})
                .get("decision_link") == "linked")
            # The endpoint dies mid-session: the recheck flips
            # the state to pending, locally AND on the relay.
            ep.close()
            assert await wait_for(
                lambda: a.decision_link_state["verified"] is False,
                timeout=15)
            assert await wait_for(
                lambda: (store_row(relay_env, "linkflip") or {})
                .get("decision_link") == "pending", timeout=15)
            # It comes back on the same port: the state recovers
            # the same way, with no restart and no manual step.
            ep2 = _Endpoint(echo=True, port=port)
            try:
                assert await wait_for(
                    lambda: a.decision_link_state["verified"] is True,
                    timeout=15)
                assert await wait_for(
                    lambda: (store_row(relay_env, "linkflip") or {})
                    .get("decision_link") == "linked", timeout=15)
            finally:
                ep2.close()
        finally:
            await a.close()

    run(_t())


# ---------------------------------------------------------------------
# PART B
# ---------------------------------------------------------------------

async def _ceremony(a, grantor="the agent's owner"):
    """The corrected grant flow (v1.8.1), driven end-to-end the
    way the owner's design prescribes: the AGENT asks
    (request_permission), its OWNER allows (allow_permission,
    the agent-side ceremony entry point), and only then does a
    grant exist. Returns the active grant summary."""
    out = await a.request_permission("pin ceremony")
    assert out["status"] == "requested", out
    out = await a.allow_permission(grantor)
    grant = (out or {}).get("grant") or {}
    assert grant.get("status") == "active", out
    return grant


def test_b1_to_b4_grant_flow(relay_env, state_root, dead_convention):
    async def _t():
        relay = relay_env["relay"]
        store = relay.store
        mail = TestMailboxAdapter()
        a = await make(relay_env, state_root, "gflow",
                       decision_link=lambda ctx: None,
                       connectors=[mail])
        try:
            # B1: no grant -> refused (and the refusal is receipted).
            out = await a.grant_action("testmail", "list", {})
            assert out["status"] == "refused", out
            assert out.get("receipt_id"), out
            assert await a.my_grant() is None
            # The agent asks; its owner allows. The grantor
            # attestation is on the record.
            grant = await _ceremony(a)
            assert grant["grantor"] == "the agent's owner", grant
            assert grant["coverage"] == "connector_vault", grant
            mine = await a.my_grant()
            assert mine and mine["status"] == "active", mine
            assert a.whoami()["grant"]["status"] == "active"
            # Seed the BRIDGED fixture + B2: read succeeds through
            # the agent's own host bridge and writes a verified
            # receipt.
            mail.seed("gflow", [{"from": "owner@example",
                                 "subject": "hi", "body": "seeded"}])
            out = await a.grant_action("testmail", "list", {})
            assert out["status"] == "executed", out
            assert out["result"]["count"] == 1, out
            rid = out["receipt_id"]
            recs = [r for r in store.list_receipts("gflow")
                    if r["id"] == rid]
            assert len(recs) == 1 and recs[0]["status"] == "executed"
            from agentlink.grants import verify_receipt
            assert verify_receipt(store.grant_receipt_pubkey(),
                                  recs[0]) is True
            out = await a.grant_action(
                "testmail", "send",
                {"to": "peer@example", "subject": "s", "body": "b"})
            assert out["status"] == "executed", out
            # B3 (corrected model): an action the connector does
            # not declare is refused — and so is a connector that
            # is not in the agent's vault at all, even under the
            # active grant. (v1.8.0's narrowed-scope refusal is
            # gone by design: coverage is inventory-wide.)
            out = await a.grant_action("testmail", "securityish",
                                       {})
            assert out["status"] == "refused", out  # unknown action
            out = await a.grant_action("outlook", "list", {})
            assert out["status"] == "refused", out
            assert "connector vault" in (out.get("reason") or ""), out
            # B4: the owner's agent-side signed revoke -> the very
            # next action refuses.
            out = await a.revoke_permission()
            assert (out.get("grant") or {})["status"] == "revoked", out
            out = await a.grant_action("testmail", "list", {})
            assert out["status"] == "refused", out
            assert "no active grant" in (out.get("reason") or ""), out
        finally:
            await a.close()

    run(_t())


def test_b5_red_line_queues_then_approval_executes(
        relay_env, state_root, dead_convention):
    async def _t():
        relay = relay_env["relay"]
        store = relay.store
        mail = TestMailboxAdapter()
        a = await make(relay_env, state_root, "gred",
                       decision_link=lambda ctx: None,
                       connectors=[mail])
        try:
            await _ceremony(a)
            mail.seed("gred", [{"from": "x@example", "subject": "1",
                                "body": "one"},
                               {"from": "y@example", "subject": "2",
                                "body": "two"}])
            out = await a.grant_action("testmail", "delete_all", {})
            assert out["status"] == "awaiting_approval", out
            assert out.get("approval_id"), out
            # NOT executed: both messages are still there.
            box = mail._boxes["gred"]
            assert len(box["inbox"]) == 2
            appr = store.get_approval(out["approval_id"])
            assert appr["status"] == "awaiting_approval"
            assert "bulk deletion" in appr["reason"]
            # The approval waits in THE AGENT'S OWN queue — the
            # agent owner's surface, not the platform's.
            queue = await a.pending_approvals()
            assert [q["id"] for q in queue] == [appr["id"]], queue
            # The agent's owner approves, agent-side: the gate
            # re-runs, the action executes through the agent's
            # bridge, the approval carries the receipt.
            done = await a.decide_approval(appr["id"], True,
                                           "the agent's owner")
            assert done["status"] == "executed", done
            assert len(box["inbox"]) == 0
            appr2 = store.get_approval(appr["id"])
            assert appr2["status"] == "executed"
            assert appr2["receipt_id"] == done["receipt_id"]
            assert appr2["decided_by"] == "the agent's owner"
        finally:
            await a.close()

    run(_t())


def test_b6_rate_trip_fails_closed_and_alerts(relay_env, state_root,
                                              dead_convention,
                                              monkeypatch):
    monkeypatch.setitem(grants_module.GRANT_RATE_LIMITS,
                        "mail.read", 2)

    async def _t():
        relay = relay_env["relay"]
        store = relay.store
        a = await make(relay_env, state_root, "grate",
                       decision_link=lambda ctx: None,
                       connectors=[TestMailboxAdapter()])
        try:
            await _ceremony(a)
            for _ in range(2):
                out = await a.grant_action("testmail", "list", {})
                assert out["status"] == "executed", out
            out = await a.grant_action("testmail", "list", {})
            assert out["status"] == "rate_limited", out
            alerts = store.list_alerts()
            mine = [x for x in alerts
                    if x.get("kind") == "grant_rate_limit"
                    and "grate" in (x.get("subject") or "")]
            assert mine, f"rate trip must raise a fleet alert: {alerts}"
        finally:
            await a.close()

    run(_t())


def test_b7_activity_report_exact_window(relay_env, state_root,
                                         dead_convention):
    async def _t():
        store = relay_env["relay"].store
        a = await make(relay_env, state_root, "greport",
                       decision_link=lambda ctx: None,
                       connectors=[TestMailboxAdapter()])
        try:
            await _ceremony(a)
            t0 = int(time.time())
            await a.grant_action("testmail", "list", {})
            await a.grant_action(
                "testmail", "send",
                {"to": "z@example", "subject": "s", "body": "b"})
            await a.grant_action("testmail", "list", {})
            rep = activity_report(store, "greport", t0 - 5)
            assert rep["total"] == 3, rep
            assert rep["counts"] == {"executed": 3}, rep
            assert all(r["verified"] for r in rep["receipts"]), rep
            doc = render_activity_markdown(rep)
            for r in rep["receipts"]:
                assert r["id"] in doc
            # A window after everything: exactly nothing.
            rep2 = activity_report(store, "greport",
                                   int(time.time()) + 3600)
            assert rep2["total"] == 0, rep2
            # Another agent's receipts never leak into the window.
            rep3 = activity_report(store, "someoneelse", 0)
            assert rep3["total"] == 0, rep3
        finally:
            await a.close()

    run(_t())


def test_b8_vault_entry_carries_grant_receipt(state_root):
    ident = Identity("agentx", str(state_root / "ident"))
    vault = CredentialsVault(ident, state_root / "vstate", "agentx")
    entry = vault.put("example.com", "agentx@example.com", "pw123",
                      grant_receipt="rcpt-deadbeef")
    assert entry["grant_receipt"] == "rcpt-deadbeef"
    assert vault.get("example.com")["grant_receipt"] == "rcpt-deadbeef"
    # The oversight content envelope (what the dashboard opens)
    # carries the provenance too.
    oversight = Identity.ephemeral()
    env = vault.content_envelope(oversight.public_key_b64)
    payload = json.loads(oversight.decrypt_envelope(env))
    entries = payload["entries"]
    assert entries and entries[0]["grant_receipt"] == "rcpt-deadbeef"
    # An entry NOT created under a grant carries none.
    vault.put("other.com", "a@b.c", "pw")
    assert vault.get("other.com")["grant_receipt"] == ""


def test_b9_recovery_reclaim_rebinds_grant(relay_env, state_root,
                                           dead_convention):
    async def _t():
        store = relay_env["relay"].store
        ws1 = state_root / "ws-b9-1"
        ws2 = state_root / "ws-b9-2"
        a = await make(relay_env, state_root, "grebind",
                       workspace=str(ws1),
                       decision_link=lambda ctx: None,
                       connectors=[TestMailboxAdapter()])
        key = a.recovery_key
        assert key, "registration must issue a recovery key"
        old_pub = store_row(relay_env, "grebind")["sign_pub"]
        await _ceremony(a)
        await a.close()
        # Fresh machine, fresh keys, the recovery key only. The
        # fresh client bridges its own fixture connector; the
        # grant follows the IDENTITY through the reclaim.
        b = Agent("grebind", endpoint=relay_env["url"],
                  state_dir=str(state_root / "grebind-fresh"),
                  workspace=str(ws2), recovery_key=key,
                  decision_link=lambda ctx: None,
                  connectors=[TestMailboxAdapter()])
        await b.start()
        try:
            row = store_row(relay_env, "grebind")
            assert row["sign_pub"] != old_pub
            grant = store.grant_of("grebind")
            assert grant["status"] == "active", grant
            assert grant["bound_sign_pub"] == row["sign_pub"], grant
            out = await b.grant_action("testmail", "list", {})
            assert out["status"] == "executed", out
        finally:
            await b.close()

    run(_t())


def test_b10_different_identity_gets_no_grant(relay_env, state_root,
                                              dead_convention):
    async def _t():
        store = relay_env["relay"].store
        a = await make(relay_env, state_root, "gtaken",
                       decision_link=lambda ctx: None,
                       connectors=[TestMailboxAdapter()])
        await _ceremony(a)
        await a.close()
        # The operator removes the dead identity entirely; a
        # DIFFERENT identity then claims the name. The grant must
        # not follow the name to a stranger.
        store.remove_user("gtaken", force=True)
        assert store.grant_of("gtaken") is None
        b = Agent("gtaken", endpoint=relay_env["url"],
                  state_dir=str(state_root / "gtaken-new"),
                  workspace=str(state_root / "gtaken-new-ws"),
                  decision_link=lambda ctx: None)
        await b.start()
        try:
            assert await b.my_grant() is None
            out = await b.grant_action("testmail", "list", {})
            assert out["status"] == "refused", out
        finally:
            await b.close()

    run(_t())


def test_b11_dashboard_has_no_grant_actions(
        relay_env, state_root, dead_convention):
    """The corrected model (v1.8.1): the dashboard is OVERSIGHT
    ONLY — the v1.8.0 grant write endpoints are GONE. Logged out
    AND logged in, POST /api/grant/* answers 404, no grant can
    materialise through the dashboard, and the served page
    carries no grant controls at all."""
    import urllib.error
    import urllib.request

    base = f"http://{HOST}:{relay_env['dash_port']}"

    def post(path, fields, cookie=None):
        data = urllib.parse.urlencode(fields).encode()
        req = urllib.request.Request(base + path, data=data,
                                     method="POST")
        if cookie:
            req.add_header("Cookie", cookie)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.headers, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.headers, exc.read()

    def get(path, cookie=None):
        req = urllib.request.Request(base + path, method="GET")
        if cookie:
            req.add_header("Cookie", cookie)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode(
                    "utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8", "replace")

    async def _t():
        a = await make(relay_env, state_root, "gdash",
                       decision_link=lambda ctx: None)
        await a.close()

    run(_t())
    store = relay_env["relay"].store
    # Logged out: 404 (the path does not exist as an action),
    # and no grant materialises.
    code, _, _ = post("/api/grant/issue",
                      {"username": "gdash", "scopes": "mail.read"})
    assert code == 404, code
    assert store.grant_of("gdash") is None
    # Login (the staging dashboard password) — 302 + Set-Cookie,
    # read with a no-redirect opener so the cookie survives.
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(
        base + "/login",
        data=urllib.parse.urlencode(
            {"password": DASH_PW}).encode(), method="POST")
    try:
        with opener.open(req, timeout=10) as resp:
            code, headers = resp.status, resp.headers
    except urllib.error.HTTPError as exc:
        code, headers = exc.code, exc.headers
    assert code == 302, code
    cookie = headers.get("Set-Cookie", "").split(";")[0]
    assert cookie, headers
    # Logged in: STILL 404 on every v1.8.0 grant action — the
    # platform cannot issue, revoke or decide. Nothing changes.
    for path, fields in (
            ("/api/grant/issue",
             {"username": "gdash", "scopes": "mail.read,mail.send"}),
            ("/api/grant/revoke", {"username": "gdash"}),
            ("/api/grant/approve", {"id": "appr-nope"}),
            ("/api/grant/reject", {"id": "appr-nope"})):
        code, _, body = post(path, fields, cookie=cookie)
        assert code == 404, (path, code, body)
    assert store.grant_of("gdash") is None
    # The served page itself carries no grant controls.
    code, page = get("/", cookie=cookie)
    assert code == 200, code
    assert "data-gact" not in page
    assert "/api/grant/" not in page
    assert "Issue grant" not in page
