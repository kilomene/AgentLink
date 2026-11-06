"""v1.8.1 — the grant, corrected (owner's ruling 2026-11-04).

The v1.8.0 grant model (platform operator issues named-scope
grants; a relay-side test mailbox executes) was rejected by the
owner the day it shipped. v1.8.1 implements HIS design, and
these pins hold it:

  C1. NO OPERATOR PATH: the CLI has no issuance subcommand (the
      old `grant issue` / `grant approve` are unknown commands
      that change nothing); combined with updated 180-B11 (the
      dashboard POST endpoints answer 404), a grant cannot be
      created from any platform surface.
  C2. THE FLOW IS AGENT-INITIATED AND SIGNED: allow with no
      pending request lands nowhere; a statement signed by the
      WRONG key is refused; the agent's request -> its owner's
      allow activates the grant with the grantor attestation and
      the identity binding on record.
  C3. COVERAGE IS THE CONNECTOR VAULT: an action on a connector
      outside the agent's inventory is refused even under an
      active grant; an in-inventory connector executes; an
      unlinked connector refuses; unregistering a connector
      removes its coverage immediately.
  C4. CAPABILITY SYNTHESIS: the advertised profile is declared
      union connector-derived (gmail confers email.receive /
      email.send) on the store row AND the dashboard payload;
      disconnecting the connector removes the derived tags.
  C9. PER-AGENT CONNECTOR ISOLATION: a brokered action runs
      only through the ACTING agent's own bridge under its own
      grant. Agent B (active grant, own vault) aiming at agent
      A's connector is refused as outside B's vault; A's
      handler never fires; no receipt lands on A's record; a
      raw frame smuggling A's username changes nothing (the
      relay binds the ask to the authenticated peer).
  C10. SYNTHESIS IS GRANULAR AND TRUTHFUL: a receive-only
      mailbox confers email.receive and NOT email.send; a
      draft action (mail.draft) confers email.draft only; a
      restricted class (mail.receive.business) confers itself
      verbatim under its restricted name. Nothing rounds up.
  C11. NARROWING UPDATES THE PROFILE: re-registering a
      connector with a narrowed action table re-synthesizes
      the advertised profile — the dropped capability leaves
      the store row the moment the narrower declaration lands.
  C5. RED LINES BELONG TO THE AGENT'S OWNER: the approval waits
      in the agent's own queue; the owner's agent-side rejection
      means the action NEVER executes; approval executes it.
  C6. THE HARD EXCLUSION AT THE BOUNDARY: a payment-shaped
      action class cannot be declared — CallableConnector
      raises at construction, and a hello smuggling one in an
      inventory is refused whole (stored inventory stands,
      audit row written).
  C7. DASHBOARD PAYLOAD = LINKAGE: grant state + grantor, the
      per-connector linked state with OAuth scopes, derived
      capabilities — and NO platform connector list.
  C8. REQUESTED IS NOT GRANTED: while a request merely pends,
      actions refuse and every surface says "requested".

Harness: the staging relay (SQLite, in-process), same pattern
as tests/test_onboarding_180.py.
"""

from __future__ import annotations

import asyncio
import json
import tempfile
import threading
import time
from pathlib import Path

import pytest
from websockets.client import connect

import agentlink.client as client_module
from agentlink.cli import _grant as cli_grant
from agentlink.client import Agent
from agentlink.connectors import (CallableConnector, Connector,
                                  validate_inventory)
from agentlink.crypto import Identity
from agentlink.grants import TestMailboxAdapter
from agentlink.protocol import (auth_challenge_payload,
                                grant_statement_payload)
from agentlink.relay import Relay

HOST = "127.0.0.1"
DASH_PW = "onboarding-test-pw"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-181-")
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
           "db": db, "dash_port": relay.dashboard_port,
           "relay": relay}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(
            prefix="agentlink-181-agents-") as tmp:
        yield Path(tmp)


@pytest.fixture()
def dead_convention(monkeypatch):
    monkeypatch.setattr(client_module, "DECISION_CONVENTION_URL",
                        "http://127.0.0.1:1/decide")


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def make(relay_env, state_root, username, **kw):
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
    return next((r for r in rows if r["username"] == username),
                None)


async def ceremony(a, grantor="the agent's owner"):
    out = await a.request_permission("181 pin ceremony")
    assert out["status"] == "requested", out
    out = await a.allow_permission(grantor)
    grant = (out or {}).get("grant") or {}
    assert grant.get("status") == "active", out
    return grant


def gmail_connector():
    """A Gmail-shaped OAuth-linked connector over a plain
    callable — the host-bridge shape the production proof uses
    with the real CLI."""
    return CallableConnector(
        "gmail",
        lambda action, params: {"action": action,
                                "count": 7,
                                "echo": params},
        actions={"search": "mail.read", "send": "mail.send"},
        service="gmail", label="Gmail",
        oauth_scopes=("gmail.readonly", "gmail.send"))


# ---------------------------------------------------------------------
# C1 — no operator path can create a grant
# ---------------------------------------------------------------------

def test_c1_cli_has_no_issuance_path(relay_env, state_root):
    store = relay_env["relay"].store
    # The v1.8.0 operator commands are gone: unknown subcommands,
    # exit 2, and — the point — nothing is created anywhere.
    assert cli_grant(["issue", "anyone", "--scopes",
                      "mail.read"]) == 2
    assert cli_grant(["approve", "appr-whatever"]) == 2
    assert cli_grant(["reject", "appr-whatever"]) == 2
    assert store.list_receipts(limit=10) == []
    # The store itself has no issuance method left to call.
    assert not hasattr(store, "set_grant")


# ---------------------------------------------------------------------
# C2 — the signed, agent-initiated flow
# ---------------------------------------------------------------------

def test_c2_request_then_allow_is_the_only_way(
        relay_env, state_root, dead_convention):
    async def _t():
        store = relay_env["relay"].store
        a = await make(relay_env, state_root, "cflow",
                       decision_link=lambda ctx: None,
                       connectors=[gmail_connector()])
        try:
            # Allow with NO pending request: refused client-side,
            # and nothing reaches the store.
            out = await a.allow_permission("premature owner")
            assert out["status"] == "refused", out
            assert "ask first" in (out.get("reason") or ""), out
            assert store.grant_of("cflow") is None
            # The agent asks: the request exists locally AND at
            # the relay (status requested, NOT active).
            out = await a.request_permission("please")
            assert out["status"] == "requested", out
            req_id = out["request"]["id"]
            assert a.whoami()["permission_request"]["id"] == req_id
            row = store.grant_of("cflow")
            assert row["status"] == "requested", row
            assert row["request_id"] == req_id, row
            # The owner's allow activates it: grantor attestation
            # + identity binding land on the record.
            out = await a.allow_permission("cflow's owner")
            grant = out["grant"]
            assert grant["status"] == "active", grant
            assert grant["grantor"] == "cflow's owner", grant
            row = store.grant_of("cflow")
            assert row["bound_sign_pub"] == \
                store_row(relay_env, "cflow")["sign_pub"], row
            assert row["ceremony_at"] > 0, row
            kinds = [r["kind"] for r in store.list_audit(
                limit=200)]
            assert "grant_requested" in kinds, kinds
            assert "grant_allowed" in kinds, kinds
            # The local request is consumed; whoami tells the
            # truth on every surface.
            assert a.permission_request is None
            assert a.whoami()["grant"]["status"] == "active"
        finally:
            await a.close()

    run(_t())


def test_c2_forged_statement_is_refused(relay_env, state_root,
                                        dead_convention):
    async def _t():
        store = relay_env["relay"].store
        a = await make(relay_env, state_root, "cforge",
                       decision_link=lambda ctx: None,
                       connectors=[gmail_connector()])
        try:
            await a.request_permission("mine")
            # A second connection AS the agent: key auth with the
            # agent's REAL identity (hello verifies), then a
            # grant_allow statement signed by a DIFFERENT key.
            ident = Identity("cforge",
                             str(state_root / "cforge"))
            stranger = Identity.ephemeral()
            async with connect(relay_env["url"]) as ws:
                await ws.send(json.dumps({
                    "type": "hello", "username": "cforge",
                    "display_name": "cforge", "secret": None,
                    "auth": "key", "ephemeral": False,
                    "pubkey": ident.public_key_b64,
                    "sign_pub": ident.signing_public_key_b64,
                    "capabilities": [], "mode": "autonomous"}))
                while True:
                    got = json.loads(await asyncio.wait_for(
                        ws.recv(), 10))
                    if got.get("type") == "auth_challenge":
                        payload = auth_challenge_payload(
                            got["nonce"], got["relay"], "cforge",
                            got["expires"])
                        await ws.send(json.dumps({
                            "type": "auth_response",
                            "signature": ident.sign(payload)}))
                        continue
                    assert got.get("type") == "welcome", got
                    break
                fields = {"request_id": "greq-forged",
                          "grantor": "forger",
                          "inventory_digest": "x" * 64}
                ts = int(time.time())
                stmt = {"kind": "allow", "ts": ts}
                stmt.update(fields)
                sig = stranger.sign(grant_statement_payload(
                    "allow", "cforge", ts, fields))
                await ws.send(json.dumps({
                    "type": "grant_allow", "req_id": "forge-1",
                    "statement": stmt, "sig": sig}))
                while True:
                    got = json.loads(await asyncio.wait_for(
                        ws.recv(), 10))
                    if got.get("req_id") == "forge-1":
                        break
                assert got.get("type") == "error", got
            # Nothing landed: the request still pends, unallowed.
            row = store.grant_of("cforge")
            assert row["status"] == "requested", row
        finally:
            await a.close()

    run(_t())


# ---------------------------------------------------------------------
# C3 — coverage is the vault
# ---------------------------------------------------------------------

def test_c3_coverage_follows_the_vault(relay_env, state_root,
                                       dead_convention):
    async def _t():
        store = relay_env["relay"].store
        mail = TestMailboxAdapter()
        a = await make(relay_env, state_root, "cvault",
                       decision_link=lambda ctx: None,
                       connectors=[mail])
        try:
            await ceremony(a)
            # In-inventory executes.
            out = await a.connector_action("testmail", "list", {})
            assert out["status"] == "executed", out
            # Off-inventory refuses, grant notwithstanding.
            out = await a.connector_action("outlook", "list", {})
            assert out["status"] == "refused", out
            assert "connector vault" in (out.get("reason")
                                         or ""), out
            # An UNLINKED connector in the vault refuses too.
            ghost = CallableConnector(
                "ghost", lambda act, p: {"ok": True},
                actions={"peek": "mail.read"}, linked=False)
            await a.register_connector(ghost)
            out = await a.connector_action("ghost", "peek", {})
            assert out["status"] == "refused", out
            assert "not linked" in (out.get("reason") or ""), out
            # Disconnect removes coverage at once.
            await a.unregister_connector("testmail")
            assert await wait_for(
                lambda: store.connector_inventory_of("cvault")
                and all(e["name"] != "testmail"
                        for e in store.connector_inventory_of(
                            "cvault")))
            out = await a.connector_action("testmail", "list", {})
            assert out["status"] == "refused", out
        finally:
            await a.close()

    run(_t())


# ---------------------------------------------------------------------
# C4 — capability synthesis
# ---------------------------------------------------------------------

def test_c4_capabilities_synthesized_from_connectors(
        relay_env, state_root, dead_convention):
    async def _t():
        relay = relay_env["relay"]
        a = await make(relay_env, state_root, "ccaps",
                       capabilities=["custom.thing"],
                       decision_link=lambda ctx: None,
                       connectors=[gmail_connector()])
        try:
            assert "email.receive" in a.advertised_capabilities()
            assert "email.send" in a.advertised_capabilities()
            # The store row (what work-matching sees) carries the
            # synthesized set.
            assert await wait_for(
                lambda: "email.receive" in (
                    store_row(relay_env, "ccaps") or {})
                .get("capabilities", ""))
            row = store_row(relay_env, "ccaps")
            assert "custom.thing" in row["capabilities"], row
            # The dashboard payload shows the same derivation.
            payload = relay._dashboard_data()
            me = next(u for u in payload["users"]
                      if u["username"] == "ccaps")
            assert "email.receive" in me["derived_capabilities"], me
            assert "email.send" in me["derived_capabilities"], me
            # Disconnect: derived tags leave the profile.
            await a.unregister_connector("gmail")
            assert "email.receive" not in a.advertised_capabilities()
            assert await wait_for(
                lambda: "email.receive" not in (
                    store_row(relay_env, "ccaps") or {})
                .get("capabilities", ""))
            payload = relay._dashboard_data()
            me = next(u for u in payload["users"]
                      if u["username"] == "ccaps")
            assert me["derived_capabilities"] == [], me
            assert me["connectors"] == [], me
        finally:
            await a.close()

    run(_t())


# ---------------------------------------------------------------------
# C5 — red lines belong to the agent's owner
# ---------------------------------------------------------------------

def test_c5_red_line_owner_decides(relay_env, state_root,
                                   dead_convention):
    async def _t():
        store = relay_env["relay"].store
        mail = TestMailboxAdapter()
        a = await make(relay_env, state_root, "credl",
                       decision_link=lambda ctx: None,
                       connectors=[mail])
        try:
            await ceremony(a)
            # Granting third-party access is a red line.
            out = await a.connector_action(
                "testmail", "access.share",
                {"with": "third@party.example"})
            assert out["status"] == "awaiting_approval", out
            appr_id = out["approval_id"]
            # It waits in the AGENT's queue.
            queue = await a.pending_approvals()
            assert [q["id"] for q in queue] == [appr_id], queue
            # The owner REJECTS, agent-side: never executes.
            out = await a.decide_approval(appr_id, False,
                                          "credl's owner")
            assert out["status"] == "rejected", out
            row = store.get_approval(appr_id)
            assert row["status"] == "rejected", row
            assert row["decided_by"] == "credl's owner", row
            box = mail._boxes.get("credl") or {}
            assert (box.get("shares") or []) == [], box
            # And an APPROVED red line executes through the
            # bridge, receipt tied to the approval.
            mail.seed("credl", [{"from": "x@example",
                                 "subject": "1", "body": "one"}])
            out = await a.connector_action("testmail",
                                           "delete_all", {})
            assert out["status"] == "awaiting_approval", out
            done = await a.decide_approval(out["approval_id"],
                                           True, "credl's owner")
            assert done["status"] == "executed", done
            assert mail._boxes["credl"]["inbox"] == []
            row = store.get_approval(out["approval_id"])
            assert row["status"] == "executed", row
            assert row["receipt_id"] == done["receipt_id"], row
        finally:
            await a.close()

    run(_t())


# ---------------------------------------------------------------------
# C6 — the hard exclusion at the declaration boundary
# ---------------------------------------------------------------------

def test_c6_payment_class_cannot_be_declared(relay_env,
                                             state_root,
                                             dead_convention):
    # The generic bridge refuses it at construction.
    with pytest.raises(ValueError):
        CallableConnector("stripe", lambda act, p: {},
                          actions={"charge": "payment.charge"})
    with pytest.raises(ValueError):
        CallableConnector("bank", lambda act, p: {},
                          actions={"withdraw": "card.withdraw"})
    # The inventory validator refuses it whole.
    bad = [{"name": "stripe", "service": "stripe", "label": "s",
            "linked": True, "oauth_scopes": [],
            "actions": {"charge": "payment.charge"},
            "capabilities": []}]
    assert validate_inventory(bad) is None

    class Smuggler(Connector):
        name = "smugglepay"
        service = "smugglepay"
        actions = {"charge": "payment.charge"}

        def execute(self, action, params, account):
            return {"never": True}

    async def _t():
        store = relay_env["relay"].store
        a = await make(relay_env, state_root, "csmug",
                       decision_link=lambda ctx: None,
                       connectors=[Smuggler()])
        try:
            # The hello's inventory was refused whole: nothing
            # is stored, and the refusal is audited.
            assert store.connector_inventory_of("csmug") == []
            audits = store.list_audit(limit=200)
            assert any(r.get("kind") ==
                       "connector_inventory_refused"
                       for r in audits), audits
            out = await a.connector_action("smugglepay",
                                           "charge", {})
            assert out["status"] == "refused", out
        finally:
            await a.close()

    run(_t())


# ---------------------------------------------------------------------
# C7 + C8 — payload linkage; requested is not granted
# ---------------------------------------------------------------------

def test_c7_c8_payload_linkage_and_requested_state(
        relay_env, state_root, dead_convention):
    async def _t():
        relay = relay_env["relay"]
        store = relay.store
        a = await make(relay_env, state_root, "clink",
                       decision_link=lambda ctx: None,
                       connectors=[gmail_connector()])
        try:
            # C8: requested -> payload says requested; actions
            # refuse ("no active grant").
            await a.request_permission("linkage please")
            payload = relay._dashboard_data()
            me = next(u for u in payload["users"]
                      if u["username"] == "clink")
            assert me["grant"]["status"] == "requested", me
            out = await a.connector_action("gmail", "search", {})
            assert out["status"] == "refused", out
            assert "no active grant" in (out.get("reason")
                                         or ""), out
            # C7: after the allow, the payload carries the full
            # linkage picture — and no platform connector list.
            await a.allow_permission("clink's owner")
            payload = relay._dashboard_data()
            assert "grant_connectors" not in payload, payload
            me = next(u for u in payload["users"]
                      if u["username"] == "clink")
            assert me["grant"]["status"] == "active", me
            assert me["grant"]["grantor"] == "clink's owner", me
            conns = {c["name"]: c for c in me["connectors"]}
            assert "gmail" in conns, me
            assert conns["gmail"]["linked"] is True, conns
            assert "gmail.readonly" in \
                conns["gmail"]["oauth_scopes"], conns
            assert "email.receive" in me["derived_capabilities"], me
            # The action executes and the receipt lands in the
            # payload's grant activity feed.
            out = await a.connector_action(
                "gmail", "search", {"q": "in:inbox"})
            assert out["status"] == "executed", out
            assert out["result"]["count"] == 7, out
            payload = relay._dashboard_data()
            feed = [r for r in payload["grant_activity"]
                    if r["id"] == out["receipt_id"]]
            assert feed and feed[0]["status"] == "executed", feed
            assert feed[0]["connector"] == "gmail", feed
        finally:
            await a.close()

    run(_t())


# ---------------------------------------------------------------------
# C9 — per-agent connector isolation (owner's doctrine)
# ---------------------------------------------------------------------

def test_c9_cross_agent_connector_use_is_not_routable(
        relay_env, state_root, dead_convention):
    async def _t():
        store = relay_env["relay"].store
        mail_a = TestMailboxAdapter()
        a = await make(relay_env, state_root, "isoa",
                       decision_link=lambda ctx: None,
                       connectors=[mail_a])
        webmail_b = CallableConnector(
            "webmail", lambda act, p: {"ok": True},
            actions={"list": "mail.read"}, service="webmail")
        b = await make(relay_env, state_root, "isob",
                       decision_link=lambda ctx: None,
                       connectors=[webmail_b])
        try:
            await ceremony(a)
            await ceremony(b)
            # Each agent's own door works under its own grant.
            mail_a.seed("isoa", [{"from": "x@example",
                                  "subject": "s", "body": "hi"}])
            out = await a.connector_action("testmail", "list", {})
            assert out["status"] == "executed", out
            out = await b.connector_action("webmail", "list", {})
            assert out["status"] == "executed", out
            a_receipts = {r["id"] for r in store.list_receipts(
                username="isoa", limit=100)}
            assert a_receipts, "baseline: A has its own receipts"
            # B aims at A's connector by name: refused — the
            # name lives in A's vault, not B's; B's active grant
            # does not reach it.
            out = await b.connector_action("testmail", "list", {})
            assert out["status"] == "refused", out
            assert "connector vault" in (out.get("reason")
                                         or ""), out
            # B smuggles A's username into a raw authorize ask:
            # the relay binds the ask to the authenticated peer
            # (B) — still refused, and any receipt is B's.
            out = await b._request(
                {"type": "grant_action", "connector": "testmail",
                 "action": "list", "params": {},
                 "username": "isoa"}, timeout=30.0)
            assert out.get("status") == "refused", out
            # A's world is untouched: no new receipts on A's
            # record, and A's mailbox never served B (its box
            # still holds exactly the seeded message, unread by
            # anyone but A).
            assert {r["id"] for r in store.list_receipts(
                username="isoa", limit=100)} == a_receipts
            box = mail_a._boxes.get("isoa") or {}
            assert len(box.get("inbox") or []) == 1, box
            assert (box.get("sent") or []) == [], box
        finally:
            await a.close()
            await b.close()

    run(_t())


# ---------------------------------------------------------------------
# C10 — synthesis is granular and truthful (owner's doctrine)
# ---------------------------------------------------------------------

def test_c10_synthesis_is_granular_and_truthful(
        relay_env, state_root, dead_convention):
    from agentlink.connectors import derived_capabilities_for
    # Pure derivation, exactly as declared — nothing rounds up.
    recv_only = {"name": "gmail", "linked": True,
                 "capabilities": [],
                 "actions": {"search": "mail.read",
                             "count": "mail.read"}}
    assert derived_capabilities_for(recv_only) == ["email.receive"]
    draft_only = {"name": "gmail", "linked": True,
                  "capabilities": [],
                  "actions": {"draft": "mail.draft"}}
    assert derived_capabilities_for(draft_only) == ["email.draft"]
    restricted = {"name": "bizline", "linked": True,
                  "capabilities": [],
                  "actions": {"inbox": "mail.receive.business"}}
    assert derived_capabilities_for(restricted) == [
        "mail.receive.business"]

    async def _t():
        # Live: a receive-only agent's advertised profile (and
        # the store row work-matching reads) carries receive and
        # NOT send — as-is, no inference.
        recv = CallableConnector(
            "gmail", lambda act, p: {"ok": True},
            actions={"search": "mail.read"}, service="gmail",
            oauth_scopes=("gmail.readonly",))
        a = await make(relay_env, state_root, "cgran",
                       decision_link=lambda ctx: None,
                       connectors=[recv])
        try:
            assert "email.receive" in a.advertised_capabilities()
            assert "email.send" not in a.advertised_capabilities()
            assert await wait_for(
                lambda: "email.receive" in (
                    store_row(relay_env, "cgran") or {})
                .get("capabilities", ""))
            row = store_row(relay_env, "cgran")
            assert "email.send" not in row["capabilities"], row
        finally:
            await a.close()

    run(_t())


# ---------------------------------------------------------------------
# C11 — narrowing a connector updates the advertised profile
# ---------------------------------------------------------------------

def test_c11_narrowing_a_connector_updates_the_profile(
        relay_env, state_root, dead_convention):
    async def _t():
        a = await make(relay_env, state_root, "cnarrow",
                       decision_link=lambda ctx: None,
                       connectors=[gmail_connector()])
        try:
            assert "email.send" in a.advertised_capabilities()
            assert await wait_for(
                lambda: "email.send" in (
                    store_row(relay_env, "cnarrow") or {})
                .get("capabilities", ""))
            # The owner narrows the connector agent-side (the
            # send action is disconnected): re-registering the
            # narrower table re-synthesizes the profile at once.
            narrowed = CallableConnector(
                "gmail", lambda act, p: {"ok": True},
                actions={"search": "mail.read"}, service="gmail",
                oauth_scopes=("gmail.readonly",))
            await a.register_connector(narrowed)
            assert "email.send" not in a.advertised_capabilities()
            assert "email.receive" in a.advertised_capabilities()
            assert await wait_for(
                lambda: "email.send" not in (
                    store_row(relay_env, "cnarrow") or {})
                .get("capabilities", ""))
            row = store_row(relay_env, "cnarrow")
            assert "email.receive" in row["capabilities"], row
        finally:
            await a.close()

    run(_t())
