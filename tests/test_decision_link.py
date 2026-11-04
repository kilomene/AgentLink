"""v1.3.5 decision link — regression pins ("the agent is the brain").

The doctrine under test: the agent IS its own intelligence — its
capability and memory are its own, always. This client is only its
line CONNECTION. The one thing that can be missing is the DECISION
LINK between that connection and the agent's own decision-making,
wired one of three ways: an in-process callable (``decision_link=``
/ ``on_decision=``; ``brain=`` is the deprecated alias that must
keep working), the agent's own handlers, or an out-call decision
ENDPOINT (``decision_endpoint=`` / ``AGENTLINK_DECISION_ENDPOINT``)
the runtime POSTs each event to.

Pinned here, all against a real staging relay (SQLite, in-process
clients, fully offline — the relay_env/state_root harness is reused
verbatim from tests/test_autonomous.py):

  1. TRUTHFUL WARNING — an unlinked autonomous agent warns in the
     new language (the agent itself is the intelligence; the
     connection holds the line; messages & work queue) and NEVER in
     the old framing ("no brain" / "WITHOUT A BRAIN" /
     "no intelligence wired"); Agent(brain=<callable>) still works
     end-to-end and declares "linked".
  2. ENDPOINT ROUND-TRIP — a real local HTTP endpoint (stdlib
     http.server, ephemeral port) answers a DM with its exact
     returned string and delivers assigned work whose body is its
     exact returned words, assigner-visible verbatim, proof flow
     intact; the env-var wiring reaches the same place.
  3. ENDPOINT FAILURE = HELD, NEVER FABRICATED — unreachable and
     HTTP 500 endpoints produce NO reply, NO read-marking, NO
     delivery, NO acceptance; DecisionLinkError is raised at the
     link and logged as a link error. A 204 / JSON null answer is
     the agent's chosen SILENCE — observably distinct from failure
     (decision_silent / work_decision_silent, never *_link_error).
  4. UNLINKED STATE SURFACES (client half) — declarations, the
     directory and the store agree: autonomous+unwired = "pending",
     autonomous+wired = "linked", manual = "" (no question).
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

import agentlink.client as client_module
from agentlink.client import Agent, DecisionLinkError
from agentlink.relay import Relay

HOST = "127.0.0.1"
DASH_PW = "decision-link-test-pw"

ENDPOINT_REPLY = "endpoint reply 7f3: decided by the agent, verbatim"
ENDPOINT_WORK_BODY = "endpoint work body 9c1: finished exactly as decided"
ENV_REPLY = "env endpoint reply 4d2: wired by environment, verbatim"


# ---------------------------------------------------------------------
# Harness — reused exactly as in tests/test_autonomous.py
# ---------------------------------------------------------------------

@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-auto-")
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
    with tempfile.TemporaryDirectory(prefix="agentlink-auto-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def make(relay_env, state_root, username, **kw):
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


@pytest.fixture()
def short_decision_timeout(monkeypatch):
    """Never wait out the production 30s decision-link timeout in a
    test: the client reads the timing constant from its own module
    namespace, so shorten it there."""
    monkeypatch.setattr(client_module, "DECISION_LINK_TIMEOUT_SECONDS", 3)
    return 3


# ---------------------------------------------------------------------
# A real local decision endpoint: stdlib http.server, ephemeral port
# ---------------------------------------------------------------------

class _DecisionEndpoint:
    """Speaks the decision protocol over HTTP: POSTed JSON ctx in,
    the decision-callable's answer JSON-encoded out — a string for a
    message reply, {"body": ...} for work, 204 / null for silence,
    500 for a link-side failure."""

    def __init__(self, mode="reply", reply_text="", work_body="",
                 work_progress=False):
        self.mode = mode
        self.reply_text = reply_text
        self.work_body = work_body
        self.work_progress = work_progress
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
                if outer.mode == "error500":
                    body = b"endpoint boom"
                    self.send_response(500)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
                if outer.mode == "silence204":
                    self.send_response(204)
                    self.end_headers()
                    return
                if outer.mode == "null":
                    body = b"null"
                elif payload.get("kind") == "work":
                    result = {"body": outer.work_body}
                    if outer.work_progress:
                        # Progress as a JSON encoder emits it:
                        # percent may be a float (50.0), and the
                        # runtime's report_progress contract is
                        # int percent — the adapter must coerce.
                        result["progress"] = [
                            {"percent": 50.0, "note": "computing"}]
                    body = json.dumps(result).encode()
                else:
                    body = json.dumps(outer.reply_text).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer((HOST, 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        self.url = f"http://{HOST}:{self._server.server_address[1]}/decide"

    def close(self):
        self._server.shutdown()
        self._server.server_close()


@pytest.fixture()
def endpoint_factory():
    made: list[_DecisionEndpoint] = []

    def factory(**kw):
        ep = _DecisionEndpoint(**kw)
        made.append(ep)
        return ep

    yield factory
    for ep in made:
        ep.close()


def closed_port_url() -> str:
    s = socket.socket()
    s.bind((HOST, 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://{HOST}:{port}/decide"


def store_rows(relay_env):
    return {r["username"]: r
            for r in relay_env["relay"].store.list_users()}


# ---------------------------------------------------------------------
# 1. TRUTHFUL WARNING + the deprecated brain= alias
# ---------------------------------------------------------------------

def test_unlinked_warning_is_truthful(relay_env, state_root):
    """An autonomous agent with nothing wired logs the DECISION LINK
    PENDING warning: the agent itself is the intelligence, the
    connection holds the line, messages and work queue — and the
    text never slips back into the old framing that claimed
    something about the AGENT ("no brain" / "WITHOUT A BRAIN" /
    "no intelligence wired")."""
    records: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record):
            records.append(record.getMessage())

    handler = _Capture(level=logging.WARNING)
    logger = logging.getLogger("agentlink.client")
    logger.addHandler(handler)
    try:
        async def _t():
            hollow = await make(relay_env, state_root, "hollowwarn")
            assert hollow._decision_declaration() == "pending"
            assert hollow.decision_linked is False
            assert any(e["event"] == "decision_link_pending_warning"
                       for e in hollow.autonomous_log)
            await hollow.close()
        run(_t())
    finally:
        logger.removeHandler(handler)

    warnings = [m for m in records if "DECISION LINK PENDING" in m]
    assert warnings, records
    text = warnings[0]
    # The truthful claims, in the warning's own words.
    assert "the agent itself is the intelligence" in text
    assert "holds the line" in text
    assert "messages and work queue" in text
    assert "NOT answered or accepted on the agent's behalf" in text
    # The old framing, in any casing, is gone.
    lowered = text.lower()
    assert "no brain" not in lowered
    assert "without a brain" not in lowered
    assert "no intelligence wired" not in lowered


def test_brain_alias_still_works_and_declares_linked(relay_env, state_root):
    """Agent(brain=<callable>) is the deprecated pre-1.3.5 name for
    the decision link: it must still work end-to-end — the callable
    receives the event and its words are the reply — and the agent
    declares "linked" in its hello (directory + store agree)."""
    seen_ctx = []

    async def brain(ctx):
        seen_ctx.append(ctx)
        if ctx["kind"] == "message":
            return f"brain alias reply to: {ctx['message'].get('body')}"
        return None

    async def _t():
        poster = await make(relay_env, state_root, "aliasposter",
                            mode="manual")
        legacy = await make(relay_env, state_root, "legacybrain",
                            brain=brain)
        assert legacy.brain is brain
        assert legacy.decision_linked is True
        assert legacy._decision_declaration() == "linked"
        await poster.send_message("legacybrain", "hello legacy")
        assert await wait_for(lambda: any(
            m.get("from") == "legacybrain" for m in poster.messages))
        reply = [m for m in poster.messages
                 if m.get("from") == "legacybrain"][0]
        assert reply["body"] == "brain alias reply to: hello legacy"
        assert (reply.get("meta") or {}).get("autonomous") is True
        # v1.8.0: the registration self-check probe (kind
        # "link_check") is the callable's first event by law —
        # the first MESSAGE ctx is the pin's subject.
        msg_ctx = [c for c in seen_ctx if c["kind"] == "message"]
        assert msg_ctx and msg_ctx[0]["agent"]["username"] \
            == "legacybrain"
        assert any(c["kind"] == "link_check" for c in seen_ctx)
        rows = {r["username"]: r for r in await poster.directory()}
        assert rows["legacybrain"]["decision_link"] == "linked"
        assert store_rows(relay_env)["legacybrain"]["decision_link"] \
            == "linked"
        await poster.close()
        await legacy.close()
    run(_t())


def test_decision_param_names_all_wire_the_link(state_root):
    """Every wiring name lands on the same link, and the bare
    declarations are exact: decision_link= / on_decision= / brain= /
    decision_endpoint= -> "linked"; nothing -> "pending"; manual ->
    "" even WITH a callable (the question does not apply)."""
    async def decide(ctx):
        return None

    base = dict(state_dir=None)  # replaced per-agent below

    def build(name, **kw):
        return Agent(name, state_dir=str(state_root / name), **kw)

    a = build("viadecisionlink", decision_link=decide)
    assert a.decision_linked is True
    assert a._decision_declaration() == "linked"
    b = build("viaondecision", on_decision=decide)
    assert b.decision_linked is True
    assert b._decision_declaration() == "linked"
    c = build("viabrain", brain=decide)
    assert c.decision_linked is True
    assert c._decision_declaration() == "linked"
    d = build("viaendpoint", decision_endpoint="http://127.0.0.1:9/x")
    assert d.decision_linked is True
    assert d._decision_declaration() == "linked"
    e = build("vianothing")
    assert e.decision_linked is False
    assert e._decision_declaration() == "pending"
    f = build("viamanual", mode="manual", decision_link=decide)
    assert f._decision_declaration() == ""
    g = build("viamanualbare", mode="manual")
    assert g._decision_declaration() == ""
    assert base  # (kept minimal: construction alone wires nothing live)


# ---------------------------------------------------------------------
# 2. DECISION ENDPOINT ROUND-TRIP (the paved link)
# ---------------------------------------------------------------------

def test_decision_endpoint_dm_and_work_roundtrip(
        relay_env, state_root, endpoint_factory, short_decision_timeout):
    """The paved link, end-to-end over real HTTP: the endpoint's
    exact returned string is the DM reply; its exact returned words
    are the delivered work body, seen verbatim by the assigner,
    with the relay-verified signed proof flow intact."""
    ep = endpoint_factory(mode="reply", reply_text=ENDPOINT_REPLY,
                          work_body=ENDPOINT_WORK_BODY)

    async def _t():
        boss = await make(relay_env, state_root, "epboss", mode="manual")
        worker = await make(relay_env, state_root, "epworker",
                            decision_endpoint=ep.url)
        assert worker.decision_endpoint == ep.url
        assert worker._decision_declaration() == "linked"

        # DM: the endpoint's exact string comes back as the reply.
        await boss.send_message("epworker", "what do you say?")
        assert await wait_for(lambda: any(
            m.get("from") == "epworker" for m in boss.messages),
            timeout=20)
        reply = [m for m in boss.messages
                 if m.get("from") == "epworker"][0]
        assert reply["body"] == ENDPOINT_REPLY
        assert (reply.get("meta") or {}).get("autonomous") is True
        posted = [r for r in ep.requests if r.get("kind") == "message"]
        assert posted and posted[0]["message"]["body"] == "what do you say?"
        assert posted[0]["agent"]["username"] == "epworker"

        # Work: the endpoint's exact words are the delivery body.
        works = await boss.assign_work(
            ["epworker"], "Endpoint job",
            instructions="do it in your own words")
        wid = works[0]["id"]
        assert await wait_for(
            lambda: any(w["id"] == wid and w["status"] == "delivered"
                        for w in boss.work_updates), timeout=20)
        row = relay_env["relay"].store.get_work(wid)
        assert row["status"] == "delivered"
        assert row["proof_verified"] == 1  # relay-verified signature
        inbox = await boss.work_inbox()
        mine = [w for w in inbox if w["id"] == wid][0]
        assert mine["deliveries"], mine
        assert mine["deliveries"][0]["body"] == ENDPOINT_WORK_BODY
        assert mine["deliveries"][0]["deliverer"] == "epworker"
        assert any(e["event"] == "work_delivered"
                   for e in worker.autonomous_log)
        posted_work = [r for r in ep.requests if r.get("kind") == "work"]
        assert posted_work
        assert posted_work[0]["work"]["id"] == wid
        await boss.close()
        await worker.close()
    run(_t())


def test_decision_endpoint_work_with_progress_delivers(
        relay_env, state_root, endpoint_factory, short_decision_timeout):
    """Regression pin (production proof, 2026-11-02): an endpoint
    whose work decision REPORTS PROGRESS — percent arriving as a
    JSON float — must still deliver. The first production exercise
    of the paved link (deploy-probe) failed exactly here:
    report_progress's contract is int percent, the adapter replayed
    float(entry['percent']) verbatim, and every work decision died
    on bad_percent before the agent's own words could deliver."""
    ep = endpoint_factory(mode="reply", reply_text=ENDPOINT_REPLY,
                          work_body=ENDPOINT_WORK_BODY,
                          work_progress=True)

    async def _t():
        boss = await make(relay_env, state_root, "epboss2", mode="manual")
        worker = await make(relay_env, state_root, "epworker2",
                            decision_endpoint=ep.url)
        works = await boss.assign_work(
            ["epworker2"], "Endpoint job with progress",
            instructions="report progress, then deliver")
        wid = works[0]["id"]
        assert await wait_for(
            lambda: any(w["id"] == wid and w["status"] == "delivered"
                        for w in boss.work_updates), timeout=20)
        row = relay_env["relay"].store.get_work(wid)
        assert row["status"] == "delivered"
        assert row["proof_verified"] == 1
        # The float 50.0 crossed the adapter as int 50.
        assert row["progress_percent"] == 50
        assert isinstance(row["progress_percent"], int)
        inbox = await boss.work_inbox()
        mine = [w for w in inbox if w["id"] == wid][0]
        assert mine["deliveries"][0]["body"] == ENDPOINT_WORK_BODY
        await boss.close()
        await worker.close()
    run(_t())


def test_decision_endpoint_from_env_answers_dm(
        relay_env, state_root, endpoint_factory, monkeypatch,
        short_decision_timeout):
    """AGENTLINK_DECISION_ENDPOINT wires the same paved link with no
    constructor argument at all."""
    ep = endpoint_factory(mode="reply", reply_text=ENV_REPLY,
                          work_body="unused")
    monkeypatch.setenv("AGENTLINK_DECISION_ENDPOINT", ep.url)
    worker = Agent("envepworker", endpoint=relay_env["url"],
                   state_dir=str(state_root / "envepworker"))
    # The env must not leak into any other agent built in this test.
    monkeypatch.delenv("AGENTLINK_DECISION_ENDPOINT", raising=False)
    assert worker.decision_endpoint == ep.url
    assert worker._decision_declaration() == "linked"

    async def _t():
        await worker.start()
        boss = await make(relay_env, state_root, "envepboss",
                          mode="manual")
        assert boss.decision_endpoint is None
        await boss.send_message("envepworker", "env check")
        assert await wait_for(lambda: any(
            m.get("from") == "envepworker" for m in boss.messages),
            timeout=20)
        reply = [m for m in boss.messages
                 if m.get("from") == "envepworker"][0]
        assert reply["body"] == ENV_REPLY
        await boss.close()
        await worker.close()
    run(_t())


# ---------------------------------------------------------------------
# 3. ENDPOINT FAILURE = HELD, NEVER FABRICATED (+ silence != failure)
# ---------------------------------------------------------------------

async def _exercise_endpoint_failure(relay_env, state_root, url, tag):
    """One failure mode, both surfaces: a DM draws NO reply and NO
    read-marking (the message stays in the agent's inbox, unread,
    for later); assigned work draws NO delivery and NO acceptance
    (it stays assigned, untouched). The link failure is logged as
    exactly what it is — decision_link_error /
    work_decision_link_error — never as the agent's silence."""
    boss_name = f"{tag}boss"
    worker_name = f"{tag}worker"
    boss = await make(relay_env, state_root, boss_name, mode="manual")
    worker = await make(relay_env, state_root, worker_name,
                        decision_endpoint=url)
    # v1.8.0 verified declarations: the endpoint is wired but
    # its registration self-check FAILED (that is this pin's
    # setup), so the truthful declaration is "pending".
    assert worker._decision_declaration() == "pending"
    store = relay_env["relay"].store

    res = await boss.send_message(worker_name, "please answer this")
    mid = res["id"]
    assert await wait_for(lambda: any(
        e["event"] == "decision_link_error"
        for e in worker.autonomous_log), timeout=20), worker.autonomous_log
    await asyncio.sleep(0.6)  # a read flush, if wrongly queued, lands in 0.3s
    assert [m for m in boss.messages if m.get("from") == worker_name] == []
    assert store.reads_for([mid]) == {}          # never marked read
    assert mid not in worker._pending_reads
    assert not any(r.get("id") == mid for r in boss.read_receipts)
    # Held, not lost: the message is still in the agent's own inbox.
    assert any(m.get("id") == mid for m in worker.messages)

    works = await boss.assign_work([worker_name], "Failure job",
                                   instructions="do the thing")
    wid = works[0]["id"]
    assert await wait_for(lambda: any(
        e["event"] == "work_decision_link_error"
        and e.get("work_id") == wid
        for e in worker.autonomous_log), timeout=20), worker.autonomous_log
    await asyncio.sleep(0.6)
    row = store.get_work(wid)
    assert row["status"] == "assigned"           # not delivered/accepted
    assert row["proof_verified"] == 0
    inbox = await worker.work_inbox()
    mine = [w for w in inbox if w["id"] == wid][0]
    assert mine["status"] == "assigned"
    assert mine["deliveries"] == []
    assert not any(w["id"] == wid and w["status"] == "delivered"
                   for w in boss.work_updates)
    # No fabricated decline DM either: the agent never decided.
    assert [m for m in boss.messages if m.get("from") == worker_name] == []
    await boss.close()
    await worker.close()


def test_endpoint_unreachable_holds_message_and_work(
        relay_env, state_root, short_decision_timeout):
    run(_exercise_endpoint_failure(relay_env, state_root,
                                   closed_port_url(), "dead"))


def test_endpoint_http500_holds_message_and_work(
        relay_env, state_root, endpoint_factory, short_decision_timeout):
    ep = endpoint_factory(mode="error500")
    run(_exercise_endpoint_failure(relay_env, state_root, ep.url, "boom"))
    assert ep.requests  # the link really was exercised


def test_decision_link_error_raised_and_silence_returns_none(
        state_root, endpoint_factory, short_decision_timeout):
    """The link-level distinction, directly at _call_decision:
    unreachable and HTTP 500 RAISE DecisionLinkError (a failure —
    the agent never decided), while 204 and JSON null RETURN None
    (a decision: the agent chose silence)."""
    err500 = endpoint_factory(mode="error500")
    silent204 = endpoint_factory(mode="silence204")
    null_ep = endpoint_factory(mode="null")
    ctx = {"kind": "message", "agent": {"username": "probe"},
           "message": {"body": "hi"}, "sender": {"username": "x"},
           "conversation": {"type": "dm", "key": "dm:x"}, "recent": []}

    async def _t():
        dead = Agent("prodead", state_dir=str(state_root / "prodead"),
                     decision_endpoint=closed_port_url())
        with pytest.raises(DecisionLinkError):
            await dead._call_decision(ctx)
        boom = Agent("proboom", state_dir=str(state_root / "proboom"),
                     decision_endpoint=err500.url)
        with pytest.raises(DecisionLinkError):
            await boom._call_decision(ctx)
        hush = Agent("prohush", state_dir=str(state_root / "prohush"),
                     decision_endpoint=silent204.url)
        assert await hush._call_decision(ctx) is None
        null_agent = Agent("pronull",
                           state_dir=str(state_root / "pronull"),
                           decision_endpoint=null_ep.url)
        assert await null_agent._call_decision(ctx) is None
    run(_t())


def test_endpoint_silence_is_a_decision_not_a_failure(
        relay_env, state_root, endpoint_factory, short_decision_timeout):
    """204 and JSON-null endpoints over the live line: no reply and
    no delivery — but the observable record says the agent CHOSE
    silence (decision_silent / work_decision_silent) and records NO
    link error. That distinction is the whole point: silence is a
    decision; a dead link is not."""
    ep204 = endpoint_factory(mode="silence204")
    epnull = endpoint_factory(mode="null")

    async def _t():
        boss = await make(relay_env, state_root, "hushboss",
                          mode="manual")
        w204 = await make(relay_env, state_root, "hushworker",
                          decision_endpoint=ep204.url)
        wnull = await make(relay_env, state_root, "nullworker",
                           decision_endpoint=epnull.url)
        await boss.send_message("hushworker", "anything?")
        await boss.send_message("nullworker", "anything?")
        assert await wait_for(lambda: any(
            e["event"] == "decision_silent" for e in w204.autonomous_log),
            timeout=20)
        assert await wait_for(lambda: any(
            e["event"] == "decision_silent" for e in wnull.autonomous_log),
            timeout=20)
        await asyncio.sleep(0.6)
        assert boss.messages == []  # neither spoke — by choice
        for w in (w204, wnull):
            events = [e["event"] for e in w.autonomous_log]
            assert "decision_link_error" not in events
            assert "decision_error" not in events
        works = await boss.assign_work(["hushworker"], "Quiet job",
                                       instructions="maybe do it")
        wid = works[0]["id"]
        assert await wait_for(lambda: any(
            e["event"] == "work_decision_silent"
            and e.get("work_id") == wid for e in w204.autonomous_log),
            timeout=20)
        assert not any(e["event"] == "work_decision_link_error"
                       for e in w204.autonomous_log)
        row = relay_env["relay"].store.get_work(wid)
        assert row["status"] == "assigned"
        assert row["proof_verified"] == 0
        await boss.close()
        await w204.close()
        await wnull.close()
    run(_t())


# ---------------------------------------------------------------------
# 4. UNLINKED STATE SURFACES (client half: declaration/directory/store)
# ---------------------------------------------------------------------

def test_unlinked_linked_and_manual_declarations_surface(
        relay_env, state_root):
    """Client declaration, directory row and store row all state the
    same connection-side fact: autonomous+unwired = "pending",
    autonomous+callable = "linked", manual = "" (the store never
    records a link state for a manual agent — no question applies;
    the directory presents its decision_state as "operator")."""

    async def decide(ctx):
        return None

    async def _t():
        viewer = await make(relay_env, state_root, "dlviewer",
                            mode="manual")
        pending = await make(relay_env, state_root, "dlpending")
        linked = await make(relay_env, state_root, "dllinked",
                            decision_link=decide)
        manual = await make(relay_env, state_root, "dlmanual",
                            mode="manual")
        # The clients' own declarations (what their hellos carried).
        assert pending._decision_declaration() == "pending"
        assert linked._decision_declaration() == "linked"
        assert manual._decision_declaration() == ""
        assert pending.decision_linked is False
        assert linked.decision_linked is True
        # The directory, as any other agent sees it.
        rows = {r["username"]: r for r in await viewer.directory()}
        assert rows["dlpending"]["decision_link"] == "pending"
        assert rows["dlpending"]["decision_state"] == "pending"
        assert rows["dllinked"]["decision_link"] == "linked"
        assert rows["dllinked"]["decision_state"] == "linked"
        assert rows["dlmanual"]["decision_link"] == ""
        assert rows["dlmanual"]["decision_state"] == "operator"
        # The store rows underneath.
        stored = store_rows(relay_env)
        assert stored["dlpending"]["decision_link"] == "pending"
        assert stored["dllinked"]["decision_link"] == "linked"
        assert stored["dlmanual"]["decision_link"] == ""
        await viewer.close()
        await pending.close()
        await linked.close()
        await manual.close()
    run(_t())
