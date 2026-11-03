"""v1.3.7 delivery guarantee — ACCEPTANCE tests (Worker D).

The contract pinned here (owner's delivery law: a message is not
delivered until the recipient has DURABLY taken custody of it):

  * hello may declare ``"delivery_ack": 1``. For ack-capable
    clients the relay queue is a CUSTODY OUTBOX: frames are OFFERED
    on hello / drain but deleted ONLY when the client sends
    ``{"type": "ack", "ids": [...]}`` after durably journaling
    them. The audit row's status becomes "delivered" ONLY on ack.
  * Legacy clients (no declaration) keep today's behaviour:
    the hello flush dequeues — gone from the store, no ack needed.
  * The SDK client journals inbound messages into a canonical
    local mailbox (``state_dir/mailbox.db``) BEFORE processing;
    duplicates are acked but never reprocessed; journaled-but-not-
    taken-in items replay on the next start; ``Agent.inbox(...)``
    reads the mailbox OFFLINE; ``Agent.sync_history()`` backfills
    the mailbox from the relay's history frame
    (``{"type": "history"}`` -> result data ``{"rows": [...]}``).
  * Store surface: ``pending_frames(username)``,
    ``ack_frames(username, ids)``, ``queue_stats(username)``,
    ``count_online_since(username, ts)``,
    ``content_audit_for_user(username, limit, before_seq)``.
  * Stuck alert: an item unacked with age >
    ``timing.DELIVERY_STUCK_SECONDS`` (300) whose recipient has an
    'online' audit row after the item's queue ts raises an open
    ``delivery_stuck`` alert in ``relay._alert_scan``; acking
    resolves it.
  * Timing: DELIVERY_RESEND_SECONDS=30,
    DELIVERY_STUCK_SECONDS=300, DELIVERY_HISTORY_PAGE=200.

Everything runs the REAL chain (real Relay + real Agent clients on
a temp SQLite store, raw websockets where the protocol itself is
under test) — the harness is reused from tests/test_read_receipts.py
/ tests/test_autonomous.py.

CONTRACT GUESSES (the spec names these APIs but not their exact
signatures; the helpers below adapt, and the guesses are listed in
the worker report):
  * ``Agent.inbox(...)`` is called with no arguments and may be a
    plain method or a coroutine; its result may be a list of item
    dicts or a dict carrying them under items/messages/rows.
  * ``Agent.sync_history()`` may be sync or async.
  * ``pending_frames`` entries may be the frame dict itself or a
    wrapper carrying it under "payload"/"frame" (dict or JSON str).
  * ``queue_stats`` may be an int or a dict with a
    pending/count/queued/total-style key.
  * For the fresh-mailbox history test, the recipient IDENTITY
    (keys-*.json + secret-*.json) is transplanted into the fresh
    state dir — a truly empty dir could neither reclaim the
    username nor decrypt anything; "fresh" pins the MAILBOX.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import shutil
import sqlite3
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from websockets.client import connect

from agentlink import timing
from agentlink.client import Agent
from agentlink.crypto import Identity
from agentlink.relay import Relay

HOST = "127.0.0.1"


# ---------------------------------------------------------------------
# Harness (reused from tests/test_read_receipts.py / test_autonomous.py)
# ---------------------------------------------------------------------

@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-dg-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="test-dash-pass", dashboard_port=0)
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
           "db": db, "dash_port": relay.dashboard_port, "relay": relay,
           "loop_box": box}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-dg-agents-") as tmp:
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


async def wait_peer_gone(relay_env, username, timeout=5.0):
    return await wait_for(
        lambda: username not in relay_env["relay"].peers, timeout=timeout)


def run_scan(relay_env, now):
    """Run relay._alert_scan(now) once, on the relay's own loop."""
    relay = relay_env["relay"]
    fut = asyncio.run_coroutine_threadsafe(
        relay._alert_scan(int(now)), relay_env["loop_box"]["loop"])
    fut.result(timeout=15)


# ---------------------------------------------------------------------
# Contract adapters (see GUESSES in the module docstring)
# ---------------------------------------------------------------------

def _frame_of(entry):
    """The message frame inside a pending_frames entry, or None."""
    if not isinstance(entry, dict):
        return None
    if entry.get("type") == "message" or "content" in entry:
        return entry
    for key in ("payload", "frame"):
        inner = entry.get(key)
        if isinstance(inner, str):
            try:
                inner = json.loads(inner)
            except Exception:
                inner = None
        if isinstance(inner, dict):
            return inner
    return None


def _entry_id(entry):
    frame = _frame_of(entry)
    if frame is not None and frame.get("id"):
        return frame["id"]
    if isinstance(entry, dict):
        return entry.get("id") or entry.get("ref_id") \
            or entry.get("message_id")
    return None


def pending_frames(store, username):
    fn = getattr(store, "pending_frames", None)
    assert fn is not None, \
        "Store.pending_frames(username) is not implemented yet"
    return fn(username) or []


def pending_ids(store, username):
    return [_entry_id(e) for e in pending_frames(store, username)]


def audit_status(store, message_id):
    """Delivery status on the message's audit row (existing store
    surface: audit_rows_for_ids)."""
    for row in store.audit_rows_for_ids([message_id]):
        if row.get("ref_id") == message_id:
            return row.get("status")
    return None


def _item_id(item):
    if isinstance(item, dict):
        return item.get("id") or item.get("ref_id") \
            or item.get("message_id")
    return None


def _normalize_items(result):
    if result is None:
        return []
    if isinstance(result, dict):
        for key in ("items", "messages", "rows", "inbox"):
            if isinstance(result.get(key), list):
                return result[key]
        return [result] if _item_id(result) else []
    return list(result)


async def inbox_items(agent):
    """Agent.inbox(...) — the OFFLINE local-mailbox read. Works on a
    closed agent: the mailbox is a file, not a connection."""
    attr = getattr(agent, "inbox", None)
    assert attr is not None, \
        "Agent.inbox(...) is not implemented yet (local mailbox read)"
    if callable(attr):
        try:
            result = attr()
        except TypeError:
            result = attr(limit=200)
        if inspect.isawaitable(result):
            result = await result
    else:
        result = attr
    return _normalize_items(result)


async def wait_inbox(agent, message_id, timeout=10.0):
    for _ in range(int(timeout / 0.05)):
        items = await inbox_items(agent)
        if any(_item_id(i) == message_id for i in items):
            return True
        await asyncio.sleep(0.05)
    items = await inbox_items(agent)
    return any(_item_id(i) == message_id for i in items)


async def sync_history(agent):
    fn = getattr(agent, "sync_history", None)
    assert fn is not None, \
        "Agent.sync_history() is not implemented yet (history backfill)"
    result = fn()
    if inspect.isawaitable(result):
        result = await result
    return result


def mailbox_db_path(state_dir):
    return Path(state_dir) / "mailbox.db"


def mailbox_disk_contains(state_dir, needle):
    """True when any row of any table in mailbox.db mentions
    ``needle`` (as a column value or inside a JSON payload) —
    schema-agnostic proof the journal hit disk."""
    db = mailbox_db_path(state_dir)
    if not db.exists():
        return False
    con = sqlite3.connect(f"file:{db}?mode=ro", uri=True)
    try:
        tables = [r[0] for r in con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            try:
                rows = con.execute(f"SELECT * FROM {table}").fetchall()
            except sqlite3.Error:
                continue
            for row in rows:
                for value in row:
                    if isinstance(value, str) and needle in value:
                        return True
                    if isinstance(value, bytes) \
                            and needle.encode() in value:
                        return True
        return False
    finally:
        con.close()


# ---------------------------------------------------------------------
# A recording decision endpoint double (test 1): speaks the paved
# decision-link protocol over real HTTP, answers silence (JSON
# null), and records every event it was consulted on.
# ---------------------------------------------------------------------

class _DecisionRecorder:
    def __init__(self):
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
                body = b"null"  # the agent chose silence; no reply
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        self._server = ThreadingHTTPServer((HOST, 0), Handler)
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.url = f"http://{HOST}:{self._server.server_address[1]}/decide"

    def seen_ids(self):
        return [(r.get("message") or {}).get("id")
                for r in self.requests if r.get("kind") == "message"]

    def stop(self):
        self._server.shutdown()


# ---------------------------------------------------------------------
# Raw websocket helpers (tests 4, 6, 8, 10): the protocol itself.
# ---------------------------------------------------------------------

async def raw_hello(url, username, secret=None, ack=False,
                    pubkey="", sign_pub=""):
    ws = await connect(url)
    frame = {"type": "hello", "username": username,
             "display_name": username, "secret": secret,
             "ephemeral": False, "req_id": "raw-hello"}
    if pubkey:
        frame["pubkey"] = pubkey
        frame["sign_pub"] = sign_pub
    if ack:
        frame["delivery_ack"] = 1
    await ws.send(json.dumps(frame))
    welcome = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
    assert welcome.get("type") == "welcome", welcome
    return ws, welcome


async def raw_collect_until(ws, want_type="message", timeout=6.0):
    """Read frames until one of ``want_type`` arrives; return it
    (plus everything read before it)."""
    seen = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        raw = await asyncio.wait_for(
            ws.recv(), timeout=max(0.1, deadline - time.time()))
        frame = json.loads(raw)
        seen.append(frame)
        if frame.get("type") == want_type:
            return frame, seen
    raise AssertionError(
        f"no {want_type!r} frame offered; saw "
        f"{[f.get('type') for f in seen]}")


async def raw_register(relay_env, username, ack=False):
    """Register a raw identity (with a real pubkey, so SDK agents
    can encrypt to it), then disconnect and wait until the relay
    has dropped the peer. Returns the owner's secret."""
    ident = Identity.ephemeral()
    ws, welcome = await raw_hello(
        relay_env["url"], username, ack=ack,
        pubkey=ident.public_key_b64,
        sign_pub=ident.signing_public_key_b64)
    secret = welcome.get("secret")
    assert secret, welcome
    await ws.close()
    assert await wait_peer_gone(relay_env, username)
    return secret


# ---------------------------------------------------------------------
# 1. Check-in pattern: brief sessions still receive, exactly once
# ---------------------------------------------------------------------

def test_checkin_pattern_receives_without_prompt(relay_env, state_root):
    """A recipient that only 'checks in' (start, idle ~1s, stop)
    still receives a DM sent while it was away: on its NEXT start —
    with no test code touching the relay in between — the message
    is in its local mailbox, its decision path saw it exactly once,
    and the relay custody queue is empty (journaled -> acked)."""
    ep = _DecisionRecorder()
    try:
        async def _t():
            store = relay_env["relay"].store
            sender = await make(relay_env, state_root, "dg-ck-sender",
                                mode="manual")
            recip = await make(relay_env, state_root, "dg-ck-recip",
                               decision_endpoint=ep.url)
            await asyncio.sleep(1.0)          # the brief "check"
            await recip.close()
            assert await wait_peer_gone(relay_env, "dg-ck-recip")
            res = await sender.send_message(
                "dg-ck-recip", "check-in delivery, please")
            mid = res["id"]
            assert res["queued"] is True
            # The recipient starts again ON ITS OWN.
            recip2 = Agent("dg-ck-recip", endpoint=relay_env["url"],
                           state_dir=str(state_root / "dg-ck-recip"),
                           decision_endpoint=ep.url)
            await recip2.start()
            assert await wait_inbox(recip2, mid), \
                await inbox_items(recip2)
            assert await wait_for(
                lambda: ep.seen_ids().count(mid) == 1), ep.requests
            await asyncio.sleep(0.7)
            assert ep.seen_ids().count(mid) == 1  # exactly once
            items = [i for i in await inbox_items(recip2)
                     if _item_id(i) == mid]
            assert len(items) == 1
            assert items[0].get("body") == "check-in delivery, please"
            assert await wait_for(
                lambda: pending_ids(store, "dg-ck-recip") == [])
            assert await wait_for(
                lambda: audit_status(store, mid) == "delivered")
            await recip2.close()
            await sender.close()
        run(_t())
    finally:
        ep.stop()


# ---------------------------------------------------------------------
# 2. Daemon pattern: continuously connected recipient
# ---------------------------------------------------------------------

def test_daemon_pattern_receives(relay_env, state_root):
    """Same guarantee, boring topology: a continuously connected
    recipient's handler fires exactly once, the message lands in
    its mailbox, and the custody queue drains to empty on ack."""
    async def _t():
        store = relay_env["relay"].store
        sender = await make(relay_env, state_root, "dg-dm-sender",
                            mode="manual")
        recip = await make(relay_env, state_root, "dg-dm-recip",
                           mode="manual")
        got = []
        recip.on_message(lambda msg: got.append(msg))
        res = await sender.send_message("dg-dm-recip",
                                        "daemon delivery, please")
        mid = res["id"]
        assert await wait_for(lambda: len(got) == 1)
        assert got[0]["id"] == mid
        assert got[0]["body"] == "daemon delivery, please"
        assert await wait_inbox(recip, mid)
        assert await wait_for(
            lambda: pending_ids(store, "dg-dm-recip") == [])
        assert await wait_for(
            lambda: audit_status(store, mid) == "delivered")
        await asyncio.sleep(0.7)
        assert len(got) == 1  # still exactly once
        await sender.close()
        await recip.close()
    run(_t())


# ---------------------------------------------------------------------
# 3. One-shot journal: survives on disk, replays exactly once
# ---------------------------------------------------------------------

def test_oneshot_journal_survives_and_replays(relay_env, state_root):
    """Manual + auto_read=False + NO handler: the flush is journaled
    to mailbox.db on disk but NOT taken in. The next start (with a
    handler) replays it exactly once; a third start replays
    nothing."""
    async def _t():
        store = relay_env["relay"].store
        sender = await make(relay_env, state_root, "dg-os-sender",
                            mode="manual")
        recip_dir = state_root / "dg-os-recip"
        first = await make(relay_env, state_root, "dg-os-recip",
                           mode="manual", auto_read=False)
        await first.close()
        assert await wait_peer_gone(relay_env, "dg-os-recip")
        res = await sender.send_message("dg-os-recip",
                                        "one-shot journal entry")
        mid = res["id"]
        assert res["queued"] is True

        # Start #2: receives the flush, no handler — journal only.
        second = Agent("dg-os-recip", endpoint=relay_env["url"],
                       state_dir=str(recip_dir), mode="manual",
                       auto_read=False)
        await second.start()
        assert await wait_inbox(second, mid), await inbox_items(second)
        await second.close()
        # On DISK, in the canonical mailbox file.
        assert mailbox_db_path(recip_dir).exists(), \
            list(recip_dir.iterdir())
        assert mailbox_disk_contains(recip_dir, mid)

        # Start #3: a handler is wired — the journaled item replays.
        third = Agent("dg-os-recip", endpoint=relay_env["url"],
                      state_dir=str(recip_dir), mode="manual",
                      auto_read=False)
        got = []
        third.on_message(lambda msg: got.append(msg))
        await third.start()
        assert await wait_for(lambda: len(got) == 1)
        assert got[0]["id"] == mid
        assert got[0]["body"] == "one-shot journal entry"
        await asyncio.sleep(0.7)
        assert len(got) == 1
        await third.close()

        # Start #4: taken in already — nothing replays.
        fourth = Agent("dg-os-recip", endpoint=relay_env["url"],
                       state_dir=str(recip_dir), mode="manual",
                       auto_read=False)
        got4 = []
        fourth.on_message(lambda msg: got4.append(msg))
        await fourth.start()
        await asyncio.sleep(2.0)
        assert got4 == []
        # ...but the mailbox (the canonical history) still holds it,
        # exactly once.
        items = [i for i in await inbox_items(fourth)
                 if _item_id(i) == mid]
        assert len(items) == 1
        assert pending_ids(store, "dg-os-recip") == []
        await fourth.close()
        await sender.close()
    run(_t())


# ---------------------------------------------------------------------
# 4. Redelivery until ack (raw protocol)
# ---------------------------------------------------------------------

def test_redelivery_until_ack_raw(relay_env, state_root):
    """Custody outbox, raw: an ack-capable client that disconnects
    WITHOUT acking is offered the same frame again on its next
    hello — the frame never left the store queue, and the audit
    status is NOT 'delivered'. Only the ack deletes it and upgrades
    the audit row."""
    async def _t():
        store = relay_env["relay"].store
        secret = await raw_register(relay_env, "dg-raw-recip", ack=True)
        sender = await make(relay_env, state_root, "dg-raw-sender",
                            mode="manual")
        res = await sender.send_message("dg-raw-recip",
                                        "custody, not fire-and-forget")
        mid = res["id"]
        assert res["queued"] is True
        assert mid in pending_ids(store, "dg-raw-recip")

        # Hello #1: offered — read it, disconnect WITHOUT acking.
        ws, _w = await raw_hello(relay_env["url"], "dg-raw-recip",
                                 secret=secret, ack=True)
        offered, _seen = await raw_collect_until(ws, "message")
        assert offered["id"] == mid
        await ws.close()
        assert await wait_peer_gone(relay_env, "dg-raw-recip")
        # Still in custody; NOT delivered.
        assert mid in pending_ids(store, "dg-raw-recip")
        assert audit_status(store, mid) != "delivered"

        # Hello #2: offered AGAIN. This time ack after journaling.
        ws, _w = await raw_hello(relay_env["url"], "dg-raw-recip",
                                 secret=secret, ack=True)
        offered2, _seen = await raw_collect_until(ws, "message")
        assert offered2["id"] == mid
        await ws.send(json.dumps({"type": "ack", "ids": [mid]}))
        assert await wait_for(
            lambda: pending_ids(store, "dg-raw-recip") == [])
        assert await wait_for(
            lambda: audit_status(store, mid) == "delivered")
        await ws.close()
        await sender.close()
    run(_t())


# ---------------------------------------------------------------------
# 5. Dedupe: a re-offered duplicate is acked, never reprocessed
# ---------------------------------------------------------------------

def test_dedupe_exactly_once(relay_env, state_root):
    """Simulate the lost-ack drop: after a first delivery is
    journaled + handled, the SAME frame is offered again (driven by
    re-enqueueing the captured custody frame, as a relay whose ack
    never arrived would). The second start must ack the duplicate,
    keep exactly one mailbox row, and NEVER re-fire the handler."""
    async def _t():
        store = relay_env["relay"].store
        sender = await make(relay_env, state_root, "dg-dd-sender",
                            mode="manual")
        recip_dir = state_root / "dg-dd-recip"
        first0 = await make(relay_env, state_root, "dg-dd-recip",
                            mode="manual")
        await first0.close()
        assert await wait_peer_gone(relay_env, "dg-dd-recip")
        res = await sender.send_message("dg-dd-recip",
                                        "exactly once, please")
        mid = res["id"]
        # Capture the custody frame BEFORE the first delivery.
        entries = [e for e in pending_frames(store, "dg-dd-recip")
                   if _entry_id(e) == mid]
        assert len(entries) == 1, entries
        original_frame = _frame_of(entries[0])
        assert original_frame is not None

        # First start: journal + handle + ack.
        first = Agent("dg-dd-recip", endpoint=relay_env["url"],
                      state_dir=str(recip_dir), mode="manual")
        got1 = []
        first.on_message(lambda msg: got1.append(msg))
        await first.start()
        assert await wait_for(lambda: len(got1) == 1)
        assert await wait_for(
            lambda: pending_ids(store, "dg-dd-recip") == [])
        await first.close()
        assert await wait_peer_gone(relay_env, "dg-dd-recip")

        # The ack was "lost": the relay re-offers the same frame.
        store.enqueue("dg-dd-recip", dict(original_frame))
        assert mid in pending_ids(store, "dg-dd-recip")

        # Second start: duplicate acked, never reprocessed.
        second = Agent("dg-dd-recip", endpoint=relay_env["url"],
                       state_dir=str(recip_dir), mode="manual")
        got2 = []
        second.on_message(lambda msg: got2.append(msg))
        await second.start()
        assert await wait_for(
            lambda: pending_ids(store, "dg-dd-recip") == [])
        await asyncio.sleep(1.0)
        assert got2 == [], got2
        items = [i for i in await inbox_items(second)
                 if _item_id(i) == mid]
        assert len(items) == 1, items
        await second.close()
        await sender.close()
    run(_t())


# ---------------------------------------------------------------------
# 6. Stuck alert: fires on aged unacked custody, resolves on ack
# ---------------------------------------------------------------------

def test_stuck_alert_fires_and_resolves(relay_env, state_root):
    """An ack-capable recipient that came online (online audit row
    exists) but never acks: once the queued item's age passes
    DELIVERY_STUCK_SECONDS, _alert_scan opens a 'delivery_stuck'
    alert for it. Acking the item resolves the alert."""
    async def _t():
        store = relay_env["relay"].store
        stuck_after = getattr(timing, "DELIVERY_STUCK_SECONDS", None)
        assert stuck_after == 300, \
            f"timing.DELIVERY_STUCK_SECONDS must be 300, got {stuck_after}"
        secret = await raw_register(relay_env, "dg-stuck-recip",
                                    ack=True)
        sender = await make(relay_env, state_root, "dg-stuck-sender",
                            mode="manual")
        res = await sender.send_message("dg-stuck-recip",
                                        "stuck in custody")
        mid = res["id"]
        assert mid in pending_ids(store, "dg-stuck-recip")

        # Age the custody row past the stuck threshold (direct store
        # manipulation is allowed in tests). The recipient's online
        # audit row (~now) is now AFTER the item's queue ts, as the
        # contract requires.
        old_ts = int(time.time()) - (stuck_after + 120)
        with store._lock:
            store._db.execute(
                "UPDATE queue SET ts = ? WHERE to_username = ?",
                (old_ts, "dg-stuck-recip"))
            store._db.commit()

        run_scan(relay_env, int(time.time()))
        open_alerts = [a for a in store.list_alerts(status="open")
                       if a["kind"] == "delivery_stuck"
                       and a["subject"] == "dg-stuck-recip"]
        assert len(open_alerts) == 1, store.list_alerts(status="open")

        # Acknowledge the item over a fresh hello: alert resolves.
        ws, _w = await raw_hello(relay_env["url"], "dg-stuck-recip",
                                 secret=secret, ack=True)
        offered, _seen = await raw_collect_until(ws, "message")
        assert offered["id"] == mid
        await ws.send(json.dumps({"type": "ack", "ids": [mid]}))
        assert await wait_for(
            lambda: pending_ids(store, "dg-stuck-recip") == [])
        await ws.close()
        run_scan(relay_env, int(time.time()))
        still_open = [a for a in store.list_alerts(status="open")
                      if a["kind"] == "delivery_stuck"
                      and a["subject"] == "dg-stuck-recip"]
        assert still_open == [], store.list_alerts(status="open")
        await sender.close()
    run(_t())


# ---------------------------------------------------------------------
# 7. History sync backfills a fresh mailbox
# ---------------------------------------------------------------------

def test_history_sync_backfills_fresh_mailbox(relay_env, state_root):
    """Two agents exchange DMs; then the recipient identity starts
    on a FRESH state dir (fresh mailbox; identity transplanted —
    see module docstring) and sync_history() backfills its inbox
    from the relay's history. Running sync twice adds nothing."""
    async def _t():
        sender = await make(relay_env, state_root, "dg-hs-sender",
                            mode="manual")
        recip = await make(relay_env, state_root, "dg-hs-recip",
                           mode="manual")
        res = await sender.send_message("dg-hs-recip",
                                        "history-worthy hello")
        mid = res["id"]
        assert await wait_for(lambda: len(recip.messages) == 1)
        back = await recip.send_message("dg-hs-sender",
                                        "and a reply, for the record")
        assert back["id"]
        assert await wait_for(lambda: len(sender.messages) == 1)
        orig_dir = state_root / "dg-hs-recip"
        await recip.close()
        await sender.close()

        fresh_dir = state_root / "dg-hs-recip-fresh"
        fresh_dir.mkdir(parents=True)
        # Identity transplant: keys + secret move; the mailbox does
        # NOT — mailbox.db must not exist in the fresh home.
        for name in ("keys-dg-hs-recip.json", "secret-dg-hs-recip.json"):
            shutil.copy(orig_dir / name, fresh_dir / name)
        assert not mailbox_db_path(fresh_dir).exists()

        fresh = Agent("dg-hs-recip", endpoint=relay_env["url"],
                      state_dir=str(fresh_dir), mode="manual")
        await fresh.start()
        await sync_history(fresh)
        assert await wait_inbox(fresh, mid), await inbox_items(fresh)
        items = [i for i in await inbox_items(fresh)
                 if _item_id(i) == mid]
        assert len(items) == 1
        total = len(await inbox_items(fresh))
        # Dedupe: a second sync is a no-op.
        await sync_history(fresh)
        await asyncio.sleep(0.5)
        items2 = await inbox_items(fresh)
        assert len(items2) == total
        assert len([i for i in items2 if _item_id(i) == mid]) == 1
        await fresh.close()
    run(_t())


# ---------------------------------------------------------------------
# 8. Legacy flush unchanged (raw protocol, no ack declaration)
# ---------------------------------------------------------------------

def test_legacy_flush_unchanged(relay_env, state_root):
    """A client whose hello does NOT declare delivery_ack keeps the
    old semantics: the hello flush hands the frame over AND deletes
    it from the store queue — no ack exists, none is needed."""
    async def _t():
        store = relay_env["relay"].store
        secret = await raw_register(relay_env, "dg-leg-recip",
                                    ack=False)
        sender = await make(relay_env, state_root, "dg-leg-sender",
                            mode="manual")
        res = await sender.send_message("dg-leg-recip",
                                        "legacy flush me")
        mid = res["id"]
        assert res["queued"] is True
        assert mid in pending_ids(store, "dg-leg-recip")

        ws, welcome = await raw_hello(relay_env["url"], "dg-leg-recip",
                                      secret=secret, ack=False)
        assert welcome.get("queued", 0) >= 1
        offered, _seen = await raw_collect_until(ws, "message")
        assert offered["id"] == mid
        # Gone from the store queue immediately — flush semantics.
        assert pending_ids(store, "dg-leg-recip") == []
        assert await wait_for(
            lambda: audit_status(store, mid) == "delivered")
        await ws.close()
        await sender.close()
    run(_t())


# ---------------------------------------------------------------------
# 9. Journal BEFORE processing: a crashing handler loses nothing
# ---------------------------------------------------------------------

def test_journal_before_processing(relay_env, state_root):
    """The handler raises on the message: the item is STILL in the
    mailbox afterwards (the journal write preceded processing) and
    the relay queue is empty (the ack rode the journal write, not
    the handler's success)."""
    async def _t():
        store = relay_env["relay"].store
        sender = await make(relay_env, state_root, "dg-jb-sender",
                            mode="manual")
        recip_dir = state_root / "dg-jb-recip"
        first = await make(relay_env, state_root, "dg-jb-recip",
                           mode="manual", auto_read=False)
        await first.close()
        assert await wait_peer_gone(relay_env, "dg-jb-recip")
        res = await sender.send_message("dg-jb-recip",
                                        "crash all you like")
        mid = res["id"]

        attempts = []

        def exploding(msg):
            attempts.append(msg)
            raise RuntimeError("handler boom")

        recip = Agent("dg-jb-recip", endpoint=relay_env["url"],
                      state_dir=str(recip_dir), mode="manual",
                      auto_read=False)
        recip.on_message(exploding)
        await recip.start()
        assert await wait_for(lambda: len(attempts) == 1)
        assert attempts[0]["id"] == mid
        # Acked from the journal write — custody released.
        assert await wait_for(
            lambda: pending_ids(store, "dg-jb-recip") == [])
        # ...and the item survives in the mailbox, on disk.
        assert await wait_inbox(recip, mid), await inbox_items(recip)
        await recip.close()
        assert mailbox_disk_contains(recip_dir, mid)
        await sender.close()
    run(_t())


# ---------------------------------------------------------------------
# 10. Store surface + timing constants (the contract's plumbing)
# ---------------------------------------------------------------------

def test_store_delivery_surface_and_timing_constants(relay_env,
                                                      state_root):
    """Timing constants and the store's delivery surface, exercised
    end-to-end against a real queued item: pending_frames lists it,
    queue_stats counts it, count_online_since sees the recipient's
    hello, content_audit_for_user returns its audit row, and
    ack_frames releases custody."""
    # Timing law (agentlink/timing.py).
    assert getattr(timing, "DELIVERY_RESEND_SECONDS", None) == 30
    assert getattr(timing, "DELIVERY_STUCK_SECONDS", None) == 300
    assert getattr(timing, "DELIVERY_HISTORY_PAGE", None) == 200

    async def _t():
        store = relay_env["relay"].store
        for name in ("pending_frames", "ack_frames", "queue_stats",
                     "count_online_since", "content_audit_for_user"):
            assert callable(getattr(store, name, None)), \
                f"Store.{name} is not implemented yet"
        t0 = int(time.time()) - 5
        secret = await raw_register(relay_env, "dg-sf-recip", ack=True)
        assert secret
        sender = await make(relay_env, state_root, "dg-sf-sender",
                            mode="manual")
        res = await sender.send_message("dg-sf-recip",
                                        "surface check")
        mid = res["id"]

        frames = pending_frames(store, "dg-sf-recip")
        assert [_entry_id(e) for e in frames] == [mid], frames

        stats = store.queue_stats("dg-sf-recip")
        count = None
        if isinstance(stats, int):
            count = stats
        elif isinstance(stats, dict):
            for key in ("pending", "count", "queued", "total",
                        "depth", "frames_pending", "unacked"):
                if isinstance(stats.get(key), int):
                    count = stats[key]
                    break
            if count is None and isinstance(stats.get("frames"), list):
                count = len(stats["frames"])
        assert count == 1, f"queue_stats -> {stats!r}"

        # The registration hello left an 'online' audit row.
        assert store.count_online_since("dg-sf-recip", t0) >= 1
        assert store.count_online_since(
            "dg-sf-recip", int(time.time()) + 3600) == 0

        rows = None
        for args in (("dg-sf-recip", 50, None), ("dg-sf-recip", 50, 0),
                     ("dg-sf-recip", 50)):
            try:
                rows = store.content_audit_for_user(*args)
                break
            except TypeError:
                continue
        assert rows is not None, "content_audit_for_user call failed"
        mine = [r for r in rows if r.get("ref_id") == mid]
        assert len(mine) == 1, rows
        assert (mine[0].get("to") or mine[0].get("target")) \
            == "dg-sf-recip"

        # Store-level ack releases custody (the relay's ack frame
        # handler rides this same surface).
        store.ack_frames("dg-sf-recip", [mid])
        assert pending_frames(store, "dg-sf-recip") == []
        await sender.close()
    run(_t())


def test_supabase_ack_frames_deletes_integer_seqs():
    """Regression pin (v1.3.7 production proof): PostgREST returns
    the queue's seq column as INTEGERS. SupabaseStore.ack_frames
    built its delete filter with ",".join(chunk) over those ints —
    TypeError, the delete never ran, and every production ack
    errored with custody never completing (phoenix + deploy-probe
    queues stuck at 'acked 0, N still waiting' on deploy night).
    The SQLite store deletes by bound parameter and never saw it.
    Pin the Supabase shape: int seqs in, a string in.(...) filter
    out, frames retired."""
    import json as _json

    from agentlink.supabase_store import SupabaseStore

    store = SupabaseStore("https://example.invalid", "k")
    rows = [
        {"seq": 41, "payload": _json.dumps(
            {"type": "message", "id": "m-int-1"})},
        {"seq": 42, "payload": _json.dumps(
            {"type": "work_assigned", "work": {"id": "w-int-2"}})},
        {"seq": 43, "payload": _json.dumps(
            {"type": "message", "id": "m-int-3"})},
    ]
    store._get = lambda table, query: list(rows)
    deleted = []

    def _fake_delete_ids(table, col, ids):
        # Reproduce the real _delete_ids filter construction.
        chunk = list(ids)
        filt = f"{col}=in.(" + ",".join(str(v) for v in chunk) + ")"
        deleted.append((table, filt))
        return len(chunk)

    store._delete_ids = _fake_delete_ids
    acked = store.ack_frames("someone", ["m-int-1", "w-int-2"])
    assert [f.get("id") or (f.get("work") or {}).get("id")
            for f in acked] == ["m-int-1", "w-int-2"]
    assert deleted == [("queue", "seq=in.(41,42)")], deleted
    # And the real _delete_ids itself must not raise on int ids
    # (drop the instance-level fake so the class method runs).
    del store._delete_ids
    seen = {}
    store._delete_where = lambda table, query: seen.update(
        {"q": query}) or 1
    assert store._delete_ids("queue", "seq", [7, 8]) == 1
    assert seen["q"] == "seq=in.(7,8)", seen
