"""Recovery key pins (v1.7.0, owner's design).

The owner's model: an agent must LOGIN BACK, never re-register —
like a crypto private key. Hold the recovery key and everything
(conversations, groups, vault, unread custody queue) is restored;
lose it and there is no way back. All account state lives
server-side under the username; the recovery key is the missing
independent credential, and the workspace file is the durable
storage contract the owner ordered ("most things can't be wiped
on workspace — that is exactly where documents are saved").

Pinned here:
  1. claim issues a recovery key; the store holds ONLY its
     SHA-256 hash — the plaintext is absent from the user row,
     from the whole users table, and from a serialized dashboard
     payload; the dashboard row exposes recovery_enrolled only;
     both storage copies exist at their exact paths, mode 0600,
     and the workspace file carries the owner's warning;
  2. enrollment: a pre-1.7.0 row (no hash) is issued a key ONCE
     on its first verified hello, and never again;
  3. reclaim with the correct key rebinds new identity keys (the
     old key hello now fails, the new one succeeds), rotates the
     account secret (the old secret is dead), BURNS the used key
     (replay refused) and issues a working successor;
  4. a wrong key is refused recovery_failed and NOTHING on the
     row changes; unenrolled rows and unknown users are refused
     the same way;
  5. a queued unread DM + a group membership survive a simulated
     FULL state wipe (fresh state dir; the workspace file alone
     remains) and flow after auto-reclaim;
  6. a recovery login writes the audit row and fires the fleet
     alert;
  7. the manual path: Agent(recovery_key=...) reclaims
     explicitly.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import shutil
import sqlite3
import tempfile
import threading
from pathlib import Path

import pytest
from websockets.client import connect

from agentlink.client import Agent, RegistrationFailed
from agentlink.crypto import Identity
from agentlink.protocol import auth_challenge_payload
from agentlink.relay import Relay

HOST = "127.0.0.1"


class RelayHandle:
    """One real relay on its own thread/loop (the key-hello
    harness shape)."""

    def __init__(self, db, name):
        self.db = db
        self.name = name
        self.relay = None
        self.loop = None
        self.thread = None
        self.port = 0
        self.dash_port = 0

    def start(self):
        self.relay = Relay(host=HOST, port=self.port, db_path=self.db,
                           server_name=self.name,
                           dashboard_password="test-password",
                           dashboard_port=self.dash_port)
        ready = threading.Event()

        def _thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.loop = loop

            async def _serve():
                await self.relay.start()
                ready.set()
                await asyncio.Future()

            try:
                loop.run_until_complete(_serve())
            except (RuntimeError, asyncio.CancelledError):
                pass

        self.thread = threading.Thread(target=_thread, daemon=True)
        self.thread.start()
        assert ready.wait(timeout=10)
        self.port = self.relay.port
        self.dash_port = self.relay.dashboard_port
        return f"ws://{HOST}:{self.relay.port}"

    def stop(self):
        if self.relay is not None and self.loop is not None:
            fut = asyncio.run_coroutine_threadsafe(
                self.relay.stop(), self.loop)
            try:
                fut.result(timeout=10)
            except Exception:
                pass
            self.relay = None


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def wait_for(pred, timeout=20.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-rk-agents-") as tmp:
        yield Path(tmp)


def _db(tmp):
    return str(Path(tmp) / "shared.db")


def _sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def _row(db, username):
    conn = sqlite3.connect(db)
    conn.row_factory = sqlite3.Row
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _sql(db, statement, params=()):
    conn = sqlite3.connect(db)
    try:
        cur = conn.execute(statement, params)
        rows = cur.fetchall()
        conn.commit()
        return rows
    finally:
        conn.close()


async def _raw_recovery_hello(url, username, identity, key):
    """One raw recovery hello attempt; returns the first frame
    after the hello (welcome or error — recovery has no
    challenge step)."""
    async with connect(url) as ws:
        await ws.send(json.dumps({
            "type": "hello", "username": username,
            "display_name": username, "secret": None,
            "auth": "recovery", "recovery_key": key,
            "ephemeral": False,
            "pubkey": identity.public_key_b64,
            "sign_pub": identity.signing_public_key_b64,
            "capabilities": [], "mode": "autonomous"}))
        return json.loads(await asyncio.wait_for(ws.recv(), 10))


async def _raw_key_hello_last(url, username, identity):
    """One raw key-signed hello; returns the terminal frame."""
    async with connect(url) as ws:
        await ws.send(json.dumps({
            "type": "hello", "username": username,
            "display_name": username, "secret": None,
            "auth": "key", "ephemeral": False,
            "pubkey": identity.public_key_b64,
            "sign_pub": identity.signing_public_key_b64,
            "capabilities": [], "mode": "autonomous"}))
        while True:
            frame = json.loads(await asyncio.wait_for(ws.recv(), 10))
            if frame.get("type") == "auth_challenge":
                payload = auth_challenge_payload(
                    frame["nonce"], frame["relay"], username,
                    frame["expires"])
                await ws.send(json.dumps({
                    "type": "auth_response",
                    "signature": identity.sign(payload)}))
                continue
            return frame


async def _raw_secret_hello(url, username, identity, secret):
    async with connect(url) as ws:
        await ws.send(json.dumps({
            "type": "hello", "username": username,
            "display_name": username, "secret": secret,
            "ephemeral": False,
            "pubkey": identity.public_key_b64,
            "sign_pub": identity.signing_public_key_b64,
            "capabilities": [], "mode": "autonomous"}))
        return json.loads(await asyncio.wait_for(ws.recv(), 10))


def test_claim_issues_key_hash_only_and_storage_contract(state_root):
    """Pin 1: the claiming hello issues a recovery key; the store
    holds only its hash; both durable copies land at their exact
    paths with mode 0600; the dashboard sees enrolled-only."""
    tmp = tempfile.mkdtemp(prefix="agentlink-rk-")
    db = _db(tmp)
    h = RelayHandle(db, "rk-claim")
    url = h.start()
    ws_dir = state_root / "ws-claim"
    holder = {}

    async def _t():
        a = Agent("recclaim", endpoint=url,
                  state_dir=str(state_root / "recclaim"),
                  workspace=str(ws_dir))
        await a.start()
        try:
            holder["key"] = a.recovery_key
            assert a.recovery_key, "no recovery key surfaced at claim"
            assert len(a.recovery_key) >= 32
            holder["file"] = a.recovery_file
        finally:
            await a.close()

    run(_t())
    key = holder["key"]
    row = _row(db, "recclaim")
    assert row["recovery_hash"] == _sha(key), \
        "the store must hold exactly the key's SHA-256 hash"
    assert row["recovery_used_at"] == 0
    # The plaintext appears NOWHERE server-side: not in the row,
    # not anywhere in the users table, not in the dashboard
    # payload (which also must not carry the hash).
    assert key not in json.dumps(row)
    all_rows = _sql(db, "SELECT * FROM users")
    assert key not in json.dumps([list(r) for r in all_rows])
    data = h.relay._dashboard_data()
    payload = json.dumps(data)
    assert key not in payload
    assert row["recovery_hash"] not in payload
    urow = [u for u in data["users"]
            if u["username"] == "recclaim"][0]
    assert urow["recovery_enrolled"] is True
    assert urow["recovery_used_at"] == 0
    assert "recovery_hash" not in urow
    # The storage contract: state-dir copy + THE WORKSPACE FILE,
    # both 0600; the workspace file explains itself.
    sp = state_root / "recclaim" / "recovery-recclaim.json"
    assert sp.exists()
    assert json.loads(sp.read_text())["recovery_key"] == key
    assert (sp.stat().st_mode & 0o777) == 0o600
    wp = ws_dir / "agentlink-recovery-recclaim.txt"
    assert str(wp) == holder["file"]
    assert wp.exists()
    assert (wp.stat().st_mode & 0o777) == 0o600
    text = wp.read_text()
    assert key in text
    assert "NEVER DELETE THIS FILE" in text
    assert "recclaim" in text
    h.stop()


def test_enrollment_issues_once_for_existing_agent(state_root):
    """Pin 2: a row with no recovery hash (every pre-1.7.0
    registration) is issued a key on its first VERIFIED hello —
    and not on the next one."""
    tmp = tempfile.mkdtemp(prefix="agentlink-rk-")
    db = _db(tmp)
    h = RelayHandle(db, "rk-enroll")
    url = h.start()
    ws_dir = state_root / "ws-enroll"
    sd = state_root / "oldenroll"

    async def _t():
        a = Agent("oldenroll", endpoint=url, state_dir=str(sd),
                  workspace=str(ws_dir))
        await a.start()
        await a.close()
        # Simulate the pre-1.7.0 world: no hash on the row, no
        # client copies anywhere.
        _sql(db, "UPDATE users SET recovery_hash = ''"
                 " WHERE username = 'oldenroll'")
        for p in (sd / "recovery-oldenroll.json",
                  ws_dir / "agentlink-recovery-oldenroll.txt"):
            if p.exists():
                p.unlink()
        # First verified hello after the upgrade: enrollment.
        b = Agent("oldenroll", endpoint=url, state_dir=str(sd),
                  workspace=str(ws_dir))
        await b.start()
        try:
            enrolled_key = b.recovery_key
            assert enrolled_key, "enrollment did not issue a key"
        finally:
            await b.close()
        assert _row(db, "oldenroll")["recovery_hash"] == \
            _sha(enrolled_key)
        # Delete the client copies again: a re-issue would write
        # fresh ones and rotate the stored hash. Neither happens.
        for p in (sd / "recovery-oldenroll.json",
                  ws_dir / "agentlink-recovery-oldenroll.txt"):
            if p.exists():
                p.unlink()
        c = Agent("oldenroll", endpoint=url, state_dir=str(sd),
                  workspace=str(ws_dir))
        await c.start()
        try:
            assert c.recovery_key is None, \
                "a second key was issued to an enrolled agent"
        finally:
            await c.close()
        assert _row(db, "oldenroll")["recovery_hash"] == \
            _sha(enrolled_key)
        assert not (ws_dir / "agentlink-recovery-oldenroll.txt"
                    ).exists()

    run(_t())
    h.stop()


def test_reclaim_rebinds_rotates_burns_and_audits(state_root):
    """Pin 3 + 6: correct-key reclaim from a full wipe rebinds the
    identity (old key dead, new key live), rotates the secret
    (old secret dead), burns the used key (replay refused),
    issues a working successor — and writes the audit row + the
    owner alert."""
    tmp = tempfile.mkdtemp(prefix="agentlink-rk-")
    db = _db(tmp)
    h = RelayHandle(db, "rk-reclaim")
    url = h.start()
    ws_dir = state_root / "ws-reclaim"
    sd = state_root / "recdown"
    sd2 = state_root / "recdown-fresh"
    holder = {}

    async def _t():
        a = Agent("recdown", endpoint=url, state_dir=str(sd),
                  workspace=str(ws_dir))
        await a.start()
        holder["key1"] = a.recovery_key
        holder["old_ident"] = Identity("recdown", str(sd))
        holder["old_secret"] = json.loads(
            (sd / "secret-recdown.json").read_text())["secret"]
        await a.close()
        # FULL WIPE of the client state. Only the workspace
        # survives — exactly the owner's scenario.
        shutil.rmtree(sd)
        # Boot fresh: no saved secret, brand-new identity — the
        # workspace recovery file alone logs the agent back in.
        b = Agent("recdown", endpoint=url, state_dir=str(sd2),
                  workspace=str(ws_dir))
        await b.start()
        try:
            assert b.username == "recdown"
            holder["key2"] = b.recovery_key
            holder["new_ident"] = Identity("recdown", str(sd2))
            holder["new_secret"] = json.loads(
                (sd2 / "secret-recdown.json").read_text())["secret"]
        finally:
            await b.close()

    run(_t())
    key1, key2 = holder["key1"], holder["key2"]
    assert key2 and key2 != key1, "rotation must issue a NEW key"
    row = _row(db, "recdown")
    assert row["recovery_hash"] == _sha(key2)
    assert row["recovery_used_at"] > 0
    assert row["auth_method"] == "recovery"
    # Secret rotated: the row's stored hash matches the NEW
    # secret only.
    assert row["secret"] == _sha(holder["new_secret"])
    assert row["secret"] != _sha(holder["old_secret"])
    # The workspace file was rewritten with the successor key.
    text = (ws_dir / "agentlink-recovery-recdown.txt").read_text()
    assert key2 in text and key1 not in text

    async def _t2():
        # Replay of the BURNED key: refused, distinctly.
        attacker = Identity.ephemeral()
        last = await _raw_recovery_hello(url, "recdown", attacker,
                                         key1)
        assert last["type"] == "error"
        assert last["reason"] == "recovery_failed"
        # The OLD identity's key hello is dead (keys rebound).
        last = await _raw_key_hello_last(url, "recdown",
                                         holder["old_ident"])
        assert last["type"] == "error"
        assert last["reason"] == "key_auth_failed"
        # The OLD secret is dead too.
        last = await _raw_secret_hello(url, "recdown",
                                       holder["old_ident"],
                                       holder["old_secret"])
        assert last["type"] == "error"
        assert last["reason"] == "username_taken"
        # The NEW identity authenticates by key...
        last = await _raw_key_hello_last(url, "recdown",
                                         holder["new_ident"])
        assert last["type"] == "welcome"
        # ...and the successor recovery key works (burning itself
        # in the process — proven by the hash moving again).
        last = await _raw_recovery_hello(url, "recdown",
                                         Identity.ephemeral(), key2)
        assert last["type"] == "welcome"
        assert last.get("recovery_key")
        assert last["recovery_key"] != key2
        assert _row(db, "recdown")["recovery_hash"] == \
            _sha(last["recovery_key"])

    run(_t2())
    # Audit + alert (post-welcome writes — wait for them).
    async def _t3():
        assert await wait_for(lambda: _sql(
            db, "SELECT COUNT(*) FROM audit_log"
                " WHERE kind = 'recovery_login'"
                " AND actor = 'recdown'")[0][0] >= 1)
        assert await wait_for(lambda: _sql(
            db, "SELECT COUNT(*) FROM alerts"
                " WHERE kind = 'recovery_login'"
                " AND subject = 'recdown'")[0][0] >= 1)

    run(_t3())
    h.stop()


def test_wrong_key_refused_and_row_untouched(state_root):
    """Pin 4: wrong key / unenrolled / unknown — all refused
    recovery_failed, and a refused attempt changes NOTHING on
    the row (keys, secret, hash all identical after)."""
    tmp = tempfile.mkdtemp(prefix="agentlink-rk-")
    db = _db(tmp)
    h = RelayHandle(db, "rk-refuse")
    url = h.start()
    ws_dir = state_root / "ws-refuse"

    async def _t():
        a = Agent("recguard", endpoint=url,
                  state_dir=str(state_root / "recguard"),
                  workspace=str(ws_dir))
        await a.start()
        await a.close()
        before = _row(db, "recguard")
        stranger = Identity.ephemeral()
        last = await _raw_recovery_hello(
            url, "recguard", stranger, "not-the-recovery-key")
        assert last["type"] == "error"
        assert last["reason"] == "recovery_failed"
        after = _row(db, "recguard")
        for col in ("pubkey", "sign_pub", "secret",
                    "recovery_hash", "recovery_used_at"):
            assert after[col] == before[col], \
                f"a refused recovery changed {col}"
        # Unenrolled row: even a well-formed key is refused.
        _sql(db, "UPDATE users SET recovery_hash = ''"
                 " WHERE username = 'recguard'")
        last = await _raw_recovery_hello(
            url, "recguard", stranger,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        assert last["type"] == "error"
        assert last["reason"] == "recovery_failed"
        # Unknown username: refused — never a silent fresh claim.
        last = await _raw_recovery_hello(
            url, "recghost", stranger,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
        assert last["type"] == "error"
        assert last["reason"] == "recovery_failed"
        assert _row(db, "recghost") is None

    run(_t())
    h.stop()


def test_wipe_reclaim_restores_queue_and_group(state_root):
    """Pin 5: the owner's headline scenario end-to-end — a DM
    queued while the agent is down + its group membership
    survive a FULL client-state wipe and flow after the fresh
    client auto-reclaims from the workspace file alone."""
    tmp = tempfile.mkdtemp(prefix="agentlink-rk-")
    db = _db(tmp)
    h = RelayHandle(db, "rk-wipe")
    url = h.start()
    ws_dir = state_root / "ws-wipe"
    sd = state_root / "recmember"
    sd2 = state_root / "recmember-fresh"
    holder = {}

    async def _t():
        boss = Agent("recboss", endpoint=url,
                     state_dir=str(state_root / "recboss"))
        await boss.start()
        member = Agent("recmember", endpoint=url, state_dir=str(sd),
                       workspace=str(ws_dir))
        await member.start()
        g = await boss.group_create("Recovery Crew", ["recmember"])
        holder["gid"] = g["group_id"]
        await member.close()
        # The DM lands in custody while the member is offline.
        await boss.send_message("recmember",
                                "queued while you were wiped")
        # FULL WIPE: the entire state dir goes. The workspace
        # file is all that remains of the agent's identity.
        shutil.rmtree(sd)
        back = Agent("recmember", endpoint=url, state_dir=str(sd2),
                     workspace=str(ws_dir))
        await back.start()
        try:
            assert back.username == "recmember"
            # The queued DM is restored into the reclaimed
            # agent's inbox/history — same message, custody
            # honored across the wipe. Its BODY was sealed to
            # the wiped identity's encryption key, so the new
            # keypair cannot open it (body empty, sealed=True):
            # that is E2EE physics, pinned honestly rather than
            # papered over — the record, the membership and the
            # line are what the recovery key restores, and the
            # owner-side oversight copy stays readable on the
            # dashboard by design.
            assert await wait_for(
                lambda: any(
                    m.get("from") == "recboss"
                    for m in back.inbox(limit=50)))
            restored = [m for m in back.inbox(limit=50)
                        if m.get("from") == "recboss"][0]
            assert restored["sealed"] is True
            assert restored["body"] == ""
            # And the restored line is FULLY functional: a fresh
            # DM seals to the NEW keys and arrives readable.
            await boss.send_message("recmember", "welcome back")
            assert await wait_for(
                lambda: any(
                    m.get("body") == "welcome back"
                    for m in back.inbox(limit=50)))
            members = await back.group_members(holder["gid"])
            assert "recmember" in json.dumps(members)
        finally:
            await back.close()
            await boss.close()

    run(_t())
    assert _row(db, "recmember")["auth_method"] == "recovery"
    h.stop()


def test_stored_key_scoped_to_its_line(state_root):
    """Pin 8: a stored recovery copy is scoped to the line that
    issued it (the endpoint recorded in the copy). A fresh agent
    on a DIFFERENT line whose workspace happens to hold a copy
    for the same username does NOT present it — it registers
    normally. Presenting a credential to a line that never
    issued it would be wrong on its face, and a stale copy must
    never turn a fresh registration into a refused recovery."""
    tmp = tempfile.mkdtemp(prefix="agentlink-rk-")
    db_a = _db(tmp + "a")
    db_b = _db(tmp + "b")
    ha = RelayHandle(db_a, "rk-line-a")
    hb = RelayHandle(db_b, "rk-line-b")
    url_a = ha.start()
    url_b = hb.start()
    ws_dir = state_root / "ws-scoped"

    async def _t():
        a = Agent("recline", endpoint=url_a,
                  state_dir=str(state_root / "recline-a"),
                  workspace=str(ws_dir))
        await a.start()
        await a.close()
        assert (ws_dir / "agentlink-recovery-recline.txt").exists()
        # Same username, same workspace — DIFFERENT line (fresh
        # relay, fresh DB, different port): the copy's recorded
        # endpoint is line A's, so nothing is presented and the
        # registration claims cleanly.
        b = Agent("recline", endpoint=url_b,
                  state_dir=str(state_root / "recline-b"),
                  workspace=str(ws_dir))
        await b.start()
        try:
            assert b.username == "recline"
        finally:
            await b.close()
        assert _row(db_b, "recline")["auth_method"] == "bootstrap"

    run(_t())
    ha.stop()
    hb.stop()


def test_manual_recovery_key_path(state_root):
    """Pin 7: Agent(recovery_key=...) reclaims explicitly even
    with no stored copies anywhere — and the used key burns."""
    tmp = tempfile.mkdtemp(prefix="agentlink-rk-")
    db = _db(tmp)
    h = RelayHandle(db, "rk-manual")
    url = h.start()
    ws1 = state_root / "ws-manual-1"
    ws2 = state_root / "ws-manual-2"
    holder = {}

    async def _t():
        a = Agent("recmanual", endpoint=url,
                  state_dir=str(state_root / "recmanual"),
                  workspace=str(ws1))
        await a.start()
        holder["key"] = a.recovery_key
        await a.close()
        # A totally fresh machine: new state dir, an EMPTY
        # workspace — only the explicitly presented key.
        b = Agent("recmanual", endpoint=url,
                  state_dir=str(state_root / "recmanual-fresh"),
                  workspace=str(ws2), recovery_key=holder["key"])
        await b.start()
        try:
            assert b.username == "recmanual"
            assert b.recovery_key and b.recovery_key != holder["key"]
        finally:
            await b.close()
        # The presented key is burned now.
        c = Agent("recmanual", endpoint=url,
                  state_dir=str(state_root / "recmanual-third"),
                  workspace=str(state_root / "ws-manual-3"),
                  recovery_key=holder["key"])
        with pytest.raises(RegistrationFailed) as ei:
            await c.start()
        assert "recovery_failed" in str(ei.value)
        await c.close()

    run(_t())
    h.stop()


def test_suite_workspace_isolated_from_real_workspace():
    """Suite hygiene (2026-11-05): a client built WITHOUT an
    explicit workspace= must land in the suite's scratch
    workspace (conftest points AGENTLINK_WORKSPACE at a temp
    dir), never the developer's real ~/workspace — otherwise
    every gate run scatters agentlink-recovery-<user>.txt files
    for scratch identities across the real workspace."""
    import os
    env_ws = os.environ.get("AGENTLINK_WORKSPACE")
    assert env_ws, "conftest must set AGENTLINK_WORKSPACE"
    assert Path(env_ws) != Path("~/workspace").expanduser()
    probe = Agent("wsisolationprobe", state_dir=tempfile.mkdtemp())
    assert probe.workspace == Path(env_ws)
