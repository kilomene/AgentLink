"""Feature-wave tests (owner picks, points 21-28, 35, 36, 38, 40c).

Real relay, real clients, no mocks — same fixture style as the other
suites. Every test names the owner point it proves.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

import pytest

import agentlink.client as client_module
from agentlink.client import Agent, RequestFailed, unpack_folder
from agentlink.deadlines import pacific_display, parse_deadline
from agentlink.protocol import file_bytes
from agentlink.relay import Relay


@pytest.fixture(autouse=True)
def dead_convention(monkeypatch):
    """Hermetic convention (v1.8.1 arbitration): see
    tests/test_decision_link.py — this VM hosts a REAL decision
    endpoint on the convention port (deploy-probe's, production)
    which an unwired test agent would otherwise adopt; its
    reference decisions (e.g. a mid-work progress report) then
    leak into assertions about the test's OWN agents. Point the
    convention at a dead address."""
    monkeypatch.setattr(client_module, "DECISION_CONVENTION_URL",
                        "http://127.0.0.1:1/decide")

HOST = "127.0.0.1"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-f2-")
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
           "db": db, "dash_port": relay.dashboard_port, "relay": relay}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-f2-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


async def make(relay_env, state_root, username, **kw):
    a = Agent(username, endpoint=relay_env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=8.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


def dash_data(relay_env):
    base = f"http://{HOST}:{relay_env['dash_port']}"
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor())
    req = urllib.request.Request(
        base + "/login", data=b"password=test-dash-pass",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        opener.open(req, timeout=5)
    except urllib.error.HTTPError:
        pass
    return json.loads(opener.open(base + "/api/status", timeout=5).read())


# -- point 21: live progress -------------------------------------------------

def test_progress_events_in_order_and_dashboard(relay_env, state_root):
    """Point 21: progress arrives in order, first progress moves work
    to in_progress, dashboard shows the percent, bad percent rejected
    on both client and relay paths."""
    async def _t():
        boss = await make(relay_env, state_root, "boss21")
        worker = await make(relay_env, state_root, "worker21")
        work = (await boss.assign_work(["worker21"], "Progress job"))[0]
        wid = work["id"]
        with pytest.raises(RequestFailed):
            await worker.report_progress(wid, 101)
        with pytest.raises(RequestFailed):
            await worker.report_progress(wid, -5)
        await worker.report_progress(wid, 25, note="quarter done")
        await worker.report_progress(wid, 60)
        await worker.report_progress(wid, 100)
        assert await wait_for(lambda: len(
            [e for e in boss.work_progress_events
             if (e.get("work") or {}).get("id") == wid]) >= 3)
        percents = [e["percent"] for e in boss.work_progress_events
                    if (e.get("work") or {}).get("id") == wid]
        assert percents == [25, 60, 100]
        notes = [e.get("note") for e in boss.work_progress_events
                 if (e.get("work") or {}).get("id") == wid]
        assert notes[0] == "quarter done"  # note decrypted E2E
        inbox = await worker.work_inbox()
        mine = next(w for w in inbox if w["id"] == wid)
        assert mine["status"] == "in_progress"
        assert mine["progress_percent"] == 100
        data = dash_data(relay_env)
        row = next(w for w in data["work"] if w["id"] == wid)
        assert row["progress_percent"] == 100
        assert row["status"] == "in_progress"
        await boss.close(); await worker.close()
    run(_t())


# -- point 22: assign by role --------------------------------------------------

def test_assign_by_role_single_multi_empty_and_mention(relay_env,
                                                        state_root):
    """Point 22: role assignment resolves holders server-side; one
    delivery covers the batch; empty role rejected; a @RoleName
    mention fires mention events for all holders only."""
    async def _t():
        boss = await make(relay_env, state_root, "boss22")
        r1 = await make(relay_env, state_root, "res-one")
        r2 = await make(relay_env, state_root, "res-two")
        other = await make(relay_env, state_root, "plain22")
        g = await boss.group_create(
            "Roles", ["res-one", "res-two", "plain22"])
        gid = g["group_id"]
        await boss.group_set_custom_role(gid, "res-one", "Researcher")
        await boss.group_set_custom_role(gid, "res-two", "Researcher")

        with pytest.raises(RequestFailed) as ei:
            await boss.assign_work_role(gid, "Wizard", "Nope")
        assert ei.value.reason == "empty_role"

        await boss.assign_work_role(gid, "Researcher", "Dig")
        inbox1 = await r1.work_inbox()
        inbox2 = await r2.work_inbox()
        assert len(inbox1) == 1 and len(inbox2) == 1
        assert inbox1[0]["id"] != inbox2[0]["id"]  # copy per holder
        await r1.deliver_work(inbox1[0]["id"], body="findings")
        assert await wait_for(lambda: any(
            u.get("status") == "covered" for u in r2.work_updates))
        inbox2_after = await r2.work_inbox()
        assert inbox2_after[0]["status"] == "covered"

        mentions = {"res-one": [], "res-two": [], "plain22": []}
        r1.on_mention(lambda m: mentions["res-one"].append(m))
        r2.on_mention(lambda m: mentions["res-two"].append(m))
        other.on_mention(lambda m: mentions["plain22"].append(m))
        await boss.group_send(gid, "@Researcher please look")
        assert await wait_for(lambda: mentions["res-one"]
                              and mentions["res-two"])
        await asyncio.sleep(0.3)
        assert mentions["plain22"] == []
        for a in (boss, r1, r2, other):
            await a.close()
    run(_t())


# -- point 23 + 32a: signed delivery proof --------------------------------------

def test_signed_delivery_proof(relay_env, state_root):
    """Point 23: a valid proof verifies against the registered key;
    a tampered hash fails; a forged delivery (signed by a stranger's
    key) is rejected by the relay and the status does not move."""
    async def _t():
        boss = await make(relay_env, state_root, "boss23")
        worker = await make(relay_env, state_root, "worker23")
        work = (await boss.assign_work(["worker23"], "Proof job"))[0]
        wid = work["id"]
        await worker.deliver_work(wid, body="the result")
        raw = await boss._request({"type": "work_inbox", "status": None,
                                   "group_id": None})
        raw_work = next(w for w in raw["work"] if w["id"] == wid)
        assert raw_work["proof_verified"] in (1, True)
        assert await boss.verify_delivery_proof(raw_work) is True
        bad = dict(raw_work); bad["proof_hash"] = "0" * 64
        assert await boss.verify_delivery_proof(bad) is False

        from agentlink.crypto import Identity
        stranger = Identity.ephemeral()
        work2 = (await boss.assign_work(["worker23"], "Forge target"))[0]
        obj = {"body": "forged", "files": []}
        proof = worker.delivery_proof(work2["id"], obj)
        payload = "{}|{}|{}|{}".format(
            work2["id"], proof["hash"], proof["ts"], "worker23").encode()
        proof["sig"] = stranger.sign(payload)  # not worker23's key
        with pytest.raises(RequestFailed) as ei:
            await worker._request({
                "type": "deliver_work", "work_id": work2["id"],
                "attempt": 1, "proof": proof,
                "content_enc": worker._encrypt_obj(
                    await worker.pubkey_of("boss23"), obj),
                "content_self": worker._encrypt_obj(
                    worker.identity.public_key_b64, obj)})
        assert ei.value.reason == "bad_proof"
        inbox = await worker.work_inbox()
        assert next(w for w in inbox
                    if w["id"] == work2["id"])["status"] == "assigned"
        await boss.close(); await worker.close()
    run(_t())


# -- point 24: resumable chunked transfer + dedup ---------------------------------

def test_chunked_resume_and_dedup(relay_env, state_root):
    """Point 24: an interrupted upload resumes sending ONLY the
    missing chunks; a corrupt chunk is rejected by hash; an identical
    re-upload dedups to the same blob with no new session."""
    async def _t():
        a = await make(relay_env, state_root, "up24")
        b = await make(relay_env, state_root, "down24")
        data = os.urandom(2_600_000)  # 3 chunks at 1 MiB
        session_id, chunk_size = await a.start_upload_session(
            data, for_user="down24")
        assert isinstance(session_id, str) \
            and not session_id.startswith("dedup:")
        # First chunk lands, then the connection "drops".
        chunk0 = data[:chunk_size]
        await a._request({
            "type": "blob_chunk", "session_id": session_id, "index": 0,
            "chunk_sha": hashlib.sha256(chunk0).hexdigest(),
            "data_b64": base64.b64encode(chunk0).decode()})
        status = await a._request({"type": "blob_session_status",
                                   "session_id": session_id})
        assert status["missing"] == [1, 2], status
        # Corrupt chunk (bytes do not match the declared chunk hash).
        chunk = data[1048576:2097152]
        bad = bytearray(chunk); bad[0] ^= 0xFF
        with pytest.raises(RequestFailed):
            await a._request({
                "type": "blob_chunk", "session_id": session_id,
                "index": 1, "chunk_sha": hashlib.sha256(chunk).hexdigest(),
                "data_b64": base64.b64encode(bytes(bad)).decode()})
        blob_id = await a.upload_blob(data, for_user="down24",
                                      session_id=session_id)
        got = await b._request({"type": "blob_get", "blob_id": blob_id})
        assert base64.b64decode(got["data_b64"]) == data
        blob_id2 = await a.upload_blob(data, for_user="down24")
        assert blob_id2 == blob_id  # dedup hit: same blob, no re-upload
        await a.close(); await b.close()
    run(_t())


# -- point 25: priority + urgent -----------------------------------------------------

def test_urgent_jumps_offline_queue_and_fires_on_urgent(relay_env,
                                                        state_root):
    """Point 25: urgent drains before normal regardless of send
    order; on_urgent fires only for the urgent item; the dashboard
    feed marks the urgent priority."""
    async def _t():
        a = await make(relay_env, state_root, "sender25")
        b = await make(relay_env, state_root, "recv25")
        await b.close()
        await asyncio.sleep(0.2)
        await a.send_message("recv25", "normal one")
        await a.send_message("recv25", "URGENT one", priority="urgent")
        await a.send_message("recv25", "normal two")
        b2 = Agent("recv25", endpoint=relay_env["url"],
                   state_dir=str(state_root / "recv25"))
        urgent_hits = []
        b2.on_urgent(lambda m: urgent_hits.append(m))
        await b2.start()
        assert await wait_for(lambda: len(b2.messages) >= 3)
        bodies = [m["body"] for m in b2.messages]
        assert bodies[0] == "URGENT one", bodies
        assert await wait_for(lambda: len(urgent_hits) == 1)
        assert urgent_hits[0]["body"] == "URGENT one"
        data = dash_data(relay_env)
        urg = [e for e in data["activity"]
               if e.get("priority") == "urgent"]
        assert urg, "dashboard activity must mark urgent priority"
        await a.close(); await b2.close()
    run(_t())


# -- point 26: broadcast channels ------------------------------------------------------

def test_channels_admin_post_only(relay_env, state_root):
    """Point 26: creator posts, subscribers receive having never
    accepted anything; a subscriber post is rejected server-side;
    invite-link join works."""
    async def _t():
        owner = await make(relay_env, state_root, "chan-owner")
        sub = await make(relay_env, state_root, "chan-sub")
        third = await make(relay_env, state_root, "chan-third")
        ch = await owner.channel_create("Announcements", ["chan-sub"])
        cid = ch["channel_id"]
        await owner.channel_send(cid, "first broadcast")
        assert await wait_for(lambda: any(
            m["body"] == "first broadcast" for m in sub.messages))
        with pytest.raises(RequestFailed) as ei:
            await sub.channel_send(cid, "subscriber trying to post")
        assert ei.value.reason == "permission_denied"
        link = await owner.channel_join_link(cid)
        await third.channel_join(link["link"])
        await owner.channel_send(cid, "second broadcast")
        assert await wait_for(lambda: any(
            m["body"] == "second broadcast" for m in third.messages))
        assert await wait_for(lambda: any(
            m["body"] == "second broadcast" for m in sub.messages))
        for a in (owner, sub, third):
            await a.close()
    run(_t())


# -- point 27: trust score -----------------------------------------------------------------

def test_trust_score_from_history_only(relay_env, state_root):
    """Point 27: score = documented formula over work history only:
    0 start (owner's ruling 2026-11-06 — trust is earned, never
    granted), +4 per completion (work done AND reviewed
    successfully), -6 changes-requested, -6 overdue; delivery
    alone earns nothing; plain messages never move it."""
    async def _t():
        boss = await make(relay_env, state_root, "boss27")
        w = await make(relay_env, state_root, "worker27")

        async def score():
            rows = await boss.directory(query="worker27")
            return next(r["trust_score"] for r in rows
                        if r["username"] == "worker27")

        assert await score() == 0
        await boss.send_message("worker27", "just chatting")
        await boss.send_message("worker27", "more chat")
        assert await score() == 0
        for i in range(3):
            job = (await boss.assign_work(["worker27"], f"job {i}"))[0]
            await w.deliver_work(job["id"], body="done")
            await boss.complete_work(job["id"])
        assert await score() == 3 * 4
        job = (await boss.assign_work(["worker27"], "needs rework"))[0]
        await w.deliver_work(job["id"], body="v1")
        await boss.request_changes(job["id"], note="redo")
        assert await score() == 12 - 6
        await boss.assign_work(["worker27"], "late job",
                               deadline=int(time.time()) - 60)
        assert await score() == 12 - 6 - 6
        await boss.close(); await w.close()
    run(_t())


# -- point 35: any file of any kind ----------------------------------------------------------

def test_any_file_kind_roundtrips(relay_env, state_root, tmp_path):
    """Point 35: format-blind transport — .pdf, .zip, .docx-style
    binary, extensionless random binary, PNG bytes named .txt, and
    .tar.gz all round-trip byte-identical with matching SHA256."""
    async def _t():
        a = await make(relay_env, state_root, "files35a")
        b = await make(relay_env, state_root, "files35b")
        src = tmp_path / "src"; src.mkdir()
        zp = src / "bundle.zip"
        with zipfile.ZipFile(zp, "w") as z:
            z.writestr("inner/a.txt", "hello")
        inner = src / "member.txt"; inner.write_text("tar member")
        tp = src / "archive.tar.gz"
        with tarfile.open(tp, "w:gz") as t:
            t.add(inner, arcname="member.txt")
        cases = {
            "report.pdf": b"%PDF-1.7\n" + os.urandom(4096),
            "bundle.zip": zp.read_bytes(),
            "notes.docx": b"PK\x03\x04" + os.urandom(2048),
            "noextension": os.urandom(3000),
            "lying.txt": b"\x89PNG\r\n\x1a\n" + os.urandom(1024),
            "archive.tar.gz": tp.read_bytes(),
        }
        for name, data in cases.items():
            p = src / name
            if not p.exists():
                p.write_bytes(data)
            await a.send_file("files35b", str(p))
        assert await wait_for(lambda: len(
            [m for m in b.messages if m.get("file")]) == len(cases), 15)
        received = {m["file"]["name"]: m["file"]
                    for m in b.messages if m.get("file")}
        for name, data in cases.items():
            assert file_bytes(received[name]) == data, name
            assert received[name]["sha256"] == \
                hashlib.sha256(data).hexdigest()
        await a.close(); await b.close()
    run(_t())


def test_folder_send_unpacks_identical_tree(relay_env, state_root,
                                            tmp_path):
    """Point 35c: folder-send packs a directory; the receiver unpacks
    the identical tree."""
    async def _t():
        a = await make(relay_env, state_root, "folder35a")
        b = await make(relay_env, state_root, "folder35b")
        src = tmp_path / "tree"
        (src / "sub" / "deep").mkdir(parents=True)
        (src / "a.txt").write_text("alpha")
        (src / "sub" / "b.bin").write_bytes(os.urandom(777))
        (src / "sub" / "deep" / "c").write_bytes(b"extensionless")
        await a.send_folder("folder35b", str(src))
        assert await wait_for(lambda: any(m.get("file")
                                          for m in b.messages))
        msg = next(m for m in b.messages if m.get("file"))
        out = tmp_path / "unpacked"
        unpack_folder(file_bytes(msg["file"]), str(out))
        for rel in ("a.txt", "sub/b.bin", "sub/deep/c"):
            assert (out / rel).read_bytes() == (src / rel).read_bytes()
        await a.close(); await b.close()
    run(_t())


# -- point 36: Pacific deadlines --------------------------------------------------------------

def test_pacific_deadline_same_epoch_any_host_tz():
    """Point 36: the same Pacific deadline string produces the same
    epoch under TZ=UTC, Asia/Tokyo, America/New_York and
    America/Los_Angeles; naive input is Pacific by definition; the
    display string carries its UTC offset."""
    import subprocess
    import sys
    code = ("from agentlink.deadlines import parse_deadline;"
            "print(parse_deadline('2026-11-05 17:00'))")
    epochs = set()
    root = str(Path(__file__).resolve().parent.parent)
    for tz in ("UTC", "Asia/Tokyo", "America/New_York",
               "America/Los_Angeles"):
        env = dict(os.environ, TZ=tz, PYTHONPATH=root)
        out = subprocess.run([sys.executable, "-c", code], env=env,
                             capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        epochs.add(out.stdout.strip())
    assert len(epochs) == 1, epochs
    disp = pacific_display(parse_deadline("2026-11-05 17:00"))
    assert disp.startswith("2026-11-05 17:00 PT (UTC")
    assert parse_deadline("2026-11-05T17:00:00") == \
        parse_deadline("2026-11-05 17:00")


def test_deadline_pressure_warnings_and_overdue(relay_env, state_root):
    """Point 36: threshold warnings reach the assignee; once overdue
    the priority auto-escalates to urgent and the assigner is
    notified; the work view carries epoch + Pacific string."""
    async def _t():
        boss = await make(relay_env, state_root, "boss36")
        w = await make(relay_env, state_root, "worker36")
        now = int(time.time())
        job = (await boss.assign_work(
            ["worker36"], "tight window", deadline=now + 4))[0]
        assert job["deadline"] == now + 4
        assert "PT (UTC" in job["deadline_pt"]
        assert await wait_for(
            lambda: len(w.deadline_warnings) >= 1, 10)
        assert await wait_for(
            lambda: any((e.get("work") or {}).get("id") == job["id"]
                        or e.get("work_id") == job["id"]
                        for e in boss.overdue_events), 12)
        inbox = await w.work_inbox()
        mine = next(x for x in inbox if x["id"] == job["id"])
        assert mine["priority"] == "urgent"
        await boss.close(); await w.close()
    run(_t())


# -- point 38: delivery library + group vault ----------------------------------------------------

def test_library_and_vault(relay_env, state_root, tmp_path):
    """Point 38: a completed delivery is indexed and findable by name
    and hash prefix by entitled agents only (an unrelated agent sees
    nothing and its fetch is refused); the group vault honours
    membership, pin-first ordering, admins-only put, and removal."""
    async def _t():
        boss = await make(relay_env, state_root, "boss38")
        w = await make(relay_env, state_root, "worker38")
        outsider = await make(relay_env, state_root, "outsider38")
        deliverable = tmp_path / "result.bin"
        deliverable.write_bytes(b"library-me-" + os.urandom(64))
        sha = hashlib.sha256(deliverable.read_bytes()).hexdigest()
        job = (await boss.assign_work(["worker38"], "lib job"))[0]
        await w.deliver_work(job["id"], body="done",
                             files=[str(deliverable)])
        await boss.complete_work(job["id"])
        hits = await boss.library_search(q="result")
        assert any(h["sha256"] == sha for h in hits)
        hits2 = await w.library_search(hash_prefix=sha[:10])
        assert any(h["sha256"] == sha for h in hits2)
        lib_id = next(h["id"] for h in hits if h["sha256"] == sha)
        fetched = await boss.library_fetch(lib_id)
        assert file_bytes(fetched["files"][0]) == \
            deliverable.read_bytes()
        assert await outsider.library_search(q="result") == []
        with pytest.raises(RequestFailed):
            await outsider.library_fetch(lib_id)

        g = await boss.group_create("VaultG", ["worker38"])
        gid = g["group_id"]
        vf = tmp_path / "vault.txt"; vf.write_text("vault contents")
        entry = await boss.vault_put(gid, str(vf))
        lst = await w.vault_list(gid)
        assert any(e["id"] == entry["id"] for e in lst)
        got = await w.vault_get(entry)
        assert file_bytes(got) == b"vault contents"
        with pytest.raises(RequestFailed):
            await outsider.vault_get(entry)
        vf2 = tmp_path / "vault2.txt"; vf2.write_text("second")
        e2 = await boss.vault_put(gid, str(vf2))
        await boss.vault_pin(e2["id"], True)
        lst = await boss.vault_list(gid)
        assert lst[0]["id"] == e2["id"]  # pinned first
        await boss.group_settings(gid, {"vault_add": "admins_only"})
        await asyncio.sleep(0.3)
        with pytest.raises(RequestFailed):
            await w.vault_put(gid, str(vf))
        await boss.group_remove(gid, "worker38")
        with pytest.raises(RequestFailed):
            await w.vault_get(entry)
        for a in (boss, w, outsider):
            await a.close()
    run(_t())


# -- point 40c: any agent creates groups ------------------------------------------------------------

def test_third_agent_creates_own_group_and_work_flows(relay_env,
                                                      state_root):
    """Point 40c: group creation is a general ability — an unrelated
    third agent creates its own group, adds two others with no
    acceptance step, and work flows to completion inside it."""
    async def _t():
        third = await make(relay_env, state_root, "third40")
        x = await make(relay_env, state_root, "x40")
        y = await make(relay_env, state_root, "y40")
        g = await third.group_create("Third's crew", ["x40", "y40"])
        gid = g["group_id"]
        job = (await third.assign_work(
            ["x40"], "crew task", group_id=gid))[0]
        await x.deliver_work(job["id"], body="crew result")
        await third.complete_work(job["id"])
        inbox = await third.work_inbox(group_id=gid)
        assert inbox[0]["status"] == "completed"
        await third.close(); await x.close(); await y.close()
    run(_t())
