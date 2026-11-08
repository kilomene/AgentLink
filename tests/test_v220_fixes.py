"""2.2.0 — the consolidated fleet fix release.

One test class per owner-ordered item:

1. The 29 empty-body family items: payload text lives under the
   canonical "body" OR the legacy "text" key — both open paths
   read it through one helper — and a journal entry that opened
   empty heals when the server copy opens with text.
2. Support proof media: video types accepted at the Edge and in
   the client mirror set; the dashboard ticket renders images
   inline and video in a player.
3. Directory capabilities: the declaration a session publishes
   is durable local state — a later session's boot declare
   re-presents it instead of unpublishing it (the live-proven
   wipe) — and the account Edge stores the jsonb array itself.
4. Supervision: the systemd unit carries WatchdogSec and the
   daemon pats it from its stamp loop; the watchdog script is
   stamped per agent/state-dir, kills a frozen lock holder in
   every mode, and leaves a fresh or absent daemon alone; the
   fallback supervisor ticks the watchdog itself (no cron).
5. README brain doctrine: the section exists in the body and
   says the quiet part — no reflexive acknowledgments.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENT = (ROOT / "agentlink/client.py").read_text()
CLI = (ROOT / "agentlink/cli.py").read_text()
SUPPORT_TS = (ROOT / "supabase/functions/agentlink-support/index.ts").read_text()
SUPPORT_PY = (ROOT / "agentlink/support.py").read_text()
ACCOUNT_TS = (ROOT / "supabase/functions/agentlink-account/index.ts").read_text()
API_TS = (ROOT / "supabase/functions/agentlink-api/index.ts").read_text()
SUPPORT_JS = (ROOT / "dashboard-v2/js/views/support.js").read_text()
SUPPORT_HTML = (ROOT / "dashboard-v2/support.html").read_text()
README = (ROOT / "README.md").read_text()
README_BODY = README.partition(
    "## Retired appendix — the v1 relay line (historical record)")[0]


def _agent(tmp_path, username="alice", **kw):
    from agentlink.client import Agent
    return Agent(username=username,
                 state_dir=str(tmp_path / "state"),
                 workspace=str(tmp_path / "ws"),
                 transport="serverless", mode="manual", **kw)


# ====================== 1. the legacy text key ===================

def test_1_payload_body_canonical_wins():
    from agentlink.client import _payload_body
    assert _payload_body({"body": "real", "text": "other"}) == "real"
    # An intentionally empty canonical body stays empty — the
    # alias must not resurrect a "text" the sender superseded.
    assert _payload_body({"body": "", "text": "other"}) == ""


def test_1_payload_body_legacy_text_fallback():
    from agentlink.client import _payload_body
    assert _payload_body({"text": "[soak] cycle 1 group post"}) \
        == "[soak] cycle 1 group post"
    assert _payload_body({}) == ""
    assert _payload_body({"body": None, "text": None}) == ""
    assert _payload_body("not a dict") == ""


def test_1_open_paths_use_the_one_helper():
    # Both readers (history + live) take the body through the
    # helper — the alias can never drift between them again.
    assert CLIENT.count("_payload_body(payload)") >= 2
    assert 'payload.get("body", "")' not in CLIENT


def test_1_history_row_with_legacy_text_renders(tmp_path):
    from agentlink.crypto import encrypt_to_pubkey
    agent = _agent(tmp_path)
    payload = {"text": "the retired injector's words"}
    envelope = encrypt_to_pubkey(
        agent.identity.public_key_b64,
        json.dumps(payload).encode())
    row = {"seq": 3, "ts": int(time.time()), "kind": "message",
           "actor": "bob", "target": "alice", "group_id": "",
           "ref_id": "legacy1", "status": "sent",
           "content_envelope": envelope, "oversight": None}
    msg = agent._history_row_to_msg(row)
    assert msg is not None
    assert msg["body"] == "the retired injector's words"
    assert not msg.get("sealed")


def test_1_sync_heals_an_empty_body_journal_entry(tmp_path):
    from agentlink.crypto import encrypt_to_pubkey
    agent = _agent(tmp_path)
    mid = "emptyheal1"
    # The pre-fix local state: opened, journaled, EMPTY — not
    # sealed, not unreadable (the old heal arms missed exactly
    # this shape).
    agent.mailbox.put_if_absent({
        "id": mid, "from": "bob", "to": "alice", "kind": "text",
        "body": "", "ts": int(time.time())})
    payload = {"body": "now visible", "kind": "text", "file": None}
    envelope = encrypt_to_pubkey(
        agent.identity.public_key_b64,
        json.dumps(payload).encode())
    row = {"seq": 7, "ts": int(time.time()), "kind": "message",
           "actor": "bob", "target": "alice", "group_id": "",
           "ref_id": mid, "status": "sent",
           "content_envelope": envelope, "oversight": None}

    class _V2:
        def fetch_history_page(self, limit=200, before_seq=None):
            return [] if before_seq else [row]

    agent._v2 = _V2()
    out = asyncio.run(agent.sync_history())
    assert out["healed"] == 1
    assert agent.mailbox.get(mid)["body"] == "now visible"


def test_1_sync_never_overwrites_a_body_the_journal_holds(tmp_path):
    from agentlink.crypto import encrypt_to_pubkey
    agent = _agent(tmp_path)
    mid = "keepmine1"
    agent.mailbox.put_if_absent({
        "id": mid, "from": "bob", "to": "alice", "kind": "text",
        "body": "my local copy", "ts": int(time.time())})
    payload = {"body": "the server copy", "kind": "text",
               "file": None}
    envelope = encrypt_to_pubkey(
        agent.identity.public_key_b64,
        json.dumps(payload).encode())
    row = {"seq": 9, "ts": int(time.time()), "kind": "message",
           "actor": "bob", "target": "alice", "group_id": "",
           "ref_id": mid, "status": "sent",
           "content_envelope": envelope, "oversight": None}

    class _V2:
        def fetch_history_page(self, limit=200, before_seq=None):
            return [] if before_seq else [row]

    agent._v2 = _V2()
    out = asyncio.run(agent.sync_history())
    assert out["healed"] == 0
    assert agent.mailbox.get(mid)["body"] == "my local copy"


# ====================== 2. support proof media ===================

def test_2_support_edge_accepts_video():
    for t in ("video/mp4", "video/webm", "video/quicktime"):
        assert f'"{t}"' in SUPPORT_TS


def test_2_support_client_mirrors_video_types():
    for t in ("video/mp4", "video/webm", "video/quicktime"):
        assert f'"{t}"' in SUPPORT_PY
    for ext in ('".mp4"', '".webm"', '".mov"'):
        assert ext in SUPPORT_PY


def test_2_dashboard_renders_proof_media_in_the_ticket():
    assert 'ct.startsWith("image/")' in SUPPORT_JS
    assert "<img" in SUPPORT_JS
    assert 'ct.startsWith("video/")' in SUPPORT_JS
    assert "<video controls" in SUPPORT_JS


def test_2_form_copy_names_video():
    assert "images/video/text/json/zip" in SUPPORT_HTML


# ====================== 3. capabilities truth ===================

def test_3_account_edge_stores_the_array_itself():
    # jsonb column: JSON.stringify stored a string scalar —
    # double-encoded capabilities on every row.
    assert "capabilities: caps," in ACCOUNT_TS
    assert "JSON.stringify(caps)" not in ACCOUNT_TS


def test_3_api_edge_normalizes_caps():
    assert "function capsArray" in API_TS
    assert "capabilities: capsArray(u.capabilities)" in API_TS


def test_3_migration_normalizes_stored_strings():
    sql = (ROOT / "supabase/migration-v210-capabilities-jsonb.sql"
           ).read_text()
    assert "jsonb_typeof(capabilities) = 'string'" in sql


def test_3_declaration_survives_a_fresh_session(tmp_path):
    agent = _agent(tmp_path)

    async def fake_request(frame):
        return {"ok": True}

    agent._request = fake_request
    asyncio.run(agent.update_capabilities(
        ["internet", "files"], "declared in session one"))
    saved = json.loads(
        (Path(agent.state_dir) / "capabilities-alice.json")
        .read_text())
    assert saved["capabilities"] == ["internet", "files"]
    assert saved["description"] == "declared in session one"
    # A fresh session on the same state states nothing in its
    # constructor — the boot declare must re-present the
    # PUBLISHED declaration, not the [] default that used to
    # unpublish it.
    again = _agent(tmp_path)
    assert again.capabilities == ["internet", "files"]
    assert again.cap_description == "declared in session one"


def test_3_constructor_declaration_still_wins(tmp_path):
    agent = _agent(tmp_path)

    async def fake_request(frame):
        return {"ok": True}

    agent._request = fake_request
    asyncio.run(agent.update_capabilities(["internet"], "stored"))
    explicit = _agent(tmp_path, capabilities=["coding"],
                      cap_description="from the host program")
    assert explicit.capabilities == ["coding"]
    assert explicit.cap_description == "from the host program"


def test_3_transport_directory_entry_normalizes(tmp_path):
    src = (ROOT / "agentlink/transport_v2.py").read_text()
    assert 'caps = _loads(caps, [])' in src


# ====================== 4. frozen-process supervision ============

def test_4_sd_notify_is_a_noop_without_systemd(monkeypatch):
    from agentlink.client import _sd_notify_watchdog
    monkeypatch.delenv("NOTIFY_SOCKET", raising=False)
    _sd_notify_watchdog()  # must simply do nothing


def test_4_sd_notify_pats_the_watchdog_socket(monkeypatch):
    import socket as _socket
    import tempfile
    from agentlink.client import _sd_notify_watchdog
    # AF_UNIX paths cap at ~108 chars; pytest's tmp_path under
    # the gate TMPDIR is far longer — bind somewhere short.
    short = tempfile.mkdtemp(prefix="n", dir="/tmp")
    addr = os.path.join(short, "s.sock")
    srv = _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM)
    srv.bind(addr)
    srv.settimeout(5)
    monkeypatch.setenv("NOTIFY_SOCKET", addr)
    try:
        _sd_notify_watchdog()
        data, _ = srv.recvfrom(64)
    finally:
        srv.close()
    assert data == b"WATCHDOG=1"


def _install_service(tmp_path, monkeypatch, state_dir):
    from agentlink import cli
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    shim = tmp_path / "shim"
    shim.mkdir(exist_ok=True)
    monkeypatch.setenv("PATH", str(shim))  # no systemctl/crontab
    real_popen = subprocess.Popen
    monkeypatch.setattr(subprocess, "Popen",
                        lambda *a, **k: None)
    rc = cli._service(["install", "--username", "frozenagent",
                       "--user", "--state-dir", str(state_dir)])
    assert rc == 0
    # The Popen stub exists only to keep the install from
    # spawning a real supervisor inside a test — restore the
    # real one so callers can run processes again.
    monkeypatch.setattr(subprocess, "Popen", real_popen)
    return home


def test_4_unit_carries_watchdogsec(tmp_path, monkeypatch):
    home = _install_service(tmp_path, monkeypatch,
                            tmp_path / "sd-frozen")
    unit = (home / ".config" / "systemd" / "user"
            / "agentlink-agent.service").read_text()
    assert "WatchdogSec=30" in unit
    assert "NotifyAccess=main" in unit
    assert "Restart=always" in unit


def test_4_watchdog_script_is_stamped_and_mode_aware(
        tmp_path, monkeypatch):
    sd = tmp_path / "sd-frozen"
    home = _install_service(tmp_path, monkeypatch, sd)
    script = (home / ".agentlink" / "watchdog.sh").read_text()
    assert f'"{sd}/heartbeat-frozenagent.txt"' in script.replace(
        "STAMP=", "STAMP=") or "heartbeat-frozenagent.txt" in script
    assert "instance-frozenagent.lock" in script
    assert "kill -TERM" in script and "kill -KILL" in script
    assert "heartbeat-*" not in script        # no first-glob guess
    sup = (home / ".agentlink" / "supervise-agent.sh").read_text()
    assert "watchdog.sh" in sup and "sleep 30" in sup


def _watchdog_env(tmp_path, monkeypatch, stamp_age, lock_age,
                  with_pid=True, stamp_mtime_age=None):
    """A fake daemon: a live sleeper + its state dir."""
    sd = tmp_path / "sd-frozen"
    sd.mkdir(exist_ok=True)
    proc = subprocess.Popen(["sleep", "120"])
    if with_pid:
        (sd / "instance-frozenagent.lock").write_text(json.dumps(
            {"username": "frozenagent", "pid": proc.pid}))
    stamp = sd / "heartbeat-frozenagent.txt"
    stamp.write_text(str(int(time.time()) - stamp_age))
    if stamp_mtime_age is not None:
        old = time.time() - stamp_mtime_age
        os.utime(stamp, (old, old))
    if lock_age is not None:
        old = time.time() - lock_age
        os.utime(sd / "instance-frozenagent.lock", (old, old))
    home = _install_service(tmp_path, monkeypatch, sd)
    script = str(home / ".agentlink" / "watchdog.sh")
    return proc, script


REAL_ENV = {**os.environ, "PATH": "/usr/bin:/bin"}


def test_4_watchdog_kills_a_frozen_daemon(tmp_path, monkeypatch):
    proc, script = _watchdog_env(tmp_path, monkeypatch,
                                 stamp_age=120, lock_age=120)
    try:
        subprocess.run(["/bin/sh", script], timeout=60,
                       check=False, env=REAL_ENV)
        assert proc.poll() is not None, \
            "the frozen daemon must be killed for its supervisor"
    finally:
        if proc.poll() is None:
            proc.kill()


def test_4_watchdog_leaves_a_fresh_daemon_alone(tmp_path,
                                                monkeypatch):
    proc, script = _watchdog_env(tmp_path, monkeypatch,
                                 stamp_age=0, lock_age=120)
    try:
        subprocess.run(["/bin/sh", script], timeout=60,
                       check=False, env=REAL_ENV)
        assert proc.poll() is None
    finally:
        proc.kill()


def test_4_watchdog_respects_the_startup_grace(tmp_path,
                                               monkeypatch):
    proc, script = _watchdog_env(tmp_path, monkeypatch,
                                 stamp_age=120, lock_age=0)
    try:
        subprocess.run(["/bin/sh", script], timeout=60,
                       check=False, env=REAL_ENV)
        assert proc.poll() is None, \
            "a just-started daemon may not have stamped yet"
    finally:
        proc.kill()


def test_4_watchdog_shelters_a_slow_first_login(tmp_path,
                                                monkeypatch):
    # The stamp file predates this lock entirely (left by an
    # earlier session): this daemon has never stamped and is
    # still inside the 120s startup allowance at 60s old —
    # first login on a slow network measured ~75s in the
    # release drill, and killing it there restarts the login
    # forever.
    proc, script = _watchdog_env(tmp_path, monkeypatch,
                                 stamp_age=3600, lock_age=60,
                                 stamp_mtime_age=3600)
    try:
        subprocess.run(["/bin/sh", script], timeout=60,
                       check=False, env=REAL_ENV)
        assert proc.poll() is None
    finally:
        proc.kill()


def test_4_watchdog_kills_a_daemon_that_stamped_then_froze(
        tmp_path, monkeypatch):
    # Same lock age (60s), but this daemon DID stamp under its
    # lock (stamp mtime younger than the lock's age) and then
    # froze: no startup shelter applies.
    proc, script = _watchdog_env(tmp_path, monkeypatch,
                                 stamp_age=120, lock_age=60,
                                 stamp_mtime_age=30)
    try:
        subprocess.run(["/bin/sh", script], timeout=60,
                       check=False, env=REAL_ENV)
        assert proc.poll() is not None
    finally:
        if proc.poll() is None:
            proc.kill()


# ====================== 5. the brain doctrine ===================

def test_5_readme_carries_the_brain_doctrine():
    assert "## The brain doctrine — you are the intelligence" \
        in README_BODY
    assert "[The brain doctrine — you are the intelligence]" \
        in README_BODY                       # the ToC names it
    section = README_BODY.partition(
        "## The brain doctrine — you are the intelligence")[2]
    section = section.partition("\n## ")[0]
    assert "AgentLink is the line" in section
    assert "Never send reflexive acknowledgments" in section
    assert "spam" in section
    assert "decision link" in section
