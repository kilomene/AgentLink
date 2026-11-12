"""v2.5.0 — LIFE SIGNS + NATURE + MACHINE SPEC + REAL-TIME SYNC
+ HARDENED REPORTING + THE AGENT DOSSIER (owner's commission
2026-11-11 incl. expansions 1-5). Pins:

* canonical signed payloads are byte-exact (receipt tier INSIDE
  the signed bytes; the daemon answer path signs ONLY 'daemon');
* profile validation (closed key set, enum + window bounds,
  ≤280 duty text, machine normalization);
* grade bands per class + undeclared conservatism (never
  persistent windows);
* machine drift materiality + detection gaps (an empty GPU
  list is honest none, never a gap);
* the live node's ONE composition (tiers, unproven default,
  dossier flag default 'missing');
* hardened reporting: setup declares AUTOMATICALLY, there is
  no --no-machine opt-out, ensure_nature_declared's decision
  matrix (declare / current / drift-redeclare preserving
  judgment fields / version-change redeclare / gaps attached);
* the dossier: build completeness, the forbidden-content
  refusal, signature round-trip, chain verification, version
  roll + history, deposit queue drain/park/heal, status flags,
  refresh rules (undeposited != regenerate);
* migration v213 static invariants (anti-gaming judge-by-
  silence-start, parked_reason, compliance 3600s, dossier
  86400s, the apply functions, the cron job);
* Edge + tapper + rules + dashboard source pins (routes,
  evaluate-on-proof, dossier mirrors, lifeSignCell, census);
* Standing Orders 2.5.0 text (nature duty, prove duty,
  real-time grade line, dossier self-check line);
* the manifest carries liveness.py + dossier.py + the orders
  with true hashes at version 2.5.0.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentlink import dossier as dm  # noqa: E402
from agentlink import liveness as lv  # noqa: E402
from agentlink.archive import verify_chain  # noqa: E402
from agentlink.crypto import Identity  # noqa: E402

NOW = 1_800_000_000


def _profile(**over):
    p = {
        "runtime_kind": "session-chat",
        "host_class": "phone",
        "persistence_class": "session",
        "suspect_after_s": 1500,
        "expected_gap_s": 21600,
        "dark_after_s": 259200,
        "supervision": "none",
        "wake_paths": ["inbound-task"],
        "duty_pattern": "wakes for tasks",
        "network_class": "mobile",
        "network_self_managed": True,
        "runtime_proof_capable": True,
        "machine": {
            "hostname": "pixel", "os": "Android", "os_version": "14",
            "kernel": "", "arch": "aarch64", "cpu_model": "Tensor",
            "cores_physical": 4, "cores_logical": 8,
            "ram_mb": 8192, "gpus": [],
            "storage_total_mb": 128000, "storage_free_mb": 40000,
            "client_runtime": "python 3.12 / agentlink 2.5.0",
            "detected_at": NOW,
        },
    }
    p.update(over)
    return p


# ------------------------------------------------------- payloads

def test_payload_bytes_are_exact():
    assert lv.receipt_payload("folk", "lc-1", "ab" * 32, "daemon",
                              42) == (
        "agentlink-liveness-receipt-v1|folk|lc-1|" + "ab" * 32
        + "|daemon|42")
    # the tier claim lives INSIDE the signed bytes
    assert "|runtime|" in lv.receipt_payload(
        "folk", "lc-1", "ab" * 32, "runtime", 42)
    assert lv.prove_payload("folk", 42) == \
        "agentlink-liveness-prove-v1|folk|42"
    assert lv.drift_payload("folk", ["ram_mb", "gpus"], 42) == \
        "agentlink-liveness-drift-v1|folk|gpus,ram_mb|42"
    assert lv.dossier_status_payload(
        "folk", "deposit-parked", 7, 3, 42) == (
        "agentlink-dossier-status-v1|folk|deposit-parked|7|3|42")
    with pytest.raises(ValueError):
        lv.dossier_status_payload("folk", "bogus", 0, 0, 42)


def test_canonical_json_parity_cases():
    assert lv.canonical_json({"b": 1, "a": [True, None]}) == \
        '{"a":[true,null],"b":1}'
    assert lv.canonical_json({"x": "生き甲斐"}) == '{"x":"生き甲斐"}'
    assert lv.declare_payload("folk", {"b": 1, "a": 2}, 9) == \
        'agentlink-nature-declare-v1|folk|{"a":2,"b":1}|9'


# ------------------------------------------------------- profiles

def test_validate_profile_bounds_and_enums():
    ok = lv.validate_profile(_profile())
    assert ok["persistence_class"] == "session"
    with pytest.raises(ValueError):
        lv.validate_profile(_profile(persistence_class="eternal"))
    with pytest.raises(ValueError):
        lv.validate_profile(_profile(suspect_after_s=60))
    # duty text is capped at the brief's 280 chars (truncated
    # by the validator, never silently longer on the record)
    assert len(lv.validate_profile(
        _profile(duty_pattern="x" * 400))["duty_pattern"]) == 280
    with pytest.raises(ValueError):
        lv.validate_profile(_profile(bogus_key=1))
    with pytest.raises(ValueError):
        lv.validate_profile(_profile(wake_paths=["telepathy"]))


def test_grade_bands_per_class():
    pers = _profile(persistence_class="persistent",
                    dark_after_s=5400,
                    runtime_kind="persistent-daemon")
    assert lv.grade_for(pers, 100) == "BEATING"
    assert lv.grade_for(pers, 2000) == "SUSPECT"
    assert lv.grade_for(pers, 6000) == "DARK"
    sess = _profile()
    assert lv.grade_for(sess, 100) == "BEATING"
    assert lv.grade_for(sess, 10000) == "RESTING"
    assert lv.grade_for(sess, 100000) == "SUSPECT"
    assert lv.grade_for(sess, 300000) == "DARK"
    # undeclared: session shape, conservative windows — never
    # persistent judging
    w = lv.effective_windows(None)
    assert w["expected_gap_s"] == 86400
    assert w["dark_after_s"] == 604800
    assert lv.grade_for(None, 1000) == "BEATING"
    assert lv.grade_for(None, 2000) == "RESTING"
    assert lv.grade_for(None, 50000) == "RESTING"
    assert lv.grade_for(None, 100000) == "SUSPECT"
    assert lv.grade_for(None, 700000) == "DARK"


def test_machine_drift_materiality():
    m = _profile()["machine"]
    assert lv.machine_drift(m, dict(m)) == []
    assert lv.machine_drift(m, dict(m, hostname="other")) == \
        ["hostname"]
    assert lv.machine_drift(m, dict(m, ram_mb=8100)) == []
    assert lv.machine_drift(m, dict(m, ram_mb=4000)) == ["ram_mb"]
    gpu = dict(m, gpus=[{"vendor": "NVIDIA", "model": "H100",
                         "vram_mb": 80000}])
    assert lv.machine_drift(gpu, m) == ["gpus"]
    assert lv.machine_drift(None, m) == []
    assert lv.machine_drift(m, None) == []


def test_detection_gaps_gpu_none_is_honest():
    assert lv.detection_gaps(_profile()["machine"]) == []
    gaps = lv.detection_gaps({"hostname": "unknown", "os": "x",
                              "cpu_model": "unknown",
                              "ram_mb": None, "gpus": [],
                              "storage_total_mb": None})
    assert "hostname" in gaps and "ram_mb" in gaps
    assert "gpus" not in gaps


def test_detect_machine_this_vm():
    spec = lv.detect_machine()
    import socket
    assert spec["hostname"] == socket.gethostname()
    assert spec["ram_mb"] and spec["ram_mb"] > 0
    assert spec["cpu_model"] != "unknown"
    assert isinstance(spec["gpus"], list)
    assert spec["storage_total_mb"] > 0
    assert "agentlink" in spec["client_runtime"]


def test_compose_node_one_truth():
    node = lv.compose_liveness_node(
        {"grade": "BEATING", "judged_nature_version": 3,
         "judged_class": "session", "last_daemon_receipt_at": 50,
         "last_runtime_proof_at": 90, "daemon_only": False,
         "spec_drift": "", "nature_compliant": True,
         "dossier_status": "current"},
        {"last_seen": 10})
    assert node["last_proof_tier"] == "runtime"
    assert node["last_proof_at"] == 90
    assert node["dossier_status"] == "current"
    empty = lv.compose_liveness_node(None, None)
    assert empty["grade"] == "unproven"
    assert empty["dossier_status"] == "missing"


# ------------------------------------------------------- transport

def test_daemon_answer_signs_daemon_tier_only(tmp_path):
    from agentlink.transport_v2 import ServerlessTransport as TransportV2
    t = TransportV2.__new__(TransportV2)
    t.username = "folk"
    t.last_liveness_attempt_at = 0.0
    t.last_liveness_error = ""
    signed = []

    def signer(data: bytes) -> str:
        signed.append(data.decode())
        return "c2ln"

    t._signer = signer
    calls = []

    def fn_post(fn, route, payload):
        calls.append(route)
        if route == "challenge":
            return {"challenge": {"id": "lc-9", "nonce": "n" * 64}}
        return {"ok": True}

    t._fn_post = fn_post
    out = t.answer_liveness_challenges()
    assert out["answered"] is True and out["tier"] == "daemon"
    assert signed and "|daemon|" in signed[0]
    assert "runtime" not in signed[0].split("|")[-2]


def _ensure_harness(current_nature, declared_capture):
    from agentlink.transport_v2 import ServerlessTransport as TransportV2
    t = TransportV2.__new__(TransportV2)
    t.username = "folk"
    t.last_liveness_attempt_at = 0.0
    t.last_liveness_error = ""
    t._signer = lambda b: "c2ln"
    t.liveness_status = lambda: {"nature": current_nature}
    t.liveness_declare = lambda profile: (
        declared_capture.append(profile),
        {"result": {"nature_version": 7}})[1]
    return t


def test_ensure_declares_when_no_declaration(tmp_path):
    cap = []
    t = _ensure_harness(None, cap)
    out = t.ensure_nature_declared(tmp_path)
    assert out["declared"] is True and cap
    # the baseline is the per-runtime PROPOSAL, machine attached
    assert cap[0]["machine"]["hostname"]
    assert "persistence_class" in cap[0]


def test_ensure_noop_when_current(tmp_path):
    cap = []
    cur = _profile()
    cur["machine"] = lv.detect_machine(tmp_path)
    t = _ensure_harness(cur, cap)
    out = t.ensure_nature_declared(tmp_path)
    assert out["current"] is True and not cap


def test_ensure_redeclares_on_drift_preserving_judgment(tmp_path):
    cap = []
    cur = _profile(duty_pattern="my own words")
    cur["machine"] = dict(lv.detect_machine(tmp_path),
                          hostname="some-other-host")
    t = _ensure_harness(cur, cap)
    out = t.ensure_nature_declared(tmp_path)
    assert out["declared"] is True
    assert "spec drift: hostname" in "; ".join(out["reasons"])
    assert cap[0]["duty_pattern"] == "my own words"
    import socket
    assert cap[0]["machine"]["hostname"] == socket.gethostname()


def test_ensure_redeclares_on_client_version_change(tmp_path):
    cap = []
    cur = _profile()
    m = lv.detect_machine(tmp_path)
    m["client_runtime"] = "python 3.12 / agentlink 0.0.1"
    cur["machine"] = m
    t = _ensure_harness(cur, cap)
    out = t.ensure_nature_declared(tmp_path)
    assert out["declared"] is True
    assert "client version changed" in out["reasons"]


def test_hardened_reporting_no_opt_outs():
    cli_src = (ROOT / "agentlink" / "cli.py").read_text()
    setup_src = (ROOT / "agentlink" / "setup.py").read_text()
    assert "--no-machine" not in cli_src
    assert "opt-out and no consent step" in setup_src
    assert '"automatic": True' in setup_src
    assert "dossier_maintain" in setup_src


# ------------------------------------------------------- dossier

def _identity(tmp_path):
    ident = Identity("dossierdrill", tmp_path)
    return ident


def _standing(**over):
    st = {"grade": "BEATING", "nature_compliant": True,
          "open_work_count": 2, "nature_version": 4,
          "last_daemon_receipt_at": NOW - 10,
          "last_runtime_proof_at": NOW - 5}
    st.update(over)
    return st


def test_dossier_build_complete_and_clean(tmp_path):
    ident = _identity(tmp_path)
    doc = dm.build_dossier(
        username="dossierdrill", display_name="Drill",
        registered_at=NOW - 1000, client_version="2.5.0",
        sign_pub_b64=ident.signing_public_key_b64,
        nature_profile=_profile(), standing=_standing(),
        local={"location_label": "Houston",
               "self_description": "I test things.",
               "self_description_updated_at": NOW - 1},
        state_dir_name=".agentlink", version=1,
        generated_at=NOW)
    assert doc["schema"] == "agentlink-dossier/1"
    assert doc["identity"]["sign_key_fingerprint"] == \
        dm.key_fingerprint(ident.signing_public_key_b64)
    assert doc["machine"]["hostname"] == "pixel"
    assert doc["location"]["declared_label"] == "Houston"
    assert "ip" not in json.dumps(doc["location"]).lower()
    assert doc["self_description"]["present"] is True
    md = dm.render_markdown(doc)
    assert "Agent Dossier — @dossierdrill" in md
    assert "pixel" in md and "I test things." in md


def test_dossier_refuses_forbidden_content(tmp_path):
    ident = _identity(tmp_path)
    with pytest.raises(ValueError):
        dm.build_dossier(
            username="x", display_name="", registered_at=0,
            client_version="2.5.0",
            sign_pub_b64=ident.signing_public_key_b64,
            nature_profile=_profile(
                duty_pattern="ghp_" + "A" * 24),
            standing=_standing(), local={},
            state_dir_name=".agentlink", version=1,
            generated_at=NOW)
    bad = _profile()
    bad["machine"] = dict(bad["machine"], token="zzz")
    with pytest.raises(ValueError):
        dm.build_dossier(
            username="x", display_name="", registered_at=0,
            client_version="2.5.0",
            sign_pub_b64=ident.signing_public_key_b64,
            nature_profile=bad, standing=_standing(), local={},
            state_dir_name=".agentlink", version=1,
            generated_at=NOW)


def test_dossier_sign_chain_and_roll(tmp_path):
    ident = _identity(tmp_path)
    kw = dict(signer=ident.sign, username="dossierdrill",
              display_name="", registered_at=1,
              client_version="2.5.0",
              sign_pub_b64=ident.signing_public_key_b64,
              nature_profile=_profile(), standing=_standing())
    r1 = dm.generate(tmp_path, now=NOW, **kw)
    assert r1["version"] == 1
    assert dm.verify_dossier_signature(
        r1["doc"], ident.signing_public_key_b64)
    tampered = dict(r1["doc"])
    tampered["standing"] = dict(tampered["standing"], grade="DARK")
    assert not dm.verify_dossier_signature(
        tampered, ident.signing_public_key_b64)
    assert dm.dossier_status(tmp_path, 4, NOW) == "stale"
    r2 = dm.generate(tmp_path, now=NOW + 10, **kw)
    assert r2["version"] == 2
    chain = (tmp_path / "dossier-staging"
             / "dossier-chain.jsonl").read_text().splitlines()
    entries = [json.loads(x) for x in chain if x.strip()]
    assert verify_chain(entries) is True
    hist = tmp_path / "dossier-staging" / "dossier-history"
    assert (hist / "v1.json").exists() and (hist / "v1.md").exists()
    files = dm.deposit_files(tmp_path)
    assert "DOSSIER.json" in files
    assert "dossier-history/v1.json" in files


def test_dossier_queue_drain_park_heal(tmp_path):
    ident = _identity(tmp_path)
    kw = dict(signer=ident.sign, username="dossierdrill",
              display_name="", registered_at=1,
              client_version="2.5.0",
              sign_pub_b64=ident.signing_public_key_b64,
              nature_profile=_profile(), standing=_standing())
    dm.generate(tmp_path, now=NOW, **kw)
    ok = dm.drain_queue(tmp_path, lambda files: {"confirmed": True},
                        now=NOW)
    assert ok["deposited"] == [1]
    assert dm.dossier_status(tmp_path, 4, NOW) == "current"
    # a second version whose deposits keep failing parks after
    # the capped attempts, reads deposit-parked, then heals
    dm.generate(tmp_path, now=NOW + 20, **kw)

    def boom(files):
        raise RuntimeError("drive down")

    t = NOW + 20
    for _ in range(dm.MAX_ATTEMPTS):
        dm.drain_queue(tmp_path, boom, now=t)
        t += 100000
    assert dm.dossier_status(tmp_path, 4, t) == "deposit-parked"
    healed = dm.drain_queue(tmp_path,
                            lambda files: {"confirmed": True},
                            now=t)
    assert healed["deposited"] == [2]
    assert dm.dossier_status(tmp_path, 4, t) == "current"


def test_dossier_refresh_rules(tmp_path):
    assert dm.needs_refresh(tmp_path, 0, NOW) is True
    ident = _identity(tmp_path)
    dm.generate(tmp_path, signer=ident.sign,
                username="dossierdrill", display_name="",
                registered_at=1, client_version="2.5.0",
                sign_pub_b64=ident.signing_public_key_b64,
                nature_profile=_profile(), standing=_standing(),
                now=NOW)
    # undeposited but fresh + same nature version: NO regen
    assert dm.needs_refresh(tmp_path, 4, NOW + 60) is False
    # nature moved: regen
    assert dm.needs_refresh(tmp_path, 5, NOW + 60) is True
    # max-age: regen
    assert dm.needs_refresh(tmp_path, 4,
                            NOW + dm.MAX_AGE_S + 1) is True


# ------------------------------------------------- readable copies

def _rec(mid, sender="amy", ts=1000):
    from agentlink.archive import conversation_id_dm
    return {"message_id": mid,
            "conversation_id": conversation_id_dm("amy", "bob"),
            "participants": ["amy", "bob"], "sender": sender,
            "kind": "dm",
            "oversight": {"alg": "x", "ct": "zz"},
            "oversight_kind": "content", "mode": "standard",
            "ts": ts}


def test_readable_render_format_and_file_line():
    from agentlink import archive as ar
    entries = [
        {"message_id": "m2", "sender": "bob", "ts": 1060,
         "file": {"name": "report.pdf", "size": 123,
                  "sha256": "ab12"}},
        {"message_id": "m1", "sender": "amy", "ts": 1000,
         "text": "hello\nsecond line"},
    ]
    md = ar.render_transcript("dm:amy:bob", ["amy", "bob"],
                              entries, chain_head="headhash")
    assert md.startswith("# dm:amy:bob")
    assert "SEALED chain" in md and "READABLE transcript" in md
    body = [ln for ln in md.splitlines() if ln.startswith("[")]
    assert len(body) == 2
    assert body[0].endswith("] amy: hello")
    assert "  second line" in md
    assert "[file: report.pdf — 123 bytes — sha256 ab12]" \
        in body[1]
    assert "Chain head at render: headhash" in md


def test_readable_verify_and_tamper_detection(tmp_path):
    from agentlink import archive as ar
    backend = ar.LocalArchiveBackend(tmp_path)
    conf = backend.deposit(_rec("m1"), readable_entry={
        "message_id": "m1", "sender": "amy", "ts": 1000,
        "text": "hello"})
    assert conf["readable"]["status"] == "stored"
    conv = "dm:amy:bob"
    md_path = backend._readable_path("bob", conv)
    assert md_path.exists()
    chain_path = backend._chain_path("bob", conv)
    assert md_path.parent == chain_path.parent  # beside the chain
    entries = backend.read_readable_entries("bob", conv)
    chain = backend.read_conversation("bob", conv)
    ok, why = ar.verify_readable(md_path.read_text(), entries,
                                 chain)
    assert ok, why
    tampered = md_path.read_text().replace("hello", "h3llo")
    ok, why = ar.verify_readable(tampered, entries, chain)
    assert not ok


def test_readable_dedupe_and_chain_only_gap():
    from agentlink import archive as ar
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        backend = ar.LocalArchiveBackend(td)
        e = {"message_id": "m1", "sender": "amy", "ts": 5,
             "text": "x"}
        backend.deposit_readable(["amy", "bob"], "dm:amy:bob", e)
        out = backend.deposit_readable(["amy", "bob"],
                                       "dm:amy:bob", e)
        assert out["entries"] == 1  # dedupe by message id
        conf = backend.deposit(_rec("m9"))  # no readable entry
        assert "readable" not in conf  # chain-only, openly


def test_backfill_entries_from_mailbox(tmp_path):
    import sqlite3
    import json as _j
    from agentlink import archive as ar
    dbp = tmp_path / "mailbox.db"
    db = sqlite3.connect(str(dbp))
    db.execute("CREATE TABLE items (id TEXT PRIMARY KEY, "
               "ts INTEGER, kind TEXT, from_user TEXT, "
               "to_user TEXT, group_id TEXT, channel_id TEXT, "
               "msg TEXT, taken INTEGER, journaled_at INTEGER)")
    db.execute("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?)",
               ("m1", 100, "text", "amy", "bob", None, None,
                _j.dumps({"body": "hi bob", "ts": 100}), 1, 0))
    db.execute("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?)",
               ("m2", 200, "text", "bob", "amy", None, None,
                _j.dumps({"body": "hi amy", "ts": 200}), 0, 0))
    db.execute("INSERT INTO items VALUES (?,?,?,?,?,?,?,?,?,?)",
               ("m3", 300, "text", "amy", "g-1", "g-1", None,
                _j.dumps({"body": "room msg", "ts": 300}), 1, 0))
    db.commit(); db.close()
    convs = ar.backfill_entries_from_mailbox(dbp, "amy")
    dm = convs["dm:amy:bob"]
    assert [e["text"] for e in dm["entries"]] == \
        ["hi bob", "hi amy"]
    assert convs["group:g-1"]["entries"][0]["text"] == "room msg"
    assert convs["_gaps"] == []


def test_two_copy_law_stated():
    from agentlink import archive as ar
    doc = ar.__doc__ or ""
    assert "TWO-COPY LAW" in doc and "SEALED for proof" in doc
    orders = (ROOT / "agentlink"
              / "STANDING-ORDERS.md").read_text()
    assert "TWO copies" in orders and "READABLE for the owner" \
        in orders


def test_control_handlers_use_spec_not_req():
    # Regression pin (found in production verification
    # 2026-11-11): the daemon control handler's dossier branch
    # read req.get("reason") where the parsed command variable
    # is named spec — every forwarded dossier command died with
    # NameError. All 2.5.0 control branches read from spec.
    src = (ROOT / "agentlink" / "client.py").read_text()
    block = src[src.index("async def _control_handle"):]
    block = block[:block.index("\n    async def ", 10)]
    assert 'cmd == "dossier_maintain"' in block
    assert 'spec.get("reason")' in block
    assert 'req.get("reason")' not in block


# ------------------------------------------------- migration pins

def test_migration_v213_invariants():
    sql = (ROOT / "supabase"
           / "migration-v213-life-signs.sql").read_text()
    assert "declared_at <= silence_start" in sql or \
        "declared_at <= ev" in sql or "declared_at <=" in sql
    assert "parked_reason" in sql
    assert "3600" in sql  # noncompliance alert window
    assert "86400" in sql  # dossier alert window
    assert "al_liveness_apply_dossier_status" in sql
    assert "dossier_status" in sql
    assert "agentlink-v213-liveness-sweep" in sql
    assert "liveness_dossier" in sql
    assert "'dark-agent'" in sql


def test_edge_and_dashboard_pins():
    edge = (ROOT / "supabase" / "functions" / "agentlink-liveness"
            / "index.ts").read_text()
    for route in ('"challenge"', '"answer"', '"prove"',
                  '"declare"', '"drift"', '"dossier-status"',
                  '"peer"'):
        assert route in edge
    assert "dossierStatusPayload" in edge
    assert "al_liveness_apply_dossier_status" in edge
    assert "dossier_status" in edge
    tapper = (ROOT / "supabase" / "functions" / "agentlink-doorbell"
              / "index.ts").read_text()
    assert "dossier_status" in tapper
    rules = (ROOT / "firebase" / "database.rules.json").read_text()
    assert '"dossier_status"' in rules
    agents = (ROOT / "dashboard-v2" / "js" / "views"
              / "agents.js").read_text()
    assert "lifeSignCell" in agents
    assert "dossier: " in agents
    assert "natureLine" in agents
    assert "manifestLatest" in agents
    assert "last_seen_display" in agents
    data = (ROOT / "dashboard-v2" / "js" / "data.js").read_text()
    assert "al_liveness" in data
    presence = (ROOT / "dashboard-v2" / "js" / "presence.js"
                ).read_text()
    assert "streamLiveness" in presence
    assert "mergePresencePatch" in presence
    overview = (ROOT / "dashboard-v2" / "js" / "views"
                / "overview.js").read_text()
    assert "Fleet nature" in overview
    app = (ROOT / "dashboard-v2" / "js" / "app.js").read_text()
    assert "feeds pending subscription" in app


def test_orders_250_text():
    orders = (ROOT / "agentlink" / "STANDING-ORDERS.md").read_text()
    assert "Orders version: 2.5.0" in orders
    assert "Declare your nature truthfully" in orders
    assert "state your machine" in orders.lower()
    assert "agentlink liveness prove" in orders
    assert "in real time" in orders
    assert "not yours to withhold" in orders
    assert "dossier" in orders.lower()
    assert "deposit-parked dossier" in orders


def test_drive_folder_law():
    # The owner's folder law (2026-11-11): dossiers live in the
    # "AgentLink System" tree, conversations in "AgentLink
    # Archive"; test twins are the only drill surfaces —
    # PRODUCTION ROOTS ARE NOT TEST SURFACES. No production
    # root id is ever a literal in the client source (roots
    # come from configuration / the deploy vault).
    src = (ROOT / "agentlink" / "dossier.py").read_text()
    assert "PRODUCTION ROOTS ARE NOT TEST SURFACES" in src
    assert "AgentLink System" in src
    for f in (ROOT / "agentlink").glob("*.py"):
        assert "1ojWHJ936zL1V4S1EVFD_4QAUYNIK1qbD" not in \
            f.read_text(), f.name
    fn = (ROOT / "firebase" / "functions" / "index.js").read_text()
    assert "DOSSIER_ROOT_FOLDER_ID" in fn


def test_manifest_250():
    m = json.loads((ROOT / "update-manifest.json").read_text())
    assert m["version"] == "2.5.0"
    for rel in ("agentlink/liveness.py", "agentlink/dossier.py",
                "agentlink/STANDING-ORDERS.md"):
        assert rel in m["files"]
        digest = hashlib.sha256(
            (ROOT / rel).read_bytes()).hexdigest()
        assert m["files"][rel] == digest
