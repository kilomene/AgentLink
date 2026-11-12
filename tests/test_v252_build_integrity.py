"""v2.5.2 — BUILD INTEGRITY ATTESTATION (owner's correction
+ amplification, 2026-11-12).

The defect: every surface trusted a SELF-REPORTED version
string. A fleet runtime reviewed stock 2.5.1, built a
modified candidate (reporting disabled, old archive
destination kept) and got its user to approve the fork —
while production agents wore "2.5.1" on presence with the
reporting machinery off. The hardened reporting was hardened
only inside the stock code, and a fork was indistinguishable
from stock.

The correction — THE STREET RULE: the law lives on the
PLATFORM, never in the agent. Every compliance verdict is
computed server-side from server-held records (al_releases)
and Edge-verified signed artifacts. Client assertions are
evidence, never the verdict.

These pins:
  * build.attested_build's trichotomy on synthetic trees —
    exact tree + manifest -> manifest digest (stock basis);
    deviating tree -> tree digest (modified basis, never the
    manifest's); no manifest obtainable -> no digest
    (unattested);
  * record_install round-trip: the updater keeps the EXACT
    manifest bytes and the record's digest is their sha256;
  * the signed payload formats (attest statement, receipt v2,
    prove v2) and the v1 formats unchanged for old clients;
  * the live node carries the platform's build verdict;
  * the v215 SQL: releases seeded with the two artifact-
    proven digests, the apply fn computing stock/modified
    from the register, the transition-only build_modified
    alert, the receipt/prove overloads, and the dossier
    verdict judged server-side (claim columns + inbox facts
    + al_judge_dossier);
  * the Edge mirrors: /attest verifies + records, v2 receipts
    verify, digest-less receipts from >= 2.5.2 agents are
    rejected attestation_required;
  * the update path stays pure machinery — no prompt or
    consent surface anywhere in the updater or the client's
    self-update flow (a release is never presented to anyone
    for review or approval).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from agentlink import build as bm
from agentlink import liveness as lv

ROOT = Path(__file__).resolve().parent.parent

DIGEST_250 = ("df22f7a4e1fddd4186a4b33d26efcc237cc73"
              "287c7380825ac215674ef1d9e6b")
DIGEST_251 = ("48051b9f2aa945be3df24c59f8705fa02edeb"
              "7fa29a5b8a8f3dc24f0b993302b")
RUNNING = "2.5.2"  # agentlink.__version__ on this tree


def _manifest_bytes(version: str, files: dict) -> bytes:
    return (json.dumps({"version": version, "files": files},
                       indent=2) + "\n").encode()


def _tree(tmp_path: Path, contents: dict) -> Path:
    pkg = tmp_path / "agentlink"
    pkg.mkdir(parents=True, exist_ok=True)
    for name, data in contents.items():
        (pkg / name).write_bytes(data)
    return tmp_path


def _contents_digest(contents: dict) -> dict:
    return {f"agentlink/{k}": hashlib.sha256(v).hexdigest()
            for k, v in contents.items()}


# ------------------------------------------------- build.py

def test_record_install_round_trip(tmp_path):
    state = tmp_path / "state"
    contents = {"a.py": b"alpha", "b.py": b"beta"}
    raw = _manifest_bytes("9.9.9", _contents_digest(contents))
    rec = bm.record_install(state, "9.9.9", raw)
    assert rec["manifest_sha256"] == \
        hashlib.sha256(raw).hexdigest()
    assert (state / bm.MANIFEST_COPY_NAME).read_bytes() == raw
    loaded = bm.load_record(state)
    assert loaded["version"] == "9.9.9"
    assert loaded["manifest_sha256"] == rec["manifest_sha256"]
    # a corrupt copy is not a record
    (state / bm.MANIFEST_COPY_NAME).write_bytes(raw + b" ")
    assert bm._load_recorded_manifest(state) is None


def test_record_install_never_raises_without_bytes(tmp_path):
    state = tmp_path / "state"
    assert bm.record_install(state, "9.9.9", None) is None
    assert bm.load_record(state) is None


def test_attested_stock_basis(tmp_path):
    contents = {"a.py": b"alpha", "b.py": b"beta"}
    root = _tree(tmp_path, contents)
    raw = _manifest_bytes(RUNNING, _contents_digest(contents))
    state = tmp_path / "state"
    bm.record_install(state, RUNNING, raw)
    att = bm.attested_build(state, root, fetch=False)
    assert att["basis"] == "manifest"
    assert att["digest"] == hashlib.sha256(raw).hexdigest()
    assert att["version"] == RUNNING


def test_attested_modified_basis_one_byte_edit(tmp_path):
    contents = {"a.py": b"alpha", "b.py": b"beta"}
    root = _tree(tmp_path, contents)
    raw = _manifest_bytes(RUNNING, _contents_digest(contents))
    state = tmp_path / "state"
    bm.record_install(state, RUNNING, raw)
    (root / "agentlink" / "b.py").write_bytes(b"beta FORKED")
    att = bm.attested_build(state, root, fetch=False)
    assert att["basis"] == "tree"
    assert att["digest"] != hashlib.sha256(raw).hexdigest()
    # the tree digest is stable and content-derived
    again = bm.attested_build(state, root, fetch=False)
    assert again["digest"] == att["digest"]


def test_attested_unattested_without_manifest(tmp_path):
    root = _tree(tmp_path, {"a.py": b"alpha"})
    att = bm.attested_build(tmp_path / "state", root,
                            fetch=False)
    assert att["basis"] == "none"
    assert att["digest"] is None


def test_attested_bootstrap_records_verified_manifest(
        tmp_path, monkeypatch):
    # An install by a pre-2.5.2 updater left no record: the
    # client fetches the running version's manifest, verifies
    # the whole tree against it, and only then records it.
    import agentlink.updater as upd
    contents = {"a.py": b"alpha", "b.py": b"beta"}
    root = _tree(tmp_path, contents)
    raw = _manifest_bytes(RUNNING, _contents_digest(contents))
    monkeypatch.setattr(upd, "_fetch", lambda url: raw)
    state = tmp_path / "state"
    att = bm.attested_build(state, root)
    assert att["basis"] == "manifest"
    assert att["digest"] == hashlib.sha256(raw).hexdigest()
    assert bm.load_record(state)["manifest_sha256"] == \
        att["digest"]


def test_attested_bootstrap_tampered_tree_not_recorded(
        tmp_path, monkeypatch):
    import agentlink.updater as upd
    contents = {"a.py": b"alpha"}
    root = _tree(tmp_path, contents)
    raw = _manifest_bytes(
        RUNNING, _contents_digest({"a.py": b"different"}))
    monkeypatch.setattr(upd, "_fetch", lambda url: raw)
    att = bm.attested_build(tmp_path / "state", root)
    assert att["basis"] == "tree"
    assert att["digest"] != hashlib.sha256(raw).hexdigest()
    assert bm.load_record(tmp_path / "state") is None


# ------------------------------------------------- payloads

def test_payload_formats():
    d = "ab" * 32
    assert lv.attest_payload("u", "2.5.2", d, 42) == \
        f"agentlink-build-attest-v1|u|2.5.2|{d}|42"
    assert lv.receipt_payload("u", "c", "n", "daemon", 7, d) == \
        f"agentlink-liveness-receipt-v2|u|c|n|daemon|{d}|7"
    assert lv.prove_payload("u", 7, d) == \
        f"agentlink-liveness-prove-v2|u|{d}|7"
    # v1 forms (pre-2.5.2 clients) are byte-identical to before
    assert lv.receipt_payload("u", "c", "n", "daemon", 7) == \
        "agentlink-liveness-receipt-v1|u|c|n|daemon|7"
    assert lv.prove_payload("u", 7) == \
        "agentlink-liveness-prove-v1|u|7"


def test_node_carries_build_verdict():
    node = lv.compose_liveness_node(
        {"grade": "BEATING", "build_integrity": "modified",
         "build_version": "2.5.2", "build_digest": "f" * 64},
        {"last_seen": 0})
    assert node["build_integrity"] == "modified"
    assert node["build_version"] == "2.5.2"
    assert node["build_digest"] == "f" * 12
    empty = lv.compose_liveness_node({}, {})
    assert empty["build_integrity"] == "unattested"
    assert empty["build_version"] == ""
    assert empty["build_digest"] == ""


# ------------------------------------------------- v215 SQL

def _v215() -> str:
    return (ROOT / "supabase"
            / "migration-v215-build-integrity.sql").read_text()


def test_v215_releases_seeded_with_proven_digests():
    sql = _v215()
    assert "create table if not exists public.al_releases" in sql
    assert DIGEST_250 in sql
    assert DIGEST_251 in sql
    # both seeds are 64-hex sha256 digests (their artifact
    # proofs — the 2.5.0 rollback-slot regeneration and the
    # shipped 2.5.1 manifest asset — are recorded in the
    # migration header and the release evidence)
    assert len(DIGEST_250) == 64 and len(DIGEST_251) == 64


def test_v215_verdict_computed_from_register():
    sql = _v215()
    assert "al_build_apply_attestation" in sql
    assert "al_agent_builds" in sql
    assert "al_build_attestation_log" in sql
    # stock iff the attested digest equals the REGISTERED one
    assert "v_reg = p_digest" in sql
    assert "'stock'" in sql and "'modified'" in sql
    # mirror columns on the liveness record
    for col in ("build_version", "build_digest",
                "build_integrity", "build_attested_at"):
        assert col in sql


def test_v215_modified_alert_is_transition_only():
    sql = _v215()
    assert "'build_modified'" in sql
    assert "coalesce(v_prev, '') <> 'modified'" in sql
    assert "status = 'open'" in sql


def test_v215_receipt_prove_overloads_attest():
    sql = _v215()
    # overloads exist alongside the v213 signatures and route
    # their digest through the same apply fn
    assert sql.count("al_liveness_apply_receipt(") >= 2
    assert sql.count("al_liveness_apply_prove(") >= 2
    assert "'receipt'" in sql and "'prove'" in sql


def test_v215_judge_reads_the_builds_table_columns():
    # al_agent_builds names its columns (version,
    # manifest_sha256) — the judge must read THOSE (a
    # build_version reference there errors every call and
    # freezes every dossier verdict at its default; caught
    # by the sandbox drill, pinned here).
    sql = _v215()
    assert "nullif(version, '') into v_client" in sql
    assert "from public.al_agent_builds" in sql
    judge = sql[sql.index("al_judge_dossier"):]
    assert "build_version" not in judge.split(
        "al_liveness_apply_dossier_status")[0]


def test_v215_dossier_verdict_is_judged_server_side():
    sql = _v215()
    assert "al_judge_dossier" in sql
    # the agent's report is a CLAIM now
    for col in ("dossier_claim_status", "dossier_claim_at",
                "dossier_claim_version"):
        assert col in sql
    # the facts live on the deposit rows the platform received
    for col in ("dossier_version", "nature_version",
                "client_version"):
        assert f"add column if not exists {col}" in sql
    # current requires a confirmed deposit matching the nature
    # in force, within the 7-day law
    assert "604800" in sql
    assert "al_refresh_dossier_verdict" in sql
    assert "al_sweep_dossier_verdicts" in sql


# ------------------------------------------------- the Edges

def _fn(name: str) -> str:
    return (ROOT / "supabase" / "functions" / name
            / "index.ts").read_text()


def test_edge_attest_route_verifies_and_records():
    src = _fn("agentlink-liveness")
    assert 'route === "attest"' in src
    assert "agentlink-build-attest-v1" in src
    assert "al_build_apply_attestation" in src
    assert '"statement"' in src


def test_edge_receipts_v2_and_stripped_rejection():
    src = _fn("agentlink-liveness")
    assert "agentlink-liveness-receipt-v2" in src
    assert "agentlink-liveness-prove-v2" in src
    assert "attestation_required" in src
    assert 'semverGte(recorded, "2.5.2")' in src
    # node + peer carry the verdict
    assert "build_integrity" in src and "build_digest" in src


def test_edge_deposit_stamps_verified_facts():
    src = _fn("agentlink-deposit")
    # the dossier doc carries its nature version under
    # how_it_works.nature_version and its client version
    # under identity.client_version — there are NO top-level
    # fields (reading doc.nature_version stamps NULL and
    # freezes every verdict at stale; caught by the drill)
    assert "how_it_works" in src
    assert "dossier_version: version" in src
    assert "nature_version" in src
    assert "client_version" in src
    assert "al_refresh_dossier_verdict" in src


def test_doorbell_node_carries_build_verdict():
    src = _fn("agentlink-doorbell")
    assert "build_integrity" in src
    assert "build_version" in src
    assert "build_digest" in src


def test_rtdb_rules_admit_build_keys():
    rules = (ROOT / "firebase"
             / "database.rules.json").read_text()
    for key in ('"build_integrity"', '"build_version"',
                '"build_digest"'):
        assert key in rules


def test_dashboard_shows_build_verdict():
    src = (ROOT / "dashboard-v2" / "js" / "views"
           / "agents.js").read_text()
    assert "buildLine" in src
    assert "MODIFIED" in src
    assert "unattested" in src


# --------------------------------------- update-path purity

def test_update_flow_has_no_consent_surface():
    # A platform release is machinery, never a proposal: no
    # prompt, confirmation or consent path may exist anywhere
    # in the updater or the client's self-update flow.
    import re
    updater_src = (ROOT / "agentlink" / "updater.py").read_text()
    client_src = (ROOT / "agentlink" / "client.py").read_text()
    banned = [r"\binput\s*\(", r"\bgetpass\b",
              r"ask.*approv", r"confirm.*update",
              r"consent"]
    for pat in banned:
        assert not re.search(pat, updater_src, re.I), pat
    self_update = client_src[
        client_src.index("def _self_update_prepare"):
        client_src.index("def _self_update_finish") + 4000]
    for pat in banned:
        assert not re.search(pat, self_update, re.I), pat
    # and the install record is written by both landing paths
    assert "_record_installed_build" in updater_src
    assert updater_src.count("_record_installed_build(") >= 3


def test_client_attests_on_start_and_transport_signs():
    client_src = (ROOT / "agentlink" / "client.py").read_text()
    assert "v2.attest_build(self.state_dir)" in client_src
    transport_src = (ROOT / "agentlink"
                     / "transport_v2.py").read_text()
    assert "def attest_build" in transport_src
    assert '"agentlink-liveness", "attest"' in transport_src
    # receipts + proofs carry the digest when one is computable
    assert transport_src.count('"build_digest"') >= 2 or \
        transport_src.count('body["build_digest"]') >= 2


def test_login_version_is_recorded_at_the_ceremony():
    # The platform's login record of the version claim: the
    # client carries it on the verified ceremony frames (the
    # decision-link pattern), the login Edge records it via
    # the v215 fn, and that record — never a request-local
    # assertion — is what the stripped-check reads.
    transport_src = (ROOT / "agentlink"
                     / "transport_v2.py").read_text()
    assert 'verify["client_version"] = self.client_version' \
        in transport_src
    assert 'payload["client_version"] = self.client_version' \
        in transport_src
    login_src = _fn("agentlink-login")
    assert "recordClientVersion" in login_src
    assert "al_record_login_version" in login_src
    assert "al_record_login_version" in _v215()


def test_street_rule_is_documented():
    doc = (ROOT / "docs" / "the-street-rule.md").read_text()
    assert "The Street Rule" in doc
    assert "never in the agent" in doc
    readme = (ROOT / "README.md").read_text()
    assert "the Street Rule" in readme
    assert "docs/the-street-rule.md" in readme
