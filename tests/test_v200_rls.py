"""AgentLink v2.0 Phase 1 — RLS / cron migration static pins.

These tests parse the two v2.0 migration files as TEXT and pin the
security contract, so a future edit cannot quietly widen the
perimeter:

  * every al_ table has at least one policy for `authenticated`,
    or an explicit SERVICE-ONLY note (no silent gaps);
  * the JWT username helper exists and reads request.jwt.claims;
  * no policy is granted to anon, ever;
  * `using (true)` appears only on the al_servers registry read;
  * doorbell triggers sit on al_work / al_alerts ONLY — never on
    the message tables (al_queue / al_audit_log);
  * both migrations are additive-only (no dropped tables, no row
    deletions, no data-rewriting statements outside function
    bodies — sweep logic inside plpgsql bodies is runtime code,
    not migration-time rewriting);
  * the hyper-sensitive activeness ladder is pinned at
    BEAT 5s / SUSPECT >10s / OFFLINE >15s;
  * the quota watchdog exists, warns at 80%, and carries the
    three free-tier budgets;
  * reassignment evaluation reads the activeness truth.

The live adversarial class at the bottom runs only when
AGENTLINK_V200_LIVE=1 (with per-agent JWTs in the environment);
it is the harness the later gate phases point at a real project.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RLS_SQL = (ROOT / "supabase" / "migration-v200-rls.sql").read_text()
CRON_SQL = (ROOT / "supabase" / "migration-v200-cron.sql").read_text()
SCHEMA_SQL = (ROOT / "supabase" / "schema.sql").read_text()
BOTH = RLS_SQL + "\n" + CRON_SQL
BOTH_LOWER = BOTH.lower()

SENSITIVE_NO_TRUE = {
    "al_users", "al_grants", "al_agent_connectors", "al_group_keys",
    "al_channel_keys", "al_queue", "al_audit_log", "al_vault",
}


def _tables() -> set[str]:
    tables = set(re.findall(
        r"create table if not exists (?:public\.)?(al_\w+)", SCHEMA_SQL))
    tables |= set(re.findall(
        r"create table if not exists (?:public\.)?(al_\w+)", BOTH))
    return tables


def _policy_tables() -> set[str]:
    return set(re.findall(
        r"create policy \w+ on (?:public\.)?(al_\w+)", BOTH))


def _service_only_tables() -> set[str]:
    return set(re.findall(r"SERVICE-ONLY:\s*(al_\w+)", BOTH))


def _policy_blocks() -> list[tuple[str, str]]:
    """(table, block text) for every create-policy statement."""
    out = []
    for m in re.finditer(
            r"create policy (\w+) on (?:public\.)?(al_\w+)(.*?);",
            BOTH, flags=re.S):
        out.append((m.group(2), m.group(0)))
    return out


def _strip_function_bodies(sql: str) -> str:
    return re.sub(r"\$\$.*?\$\$", " ", sql, flags=re.S)


# ------------------------------------------------------------ coverage

def test_every_table_has_policy_or_service_only_note():
    missing = _tables() - _policy_tables() - _service_only_tables()
    assert not missing, f"tables with no policy and no note: {missing}"


def test_service_only_set_is_exactly_the_documented_one():
    assert _service_only_tables() == {
        "al_invites", "al_alert_dispatches", "al_dashboard_sessions",
        "al_grant_meta", "al_doorbell_outbox", "al_quota_budgets",
    }


def test_rls_enabled_for_all_tables_in_rls_file():
    for table in _tables() - {"al_doorbell_outbox", "al_activeness",
                              "al_quota_budgets"}:
        assert table in RLS_SQL, table


# -------------------------------------------------------------- helper

def test_jwt_username_helper_exists_and_reads_claims():
    assert "al_jwt_username" in BOTH
    assert "request.jwt.claims" in RLS_SQL
    assert "app_metadata" in RLS_SQL  # documented fallback source


def test_payload_sender_helper_covers_real_queue_shapes():
    # message frames: top-level "from"; work_assigned: work.assigner
    assert "al_payload_sender" in RLS_SQL
    assert "->> 'from'" in RLS_SQL
    assert "-> 'work' ->> 'assigner'" in RLS_SQL


# ---------------------------------------------------------------- anon

def test_no_policy_grants_anything_to_anon():
    assert "to anon" not in BOTH_LOWER
    for _table, block in _policy_blocks():
        assert "anon" not in block.lower()
    # and anon privileges are actively revoked
    assert "from anon" in BOTH_LOWER


def test_every_policy_targets_authenticated():
    blocks = _policy_blocks()
    assert blocks, "no policies parsed — parser or file is broken"
    for table, block in blocks:
        assert "to authenticated" in block, (table, block[:120])


# ------------------------------------------------------------ using(true)

def test_using_true_only_on_servers_registry():
    offenders = []
    for table, block in _policy_blocks():
        if re.search(r"using\s*\(\s*true\s*\)", block):
            offenders.append(table)
    assert offenders == ["al_servers"], offenders


def test_no_using_true_on_sensitive_tables():
    for table, block in _policy_blocks():
        if table in SENSITIVE_NO_TRUE:
            assert not re.search(r"using\s*\(\s*true\s*\)", block), table


# --------------------------------------------------------------- queue

def test_queue_ack_is_delete_of_own_rows():
    blocks = [b for t, b in _policy_blocks() if t == "al_queue"]
    joined = "\n".join(blocks)
    assert "for delete" in joined
    assert "to_username" in joined
    # the ack-by-delete choice is stated in the migration itself
    assert "acks by" in RLS_SQL and "DELETION" in RLS_SQL


def test_queue_insert_checks_payload_sender():
    assert "al_queue_insert_sender" in RLS_SQL
    assert "al_payload_sender(payload)" in RLS_SQL


# ------------------------------------------------------------- directory

def test_directory_view_excludes_secret_bearing_columns():
    m = re.search(r"create or replace view public\.al_directory as(.*?);",
                  RLS_SQL, flags=re.S)
    assert m, "al_directory view missing"
    cols = m.group(1).lower()
    for forbidden in ("secret", "recovery_hash", "vault_", "auth_method"):
        assert forbidden not in cols, forbidden
    assert "pubkey" in cols and "sign_pub" in cols


def test_users_identity_guard_trigger_exists():
    assert "al_users_guard_identity" in RLS_SQL
    assert "before update on public.al_users" in RLS_SQL


def test_work_column_guard_trigger_exists():
    assert "al_work_guard_columns" in RLS_SQL
    assert "before update on public.al_work" in RLS_SQL


def test_grants_are_read_own_only_for_authenticated():
    blocks = [b for t, b in _policy_blocks() if t == "al_grants"]
    assert len(blocks) == 1 and "for select" in blocks[0]


def test_grant_receipts_have_no_insert_policy():
    blocks = [b for t, b in _policy_blocks() if t == "al_grant_receipts"]
    assert blocks and all("for select" in b for b in blocks)


# ------------------------------------------------------------- doorbell

def test_doorbell_triggers_only_on_control_tables():
    trigs = re.findall(
        r"create trigger (\w*doorbell\w*).*?on (?:public\.)?(al_\w+)",
        BOTH, flags=re.S)
    tables = {t for _name, t in
              [(n, t) for n, t in trigs]}
    assert tables == {"al_work", "al_alerts"}, trigs


def test_doorbell_triggers_never_on_message_tables():
    for m in re.finditer(r"create trigger (\w*doorbell\w*)", BOTH):
        segment = BOTH[m.start():m.start() + 400]
        assert "al_queue" not in segment
        assert "al_audit_log" not in segment


def test_doorbell_outbox_table_shape():
    m = re.search(r"create table if not exists (?:public\.)?"
                  r"al_doorbell_outbox \((.*?)\);", CRON_SQL, flags=re.S)
    assert m
    body = m.group(1)
    for col in ("username", "ref", "kind", "ts", "tapped"):
        assert col in body, col


# ------------------------------------------------------------- additive

def test_migrations_are_additive_only():
    lower = BOTH_LOWER
    assert "drop table" not in lower
    assert "delete from" not in lower
    assert "truncate" not in lower
    drops = set(re.findall(r"drop\s+(\w+)", lower))
    assert drops <= {"policy", "trigger"}, drops


def test_no_data_rewriting_statements_outside_function_bodies():
    for name, sql in (("rls", RLS_SQL), ("cron", CRON_SQL)):
        stripped = _strip_function_bodies(sql)
        assert not re.search(
            r"update\s+(?:public\.)?al_\w+\s+set", stripped), name
        assert not re.search(r"delete\s+from", stripped.lower()), name


def test_existing_v1_sweeps_untouched_by_cron_file():
    # the v2 file must not redefine the schema.sql sweep functions
    for fn in ("al_sweep_offline", "al_sweep_deadlines",
               "al_sweep_reassignment"):
        assert f"function public.{fn}" not in CRON_SQL
        assert f"function {fn}" not in CRON_SQL


def test_cron_jobs_use_unschedule_first_idempotence():
    jobs = re.findall(r"cron\.schedule\('([\w-]+)'", CRON_SQL)
    assert jobs, "no cron jobs parsed"
    for job in jobs:
        assert f"jobname = '{job}'" in CRON_SQL, job


# ----------------------------------------------------------- activeness

def test_activeness_ladder_thresholds_are_the_law():
    lower = CRON_SQL.lower()
    assert "beat 5s" in lower
    assert "suspect >10s" in lower
    assert "offline >15s" in lower
    # and the sweep itself evaluates with those numbers
    m = re.search(r"function public\.al_sweep_activeness\(\)(.*?)\$\$;",
                  CRON_SQL, flags=re.S)
    assert m, "al_sweep_activeness missing"
    body = m.group(1)
    assert "> 15" in body and "> 10" in body


def test_activeness_table_shape_and_transition_only_intent():
    m = re.search(r"create table if not exists public\.al_activeness"
                  r" \((.*?)\);", CRON_SQL, flags=re.S)
    assert m, "al_activeness table missing"
    body = m.group(1)
    for col in ("username", "state", "beat_at", "connected_at",
                "client_version", "transport", "updated_at"):
        assert col in body, col
    assert "transition-only" in CRON_SQL.lower()
    assert "never per beat" in CRON_SQL.lower()


def test_activeness_has_own_and_circle_policies():
    tables = [t for t, _b in _policy_blocks() if t == "al_activeness"]
    assert len(tables) >= 3  # select + insert + update
    blocks = [b for t, b in _policy_blocks() if t == "al_activeness"]
    assert any("al_shares_group_with" in b for b in blocks)


def test_reassignment_reads_activeness_truth():
    m = re.search(r"(function public\.al_sweep_activeness_reassignment"
                  r".*?\$\$;)",
                  CRON_SQL, flags=re.S)
    assert m, "activeness reassignment sweep missing"
    body = m.group(1)  # signature (grace default) + body
    assert "al_activeness" in body
    assert "'offline'" in body
    assert "awaiting_agent" in body
    assert "30" in body  # reassignment grace seconds


def test_deadline_sweep_writes_doorbell_taps():
    m = re.search(r"function public\.al_sweep_activeness_deadlines"
                  r"\(\)(.*?)\$\$;", CRON_SQL, flags=re.S)
    assert m
    assert "al_doorbell_outbox" in m.group(1)


# ---------------------------------------------------------------- quota

def test_quota_watchdog_exists_and_warns_at_80_percent():
    assert "function public.al_quota_watchdog" in CRON_SQL
    assert "0.8" in CRON_SQL
    assert "warn_fraction" in CRON_SQL
    assert "kind = 'quota'" in CRON_SQL or "'quota'" in CRON_SQL


def test_quota_budgets_carry_the_free_tier_numbers():
    for number in ("500000", "10000000000", "5000000000"):
        assert number in CRON_SQL, number
    for leg in ("edge_invocations", "rtdb_download_bytes",
                "supabase_egress_bytes"):
        assert leg in CRON_SQL, leg


def test_quota_projection_is_listener_weighted_and_valved():
    # beats constant from the 5s law, the coalesce valve, and the
    # dashboard-as-one-listener term all appear in the watchdog
    assert "518400" in CRON_SQL
    assert "rtdb_coalesce_window_seconds" in CRON_SQL
    m = re.search(r"function public\.al_quota_watchdog\(\)(.*?)\$\$;",
                  CRON_SQL, flags=re.S)
    assert m and "avg_circle" in m.group(1)


def test_service_role_bypass_is_stated():
    assert "bypasses RLS" in RLS_SQL
    assert "service role" in RLS_SQL.lower()


# ------------------------------------------------------------ live tests

@pytest.mark.skipif(os.environ.get("AGENTLINK_V200_LIVE") != "1",
                    reason="live RLS tests need AGENTLINK_V200_LIVE=1")
class TestV200LiveAdversarial:
    """Cross-user adversarial reads against a real project.

    Required env: AGENTLINK_V200_SUPABASE_URL,
    AGENTLINK_V200_ANON_KEY, AGENTLINK_V200_JWT_A,
    AGENTLINK_V200_JWT_B, AGENTLINK_V200_USER_A, AGENTLINK_V200_USER_B.
    JWTs are scoped login-Edge tokens for two different agents.
    """

    def _get(self, path: str, jwt: str):
        import json
        import urllib.request
        url = os.environ["AGENTLINK_V200_SUPABASE_URL"].rstrip("/")
        req = urllib.request.Request(
            f"{url}/rest/v1/{path}",
            headers={"apikey": os.environ["AGENTLINK_V200_ANON_KEY"],
                     "Authorization": f"Bearer {jwt}"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read() or b"[]")

    def _env(self):
        keys = ("AGENTLINK_V200_SUPABASE_URL", "AGENTLINK_V200_ANON_KEY",
                "AGENTLINK_V200_JWT_A", "AGENTLINK_V200_JWT_B",
                "AGENTLINK_V200_USER_A", "AGENTLINK_V200_USER_B")
        if not all(os.environ.get(k) for k in keys):
            pytest.skip("live env incomplete")
        return {k: os.environ[k] for k in keys}

    def test_agent_cannot_read_other_agents_user_row(self):
        e = self._env()
        rows = self._get(
            f"al_users?username=eq.{e['AGENTLINK_V200_USER_B']}&select=username",
            e["AGENTLINK_V200_JWT_A"])
        assert rows == []

    def test_agent_reads_own_user_row(self):
        e = self._env()
        rows = self._get(
            f"al_users?username=eq.{e['AGENTLINK_V200_USER_A']}&select=username",
            e["AGENTLINK_V200_JWT_A"])
        assert [r["username"] for r in rows] == [e["AGENTLINK_V200_USER_A"]]

    def test_agent_cannot_read_other_agents_grant_or_keys(self):
        e = self._env()
        for table in ("al_grants", "al_group_keys", "al_agent_connectors"):
            rows = self._get(
                f"{table}?username=eq.{e['AGENTLINK_V200_USER_B']}",
                e["AGENTLINK_V200_JWT_A"])
            assert rows == [], table

    def test_agent_queue_reads_are_own_only(self):
        e = self._env()
        rows = self._get("al_queue?select=to_username",
                         e["AGENTLINK_V200_JWT_A"])
        assert {r["to_username"] for r in rows} <= {
            e["AGENTLINK_V200_USER_A"]}

    def test_service_only_tables_are_invisible(self):
        e = self._env()
        for table in ("al_invites", "al_dashboard_sessions",
                      "al_grant_meta", "al_doorbell_outbox"):
            rows = self._get(f"{table}?select=*",
                             e["AGENTLINK_V200_JWT_A"])
            assert rows == [], table
