"""AgentLink v2.0 Phase 7 — operator (dashboard) auth static pins.

These tests parse the two NEW Phase 7 files as TEXT and pin the
security contract, so a future edit cannot quietly widen it:

  * migration-v200-operator.sql gives the operator JWT a SELECT
    policy on exactly the 27 dashboard-read tables — and NO write
    policy (insert / update / delete / all) anywhere in the file;
  * al_dashboard_sessions carries NO operator policy (Edge service
    role only), and no policy is granted to anon;
  * al_jwt_is_operator() reads the operator claim from
    request.jwt.claims, in the Phase 1 helper style, failing
    closed;
  * agentlink-dashboard/index.ts verifies the password ONLY as a
    SHA-256 hex against the DASHBOARD_PASSWORD_SHA256 function
    secret (never a plaintext-password env), stores only the
    token's SHA-256 hash with a 7-day expiry, mints the operator
    JWT with both documented operator-claim spellings, and answers
    with the field names dashboard-v2/js/data.js actually reads
    (device_token / access_token — the frontend contract wins),
    plus the Phase 7 brief's aliases;
  * the service key is read only from its env NAME; no secret
    value, token literal or raw-token storage appears anywhere.

No network, no secrets: pure text pins, like the Phase 1 suite.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OP_SQL = (ROOT / "supabase" / "migration-v200-operator.sql").read_text()
EDGE = (ROOT / "supabase" / "functions" / "agentlink-dashboard"
        / "index.ts").read_text()
DATA_JS = (ROOT / "dashboard-v2" / "js" / "data.js").read_text()
SHARED = (ROOT / "supabase" / "functions" / "_shared"
          / "v200.ts").read_text()

# The exact dashboard-read table list (Phase 7 brief; derived from
# dashboard-v2/js/data.js loadAll() plus the composition tables
# documented in the migration header).
DASHBOARD_TABLES = [
    "al_users", "al_groups", "al_group_members", "al_group_keys",
    "al_channels", "al_channel_members", "al_channel_keys",
    "al_queue", "al_work", "al_work_deliveries",
    "al_work_checkpoints", "al_chains", "al_chain_steps",
    "al_blobs", "al_library", "al_vault", "al_alerts",
    "al_audit_log", "al_message_reads", "al_servers",
    "al_connections", "al_rooms", "al_agent_connectors",
    "al_grants", "al_grant_receipts", "al_grant_approvals",
    "al_activeness",
]


def _policies(sql: str) -> list[tuple[str, str, str]]:
    """(name, table, block) for every create-policy statement that
    is NOT inside a comment (the rollback block is commented out
    and must not count — a rollback drop is not a policy)."""
    live = "\n".join(
        line for line in sql.splitlines()
        if not line.lstrip().startswith("--"))
    out = []
    for m in re.finditer(
            r"create policy (\w+) on (?:public\.)?(al_\w+)(.*?);",
            live, flags=re.S):
        out.append((m.group(1), m.group(2), m.group(0)))
    return out


# ------------------------------------------------------- migration

def test_operator_table_list_is_exact():
    assert len(DASHBOARD_TABLES) == 27
    assert len(set(DASHBOARD_TABLES)) == 27


def test_every_dashboard_table_has_an_op_select_policy():
    by_table = {t: (n, b) for n, t, b in _policies(OP_SQL)}
    for table in DASHBOARD_TABLES:
        assert table in by_table, table
        name, block = by_table[table]
        assert name == f"op_{table}_select", (table, name)
        assert "for select" in block, table
        assert "to authenticated" in block, table
        assert "al_jwt_is_operator()" in block, table


def test_no_extra_operator_policies():
    tables = sorted(t for _n, t, _b in _policies(OP_SQL))
    assert tables == sorted(DASHBOARD_TABLES), tables


def test_no_write_policy_for_operator_anywhere():
    for name, _table, block in _policies(OP_SQL):
        assert name.startswith("op_"), name
        lowered = block.lower()
        for verb in ("for insert", "for update", "for delete",
                     "for all"):
            assert verb not in lowered, (name, verb)
    # and no write GRANT to authenticated either: every live
    # (non-comment) grant statement grants SELECT and nothing else
    live = "\n".join(
        line for line in OP_SQL.splitlines()
        if not line.lstrip().startswith("--"))
    grants = re.findall(r"grant\s+([^;]+?)\s+to authenticated\s*;",
                        live)
    assert grants, "no grants parsed — parser or file is broken"
    for g in grants:
        assert re.fullmatch(r"select on table public\.al_\w+",
                            g.strip()), g


def test_dashboard_sessions_has_no_operator_policy():
    tables = {t for _n, t, _b in _policies(OP_SQL)}
    assert "al_dashboard_sessions" not in tables
    # the exclusion is explicit in the file, with the revoke kept
    assert "SERVICE-ONLY" in OP_SQL and "al_dashboard_sessions" in OP_SQL
    assert ("revoke all on table public.al_dashboard_sessions"
            " from authenticated") in OP_SQL


def test_no_policy_for_anon_and_no_using_true():
    for name, _table, block in _policies(OP_SQL):
        assert "anon" not in block.lower(), name
        assert not re.search(r"using\s*\(\s*true\s*\)", block), name


def test_is_operator_helper_reads_the_operator_claim():
    assert "function public.al_jwt_is_operator()" in OP_SQL
    assert "request.jwt.claims" in OP_SQL
    # boolean claim (Phase 7 brief) AND string claim (frontend
    # README contract) are both recognised
    assert "->> 'operator'" in OP_SQL
    assert "->> 'app_role'" in OP_SQL
    assert "= 'operator'" in OP_SQL
    # written in the Phase 1 helper style and failing closed
    m = re.search(r"function public\.al_jwt_is_operator\(\)(.*?)\$\$;",
                  OP_SQL, flags=re.S)
    assert m, "al_jwt_is_operator body missing"
    assert "return false" in m.group(1)
    assert "app_metadata" in m.group(1)  # documented fallback source


def test_migration_is_additive_and_idempotent():
    live = "\n".join(
        line for line in OP_SQL.splitlines()
        if not line.lstrip().startswith("--")).lower()
    assert "drop table" not in live
    assert "delete from" not in live
    assert "truncate" not in live
    # idempotence: helper is create-or-replace, every policy is
    # drop-if-exists first, RLS enables restated per table
    assert "create or replace function public.al_jwt_is_operator" in OP_SQL
    assert OP_SQL.count("drop policy if exists op_") >= 27
    for table in DASHBOARD_TABLES:
        assert f"alter table public.{table} enable row level security" \
            in OP_SQL, table
        assert f"grant select on table public.{table} to authenticated" \
            in OP_SQL, table


def test_rollback_is_documented_by_op_prefix():
    assert "drop policy if exists op_al_users_select" in OP_SQL
    assert "drop function if exists public.al_jwt_is_operator()" in OP_SQL
    assert OP_SQL.count("drop policy if exists op_") >= 54  # live + rollback


def test_monitor_only_law_is_stated():
    # the header states the no-write law and where downloads go
    assert "monitor-only" in OP_SQL
    assert "r2sign" in OP_SQL and "oversight" in OP_SQL


# ------------------------------------------------------------ edge

def test_edge_compares_only_the_password_hash_env():
    assert 'env("DASHBOARD_PASSWORD_SHA256")' in EDGE
    # never a plaintext password env: the exact-name lookups that
    # would read one do not exist (the _SHA256 name itself is fine)
    assert not re.search(r'env\("DASHBOARD_PASSWORD"\)', EDGE)
    assert not re.search(r'Deno\.env\.get\("DASHBOARD_PASSWORD"\)', EDGE)
    # the presented password is hashed, then compared in constant
    # time against the configured digest
    assert "sha256Hex(password)" in EDGE
    assert "constantTimeEqual(presentedHash, configuredHash)" in EDGE


def test_edge_stores_only_the_token_hash_with_7_day_expiry():
    assert 'insertRow(supabase, "al_dashboard_sessions"' in EDGE
    assert "token_hash: await sha256Hex(deviceToken)" in EDGE
    assert "7 * 24 * 3600" in EDGE  # DEVICE_TRUST_SECONDS mirror
    assert "expires_at: now + SESSION_TTL_SECONDS" in EDGE
    assert "created_at: now" in EDGE
    # the raw token is never a stored column value under its own
    # name in the insert body
    insert = re.search(r'insertRow\(supabase, "al_dashboard_sessions",'
                       r"\s*\{(.*?)\}\)", EDGE, flags=re.S)
    assert insert and "deviceToken)" in insert.group(1)
    assert "token:" not in insert.group(1)
    # 32 random bytes, base64url — secrets.token_urlsafe(32) mirror
    assert "randomTokenUrlSafe(32)" in EDGE


def test_edge_mints_operator_jwt_with_both_claim_spellings():
    for token in ('role: "authenticated"', 'username: OPERATOR_USERNAME',
                  "operator: true", 'app_role: "operator"',
                  'aud: "authenticated"'):
        assert token in EDGE, token
    assert 'OPERATOR_USERNAME = "operator"' in EDGE
    # TTL is the shared module's 3600s constant, reused not forked
    assert "SUPABASE_JWT_TTL_SECONDS" in EDGE
    assert "SUPABASE_JWT_TTL_SECONDS" in SHARED
    # local variant built from shared primitives (shared file is
    # imported, never reimplemented wholesale)
    assert 'from "../_shared/v200.ts"' in EDGE
    for helper in ("stableSubForUsername", "hmacSha256", "sha256Hex",
                   "insertRow", "selectOne", "jsonResponse",
                   "methodGuard"):
        assert helper in EDGE, helper


def test_edge_response_matches_the_frontend_contract():
    # data.js reads exactly these two fields off the login response
    assert "j.device_token" in DATA_JS and "j.access_token" in DATA_JS
    assert "device_token: deviceToken" in EDGE
    assert "access_token: accessToken" in EDGE
    # the Phase 7 brief's names ride as aliases for the same values
    assert "session_token: deviceToken" in EDGE
    assert "supabase_jwt: accessToken" in EDGE
    assert "expires_in: SUPABASE_JWT_TTL_SECONDS" in EDGE
    assert "session_expires_in: SESSION_TTL_SECONDS" in EDGE
    # and the frontend's hard-coded route is the documented slug
    assert '"/dashboard-login"' in DATA_JS
    assert "dashboard-login" in EDGE


def test_edge_login_failure_is_uniform_and_rate_limited():
    assert 'errorResponse(\n    "invalid_credentials"' in EDGE \
        or '"invalid_credentials"' in EDGE
    assert "401" in EDGE
    assert "MAX_FAILURES = 5" in EDGE
    assert "FAILURE_WINDOW_SECONDS = 300" in EDGE
    assert '"rate_limited"' in EDGE and "429" in EDGE


def test_edge_logout_deletes_the_session_row():
    assert '"logout"' in EDGE
    assert '.from("al_dashboard_sessions")' in EDGE
    assert ".delete().eq(\"token_hash\", tokenHash)" in EDGE


def test_edge_refresh_remints_from_the_device_token():
    assert '"refresh"' in EDGE
    # refresh validates the stored session before minting, and the
    # validation hashes the presented token (never stores/compares
    # a raw token against the table)
    assert "sessionRow" in EDGE
    assert "token_hash: await sha256Hex(token)" in EDGE


def test_service_key_is_read_only_from_its_env_name():
    # every mention of the service key env name is either the
    # createClient env read or a comment line naming secrets
    for line in EDGE.splitlines():
        if "SUPABASE_SERVICE_ROLE_KEY" in line:
            assert 'Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")' in line \
                or line.lstrip().startswith("//"), line
    assert 'env("AGENTLINK_JWT_SECRET")' in EDGE


def test_no_secret_values_or_literals_in_new_files():
    keyish = re.compile(r"eyJ[A-Za-z0-9_-]{20,}|[0-9a-f]{64}")
    for label, text in (("edge", EDGE), ("migration", OP_SQL)):
        assert not keyish.search(text), label
    # the password value itself is never logged anywhere
    assert "console.log" not in EDGE
    assert "console.error" not in EDGE
