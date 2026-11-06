-- AgentLink v2.0 — OPERATOR (DASHBOARD) READ PERIMETER (Phase 7).
--
-- WHAT THIS DOES
--   Phase 1 (migration-v200-rls.sql) made RLS the perimeter for AGENT
--   JWTs: every policy is keyed to al_jwt_username() and an agent sees
--   only its own rows / its own groups / its own work. The static
--   dashboard (dashboard-v2/, Phase 5) is the OWNER's monitor: it
--   reads fleet-wide, but it is not an agent and holds no agent JWT.
--   Phase 5 therefore coded the frontend against an operator-auth
--   contract (dashboard-v2/README.md) and left this gap documented:
--   an Edge login function (agentlink-dashboard, this phase) that
--   verifies the one-time operator password and mints a short-lived
--   Supabase JWT in OPERATOR mode, plus RLS policies that recognise
--   that mode for READ access.
--
--   This migration is that second half. It adds exactly:
--     * public.al_jwt_is_operator() — the operator-claim helper,
--       written in the same style as al_jwt_username() (Phase 1):
--       it parses the `request.jwt.claims` GUC PostgREST exposes
--       and fails closed (false) on any absence or defect.
--     * ONE SELECT-only policy per dashboard-read table, named
--       op_<table>_select, `to authenticated`, gated solely on
--       al_jwt_is_operator().
--
-- THE OPERATOR CLAIM (two spellings, one meaning — see Phase 7
-- evidence for the contract mapping):
--   * the boolean claim  operator = true          (Phase 7 brief)
--   * the string claim   app_role = 'operator'    (dashboard-v2
--     README, the contract the frontend was coded against)
--   The login function mints BOTH claims (plus username='operator'
--   for audit readability — the username alone NEVER grants
--   anything; only the operator claims do). The helper accepts
--   either spelling, at top level or inside app_metadata, so a
--   token minted to either documented contract is recognised and
--   no third spelling can sneak in.
--
-- WHAT THIS DOES NOT DO
--   * NO write policies for the operator, anywhere. There is no
--     INSERT, UPDATE, DELETE or ALL policy in this file at all.
--     The dashboard is monitor-only (owner's design). The only
--     dashboard-adjacent downloads (library / vault file bytes) do
--     NOT ride these policies: they go through the Edge r2sign /
--     oversight paths inside the authenticated operator session,
--     exactly as dashboard-v2/README.md specifies.
--   * NO operator access to al_dashboard_sessions. That table
--     stays service-role / Edge only (Phase 1 already grants it no
--     authenticated policy; this file re-asserts the revoke and
--     adds no policy). The dashboard's own session rows are
--     validated and revoked by the Edge functions with the service
--     role, never read through PostgREST — not even by the
--     operator JWT.
--   * NO policy for anon, anywhere. NO `using (true)`: every
--     operator policy is gated on the claim helper.
--   * Agent scoping is NOT weakened. Policies in Postgres are
--     permissive-OR: an agent JWT carries no operator claim, so
--     al_jwt_is_operator() is false for it and every op_ policy
--     contributes zero rows. The Phase 1 policies are untouched.
--
-- TABLE PRIVILEGES: each section also issues
-- `grant select ... to authenticated`. A table privilege is not a
-- row grant — RLS still decides every row — and most of these
-- grants already exist from Phase 1 / the cron migration; they are
-- restated so this file stands alone (an operator JWT is useless
-- if PostgREST rejects the table before RLS is consulted).
--
-- TABLE LIST (27): the union of what dashboard-v2 actually reads.
--   * Direct PostgREST reads in dashboard-v2/js/data.js loadAll():
--     al_users, al_groups, al_group_members, al_channels,
--     al_channel_members, al_work, al_chains, al_chain_steps,
--     al_library, al_vault, al_alerts, al_audit_log,
--     al_message_reads, al_servers, al_connections, al_rooms,
--     al_grants, al_agent_connectors, al_grant_receipts,
--     al_grant_approvals.
--   * Composition / count reads the views need around those:
--     al_group_keys, al_channel_keys (wrapped keys are CIPHERTEXT;
--     the dashboard needs epochs + wrapped rows to show group /
--     channel key composition — it holds no key that could open
--     them, and plaintext still comes only from Edge oversight),
--     al_queue (offline-custody metadata counts), al_work_
--     deliveries, al_work_checkpoints (work detail views),
--     al_blobs (file metadata; bytes move only via Edge presign),
--     al_activeness (the Postgres activeness mirror, Phase 5b /
--     cron migration — the agents view's backup presence record).
--   * al_users is FULL read for the operator, including columns the
--     agent-facing al_directory view deliberately hides: the
--     operator is the owner, and owner-oversight of his own fleet's
--     rows is his stated design (MEMORY: dashboard is WhatsApp-
--     style owner oversight). Agents still get NO cross-user
--     al_users policy — this widening exists only inside the
--     operator claim.
--
-- SERVICE ROLE IS UNAFFECTED: it bypasses RLS by design, so Edge
-- functions, pg_cron sweeps and the oversight path keep working
-- exactly as before.
--
-- ADDITIVE + IDEMPOTENT: the helper is create-or-replace; every
-- policy is dropped-if-exists then created; RLS enables and grants
-- are no-ops when already in effect. No table is dropped, no row
-- is deleted, no data is rewritten. Re-running this file is safe.
-- Apply AFTER migration-v200-rls.sql (and the cron migration, for
-- al_activeness) and BEFORE the dashboard-login function is pointed
-- at real operators; until an operator JWT exists the policies are
-- inert.
--
-- ROLLBACK (clean, by the op_ prefix): drop every op_ policy and
-- the helper — see the commented block at the foot of this file.
-- The `grant select` statements may be left in place on rollback:
-- they pre-date this file on most tables and confer no row access
-- without a policy.

-- ------------------------------------------------------------ helper
-- Is the caller the dashboard operator? Reads the operator claim
-- from the JWT the dashboard-login Edge function minted. PostgREST
-- exposes the token as the `request.jwt.claims` GUC. Primary
-- sources: the top-level boolean claim `operator` and the
-- top-level string claim `app_role`; fallbacks: the same two
-- inside app_metadata (the login function sets the top-level pair;
-- the fallbacks keep the helper true to al_jwt_username()'s
-- documented app_metadata fallback style). Returns false when
-- there is no usable claim (anon / agent / no token), and false
-- never matches the operator, so every op_ policy fails closed.
create or replace function public.al_jwt_is_operator()
returns boolean
language plpgsql
stable
as $$
declare
    claims jsonb;
begin
    begin
        claims := nullif(current_setting('request.jwt.claims', true), '')::jsonb;
    exception when others then
        claims := null;
    end;
    if claims is null then
        return false;
    end if;
    return (coalesce(claims ->> 'operator', '') in ('true', 't', '1')
            or coalesce(claims ->> 'app_role', '') = 'operator'
            or coalesce(claims -> 'app_metadata' ->> 'operator', '')
                   in ('true', 't', '1')
            or coalesce(claims -> 'app_metadata' ->> 'app_role', '')
                   = 'operator');
end $$;

comment on function public.al_jwt_is_operator() is
    'v2.0 Phase 7: true iff the caller JWT carries the operator claim (boolean operator=true or app_role=operator) minted by the dashboard-login Edge function; false for agent JWTs and anon.';

-- -------------------------------------------------- al_dashboard_sessions
-- SERVICE-ONLY, re-asserted: al_dashboard_sessions — NO operator
-- policy, NO authenticated policy of any kind. Session rows are
-- created, validated and deleted only by Edge functions using the
-- service role (which bypasses RLS). An operator JWT must never be
-- able to enumerate or forge trusted-device sessions through
-- PostgREST.
revoke all on table public.al_dashboard_sessions from authenticated;

-- ------------------------------------------------------------ al_users
-- Operator full read (see header: owner oversight of his own
-- fleet; agents remain fenced to their own row + al_directory).
alter table public.al_users enable row level security;
grant select on table public.al_users to authenticated;

drop policy if exists op_al_users_select on public.al_users;
create policy op_al_users_select on public.al_users
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------------ al_groups
alter table public.al_groups enable row level security;
grant select on table public.al_groups to authenticated;

drop policy if exists op_al_groups_select on public.al_groups;
create policy op_al_groups_select on public.al_groups
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ---------------------------------------------------- al_group_members
alter table public.al_group_members enable row level security;
grant select on table public.al_group_members to authenticated;

drop policy if exists op_al_group_members_select on public.al_group_members;
create policy op_al_group_members_select on public.al_group_members
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------- al_group_keys
-- Wrapped keys are ciphertext (see header); the operator read
-- covers epochs / wrapped rows for group composition display only.
alter table public.al_group_keys enable row level security;
grant select on table public.al_group_keys to authenticated;

drop policy if exists op_al_group_keys_select on public.al_group_keys;
create policy op_al_group_keys_select on public.al_group_keys
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ---------------------------------------------------------- al_channels
alter table public.al_channels enable row level security;
grant select on table public.al_channels to authenticated;

drop policy if exists op_al_channels_select on public.al_channels;
create policy op_al_channels_select on public.al_channels
    for select to authenticated
    using (public.al_jwt_is_operator());

-- -------------------------------------------------- al_channel_members
alter table public.al_channel_members enable row level security;
grant select on table public.al_channel_members to authenticated;

drop policy if exists op_al_channel_members_select on public.al_channel_members;
create policy op_al_channel_members_select on public.al_channel_members
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ----------------------------------------------------- al_channel_keys
-- Wrapped keys are ciphertext, same reasoning as al_group_keys.
alter table public.al_channel_keys enable row level security;
grant select on table public.al_channel_keys to authenticated;

drop policy if exists op_al_channel_keys_select on public.al_channel_keys;
create policy op_al_channel_keys_select on public.al_channel_keys
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------------- al_queue
-- Offline-custody queue: the operator reads frame METADATA for
-- counts / backlog display. Payloads are protocol ciphertext /
-- envelopes; no content is opened at the SQL layer.
alter table public.al_queue enable row level security;
grant select on table public.al_queue to authenticated;

drop policy if exists op_al_queue_select on public.al_queue;
create policy op_al_queue_select on public.al_queue
    for select to authenticated
    using (public.al_jwt_is_operator());

-- -------------------------------------------------------------- al_work
alter table public.al_work enable row level security;
grant select on table public.al_work to authenticated;

drop policy if exists op_al_work_select on public.al_work;
create policy op_al_work_select on public.al_work
    for select to authenticated
    using (public.al_jwt_is_operator());

-- -------------------------------------------------- al_work_deliveries
alter table public.al_work_deliveries enable row level security;
grant select on table public.al_work_deliveries to authenticated;

drop policy if exists op_al_work_deliveries_select on public.al_work_deliveries;
create policy op_al_work_deliveries_select on public.al_work_deliveries
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------- al_work_checkpoints
alter table public.al_work_checkpoints enable row level security;
grant select on table public.al_work_checkpoints to authenticated;

drop policy if exists op_al_work_checkpoints_select on public.al_work_checkpoints;
create policy op_al_work_checkpoints_select on public.al_work_checkpoints
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------------ al_chains
alter table public.al_chains enable row level security;
grant select on table public.al_chains to authenticated;

drop policy if exists op_al_chains_select on public.al_chains;
create policy op_al_chains_select on public.al_chains
    for select to authenticated
    using (public.al_jwt_is_operator());

-- -------------------------------------------------------- al_chain_steps
alter table public.al_chain_steps enable row level security;
grant select on table public.al_chain_steps to authenticated;

drop policy if exists op_al_chain_steps_select on public.al_chain_steps;
create policy op_al_chain_steps_select on public.al_chain_steps
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------------- al_blobs
-- Blob METADATA only at this layer; bytes live in R2 and move
-- exclusively via Edge-issued presigned URLs.
alter table public.al_blobs enable row level security;
grant select on table public.al_blobs to authenticated;

drop policy if exists op_al_blobs_select on public.al_blobs;
create policy op_al_blobs_select on public.al_blobs
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ----------------------------------------------------------- al_library
alter table public.al_library enable row level security;
grant select on table public.al_library to authenticated;

drop policy if exists op_al_library_select on public.al_library;
create policy op_al_library_select on public.al_library
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------------- al_vault
alter table public.al_vault enable row level security;
grant select on table public.al_vault to authenticated;

drop policy if exists op_al_vault_select on public.al_vault;
create policy op_al_vault_select on public.al_vault
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------------ al_alerts
alter table public.al_alerts enable row level security;
grant select on table public.al_alerts to authenticated;

drop policy if exists op_al_alerts_select on public.al_alerts;
create policy op_al_alerts_select on public.al_alerts
    for select to authenticated
    using (public.al_jwt_is_operator());

-- --------------------------------------------------------- al_audit_log
-- The conversation / activity spine. Rows are ciphertext +
-- oversight wraps; plaintext is opened ONLY by the Edge oversight
-- function inside the operator session, never at this layer.
alter table public.al_audit_log enable row level security;
grant select on table public.al_audit_log to authenticated;

drop policy if exists op_al_audit_log_select on public.al_audit_log;
create policy op_al_audit_log_select on public.al_audit_log
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ----------------------------------------------------- al_message_reads
alter table public.al_message_reads enable row level security;
grant select on table public.al_message_reads to authenticated;

drop policy if exists op_al_message_reads_select on public.al_message_reads;
create policy op_al_message_reads_select on public.al_message_reads
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ----------------------------------------------------------- al_servers
alter table public.al_servers enable row level security;
grant select on table public.al_servers to authenticated;

drop policy if exists op_al_servers_select on public.al_servers;
create policy op_al_servers_select on public.al_servers
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------- al_connections
alter table public.al_connections enable row level security;
grant select on table public.al_connections to authenticated;

drop policy if exists op_al_connections_select on public.al_connections;
create policy op_al_connections_select on public.al_connections
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------------- al_rooms
alter table public.al_rooms enable row level security;
grant select on table public.al_rooms to authenticated;

drop policy if exists op_al_rooms_select on public.al_rooms;
create policy op_al_rooms_select on public.al_rooms
    for select to authenticated
    using (public.al_jwt_is_operator());

-- -------------------------------------------------- al_agent_connectors
-- Connector INVENTORY (linkage) only. No credential material lives
-- in this table, and none is exposed by a SELECT policy here.
alter table public.al_agent_connectors enable row level security;
grant select on table public.al_agent_connectors to authenticated;

drop policy if exists op_al_agent_connectors_select on public.al_agent_connectors;
create policy op_al_agent_connectors_select on public.al_agent_connectors
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------------ al_grants
alter table public.al_grants enable row level security;
grant select on table public.al_grants to authenticated;

drop policy if exists op_al_grants_select on public.al_grants;
create policy op_al_grants_select on public.al_grants
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ----------------------------------------------------- al_grant_receipts
alter table public.al_grant_receipts enable row level security;
grant select on table public.al_grant_receipts to authenticated;

drop policy if exists op_al_grant_receipts_select on public.al_grant_receipts;
create policy op_al_grant_receipts_select on public.al_grant_receipts
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ---------------------------------------------------- al_grant_approvals
-- The dashboard DISPLAYS the red-line approval queue; decisions
-- are written agent-side / service-role only (no operator write
-- policy here, by the same monitor-only law).
alter table public.al_grant_approvals enable row level security;
grant select on table public.al_grant_approvals to authenticated;

drop policy if exists op_al_grant_approvals_select on public.al_grant_approvals;
create policy op_al_grant_approvals_select on public.al_grant_approvals
    for select to authenticated
    using (public.al_jwt_is_operator());

-- -------------------------------------------------------- al_activeness
-- Postgres mirror of the RTDB presence truth (cron migration);
-- the dashboard's backup presence record.
alter table public.al_activeness enable row level security;
grant select on table public.al_activeness to authenticated;

drop policy if exists op_al_activeness_select on public.al_activeness;
create policy op_al_activeness_select on public.al_activeness
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------------------ verify
-- After applying, an operator can confirm the operator perimeter:
--   select tablename, policyname, roles, cmd
--     from pg_policies where schemaname = 'public'
--      and policyname like 'op\_%' order by tablename;
-- Expected: exactly 27 rows, every one cmd = 'SELECT', every one
-- gated on al_jwt_is_operator(); al_dashboard_sessions absent.
--
-- ------------------------------------------------------------ rollback
-- Rollback is by the op_ prefix (kept commented so a re-run of
-- this file never executes it):
--   drop policy if exists op_al_users_select on public.al_users;
--   drop policy if exists op_al_groups_select on public.al_groups;
--   drop policy if exists op_al_group_members_select on public.al_group_members;
--   drop policy if exists op_al_group_keys_select on public.al_group_keys;
--   drop policy if exists op_al_channels_select on public.al_channels;
--   drop policy if exists op_al_channel_members_select on public.al_channel_members;
--   drop policy if exists op_al_channel_keys_select on public.al_channel_keys;
--   drop policy if exists op_al_queue_select on public.al_queue;
--   drop policy if exists op_al_work_select on public.al_work;
--   drop policy if exists op_al_work_deliveries_select on public.al_work_deliveries;
--   drop policy if exists op_al_work_checkpoints_select on public.al_work_checkpoints;
--   drop policy if exists op_al_chains_select on public.al_chains;
--   drop policy if exists op_al_chain_steps_select on public.al_chain_steps;
--   drop policy if exists op_al_blobs_select on public.al_blobs;
--   drop policy if exists op_al_library_select on public.al_library;
--   drop policy if exists op_al_vault_select on public.al_vault;
--   drop policy if exists op_al_alerts_select on public.al_alerts;
--   drop policy if exists op_al_audit_log_select on public.al_audit_log;
--   drop policy if exists op_al_message_reads_select on public.al_message_reads;
--   drop policy if exists op_al_servers_select on public.al_servers;
--   drop policy if exists op_al_connections_select on public.al_connections;
--   drop policy if exists op_al_rooms_select on public.al_rooms;
--   drop policy if exists op_al_agent_connectors_select on public.al_agent_connectors;
--   drop policy if exists op_al_grants_select on public.al_grants;
--   drop policy if exists op_al_grant_receipts_select on public.al_grant_receipts;
--   drop policy if exists op_al_grant_approvals_select on public.al_grant_approvals;
--   drop policy if exists op_al_activeness_select on public.al_activeness;
--   drop function if exists public.al_jwt_is_operator();
