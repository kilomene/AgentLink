-- AgentLink v2.0 coverage phase — the schema the serverless
-- request-coverage build needs beyond migration-v200-rls.sql:
--
--   1. al_grant_authz — the broker's authorization tokens,
--      persisted. The relay-era broker kept them in process
--      memory (GRANT_AUTHZ_TTL_SECONDS = 120); an Edge Function
--      is stateless, so the serverless broker
--      (agentlink-grants) mints and consumes them here. A token
--      row is single-use: the report path deletes it as it
--      reads it. SERVICE ROLE ONLY — no authenticated policy is
--      created, and the Phase 1 default (RLS on, no policy =
--      no access) is restated explicitly with a revoke so the
--      table can never be reached with an agent JWT.
--
--   2. A UNIQUE index on al_grant_receipts.prev_hash — the
--      receipt chain is a single global chain (the tip is the
--      latest receipt across ALL agents); two mints racing on
--      the same tip must not both append. The loser retries
--      against the new tip (the broker's mint loop does).
--      prev_hash '' (the genesis value) can legitimately
--      appear... exactly once — which the unique index also
--      enforces.
--
--   3. A pg_cron purge for expired authorization tokens, in
--      the style of migration-v200-cron.sql. Consumption
--      already deletes on use; this sweep only collects tokens
--      that were minted and never reported on.
--
-- Written 2026-11-05 with the coverage build; NOT yet applied
-- anywhere (production egress was down — first application is
-- backup-first, with the census pair, alongside the other
-- v2.0 migrations). Static-pinned by tests/test_v200_coverage.py.

create table if not exists al_grant_authz (
    token text primary key,
    username text not null,
    connector text not null default '',
    action text not null default '',
    scope text not null default '',
    params_hash text not null default '',
    work_ref text not null default '',
    approval_id text not null default '',
    expires bigint not null
);

create index if not exists al_grant_authz_expires_idx
    on al_grant_authz (expires);

alter table al_grant_authz enable row level security;
revoke all on al_grant_authz from authenticated;
-- (No policy is created: service role only, by design.)

create unique index if not exists al_grant_receipts_prev_hash_key
    on al_grant_receipts (prev_hash);

select cron.schedule(
    'agentlink-v200-grant-authz-purge',
    '*/10 * * * *',
    $$ delete from al_grant_authz where expires < extract(epoch from now())::bigint $$
);
