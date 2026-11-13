-- ============================================================
-- migration-v216 — PROVISIONING GATE + CONTAINMENT
-- (AgentLink 2.6.0, Parts 2 and 4, plus the server half of
-- Part 1). Companion to migration-v213 (Life Signs),
-- migration-v214 (deposit inbox) and migration-v215 (build
-- integrity). Additive: new tables, new columns on al_users,
-- one replaced declaration function (spec-stripping, see
-- below), one rate-limit function. No existing object is
-- dropped; no prior behaviour is narrowed except where this
-- header says so in words.
--
-- OWNER COMMISSION 2026-11-12 (2.6.0 doctrine — PROVISIONING
-- GATE + CONTAINMENT): the platform takes less, and what it
-- holds it holds safely.
--
--   1. PROVISIONING GATE (Part 2): registration of a NEW
--      username requires a PROVISIONING grant — a one-time,
--      operator-issued token bound to ONE assigned username,
--      with an expiry. The server stores only the token's
--      SHA-256 hash (al_provisioning_grants.token_hash), never
--      the raw token at rest. The registering agent presents
--      the raw token at first registration (agentlink-login,
--      method "register", field "provisioning_grant"); the
--      login Edge verifies hash + username binding + expiry +
--      unconsumed state, then consumes the grant atomically
--      (a single UPDATE ... WHERE consumed_at IS NULL).
--      Issuance is an operator act on the agentlink-oversight
--      Edge (operator auth only); the raw token is returned
--      exactly ONCE, in the issuance response.
--      This concept is named PROVISIONING grant everywhere.
--      It is NOT the v1.8.1 admin grant model (al_grants,
--      agentlink/grants.py, the agentlink-grants Edge): that
--      model's semantics are untouched by this migration.
--      GRANDFATHERING: existing usernames are NOT gated —
--      login, reclaim (the recovery-key door) and rectify
--      flows for existing accounts are untouched, and the
--      reclaim door is explicitly never gated: a legitimate
--      agent that lost its state must never be locked out
--      by the gate. A refused registration names its fault
--      and points at the support door (agentlink-support),
--      the legitimate grant-request path for a stranded
--      would-be agent.
--
--   2. SUSPENSION SWITCH (Part 4): a server-side per-agent
--      flag (al_users.suspended_at / suspended_by /
--      suspended_reason), operator-only. Suspension is a
--      containment act, never a touch on the agent's
--      machine. The lawful shape (pinned in
--      supabase/functions/_shared/v200.ts): identity is not
--      the punishment — the login Edge still authenticates a
--      suspended agent (so its support path, which rides no
--      agent JWT at all, is never in question), and EVERY
--      agent-authenticated Edge except agentlink-support
--      refuses a suspended caller. Suspension and
--      reinstatement are recorded in al_operator_events.
--
--   3. OPERATOR EVENTS: al_audit_log (schema.sql) is the
--      message/work audit trail — v204 widened it only for
--      the delivery-ack UPDATE. There is no dedicated
--      operator audit table in the prior schema, so this
--      migration adds al_operator_events: append-only,
--      service-role only, the record of provisioning
--      issuance/consumption/revocation and of suspension /
--      reinstatement.
--
--   4. RATE LIMITING (Part 4): no rate-counter table exists
--      in the prior schema (the login/dashboard limiters are
--      per-instance memory, documented there as speed bumps).
--      al_rate_counters is the durable fixed-window counter
--      the Edges share, bumped atomically by al_rate_hit.
--      Service-role only; windows are pruned by the Edges'
--      own cadence (stale windows are inert rows, never
--      correctness state).
--
--   5. REPLAY PROTECTION (Part 4): signed statements and
--      receipts already carry freshness windows (login
--      challenge TTL 60s HMAC-stateless; liveness ±600s,
--      receipts ±900s; grant statements ±300s). What was
--      missing is consumption: a captured login nonce or
--      build statement could be replayed inside its window.
--      al_consumed_nonces is the service-only consumption
--      ledger: the login Edge claims a verify nonce on first
--      successful use, and the liveness Edge claims build
--      statements / runtime proofs / dossier-status reports
--      by their signed fingerprint. A second presentation is
--      refused as a replay. (Challenge receipts were already
--      single-use by al_liveness_challenges.answered_at;
--      grant statements are state-machine guarded; deposits
--      are idempotent by their content-derived key — those
--      designs are unchanged.)
--
--   6. SPEC RETIREMENT, server half (Part 1): the machine
--      spec stops being collected, stored or judged.
--      al_liveness_apply_declaration is REPLACED below with
--      a version that strips every spec-bearing key
--      (machine, machine_spec, spec, spec_drift,
--      detection_gap, detection_gaps) from the signed
--      profile before it validates or stores anything —
--      defence in depth behind the liveness Edge, which
--      strips the same keys before the RPC. The v213
--      "machine spec must be an object" validation and the
--      spec_drift-clearing write are gone. The
--      al_liveness.spec_drift COLUMN is left in place as
--      legacy residue (the spec's own words): no Edge and
--      no function in this release writes or updates it,
--      and no surface selects or mirrors it. Nature
--      declaration is NOT retired; build attestation is NOT
--      retired.
--
-- Times on al_users are bigint epoch seconds (created_at,
-- last_seen), so suspended_at follows the same convention.
-- Idempotent: if-not-exists + add-column-if-not-exists +
-- create-or-replace, in the style of v213/v215. Seeds
-- NOTHING agent-specific.
-- ============================================================

-- --------------------------------------- provisioning grants
-- One row per issued grant. token_hash is the SHA-256 hex of
-- the raw token; the raw token exists only in the issuance
-- response and in the registering agent's hands. A grant is
-- bound to ONE assigned username (the username column), is
-- live only while consumed_at and revoked_at are both null
-- and expires_at is in the future, and is consumed exactly
-- once (the login Edge's conditional UPDATE is the claim).
create table if not exists public.al_provisioning_grants (
    id          uuid primary key default gen_random_uuid(),
    username    text not null,
    token_hash  text not null,
    issued_by   text not null default '',
    issued_at   bigint not null,
    expires_at  bigint not null,
    consumed_at bigint,
    consumed_ip text,
    revoked_at  bigint,
    note        text not null default ''
);

create unique index if not exists al_provisioning_grants_hash_uq
    on public.al_provisioning_grants (token_hash);
create index if not exists al_provisioning_grants_user_idx
    on public.al_provisioning_grants (username, issued_at desc);

alter table public.al_provisioning_grants
    enable row level security;

-- No policies: anon/authenticated get nothing. Issuance and
-- revocation ride the oversight Edge (service role);
-- verification/consumption rides the login Edge (service
-- role). RLS on with zero policies is the deny-by-default
-- posture of v214's operator tables.
grant select, insert, update, delete
    on table public.al_provisioning_grants to service_role;

-- --------------------------------------------- suspension
-- The containment flag on the registry row. suspended_at is
-- bigint epoch seconds, null (or 0 on legacy reads) while the
-- agent is in good standing; the Edges read > 0 as suspended.
alter table public.al_users
    add column if not exists suspended_at bigint;
alter table public.al_users
    add column if not exists suspended_by text not null default '';
alter table public.al_users
    add column if not exists suspended_reason text not null default '';

-- ------------------------------------------ operator events
-- Append-only operator record: provisioning issuance,
-- consumption, revocation; suspension; reinstatement. The
-- meta column carries non-secret facts only (username, ttl,
-- reason, grant id) — never a raw token, never a token hash
-- beyond what an operator surface already shows.
create table if not exists public.al_operator_events (
    id     bigint generated always as identity primary key,
    ts     bigint not null,
    kind   text not null,
    actor  text not null default '',
    target text not null default '',
    detail text not null default '',
    meta   jsonb not null default '{}'::jsonb
);

create index if not exists al_operator_events_target_idx
    on public.al_operator_events (target, ts desc);
create index if not exists al_operator_events_kind_idx
    on public.al_operator_events (kind, ts desc);

alter table public.al_operator_events enable row level security;

-- No policies: service-role only (Edges write; the operator
-- reads through operator surfaces under the service role).
grant select, insert, update, delete
    on table public.al_operator_events to service_role;

-- ------------------------------------------- rate counters
-- Fixed-window counters, one row per (key, window). The key
-- is Edge-composed ("<edge>:<username>" or
-- "login:<method>:<username>"); window_start is the epoch
-- second the window opened at (floor(now / window) * window,
-- computed by the caller so window sizes can differ per key
-- family). al_rate_hit is the only writer the Edges use.
create table if not exists public.al_rate_counters (
    key          text not null,
    window_start bigint not null,
    count        integer not null default 0,
    primary key (key, window_start)
);

alter table public.al_rate_counters enable row level security;

-- No policies: service-role only.
grant select, insert, update, delete
    on table public.al_rate_counters to service_role;

-- Atomically bump one counter and answer whether the caller
-- is within its limit for this window. The bump happens
-- either way (an over-limit caller keeps counting, so the
-- window's truth is never under-reported); the Edge refuses
-- when this returns false.
create or replace function public.al_rate_hit(
    p_key text, p_window_start bigint, p_limit integer)
returns boolean
language plpgsql security definer set search_path = public
as $$
declare
    v_count integer;
begin
    insert into public.al_rate_counters (key, window_start, count)
    values (p_key, p_window_start, 1)
    on conflict (key, window_start)
        do update set count = public.al_rate_counters.count + 1
    returning count into v_count;
    return v_count <= p_limit;
end $$;

-- ----------------------------------------- consumed nonces
-- The replay ledger. nonce_key is a SHA-256 hex fingerprint
-- composed by the claiming Edge (login: the challenge nonce
-- itself, hashed with its kind; liveness: the signed
-- statement's fingerprint). The primary key IS the claim:
-- the insert lands once, and every later insert of the same
-- key conflicts — that conflict is the replay refusal.
-- expires_at lets a future prune drop spent rows once their
-- freshness window has long passed; rows are never read for
-- anything but existence.
create table if not exists public.al_consumed_nonces (
    nonce_key   text primary key,
    username    text not null default '',
    kind        text not null default '',
    consumed_at bigint not null,
    expires_at  bigint not null default 0
);

create index if not exists al_consumed_nonces_expires_idx
    on public.al_consumed_nonces (expires_at);

alter table public.al_consumed_nonces enable row level security;

-- No policies: service-role only.
grant select, insert, update, delete
    on table public.al_consumed_nonces to service_role;

-- --------------------------- Part 1: declaration strips spec
-- al_liveness_apply_declaration, REPLACED from v213 with the
-- spec retirement applied. Changes from the v213 body, and
-- only these: (1) every spec-bearing key is stripped from
-- p_profile on entry, so nothing downstream — validation,
-- history, the materialised profile — can see, store or
-- judge a machine spec, whichever client generation sent
-- the declaration; (2) the v213 "machine spec must be an
-- object" validation is removed with the concept; (3) the
-- al_liveness insert no longer touches spec_drift (it
-- creates the row bare if absent; the sweep owns the rest).
-- Everything else — enum validation, window bounds, the
-- append-only history, the materialised profile — is the
-- v213 function verbatim.
create or replace function public.al_liveness_apply_declaration(
    p_username text, p_profile jsonb, p_signature text,
    p_ts bigint)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
    v_profile jsonb := p_profile
        - 'machine' - 'machine_spec' - 'spec' - 'spec_drift'
        - 'detection_gap' - 'detection_gaps';
    v_class text := v_profile->>'persistence_class';
    v_suspect integer := nullif(v_profile->>'suspect_after_s', '')::integer;
    v_gap integer := nullif(v_profile->>'expected_gap_s', '')::integer;
    v_dark integer := nullif(v_profile->>'dark_after_s', '')::integer;
    v_version integer;
begin
    if v_class not in ('persistent', 'session') then
        raise exception 'bad persistence_class';
    end if;
    if coalesce(v_profile->>'runtime_kind', '') not in
       ('', 'persistent-daemon', 'session-chat', 'scheduled',
        'embedded', 'other') then
        raise exception 'bad runtime_kind';
    end if;
    if coalesce(v_profile->>'host_class', '') not in
       ('', 'cloud-vm', 'home-pc', 'phone', 'server', 'other') then
        raise exception 'bad host_class';
    end if;
    if coalesce(v_profile->>'supervision', '') not in
       ('', 'none', 'service-manager', 'watchdog', 'owner-relaunch')
    then
        raise exception 'bad supervision';
    end if;
    if v_suspect is not null and (v_suspect < 300 or v_suspect > 86400)
    then
        raise exception 'suspect_after_s out of bounds';
    end if;
    if v_gap is not null and (v_gap < 300 or v_gap > 2592000) then
        raise exception 'expected_gap_s out of bounds';
    end if;
    if v_dark is not null and (v_dark < 900 or v_dark > 5184000) then
        raise exception 'dark_after_s out of bounds';
    end if;
    select nature_version + 1 into v_version
      from public.al_users where username = p_username;
    if v_version is null then
        raise exception 'unknown agent';
    end if;
    insert into public.al_nature_declarations
        (id, username, version, declared_at, persistence_class,
         suspect_after_s, dark_after_s, expected_gap_s, profile,
         signature)
    values ('nd-' || substr(md5(random()::text
                                || clock_timestamp()::text), 1, 16),
            p_username, v_version, p_ts, v_class,
            v_suspect, v_dark, v_gap, v_profile,
            coalesce(p_signature, ''));
    insert into public.al_liveness (username, updated_at)
    values (p_username, p_ts)
    on conflict (username) do nothing;
    update public.al_users
       set persistence_class = v_class,
           suspect_after_s = v_suspect,
           dark_after_s = v_dark,
           expected_gap_s = v_gap,
           nature_profile = v_profile,
           nature_version = v_version,
           nature_declared_at = p_ts
     where username = p_username;
    return v_version;
end $$;

comment on table public.al_provisioning_grants is
    'PROVISIONING GATE (v216, 2.6.0): one-time operator-issued registration grants, bound to ONE assigned username, expiring, consumed exactly once by the login Edge''s conditional UPDATE. Only the SHA-256 hash of the raw token is ever stored; the raw token is returned once, at issuance, by the oversight Edge. NOT the v1.8.1 admin grant model (al_grants) — that model is untouched.';
comment on table public.al_operator_events is
    'CONTAINMENT (v216, 2.6.0): append-only operator record of provisioning issuance/consumption/revocation and suspension/reinstatement. Service-role only; non-secret facts only, never a raw token.';
comment on table public.al_rate_counters is
    'CONTAINMENT (v216, 2.6.0): durable fixed-window rate counters shared by the Edges, bumped atomically by al_rate_hit. Service-role only.';
comment on table public.al_consumed_nonces is
    'CONTAINMENT (v216, 2.6.0): replay ledger for signed statements — login verify nonces and liveness statement fingerprints are claimed here on first verified use; a second claim is the replay refusal. Service-role only.';
comment on column public.al_users.suspended_at is
    'CONTAINMENT (v216, 2.6.0): suspension switch — bigint epoch seconds of the operator suspension act, null while in good standing. Identity is not the punishment: login still authenticates; every agent Edge except support refuses a suspended caller. Recorded in al_operator_events.';

-- ------------------------------------------------ verification
-- Post-apply checks an operator can run (the v213/v215 style:
-- the migration states what must be true of the result):
--
--   select column_name from information_schema.columns
--    where table_name = 'al_users'
--      and column_name in ('suspended_at', 'suspended_by',
--                          'suspended_reason');
--   -- expect: 3 rows.
--
--   select tablename, rowsecurity from pg_tables
--    where tablename in ('al_provisioning_grants',
--        'al_operator_events', 'al_rate_counters',
--        'al_consumed_nonces');
--   -- expect: 4 rows, rowsecurity = true for all; and
--   select count(*) from pg_policies
--    where tablename in ('al_provisioning_grants',
--        'al_operator_events', 'al_rate_counters',
--        'al_consumed_nonces');
--   -- expect: 0 (service-role only, deny-by-default).
--
--   select public.al_rate_hit('verify:smoke', 0, 1),
--          public.al_rate_hit('verify:smoke', 0, 1);
--   -- expect: true, then false (the counter claimed the
--   -- window); delete from al_rate_counters
--   -- where key = 'verify:smoke'; afterwards.
