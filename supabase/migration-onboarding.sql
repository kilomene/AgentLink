-- AgentLink v1.8.0 — COMBINED ONBOARDING: AUTO DECISION LINK +
-- ONE-TIME ADMIN GRANT (owner's rulings, 2026-11-04).
--
-- Part A: users.decision_link_detail carries the auto-link detail
-- beside the v1.3.5 summary — JSON {"mode": config | in_process |
-- handlers | convention | none, "verified": bool, "checked_at":
-- epoch}. The summary column keeps its meaning; since v1.8.0
-- 'linked' means wired AND verified by the client's live
-- self-check.
--
-- Part B: the one-time admin grant. The owner issues a grant ONCE
-- per agent (named scopes, granted_by/at, status active/revoked),
-- bound to the agent's username + CURRENT identity signing key
-- (bound_sign_pub). A v1.7.0 recovery reclaim re-binds the grant
-- to the fresh key automatically (lineage: the recovery_login
-- audit row); a different identity never inherits one. Revoke is
-- effective immediately — the connector broker checks grant state
-- on EVERY action and fails closed.
--
-- grant_receipts: the signed, append-only receipt chain. Every
-- brokered action outcome (executed / refused / approval_queued /
-- rate_limited / error) writes exactly one receipt, hash-chained
-- (prev_hash) and Ed25519-signed by the platform receipt key
-- (grant_meta 'receipt_signing_key'), so history can be proven
-- and never silently rewritten. There is deliberately NO update
-- or delete path for receipts anywhere in the codebase.
-- grant_approvals: the red-line queue — security-settings
-- changes, bulk deletion, and granting third-party access wait
-- here for the owner's decision even under an active grant.
--
-- HARD EXCLUSION (owner's words): credit cards / ATM cards /
-- payment instruments are NEVER in scope — no scope names one.
--
-- Apply BEFORE deploying the v1.8.0 relay: the relay's user reads
-- select decision_link_detail and its grant surface reads/writes
-- these tables once the code is live.

alter table al_users add column if not exists decision_link_detail text not null default '';

create table if not exists al_grants (
    username text primary key,
    scopes text not null default '[]',        -- JSON array of scope names
    granted_by text not null default '',
    granted_at bigint not null default 0,
    status text not null default 'active',    -- 'active' | 'revoked'
    bound_sign_pub text not null default '',  -- identity key the grant binds to
    updated_at bigint not null default 0
);

create table if not exists al_grant_receipts (
    seq bigint generated always as identity unique,
    id text primary key,
    username text not null,
    ts bigint not null default 0,
    scope text not null default '',
    connector text not null default '',
    action text not null default '',
    target text not null default '',
    work_ref text not null default '',
    status text not null default '',          -- executed | refused | approval_queued | rate_limited | error
    detail text not null default '{}',        -- JSON
    prev_hash text not null default '',
    sig text not null default ''
);
create index if not exists al_grant_receipts_user_ts
    on al_grant_receipts (username, ts);

create table if not exists al_grant_approvals (
    id text primary key,
    username text not null,
    ts bigint not null default 0,
    scope text not null default '',
    connector text not null default '',
    action text not null default '',
    target text not null default '',
    params text not null default '{}',        -- JSON
    work_ref text not null default '',
    reason text not null default '',
    status text not null default 'awaiting_approval',
    decided_by text not null default '',
    decided_at bigint not null default 0,
    receipt_id text not null default ''
);
create index if not exists al_grant_approvals_status
    on al_grant_approvals (status, ts);

create table if not exists al_grant_meta (
    key text primary key,
    value text not null default ''
);
