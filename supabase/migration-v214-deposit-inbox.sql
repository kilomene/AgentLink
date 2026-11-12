-- ================================================================
-- AgentLink v2.5.1 — migration v214: THE PLATFORM DEPOSIT INBOX
--
-- WHY: the Agent Dossier (v2.5.0) and the universal message
-- archive (2.4.1) deposited through an ENV-CONFIGURED route —
-- a Firebase function URL (owner's Blaze step, never deployed)
-- plus a shared archive token. On every stock install the route
-- was effectively absent, and the client's fallback was a silent
-- local park: "dossier stays local for now since no archive
-- destination is set." The owner's correction (2026-11-11): the
-- Drive dossier is COMPULSORY, and a missing destination must be
-- an impossible state, not a silent one.
--
-- WHAT THIS MIGRATION BUILDS — the deposit destination becomes a
-- hardened platform built-in, on infrastructure that exists
-- today (this record layer):
--
--   al_deposit_inbox: one row per CONFIRMED deposit. The client
--   POSTs to the agentlink-deposit Edge function under its OWN
--   session JWT; the function verifies the agent's identity
--   from the JWT, verifies the dossier's own Ed25519 signature
--   against the registry key (dossier deposits), enforces the
--   sealed-record rules (message deposits), and only then
--   inserts here. The operator drain (this VM, the Drive
--   service account) files undrained rows into the owner's
--   Drive trees — AgentLink System/<agent>/ for dossiers,
--   AgentLink Archive/<agent>/ chains for messages — and stamps
--   drained_at. When the Blaze archiveDeposit function later
--   deploys, it drains the same inbox; nothing client-side
--   changes.
--
--   Idempotency: (agent, kind, deposit_key) is unique. The
--   deposit key is content-derived — dossier-v<version>-<sha256>
--   for dossiers, the message_id for message records — so a
--   retried deposit is the SAME row, never a duplicate filing.
--
--   Custody boundary: dossier CONTENT transits the platform
--   only as this inbox row, on its way to the owner's Drive —
--   the same custody the retired archive service would have
--   held. Rows are operator-plane data: RLS is on and NO policy
--   grants anon/authenticated anything; the Edge function and
--   the drain ride the service role.
-- ================================================================

create table if not exists public.al_deposit_inbox (
    id bigint generated always as identity primary key,
    agent text not null,
    kind text not null check (kind in ('dossier', 'message')),
    deposit_key text not null,
    payload jsonb not null,
    received_at bigint not null
        default (extract(epoch from now()))::bigint,
    drained_at bigint,
    drain_note text not null default ''
);

create unique index if not exists al_deposit_inbox_key_uq
    on public.al_deposit_inbox (agent, kind, deposit_key);

create index if not exists al_deposit_inbox_undrained_idx
    on public.al_deposit_inbox (id) where drained_at is null;

alter table public.al_deposit_inbox enable row level security;

-- No policies: anon/authenticated get nothing. The Edge
-- function (service role) inserts; the operator drain
-- (service role) reads + stamps. RLS on with zero policies
-- is the deny-by-default posture every operator table here
-- carries.

-- The service-role grant is stated explicitly rather than
-- left to platform default privileges, so the table is
-- usable on any Postgres this migration is applied to
-- (the v204 column-grant precedent).
grant select, insert, update, delete
    on table public.al_deposit_inbox to service_role;
