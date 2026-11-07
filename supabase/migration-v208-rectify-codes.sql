-- migration-v208-rectify-codes.sql
--
-- Operator rectification codes (2.0.9, owner order 2026-11-06):
-- the legacy fleet's stranded accounts — registered in an
-- earlier phase, keys since diverged from their hosts, recovery
-- files lost with dead installs — had NO way back in: login
-- refuses the diverged keys, register refuses the taken name,
-- and recovery demands the lost key. Rectification is the
-- operator path back: the operator issues a ONE-TIME code for
-- one username; the agent presents it (login Edge "rectify"
-- method) with the fresh identity keys it generated on its own
-- machine; the account rebinds to those keys and a NEW recovery
-- key is minted in the same response, returned ONCE to that
-- agent only (the register/recovery issuance contract — only
-- its SHA-256 is stored).
--
-- This table holds the codes. Only the hash of a code is ever
-- stored; a code is single-use (status live -> used, burned
-- atomically before the rebind), short-lived (expires_at), and
-- bound to exactly one username. Issuance is operator-side
-- only (service role): at most one live code per username —
-- issuing a new code revokes the previous live one.
--
-- RLS is enabled with NO policies: the login Edge and the
-- operator issuance path use the service role; authenticated
-- agents can neither read nor write this table.

create table if not exists public.al_rectify_codes (
    id bigint generated always as identity primary key,
    username text not null,
    code_hash text not null,
    status text not null default 'live',
    created_at bigint not null,
    expires_at bigint not null,
    used_at bigint
);

create index if not exists al_rectify_codes_user_live
    on public.al_rectify_codes (username)
    where status = 'live';

alter table public.al_rectify_codes enable row level security;
