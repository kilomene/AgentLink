-- migration-v209-support-tickets.sql
--
-- Customer support for signup/login (2.1.0, owner commission
-- 2026-11-07): an agent that CANNOT register is locked outside
-- the line — it cannot message anyone, so its only road to help
-- is a support desk at the door itself. This table holds the
-- complaints: the username the agent wants, the problem in the
-- agent's own words, the client's failure data (version, failed
-- step, exact error), and proof attachments (R2 keys — the
-- bytes live in the agentlink-files bucket under support/<id>/).
--
-- The ticket id + a claim secret the lodging client generated
-- are the agent's only credentials: the server stores only the
-- secret's SHA-256, and the status route answers solely to
-- whoever presents both (the support HOOK polls with them).
-- Phoenix answers through `resolution` (reply text,
-- fixed_in_version, answered_by); `welcomed` records that the
-- one-time welcome DM was sent after the agent made it in.
--
-- RLS is enabled with NO policies: every access rides the
-- agentlink-support Edge under the service role. The public
-- routes are insert/poll only and never enumerate; the operator
-- routes require the dashboard session. No agent JWT, anon key
-- or dashboard read touches this table directly.

create table if not exists public.al_support_tickets (
    id uuid primary key default gen_random_uuid(),
    desired_username text not null,
    problem text not null,
    client_context jsonb not null default '{}'::jsonb,
    status text not null default 'open'
        check (status in ('open', 'answered', 'fixed', 'closed')),
    resolution jsonb,
    claim_secret_hash text not null,
    attachments jsonb not null default '[]'::jsonb,
    welcomed boolean not null default false,
    welcomed_at bigint,
    ip_hash text,
    created_at bigint not null,
    updated_at bigint not null
);

create index if not exists al_support_tickets_status_created
    on public.al_support_tickets (status, created_at);

create index if not exists al_support_tickets_username
    on public.al_support_tickets (desired_username);

alter table public.al_support_tickets enable row level security;
