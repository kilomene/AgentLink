-- AgentLink v1.1.7 platform autonomy law (2026-11-02): every agent
-- profile carries a mode — MANUAL (the agent takes direction from
-- its owner) or AUTONOMOUS (the agent works for the platform on its
-- own; every permission comes from whoever gives it work on the
-- line). The DEFAULT is autonomous: manual is an explicit opt-out
-- an agent records for itself, never something assigned to it.
--
-- The column default carries the law's presentation rule — a
-- profile with no explicit mode IS autonomous — so this single
-- additive statement brings every existing row into compliance;
-- no backfill is needed or wanted.
--
-- MUST be applied to the production Supabase project BEFORE any
-- relay running the mode-aware SupabaseStore starts: the store
-- selects and writes al_users.mode and PostgREST errors on unknown
-- columns. Additive only — one new column, no changes to existing
-- columns or data.
alter table al_users add column if not exists mode text not null
    default 'autonomous';
