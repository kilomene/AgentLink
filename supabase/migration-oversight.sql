-- AgentLink owner-oversight migration (2026-11-01).
-- MUST be applied to the production Supabase project BEFORE any relay
-- running the oversight-aware SupabaseStore starts: list_audit selects
-- the oversight column and audit inserts write it; PostgREST errors on
-- unknown columns. The column holds the oversight wrap as JSON text —
-- ciphertext only; the relay holds no oversight private key.
alter table al_audit_log
    add column if not exists oversight text not null default '';
