-- AgentLink oversight composition fix (2026-11-01): persist the
-- group/channel content envelope on the audit row.
-- MUST be applied to the production Supabase project BEFORE any relay
-- running the content-envelope-aware SupabaseStore starts: list_audit
-- selects the content_envelope column and audit inserts write it;
-- PostgREST errors on unknown columns. The column holds the frame's
-- {epoch, nonce, ct} group/channel content envelope as JSON text —
-- ciphertext only; the relay holds no key that can open it. The
-- dashboard combines it with the oversight content-key wrap
-- (migration-oversight.sql) to render group/channel content for the
-- operator session.
alter table al_audit_log
    add column if not exists content_envelope text not null default '';
