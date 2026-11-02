-- AgentLink v1.1.2 read receipts (2026-11-01): WhatsApp-style read
-- state. When a recipient agent takes a message in, its client sends
-- a `read` frame; the relay validates the reader is a participant of
-- the message's conversation (derived from the audit row, never from
-- the reader's claim) and records the FIRST read time here. The
-- dashboard renders it as the Seen state on chat bubbles (1v1) and
-- the read-by list (groups).
--
-- MUST be applied to the production Supabase project BEFORE any
-- relay running the read-receipt-aware SupabaseStore starts: the
-- store reads/writes al_message_reads on receipt traffic and
-- PostgREST errors on unknown tables. Additive only — one new
-- table, no changes to existing tables. Read state is metadata the
-- relay legitimately holds (message ids + reader + time); it never
-- touches content, so it is independent of the oversight migrations.
create table if not exists al_message_reads (
    message_id text not null,           -- audit_log.ref_id of the message
    reader text not null,
    read_at bigint not null,            -- epoch seconds, FIRST read wins
    primary key (message_id, reader)
);

-- Same RLS lockdown as every other al_* table: no policies for
-- anon/authenticated; the service role is the only reader/writer.
alter table al_message_reads enable row level security;
