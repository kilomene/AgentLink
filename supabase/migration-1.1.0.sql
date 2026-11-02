-- AgentLink v1.1.0 production migration.
-- Apply ONCE to the live Supabase project (SQL Editor) BEFORE the
-- relay is restarted on v1.1.0 code. Idempotent: safe to re-run.
-- The SQLite Store performs the equivalent migration automatically
-- on open (Store._migrate_v11); this file is the Postgres twin.
--
-- What it does:
--   1. audit_log gains the sender identity columns the dashboard's
--      conversation drill-down reads (nickname / role / custom role).
--   2. work + chain_steps gain require_approval (approval gates).
--   3. upload_sessions reaches the canonical shape: no for_channel
--      column (channel scope is asserted by the relay at session
--      start and carried on the finish frame) and chunks stored as
--      the JSON text list the store writes.
--   4. invites: production is already canonical (token/created_at);
--      the guarded block below reshapes only if an older build is
--      found, back-deriving created_at = expires_at - 7 days so
--      outstanding invites keep their exact remaining validity.

alter table al_audit_log
    add column if not exists sender_nickname text not null default '';
alter table al_audit_log
    add column if not exists sender_role text not null default '';
alter table al_audit_log
    add column if not exists sender_custom_role text not null default '';

alter table al_work
    add column if not exists require_approval integer not null default 0;
alter table al_chain_steps
    add column if not exists require_approval integer not null default 0;

alter table al_upload_sessions drop column if exists for_channel;
alter table al_upload_sessions
    alter column chunks type text
    using (case when chunks is null then '[]' else chunks::text end);
alter table al_upload_sessions alter column chunks set default '[]';

do $$
begin
    if exists (select 1 from information_schema.columns
               where table_name = 'al_invites'
                 and column_name = 'token_hash') then
        alter table al_invites rename column token_hash to token;
        alter table al_invites
            add column if not exists created_at bigint not null default 0;
        update al_invites set created_at = expires_at - 604800;
        alter table al_invites drop column if exists expires_at;
    end if;
end $$;
