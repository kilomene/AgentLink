-- AgentLink v2.0.2 (migration): dashboard realtime publication.
--
-- The v2 dashboard (dashboard-v2/) is a live monitor fed by Supabase
-- Realtime postgres_changes. schema.sql published only six tables to
-- supabase_realtime (al_users, al_work, al_chains, al_alerts,
-- al_audit_log, al_library). The dashboard subscribes to the message
-- queue, deliveries, activeness mirror, grants, rooms, vault, group
-- structure, chain steps, reads and connector inventory as well;
-- without publication membership their changes never reach the
-- subscription and the views would sit stale.
--
-- This migration is purely additive and idempotent: each block adds
-- one table to the publication only if it is not already a member.
-- REPLICA IDENTITY FULL is set on the four tables whose UPDATE
-- events the dashboard diffs in place (work pipeline, activeness
-- mirror, rooms, grants) so old-row values ride along in the event.
--
-- Applied by the operator (Phoenix) after review; RLS is unchanged -
-- Realtime evaluates the same operator policies as REST for every
-- subscriber.

do $$
declare
  t text;
  tables text[] := array[
    'al_queue', 'al_work_deliveries', 'al_activeness',
    'al_grants', 'al_grant_receipts', 'al_grant_approvals',
    'al_rooms', 'al_vault',
    'al_groups', 'al_channels', 'al_group_members', 'al_channel_members',
    'al_chain_steps', 'al_message_reads',
    'al_agent_connectors', 'al_connections', 'al_servers', 'al_blobs'
  ];
begin
  foreach t in array tables loop
    if not exists (
      select 1 from pg_publication_tables
      where pubname = 'supabase_realtime' and schemaname = 'public'
        and tablename = t
    ) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

alter table public.al_work replica identity full;
alter table public.al_activeness replica identity full;
alter table public.al_rooms replica identity full;
alter table public.al_grants replica identity full;
