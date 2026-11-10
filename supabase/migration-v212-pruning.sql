-- AgentLink v212 (2.4.0) — growth hygiene for delivery
-- machinery + sweep silence.
--
-- The 2026-11-08 restriction was two meters: egress and LOG
-- INGESTION. Both grow when delivery-machinery tables grow
-- without bound (every read of a bloated table is egress) and
-- when sweeps chatter into platform logs. This migration adds
-- the missing pruning and pins the silence rule:
--
-- * al_doorbell_outbox: a row's life ends when it is tapped.
--   Tapped rows older than 7 days are delivery history nobody
--   reads — prune them daily. Untapped rows are NEVER pruned
--   (an untapped row is a pending wakeup, not garbage).
-- * al_rectify_codes: a used or expired code is spent; spent
--   codes older than 30 days are pruned daily. Unused,
--   unexpired codes are NEVER pruned.
--
-- HARD BOUNDARY (immortality law): pruning touches DELIVERY
-- MACHINERY ONLY. Conversation content — al_audit_log,
-- al_queue custody, mailboxes, the owner archive — is never
-- pruned, by any job, ever. Neither function below names a
-- content table, and the 2.4.0 gate pins that (the migration
-- text is scanned for content-table names in DELETEs).
--
-- SWEEP SILENCE: these functions RAISE nothing on a normal
-- run — no per-row, no per-run notices into platform logs.
-- The row counts land in al_quota_budgets-free bookkeeping:
-- the prune functions return the count to the cron caller
-- only, and cron.job_run_details is the operator's record.
-- Anomalies (a prune that errors) surface as job failures,
-- which is the one signal that should ever speak.

create or replace function public.al_prune_doorbell_outbox()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
    removed integer;
begin
    delete from public.al_doorbell_outbox
    where tapped
      and ts < extract(epoch from now() - interval '7 days')::bigint;
    get diagnostics removed = row_count;
    return removed;
end;
$$;

create or replace function public.al_prune_rectify_codes()
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
    removed integer;
begin
    -- al_rectify_codes stamps are epoch SECONDS (bigint).
    delete from public.al_rectify_codes
    where (status <> 'live'
           or expires_at < extract(epoch from now())::bigint)
      and created_at < extract(epoch from now())::bigint
                        - 30 * 86400;
    get diagnostics removed = row_count;
    return removed;
end;
$$;

-- Daily, off-peak. Unschedule-first: re-running is safe.
select cron.unschedule('agentlink-v212-prune-doorbell-outbox')
where exists (select 1 from cron.job
              where jobname = 'agentlink-v212-prune-doorbell-outbox');
select cron.schedule('agentlink-v212-prune-doorbell-outbox',
    '17 4 * * *',
    $$ select public.al_prune_doorbell_outbox() $$);

select cron.unschedule('agentlink-v212-prune-rectify-codes')
where exists (select 1 from cron.job
              where jobname = 'agentlink-v212-prune-rectify-codes');
select cron.schedule('agentlink-v212-prune-rectify-codes',
    '23 4 * * *',
    $$ select public.al_prune_rectify_codes() $$);
