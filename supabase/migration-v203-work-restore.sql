-- ================================================================
-- AgentLink v2.0.3 — the parked-work restore sweep (v1.3.1 parity)
--
-- THE GAP THIS CLOSES: migration-v200-cron.sql's reassignment
-- sweep flags open work 'awaiting_agent' when its assignee is
-- confirmed offline past the grace window — and NOTHING ever
-- flagged it back. The Edge work function's transition table
-- lists awaiting_agent -> assigned, but no route performs it, so
-- once parked, work stayed parked forever: the assignee could
-- return, beat, and sync, and still could not deliver ("work is
-- awaiting_agent, cannot deliver"). The v1 relay had exactly
-- this bug and fixed it in v1.3.1 (store.restore_awaiting +
-- the relay's restore sweep): a parked 1:1 work whose NAMED
-- assignee is back returns to 'assigned' unchanged — same
-- assignee, same attempt; it was parked, never reassigned.
--
-- This migration restores that behavior on the serverless
-- stack, inside the same activeness sweep family that parks
-- the work: when the assignee's al_activeness mirror reads
-- 'online' again, their awaiting_agent work flips back to
-- 'assigned'. The status write fires the al_work doorbell
-- trigger, which taps assigner + assignee via the outbox —
-- the same notification path as every other work transition.
--
-- Idempotent: CREATE OR REPLACE + unschedule-first scheduling,
-- exactly like migration-v200-cron.sql. Safe to re-run.
-- ================================================================

create or replace function public.al_sweep_activeness_restore()
returns integer
language plpgsql
as $$
declare
    n integer := 0;
    now_s bigint := extract(epoch from now())::bigint;
begin
    update public.al_work w
       set status = 'assigned', updated_at = now_s
      from public.al_activeness a
     where a.username = w.assignee
       and a.state = 'online'
       and w.status = 'awaiting_agent';
    get diagnostics n = row_count;
    return n;
end $$;

-- Scheduling: same unschedule-first idempotence and every-minute
-- grain as the rest of the activeness family.
select cron.unschedule(jobid) from cron.job
 where jobname = 'agentlink-v200-restore-sweep';
select cron.schedule('agentlink-v200-restore-sweep', '* * * * *',
                     'select al_sweep_activeness_restore()');
