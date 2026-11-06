-- AgentLink v2.0 — pg_cron sweeps + doorbell outbox + activeness
-- layer + quota watchdog (Phase 1).
--
-- APPLY ORDER: migration-v200-rls.sql FIRST (it defines the JWT /
-- membership helpers this file's activeness policies call), then
-- this file.
--
-- SCOPE: purely additive. The v1.x sweeps in schema.sql
-- (al_sweep_offline / al_sweep_deadlines / al_sweep_reassignment
-- and their three cron jobs) are NOT touched, renamed or
-- rescheduled by this file. The v2 sweeps below run alongside
-- them during transition and read the v2 activeness truth.
--
-- THE DOORBELL RULE (V2-BLUEPRINT.md): database triggers/webhooks
-- fire ONLY on low-volume control tables — work assignments and
-- alerts — and tap the Firebase doorbell via an Edge function.
-- NEVER on the message tables. Accordingly the triggers below sit
-- on al_work and al_alerts ONLY. al_queue and al_audit_log get NO
-- trigger here: messages wake peers through the sender's own RTDB
-- signal write, and the queue/journal remain the re-offer truth.
--
-- HOW THE TAP FLOWS: a trigger inserts a row into
-- al_doorbell_outbox (this file). The doorbell Edge function (a
-- later phase) polls/claims untapped rows with the service role,
-- writes the agent's Firebase signal node, and marks the row
-- tapped. Postgres itself never calls Firebase. A lost tap is
-- harmless: agents slow-sync unacked work/alerts directly.
--
-- IDEMPOTENT: create-if-not-exists table/index, create-or-replace
-- functions, drop-trigger-if-exists before each trigger, and
-- unschedule-first before each cron.schedule. Re-running is safe.
-- Nothing is applied to production by this file existing.

create extension if not exists pg_cron;

-- ------------------------------------------------- doorbell outbox
create table if not exists al_doorbell_outbox (
    id text primary key,                -- 'db-' + random hex
    username text not null,             -- agent whose doorbell to tap
    ref text not null default '',       -- conversation ref: work id, group id, or alert id
    kind text not null default '',      -- work_assigned | work_status | work_deadline | work_awaiting | alert
    ts bigint not null default 0,       -- epoch seconds the event was flagged
    tapped boolean not null default false
);
create index if not exists al_doorbell_outbox_pending_idx
    on al_doorbell_outbox (username, tapped, ts);
create index if not exists al_doorbell_outbox_tapped_idx
    on al_doorbell_outbox (tapped, ts);

-- SERVICE-ONLY: al_doorbell_outbox — no authenticated policies (service role / Edge only).
-- The outbox is control-plane plumbing: agents must never read
-- each other's pending taps or forge a tap for someone else.
alter table public.al_doorbell_outbox enable row level security;
revoke all on table public.al_doorbell_outbox from anon, authenticated;

-- ------------------------------------------------------ trigger core
-- One trigger function for both control tables. It only ever
-- APPENDS outbox rows; it never touches the source row.
create or replace function public.al_doorbell_flag()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
    now_s bigint := extract(epoch from now())::bigint;
    new_id text := 'db-' || substr(md5(random()::text
                                       || clock_timestamp()::text), 1, 16);
begin
    if tg_table_name = 'al_work' then
        if tg_op = 'INSERT' then
            insert into public.al_doorbell_outbox
                (id, username, ref, kind, ts)
            values (new_id, new.assignee,
                    coalesce(nullif(new.group_id, ''), new.id),
                    'work_assigned', now_s);
        elsif tg_op = 'UPDATE'
              and (new.status is distinct from old.status
                   or new.assignee is distinct from old.assignee) then
            -- Status moved (or the row was reassigned): tap BOTH
            -- parties. A doorbell tap is only a wake-up signal —
            -- an extra tap costs one wasted fetch, a missed tap
            -- costs latency until the slow-sync catches it.
            insert into public.al_doorbell_outbox
                (id, username, ref, kind, ts)
            values (new_id, new.assignee,
                    coalesce(nullif(new.group_id, ''), new.id),
                    'work_status', now_s);
            if new.assigner <> new.assignee then
                insert into public.al_doorbell_outbox
                    (id, username, ref, kind, ts)
                values ('db-' || substr(md5(random()::text
                                       || clock_timestamp()::text), 1, 16),
                        new.assigner,
                        coalesce(nullif(new.group_id, ''), new.id),
                        'work_status', now_s);
            end if;
        end if;
    elsif tg_table_name = 'al_alerts' then
        -- Only agent-subject alerts tap a doorbell. System alerts
        -- (e.g. the quota watchdog's, whose subject is 'quota:<leg>')
        -- must never enqueue a tap for a non-existent username.
        if tg_op = 'INSERT' and new.subject <> ''
           and exists (select 1 from public.al_users u
                       where u.username = new.subject) then
            insert into public.al_doorbell_outbox
                (id, username, ref, kind, ts)
            values (new_id, new.subject, new.id, 'alert', now_s);
        end if;
    end if;
    return new;
end $$;

-- CONTROL TABLES ONLY (see the doorbell rule in the header):
drop trigger if exists al_doorbell_work_trg on public.al_work;
create trigger al_doorbell_work_trg
    after insert or update of status, assignee on public.al_work
    for each row execute function public.al_doorbell_flag();

drop trigger if exists al_doorbell_alerts_trg on public.al_alerts;
create trigger al_doorbell_alerts_trg
    after insert on public.al_alerts
    for each row execute function public.al_doorbell_flag();

-- ------------------------------------------- doorbell control sweep
-- Placeholder scanner for the Edge tapper: reports how many taps
-- are still untapped and older than the staleness window (taps the
-- tapper has presumably missed). It changes nothing itself — the
-- Edge function owns claiming, tapping Firebase and marking rows
-- tapped, all with the service role. Kept as a scheduled function
-- so the staleness number exists in cron.job_run_details from day
-- one and the tapper's contract is pinned in the schema.
create or replace function public.al_sweep_doorbell_outbox(
    p_stale_seconds integer default 120)
returns integer
language plpgsql
as $$
declare
    n integer := 0;
    now_s bigint := extract(epoch from now())::bigint;
begin
    select count(*) into n
      from public.al_doorbell_outbox
     where tapped = false
       and ts > 0
       and now_s - ts > p_stale_seconds;
    return n;
end $$;

-- ------------------------------------- presence backup staleness
-- Firebase RTDB presence is the live truth in v2.0 (connection +
-- onDisconnect). Supabase al_users.last_seen is the BACKUP record,
-- written at login/logout by the Edge login function — so this
-- sweep must NEVER write last_seen: stamping it here would
-- resurrect offline agents in the backup record and corrupt the
-- fallback. Its job is assessment only: count agents whose backup
-- record is stale, so the fleet's backup freshness is observable
-- alongside the existing (untouched) al_sweep_offline alerting.
create or replace function public.al_sweep_presence_backup(
    p_stale_seconds integer default 900)
returns integer
language plpgsql
as $$
declare
    n integer := 0;
    now_s bigint := extract(epoch from now())::bigint;
begin
    select count(*) into n
      from public.al_users
     where last_seen > 0
       and now_s - last_seen > p_stale_seconds;
    return n;
end $$;

-- ------------------------------------------------------- scheduling
-- Unschedule-first: re-running this file replaces the v2 jobs
-- instead of stacking duplicates. (A select over cron.job calls
-- unschedule only for jobs that actually exist.)
select cron.unschedule(jobid) from cron.job
 where jobname = 'agentlink-v200-doorbell-sweep';
select cron.schedule('agentlink-v200-doorbell-sweep', '* * * * *',
                     'select al_sweep_doorbell_outbox()');

select cron.unschedule(jobid) from cron.job
 where jobname = 'agentlink-v200-presence-backup-sweep';
select cron.schedule('agentlink-v200-presence-backup-sweep', '*/5 * * * *',
                     'select al_sweep_presence_backup()');

-- ================================================================
-- ACTIVENESS LAYER (owner escalation 2026-11-05 ~09:42 PST)
--
-- HYPER-SENSITIVE ACTIVENESS — AgentLink's ORIGINAL timing law,
-- transplanted onto Firebase. The thresholds are LAW, not tuning:
--   BEAT 5s     — the client beats its own RTDB presence node
--                 every 5 seconds.
--   SUSPECT >10s — beat age over 10s = 2 missed beats = suspect.
--   OFFLINE >15s — beat age over 15s = 3 missed beats = offline,
--                 OR instantly when onDisconnect fires, whichever
--                 comes first.
-- These numbers are NEVER loosened to save quota. If the RTDB
-- download projection threatens the free tier, the answer is the
-- fan-out batching valve documented at the quota watchdog below
-- (own-node beats stay 5s; peer fan-out is coalesced), never a
-- slower beat.
--
-- al_activeness is the Postgres MIRROR of that truth — the record
-- the pg_cron sweeps evaluate. It is TRANSITION-ONLY: clients and
-- the Edge presence bridge write a row ONLY when the state changes
-- (login -> online, observed staleness -> suspect, disconnect or
-- confirmed staleness -> offline, return -> online). NOBODY writes
-- this table per beat: the 5s beats live and die in Firebase, and
-- beat_at here means "the beat clock as last mirrored at a
-- transition", cross-checked by the sweeps against the
-- al_users.last_seen backup (login/logout writes, Edge-maintained).
-- A live agent whose mirror goes stale is flipped suspect/offline
-- by the sweep and flips itself back to online with its next
-- transition write — hyper-sensitive and self-correcting by design.
-- ================================================================
create table if not exists public.al_activeness (
    username text primary key,
    state text not null default 'offline',  -- online | suspect | offline
    beat_at bigint not null default 0,      -- beat clock at last transition (epoch s)
    connected_at bigint not null default 0, -- start of the current connection (epoch s)
    client_version text not null default '',
    transport text not null default '',     -- rtdb | slow-sync | relay (transition era)
    updated_at bigint not null default 0    -- when this row last transitioned (epoch s)
);
create index if not exists al_activeness_state_idx
    on public.al_activeness (state, updated_at);

comment on table public.al_activeness is
    'TRANSITION-ONLY activeness mirror (v2.0): written only on state transitions (login/suspect/offline/return), never per beat. Ladder: BEAT 5s, SUSPECT >10s, OFFLINE >15s or onDisconnect.';

-- RLS for the mirror (helpers come from migration-v200-rls.sql):
-- I read and write my own row; I may READ the rows of agents I
-- share a group or channel with (presence visibility inside my
-- circle — the same scope as al_connections); the service role
-- (Edge presence bridge, sweeps) bypasses RLS and sees all.
alter table public.al_activeness enable row level security;
revoke all on table public.al_activeness from anon, authenticated;
grant select, insert, update on table public.al_activeness to authenticated;

drop policy if exists al_activeness_select_circle on public.al_activeness;
create policy al_activeness_select_circle on public.al_activeness
    for select to authenticated
    using (username = public.al_jwt_username()
           or public.al_shares_group_with(username));

drop policy if exists al_activeness_insert_own on public.al_activeness;
create policy al_activeness_insert_own on public.al_activeness
    for insert to authenticated
    with check (username = public.al_jwt_username());

drop policy if exists al_activeness_update_own on public.al_activeness;
create policy al_activeness_update_own on public.al_activeness
    for update to authenticated
    using (username = public.al_jwt_username())
    with check (username = public.al_jwt_username());

-- ------------------------------------------------ activeness sweeps
-- (a) Staleness evaluation, every minute. Effective beat clock =
-- greatest(mirrored beat_at, last_seen backup). Transitions:
--   age > 15 and state <> 'offline'  -> offline   (OFFLINE >15s)
--   age > 10 and state = 'online'    -> suspect   (SUSPECT >10s)
-- Instant-offline on onDisconnect does NOT wait for this sweep:
-- the Edge presence bridge writes state='offline' the moment the
-- disconnect event lands (a transition write on the row above).
-- Only rows whose state actually changes are touched, and the
-- return value is the number of transitions made.
create or replace function public.al_sweep_activeness()
returns integer
language plpgsql
as $$
declare
    n integer := 0;
    m integer := 0;
    now_s bigint := extract(epoch from now())::bigint;
begin
    with aged as (
        select a.username,
               greatest(a.beat_at, coalesce(u.last_seen, 0)) as beat,
               a.state
          from public.al_activeness a
          left join public.al_users u on u.username = a.username
    ),
    targets as (
        select username,
               case when now_s - beat > 15 then 'offline'
                    when now_s - beat > 10 then 'suspect'
               end as next_state
          from aged
         where beat > 0
           and ((now_s - beat > 15 and state <> 'offline')
                or (now_s - beat > 10 and state = 'online'))
    )
    update public.al_activeness a
       set state = t.next_state, updated_at = now_s
      from targets t
     where a.username = t.username;
    get diagnostics n = row_count;

    -- Control outcome: a suspect/offline transition for an agent
    -- holding open work is exactly what the reassignment and
    -- deadline sweeps below consume; they run on the same minute
    -- and write the doorbell taps. No tap is written here for the
    -- stale agent itself — tapping an offline agent's doorbell is
    -- wasted Edge quota by construction.
    return n;
end $$;

-- (b1) Deadline pressure, driven off the same activeness truth:
-- overdue open work escalates to urgent (the v1.x fact), and the
-- escalation is a control outcome, so each escalated row writes a
-- doorbell tap for its assignee directly into the outbox (the
-- al_work doorbell trigger watches status/assignee changes, not
-- priority, so this sweep taps explicitly).
create or replace function public.al_sweep_activeness_deadlines()
returns integer
language plpgsql
as $$
declare
    n integer := 0;
    r record;
    now_s bigint := extract(epoch from now())::bigint;
begin
    for r in
        select id, assignee, group_id from public.al_work
         where deadline is not null and deadline < now_s
           and status in ('assigned', 'in_progress', 'changes_requested')
           and priority <> 'urgent'
    loop
        update public.al_work
           set priority = 'urgent', updated_at = now_s
         where id = r.id;
        insert into public.al_doorbell_outbox (id, username, ref, kind, ts)
        values ('db-' || substr(md5(random()::text
                               || clock_timestamp()::text
                               || r.id), 1, 16),
                r.assignee,
                coalesce(nullif(r.group_id, ''), r.id),
                'work_deadline', now_s);
        n := n + 1;
    end loop;
    return n;
end $$;

-- (b2) Dead-agent reassignment EVALUATION, driven off the
-- activeness truth: work is flagged awaiting_agent only when the
-- assignee is CONFIRMED offline in al_activeness AND the v1.x
-- reassignment grace — 30s after confirmed offline — has elapsed
-- (activeness.updated_at is the moment the row transitioned to
-- offline). The flag write fires the al_work doorbell trigger,
-- which taps assigner + assignee via the outbox.
-- BOUNDARY (documented): this sweep EVALUATES and FLAGS only. The
-- encrypted handoff itself — group-key copy, checkpoint travel,
-- candidate selection — stays a client/Edge concern, exactly as
-- in the relay era; no ciphertext moves inside Postgres.
create or replace function public.al_sweep_activeness_reassignment(
    p_grace_seconds integer default 30)
returns integer
language plpgsql
as $$
declare
    n integer := 0;
    now_s bigint := extract(epoch from now())::bigint;
begin
    update public.al_work w
       set status = 'awaiting_agent', updated_at = now_s
      from public.al_activeness a
     where a.username = w.assignee
       and a.state = 'offline'
       and a.updated_at > 0
       and now_s - a.updated_at >= p_grace_seconds
       and w.status in ('assigned', 'in_progress')
       and w.auto_reassign = 1;
    get diagnostics n = row_count;
    return n;
end $$;

-- ================================================================
-- QUOTA WATCHDOG (owner refinement 2026-11-05 ~09:41 PST)
--
-- Budgets are ROWS, seeded below; the watchdog warns at 80% of a
-- leg's monthly budget (warn_fraction per row). ALERT ONLY: the
-- watchdog inserts an al_alerts row (kind 'quota') and NEVER
-- blocks, throttles or drops traffic.
--
-- WHAT IS MEASURED vs MODELED — stated honestly:
--   * Edge leg: MEASURED proxy. The doorbell outbox rows written
--     this month are counted directly (one outbox row = one Edge
--     doorbell tap, plus login/oversight/file-sign invocations
--     that Postgres cannot see — so this leg UNDERCOUNTS Edge and
--     is a floor, not a meter).
--   * RTDB leg: MODELED, listener-weighted. Postgres never sees a
--     beat. The projection is beats/agent/month (518,400 at the
--     BEAT 5s law on a 30-day month) x fleet size (measured from
--     al_users) x delivered-event bytes (128 B: the presence node
--     {"beat_at","connected_at","client_version","transport",
--     "state"} measures 109 B as compact JSON; 128 B adds key /
--     framing margin) x listener weight (1 dashboard, which reads
--     the whole fleet raw, + the average scoped circle size,
--     measured from group/channel co-membership), divided by the
--     fan-out BATCHING VALVE divisor.
--   * Supabase egress leg: MEASURED proxy. Bytes of queue payloads
--     + audit content envelopes written this month. Undercounts
--     (row reads are not metered here) — a floor again.
--
-- THE BATCHING VALVE (the design answer when the raw projection
-- threatens the tier — the 5/10/15 law itself never moves):
-- own-node beats stay 5s and are consumed raw by the owner, the
-- activeness evaluation and the dashboard. PEER fan-out is
-- coalesced: peers subscribe to a per-user presence DIGEST node
-- that republishes the beat summary at most once per coalesce
-- window (30s below = divisor 6; 60s = divisor 12), and peers
-- subscribe ONLY to their circle (shared group/channel members),
-- never fleet-wide. At 30 agents the raw scoped projection
-- (avg circle 10) is ~19.9 GB/mo — 2x OVER the 10 GB tier; with
-- the valve it is ~5.3 GB/mo including the dashboard's raw read
-- (1.88x headroom). Full arithmetic: evidence note phase1-rls.md.
-- ================================================================
create table if not exists public.al_quota_budgets (
    leg text primary key,               -- edge_invocations | rtdb_download_bytes | supabase_egress_bytes | rtdb_coalesce_window_seconds
    monthly_budget numeric not null,
    unit text not null default '',
    warn_fraction numeric not null default 0.8,
    note text not null default ''
);

-- SERVICE-ONLY: al_quota_budgets — no authenticated policies (service role / Edge only).
alter table public.al_quota_budgets enable row level security;
revoke all on table public.al_quota_budgets from anon, authenticated;

insert into public.al_quota_budgets (leg, monthly_budget, unit, warn_fraction, note)
values
    ('edge_invocations', 500000, 'invocations', 0.8,
     'Supabase Edge free tier. Watchdog counts doorbell outbox rows this month (floor proxy).'),
    ('rtdb_download_bytes', 10000000000, 'bytes', 0.8,
     'Firebase RTDB free tier 10 GB downloaded. Watchdog uses the listener-weighted projection (modeled).'),
    ('supabase_egress_bytes', 5000000000, 'bytes', 0.8,
     'Supabase free tier 5 GB egress. Watchdog sums queue payload + audit envelope bytes this month (floor proxy).'),
    ('rtdb_coalesce_window_seconds', 30, 'seconds', 0.8,
     'Fan-out batching valve: peer presence digests republish at most once per this window; own-node beats stay 5s.')
on conflict (leg) do nothing;

create or replace function public.al_quota_watchdog()
returns integer
language plpgsql
as $$
declare
    raised integer := 0;
    now_s bigint := extract(epoch from now())::bigint;
    month_start bigint := extract(epoch from date_trunc('month', now()))::bigint;
    fleet integer := 0;
    avg_circle numeric := 0;
    edge_used numeric := 0;
    egress_used numeric := 0;
    rtdb_projected numeric := 0;
    beats_per_agent constant numeric := 518400;   -- 30 days at BEAT 5s
    event_bytes constant numeric := 128;          -- 109 B measured node + margin
    coalesce_seconds numeric := 30;
    b record;
    used numeric;
begin
    select count(*) into fleet from public.al_users;

    -- Average scoped circle: distinct co-members per agent across
    -- groups + channels (agents with no memberships count as 0 in
    -- spirit; the average is taken over members, which keeps the
    -- projection conservative — documented approximation).
    select coalesce(avg(c.cnt), 0) into avg_circle
      from (select mine.username as username,
                   count(distinct theirs.username) as cnt
              from (select group_id as gid, username
                      from public.al_group_members
                    union all
                    select channel_id as gid, username
                      from public.al_channel_members) mine
              join (select group_id as gid, username
                      from public.al_group_members
                    union all
                    select channel_id as gid, username
                      from public.al_channel_members) theirs
                on theirs.gid = mine.gid
               and theirs.username <> mine.username
             group by mine.username) c;

    select coalesce(monthly_budget, 30) into coalesce_seconds
      from public.al_quota_budgets
     where leg = 'rtdb_coalesce_window_seconds';

    -- Edge leg (measured floor): doorbell taps queued this month.
    select count(*) into edge_used
      from public.al_doorbell_outbox where ts >= month_start;

    -- RTDB leg (modeled): fleet beats x event bytes x listeners
    -- (dashboard 1 + average circle), batching valve applied.
    rtdb_projected := beats_per_agent * fleet * event_bytes
                      * (1 + avg_circle)
                      / greatest(coalesce_seconds / 5, 1);

    -- Egress leg (measured floor): payload + envelope bytes that
    -- Postgres wrote this month.
    select coalesce(sum(octet_length(payload::text)), 0) into egress_used
      from public.al_queue where ts >= month_start;
    select egress_used + coalesce(sum(octet_length(content_envelope)), 0)
      into egress_used
      from public.al_audit_log where ts >= month_start;

    for b in
        select leg, monthly_budget, warn_fraction
          from public.al_quota_budgets
         where leg in ('edge_invocations', 'rtdb_download_bytes',
                       'supabase_egress_bytes')
    loop
        used := case b.leg
                    when 'edge_invocations' then edge_used
                    when 'rtdb_download_bytes' then rtdb_projected
                    else egress_used
                end;
        if b.monthly_budget > 0
           and used >= b.monthly_budget * b.warn_fraction then
            -- One open alert per leg per month: no alert spam.
            if not exists (select 1 from public.al_alerts
                            where kind = 'quota'
                              and subject = 'quota:' || b.leg
                              and status = 'open'
                              and created_at >= month_start) then
                insert into public.al_alerts
                    (id, kind, subject, detail, created_at)
                values ('q-' || substr(md5(random()::text
                                       || b.leg), 1, 12),
                        'quota', 'quota:' || b.leg,
                        'projected/measured ' || round(used)::text
                        || ' of ' || b.monthly_budget::text
                        || ' monthly budget (>= '
                        || round(b.warn_fraction * 100)::text
                        || '%%) — alert only, traffic never blocked',
                        now_s);
                raised := raised + 1;
            end if;
        end if;
    end loop;
    return raised;
end $$;

-- ------------------------------------------- activeness scheduling
-- Same unschedule-first idempotence as the doorbell jobs above.
-- All activeness/control sweeps run every minute (the sweep grain
-- matches the v1.x sweeps; the 5/10/15 ladder itself is evaluated
-- from beat ages, not from the sweep cadence). The watchdog runs
-- every 15 minutes — quota moves slowly and alerts dedupe monthly.
select cron.unschedule(jobid) from cron.job
 where jobname = 'agentlink-v200-activeness-sweep';
select cron.schedule('agentlink-v200-activeness-sweep', '* * * * *',
                     'select al_sweep_activeness()');

select cron.unschedule(jobid) from cron.job
 where jobname = 'agentlink-v200-deadline-sweep';
select cron.schedule('agentlink-v200-deadline-sweep', '* * * * *',
                     'select al_sweep_activeness_deadlines()');

select cron.unschedule(jobid) from cron.job
 where jobname = 'agentlink-v200-reassignment-sweep';
select cron.schedule('agentlink-v200-reassignment-sweep', '* * * * *',
                     'select al_sweep_activeness_reassignment()');

select cron.unschedule(jobid) from cron.job
 where jobname = 'agentlink-v200-quota-watchdog';
select cron.schedule('agentlink-v200-quota-watchdog', '*/15 * * * *',
                     'select al_quota_watchdog()');
