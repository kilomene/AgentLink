-- migration-v205-activeness-sweep.sql
--
-- Owner catch, 2026-11-06: the dashboard showed @phoenix OFFLINE
-- while the agent was live and beating (RTDB presence fresh to
-- ~1s). One of the two falsifications was this sweep.
--
-- al_sweep_activeness (migration-v200-cron.sql) ages EVERY
-- al_activeness row by greatest(beat_at, last_seen) against the
-- hyper-sensitive ladder (suspect >10s, offline >15s). That
-- ladder is calibrated for a 5-second heartbeat written into
-- Postgres — the relay era's signal. Serverless (transport
-- 'rtdb') agents beat into Firebase by design; their Postgres
-- timestamps advance only when the client re-asserts its mirror,
-- which 2.0.4 does once per 60s slow-sync cadence while online.
-- Against a 15s ladder the old sweep stamped every live
-- serverless agent 'offline' about a minute after login, and
-- the row never recovered (no further transitions occur while
-- steadily online).
--
-- The fix is transport-aware aging, one truth per transport:
--   * 'rtdb' rows: suspect after 100s without a re-assertion,
--     offline after 170s (~2 missed cadences + slack). A dead
--     serverless agent stops re-asserting and still ages out;
--     the reassignment/deadline sweeps keep consuming these
--     transitions for work protection.
--   * all other rows (relay-era semantics): unchanged, 10s/15s.
--
-- The display ladder is NOT touched: the dashboard reads RTDB
-- presence directly at 5s/10s/15s. This sweep governs only the
-- Postgres mirror and the work-protection consumers.

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
               a.state,
               case when a.transport = 'rtdb' then 170 else 15 end
                   as offline_after,
               case when a.transport = 'rtdb' then 100 else 10 end
                   as suspect_after
          from public.al_activeness a
          left join public.al_users u on u.username = a.username
    ),
    targets as (
        select username,
               case when now_s - beat > offline_after then 'offline'
                    when now_s - beat > suspect_after then 'suspect'
               end as next_state
          from aged
         where beat > 0
           and ((now_s - beat > offline_after and state <> 'offline')
                or (now_s - beat > suspect_after and state = 'online'))
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
