-- ================================================================
-- AgentLink v2.3.0 — migration v211: the activeness mirror retires
--
-- WHY: 2.3.0 presence is connection-based and lives in Firebase
-- ONLY (owner-ratified 2026-11-09; DESIGN-DECISIONS D1/D2). The
-- 2.3.0 client writes NO Postgres activeness rows: the mirror
-- upsert, the presence backup and the 60s re-assertion are deleted
-- from the transport. Left as-is, the v205 sweep
-- (al_sweep_activeness) would age the frozen pre-2.3.0 rows
-- against greatest(beat_at, last_seen) and stamp 'offline' over
-- them — harmless for display (the dashboard reads RTDB) but the
-- Postgres consumers of the mirror would be reading a clock
-- nobody winds:
--
--   * al_sweep_activeness_reassignment (v200-cron): parks open
--     work 'awaiting_agent' when the assignee is CONFIRMED
--     offline in al_activeness (+30s grace).
--   * al_sweep_activeness_restore (v203): flips parked work back
--     to 'assigned' when the mirror reads 'online' again.
--   * agentlink-account /directory: completes each row with a
--     coarse `online` hint from al_activeness.state.
--   * agentlink-work chain member-pick: prefers a member whose
--     mirror beat is <= 60s old.
--   * dashboard: activenessMirror is a display FLOOR only
--     (RTDB node missing + fresh mirror 'online' -> suspect,
--     never online).
--
-- WHAT THIS MIGRATION DOES — no new writers, no new tables, the
-- login Edge becomes the only activeness event in Postgres,
-- exactly as the ratified design states ("login Edge
-- (event-only)"):
--
--   1. al_activeness rows are maintained by a trigger on
--      al_users.last_seen. The login Edge stamps last_seen on
--      EVERY successful ceremony (register, key login, recovery,
--      rectify — every patchRows site in agentlink-login). The
--      trigger upserts the mirror row: state 'online',
--      beat_at = last_seen, updated_at = last_seen,
--      transport 'rtdb'. Rows therefore mean "this agent has
--      authenticated against this backend" with the timestamp of
--      its last authentication — a LOGIN record, never a liveness
--      claim. Liveness lives in RTDB and nowhere else.
--
--   2. al_sweep_activeness() is replaced by a NO-OP. Aging a
--      login record against a beat ladder manufactures false
--      offline transitions for steadily-online agents (the exact
--      falsification v205 was written to fix, one layer down).
--      The cron job keeps its schedule and now costs one no-op
--      call per minute; the function remains for inventory
--      compatibility.
--
--   3. al_sweep_activeness_reassignment() now derives confirmed
--      offline from the SAME clock the ratified ladder uses:
--      an assignee is confirmed offline when their last
--      authentication (al_users.last_seen) is older than
--      SUSPECT_MAX_AGE_S (420s — two missed 180s beats + grace),
--      and the 30s reassignment grace runs from that moment:
--      now - last_seen >= 420 + grace. An assignee with NO
--      al_users row (deregistered) is treated as last_seen = 0
--      (confirmed offline), preserving the old behavior for
--      removed agents. The encrypted handoff itself stays a
--      client/Edge concern, as before.
--
--   4. al_sweep_activeness_restore() now derives "the assignee
--      is back" from a FRESH authentication: last_seen within
--      ONLINE_MAX_AGE_S (240s — one beat + grace) flips their
--      awaiting_agent work back to 'assigned'. The status write
--      fires the al_work doorbell trigger exactly as before.
--
--   5. Consumers left deliberately untouched, with the new
--      meaning of the row documented:
--      - /directory `online` hint: now reads "has authenticated
--        (login record present, state online)". It is a coarse
--        sort/presentation hint only; the authoritative presence
--        is the RTDB ladder (dashboard + client). Tightening it
--        would require the Edge to read RTDB per request — a
--        per-request live-layer read on the record layer's hot
--        path, against the split's whole point.
--      - work member-pick (<= 60s beat): beat_at is now the last
--        authentication; the check reads "authenticated within
--        the last minute", a sane freshness preference for chain
--        assignment, with the first-member fallback unchanged.
--      - dashboard mirror floor: presence.js now ALSO requires
--        the mirror row to be fresh (updated_at within
--        ONLINE_MAX_AGE_S) before it may lift a missing RTDB
--        node from offline to suspect — a stale login record can
--        no longer resurrect a dead agent's display state.
--
-- The ladder constants below (240 / 420) mirror
-- agentlink/doorbell.py ONLINE_MAX_AGE_S / SUSPECT_MAX_AGE_S and
-- dashboard-v2/js/activeness.js — same numbers, same names, one
-- law in three places, as those files already demand of each
-- other.
--
-- Idempotent: CREATE OR REPLACE + trigger drop-first. Safe to
-- re-run. Applied at SHIP time to the new production project
-- (after v201–v210), never to the restricted predecessor.
-- ================================================================

-- ------------------------------------------------ 1. login-event
-- maintenance of the mirror row.
create or replace function public.al_activeness_from_login()
returns trigger
language plpgsql
as $$
begin
    if new.last_seen is null or new.last_seen <= 0 then
        return new;
    end if;
    if tg_op = 'UPDATE'
       and old.last_seen is not distinct from new.last_seen then
        return new;
    end if;
    insert into public.al_activeness
        (username, state, beat_at, connected_at, client_version,
         transport, updated_at)
    values
        (new.username, 'online', new.last_seen, new.last_seen, '',
         'rtdb', new.last_seen)
    on conflict (username) do update
        set state = 'online',
            beat_at = excluded.beat_at,
            updated_at = excluded.updated_at,
            transport = 'rtdb'
        where excluded.beat_at > public.al_activeness.beat_at;
    return new;
end $$;

drop trigger if exists al_users_activeness_from_login
    on public.al_users;
create trigger al_users_activeness_from_login
    after insert or update of last_seen on public.al_users
    for each row execute function public.al_activeness_from_login();

comment on table public.al_activeness is
    'LOGIN RECORD (v211, 2.3.0): maintained ONLY by the al_users.last_seen trigger — one row per agent, state online at its last authentication (register/login/recovery/rectify via the login Edge). NOT a liveness signal: presence is connection-based in Firebase RTDB (180s beats, ladder 240/420). Consumers: work sweeps derive offline/return from al_users.last_seen against the 240/420 ladder; the dashboard uses the row as a freshness-gated display floor only.';

-- ------------------------------------------------ 2. the aging
-- sweep retires to a no-op.
create or replace function public.al_sweep_activeness()
returns integer
language plpgsql
as $$
begin
    -- RETIRED in v211 (2.3.0): al_activeness rows are login
    -- records (see the trigger above), not beat mirrors. Aging
    -- them against a ladder would stamp false 'offline'
    -- transitions over steadily-online agents. Confirmed-offline
    -- derivation lives in the reassignment sweep, computed from
    -- al_users.last_seen against SUSPECT_MAX_AGE_S (420).
    return 0;
end $$;

-- ------------------------------------------------ 3. reassignment:
-- confirmed offline derived from last authentication.
create or replace function public.al_sweep_activeness_reassignment(
    p_grace_seconds integer default 30)
returns integer
language plpgsql
as $$
declare
    n integer := 0;
    now_s bigint := extract(epoch from now())::bigint;
begin
    -- 2.3.0 (v211): the assignee is CONFIRMED offline when their
    -- last authentication is older than SUSPECT_MAX_AGE_S (420s:
    -- two missed 180s beats + grace — the ratified ladder's
    -- offline edge, measured on the only Postgres clock that
    -- still moves, al_users.last_seen) and the reassignment
    -- grace has elapsed past that moment. A missing al_users row
    -- (deregistered agent) coalesces to 0 = confirmed offline,
    -- as the mirror-based version behaved for removed agents.
    update public.al_work w
       set status = 'awaiting_agent', updated_at = now_s
      from (select distinct assignee from public.al_work
             where status in ('assigned', 'in_progress')
               and auto_reassign = 1) open_work
      left join public.al_users u
        on u.username = open_work.assignee
     where w.assignee = open_work.assignee
       and w.status in ('assigned', 'in_progress')
       and w.auto_reassign = 1
       and now_s - coalesce(u.last_seen, 0) >= 420 + p_grace_seconds;
    get diagnostics n = row_count;
    return n;
end $$;

-- ------------------------------------------------ 4. restore:
-- "back" derived from a fresh authentication.
create or replace function public.al_sweep_activeness_restore()
returns integer
language plpgsql
as $$
declare
    n integer := 0;
    now_s bigint := extract(epoch from now())::bigint;
begin
    -- 2.3.0 (v211): the assignee is back when they have
    -- authenticated within ONLINE_MAX_AGE_S (240s — one beat +
    -- grace on the ratified ladder). Same assignee, same
    -- attempt; the work was parked, never reassigned. The
    -- status write fires the al_work doorbell trigger, which
    -- taps assigner + assignee via the outbox.
    update public.al_work w
       set status = 'assigned', updated_at = now_s
      from public.al_users u
     where u.username = w.assignee
       and u.last_seen > 0
       and now_s - u.last_seen <= 240
       and w.status = 'awaiting_agent';
    get diagnostics n = row_count;
    return n;
end $$;
