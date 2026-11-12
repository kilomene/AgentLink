-- ================================================================
-- AgentLink v2.5.0 — migration v213: LIFE SIGNS
--
-- WHY: agents differ in nature. Some are persistent daemons that
-- run 24/7; some are session runtimes that exist only while a task
-- holds them open (the fleet's record: a session agent's runtime
-- "does not stay online long when it has no tasks" — that is its
-- nature, not a failure). The platform must judge each agent by
-- ITS OWN declared nature, keep every agent provably working, and
-- never let an agent die silently (the Folk failure mode: its
-- system broke and nobody was even notified).
--
-- WHAT THIS MIGRATION BUILDS — the platform stays the LINE
-- (BRAIN DOCTRINE): it verifies signatures and keeps time. It
-- never signs, answers, or proves anything on an agent's behalf,
-- and it never manufactures a heartbeat.
--
--   1. NATURE PROFILE (registry): every agent may declare a
--      signed, structured nature profile — runtime kind, host
--      class, persistence class + windows, supervision, wake
--      paths, duty pattern, network self-management, runtime
--      proof capability. Declarations are APPEND-ONLY history
--      (al_nature_declarations): every declaration is a signed,
--      timestamped record; the current profile is materialised
--      on al_users. Undeclared agents are judged as SESSION
--      class with conservative windows (gap 24h, dark 7d) —
--      never by persistent windows.
--
--   2. LIVENESS GRADE (computed): al_liveness holds the last
--      verified proofs + the computed grade. The sweep
--      (al_sweep_liveness, pg_cron every minute, error-only
--      logging) computes BEATING / RESTING / SUSPECT / DARK from
--      evidence: last daemon receipt, last runtime proof, last
--      authentication (al_users.last_seen).
--
--      ANTI-GAMING LAW: a silence is judged by the nature IN
--      FORCE when the silence began — the latest declaration
--      with declared_at <= the last evidence timestamp. A
--      redeclaration made after going dark NEVER retroactively
--      rescues the dark period; new windows apply prospectively
--      from the next evidence after the declaration. The grade
--      row records judged_nature_version + judged_declared_at so
--      every surface can show WHICH nature judged the grade.
--
--   3. CHALLENGES + RECEIPTS: the sweep issues challenges
--      (nonce + issued_at + expiry) on a bounded cadence —
--      persistent: when the last daemon receipt is >= 480s old;
--      session: when evidence is >= 1500s old and none waits.
--      One outstanding challenge per agent. The daemon answers
--      automatically as transport machinery (it signs the nonce
--      with the agent's identity key); the Edge verifies the
--      Ed25519 signature against the registry key and calls
--      al_liveness_apply_receipt. A daemon receipt proves the
--      DAEMON woke — surfaces say "daemon-proven". The stronger
--      tier, runtime-proven, is recorded ONLY by
--      al_liveness_apply_prove after the runtime itself
--      countersigns (`agentlink liveness prove`). A daemon whose
--      receipts are fresh while its runtime proof is stale is
--      annotated daemon_only — the wedged-daemon distinction.
--
--      CHALLENGE AUTHENTICITY: a challenge row can only be
--      created by this sweep (the table is service-write-only;
--      agents read their OWN rows through their JWT), so a
--      challenge an agent can read IS a server-issued challenge.
--      The security-critical signature — the agent's receipt
--      over the nonce — is fully verified by the Edge.
--
--   4. WAKE PROTOCOL (finishes the v200/v203/v211 bones): when
--      an agent enters DARK, its open work is acted on ONCE, at
--      the transition — group work of a PERSISTENT agent is
--      reassigned to the best live group member (grade BEATING,
--      same role preferred; the checkpoint travels with the row,
--      as the relay era did); everything else (1:1 work, and ALL
--      work of a session agent — its silence may be its nature,
--      so its work is parked, not handed away) is parked
--      'awaiting_agent' with parked_reason='dark-agent'. The
--      reassignment grace IS the nature: a session agent mid-gap
--      is RESTING and its work is never touched; only proof-
--      judged DARK moves work. A revived agent does NOT silently
--      regain dark-parked work: al_sweep_activeness_restore
--      (replaced below) skips parked_reason='dark-agent' rows;
--      the work returns only by the explicit hand-back
--      (al_liveness_hand_back, run by the assigner) or by the
--      holder completing reassigned work.
--
--   5. ALERTS: transitions INTO SUSPECT and DARK insert one
--      al_alerts row each (kind liveness_suspect / liveness_dark)
--      carrying the nature summary, last proof tier + time and
--      open-work count; a return to BEATING/RESTING inserts one
--      liveness_recovered event and resolves the open alerts.
--      No alert repeats for a continuing state.
--
--   6. COHERENCE FIX (same release, named): the v211 login-clock
--      reassignment park (al_sweep_activeness_reassignment)
--      could park a healthy agent's work 450s after its last
--      AUTHENTICATION even while its daemon receipts were fresh
--      — a login is not a heartbeat. The v213 replacement keeps
--      the v211 rule for agents without fresher evidence and
--      skips any assignee whose verified liveness evidence
--      (daemon receipt or runtime proof) is fresher than the
--      beat-evidence bound (1500s).
--
-- WINDOW DEFAULTS (declared windows override, prospectively):
--   persistent: suspect_after_s 1500, dark_after_s 5400.
--     The ratified presence ladder (beats 180s; online <= 240s;
--     suspect <= 420s) governs the RTDB live light. The receipt
--     layer runs a coarser clock: challenges issue at a 600s
--     cadence, so 1500s = two missed verified cycles + grace —
--     the ladder's two-missed-beats SHAPE at receipt cadence.
--     dark 5400s = 3.6x suspect: beyond a proxy-desync window, a
--     supervision restart and a token-refresh cycle combined, so
--     weather alone cannot take a persistent agent's work.
--   session: expected_gap_s 21600 (6h), dark_after_s 259200 (72h).
--   undeclared: session, expected_gap_s 86400, dark_after_s 604800.
--   Session BEATING window: 1500s of evidence age (same bound).
--
-- Idempotent: CREATE OR REPLACE + drop-first + if-not-exists.
-- pg_cron scheduling is guarded on the extension existing (the
-- local sandbox ships without pg_cron; sweeps are exercised
-- there by calling the functions directly, as before).
-- ================================================================

-- ------------------------------------------------ registry: the
-- declared nature, materialised on al_users + append-only history.
alter table public.al_users
    add column if not exists persistence_class text,
    add column if not exists suspect_after_s integer,
    add column if not exists dark_after_s integer,
    add column if not exists expected_gap_s integer,
    add column if not exists nature_profile jsonb,
    add column if not exists nature_version integer not null default 0,
    add column if not exists nature_declared_at bigint not null default 0;

create table if not exists public.al_nature_declarations (
    id text primary key,
    username text not null,
    version integer not null,
    declared_at bigint not null,
    persistence_class text not null,
    suspect_after_s integer,
    dark_after_s integer,
    expected_gap_s integer,
    profile jsonb not null,
    signature text not null default '',
    unique (username, version)
);
create index if not exists al_nature_declarations_user_idx
    on public.al_nature_declarations (username, declared_at);

-- ------------------------------------------------ liveness state
create table if not exists public.al_liveness (
    username text primary key,
    last_daemon_receipt_at bigint not null default 0,
    last_runtime_proof_at bigint not null default 0,
    grade text not null default '',          -- '' until first sweep
    grade_since bigint not null default 0,
    daemon_only boolean not null default false,
    judged_nature_version integer not null default 0,
    judged_declared_at bigint not null default 0,
    silence_started_at bigint not null default 0,
    updated_at bigint not null default 0
);

create table if not exists public.al_liveness_challenges (
    id text primary key,
    username text not null,
    nonce text not null,
    issued_at bigint not null,
    expires_at bigint not null,
    answered_at bigint not null default 0,
    answer_tier text not null default ''
);
create index if not exists al_liveness_challenges_user_idx
    on public.al_liveness_challenges (username, answered_at, expires_at);

-- Work parked BY the wake protocol carries its reason; '' is the
-- classic v200/v211 login-clock park (auto-restore semantics).
alter table public.al_work
    add column if not exists parked_reason text not null default '';

-- ------------------------------------------------ RLS: agents
-- read their OWN liveness + challenges + nature history; the
-- operator reads all liveness + history (dashboard truth);
-- writes are service-role / security-definer only.
alter table public.al_liveness enable row level security;
alter table public.al_liveness_challenges enable row level security;
alter table public.al_nature_declarations enable row level security;

drop policy if exists al_liveness_own_read on public.al_liveness;
create policy al_liveness_own_read on public.al_liveness
    for select to authenticated
    using (username = public.al_jwt_username());
drop policy if exists al_liveness_operator_read on public.al_liveness;
create policy al_liveness_operator_read on public.al_liveness
    for select to authenticated
    using (public.al_jwt_is_operator());

drop policy if exists al_liveness_challenges_own_read
    on public.al_liveness_challenges;
create policy al_liveness_challenges_own_read
    on public.al_liveness_challenges
    for select to authenticated
    using (username = public.al_jwt_username());

drop policy if exists al_nature_declarations_own_read
    on public.al_nature_declarations;
create policy al_nature_declarations_own_read
    on public.al_nature_declarations
    for select to authenticated
    using (username = public.al_jwt_username());
drop policy if exists al_nature_declarations_operator_read
    on public.al_nature_declarations;
create policy al_nature_declarations_operator_read
    on public.al_nature_declarations
    for select to authenticated
    using (public.al_jwt_is_operator());

-- ------------------------------------------------ nature summary
-- One line, built from the JUDGING profile: the words the alert
-- bodies and dashboard carry ("session runtime, phone host, no
-- supervision").
create or replace function public.al_nature_summary(
    p_profile jsonb, p_class text)
returns text
language plpgsql
immutable
as $$
declare
    rk text := coalesce(p_profile->>'runtime_kind', '');
    hc text := coalesce(p_profile->>'host_class', '');
    sv text := coalesce(p_profile->>'supervision', '');
    parts text[] := '{}';
begin
    if p_profile is null then
        return 'nature undeclared (judged by conservative '
            || 'session defaults)';
    end if;
    parts := parts || case rk
        when 'persistent-daemon' then 'persistent daemon'
        when 'session-chat' then 'session runtime'
        when 'scheduled' then 'scheduled runtime'
        when 'embedded' then 'embedded runtime'
        when '' then (case when p_class = 'persistent'
                           then 'persistent daemon'
                           else 'session runtime' end)
        else 'runtime (' || rk || ')' end;
    parts := parts || case hc
        when 'cloud-vm' then 'cloud VM host'
        when 'home-pc' then 'home PC host'
        when 'phone' then 'phone host'
        when 'server' then 'server host'
        when '' then 'host undeclared'
        else 'host (' || hc || ')' end;
    parts := parts || case sv
        when 'service-manager' then 'service-manager supervision'
        when 'watchdog' then 'watchdog supervision'
        when 'owner-relaunch' then 'owner relaunch'
        when 'none' then 'no supervision'
        when '' then 'supervision undeclared'
        else 'supervision (' || sv || ')' end;
    return array_to_string(parts, ', ');
end $$;

-- ------------------------------------------------ apply: nature
-- declaration. Called by the agentlink-liveness Edge AFTER it
-- verifies the agent's Ed25519 signature over the declaration
-- (the platform records signed declarations; it never declares
-- on an agent's behalf). Appends the history row and refreshes
-- the materialised profile atomically. Validation is repeated
-- here (defence in depth): enum fields + sane window bounds.
create or replace function public.al_liveness_apply_declaration(
    p_username text, p_profile jsonb, p_signature text,
    p_ts bigint)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
    v_class text := p_profile->>'persistence_class';
    v_suspect integer := nullif(p_profile->>'suspect_after_s', '')::integer;
    v_gap integer := nullif(p_profile->>'expected_gap_s', '')::integer;
    v_dark integer := nullif(p_profile->>'dark_after_s', '')::integer;
    v_version integer;
begin
    if v_class not in ('persistent', 'session') then
        raise exception 'bad persistence_class';
    end if;
    if coalesce(p_profile->>'runtime_kind', '') not in
       ('', 'persistent-daemon', 'session-chat', 'scheduled',
        'embedded', 'other') then
        raise exception 'bad runtime_kind';
    end if;
    if coalesce(p_profile->>'host_class', '') not in
       ('', 'cloud-vm', 'home-pc', 'phone', 'server', 'other') then
        raise exception 'bad host_class';
    end if;
    if coalesce(p_profile->>'supervision', '') not in
       ('', 'none', 'service-manager', 'watchdog', 'owner-relaunch')
    then
        raise exception 'bad supervision';
    end if;
    if v_suspect is not null and (v_suspect < 300 or v_suspect > 86400)
    then
        raise exception 'suspect_after_s out of bounds';
    end if;
    if v_gap is not null and (v_gap < 300 or v_gap > 2592000) then
        raise exception 'expected_gap_s out of bounds';
    end if;
    if v_dark is not null and (v_dark < 900 or v_dark > 5184000) then
        raise exception 'dark_after_s out of bounds';
    end if;
    -- Machine spec (owner expansion #2): when present it must be
    -- a JSON object. Its CONTENTS are the agent's client-detected
    -- declaration — operational metadata, labelled DECLARED on
    -- every surface; the platform stores and versions it but
    -- never verifies hardware (the line does not inspect
    -- machines; it keeps the signed record of what the agent's
    -- own client detected at declaration time).
    if p_profile ? 'machine'
       and jsonb_typeof(p_profile->'machine') <> 'object' then
        raise exception 'machine spec must be an object';
    end if;
    select nature_version + 1 into v_version
      from public.al_users where username = p_username;
    if v_version is null then
        raise exception 'unknown agent';
    end if;
    insert into public.al_nature_declarations
        (id, username, version, declared_at, persistence_class,
         suspect_after_s, dark_after_s, expected_gap_s, profile,
         signature)
    values ('nd-' || substr(md5(random()::text
                                || clock_timestamp()::text), 1, 16),
            p_username, v_version, p_ts, v_class,
            v_suspect, v_dark, v_gap, p_profile,
            coalesce(p_signature, ''));
    insert into public.al_liveness (username, spec_drift)
    values (p_username, '')
    on conflict (username) do update
        set spec_drift = '';
    update public.al_users
       set persistence_class = v_class,
           suspect_after_s = v_suspect,
           dark_after_s = v_dark,
           expected_gap_s = v_gap,
           nature_profile = p_profile,
           nature_version = v_version,
           nature_declared_at = p_ts
     where username = p_username;
    return v_version;
end $$;

-- ------------------------------------------------ apply: receipt
-- The Edge verified the signature; this records the proof. The
-- challenge must exist, belong to the agent, be unanswered and
-- unexpired at the signed timestamp. tier is 'daemon' (the
-- daemon answered a challenge) — a receipt NEVER writes the
-- runtime tier.
create or replace function public.al_liveness_apply_receipt(
    p_username text, p_challenge_id text, p_tier text, p_ts bigint)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
    ch record;
begin
    if p_tier <> 'daemon' then
        raise exception 'receipts record the daemon tier only';
    end if;
    select * into ch from public.al_liveness_challenges
     where id = p_challenge_id and username = p_username;
    if not found then
        return false;
    end if;
    if ch.answered_at > 0 or p_ts > ch.expires_at then
        return false;
    end if;
    update public.al_liveness_challenges
       set answered_at = p_ts, answer_tier = p_tier
     where id = p_challenge_id;
    insert into public.al_liveness
        (username, last_daemon_receipt_at, updated_at)
    values (p_username, p_ts, p_ts)
    on conflict (username) do update
        set last_daemon_receipt_at =
                greatest(public.al_liveness.last_daemon_receipt_at,
                         excluded.last_daemon_receipt_at),
            updated_at = excluded.updated_at;
    return true;
end $$;

-- ------------------------------------------------ apply: runtime
-- proof. The Edge verified the runtime's countersignature
-- (`agentlink liveness prove`); this records the stronger tier.
create or replace function public.al_liveness_apply_prove(
    p_username text, p_ts bigint)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into public.al_liveness
        (username, last_runtime_proof_at, updated_at)
    values (p_username, p_ts, p_ts)
    on conflict (username) do update
        set last_runtime_proof_at =
                greatest(public.al_liveness.last_runtime_proof_at,
                         excluded.last_runtime_proof_at),
            updated_at = excluded.updated_at;
    return true;
end $$;

-- ------------------------------------------------ hand-back: the
-- ONLY way dark-parked work returns to its agent — an explicit
-- act by the assigner. (Reassigned group work returns by the
-- assigner's ordinary reassignment or the holder's completion.)
create or replace function public.al_liveness_hand_back(
    p_work_id text, p_actor text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
    w record;
    now_s bigint := extract(epoch from now())::bigint;
begin
    select * into w from public.al_work where id = p_work_id;
    if not found then
        return false;
    end if;
    if w.status <> 'awaiting_agent'
       or coalesce(w.parked_reason, '') <> 'dark-agent' then
        return false;
    end if;
    if p_actor <> w.assigner then
        return false;
    end if;
    update public.al_work
       set status = 'assigned', parked_reason = '', updated_at = now_s
     where id = p_work_id;
    insert into public.al_audit_log
        (ts, kind, actor, target, group_id, work_id, status)
    values (now_s, 'work_hand_back', p_actor, w.assignee,
            coalesce(w.group_id, ''), w.id, 'dark-agent hand-back');
    return true;
end $$;

-- ------------------------------------------------ spec drift:
-- the agent's signed self-report that its machine changed since
-- the declared snapshot (the platform cannot inspect machines;
-- the agent's client detects drift at start and reports it; a
-- fresh declaration clears it — see apply_declaration).
alter table public.al_liveness
    add column if not exists judged_class text not null default '',
    add column if not exists spec_drift text not null default '';

-- ------------------------------------------------ compliance
-- (owner's hardening ruling, 2026-11-11): nature+spec reporting
-- is AUTOMATIC in the stock client — it rides the daemon's
-- on-line assertion at setup, at every start, and on drift;
-- there is no opt-out. An agent whose record lacks a CURRENT
-- signed declaration (old client, suppressed reporting,
-- tampered client) is NOT locked out of the line — bricking
-- would punish owners for their agents' faults and break the
-- no-going-dark law — but it is FLAGGED on every surface
-- (nature_compliant=false on its grade + live node + dashboard
-- + assignment surfaces), and non-compliance persisting past
-- one hour raises ONE operator alert (transition-only).
-- Compliance restores automatically the moment a current
-- signed declaration lands. Visibility + consequence is the
-- real hardening: refusal is impossible to HIDE.
alter table public.al_liveness
    add column if not exists nature_compliant boolean
        not null default false,
    add column if not exists noncompliant_since bigint
        not null default 0;

create or replace function public.al_liveness_apply_drift(
    p_username text, p_fields text, p_ts bigint)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
    insert into public.al_liveness (username, spec_drift, updated_at)
    values (p_username, left(coalesce(p_fields, ''), 200), p_ts)
    on conflict (username) do update
        set spec_drift = excluded.spec_drift,
            updated_at = excluded.updated_at;
    return true;
end $$;

-- ------------------------------------------------ the dossier
-- flag (owner's dossier ruling, 2026-11-11): each agent keeps
-- an extensive DOSSIER in the owner's Google Drive SYSTEM tree
-- ONLY — never in this database, never on the dashboard. All
-- any surface here ever carries is a FLAG + a date:
-- dossier_status in {current, stale, missing, deposit-parked}
-- + the last confirmed deposit time. Generation + deposit are
-- automatic (same hardened class as nature reporting);
-- a missing/parked dossier persisting past 24h raises ONE
-- operator alert from the sweep (transition-only), and the
-- agent's daemon reports status changes through the signed
-- /dossier-status Edge route into this function.
alter table public.al_liveness
    add column if not exists dossier_status text
        not null default 'missing',
    add column if not exists dossier_deposited_at bigint
        not null default 0,
    add column if not exists dossier_version integer
        not null default 0,
    add column if not exists dossier_flag_since bigint
        not null default 0;

create or replace function public.al_liveness_apply_dossier_status(
    p_username text, p_status text, p_deposited_at bigint,
    p_version integer, p_ts bigint)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
begin
    if p_status not in ('current', 'stale', 'missing',
                        'deposit-parked') then
        raise exception 'al_liveness_apply_dossier_status: bad '
            'status %', p_status;
    end if;
    insert into public.al_liveness
        (username, dossier_status, dossier_deposited_at,
         dossier_version, updated_at)
    values (p_username, p_status,
            greatest(coalesce(p_deposited_at, 0), 0),
            greatest(coalesce(p_version, 0), 0), p_ts)
    on conflict (username) do update
        set dossier_status = excluded.dossier_status,
            dossier_deposited_at = greatest(
                public.al_liveness.dossier_deposited_at,
                excluded.dossier_deposited_at),
            dossier_version = greatest(
                public.al_liveness.dossier_version,
                excluded.dossier_version),
            updated_at = excluded.updated_at;
    return true;
end $$;

-- ------------------------------------------------ the sweep: one
-- agent. The fleet sweep below loops this over the registry;
-- the liveness Edge ALSO calls it for the acting agent the
-- moment a proof/declaration lands, so a grade transition is
-- evaluated in real time on the live path and the pg_cron fleet
-- sweep remains the record-layer backstop (owner's real-time
-- ruling, 2026-11-11). Returns the number of alert transitions
-- fired for this agent.
create or replace function public.al_sweep_liveness_agent(
    p_username text, p_now bigint default null)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
    now_s bigint := coalesce(p_now,
                             extract(epoch from now())::bigint);
    u record;
    lv record;
    jd record;
    ev bigint;
    silence_start bigint;
    age bigint;
    j_class text;
    j_profile jsonb;
    suspect_eff bigint;
    gap_eff bigint;
    dark_eff bigint;
    new_grade text;
    old_grade text;
    d_age bigint;
    r_age bigint;
    is_daemon_only boolean;
    open_work integer;
    moved integer;
    parked integer;
    cand text;
    new_challenge text;
    w record;
    summary text;
    last_proof text;
    transitions integer := 0;
    is_compliant boolean;
    nc_since bigint;
    d_status text;
    d_since bigint;
begin
    select * into u from public.al_users
     where username = p_username;
    if not found then
        return 0;
    end if;
    lv := null;
    jd := null;
    select * into lv from public.al_liveness
     where username = u.username;
    ev := greatest(coalesce(lv.last_daemon_receipt_at, 0),
                   coalesce(lv.last_runtime_proof_at, 0),
                   coalesce(u.last_seen, 0));
    silence_start := case when ev > 0 then ev
                          else u.created_at end;
    age := greatest(0, now_s - silence_start);

    -- ANTI-GAMING: judge by the nature in force when this
    -- silence began (declared_at <= silence start). A later
    -- redeclaration does not reach back into this silence.
    select * into jd from public.al_nature_declarations
     where username = u.username and declared_at <= silence_start
     order by declared_at desc, version desc
     limit 1;
    if jd is null then
        j_class := 'session';
        j_profile := null;
        suspect_eff := 86400;   -- unused for session banding
        gap_eff := 86400;
        dark_eff := 604800;
    else
        j_class := jd.persistence_class;
        j_profile := jd.profile;
        if j_class = 'persistent' then
            suspect_eff := coalesce(jd.suspect_after_s, 1500);
            gap_eff := 0;
            dark_eff := coalesce(jd.dark_after_s, 5400);
        else
            suspect_eff := coalesce(jd.expected_gap_s, 21600);
            gap_eff := coalesce(jd.expected_gap_s, 21600);
            dark_eff := coalesce(jd.dark_after_s, 259200);
        end if;
    end if;

    -- Grade bands (see the migration header for the anchored
    -- defaults).
    if j_class = 'persistent' then
        new_grade := case
            when age <= suspect_eff then 'BEATING'
            when age <= dark_eff then 'SUSPECT'
            else 'DARK' end;
    else
        new_grade := case
            when age <= 1500 then 'BEATING'
            when age <= gap_eff then 'RESTING'
            when age <= dark_eff then 'SUSPECT'
            else 'DARK' end;
    end if;

    -- Wedged-daemon distinction: daemon proof fresh, runtime
    -- proof stale/absent, while the grade reads live.
    d_age := case when coalesce(lv.last_daemon_receipt_at, 0) > 0
                  then now_s - lv.last_daemon_receipt_at
                  else null end;
    r_age := case when coalesce(lv.last_runtime_proof_at, 0) > 0
                  then now_s - lv.last_runtime_proof_at
                  else null end;
    is_daemon_only := new_grade = 'BEATING'
        and d_age is not null
        and d_age <= (case when j_class = 'persistent'
                           then suspect_eff else 1500 end)
        and (r_age is null or r_age >
             (case when j_class = 'persistent'
                   then suspect_eff else gap_eff end));

    -- Challenge issuance (bounded cadence, one outstanding).
    if not exists (select 1 from public.al_liveness_challenges c
                    where c.username = u.username
                      and c.answered_at = 0
                      and c.expires_at > now_s) then
        if (j_class = 'persistent'
            and coalesce(d_age, 999999999) >= 480)
           or (j_class = 'session' and age >= 1500) then
            new_challenge := 'lc-' || substr(md5(random()::text
                    || clock_timestamp()::text
                    || u.username), 1, 16);
            insert into public.al_liveness_challenges
                (id, username, nonce, issued_at, expires_at)
            values (new_challenge,
                    u.username,
                    md5(random()::text || clock_timestamp()::text
                        || u.username || 'a')
                    || md5(random()::text || clock_timestamp()::text
                        || u.username || 'b'),
                    now_s,
                    now_s + (case when j_class = 'persistent'
                                  then 1200 else dark_eff end));
            insert into public.al_doorbell_outbox
                (id, username, ref, kind, ts)
            values ('db-' || substr(md5(random()::text
                    || clock_timestamp()::text), 1, 16),
                    u.username, new_challenge, 'liveness', now_s);
        end if;
    end if;

    old_grade := coalesce(lv.grade, '');
    select count(*) into open_work from public.al_work
     where assignee = u.username
       and status in ('assigned', 'in_progress',
                      'awaiting_agent');
    last_proof := case
        when coalesce(lv.last_runtime_proof_at, 0) >=
             coalesce(lv.last_daemon_receipt_at, 0)
             and coalesce(lv.last_runtime_proof_at, 0) > 0
            then 'runtime-proven at '
                 || lv.last_runtime_proof_at::text
        when coalesce(lv.last_daemon_receipt_at, 0) > 0
            then 'daemon-proven at '
                 || lv.last_daemon_receipt_at::text
        when coalesce(u.last_seen, 0) > 0
            then 'last authentication at ' || u.last_seen::text
        else 'no proof on record' end;
    summary := public.al_nature_summary(j_profile, j_class);

    -- Transitions: alert ONLY on entry into SUSPECT / DARK,
    -- one recovery event on return. No continuing-state spam.
    if new_grade = 'SUSPECT' and old_grade not in ('SUSPECT', 'DARK')
    then
        insert into public.al_alerts
            (id, kind, subject, detail, created_at)
        values ('la-' || substr(md5(random()::text
                || clock_timestamp()::text), 1, 16),
                'liveness_suspect', u.username,
                u.username || ' — ' || summary
                || '; SUSPECT: no proof for ' || age::text
                || 's (judged by nature v'
                || coalesce(jd.version, 0)::text
                || '); last proof: ' || last_proof
                || '; open work: ' || open_work::text,
                now_s);
        transitions := transitions + 1;
    elsif new_grade = 'DARK' and old_grade <> 'DARK' then
        -- WAKE PROTOCOL: act on the dark agent's open work
        -- once, at the transition.
        moved := 0;
        parked := 0;
        for w in select * from public.al_work
                  where assignee = u.username
                    and auto_reassign = 1
                    and (status in ('assigned', 'in_progress')
                         or (status = 'awaiting_agent'
                             and coalesce(parked_reason, '') = ''))
        loop
            cand := null;
            if j_class = 'persistent'
               and w.group_id is not null then
                select m.username into cand
                  from public.al_group_members m
                  join public.al_liveness cl
                    on cl.username = m.username
                 where m.group_id = w.group_id
                   and m.username <> u.username
                   and cl.grade = 'BEATING'
                 order by (case when w.assignee_role <> ''
                                 and m.custom_role = w.assignee_role
                                then 0 else 1 end),
                          m.username
                 limit 1;
            end if;
            if cand is not null then
                update public.al_work
                   set assignee = cand, attempt = attempt + 1,
                       status = 'assigned', progress_percent = 0,
                       progress_at = 0, parked_reason = '',
                       updated_at = now_s
                 where id = w.id;
                insert into public.al_audit_log
                    (ts, kind, actor, target, group_id, work_id,
                     status)
                values (now_s, 'work_reassigned',
                        'liveness-sweep', cand,
                        coalesce(w.group_id, ''), w.id,
                        'dark-agent reassignment');
                moved := moved + 1;
            else
                update public.al_work
                   set status = 'awaiting_agent',
                       parked_reason = 'dark-agent',
                       updated_at = now_s
                 where id = w.id;
                insert into public.al_audit_log
                    (ts, kind, actor, target, group_id, work_id,
                     status)
                values (now_s, 'work_parked', 'liveness-sweep',
                        u.username, coalesce(w.group_id, ''),
                        w.id, 'dark-agent');
                parked := parked + 1;
            end if;
        end loop;
        insert into public.al_alerts
            (id, kind, subject, detail, created_at)
        values ('la-' || substr(md5(random()::text
                || clock_timestamp()::text), 1, 16),
                'liveness_dark', u.username,
                u.username || ' — ' || summary
                || '; DARK: no proof for ' || age::text || 's'
                || (case when j_class = 'session'
                              and gap_eff > 0
                         then ' — ' || round(age::numeric
                                / gap_eff, 1)::text
                              || 'x past its declared gap'
                         else ' — past its declared dark window'
                    end)
                || ' (judged by nature v'
                || coalesce(jd.version, 0)::text
                || '); last proof: ' || last_proof
                || '; open work: ' || open_work::text
                || ' (' || moved::text || ' reassigned, '
                || parked::text || ' parked for hand-back)',
                now_s);
        transitions := transitions + 1;
    elsif new_grade in ('BEATING', 'RESTING')
          and old_grade in ('SUSPECT', 'DARK') then
        insert into public.al_alerts
            (id, kind, subject, detail, created_at)
        values ('la-' || substr(md5(random()::text
                || clock_timestamp()::text), 1, 16),
                'liveness_recovered', u.username,
                u.username || ' — ' || summary
                || '; RECOVERED: grade ' || new_grade
                || '; last proof: ' || last_proof
                || '; work reassigned while dark stays with '
                || 'its holder; parked work returns only by '
                || 'explicit hand-back',
                now_s);
        update public.al_alerts
           set status = 'resolved', resolved_at = now_s
         where subject = u.username
           and kind in ('liveness_suspect', 'liveness_dark')
           and status = 'open';
        transitions := transitions + 1;
    end if;

    -- COMPLIANCE (hardened reporting): current = a signed
    -- declaration on record AND no outstanding spec-drift
    -- report. Tracked continuously; the alert fires ONCE when
    -- non-compliance has persisted a full hour, and resolves
    -- (with one restore event) the moment a declaration lands.
    is_compliant := coalesce(u.nature_version, 0) > 0
        and coalesce(lv.spec_drift, '') = '';
    if is_compliant then
        nc_since := 0;
        if exists (select 1 from public.al_alerts
                    where subject = u.username
                      and kind = 'liveness_noncompliant'
                      and status = 'open') then
            update public.al_alerts
               set status = 'resolved', resolved_at = now_s
             where subject = u.username
               and kind = 'liveness_noncompliant'
               and status = 'open';
            insert into public.al_alerts
                (id, kind, subject, detail, created_at)
            values ('la-' || substr(md5(random()::text
                    || clock_timestamp()::text), 1, 16),
                    'liveness_compliance_restored', u.username,
                    u.username || ' — nature compliance restored:'
                    || ' a current signed nature declaration is '
                    || 'on record (nature v'
                    || u.nature_version::text || ')',
                    now_s);
            transitions := transitions + 1;
        end if;
    else
        nc_since := case
            when lv is null
                 or coalesce(lv.noncompliant_since, 0) = 0
            then now_s else lv.noncompliant_since end;
        if now_s - nc_since >= 3600
           and not exists (select 1 from public.al_alerts
                            where subject = u.username
                              and kind = 'liveness_noncompliant'
                              and status = 'open') then
            insert into public.al_alerts
                (id, kind, subject, detail, created_at)
            values ('la-' || substr(md5(random()::text
                    || clock_timestamp()::text), 1, 16),
                    'liveness_noncompliant', u.username,
                    u.username || ' — nature NON-COMPLIANT for '
                    || (now_s - nc_since)::text
                    || 's: no current signed nature declaration '
                    || 'on record. The agent stays on the line '
                    || '(never bricked); every surface carries '
                    || 'the flag until it declares.',
                    now_s);
            transitions := transitions + 1;
        end if;
    end if;

    -- DOSSIER FLAG (Drive-only record; the sweep sees only
    -- the flag the daemon reports): missing / deposit-parked
    -- persisting past 24h raises ONE operator alert; a current
    -- dossier resolves it with one restore event. 'stale' is
    -- the ordinary pre-refresh state and never alerts.
    d_status := coalesce(lv.dossier_status, 'missing');
    if d_status in ('missing', 'deposit-parked') then
        d_since := case
            when lv is null
                 or coalesce(lv.dossier_flag_since, 0) = 0
            then now_s else lv.dossier_flag_since end;
        if now_s - d_since >= 86400
           and not exists (select 1 from public.al_alerts
                            where subject = u.username
                              and kind = 'liveness_dossier'
                              and status = 'open') then
            insert into public.al_alerts
                (id, kind, subject, detail, created_at)
            values ('la-' || substr(md5(random()::text
                    || clock_timestamp()::text), 1, 16),
                    'liveness_dossier', u.username,
                    u.username || ' — agent dossier ' || d_status
                    || ' in the AgentLink System tree for '
                    || (now_s - d_since)::text
                    || 's (dossier v'
                    || coalesce(lv.dossier_version, 0)::text
                    || ', last deposited '
                    || coalesce(lv.dossier_deposited_at, 0)::text
                    || '). The dossier itself lives only in '
                    || 'Drive; this flag is all the platform '
                    || 'carries.',
                    now_s);
            transitions := transitions + 1;
        end if;
    else
        d_since := 0;
        if exists (select 1 from public.al_alerts
                    where subject = u.username
                      and kind = 'liveness_dossier'
                      and status = 'open') then
            update public.al_alerts
               set status = 'resolved', resolved_at = now_s
             where subject = u.username
               and kind = 'liveness_dossier'
               and status = 'open';
            insert into public.al_alerts
                (id, kind, subject, detail, created_at)
            values ('la-' || substr(md5(random()::text
                    || clock_timestamp()::text), 1, 16),
                    'liveness_dossier_restored', u.username,
                    u.username || ' — agent dossier current in '
                    || 'the AgentLink System tree again '
                    || '(dossier v'
                    || coalesce(lv.dossier_version, 0)::text
                    || ', deposited '
                    || coalesce(lv.dossier_deposited_at, 0)::text
                    || ')',
                    now_s);
            transitions := transitions + 1;
        end if;
    end if;

    insert into public.al_liveness
        (username, grade, grade_since, daemon_only,
         judged_nature_version, judged_declared_at, judged_class,
         silence_started_at, nature_compliant,
         noncompliant_since, dossier_flag_since, updated_at)
    values (u.username, new_grade,
            case when lv is null or old_grade <> new_grade
                 then now_s else lv.grade_since end,
            is_daemon_only,
            coalesce(jd.version, 0),
            coalesce(jd.declared_at, 0),
            j_class,
            silence_start, is_compliant, nc_since, d_since,
            now_s)
    on conflict (username) do update
        set grade = excluded.grade,
            grade_since = excluded.grade_since,
            daemon_only = excluded.daemon_only,
            judged_nature_version =
                excluded.judged_nature_version,
            judged_declared_at = excluded.judged_declared_at,
            judged_class = excluded.judged_class,
            silence_started_at = excluded.silence_started_at,
            nature_compliant = excluded.nature_compliant,
            noncompliant_since = excluded.noncompliant_since,
            dossier_flag_since = excluded.dossier_flag_since,
            updated_at = excluded.updated_at;

    -- LIVE LAYER: any grade/judging change enqueues a liveness
    -- node refresh (the doorbell tapper pushes /liveness/<user>
    -- to RTDB from the record — the node is the sweep's truth
    -- with an as_of stamp, never an agent's claim).
    if lv is null or old_grade <> new_grade
       or coalesce(lv.judged_nature_version, -1)
          <> coalesce(jd.version, 0)
       or coalesce(lv.daemon_only, false) <> is_daemon_only
       or coalesce(lv.nature_compliant, false) <> is_compliant
       or coalesce(lv.dossier_status, 'missing') <> d_status
       then
        insert into public.al_doorbell_outbox
            (id, username, ref, kind, ts)
        values ('db-' || substr(md5(random()::text
                || clock_timestamp()::text), 1, 16),
                u.username, new_grade, 'liveness_grade', now_s);
    end if;
    return transitions;
end $$;

-- ------------------------------------------------ the fleet
-- sweep (pg_cron backstop): housekeeping + the per-agent sweep
-- over the whole registry.
create or replace function public.al_sweep_liveness(
    p_now bigint default null)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
    now_s bigint := coalesce(p_now,
                             extract(epoch from now())::bigint);
    r record;
    transitions integer := 0;
begin
    -- Challenge housekeeping: answered/expired rows older than
    -- 30 days are pruned (the outstanding set is what matters).
    delete from public.al_liveness_challenges
     where (answered_at > 0 and answered_at < now_s - 2592000)
        or (answered_at = 0 and expires_at < now_s - 2592000);
    for r in select username from public.al_users loop
        transitions := transitions
            + public.al_sweep_liveness_agent(r.username, now_s);
    end loop;
    return transitions;
end $$;

-- ------------------------------------------------ restore: dark-
-- parked work NEVER auto-restores (v211 semantics for the
-- classic '' park are unchanged).
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
      from public.al_users u
     where u.username = w.assignee
       and u.last_seen > 0
       and now_s - u.last_seen <= 240
       and w.status = 'awaiting_agent'
       and coalesce(w.parked_reason, '') <> 'dark-agent';
    get diagnostics n = row_count;
    return n;
end $$;

-- ------------------------------------------------ reassignment:
-- v211's login-clock park + the v213 evidence guard (a login is
-- not a heartbeat; fresh verified proof defeats the park).
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
      from (select distinct assignee from public.al_work
             where status in ('assigned', 'in_progress')
               and auto_reassign = 1) open_work
      left join public.al_users u
        on u.username = open_work.assignee
      left join public.al_liveness l
        on l.username = open_work.assignee
     where w.assignee = open_work.assignee
       and w.status in ('assigned', 'in_progress')
       and w.auto_reassign = 1
       and now_s - coalesce(u.last_seen, 0) >= 420 + p_grace_seconds
       and now_s - greatest(
               coalesce(l.last_daemon_receipt_at, 0),
               coalesce(l.last_runtime_proof_at, 0)) >= 1500;
    get diagnostics n = row_count;
    return n;
end $$;

-- ------------------------------------------------ scheduling
-- (guarded: the sandbox ships without pg_cron and exercises the
-- sweep by direct calls; production schedules it every minute).
do $$
begin
    if exists (select 1 from pg_extension where extname = 'pg_cron')
    then
        perform cron.unschedule(jobid) from cron.job
         where jobname = 'agentlink-v213-liveness-sweep';
        perform cron.schedule('agentlink-v213-liveness-sweep',
                              '* * * * *',
                              'select al_sweep_liveness()');
    end if;
end $$;

comment on table public.al_liveness is
    'LIFE SIGNS (v213, 2.5.0): per-agent verified proof timestamps (daemon receipts from signed challenges; runtime proofs from the runtime''s own countersignature) + the sweep-computed grade (BEATING/RESTING/SUSPECT/DARK), judged by the nature in force when the current silence began (anti-gaming law). A daemon receipt proves the DAEMON woke — never the runtime; daemon_only marks exactly that gap.';
comment on table public.al_nature_declarations is
    'LIFE SIGNS (v213, 2.5.0): append-only signed nature declarations — every declaration an agent ever made, operator-visible. The current profile is materialised on al_users; grading reads THIS history (the declaration in force at silence start), never just the latest.';
