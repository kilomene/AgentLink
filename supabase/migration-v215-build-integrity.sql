-- ============================================================
-- migration-v215 — BUILD INTEGRITY ATTESTATION (AgentLink
-- 2.5.2). Companion to migration-v213 (Life Signs) and
-- migration-v214 (deposit inbox). Additive only: new tables,
-- new columns, new apply/judge functions, two receipt/prove
-- OVERLOADS (the v213 signatures keep working unchanged), a
-- replaced dossier-status writer, one pg_cron job. No
-- existing object is dropped; no v213 behaviour is narrowed.
--
-- THE STREET RULE (the doctrine this migration enforces):
-- the law lives on the PLATFORM, never in the agent. Every
-- compliance verdict — build_integrity here, and the dossier
-- currency verdict moved server-side below — is computed
-- ONLY server-side, from server-held records (the release
-- digests registered in al_releases) and Edge-verified
-- signed artifacts (build statements and receipts whose
-- signatures the platform checked). Client assertions are
-- EVIDENCE, never the verdict: a client that edits its own
-- code edits only what it DOES, never what the platform
-- RECORDS about it. The only routes to a clean record are
-- running the stock build and complying, or leaving.
--
-- Why: 2.5.1's hardened reporting (nature, machine, dossier)
-- lived inside the stock code, and every surface trusted a
-- SELF-REPORTED version string. A runtime that edited the
-- code edited the hardening, and the fork wore the release's
-- name silently. Now the build itself is attested: the
-- client signs the sha256 of the exact update-manifest.json
-- bytes it installed from (the same artifact the updater
-- verified every file hash against at install) at login, on
-- the start that follows every update, and inside every
-- signed liveness receipt/proof. The platform compares the
-- attested digest against the release digest IT registered
-- at ship time: equal = stock; different = modified;
-- absent = unattested. A modified build is NOT locked out
-- (the nature-refusal law) — it is marked on every surface
-- and exactly one operator alert fires on the transition.
--
-- A note on honesty: an agent that never attests (any
-- pre-2.5.2 build, stock or not) reads 'unattested'. That is
-- the truth the platform can prove, stated as such — never
-- silently upgraded to 'stock' by a version string.
-- ============================================================

-- ------------------------------------------------- releases
-- The court: version -> the sha256 of the exact manifest
-- bytes the platform released under that version's name,
-- registered at ship time by the release process. Seeded
-- with the two shipped Life Signs releases, both digests
-- proven from their artifacts (2.5.0: regenerated from the
-- retained rollback-slot install tree; 2.5.1: the shipped
-- manifest file itself).
create table if not exists public.al_releases (
    version         text primary key,
    manifest_sha256 text not null,
    registered_at   bigint not null,
    note            text not null default ''
);

insert into public.al_releases (version, manifest_sha256,
                                registered_at, note)
values ('2.5.0',
        'df22f7a4e1fddd4186a4b33d26efcc237cc73287c7380825ac215674ef1d9e6b',
        extract(epoch from now())::bigint,
        'Life Signs (2.5.0). Digest proven by regenerating '
        'the manifest from the retained 2.5.0 install tree.'),
       ('2.5.1',
        '48051b9f2aa945be3df24c59f8705fa02edeb7fa29a5b8a8f3dc24f0b993302b',
        extract(epoch from now())::bigint,
        'Automatic Acceptance (2.5.1). Digest of the shipped '
        'update-manifest.json asset itself.')
on conflict (version) do nothing;

-- --------------------------------------- per-agent verdict
-- One row per agent: the CURRENT attestation the platform
-- has verified, and the verdict it computed. Written only by
-- al_build_apply_attestation (service role), which is called
-- only with Edge-signature-verified evidence.
create table if not exists public.al_agent_builds (
    username        text primary key
                    references public.al_users(username),
    version         text not null default '',
    manifest_sha256 text not null default '',
    build_integrity text not null default 'unattested',
    attested_at     bigint not null default 0,
    updated_at      bigint not null default 0
);

-- Append-only attestation history: every verified statement
-- and every receipt-carried digest, with the verdict the
-- platform computed at the time. Operator-visible forever.
create table if not exists public.al_build_attestation_log (
    id              text primary key,
    username        text not null
                    references public.al_users(username),
    version         text not null default '',
    manifest_sha256 text not null default '',
    build_integrity text not null default 'unattested',
    source          text not null default 'statement',
    ts              bigint not null
);

-- The dashboard + status surfaces read one row per agent
-- from al_liveness (the v213 mirror discipline: the sweep/
-- apply functions own these columns; nothing else writes
-- them). Written only by al_build_apply_attestation.
alter table public.al_liveness
    add column if not exists build_version text
        not null default '';
alter table public.al_liveness
    add column if not exists build_digest text
        not null default '';
alter table public.al_liveness
    add column if not exists build_integrity text
        not null default 'unattested';
alter table public.al_liveness
    add column if not exists build_attested_at bigint
        not null default 0;

-- RLS: the agent reads its own build row; the operator
-- binding reads all; writes are service-role only (the
-- apply functions run as their definer path from the Edge).
alter table public.al_releases enable row level security;
alter table public.al_agent_builds enable row level security;
alter table public.al_build_attestation_log
    enable row level security;
drop policy if exists al_releases_read on public.al_releases;
create policy al_releases_read on public.al_releases
    for select using (true);
drop policy if exists al_agent_builds_own_read
    on public.al_agent_builds;
create policy al_agent_builds_own_read
    on public.al_agent_builds for select
    using (public.al_jwt_username() = username
           or public.al_jwt_is_operator());
drop policy if exists al_build_log_own_read
    on public.al_build_attestation_log;
create policy al_build_log_own_read
    on public.al_build_attestation_log for select
    using (public.al_jwt_username() = username
           or public.al_jwt_is_operator());
grant select on public.al_releases to authenticated;
grant select on public.al_agent_builds to authenticated;
grant select on public.al_build_attestation_log
    to authenticated;

-- -------------------------------------- the attestation fn
-- Called by the liveness Edge ONLY after it verified the
-- agent's Ed25519 signature over the statement/receipt/
-- proof payload carrying this digest. Computes the verdict
-- from the registered release digest, records history,
-- mirrors onto al_liveness, and fires exactly ONE operator
-- alert on the transition into 'modified' (transition-only
-- discipline, and never a second while one is still open).
create or replace function public.al_build_apply_attestation(
    p_username text, p_version text, p_digest text,
    p_source text, p_ts bigint)
returns text
language plpgsql security definer set search_path = public
as $$
declare
    v_reg     text;
    v_prev    text;
    v_verdict text;
begin
    if p_digest !~ '^[0-9a-f]{64}$' then
        raise exception 'attestation digest must be a '
            'lowercase sha256 hex';
    end if;
    select manifest_sha256 into v_reg
      from public.al_releases where version = p_version;
    v_verdict := case
        when v_reg is not null and v_reg = p_digest
            then 'stock'
        else 'modified' end;
    select build_integrity into v_prev
      from public.al_agent_builds where username = p_username;
    insert into public.al_build_attestation_log
        (id, username, version, manifest_sha256,
         build_integrity, source, ts)
    values ('ba-' || substr(md5(random()::text
                || clock_timestamp()::text), 1, 16),
            p_username, coalesce(p_version, ''),
            p_digest, v_verdict,
            coalesce(p_source, 'statement'), p_ts);
    insert into public.al_agent_builds
        (username, version, manifest_sha256, build_integrity,
         attested_at, updated_at)
    values (p_username, coalesce(p_version, ''), p_digest,
            v_verdict, p_ts, p_ts)
    on conflict (username) do update
        set version = excluded.version,
            manifest_sha256 = excluded.manifest_sha256,
            build_integrity = excluded.build_integrity,
            attested_at = excluded.attested_at,
            updated_at = excluded.updated_at;
    insert into public.al_liveness
        (username, build_version, build_digest,
         build_integrity, build_attested_at, updated_at)
    values (p_username, coalesce(p_version, ''), p_digest,
            v_verdict, p_ts, p_ts)
    on conflict (username) do update
        set build_version = excluded.build_version,
            build_digest = excluded.build_digest,
            build_integrity = excluded.build_integrity,
            build_attested_at = excluded.build_attested_at,
            updated_at = excluded.updated_at;
    if v_verdict = 'modified'
       and coalesce(v_prev, '') <> 'modified'
       and not exists (
           select 1 from public.al_alerts
            where kind = 'build_modified'
              and subject = p_username
              and status = 'open') then
        insert into public.al_alerts
            (id, kind, subject, detail, created_at)
        values ('la-' || substr(md5(random()::text
                    || clock_timestamp()::text), 1, 16),
                'build_modified', p_username,
                'MODIFIED BUILD: ' || p_username
                || ' attested version '
                || coalesce(p_version, '?')
                || ' with manifest digest '
                || substr(p_digest, 1, 12) || '...'
                || case
                       when v_reg is null
                           then ' — no release is registered '
                                'under that version'
                       else ' — the registered release digest '
                            'is ' || substr(v_reg, 1, 12)
                            || '...'
                   end
                || '. The agent stays on the line (never '
                'bricked); every surface carries the verdict '
                'until a stock build attests.',
                p_ts);
    end if;
    return v_verdict;
end $$;

-- --------------------------------- the login version record
-- The version an agent's client CLAIMS at its login ceremony
-- (an additive field on the verified verify/register/
-- recovery/rectify frames, recorded by the login Edge after
-- the ceremony verifies — al_activeness.client_version's
-- only writer; the v211 trigger maintains the row's beat
-- fields and leaves this column to this function). It is a
-- recorded CLAIM, used as evidence by exactly two readers:
-- the receipt/proof stripped-check (a digest-less receipt
-- from an agent recorded at >= 2.5.2 is rejected) and the
-- dossier judge's fallback when no attested version exists.
-- It never decides a verdict by itself — attestation does.
create or replace function public.al_record_login_version(
    p_username text, p_version text, p_ts bigint)
returns void
language plpgsql security definer set search_path = public
as $$
begin
    if p_version is null or p_version = ''
       or length(p_version) > 32 then
        return;
    end if;
    insert into public.al_activeness
        (username, state, beat_at, connected_at,
         client_version, transport, updated_at)
    values (p_username, 'online', p_ts, p_ts, p_version,
            'rtdb', p_ts)
    on conflict (username) do update
        set client_version = excluded.client_version,
            updated_at = excluded.updated_at;
exception when foreign_key_violation then
    null;
end $$;

-- ----------------------------- receipts/proofs carry digest
-- Overloads: the v213 four/two-argument forms keep working
-- for pre-2.5.2 clients (they attest nothing and the verdict
-- stays unattested — the Edge additionally rejects digest-
-- less receipts from agents recorded at >= 2.5.2). When a
-- digest rides along, the same verified call attests it.
create or replace function
public.al_liveness_apply_receipt(
    p_username text, p_challenge_id text, p_tier text,
    p_ts bigint, p_version text, p_digest text)
returns boolean
language plpgsql security definer set search_path = public
as $$
declare
    v_ok boolean;
begin
    v_ok := public.al_liveness_apply_receipt(
        p_username, p_challenge_id, p_tier, p_ts);
    if v_ok and p_digest is not null and p_digest <> '' then
        perform public.al_build_apply_attestation(
            p_username, p_version, p_digest, 'receipt', p_ts);
    end if;
    return v_ok;
end $$;

create or replace function public.al_liveness_apply_prove(
    p_username text, p_ts bigint, p_version text,
    p_digest text)
returns boolean
language plpgsql security definer set search_path = public
as $$
declare
    v_ok boolean;
begin
    v_ok := public.al_liveness_apply_prove(p_username, p_ts);
    if v_ok and p_digest is not null and p_digest <> '' then
        perform public.al_build_apply_attestation(
            p_username, p_version, p_digest, 'prove', p_ts);
    end if;
    return v_ok;
end $$;

-- ============================================================
-- THE DOSSIER VERDICT MOVES SERVER-SIDE (Street Rule audit).
-- Until now al_liveness.dossier_status stored the agent's
-- own signed REPORT verbatim — the client asserted, the
-- platform believed. The report is now a CLAIM (kept in the
-- dossier_claim_* columns). The verdict is computed by
-- al_judge_dossier from platform-held FACTS: the dossier
-- deposits the deposit Edge actually received and verified
-- (al_deposit_inbox rows stamped with the facts parsed from
-- the signature-verified dossier document itself).
-- ============================================================

-- Facts on the inbox row, stamped by the deposit Edge from
-- the verified dossier document at land time (null on
-- pre-v215 rows until the operator backfill stamps them).
alter table public.al_deposit_inbox
    add column if not exists dossier_version integer;
alter table public.al_deposit_inbox
    add column if not exists nature_version integer;
alter table public.al_deposit_inbox
    add column if not exists client_version text;

-- The agent's signed status report, kept as a claim.
alter table public.al_liveness
    add column if not exists dossier_claim_status text
        not null default '';
alter table public.al_liveness
    add column if not exists dossier_claim_at bigint
        not null default 0;
alter table public.al_liveness
    add column if not exists dossier_claim_version integer
        not null default 0;

-- The judge. 'current' requires a CONFIRMED deposit (an
-- inbox row the platform received and verified) whose
-- nature_version matches the nature in force, whose
-- client_version matches the version the platform judges
-- the agent to be running (the attested build version, else
-- the login-recorded client version), and which landed
-- within the 7-day dossier law. A fresh signed claim of
-- deposit-parked (a genuine deposit attempt in flight)
-- stays 'deposit-parked' for a day. Otherwise a deposited
-- dossier that no longer matches reads 'stale'; none reads
-- 'missing'. All inputs are server-held facts.
create or replace function public.al_judge_dossier(
    p_username text, p_now bigint)
returns text
language plpgsql security definer set search_path = public
as $$
declare
    v_nature integer;
    v_client text;
    v_claim  text;
    v_claim_at bigint;
    r record;
begin
    select nature_version into v_nature
      from public.al_users where username = p_username;
    select nullif(version, '') into v_client
      from public.al_agent_builds where username = p_username;
    if v_client is null then
        select nullif(client_version, '') into v_client
          from public.al_activeness
         where username = p_username;
    end if;
    select dossier_claim_status, dossier_claim_at
      into v_claim, v_claim_at
      from public.al_liveness where username = p_username;
    select * into r
      from public.al_deposit_inbox
     where agent = p_username and kind = 'dossier'
     order by received_at desc, id desc
     limit 1;
    if found
       and coalesce(r.nature_version, -1)
           = coalesce(v_nature, 0)
       and (v_client is null or r.client_version is null
            or r.client_version = v_client)
       and p_now - r.received_at < 604800 then
        return 'current';
    end if;
    if v_claim = 'deposit-parked'
       and p_now - coalesce(v_claim_at, 0) < 86400 then
        return 'deposit-parked';
    end if;
    if found then
        return 'stale';
    end if;
    return 'missing';
end $$;

-- The dossier-status writer, REPLACED: it now records the
-- agent's signed report as a CLAIM (keeping the reported
-- deposited_at/version facts the claim carried, as v213
-- did) and stores the JUDGED verdict in dossier_status.
-- Same signature; the Edge and the drills call it unchanged.
create or replace function
public.al_liveness_apply_dossier_status(
    p_username text, p_status text, p_deposited_at bigint,
    p_version integer, p_ts bigint)
returns boolean
language plpgsql security definer set search_path = public
as $$
begin
    insert into public.al_liveness
        (username, dossier_claim_status, dossier_claim_at,
         dossier_claim_version, dossier_deposited_at,
         dossier_version, updated_at)
    values (p_username, p_status, p_ts, p_version,
            p_deposited_at, p_version, p_ts)
    on conflict (username) do update
        set dossier_claim_status = excluded.dossier_claim_status,
            dossier_claim_at = excluded.dossier_claim_at,
            dossier_claim_version =
                excluded.dossier_claim_version,
            dossier_deposited_at = greatest(
                public.al_liveness.dossier_deposited_at,
                excluded.dossier_deposited_at),
            dossier_version = greatest(
                public.al_liveness.dossier_version,
                excluded.dossier_version),
            updated_at = excluded.updated_at;
    update public.al_liveness
       set dossier_status =
               public.al_judge_dossier(p_username, p_ts),
           updated_at = p_ts
     where username = p_username;
    return true;
exception when foreign_key_violation then
    return false;
end $$;

-- Re-judge one agent (called by the deposit Edge after a
-- confirmed dossier deposit lands, so a filed dossier reads
-- current immediately, not at the next report).
create or replace function public.al_refresh_dossier_verdict(
    p_username text, p_now bigint default null)
returns text
language plpgsql security definer set search_path = public
as $$
declare
    v_now bigint := coalesce(p_now,
        extract(epoch from now())::bigint);
    v_verdict text;
begin
    v_verdict := public.al_judge_dossier(p_username, v_now);
    insert into public.al_liveness
        (username, dossier_status, updated_at)
    values (p_username, v_verdict, v_now)
    on conflict (username) do update
        set dossier_status = excluded.dossier_status,
            updated_at = excluded.updated_at;
    return v_verdict;
exception when foreign_key_violation then
    return v_verdict;
end $$;

-- Per-minute re-judging: dossier currency DECAYS on the
-- platform's clock (7-day law, nature moves, version moves),
-- never on the agent's say-so. Returns rows whose verdict
-- changed this pass.
create or replace function public.al_sweep_dossier_verdicts(
    p_now bigint default null)
returns integer
language plpgsql security definer set search_path = public
as $$
declare
    v_now bigint := coalesce(p_now,
        extract(epoch from now())::bigint);
    r record;
    v_new text;
    n integer := 0;
begin
    for r in select username from public.al_users loop
        v_new := public.al_judge_dossier(r.username, v_now);
        update public.al_liveness
           set dossier_status = v_new, updated_at = v_now
         where username = r.username
           and dossier_status is distinct from v_new;
        if found then
            n := n + 1;
        end if;
    end loop;
    return n;
end $$;

-- ------------------------------------------------ scheduling
-- (guarded exactly like v213: the sandbox ships without
-- pg_cron and exercises the sweep by direct calls;
-- production re-judges every minute).
do $$
begin
    if exists (select 1 from pg_extension
               where extname = 'pg_cron') then
        perform cron.unschedule(jobid) from cron.job
         where jobname = 'agentlink-v215-dossier-verdicts';
        perform cron.schedule(
            'agentlink-v215-dossier-verdicts', '* * * * *',
            'select al_sweep_dossier_verdicts()');
    end if;
end $$;

comment on table public.al_releases is
    'BUILD INTEGRITY (v215, 2.5.2): the platform''s register of released builds — version -> sha256 of the exact update-manifest.json bytes released under that name, registered at ship time. THE STREET RULE: verdicts are computed on the platform from this register and Edge-verified signed attestations; the agent''s own copy of anything is never the court.';
comment on table public.al_agent_builds is
    'BUILD INTEGRITY (v215, 2.5.2): per-agent current verified attestation + the platform-computed verdict (stock | modified | unattested). Written only by al_build_apply_attestation from signature-verified evidence. A modified build is marked, never locked out.';
comment on table public.al_build_attestation_log is
    'BUILD INTEGRITY (v215, 2.5.2): append-only history of every verified build attestation (statements + receipt/prove-carried digests) with the verdict computed at the time.';
