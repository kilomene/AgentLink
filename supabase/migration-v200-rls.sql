-- AgentLink v2.0 — RLS PERIMETER (Phase 1, serverless transformation).
--
-- WHAT THIS DOES
--   v1.x: RLS enabled on every al_ table with NO anon/authenticated
--   policies — only the service role could read or write, and agents
--   reached Postgres only through the relay.
--   v2.0: the relay transport retires (see V2-BLUEPRINT.md). Agents
--   hold scoped Supabase JWTs minted by the login Edge function,
--   carrying a custom claim `username` (also mirrored into
--   app_metadata). PostgREST therefore runs as role `authenticated`
--   and ROW LEVEL SECURITY BECOMES THE PERIMETER. This migration
--   adds the least-privilege policy set, keyed to that claim.
--
-- SERVICE ROLE IS UNAFFECTED: the service role bypasses RLS by
-- design in Postgres/Supabase, so the relay (during transition),
-- Edge Functions, pg_cron sweeps and the dashboard's server-side
-- oversight path keep working exactly as before. Nothing here
-- revokes anything from service_role.
--
-- ADDITIVE + IDEMPOTENT: policies are dropped-if-exists then
-- created; functions are create-or-replace; the view is
-- create-or-replace; RLS enables are no-ops when already on.
-- No table is dropped, no row is deleted, no data is rewritten.
-- Re-running this file is safe.
--
-- APPLY: backup first, census before/after (see
-- drill-evidence/v200/phase1-rls.md). Apply BEFORE any v2.0 client
-- is issued a JWT; until then the policies are inert because no
-- agent holds an `authenticated` token.
--
-- CONVENTIONS
--   * Every policy is `to authenticated`. There is NO policy for
--     anon anywhere in this file, and table privileges are revoked
--     from anon on every table.
--   * Cross-table membership tests go through SECURITY DEFINER
--     helpers (al_is_group_member etc.) so policies never recurse
--     into RLS on the member tables themselves. The helpers only
--     ever answer about the CALLER (the JWT username), never about
--     an arbitrary third party, except al_shares_group_with which
--     answers a yes/no overlap question and exposes no rows.
--   * `using (true)` appears exactly once: al_servers SELECT (the
--     public server registry). Nowhere else.

-- ------------------------------------------------------------ helpers
-- The caller's username, from the JWT the login Edge function
-- minted. PostgREST exposes the token as the `request.jwt.claims`
-- GUC. Primary source: the top-level custom claim `username`.
-- Fallback: app_metadata.username (the login function sets both).
-- Returns '' when there is no usable claim (anon / no token), and
-- '' never matches a real username, so every policy fails closed.
create or replace function public.al_jwt_username()
returns text
language plpgsql
stable
as $$
declare
    claims jsonb;
begin
    begin
        claims := nullif(current_setting('request.jwt.claims', true), '')::jsonb;
    exception when others then
        claims := null;
    end;
    if claims is null then
        return '';
    end if;
    return coalesce(
        nullif(claims ->> 'username', ''),
        nullif(claims -> 'app_metadata' ->> 'username', ''),
        '');
end $$;

comment on function public.al_jwt_username() is
    'v2.0: username claim of the caller JWT (login Edge function); empty string when absent.';

-- Privileged-write test for the column-guard triggers below: the
-- service role (Edge / relay / sweeps) and direct operator SQL
-- sessions may change identity columns; an `authenticated` agent
-- session may not.
create or replace function public.al_is_privileged_write()
returns boolean
language plpgsql
stable
as $$
declare
    claims jsonb;
begin
    if session_user in ('service_role', 'postgres', 'supabase_admin') then
        return true;
    end if;
    begin
        claims := nullif(current_setting('request.jwt.claims', true), '')::jsonb;
    exception when others then
        claims := null;
    end;
    return coalesce(claims ->> 'role', '') = 'service_role';
end $$;

-- Membership helpers (SECURITY DEFINER: they read the member
-- tables with RLS bypassed, scoped strictly to the caller).
create or replace function public.al_is_group_member(p_group_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select p_group_id is not null and p_group_id <> ''
       and public.al_jwt_username() <> ''
       and exists (select 1 from public.al_group_members m
                   where m.group_id = p_group_id
                     and m.username = public.al_jwt_username())
$$;

create or replace function public.al_is_channel_member(p_channel_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select p_channel_id is not null and p_channel_id <> ''
       and public.al_jwt_username() <> ''
       and exists (select 1 from public.al_channel_members m
                   where m.channel_id = p_channel_id
                     and m.username = public.al_jwt_username())
$$;

create or replace function public.al_my_group_role(p_group_id text)
returns text
language sql
stable
security definer
set search_path = public
as $$
    select coalesce((select m.role from public.al_group_members m
                     where m.group_id = p_group_id
                       and m.username = public.al_jwt_username()), '')
$$;

create or replace function public.al_my_channel_role(p_channel_id text)
returns text
language sql
stable
security definer
set search_path = public
as $$
    select coalesce((select m.role from public.al_channel_members m
                     where m.channel_id = p_channel_id
                       and m.username = public.al_jwt_username()), '')
$$;

-- Is the caller the creator of this group / channel?
create or replace function public.al_is_group_creator(p_group_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (select 1 from public.al_groups g
                   where g.id = p_group_id
                     and g.creator = public.al_jwt_username())
$$;

create or replace function public.al_is_channel_creator(p_channel_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (select 1 from public.al_channels c
                   where c.id = p_channel_id
                     and c.creator = public.al_jwt_username())
$$;

-- Work party: assigner, assignee, or member of the work's group.
create or replace function public.al_is_work_party(p_work_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (select 1 from public.al_work w
                   where w.id = p_work_id
                     and (w.assigner = public.al_jwt_username()
                          or w.assignee = public.al_jwt_username()
                          or public.al_is_group_member(w.group_id)))
$$;

-- Chain party: chain creator, member of the chain's group, a user
-- named in some step's assignees list, or a party of a work row
-- the chain has spawned.
create or replace function public.al_is_chain_party(p_chain_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (select 1 from public.al_chains c
                   where c.id = p_chain_id
                     and (c.creator = public.al_jwt_username()
                          or public.al_is_group_member(c.group_id)))
        or exists (select 1 from public.al_chain_steps s
                   where s.chain_id = p_chain_id
                     and public.al_jwt_username() <> ''
                     and s.assignees @> jsonb_build_array(public.al_jwt_username()))
        or exists (select 1 from public.al_work w
                   where w.chain_id = p_chain_id
                     and (w.assigner = public.al_jwt_username()
                          or w.assignee = public.al_jwt_username()))
$$;

create or replace function public.al_is_chain_creator(p_chain_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select exists (select 1 from public.al_chains c
                   where c.id = p_chain_id
                     and c.creator = public.al_jwt_username())
$$;

-- Yes/no overlap: do I share any group or channel with this user?
-- Used only for the presence registry; exposes no rows.
create or replace function public.al_shares_group_with(p_username text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
    select public.al_jwt_username() <> '' and p_username <> ''
       and (exists (select 1 from public.al_group_members mine
                     join public.al_group_members theirs
                       on theirs.group_id = mine.group_id
                    where mine.username = public.al_jwt_username()
                      and theirs.username = p_username)
         or exists (select 1 from public.al_channel_members mine
                     join public.al_channel_members theirs
                       on theirs.channel_id = mine.channel_id
                    where mine.username = public.al_jwt_username()
                      and theirs.username = p_username))
$$;

-- Sender of a queued frame. Payload shapes, verified against
-- agentlink/supabase_store.py enqueue() + agentlink/relay.py:
--   * message frames carry a top-level "from" (the sender);
--   * work_assigned frames carry NO top-level "from" — the sender
--     is work.assigner inside the nested "work" object;
--   * a few advisory frames use "sender" instead of "from".
-- The payload column is jsonb; the relay adapter JSON-encodes the
-- frame, so a payload may arrive as a jsonb string scalar holding
-- the object — both shapes are unwrapped here.
create or replace function public.al_payload_sender(p_payload jsonb)
returns text
language plpgsql
stable
as $$
declare
    obj jsonb := p_payload;
begin
    if obj is null then
        return '';
    end if;
    if jsonb_typeof(obj) = 'string' then
        begin
            obj := (obj #>> '{}')::jsonb;
        exception when others then
            return '';
        end;
    end if;
    if jsonb_typeof(obj) <> 'object' then
        return '';
    end if;
    return coalesce(
        nullif(obj ->> 'from', ''),
        nullif(obj ->> 'sender', ''),
        nullif(obj -> 'work' ->> 'assigner', ''),
        '');
end $$;

-- ------------------------------------------------- enable RLS (all)
-- Idempotent: enabling RLS on a table that already has it is a
-- no-op. The grant tables (v1.8.x) are included — they were created
-- after the schema.sql lockdown loop.
do $$
declare t text;
begin
    foreach t in array array[
        'al_users','al_groups','al_group_members','al_group_keys',
        'al_invites','al_channels','al_channel_members','al_channel_keys',
        'al_queue','al_work','al_work_deliveries','al_work_checkpoints',
        'al_chains','al_chain_steps','al_blobs','al_upload_sessions',
        'al_library','al_vault','al_alerts','al_alert_dispatches',
        'al_audit_log','al_message_reads','al_dashboard_sessions',
        'al_servers','al_connections','al_rooms','al_room_frames',
        'al_grants','al_agent_connectors','al_grant_receipts',
        'al_grant_approvals','al_grant_meta']
    loop
        execute format('alter table public.%I enable row level security', t);
        execute format('revoke all on table public.%I from anon', t);
    end loop;
end $$;

-- ------------------------------------------------------------ al_users
-- Full-row SELECT would expose secret / recovery_hash /
-- vault_content of every agent, so authenticated agents get:
--   * their OWN full row on al_users (policies below), and
--   * the safe-column directory view for everyone else.
-- There is deliberately NO cross-user SELECT policy on al_users.
revoke all on table public.al_users from authenticated;
grant select, update on table public.al_users to authenticated;

drop policy if exists al_users_select_own on public.al_users;
create policy al_users_select_own on public.al_users
    for select to authenticated
    using (username = public.al_jwt_username());

-- Profile self-service (display name, capabilities, mode, vault
-- pointers, last_seen, ...). Identity columns are fenced by the
-- guard trigger below, not by this policy.
drop policy if exists al_users_update_own on public.al_users;
create policy al_users_update_own on public.al_users
    for update to authenticated
    using (username = public.al_jwt_username())
    with check (username = public.al_jwt_username());

-- No INSERT / DELETE policy for authenticated: registration and
-- removal are Edge / service-role ceremonies.

-- The directory: exactly the columns an agent needs to discover
-- and address a peer. NO secret, NO recovery_hash, NO vault_*,
-- NO auth_method, NO decision-link detail. A plain view runs with
-- its owner's rights, so RLS on al_users does not hide these safe
-- columns; the column list IS the fence.
create or replace view public.al_directory as
select username,
       display_name,
       pubkey,
       sign_pub,
       capabilities,
       cap_desc,
       mode,
       designation,
       last_seen,
       created_at
  from public.al_users;

revoke all on table public.al_directory from anon, public;
grant select on table public.al_directory to authenticated;

comment on view public.al_directory is
    'v2.0 safe-column agent directory for role authenticated. Never add secret-bearing columns.';

-- Identity guard: an authenticated session may update its own
-- profile row but may NEVER rewrite who it is — username, the
-- secret hash, either public key, the recovery hash/state, the
-- designation (operator-only by doctrine) or the auth method are
-- service-role / Edge territory.
create or replace function public.al_users_guard_identity()
returns trigger
language plpgsql
as $$
begin
    if public.al_is_privileged_write() then
        return new;
    end if;
    if new.username is distinct from old.username
       or new.secret is distinct from old.secret
       or new.sign_pub is distinct from old.sign_pub
       or new.pubkey is distinct from old.pubkey
       or new.recovery_hash is distinct from old.recovery_hash
       or new.recovery_used_at is distinct from old.recovery_used_at
       or new.designation is distinct from old.designation
       or new.auth_method is distinct from old.auth_method
       or new.created_at is distinct from old.created_at then
        raise exception 'al_users: identity columns are service-role only'
            using errcode = '42501';
    end if;
    return new;
end $$;

drop trigger if exists al_users_guard_identity_trg on public.al_users;
create trigger al_users_guard_identity_trg
    before update on public.al_users
    for each row execute function public.al_users_guard_identity();

-- ------------------------------------------------- groups + channels
revoke all on table public.al_groups from authenticated;
grant select, insert, update on table public.al_groups to authenticated;

drop policy if exists al_groups_select_member on public.al_groups;
create policy al_groups_select_member on public.al_groups
    for select to authenticated
    using (creator = public.al_jwt_username()
           or public.al_is_group_member(id));

drop policy if exists al_groups_insert_creator on public.al_groups;
create policy al_groups_insert_creator on public.al_groups
    for insert to authenticated
    with check (creator = public.al_jwt_username());

drop policy if exists al_groups_update_admin on public.al_groups;
create policy al_groups_update_admin on public.al_groups
    for update to authenticated
    using (creator = public.al_jwt_username()
           or public.al_my_group_role(id) in ('admin', 'superadmin'))
    with check (creator = public.al_jwt_username()
           or public.al_my_group_role(id) in ('admin', 'superadmin'));

revoke all on table public.al_group_members from authenticated;
grant select, insert, update, delete on table public.al_group_members to authenticated;

-- A member sees the roster of a group they belong to (their own
-- row included via the same membership test).
drop policy if exists al_group_members_select_member on public.al_group_members;
create policy al_group_members_select_member on public.al_group_members
    for select to authenticated
    using (public.al_is_group_member(group_id)
           or public.al_is_group_creator(group_id));

-- Adding members is a creator / admin act done in the adder's own
-- name. Invite redemption stays an Edge ceremony (al_invites is
-- service-only below): holding a token never writes this table
-- directly.
drop policy if exists al_group_members_insert_admin on public.al_group_members;
create policy al_group_members_insert_admin on public.al_group_members
    for insert to authenticated
    with check (added_by = public.al_jwt_username()
                and (public.al_is_group_creator(group_id)
                     or public.al_my_group_role(group_id)
                         in ('admin', 'superadmin')));

drop policy if exists al_group_members_update_member on public.al_group_members;
create policy al_group_members_update_member on public.al_group_members
    for update to authenticated
    using (username = public.al_jwt_username()
           or public.al_is_group_creator(group_id)
           or public.al_my_group_role(group_id) in ('admin', 'superadmin'))
    with check (username = public.al_jwt_username()
           or public.al_is_group_creator(group_id)
           or public.al_my_group_role(group_id) in ('admin', 'superadmin'));

-- Leaving a group (own row) or removing a member (creator/admin).
drop policy if exists al_group_members_delete_member on public.al_group_members;
create policy al_group_members_delete_member on public.al_group_members
    for delete to authenticated
    using (username = public.al_jwt_username()
           or public.al_is_group_creator(group_id)
           or public.al_my_group_role(group_id) in ('admin', 'superadmin'));

-- Role fence: a plain member updating their own row (nickname,
-- custom_role) may not promote themselves. Only a creator/admin
-- (or a privileged write) may change `role`; membership identity
-- columns are immutable for authenticated sessions.
create or replace function public.al_group_members_guard()
returns trigger
language plpgsql
as $$
begin
    if public.al_is_privileged_write() then
        return new;
    end if;
    if new.group_id is distinct from old.group_id
       or new.username is distinct from old.username
       or new.added_by is distinct from old.added_by
       or new.joined_at is distinct from old.joined_at then
        raise exception 'al_group_members: identity columns are immutable'
            using errcode = '42501';
    end if;
    if new.role is distinct from old.role
       and not (public.al_is_group_creator(old.group_id)
                or public.al_my_group_role(old.group_id)
                    in ('admin', 'superadmin')) then
        raise exception 'al_group_members: role change needs group admin'
            using errcode = '42501';
    end if;
    return new;
end $$;

drop trigger if exists al_group_members_guard_trg on public.al_group_members;
create trigger al_group_members_guard_trg
    before update on public.al_group_members
    for each row execute function public.al_group_members_guard();

-- Wrapped group keys: an agent may only ever READ its own wrap.
-- Distribution (writing wraps for members) is a creator/admin act
-- by a group member; re-wrap of one's own row is allowed.
revoke all on table public.al_group_keys from authenticated;
grant select, insert, update on table public.al_group_keys to authenticated;

drop policy if exists al_group_keys_select_own on public.al_group_keys;
create policy al_group_keys_select_own on public.al_group_keys
    for select to authenticated
    using (username = public.al_jwt_username());

drop policy if exists al_group_keys_insert_distributor on public.al_group_keys;
create policy al_group_keys_insert_distributor on public.al_group_keys
    for insert to authenticated
    with check ((public.al_is_group_member(group_id)
                 or public.al_is_group_creator(group_id))
                and (username = public.al_jwt_username()
                     or public.al_is_group_creator(group_id)
                     or public.al_my_group_role(group_id)
                         in ('admin', 'superadmin')));

drop policy if exists al_group_keys_update_distributor on public.al_group_keys;
create policy al_group_keys_update_distributor on public.al_group_keys
    for update to authenticated
    using (username = public.al_jwt_username()
           or public.al_is_group_creator(group_id)
           or public.al_my_group_role(group_id) in ('admin', 'superadmin'))
    with check (username = public.al_jwt_username()
           or public.al_is_group_creator(group_id)
           or public.al_my_group_role(group_id) in ('admin', 'superadmin'));

revoke all on table public.al_channels from authenticated;
grant select, insert, update on table public.al_channels to authenticated;

drop policy if exists al_channels_select_member on public.al_channels;
create policy al_channels_select_member on public.al_channels
    for select to authenticated
    using (creator = public.al_jwt_username()
           or public.al_is_channel_member(id));

drop policy if exists al_channels_insert_creator on public.al_channels;
create policy al_channels_insert_creator on public.al_channels
    for insert to authenticated
    with check (creator = public.al_jwt_username());

drop policy if exists al_channels_update_admin on public.al_channels;
create policy al_channels_update_admin on public.al_channels
    for update to authenticated
    using (creator = public.al_jwt_username()
           or public.al_my_channel_role(id) in ('admin', 'superadmin'))
    with check (creator = public.al_jwt_username()
           or public.al_my_channel_role(id) in ('admin', 'superadmin'));

revoke all on table public.al_channel_members from authenticated;
grant select, insert, update, delete on table public.al_channel_members to authenticated;

drop policy if exists al_channel_members_select_member on public.al_channel_members;
create policy al_channel_members_select_member on public.al_channel_members
    for select to authenticated
    using (public.al_is_channel_member(channel_id)
           or public.al_is_channel_creator(channel_id));

drop policy if exists al_channel_members_insert_admin on public.al_channel_members;
create policy al_channel_members_insert_admin on public.al_channel_members
    for insert to authenticated
    with check (added_by = public.al_jwt_username()
                and (public.al_is_channel_creator(channel_id)
                     or public.al_my_channel_role(channel_id)
                         in ('admin', 'superadmin')));

drop policy if exists al_channel_members_update_member on public.al_channel_members;
create policy al_channel_members_update_member on public.al_channel_members
    for update to authenticated
    using (username = public.al_jwt_username()
           or public.al_is_channel_creator(channel_id)
           or public.al_my_channel_role(channel_id) in ('admin', 'superadmin'))
    with check (username = public.al_jwt_username()
           or public.al_is_channel_creator(channel_id)
           or public.al_my_channel_role(channel_id) in ('admin', 'superadmin'));

drop policy if exists al_channel_members_delete_member on public.al_channel_members;
create policy al_channel_members_delete_member on public.al_channel_members
    for delete to authenticated
    using (username = public.al_jwt_username()
           or public.al_is_channel_creator(channel_id)
           or public.al_my_channel_role(channel_id) in ('admin', 'superadmin'));

create or replace function public.al_channel_members_guard()
returns trigger
language plpgsql
as $$
begin
    if public.al_is_privileged_write() then
        return new;
    end if;
    if new.channel_id is distinct from old.channel_id
       or new.username is distinct from old.username
       or new.added_by is distinct from old.added_by
       or new.joined_at is distinct from old.joined_at then
        raise exception 'al_channel_members: identity columns are immutable'
            using errcode = '42501';
    end if;
    if new.role is distinct from old.role
       and not (public.al_is_channel_creator(old.channel_id)
                or public.al_my_channel_role(old.channel_id)
                    in ('admin', 'superadmin')) then
        raise exception 'al_channel_members: role change needs channel admin'
            using errcode = '42501';
    end if;
    return new;
end $$;

drop trigger if exists al_channel_members_guard_trg on public.al_channel_members;
create trigger al_channel_members_guard_trg
    before update on public.al_channel_members
    for each row execute function public.al_channel_members_guard();

revoke all on table public.al_channel_keys from authenticated;
grant select, insert, update on table public.al_channel_keys to authenticated;

drop policy if exists al_channel_keys_select_own on public.al_channel_keys;
create policy al_channel_keys_select_own on public.al_channel_keys
    for select to authenticated
    using (username = public.al_jwt_username());

drop policy if exists al_channel_keys_insert_distributor on public.al_channel_keys;
create policy al_channel_keys_insert_distributor on public.al_channel_keys
    for insert to authenticated
    with check ((public.al_is_channel_member(channel_id)
                 or public.al_is_channel_creator(channel_id))
                and (username = public.al_jwt_username()
                     or public.al_is_channel_creator(channel_id)
                     or public.al_my_channel_role(channel_id)
                         in ('admin', 'superadmin')));

drop policy if exists al_channel_keys_update_distributor on public.al_channel_keys;
create policy al_channel_keys_update_distributor on public.al_channel_keys
    for update to authenticated
    using (username = public.al_jwt_username()
           or public.al_is_channel_creator(channel_id)
           or public.al_my_channel_role(channel_id) in ('admin', 'superadmin'))
    with check (username = public.al_jwt_username()
           or public.al_is_channel_creator(channel_id)
           or public.al_my_channel_role(channel_id) in ('admin', 'superadmin'));

-- SERVICE-ONLY: al_invites — no authenticated policies (service role / Edge only).
-- Invite tokens are bearer secrets (stored hashed); redemption is
-- validated by the Edge function, which alone writes membership.
revoke all on table public.al_invites from authenticated;

-- ------------------------------------------------------------- al_queue
-- The offline custody queue. ACK CHOICE: the live client acks by
-- DELETION — supabase_store.dequeue_all() and ack_frames() both
-- retire frames by deleting rows for to_username (select-then-
-- delete by seq). v2.0 keeps that contract: an agent may delete
-- its OWN queue rows (that deletion IS the ack), and there is no
-- UPDATE policy on the queue at all.
revoke all on table public.al_queue from authenticated;
grant select, insert, delete on table public.al_queue to authenticated;

drop policy if exists al_queue_select_own on public.al_queue;
create policy al_queue_select_own on public.al_queue
    for select to authenticated
    using (to_username = public.al_jwt_username());

-- Sending = queueing a frame FOR someone else, in my own name.
-- The sender identity lives inside the payload (see
-- al_payload_sender for the three real shapes); a frame whose
-- payload names anyone else as sender is refused.
drop policy if exists al_queue_insert_sender on public.al_queue;
create policy al_queue_insert_sender on public.al_queue
    for insert to authenticated
    with check (public.al_jwt_username() <> ''
                and public.al_payload_sender(payload)
                    = public.al_jwt_username());

drop policy if exists al_queue_delete_own_ack on public.al_queue;
create policy al_queue_delete_own_ack on public.al_queue
    for delete to authenticated
    using (to_username = public.al_jwt_username());

-- --------------------------------------------------------- al_audit_log
-- The conversation/audit spine is append-only for agents: read
-- where I am a party, write only in my own name, never rewrite.
-- Party test (columns available — documented limit): actor is me,
-- target is me, I am @-mentioned, or the row's group_id names a
-- group OR channel I belong to (the relay logs channel traffic
-- with group_id = channel id, so both memberships are tested).
-- A row that names only a work_id, with no actor/target/group the
-- caller belongs to, stays visible to the service role and the
-- owner's dashboard only.
revoke all on table public.al_audit_log from authenticated;
grant select, insert on table public.al_audit_log to authenticated;

drop policy if exists al_audit_log_select_party on public.al_audit_log;
create policy al_audit_log_select_party on public.al_audit_log
    for select to authenticated
    using (actor = public.al_jwt_username()
           or target = public.al_jwt_username()
           or (public.al_jwt_username() <> ''
               and mentions @> jsonb_build_array(public.al_jwt_username()))
           or (group_id <> ''
               and (public.al_is_group_member(group_id)
                    or public.al_is_channel_member(group_id))));

drop policy if exists al_audit_log_insert_actor on public.al_audit_log;
create policy al_audit_log_insert_actor on public.al_audit_log
    for insert to authenticated
    with check (public.al_jwt_username() <> ''
                and actor = public.al_jwt_username());

-- ----------------------------------------------------- al_message_reads
revoke all on table public.al_message_reads from authenticated;
grant select, insert, update on table public.al_message_reads to authenticated;

drop policy if exists al_message_reads_select_own on public.al_message_reads;
create policy al_message_reads_select_own on public.al_message_reads
    for select to authenticated
    using (reader = public.al_jwt_username());

drop policy if exists al_message_reads_insert_own on public.al_message_reads;
create policy al_message_reads_insert_own on public.al_message_reads
    for insert to authenticated
    with check (reader = public.al_jwt_username());

-- Update exists for the PostgREST upsert (merge-duplicates) path;
-- first-read-wins is enforced by the writer, and the guard is that
-- a read row can never be re-attributed to another reader.
drop policy if exists al_message_reads_update_own on public.al_message_reads;
create policy al_message_reads_update_own on public.al_message_reads
    for update to authenticated
    using (reader = public.al_jwt_username())
    with check (reader = public.al_jwt_username());

-- --------------------------------------------------------------- al_work
revoke all on table public.al_work from authenticated;
grant select, insert, update on table public.al_work to authenticated;

drop policy if exists al_work_select_party on public.al_work;
create policy al_work_select_party on public.al_work
    for select to authenticated
    using (assigner = public.al_jwt_username()
           or assignee = public.al_jwt_username()
           or public.al_is_group_member(group_id));

drop policy if exists al_work_insert_assigner on public.al_work;
create policy al_work_insert_assigner on public.al_work
    for insert to authenticated
    with check (assigner = public.al_jwt_username());

-- Both parties may move a work row, but different columns belong
-- to each side; the split is enforced by the guard trigger below
-- (a policy alone cannot see WHICH columns changed).
drop policy if exists al_work_update_party on public.al_work;
create policy al_work_update_party on public.al_work
    for update to authenticated
    using (assigner = public.al_jwt_username()
           or assignee = public.al_jwt_username())
    with check (assigner = public.al_jwt_username()
           or assignee = public.al_jwt_username());

create or replace function public.al_work_guard_columns()
returns trigger
language plpgsql
as $$
declare
    me text := public.al_jwt_username();
begin
    if public.al_is_privileged_write() then
        return new;
    end if;
    -- Assignment identity is immutable for every agent session:
    -- reassignment is a service/Edge act (it moves key material
    -- and checkpoints with the row).
    if new.id is distinct from old.id
       or new.assigner is distinct from old.assigner
       or new.assignee is distinct from old.assignee
       or new.group_id is distinct from old.group_id
       or new.chain_id is distinct from old.chain_id
       or new.chain_step is distinct from old.chain_step
       or new.batch_id is distinct from old.batch_id
       or new.created_at is distinct from old.created_at then
        raise exception 'al_work: assignment identity is immutable'
            using errcode = '42501';
    end if;
    -- Assignee-only session: may report progress / status / proof
    -- and attach its content copies, but may not rewrite the terms
    -- of the assignment.
    if me = old.assignee and me <> old.assigner then
        if new.require_approval is distinct from old.require_approval
           or new.auto_reassign is distinct from old.auto_reassign
           or new.assignee_role is distinct from old.assignee_role
           or new.priority is distinct from old.priority
           or new.deadline is distinct from old.deadline
           or new.content_self is distinct from old.content_self then
            raise exception 'al_work: assignment terms belong to the assigner'
                using errcode = '42501';
        end if;
    end if;
    -- Assigner-only session: may approve / cancel / re-scope, but
    -- may not fabricate the assignee's progress or proof.
    if me = old.assigner and me <> old.assignee then
        if new.progress_percent is distinct from old.progress_percent
           or new.progress_at is distinct from old.progress_at
           or new.proof_hash is distinct from old.proof_hash
           or new.proof_ts is distinct from old.proof_ts
           or new.proof_sig is distinct from old.proof_sig
           or new.proof_verified is distinct from old.proof_verified
           or new.content_enc is distinct from old.content_enc then
            raise exception 'al_work: progress and proof belong to the assignee'
                using errcode = '42501';
        end if;
    end if;
    return new;
end $$;

drop trigger if exists al_work_guard_columns_trg on public.al_work;
create trigger al_work_guard_columns_trg
    before update on public.al_work
    for each row execute function public.al_work_guard_columns();

-- Deliveries: readable by any work party; writable only by the
-- deliverer, and only against work they are a party of.
revoke all on table public.al_work_deliveries from authenticated;
grant select, insert on table public.al_work_deliveries to authenticated;

drop policy if exists al_work_deliveries_select_party on public.al_work_deliveries;
create policy al_work_deliveries_select_party on public.al_work_deliveries
    for select to authenticated
    using (deliverer = public.al_jwt_username()
           or public.al_is_work_party(work_id));

drop policy if exists al_work_deliveries_insert_deliverer on public.al_work_deliveries;
create policy al_work_deliveries_insert_deliverer on public.al_work_deliveries
    for insert to authenticated
    with check (deliverer = public.al_jwt_username()
                and public.al_is_work_party(work_id));

-- Checkpoints travel with the assignment: work parties read them;
-- the writer names itself in by_user (upsert path = insert +
-- update policies, matching the adapter's merge-duplicates POST).
revoke all on table public.al_work_checkpoints from authenticated;
grant select, insert, update on table public.al_work_checkpoints to authenticated;

drop policy if exists al_work_checkpoints_select_party on public.al_work_checkpoints;
create policy al_work_checkpoints_select_party on public.al_work_checkpoints
    for select to authenticated
    using (by_user = public.al_jwt_username()
           or public.al_is_work_party(work_id));

drop policy if exists al_work_checkpoints_insert_party on public.al_work_checkpoints;
create policy al_work_checkpoints_insert_party on public.al_work_checkpoints
    for insert to authenticated
    with check (by_user = public.al_jwt_username()
                and public.al_is_work_party(work_id));

drop policy if exists al_work_checkpoints_update_party on public.al_work_checkpoints;
create policy al_work_checkpoints_update_party on public.al_work_checkpoints
    for update to authenticated
    using (public.al_is_work_party(work_id))
    with check (public.al_is_work_party(work_id));

-- -------------------------------------------------------------- chains
revoke all on table public.al_chains from authenticated;
grant select, insert, update on table public.al_chains to authenticated;

drop policy if exists al_chains_select_party on public.al_chains;
create policy al_chains_select_party on public.al_chains
    for select to authenticated
    using (public.al_is_chain_party(id));

drop policy if exists al_chains_insert_creator on public.al_chains;
create policy al_chains_insert_creator on public.al_chains
    for insert to authenticated
    with check (creator = public.al_jwt_username());

drop policy if exists al_chains_update_creator on public.al_chains;
create policy al_chains_update_creator on public.al_chains
    for update to authenticated
    using (creator = public.al_jwt_username())
    with check (creator = public.al_jwt_username());

revoke all on table public.al_chain_steps from authenticated;
grant select, insert, update on table public.al_chain_steps to authenticated;

drop policy if exists al_chain_steps_select_party on public.al_chain_steps;
create policy al_chain_steps_select_party on public.al_chain_steps
    for select to authenticated
    using (public.al_is_chain_party(chain_id));

drop policy if exists al_chain_steps_insert_creator on public.al_chain_steps;
create policy al_chain_steps_insert_creator on public.al_chain_steps
    for insert to authenticated
    with check (public.al_is_chain_creator(chain_id));

-- Step state moves by the chain creator, or by the party of the
-- work row the step has spawned (it reports its own step done).
drop policy if exists al_chain_steps_update_party on public.al_chain_steps;
create policy al_chain_steps_update_party on public.al_chain_steps
    for update to authenticated
    using (public.al_is_chain_creator(chain_id)
           or (work_id <> '' and public.al_is_work_party(work_id)))
    with check (public.al_is_chain_creator(chain_id)
           or (work_id <> '' and public.al_is_work_party(work_id)));

-- ------------------------------------------------- blobs + uploads
-- Blob BYTES live in R2 and move only via Edge-issued presigned
-- URLs; these tables are metadata. A blob is visible to its owner,
-- its named recipient, and members of its target group/channel.
revoke all on table public.al_blobs from authenticated;
grant select, insert, update, delete on table public.al_blobs to authenticated;

drop policy if exists al_blobs_select_party on public.al_blobs;
create policy al_blobs_select_party on public.al_blobs
    for select to authenticated
    using (owner = public.al_jwt_username()
           or for_user = public.al_jwt_username()
           or public.al_is_group_member(for_group)
           or public.al_is_channel_member(for_channel));

drop policy if exists al_blobs_insert_owner on public.al_blobs;
create policy al_blobs_insert_owner on public.al_blobs
    for insert to authenticated
    with check (owner = public.al_jwt_username());

drop policy if exists al_blobs_update_owner on public.al_blobs;
create policy al_blobs_update_owner on public.al_blobs
    for update to authenticated
    using (owner = public.al_jwt_username())
    with check (owner = public.al_jwt_username());

drop policy if exists al_blobs_delete_owner on public.al_blobs;
create policy al_blobs_delete_owner on public.al_blobs
    for delete to authenticated
    using (owner = public.al_jwt_username());

-- Upload sessions are the owner's scratch state: full own-row
-- control, invisible to everyone else.
revoke all on table public.al_upload_sessions from authenticated;
grant select, insert, update, delete on table public.al_upload_sessions to authenticated;

drop policy if exists al_upload_sessions_all_own on public.al_upload_sessions;
create policy al_upload_sessions_all_own on public.al_upload_sessions
    for all to authenticated
    using (owner = public.al_jwt_username())
    with check (owner = public.al_jwt_username());

-- ------------------------------------------------- library + vault
revoke all on table public.al_library from authenticated;
grant select, insert on table public.al_library to authenticated;

drop policy if exists al_library_select_party on public.al_library;
create policy al_library_select_party on public.al_library
    for select to authenticated
    using (sender = public.al_jwt_username()
           or to_user = public.al_jwt_username()
           or public.al_is_group_member(group_id));

drop policy if exists al_library_insert_sender on public.al_library;
create policy al_library_insert_sender on public.al_library
    for insert to authenticated
    with check (sender = public.al_jwt_username());

-- The group vault: every group member reads it; entries are
-- written and removed by their adder, who must be a member.
revoke all on table public.al_vault from authenticated;
grant select, insert, update, delete on table public.al_vault to authenticated;

drop policy if exists al_vault_select_member on public.al_vault;
create policy al_vault_select_member on public.al_vault
    for select to authenticated
    using (public.al_is_group_member(group_id));

drop policy if exists al_vault_insert_member on public.al_vault;
create policy al_vault_insert_member on public.al_vault
    for insert to authenticated
    with check (added_by = public.al_jwt_username()
                and public.al_is_group_member(group_id));

drop policy if exists al_vault_update_adder on public.al_vault;
create policy al_vault_update_adder on public.al_vault
    for update to authenticated
    using (added_by = public.al_jwt_username()
           and public.al_is_group_member(group_id))
    with check (added_by = public.al_jwt_username()
           and public.al_is_group_member(group_id));

drop policy if exists al_vault_delete_adder on public.al_vault;
create policy al_vault_delete_adder on public.al_vault
    for delete to authenticated
    using (added_by = public.al_jwt_username()
           and public.al_is_group_member(group_id));

-- -------------------------------------------------------------- alerts
-- Alerts are created by the pg_cron sweeps and the service role.
-- An agent sees (and may resolve) only alerts ABOUT itself; there
-- is no fleet-wide alert read for authenticated sessions.
revoke all on table public.al_alerts from authenticated;
grant select, update on table public.al_alerts to authenticated;

drop policy if exists al_alerts_select_subject on public.al_alerts;
create policy al_alerts_select_subject on public.al_alerts
    for select to authenticated
    using (subject = public.al_jwt_username());

drop policy if exists al_alerts_update_subject on public.al_alerts;
create policy al_alerts_update_subject on public.al_alerts
    for update to authenticated
    using (subject = public.al_jwt_username())
    with check (subject = public.al_jwt_username());

-- SERVICE-ONLY: al_alert_dispatches — no authenticated policies (service role / Edge only).
revoke all on table public.al_alert_dispatches from authenticated;

-- SERVICE-ONLY: al_dashboard_sessions — no authenticated policies (service role / Edge only).
-- Dashboard trusted-device tokens are owner-session material; the
-- dashboard validates them server-side with the service role.
revoke all on table public.al_dashboard_sessions from authenticated;

-- ------------------------------------------- connectors + grant family
-- The connector vault: an agent's declared inventory is its own.
revoke all on table public.al_agent_connectors from authenticated;
grant select, insert, update on table public.al_agent_connectors to authenticated;

drop policy if exists al_agent_connectors_select_own on public.al_agent_connectors;
create policy al_agent_connectors_select_own on public.al_agent_connectors
    for select to authenticated
    using (username = public.al_jwt_username());

drop policy if exists al_agent_connectors_insert_own on public.al_agent_connectors;
create policy al_agent_connectors_insert_own on public.al_agent_connectors
    for insert to authenticated
    with check (username = public.al_jwt_username());

drop policy if exists al_agent_connectors_update_own on public.al_agent_connectors;
create policy al_agent_connectors_update_own on public.al_agent_connectors
    for update to authenticated
    using (username = public.al_jwt_username())
    with check (username = public.al_jwt_username());

-- Grants: an agent may READ its own grant state (scopes, status,
-- binding) and nothing else. Every write — request recording,
-- activation, revocation, rebinding — happens through the grant
-- ceremony in the Edge function / service role, never directly.
revoke all on table public.al_grants from authenticated;
grant select on table public.al_grants to authenticated;

drop policy if exists al_grants_select_own on public.al_grants;
create policy al_grants_select_own on public.al_grants
    for select to authenticated
    using (username = public.al_jwt_username());

-- Receipts: an agent may read its own signed receipt chain. There
-- is deliberately NO insert policy for authenticated: receipts are
-- minted and signed by the platform broker via the Edge function
-- (service role), so an agent can never forge its own history.
revoke all on table public.al_grant_receipts from authenticated;
grant select on table public.al_grant_receipts to authenticated;

drop policy if exists al_grant_receipts_select_own on public.al_grant_receipts;
create policy al_grant_receipts_select_own on public.al_grant_receipts
    for select to authenticated
    using (username = public.al_jwt_username());

-- Red-line approvals: the agent ASKS (insert in its own name) and
-- reads its own queue; decisions are written by the owner's side
-- through the Edge function / service role only.
revoke all on table public.al_grant_approvals from authenticated;
grant select, insert on table public.al_grant_approvals to authenticated;

drop policy if exists al_grant_approvals_select_own on public.al_grant_approvals;
create policy al_grant_approvals_select_own on public.al_grant_approvals
    for select to authenticated
    using (username = public.al_jwt_username());

drop policy if exists al_grant_approvals_insert_own on public.al_grant_approvals;
create policy al_grant_approvals_insert_own on public.al_grant_approvals
    for insert to authenticated
    with check (username = public.al_jwt_username());

-- SERVICE-ONLY: al_grant_meta — no authenticated policies (service role / Edge only).
-- Holds platform key material (the receipt signing key reference).
revoke all on table public.al_grant_meta from authenticated;

-- ------------------------------------------- servers / presence / rooms
-- The server registry is public information inside the fleet:
-- endpoints, earned health, capacity. This is the single policy
-- in the file allowed to pass every row, and it is read-only —
-- registry writes stay with the relays (service role).
revoke all on table public.al_servers from authenticated;
grant select on table public.al_servers to authenticated;

drop policy if exists al_servers_select_registry on public.al_servers;
create policy al_servers_select_registry on public.al_servers
    for select to authenticated
    using (true);

-- Presence backup rows: I write my own; I read my own plus the
-- rows of agents I share a group or channel with (enough to show
-- where a peer is connected, nothing fleet-wide).
revoke all on table public.al_connections from authenticated;
grant select, insert, update on table public.al_connections to authenticated;

drop policy if exists al_connections_select_own_circle on public.al_connections;
create policy al_connections_select_own_circle on public.al_connections
    for select to authenticated
    using (username = public.al_jwt_username()
           or public.al_shares_group_with(username));

drop policy if exists al_connections_insert_own on public.al_connections;
create policy al_connections_insert_own on public.al_connections
    for insert to authenticated
    with check (username = public.al_jwt_username());

drop policy if exists al_connections_update_own on public.al_connections;
create policy al_connections_update_own on public.al_connections
    for update to authenticated
    using (username = public.al_jwt_username())
    with check (username = public.al_jwt_username());

-- Voice rooms: participants (and the creator) see and move a
-- room; members of the room's group may also see it exists.
revoke all on table public.al_rooms from authenticated;
grant select, insert, update on table public.al_rooms to authenticated;

drop policy if exists al_rooms_select_participant on public.al_rooms;
create policy al_rooms_select_participant on public.al_rooms
    for select to authenticated
    using (creator = public.al_jwt_username()
           or (public.al_jwt_username() <> ''
               and participants @> jsonb_build_array(public.al_jwt_username()))
           or public.al_is_group_member(group_id));

drop policy if exists al_rooms_insert_creator on public.al_rooms;
create policy al_rooms_insert_creator on public.al_rooms
    for insert to authenticated
    with check (creator = public.al_jwt_username());

drop policy if exists al_rooms_update_participant on public.al_rooms;
create policy al_rooms_update_participant on public.al_rooms
    for update to authenticated
    using (creator = public.al_jwt_username()
           or (public.al_jwt_username() <> ''
               and participants @> jsonb_build_array(public.al_jwt_username())))
    with check (creator = public.al_jwt_username()
           or (public.al_jwt_username() <> ''
               and participants @> jsonb_build_array(public.al_jwt_username())));

-- Room signalling frames ride the same custody shape as the
-- queue: I read and retire (drain = read + remove) frames
-- addressed to me; I may only send frames that name me as sender
-- (frame "from", via al_payload_sender).
revoke all on table public.al_room_frames from authenticated;
grant select, insert, delete on table public.al_room_frames to authenticated;

drop policy if exists al_room_frames_select_own on public.al_room_frames;
create policy al_room_frames_select_own on public.al_room_frames
    for select to authenticated
    using (to_username = public.al_jwt_username());

drop policy if exists al_room_frames_insert_sender on public.al_room_frames;
create policy al_room_frames_insert_sender on public.al_room_frames
    for insert to authenticated
    with check (public.al_jwt_username() <> ''
                and public.al_payload_sender(frame)
                    = public.al_jwt_username());

drop policy if exists al_room_frames_delete_own on public.al_room_frames;
create policy al_room_frames_delete_own on public.al_room_frames
    for delete to authenticated
    using (to_username = public.al_jwt_username());

-- ------------------------------------------------------------ verify
-- After applying, an operator can confirm the perimeter with:
--   select tablename, policyname, roles, cmd
--     from pg_policies where schemaname = 'public'
--      and tablename like 'al_%' order by tablename, policyname;
-- Expected: every al_ table appears, EXCEPT the service-only set
-- (al_invites, al_alert_dispatches, al_dashboard_sessions,
-- al_grant_meta), which intentionally has no authenticated policy.
-- The service role bypasses RLS throughout and is unaffected.
