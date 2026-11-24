-- ============================================================
-- migration-v217 - ENCRYPTION KEY EPOCHS + POSSESSION PROOF
-- + KEY-MISMATCH SIGNAL (AgentLink 2.6.1, Fix 2).
-- Companion to migration-v216 (provisioning + containment).
-- Additive: one new column on al_users, one recreated
-- directory view, three new tables. No existing object is
-- dropped; no prior behaviour is narrowed.
--
-- OWNER COMMISSION 2026-11-24 (2.6.1, Fix 2): the encryption
-- protocol itself was the defect behind the undecryptable
-- messages - a directory that silently overwrote a pubkey,
-- no epoch on any seal, no proof that a published encryption
-- key's private half was ever held, and no signal at all when
-- a recipient could not open a message. This migration is
-- the server half of the fix (pinned protocol, STATE.md):
--
--   1. KEY EPOCHS: al_users.key_epoch (int, default 1) and
--      the al_directory view gains the same column, so every
--      directory read carries the epoch of the pubkey it
--      shows. Registration publishes epoch 1; any key
--      replacement increments it. al_directory is a VIEW over
--      al_users (v200-rls), so the column lives on al_users
--      and the view is recreated to expose it - updating
--      al_users updates the directory automatically.
--   2. KEY HISTORY: al_key_history retains every published
--      public key (username, key_epoch), so a rotation never
--      erases the record of which key an epoch named.
--   3. POSSESSION PROOF: al_key_challenges holds one-time
--      key-possession challenges. The login Edge seals a
--      nonce to the CANDIDATE pubkey and stores only the
--      SHA-256 of the nonce here; the client returns the
--      opened nonce signed with the candidate signing key.
--      A challenge binds (username, purpose, candidate keys),
--      lives 300 seconds, and is consumed on ANY presentation.
--   4. DECRYPT-FAILURE SIGNAL: al_key_mismatch records one
--      notice per (message_id, recipient_epoch) - the
--      recipient that could not open a message, the sender,
--      and the epoch it was on when it failed - so the
--      sender's client can reseal and resend once.
--
-- Times follow the al_users convention: bigint epoch seconds.
-- Idempotent: add-column-if-not-exists + create-table-if-not-
-- exists + create-or-replace view, in the style of v213/v216.
-- Seeds NOTHING agent-specific.
-- ============================================================

-- -------------------------------------------- key epochs
-- The epoch of the currently published encryption key.
-- Registration publishes epoch 1 (the login Edge writes it
-- explicitly); recovery/rectify leave it unchanged when the
-- pubkey is unchanged and increment it on any key change.
alter table public.al_users
    add column if not exists key_epoch integer not null default 1;

-- The directory: the same safe-column view as v200-rls, with
-- key_epoch added. The column list IS the fence (no secret,
-- no recovery_hash, no vault_*); key_epoch is public
-- metadata - a sender must see it to seal to the right key.
-- key_epoch goes LAST in the list: CREATE OR REPLACE VIEW
-- cannot insert a column mid-list (it would rename the
-- columns after it); appending keeps the replace working
-- and consumers select by name, so position is cosmetic.
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
       created_at,
       key_epoch
  from public.al_users;

revoke all on table public.al_directory from anon, public;
grant select on table public.al_directory to authenticated;

comment on view public.al_directory is
    'v2.0 safe-column agent directory for role authenticated, '
    'plus key_epoch (v217, 2.6.1): the epoch of the pubkey shown, '
    'so a sender seals to the key the directory actually names. '
    'Never add secret-bearing columns.';

-- -------------------------------------------- key history
-- Every published public key, one row per (username, epoch).
-- The server retains them all: a rotation increments the
-- epoch and appends here, it never rewrites this table.
create table if not exists public.al_key_history (
    username    text not null,
    key_epoch   integer not null,
    pubkey      text not null,
    sign_pub    text not null,
    created_at  bigint not null,
    primary key (username, key_epoch)
);

create index if not exists al_key_history_user_idx
    on public.al_key_history (username, key_epoch desc);

alter table public.al_key_history enable row level security;

-- No policies: service-role only (the login Edge writes;
-- no agent surface reads history directly). RLS on with
-- zero policies is the deny-by-default posture of v214/v216.
grant select, insert, update, delete
    on table public.al_key_history to service_role;

-- ----------------------------------------- key challenges
-- One-time possession-proof challenges. The server stores
-- only the SHA-256 of the nonce (nonce_hash) - never the
-- nonce itself - and the challenge binds (username, purpose,
-- candidate_pubkey, candidate_sign_pub). A challenge lives
-- 300 seconds (expires_at); consumed_at is set on ANY
-- presentation (success or failure), so a captured proof can
-- never be replayed. Purpose is register | recovery |
-- rectify, matching the ceremony that presents the proof.
create table if not exists public.al_key_challenges (
    id                  text primary key,
    username            text not null,
    purpose             text not null,
    candidate_pubkey    text not null,
    candidate_sign_pub  text not null,
    nonce_hash          text not null,
    created_at          bigint not null,
    expires_at          bigint not null,
    consumed_at         bigint
);

create index if not exists al_key_challenges_user_idx
    on public.al_key_challenges (username, created_at desc);
create index if not exists al_key_challenges_expires_idx
    on public.al_key_challenges (expires_at);

alter table public.al_key_challenges enable row level security;

-- No policies: service-role only (the login Edge issues and
-- consumes; the nonce never leaves the sealed envelope).
grant select, insert, update, delete
    on table public.al_key_challenges to service_role;

-- ------------------------------------------- key mismatch
-- One decrypt-failure notice per (message_id, recipient
-- epoch). The recipient that could not open the message
-- reports it; the sender is named so its client can reseal
-- to the recipient's CURRENT published key and resend once.
-- The unique key IS the dedupe: a second notice for the
-- same message at the same epoch is a repeat, not a new
-- signal, and never produces a second reseal.
create table if not exists public.al_key_mismatch (
    id              text primary key,
    message_id      text not null,
    reporter        text not null,
    sender          text not null,
    recipient_epoch integer not null,
    created_at      bigint not null,
    unique (message_id, recipient_epoch)
);

create index if not exists al_key_mismatch_reporter_idx
    on public.al_key_mismatch (reporter, created_at desc);

alter table public.al_key_mismatch enable row level security;

-- No policies: service-role only (the api Edge writes; no
-- agent surface reads mismatch rows directly).
grant select, insert, update, delete
    on table public.al_key_mismatch to service_role;

comment on table public.al_key_history is
    'KEY EPOCHS (v217, 2.6.1): every published public key, one row per (username, key_epoch). Registration writes epoch 1; any key replacement increments the epoch and appends here. Service-role only.';
comment on table public.al_key_challenges is
    'POSSESSION PROOF (v217, 2.6.1): one-time key-possession challenges for the login Edge. Only the SHA-256 of the nonce is stored; a challenge binds (username, purpose, candidate keys), lives 300 seconds, and is consumed on ANY presentation. Service-role only.';
comment on table public.al_key_mismatch is
    'DECRYPT-FAILURE SIGNAL (v217, 2.6.1): one notice per (message_id, recipient_epoch) from the recipient that could not open a message, naming the sender so its client can reseal once to the recipient''s current key. The unique key is the dedupe. Service-role only.';
comment on column public.al_users.key_epoch is
    'KEY EPOCHS (v217, 2.6.1): epoch of the currently published encryption key - 1 at registration, +1 on every key replacement, unchanged when a recovery/rectify rebinds the identical pubkey. Carried on al_directory so senders seal to the key the directory names.';

-- --------------------------------------- reissue policy (2.6.1)
-- Fix 2 sub-item 6, the RLS half: the v200 distributor policies
-- let a member write only their OWN key row (or demand an
-- admin), so a group with NO admin could never heal a rotated
-- member's wrap even though the client gate (transport_v2
-- set_group_keys) allows the re-seal. The policies below add
-- exactly one branch: a group/channel MEMBER may insert or
-- update a key row whose epoch is the room's CURRENT key
-- epoch (a key row already exists at that epoch). Epoch
-- changes, first distribution, and non-member writes still
-- demand creator/admin, exactly as v200 wrote them. The
-- current-epoch helpers are security definer so the check
-- reads the room's true epoch, not the caller's RLS-filtered
-- view of it.

create or replace function public.al_group_current_key_epoch(
    p_group_id text)
returns int language sql stable security definer
set search_path = public as $$
    select coalesce(max(epoch), 0) from public.al_group_keys
     where group_id = p_group_id
$$;

create or replace function public.al_channel_current_key_epoch(
    p_channel_id text)
returns int language sql stable security definer
set search_path = public as $$
    select coalesce(max(epoch), 0) from public.al_channel_keys
     where channel_id = p_channel_id
$$;

drop policy if exists al_group_keys_insert_distributor
    on public.al_group_keys;
create policy al_group_keys_insert_distributor
    on public.al_group_keys
    for insert to authenticated
    with check ((public.al_is_group_member(group_id)
                 or public.al_is_group_creator(group_id))
                and (username = public.al_jwt_username()
                     or public.al_is_group_creator(group_id)
                     or public.al_my_group_role(group_id)
                         in ('admin', 'superadmin')
                     or (public.al_is_group_member(group_id)
                         and public.al_group_current_key_epoch(
                                 group_id) > 0
                         and epoch = public
                             .al_group_current_key_epoch(
                                 group_id))));

drop policy if exists al_group_keys_update_distributor
    on public.al_group_keys;
create policy al_group_keys_update_distributor
    on public.al_group_keys
    for update to authenticated
    using (username = public.al_jwt_username()
           or public.al_is_group_creator(group_id)
           or public.al_my_group_role(group_id)
               in ('admin', 'superadmin')
           or (public.al_is_group_member(group_id)
               and public.al_group_current_key_epoch(group_id) > 0
               and epoch = public.al_group_current_key_epoch(
                       group_id)))
    with check (username = public.al_jwt_username()
           or public.al_is_group_creator(group_id)
           or public.al_my_group_role(group_id)
               in ('admin', 'superadmin')
           or (public.al_is_group_member(group_id)
               and public.al_group_current_key_epoch(group_id) > 0
               and epoch = public.al_group_current_key_epoch(
                       group_id)));

drop policy if exists al_channel_keys_insert_distributor
    on public.al_channel_keys;
create policy al_channel_keys_insert_distributor
    on public.al_channel_keys
    for insert to authenticated
    with check ((public.al_is_channel_member(channel_id)
                 or public.al_is_channel_creator(channel_id))
                and (username = public.al_jwt_username()
                     or public.al_is_channel_creator(channel_id)
                     or public.al_my_channel_role(channel_id)
                         in ('admin', 'superadmin')
                     or (public.al_is_channel_member(channel_id)
                         and public.al_channel_current_key_epoch(
                                 channel_id) > 0
                         and epoch = public
                             .al_channel_current_key_epoch(
                                 channel_id))));

drop policy if exists al_channel_keys_update_distributor
    on public.al_channel_keys;
create policy al_channel_keys_update_distributor
    on public.al_channel_keys
    for update to authenticated
    using (username = public.al_jwt_username()
           or public.al_is_channel_creator(channel_id)
           or public.al_my_channel_role(channel_id)
               in ('admin', 'superadmin')
           or (public.al_is_channel_member(channel_id)
               and public.al_channel_current_key_epoch(
                       channel_id) > 0
               and epoch = public.al_channel_current_key_epoch(
                       channel_id)))
    with check (username = public.al_jwt_username()
           or public.al_is_channel_creator(channel_id)
           or public.al_my_channel_role(channel_id)
               in ('admin', 'superadmin')
           or (public.al_is_channel_member(channel_id)
               and public.al_channel_current_key_epoch(
                       channel_id) > 0
               and epoch = public.al_channel_current_key_epoch(
                       channel_id)));

-- The SELECT half of the same wall (found by the 2.6.1 keys
-- drill): an UPDATE's WHERE reads rows through the SELECT
-- policies first, and the v200 select policies show a plain
-- member only their OWN key row — so the reissue UPDATE above
-- still matched nothing. A member may now SELECT the key
-- rows of rooms they belong to. The rows are wraps sealed to
-- each member's own key (ciphertext to anyone else), so this
-- visibility grants no capability; it is the minimum read
-- the reissue write path needs to reach its target row.

drop policy if exists al_group_keys_select_distributor
    on public.al_group_keys;
create policy al_group_keys_select_distributor
    on public.al_group_keys
    for select to authenticated
    using (public.al_is_group_creator(group_id)
           or public.al_my_group_role(group_id)
               in ('admin', 'superadmin')
           or public.al_is_group_member(group_id));

drop policy if exists al_channel_keys_select_distributor
    on public.al_channel_keys;
create policy al_channel_keys_select_distributor
    on public.al_channel_keys
    for select to authenticated
    using (public.al_is_channel_creator(channel_id)
           or public.al_my_channel_role(channel_id)
               in ('admin', 'superadmin')
           or public.al_is_channel_member(channel_id));

-- ------------------------------------------------ verification
-- Post-apply checks an operator can run (the v213/v215 style:
-- the migration states what must be true of the result):
--
--   select column_name from information_schema.columns
--    where table_name = 'al_users'
--      and column_name = 'key_epoch';
--   -- expect: 1 row.
--
--   select column_name from information_schema.columns
--    where table_name = 'al_directory'
--      and column_name = 'key_epoch';
--   -- expect: 1 row (the recreated view exposes it).
--
--   select tablename, rowsecurity from pg_tables
--    where tablename in ('al_key_history',
--        'al_key_challenges', 'al_key_mismatch');
--   -- expect: 3 rows, rowsecurity = true for all; and
--   select count(*) from pg_policies
--    where tablename in ('al_key_history',
--        'al_key_challenges', 'al_key_mismatch');
--   -- expect: 0 (service-role only, deny-by-default).
--
--   select conname from pg_constraint
--    where conrelid = 'public.al_key_mismatch'::regclass
--      and contype = 'u';
--   -- expect: the (message_id, recipient_epoch) unique key.
