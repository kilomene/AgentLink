-- AgentLink production schema for Supabase (Postgres).
-- Mirrors the SQLite dev/test schema table-for-table so the two
-- backends have identical semantics. Content columns hold ciphertext
-- only; owner secrets are stored as SHA-256 hashes; no private keys
-- exist in the database at all.
-- Files do NOT live in Supabase (owner storage split): Supabase is the
-- database + realtime layer only. File ciphertext lives in Cloudflare
-- R2, proxied exclusively by the relay; the blobs table here is only
-- the relay's access-control manifest for those R2 objects.

create table if not exists users (
  username text primary key,
  secret text not null,
  display_name text not null default '',
  pubkey text not null default '',
  created_at bigint not null
);
create table if not exists queue (
  seq bigint generated always as identity primary key,
  to_username text not null,
  payload text not null,
  ts bigint not null
);
create index if not exists idx_queue_to on queue(to_username, seq);
create table if not exists groups (
  id text primary key,
  name text not null,
  creator text not null,
  settings text not null,
  created_at bigint not null
);
create table if not exists group_members (
  group_id text not null,
  username text not null,
  role text not null default 'member',
  nickname text not null default '',
  custom_role text not null default '',
  added_by text not null default '',
  joined_at bigint not null,
  primary key (group_id, username)
);
create table if not exists group_keys (
  group_id text not null,
  username text not null,
  epoch int not null,
  wrapped text not null,
  primary key (group_id, username)
);
create table if not exists invites (
  token text primary key,
  group_id text not null,
  created_by text not null,
  created_at bigint not null
);
create table if not exists work (
  id text primary key,
  assigner text not null,
  assignee text not null,
  group_id text,
  content_enc text not null default '',
  content_self text not null default '',
  deadline bigint,
  status text not null default 'assigned',
  created_at bigint not null,
  updated_at bigint not null
);
create index if not exists idx_work_assignee on work(assignee, status);
create index if not exists idx_work_assigner on work(assigner, status);
create table if not exists work_deliveries (
  id text primary key,
  work_id text not null,
  deliverer text not null,
  content_enc text not null default '',
  content_self text not null default '',
  ts bigint not null
);
create table if not exists blobs (
  id text primary key,
  owner text not null,
  for_user text not null default '',
  for_group text not null default '',
  size bigint not null default 0,
  created_at bigint not null
);
create table if not exists dashboard_sessions (
  token_hash text primary key,
  created_at bigint not null,
  expires_at bigint not null
);
create table if not exists audit_log (
  seq bigint generated always as identity primary key,
  ts bigint not null,
  kind text not null,
  actor text not null default '',
  target text not null default '',
  group_id text not null default '',
  work_id text not null default '',
  status text not null default ''
);

-- v1 feature-wave additions (points 21-42): columns + new tables.
alter table users add column if not exists sign_pub text not null default '';
alter table users add column if not exists capabilities text not null default '[]';
alter table users add column if not exists cap_desc text not null default '';
alter table users add column if not exists last_seen double precision not null default 0;
alter table queue add column if not exists priority integer not null default 0;
alter table work add column if not exists content_group text;
alter table work add column if not exists batch_id text;
alter table work add column if not exists priority text not null default 'normal';
alter table work add column if not exists auto_reassign integer not null default 1;
alter table work add column if not exists assignee_role text not null default '';
alter table work add column if not exists require_approval integer not null default 0;
alter table work add column if not exists attempt integer not null default 1;
alter table work add column if not exists progress_percent integer not null default 0;
alter table work add column if not exists progress_at double precision not null default 0;
alter table work add column if not exists proof_hash text not null default '';
alter table work add column if not exists proof_ts double precision not null default 0;
alter table work add column if not exists proof_sig text not null default '';
alter table work add column if not exists proof_verified integer not null default 0;
alter table work add column if not exists chain_id text not null default '';
alter table work add column if not exists chain_step integer not null default 0;
alter table work_deliveries add column if not exists content_group text;
alter table work_deliveries add column if not exists content_next text;
alter table blobs add column if not exists for_channel text not null default '';
alter table blobs add column if not exists whole_sha text not null default '';
alter table audit_log add column if not exists priority text not null default '';
alter table audit_log add column if not exists size integer not null default 0;
alter table audit_log add column if not exists mentions text not null default '[]';
alter table audit_log add column if not exists ref_id text not null default '';
alter table audit_log add column if not exists sender_nickname text not null default '';
alter table audit_log add column if not exists sender_role text not null default '';
alter table audit_log add column if not exists sender_custom_role text not null default '';

create table if not exists channels (
  id text primary key, name text not null, creator text not null,
  created_at double precision not null);
create table if not exists channel_members (
  channel_id text not null, username text not null,
  role text not null default 'member', added_by text not null default '',
  joined_at double precision not null,
  primary key (channel_id, username));
create table if not exists channel_keys (
  channel_id text not null, username text not null,
  epoch integer not null, wrapped text not null,
  primary key (channel_id, username, epoch));
create table if not exists upload_sessions (
  id text primary key, owner text not null, blob_id text not null,
  whole_sha text not null, chunk_size integer not null,
  total_chunks integer not null, for_user text not null default '',
  for_group text not null default '',
  got text not null default '[]', created_at double precision not null);
create table if not exists work_checkpoints (
  work_id text primary key, attempt integer not null, by_user text not null,
  content_assigner text, content_group text,
  ts double precision not null);
create table if not exists alerts (
  id text primary key, kind text not null, subject text not null,
  created_at double precision not null,
  last_reminder double precision not null default 0,
  resolved integer not null default 0,
  resolved_at double precision not null default 0);
create table if not exists library (
  id text primary key, filename text not null,
  size integer not null default 0, sha256 text not null,
  sender text not null, dest_kind text not null, dest_id text not null,
  work_id text not null default '',
  created_at double precision not null);
create table if not exists vault (
  id text primary key, group_id text not null, filename text not null,
  size integer not null default 0, sha256 text not null,
  added_by text not null, blob_id text not null,
  pinned integer not null default 0,
  created_at double precision not null);
create table if not exists chains (
  id text primary key, creator text not null,
  group_id text not null default '', status text not null default 'running',
  current_step integer not null default 0,
  created_at double precision not null,
  updated_at double precision not null);
create table if not exists chain_steps (
  require_approval integer not null default 0,
  chain_id text not null, step_index integer not null,
  work_id text, target_kind text not null default 'user',
  target text not null default '', status text not null default 'pending',
  handoff text, released_at double precision,
  primary key (chain_id, step_index));
-- v1.3.0 server carrying + earned health:
--   health is EARNED by the server's test battery (-1 = UNRATED, still
--   in the test battery, no percentage earned) — never assigned.
--   owner_agent is PERMANENT ownership of a per-agent server
--   ('' = shared/platform relay); carried_by is a TEMPORARY helper
--   agent running the server while carried (never the owner) —
--   carrying is never a transfer of ownership.
create table if not exists servers (
  endpoint text primary key, label text not null default '',
  host_agent text not null default '', version text not null default '',
  health integer not null default -1, riders integer not null default 0,
  capacity integer not null default 10,
  last_seen double precision not null default 0,
  first_seen double precision not null default 0,
  server_id text not null default '',
  owner_agent text not null default '',
  home_host text not null default '',
  home_endpoint text not null default '',
  home_last_seen bigint not null default 0,
  home_healthy_since bigint not null default 0,
  home_health integer not null default -1,
  home_riders integer not null default 0,
  home_capacity integer not null default 0,
  carry_state text not null default '',
  carried_by text not null default '',
  carried_by_id text not null default '',
  carry_endpoint text not null default '',
  carry_lease_token text not null default '',
  carry_lease_until bigint not null default 0,
  carry_claimed_at bigint not null default 0,
  can_carry integer not null default 1);
create unique index if not exists servers_server_id_key on servers(server_id);
