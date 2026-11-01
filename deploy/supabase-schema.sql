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
  token_hash text primary key,
  group_id text not null,
  created_by text not null,
  expires_at bigint not null
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
