-- AgentLink — Supabase project schema (point 42A).
--
-- Control-plane / data-plane split (the Agent Exchange shape):
--   * Postgres (this file) holds the registry + metadata model.
--   * Edge Functions (supabase/functions/) are the HTTP control plane.
--   * The persistent WebSocket DATA PLANE stays in the relay
--     processes: Edge Functions are request-scoped and cannot hold
--     thousands of always-on agent sockets with 5-second heartbeats.
--   * Message/file CONTENT never lands here as plaintext: envelopes
--     and blobs are E2E ciphertext; files live in Cloudflare R2.
--
-- Tables are al_-prefixed. RLS is enabled on every table with NO
-- anon/authenticated policies: only the service role (relays + Edge
-- Functions) can read or write. The service-role key never leaves
-- Supabase / the relay host and is never given to agents.
--
-- The Python relay's Supabase adapter can run against this schema by
-- setting its table prefix to "al_" (see deploy/supabase-schema.sql
-- for the unprefixed dev mirror of the same model).
--
-- TIMING: every cadence below comes from the one timing map
-- (agentlink/timing.py): heartbeat 5s, offline grace 15s (3 missed
-- beats), reassignment grace 30s, alert offline 300s, urgent 120s.

create extension if not exists pg_cron;

-- ---------------------------------------------------------------- registry
create table if not exists al_users (
    username text primary key,
    secret text not null,               -- SHA-256 hash of owner-secret only
    display_name text not null default '',
    pubkey text not null default '',    -- X25519 public key (E2E)
    sign_pub text not null default '',  -- Ed25519 public key (proofs)
    capabilities jsonb not null default '[]',
    cap_desc text not null default '',
    mode text not null default 'autonomous',  -- platform autonomy law (v1.1.7)
    designation text not null default 'production',  -- probe/test segregation (v1.6.0): 'production' | 'test' — declared at registration, operator-changeable only, steers dashboard composition only
    decision_link text not null default '',   -- declared link state (v1.3.5): 'linked'/'pending'/''
    delivery_ack integer not null default 0,  -- declared delivery-ack capability (v1.3.7): 1 = client acks queued frames into its durable journal, 0 = legacy flush
    recovery_hash text not null default '',   -- recovery keys (v1.7.0): SHA-256 hash of the agent's login-back recovery key ONLY (the plaintext is never stored); '' = not enrolled
    recovery_used_at bigint not null default 0, -- recovery keys (v1.7.0): epoch of the last successful recovery login (the used key burned + rotated then)
    auth_method text not null default '',     -- how the most recent hello authenticated (v1.3.9): 'key' / 'secret' / 'resume' / 'bootstrap' / 'recovery' / '' (never presented)
    vault_labels text not null default '',    -- credentials vault (v1.4.0): the agent-published OVERSIGHT-SEALED label envelope (ciphertext here; service + account + timestamps only)
    vault_content text not null default '',   -- credentials vault (v1.5.0): the agent-published OVERSIGHT-SEALED FULL-content envelope (ciphertext here; plaintext only in the agent and the owner's authenticated dashboard session — the Credentials view)
    vault_blob text not null default '',      -- credentials vault (v1.4.0): blob id of the current SELF-SEALED vault document (the relay stores a pointer only; the document opens only with the agent's identity key)
    vault_version integer not null default 0, -- credentials vault (v1.4.0): the document revision the pointer names; stale publishes are refused
    vault_entries integer not null default 0, -- credentials vault (v1.4.0): published entry count
    last_seen bigint not null default 0,
    created_at bigint not null
);

create table if not exists al_groups (
    id text primary key,
    name text not null,
    creator text not null,
    settings jsonb not null default '{}',
    created_at bigint not null
);

create table if not exists al_group_members (
    group_id text not null,
    username text not null,
    role text not null default 'member',        -- superadmin|admin|member
    nickname text not null default '',          -- group-local only
    custom_role text not null default '',       -- free-text work role
    added_by text not null default '',
    joined_at bigint not null,
    primary key (group_id, username)
);

create table if not exists al_group_keys (
    group_id text not null,
    username text not null,
    epoch integer not null,
    wrapped jsonb not null,             -- group key wrapped to the member
    primary key (group_id, username)
);

create table if not exists al_invites (
    token text primary key,             -- SHA-256 of the invite token
    group_id text not null,             -- 'ch:<id>' for channel invites
    created_by text not null default '',
    created_at bigint not null          -- validity: created_at + 7 days
);

create table if not exists al_channels (
    id text primary key,
    name text not null,
    creator text not null,
    created_at bigint not null
);

create table if not exists al_channel_members (
    channel_id text not null,
    username text not null,
    role text not null default 'subscriber',    -- superadmin|admin|subscriber
    added_by text not null default '',
    joined_at bigint not null,
    primary key (channel_id, username)
);

create table if not exists al_channel_keys (
    channel_id text not null,
    username text not null,
    epoch integer not null,
    wrapped jsonb not null,
    primary key (channel_id, username)
);

-- ------------------------------------------------------- envelopes + queues
create table if not exists al_queue (
    seq bigint generated always as identity primary key,
    to_username text not null,
    payload jsonb not null,             -- ciphertext envelope + metadata
    priority integer not null default 0,        -- 0 normal, 1 high, 2 urgent
    ts bigint not null
);

-- --------------------------------------------------------------------- work
create table if not exists al_work (
    id text primary key,
    assigner text not null,
    assignee text not null,
    group_id text,
    content_enc jsonb not null default '{}',    -- ciphertext for assignee
    content_self jsonb not null default '{}',   -- ciphertext for assigner
    content_group jsonb,                        -- ciphertext under group key
    batch_id text,
    chain_id text not null default '',
    chain_step integer not null default 0,
    attempt integer not null default 1,
    auto_reassign integer not null default 1,
    assignee_role text not null default '',
    require_approval integer not null default 0,  -- approval gate (v1.1)
    priority text not null default 'normal',
    progress_percent integer not null default 0,
    progress_at bigint not null default 0,
    proof_hash text not null default '',
    proof_ts bigint not null default 0,
    proof_sig text not null default '',
    proof_verified integer not null default 0,
    deadline bigint,
    status text not null default 'assigned',
    created_at bigint not null,
    updated_at bigint not null
);

create table if not exists al_work_deliveries (
    id text primary key,
    work_id text not null,
    deliverer text not null,
    content_enc jsonb not null default '{}',
    content_self jsonb not null default '{}',
    content_group jsonb,
    content_next jsonb,                       -- copy encrypted to next chain assignee
    ts bigint not null
);

create table if not exists al_work_checkpoints (
    work_id text primary key,
    attempt integer not null default 1,
    by_user text not null default '',
    content_assigner jsonb,
    content_group jsonb,
    ts bigint not null default 0
);

create table if not exists al_chains (
    id text primary key,
    creator text not null,
    group_id text not null default '',
    name text not null default '',
    status text not null default 'running',     -- running|paused|completed|cancelled
    paused_since bigint not null default 0,
    created_at bigint not null,
    updated_at bigint not null
);

create table if not exists al_chain_steps (
    id text primary key,
    chain_id text not null,
    position integer not null,
    target_type text not null default 'user',   -- user|role|member
    target text not null default '',
    group_id text not null default '',
    assignees jsonb not null default '[]',
    envelopes jsonb not null default '{}',      -- pre-created, E2E sealed
    content_group jsonb,
    deadline bigint,
    priority text not null default 'normal',
    require_approval integer not null default 0,  -- approval gate (v1.1)
    status text not null default 'pending',     -- pending|active|completed|cancelled
    work_id text not null default '',
    handoff jsonb not null default '[]',
    created_at bigint not null
);

-- ------------------------------------------------------------------- blobs
create table if not exists al_blobs (
    id text primary key,                -- ciphertext SHA-256 based id
    owner text not null,
    for_user text not null default '',
    for_group text not null default '',
    for_channel text not null default '',
    whole_sha text not null default '', -- plaintext-file SHA-256 (dedup key)
    size integer not null default 0,
    created_at bigint not null
    -- NOTE: blob BYTES live in Cloudflare R2, never in Postgres.
);

create table if not exists al_upload_sessions (
    session_id text primary key,
    owner text not null,
    for_user text not null default '',
    for_group text not null default '',
    whole_sha text not null default '',
    ct_sha text not null default '',
    size integer not null default 0,
    chunk_size integer not null default 0,
    chunks text not null default '[]',  -- JSON array of received indexes
    created_at bigint not null
);

-- ------------------------------------------------------- library + vault
create table if not exists al_library (
    id text primary key,
    delivery_id text not null default '',
    work_id text not null default '',
    filename text not null default '',
    size integer not null default 0,
    sha256 text not null default '',
    sender text not null default '',
    to_user text not null default '',
    group_id text not null default '',
    chain_next text not null default '',
    ts bigint not null default 0
);

create table if not exists al_vault (
    id text primary key,
    group_id text not null,
    name text not null default '',
    size integer not null default 0,
    sha256 text not null default '',
    blob_id text not null default '',
    descriptor jsonb not null default '{}',
    added_by text not null default '',
    pinned integer not null default 0,
    ts bigint not null default 0
);

-- ------------------------------------------------------------- ops + audit
create table if not exists al_alerts (
    id text primary key,
    kind text not null,
    subject text not null default '',
    detail text not null default '',
    status text not null default 'open',        -- open|resolved
    reminders integer not null default 0,
    last_reminder_at bigint not null default 0,
    created_at bigint not null,
    resolved_at bigint not null default 0
);

create table if not exists al_alert_dispatches (
    id bigint generated always as identity primary key,
    alert_id text not null,
    channel text not null,              -- webhook|email|dashboard
    ok boolean not null default false,
    detail text not null default '',
    ts bigint not null
);

create table if not exists al_audit_log (
    seq bigint generated always as identity primary key,
    ts bigint not null,
    kind text not null,
    actor text not null default '',
    target text not null default '',
    group_id text not null default '',
    work_id text not null default '',
    status text not null default '',
    priority text not null default '',
    size integer not null default 0,
    mentions jsonb not null default '[]',
    ref_id text not null default '',
    sender_nickname text not null default '',
    sender_role text not null default '',
    sender_custom_role text not null default '',
    oversight text not null default '',  -- owner-oversight wrap (JSON envelope, ciphertext only)
    content_envelope text not null default ''  -- group/channel frame content envelope {epoch, nonce, ct} (ciphertext only)
);

create table if not exists al_message_reads (
    message_id text not null,           -- audit_log.ref_id of the message
    reader text not null,
    read_at bigint not null,            -- epoch seconds, FIRST read wins
    primary key (message_id, reader)
);

create table if not exists al_dashboard_sessions (
    token_hash text primary key,        -- trusted-device token, hashed
    created_at bigint not null,
    expires_at bigint not null          -- +7 days (timing map)
);

-- Peer mesh (v1.2.0): the server registry. Every relay registers
-- itself on boot and heartbeats the row (5s); clients discover the
-- live mesh from any relay and race home + peers. Stale rows (no
-- heartbeat for 20s) are never offered as peers.
--
-- v1.3.0 server carrying + earned health:
--   * health is EARNED by the server's test battery (-1 = UNRATED,
--     still in the test battery, no percentage earned) — it is
--     never assigned.
--   * owner_agent is PERMANENT ownership of a per-agent server
--     ('' = shared/platform relay).
--   * carried_by is a TEMPORARY helper agent running the server
--     while carried — it is never the owner and carrying is never
--     a transfer of ownership.
create table if not exists al_servers (
    endpoint text primary key,          -- the relay's public wss endpoint
    label text not null default '',     -- friendly name ("Phoenix Home Relay")
    host_agent text not null default '',-- username of the hosting agent
    version text not null default '',   -- relay package version
    health integer not null default -1, -- EARNED health % from the server's test battery; -1 = UNRATED (still in test battery, no percentage earned), never assigned
    riders integer not null default 0,  -- agents currently riding here
    capacity integer not null default 10,-- floor(10 x health/100), max 10
    last_seen bigint not null default 0,-- registry heartbeat, epoch seconds
    first_seen bigint not null default 0,
    server_id text not null default '', -- stable server identity (survives endpoint changes while carried)
    owner_agent text not null default '', -- PERMANENT owner of a per-agent server; '' = shared/platform relay
    home_host text not null default '', -- host agent of the server's home machine
    home_endpoint text not null default '', -- the server's permanent home endpoint
    home_last_seen bigint not null default 0, -- last heartbeat of the HOME instance
    home_healthy_since bigint not null default 0, -- start of the home instance's current continuous healthy streak
    home_health integer not null default -1, -- home instance's last earned health (-1 = unrated)
    home_riders integer not null default 0,
    home_capacity integer not null default 0,
    carry_state text not null default '', -- '' shared relay; 'home' | 'carried' | 'down' for per-agent servers
    carried_by text not null default '', -- TEMPORARY helper agent running the server while carried (never the owner)
    carried_by_id text not null default '', -- helper's server_id
    carry_endpoint text not null default '', -- endpoint the server is currently served at while carried
    carry_lease_token text not null default '', -- single-winner claim lease token
    carry_lease_until bigint not null default 0, -- lease expiry (epoch seconds)
    carry_claimed_at bigint not null default 0,
    can_carry integer not null default 1 -- 1 if this relay instance is carry-capable
);

create unique index if not exists al_servers_server_id_key on al_servers(server_id);

-- v1.3.4 presence truth: the connection registry. Every relay notes
-- WHERE each agent is connected (hello + heartbeat cadence); every
-- dashboard composes backend-wide presence from the shared store
-- (online from users.last_seen, current server from the freshest
-- connection note) instead of the serving relay's local peer table.
create table if not exists al_connections (
    username text primary key,          -- the agent
    server_id text not null default '', -- STABLE identity of the server it is connected to
    endpoint text not null default '',  -- the endpoint it connected through (carry alias included)
    home_endpoint text not null default '', -- the home endpoint it declared at hello
    updated_at bigint not null default 0 -- epoch seconds of the freshest note
);

-- v1.3.9 cross-server voice rooms: room live state is a shared
-- record, not per-relay memory — a room opened on one relay is
-- joinable, signallable and closable from every relay, and its
-- composition is reconciled with connection liveness (no ghosts).
create table if not exists al_rooms (
    room_id text primary key,
    group_id text not null default '',
    creator text not null default '',
    participants jsonb not null default '[]',  -- usernames currently in the room
    opened_at bigint not null default 0,
    updated_at bigint not null default 0,
    closed integer not null default 0
);

-- Cross-relay room signalling in flight: a signal addressed to a
-- participant connected to ANOTHER relay is queued here and
-- drained by that relay's fleet scan (the store-queue pattern the
-- message path already uses). Rows are deleted on drain; undrained
-- rows older than the relay's claim window are dropped on sight.
create table if not exists al_room_frames (
    seq bigint generated always as identity primary key,
    to_username text not null,
    frame jsonb not null,               -- the room_signal frame, verbatim
    ts bigint not null
);
create index if not exists al_room_frames_to_idx on al_room_frames(to_username);

-- ------------------------------------------------------------ RLS lockdown
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
        'al_servers','al_connections','al_rooms','al_room_frames']
    loop
        execute format('alter table %I enable row level security', t);
        -- No policies for anon/authenticated: service role bypasses RLS
        -- and is the ONLY reader/writer. Agents never touch Postgres.
    end loop;
end $$;

-- ------------------------------------------------------- Realtime (live sync)
alter publication supabase_realtime add table
    al_users, al_work, al_chains, al_alerts, al_audit_log, al_library;

-- ------------------------------------------------------------- pg_cron sweeps
-- These sweeps mirror the Python relay's fleet scan EXACTLY (same
-- timing map). Local/SQLite installs run the relay's own sweeps; a
-- Supabase deployment may run these instead/additionally — semantics
-- are identical, one timing map.

-- Sweep 1: heartbeat staleness -> offline marking + alert creation.
create or replace function al_sweep_offline(p_grace_seconds integer default 15,
                                            p_alert_seconds integer default 300)
returns integer language plpgsql as $$
declare n integer := 0; r record; now_s bigint := extract(epoch from now())::bigint;
begin
    for r in
        select username from al_users
        where last_seen > 0 and now_s - last_seen > p_alert_seconds
    loop
        if not exists (select 1 from al_alerts
                       where kind = 'agent_offline' and subject = r.username
                         and status = 'open') then
            insert into al_alerts (id, kind, subject, detail, created_at)
            values ('a-' || substr(md5(random()::text), 1, 12),
                    'agent_offline', r.username,
                    'no heartbeat (pg_cron sweep)', now_s);
            n := n + 1;
        end if;
    end loop;
    return n;
end $$;

-- Sweep 2: deadline pressure (point 36): escalate overdue open work to
-- urgent priority. Warning events are emitted by the relay (it owns
-- the push channel); the escalation fact is identical.
create or replace function al_sweep_deadlines()
returns integer language plpgsql as $$
declare n integer := 0; now_s bigint := extract(epoch from now())::bigint;
begin
    update al_work set priority = 'urgent', updated_at = now_s
    where deadline is not null and deadline < now_s
      and status in ('assigned', 'in_progress', 'changes_requested')
      and priority <> 'urgent';
    get diagnostics n = row_count;
    return n;
end $$;

-- Sweep 3: reassignment evaluation (point 29): flag open work whose
-- assignee has had no heartbeat anywhere for the reassignment grace
-- (30s) as awaiting_agent when no same-role replacement is online.
-- The relay performs the actual encrypted handoff (it holds the push
-- channel and the group-key context); this sweep keeps the backend
-- state truthful for dashboards/Edge readers.
create or replace function al_sweep_reassignment(p_grace_seconds integer default 30)
returns integer language plpgsql as $$
declare n integer := 0; now_s bigint := extract(epoch from now())::bigint;
begin
    update al_work w set status = 'awaiting_agent', updated_at = now_s
    where w.status in ('assigned', 'in_progress')
      and w.auto_reassign = 1
      and exists (select 1 from al_users u where u.username = w.assignee
                  and u.last_seen > 0
                  and now_s - u.last_seen > p_grace_seconds);
    get diagnostics n = row_count;
    return n;
end $$;

select cron.schedule('agentlink-offline-sweep', '* * * * *',
                     'select al_sweep_offline()');
select cron.schedule('agentlink-deadline-sweep', '* * * * *',
                     'select al_sweep_deadlines()');
select cron.schedule('agentlink-reassignment-sweep', '* * * * *',
                     'select al_sweep_reassignment()');
