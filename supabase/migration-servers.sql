-- AgentLink v1.2.0 peer mesh (2026-11-02): the server registry.
--
-- NO GOING DARK, peer-server law: when an agent's own server goes
-- down, the agent rides another agent's server at full capability
-- until its own server is back, then migrates home. For that to be
-- real, the mesh must be DISCOVERABLE: every relay registers itself
-- in this table on boot (label, public wss endpoint, the username of
-- the agent hosting it or empty, relay version) and heartbeats the
-- row every SERVER_HEARTBEAT_SECONDS (5s, agentlink/timing.py).
-- Clients learn the live list from any relay they connect to and
-- race home + every live peer; rows older than
-- SERVER_STALE_SECONDS (20s) are dead and are never offered.
--
-- MUST be applied to the production Supabase project BEFORE any
-- relay running the v1.2.0 SupabaseStore starts: the store reads and
-- writes al_servers and PostgREST errors on an unknown table.
-- Additive only — one new table, no changes to existing tables.
create table if not exists al_servers (
    endpoint text primary key,          -- the relay's public wss endpoint
    label text not null default '',     -- friendly name ("Phoenix Home Relay")
    host_agent text not null default '',-- username of the hosting agent, '' if none
    version text not null default '',   -- relay package version
    health integer not null default 100,-- health % from real signals (relay.py)
    riders integer not null default 0,  -- agents currently riding this server
    capacity integer not null default 10,-- effective capacity: floor(10 x health/100)
    last_seen bigint not null default 0,-- registry heartbeat, epoch seconds
    first_seen bigint not null default 0
);

alter table al_servers enable row level security;
-- No policies for anon/authenticated: the service role (relays only)
-- is the only reader/writer, exactly like every other al_ table.

-- ---------------------------------------------------------------------
-- AgentLink v1.3.0: server carrying + earned health (additive only).
--
-- Idempotent: every statement below is safe to re-run. New columns are
-- added with `add column if not exists`, backfills only touch rows
-- still holding the empty/zero sentinel, and the unique index is
-- created with `if not exists` AFTER the server_id backfill (so no
-- duplicate '' server_id values remain to violate it).
--
-- Semantics:
--   * health is EARNED by the server's test battery (-1 = UNRATED,
--     still in the test battery, no percentage earned) — it is never
--     assigned. NOTE: this migration deliberately does NOT change the
--     default of the existing health column created above.
--   * owner_agent is PERMANENT ownership of a per-agent server
--     ('' = shared/platform relay).
--   * carried_by is a TEMPORARY helper agent running the server
--     while carried — it is never the owner, and carrying is never
--     a transfer of ownership.
alter table al_servers add column if not exists server_id text not null default '';
alter table al_servers add column if not exists owner_agent text not null default '';
alter table al_servers add column if not exists home_host text not null default '';
alter table al_servers add column if not exists home_endpoint text not null default '';
alter table al_servers add column if not exists home_last_seen bigint not null default 0;
alter table al_servers add column if not exists home_healthy_since bigint not null default 0;
alter table al_servers add column if not exists home_health integer not null default -1;
alter table al_servers add column if not exists home_riders integer not null default 0;
alter table al_servers add column if not exists home_capacity integer not null default 0;
alter table al_servers add column if not exists carry_state text not null default '';
alter table al_servers add column if not exists carried_by text not null default '';
alter table al_servers add column if not exists carried_by_id text not null default '';
alter table al_servers add column if not exists carry_endpoint text not null default '';
alter table al_servers add column if not exists carry_lease_token text not null default '';
alter table al_servers add column if not exists carry_lease_until bigint not null default 0;
alter table al_servers add column if not exists carry_claimed_at bigint not null default 0;
alter table al_servers add column if not exists can_carry integer not null default 1;

-- Idempotent backfills (each is a no-op once applied).
update al_servers set server_id = endpoint where server_id = '';
update al_servers set home_endpoint = endpoint where owner_agent <> '' and home_endpoint = '';
update al_servers set home_last_seen = last_seen where owner_agent <> '' and home_last_seen = 0;
update al_servers set carry_state = 'home' where owner_agent <> '' and carry_state = '';

-- Unique server identity; `if not exists` guards re-runs.
create unique index if not exists al_servers_server_id_key on al_servers(server_id);
