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
