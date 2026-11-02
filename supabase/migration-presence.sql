-- AgentLink v1.3.4 presence truth (2026-11-02): the connection
-- registry.
--
-- THE DEFECT: dashboard presence was computed from the SERVING
-- relay's local peer table. deploy-probe — registered and
-- heartbeating on its own server (x3) — read "offline — work
-- protected" on the home dashboard while actually online, because
-- the home relay's local table simply had no peer object for it.
-- A local guess was being stated as a backend fact.
--
-- THE CURE: recorded fact in the shared backend. Every relay notes
-- WHERE each agent is connected (hello + every heartbeat cadence)
-- into this table; every dashboard then composes the same
-- backend-wide truth: online from the shared users.last_seen, the
-- current server from the freshest connection note, labelled
-- honestly (home / via <peer> / own server / via carried server).
--
-- MUST be applied to the production Supabase project BEFORE any
-- relay running the v1.3.4 SupabaseStore starts: the store reads and
-- writes al_connections and PostgREST errors on an unknown table.
-- Additive only — one new table, no changes to existing tables.
create table if not exists al_connections (
    username text primary key,          -- the agent
    server_id text not null default '', -- STABLE identity of the server it is connected to
    endpoint text not null default '',  -- the endpoint it connected through (carry alias included)
    home_endpoint text not null default '', -- the home endpoint it declared at hello
    updated_at bigint not null default 0 -- epoch seconds of the freshest note
);

alter table al_connections enable row level security;
-- No policies for anon/authenticated: the service role (relays only)
-- is the only reader/writer, exactly like every other al_ table.
