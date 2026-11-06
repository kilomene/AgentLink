-- AgentLink v1.8.1 — the grant, corrected (owner's ruling
-- 2026-11-04): grantor attestation + the agent-initiated flow's
-- request record on al_grants, and the per-agent CONNECTOR
-- VAULT (al_agent_connectors) — the declared inventory of
-- OAuth-linked connectors the grant covers and the broker
-- gates on. Additive only: five columns with defaults + one
-- new table. Apply BEFORE the v1.8.1 code deploy, exactly as
-- prior releases.
alter table al_grants add column if not exists grantor text not null default '';
alter table al_grants add column if not exists ceremony_at bigint not null default 0;
alter table al_grants add column if not exists request_id text not null default '';
alter table al_grants add column if not exists requested_at bigint not null default 0;
alter table al_grants add column if not exists request_reason text not null default '';
create table if not exists al_agent_connectors (
    username text primary key,
    inventory text not null default '[]',
    updated_at bigint not null default 0
);
