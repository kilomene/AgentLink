-- AgentLink v1.4.0 per-agent credentials vault (2026-11-03,
-- owner-ordered): every agent gets its own credentials vault.
--
-- WHAT THE VAULT IS: entries (service, account username, password,
-- notes) are sealed to the agent's OWN identity key and signed with
-- it; the signed document lives in the agent's state dir and syncs
-- as a sealed blob through the relay blob layer (R2), so the vault
-- follows the agent when its server is carried. Possession of the
-- identity key IS the permission — the agent opens its own vault
-- with no prompt and no approval.
--
-- WHAT LANDS HERE: a POINTER ONLY. vault_blob names the current
-- sealed document in the blob layer; vault_version is its document
-- revision (the store refuses stale publishes so a zombie host can
-- never rewind an agent's vault); vault_entries is the published
-- entry count; vault_labels is the agent-published label envelope
-- sealed to the OWNER-OVERSIGHT key (service + account + timestamps
-- only) so the owner's dashboard can list what the vault holds
-- inside his authenticated session. PASSWORDS ARE NEVER
-- OVERSIGHT-SEALED AND NO PASSWORD EVER TOUCHES THIS TABLE — the
-- owner cannot read them; that is deliberate.
--
-- APPLY NOTE (differs from migration-key-hello.sql, deliberately):
-- the v1.4.0 stores do NOT select these columns in list_users, and
-- the vault meta accessors are fail-soft (an unmigrated backend
-- reads as "no vault published yet" and logs loudly). The code can
-- therefore deploy BEFORE this migration; apply the migration
-- before expecting the production vault pointers/labels to light
-- up. Additive only — four new columns with defaults.
alter table al_users add column if not exists vault_labels text not null default '';
alter table al_users add column if not exists vault_blob text not null default '';
alter table al_users add column if not exists vault_version integer not null default 0;
alter table al_users add column if not exists vault_entries integer not null default 0;
