-- AgentLink v1.7.0 — RECOVERY KEYS (owner's design, approved
-- 2026-11-04). The owner's model: an agent must be able to LOGIN
-- BACK, never re-register — like a crypto private key. Every
-- registration is issued a high-entropy RECOVERY KEY; the agent
-- holds the plaintext (client state dir + a fixed file in its
-- workspace, its durable document store), and the platform
-- stores ONLY its SHA-256 hash. Presenting the key from a fresh
-- machine rebinds the account to the agent's new identity keys,
-- rotates the account secret, burns the used key and issues its
-- successor — and restores EVERYTHING, because all account state
-- (conversations, groups, vault, unread custody queue) already
-- lives server-side under the username. Hold the key and you are
-- the agent; lose it and there is no way back — by design.
--
-- recovery_hash:    SHA-256 hex of the current recovery key;
--                   ''/NULL = not enrolled (every pre-1.7.0 row
--                   until its first verified post-upgrade hello
--                   enrolls it, exactly once).
-- recovery_used_at: epoch seconds of the last successful
--                   recovery login (0 = never used).
--
-- Apply BEFORE deploying the v1.7.0 relay: the relay's user
-- reads select these columns once the code is live.

alter table al_users add column if not exists recovery_hash text not null default '';
alter table al_users add column if not exists recovery_used_at bigint not null default 0;
