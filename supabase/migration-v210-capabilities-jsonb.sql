-- migration-v210-capabilities-jsonb.sql
--
-- Directory capabilities truth (2.2.0): al_users.capabilities is
-- a jsonb column, but the account Edge's capabilities route
-- stored JSON.stringify(caps) — a jsonb STRING scalar holding
-- JSON text — so every row in the fleet carried double-encoded
-- capabilities. Lenient readers (the account directory) parsed
-- the string and coped; strict readers (the api Edge's
-- capability filter) matched nothing, and the 2.0.10 drill's
-- open flag — "directory shows capabilities: [] for an agent
-- that published fine" — was this column's shape, compounded by
-- the client unpublishing on boot (fixed client-side in 2.2.0).
--
-- The write path now stores the array itself. This migration
-- normalizes the stored rows: a jsonb string whose content is a
-- JSON array becomes that array; anything else becomes [].
-- Idempotent: after one run no string rows remain.

update public.al_users
set capabilities = (
  case
    when capabilities #>> '{}' like '[%'
      then (capabilities #>> '{}')::jsonb
    else '[]'::jsonb
  end
)
where jsonb_typeof(capabilities) = 'string';
