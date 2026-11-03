-- AgentLink v1.3.9 cross-server voice rooms (2026-11-03): room
-- live state moves into the shared backend.
--
-- THE DEFECT (proven live 2026-11-03 04:57 PT): room r-17e8e7ba4480
-- was opened via the home relay; a member's join via its own
-- server was refused unknown_room. Room live state sat in each
-- relay's own memory (Relay.rooms): visible backend-wide on the
-- dashboard since v1.3.4, but not OPERABLE backend-wide — join,
-- signal and close on another relay never saw the room. The same
-- per-relay memory is what let the closed-out room linger as a
-- dashboard GHOST after its creator's connection died unclosed.
--
-- THE CURE: the v1.3.4 medicine — recorded fact in the shared
-- backend. al_rooms carries the live record (room -> group,
-- creator, participants, opened/updated stamps, closed flag);
-- every relay reads and writes room state through the store, and
-- the dashboard composes rooms from these records reconciled
-- with connection liveness. al_room_frames is the cross-relay
-- signal path: a room_signal addressed to a participant connected
-- to another relay is queued here and drained by that relay's
-- fleet scan — the store-queue pattern the message path already
-- uses. Rows are deleted on drain; undrained rows past the claim
-- window are dropped on sight.
--
-- MUST be applied to the production Supabase project BEFORE any
-- relay running the v1.3.9 SupabaseStore starts: the store reads
-- and writes al_rooms / al_room_frames and PostgREST errors on an
-- unknown table. Additive only — two new tables, no changes to
-- existing tables.
create table if not exists al_rooms (
    room_id text primary key,
    group_id text not null default '',
    creator text not null default '',
    participants jsonb not null default '[]',
    opened_at bigint not null default 0,
    updated_at bigint not null default 0,
    closed integer not null default 0
);

create table if not exists al_room_frames (
    seq bigint generated always as identity primary key,
    to_username text not null,
    frame jsonb not null,
    ts bigint not null
);
create index if not exists al_room_frames_to_idx on al_room_frames(to_username);

alter table al_rooms enable row level security;
alter table al_room_frames enable row level security;
-- No policies for anon/authenticated: the service role (relays only)
-- is the only reader/writer, exactly like every other al_ table.
