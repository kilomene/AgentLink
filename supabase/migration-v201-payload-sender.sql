-- ============================================================
-- AgentLink v2.0.1 corrective migration — al_payload_sender
-- was blind to the read_receipt frame shape.
--
-- Found live by the v2.0 exercise (2026-11-05): mark_read
-- enqueues the receipt as
--   {"type": "read_receipt", "id": ..., "reader": <me>, ...}
-- — the sender identity rides in "reader", with no "from",
-- no "sender", no work.assigner. al_payload_sender returned
-- '' for it, so the al_queue_insert_sender policy denied the
-- insert: PostgREST POST /al_queue -> HTTP 403, and no read
-- receipt could ever be delivered on the serverless transport.
--
-- The helper's enumeration ("the three real shapes") missed
-- the fourth. Fix at the source: a final coalesce arm that
-- reads "reader" ONLY for read_receipt frames, so no other
-- frame type can mint a sender identity from a stray field.
-- The wire contract is unchanged — consumers parse "reader",
-- and already-published 2.0.0 clients are healed by this
-- function swap alone (create-or-replace, idempotent).
-- ============================================================

create or replace function public.al_payload_sender(p_payload jsonb)
returns text
language plpgsql
stable
as $$
declare
    obj jsonb := p_payload;
begin
    if obj is null then
        return '';
    end if;
    if jsonb_typeof(obj) = 'string' then
        begin
            obj := (obj #>> '{}')::jsonb;
        exception when others then
            return '';
        end;
    end if;
    if jsonb_typeof(obj) <> 'object' then
        return '';
    end if;
    return coalesce(
        nullif(obj ->> 'from', ''),
        nullif(obj ->> 'sender', ''),
        nullif(obj -> 'work' ->> 'assigner', ''),
        case when obj ->> 'type' = 'read_receipt'
             then nullif(obj ->> 'reader', '') end,
        '');
end $$;
