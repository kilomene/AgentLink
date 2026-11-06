-- migration-v207-rectification.sql
--
-- Two server guarantees for the 2.0.6 rectification (owner order,
-- 2026-11-06: no message may sit invisible or unreadable):
--
-- 1. al_attach_oversight(p_ref_id, p_oversight): the RECEIVER-side
--    oversight attach. A sender on an old client ships no
--    oversight wrap, so the owner's dashboard could not read the
--    message ("sealed"). The receiving agent — which legitimately
--    decrypts the message — may attach the wrap it computes,
--    exactly once, only while the row carries none. SECURITY
--    DEFINER so the function can pin the change to the oversight
--    column alone (no general UPDATE policy is widened): the
--    caller must be the row's addressee (DM) or a member of the
--    row's group/channel; the row must be a content row; an
--    existing wrap is never overwritten.
--
-- 2. al_reconcile_doorbell_outbox(): delivery reconciliation. A
--    send from an old client could write the audit row without
--    the custody queue row (and without any wakeup), leaving the
--    message at status 'sent' forever — the recipient never
--    fetches what it cannot see. Every minute this sweep finds
--    recent content rows (last 7 days) whose recipients hold no
--    custody frame for them and rebuilds the exact delivery the
--    current send path performs: one al_queue custody row per
--    recipient carrying the reconstructed message frame, plus one
--    al_doorbell_outbox row per recipient whose INSERT fires the
--    existing doorbell-tap webhook. Idempotent: a recipient who
--    already holds the frame is skipped, and once every recipient
--    holds it the audit row is never touched again.

create or replace function public.al_attach_oversight(
    p_ref_id text, p_oversight text)
returns boolean
language plpgsql
security definer
set search_path to 'public'
as $$
declare
    me text := public.al_jwt_username();
    r record;
    n integer := 0;
begin
    if me = '' or p_ref_id = '' or coalesce(p_oversight, '') = '' then
        return false;
    end if;
    select * into r from public.al_audit_log
     where ref_id = p_ref_id
       and kind in ('message', 'group_message', 'channel_message')
       and (oversight is null or oversight = '')
     limit 1;
    if not found then
        return false;
    end if;
    if not (r.target = me
            or (r.group_id <> ''
                and (public.al_is_group_member(r.group_id)
                     or public.al_is_channel_member(r.group_id)))) then
        return false;
    end if;
    update public.al_audit_log
       set oversight = p_oversight
     where ref_id = p_ref_id
       and (oversight is null or oversight = '');
    get diagnostics n = row_count;
    return n > 0;
end $$;

grant execute on function public.al_attach_oversight(text, text)
    to authenticated;

create or replace function public.al_reconcile_doorbell_outbox(
    p_window_seconds integer default 604800)
returns integer
language plpgsql
security definer
set search_path to 'public'
as $$
declare
    n integer := 0;
    added integer := 0;
    now_s bigint := extract(epoch from now())::bigint;
    r record;
    m record;
    frame jsonb;
begin
    for r in
        select * from public.al_audit_log
         where kind in ('message', 'group_message', 'channel_message')
           and status = 'sent'
           and coalesce(content_envelope, '') <> ''
           and ts > now_s - p_window_seconds
         order by ts asc
    loop
        -- recipients: the DM target, or every group/channel
        -- member except the sender.
        for m in
            select username from (
                select r.target as username
                 where r.kind = 'message' and coalesce(r.target, '') <> ''
                union all
                select gm.username
                  from public.al_group_members gm
                 where r.kind = 'group_message'
                   and gm.group_id = r.group_id
                   and gm.username <> r.actor
                union all
                select cm.username
                  from public.al_channel_members cm
                 where r.kind = 'channel_message'
                   and cm.channel_id = r.group_id
                   and cm.username <> r.actor
            ) recipients
        loop
            if exists (select 1 from public.al_queue q
                        where q.to_username = m.username
                          and q.payload ->> 'id' = r.ref_id) then
                continue;
            end if;
            -- Per-recipient guard: one malformed stored row must
            -- never poison the whole sweep (it runs every minute).
            begin
                frame := jsonb_build_object(
                    'type', 'message',
                    'id', r.ref_id,
                    'from', r.actor,
                    'from_name', '',
                    'from_pubkey', '',
                    'sender_nickname', coalesce(r.sender_nickname, ''),
                    'sender_role', coalesce(r.sender_role, ''),
                    'sender_custom_role', coalesce(r.sender_custom_role, ''),
                    'oversight', case when coalesce(r.oversight, '') <> ''
                                      then r.oversight::jsonb else null end,
                    'mentions', coalesce(r.mentions, '[]'::jsonb),
                    'priority', r.priority,
                    'content', r.content_envelope::jsonb,
                    'ts', r.ts,
                    'in_reply_to', null,
                    'group_id', case when r.kind = 'message' then null
                                     else r.group_id end,
                    'group_name', '');
                insert into public.al_queue (to_username, payload, priority, ts)
                values (m.username, frame,
                        case r.priority when 'high' then 1
                                        when 'urgent' then 2 else 0 end,
                        now_s);
                insert into public.al_doorbell_outbox (id, username, ref, kind, ts, tapped)
                values ('db-' || substr(md5(random()::text || r.ref_id || m.username), 1, 16),
                        m.username, r.ref_id, r.kind, now_s, false);
                added := added + 1;
            exception when others then
                continue;
            end;
        end loop;
    end loop;
    return added;
end $$;

select cron.schedule('agentlink-v200-doorbell-reconcile', '* * * * *',
                     'select public.al_reconcile_doorbell_outbox()')
where not exists (select 1 from cron.job
                  where jobname = 'agentlink-v200-doorbell-reconcile');
