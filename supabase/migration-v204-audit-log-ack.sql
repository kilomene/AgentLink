-- v2.0.4: let a conversation party mark a message row delivered.
--
-- ROOT CAUSE (proven live 2026-11-05, direct live exercise):
-- transport_v2.ack() releases custody and then PATCHes al_audit_log
-- (status -> 'delivered') through PostgREST as the authenticated
-- user. The v2.0 RLS migration granted authenticated only
-- select/insert on al_audit_log and created no UPDATE policy, so
-- EVERY ack 403s (deploy-probe ack: "PostgREST PATCH audit_log
-- HTTP 403") and no message can ever read 'delivered' on the
-- serverless transport. Same defect class as v2.0.1 (mark_read
-- 403), different arm.
--
-- FIX (narrow, two layers):
--   1. Column-scoped grant: authenticated may UPDATE only the
--      `status` column — no other column on the row can be
--      touched through PostgREST by an agent JWT.
--   2. Party-scoped policy, parallel to the select policy: the
--      caller must be the actor, the target, or a group/channel
--      member, the row must be a message kind, and the resulting
--      status must be 'delivered' (the only transition ack()
--      ever performs).
-- Service-role / Edge-function writes are unaffected (RLS bypass).
-- No client code changes: ack() already sends exactly this PATCH.

grant update (status) on table public.al_audit_log to authenticated;

drop policy if exists al_audit_log_update_delivered_party
    on public.al_audit_log;
create policy al_audit_log_update_delivered_party
    on public.al_audit_log
    for update to authenticated
    using (kind in ('message', 'group_message', 'channel_message')
           and (actor = public.al_jwt_username()
                or target = public.al_jwt_username()
                or (group_id <> ''
                    and (public.al_is_group_member(group_id)
                         or public.al_is_channel_member(group_id)))))
    with check (status = 'delivered'
                and kind in ('message', 'group_message',
                             'channel_message')
                and (actor = public.al_jwt_username()
                     or target = public.al_jwt_username()
                     or (group_id <> ''
                         and (public.al_is_group_member(group_id)
                              or public.al_is_channel_member(group_id)))));
