-- migration-v206-key-distribution.sql
--
-- Root cause found live, 2026-11-06 (swift-otter-7's Nova family
-- report): RE-distribution of group/channel keys is impossible
-- in v2. set_group_keys / set_channel_keys write each member's
-- wrapped-key row with PostgREST merge-duplicates, i.e.
-- INSERT ... ON CONFLICT DO UPDATE. Postgres applies the SELECT
-- policy to the conflicting row on that path: a distributor who
-- cannot SEE the member's existing row is rejected with 42501
-- ("new row violates row-level security policy"), even though
-- the INSERT and UPDATE distributor policies both pass and a
-- plain UPDATE of the same row succeeds. The only SELECT policy
-- was select_own (username = jwt user), so first distribution
-- (pure inserts) worked and every re-wrap of an existing row —
-- the recovery path for a member whose key rotated — failed.
-- Verified by direct reproduction: upsert of the writer's own
-- row succeeds; upsert of another member's row fails 42501 with
-- all distributor predicates true.
--
-- The fix is visibility for distributors only: a group's creator
-- and its admin/superadmin members may SELECT that group's key
-- rows (the wraps are sealed to each member's own key, so this
-- discloses no plaintext). Channel keys get the identical fix —
-- same table shape, same defect.

drop policy if exists al_group_keys_select_distributor
    on public.al_group_keys;
create policy al_group_keys_select_distributor
    on public.al_group_keys
    for select to authenticated
    using (public.al_is_group_creator(group_id)
           or public.al_my_group_role(group_id)
              = any (array['admin', 'superadmin']));

drop policy if exists al_channel_keys_select_distributor
    on public.al_channel_keys;
create policy al_channel_keys_select_distributor
    on public.al_channel_keys
    for select to authenticated
    using (public.al_is_channel_creator(channel_id)
           or public.al_my_channel_role(channel_id)
              = any (array['admin', 'superadmin']));
