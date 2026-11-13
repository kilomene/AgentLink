// AgentLink v2.0 — groups Edge Function (coverage phase). The
// service-role seat for group/channel administration: membership
// changes fan membership events out to every member, invite
// tokens live behind a service-only table, and the 50/1000
// capacity caps are count-then-insert application logic — none
// of which an agent JWT can express under the Phase 1 RLS
// policies. Every route mirrors relay.py's handler check order,
// error reasons, audit kinds (only channel_create audits in the
// channel family; group changes speak through membership
// events) and event shapes EXACTLY.
//
//   All endpoints: POST, Authorization: Bearer <agent supabase_jwt>.
//   The JWT's username claim is the only identity.
//
//   Routes are named after the client frame types they serve.
//   POST /group_create     the relay's _on_group_create
//   POST /group_add        _on_group_add
//   POST /group_remove     _on_group_remove (+ key cleanup)
//   POST /group_promote    _on_group_promote
//   POST /group_demote     _on_group_demote
//   POST /group_nickname   _on_group_nickname
//   POST /group_custom_role  _on_group_custom_role
//   POST /group_settings   _on_group_settings
//   POST /group_join_link  _on_group_join_link (token stored
//                          as its SHA-256; the raw token is
//                          returned ONCE, in this response)
//   POST /group_join       _on_group_join (redeem)
//   POST /channel_create   _on_channel_create
//   POST /channel_add      _on_channel_add
//   POST /channel_remove   _on_channel_remove
//   POST /channel_promote  _on_channel_promote
//   POST /channel_join_link  _on_channel_join_link
//   POST /channel_join     _on_channel_join (redeem; emits the
//                          same two events, in the same order)
//   POST /vault_pin        _on_vault_pin
//   POST /vault_remove     _on_vault_remove
//
// Reads (group_members / channel_members) and the single-writer
// vault_add / vault_list are PostgREST paths in the client
// transport, not here.
//
// Deploy: supabase functions deploy agentlink-groups
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_JWT_SECRET.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  bearerToken,
  CAP_CONTROL,
  errorResponse,
  jsonResponse,
  methodGuard,
  normalizeUsername,
  normalizeUsernameList,
  nowSeconds,
  randomTokenUrlSafe,
  rateLimitRefusal,
  readJsonBody,
  sha256Hex,
  suspendedRefusal,
  verifyAgentJwt,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const ADMIN_ROLES = ["admin", "superadmin"];
const MAX_GROUP_MEMBERS = 50;
const MAX_CHANNEL_SUBSCRIBERS = 1000;
const INVITE_TTL_SECONDS = 7 * 24 * 3600;
const GROUP_SETTINGS_KEYS = [
  "send_messages",
  "add_members",
  "assign_work",
  "vault_add",
];

function randomHex(n: number): string {
  const bytes = new Uint8Array(Math.ceil(n / 2));
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0"))
    .join("").slice(0, n);
}

function shortId(prefix: string): string {
  return prefix + randomHex(12);
}

async function selectEq(
  table: string,
  match: Record<string, unknown>,
  columns = "*",
): Promise<Record<string, unknown>[]> {
  let q = supabase.from(table).select(columns);
  for (const [k, v] of Object.entries(match)) q = q.eq(k, v);
  const { data, error } = await q;
  if (error) throw new Error(table + " select failed: " + error.message);
  return (data ?? []) as Record<string, unknown>[];
}

async function oneEq(
  table: string,
  match: Record<string, unknown>,
  columns = "*",
): Promise<Record<string, unknown> | null> {
  const rows = await selectEq(table, match, columns);
  return rows.length ? rows[0] : null;
}

async function userExists(username: string): Promise<boolean> {
  return (await oneEq("al_users", { username }, "username")) !== null;
}

async function enqueue(
  toUsername: string,
  frame: Record<string, unknown>,
): Promise<void> {
  const { error } = await supabase.from("al_queue").insert({
    to_username: toUsername,
    payload: frame,
    priority: 0,
    ts: nowSeconds(),
  });
  if (error) throw new Error("queue insert failed: " + error.message);
}

async function audit(
  kind: string,
  actor: string,
  groupId: string,
  status = "",
): Promise<void> {
  const { error } = await supabase.from("al_audit_log").insert({
    ts: nowSeconds(),
    kind,
    actor,
    target: "",
    group_id: groupId,
    work_id: "",
    status,
    priority: "",
    size: 0,
    mentions: [],
    ref_id: "",
    sender_nickname: "",
    sender_role: "",
    sender_custom_role: "",
    oversight: "",
    content_envelope: "",
  });
  if (error) throw new Error("audit insert failed: " + error.message);
}

// ------------------------------------------------------------ group helpers

async function groupRow(gid: string) {
  return await oneEq("al_groups", { id: gid });
}

async function groupMembers(gid: string) {
  return await selectEq("al_group_members", { group_id: gid });
}

async function groupMember(gid: string, username: string) {
  return await oneEq("al_group_members",
    { group_id: gid, username });
}

function memberView(rows: Record<string, unknown>[]) {
  return rows.map((r) => ({
    username: r.username,
    role: r.role,
    nickname: r.nickname ?? "",
    custom_role: r.custom_role ?? "",
    added_by: r.added_by ?? "",
    joined_at: r.joined_at,
  }));
}

/** relay._membership_event: the event frame goes to every
 * CURRENT member except the actor, post-change member list
 * attached. */
async function membershipEvent(
  group: Record<string, unknown>,
  event: string,
  actor: string,
  target: string,
  targets?: string[],
) {
  const members = await groupMembers(String(group.id));
  const frame: Record<string, unknown> = {
    type: "group_event",
    id: group.id,
    group_id: group.id,
    group_name: group.name,
    event,
    actor,
    target,
    ts: nowSeconds(),
    members: memberView(members),
  };
  if (targets !== undefined) frame.targets = targets;
  for (const m of members) {
    const u = String(m.username);
    if (u === actor) continue;
    await enqueue(u, frame);
  }
  return frame;
}

async function channelRow(cid: string) {
  return await oneEq("al_channels", { id: cid });
}

async function channelMembers(cid: string) {
  return await selectEq("al_channel_members", { channel_id: cid });
}

async function channelMember(cid: string, username: string) {
  return await oneEq("al_channel_members",
    { channel_id: cid, username });
}

function subscriberView(rows: Record<string, unknown>[]) {
  return rows.map((r) => ({
    username: r.username,
    role: r.role,
    added_by: r.added_by ?? "",
    joined_at: r.joined_at,
  }));
}

async function channelEvent(
  channel: Record<string, unknown>,
  event: string,
  actor: string,
  target: string,
  targets?: string[],
) {
  const members = await channelMembers(String(channel.id));
  const frame: Record<string, unknown> = {
    type: "channel_event",
    id: channel.id,
    channel_id: channel.id,
    channel_name: channel.name,
    event,
    actor,
    target,
    ts: nowSeconds(),
    members: subscriberView(members),
  };
  if (targets !== undefined) frame.targets = targets;
  for (const m of members) {
    const u = String(m.username);
    if (u === actor) continue;
    await enqueue(u, frame);
  }
  return frame;
}

function refuse(reason: string, detail = ""): Response {
  return errorResponse(reason, detail, 400);
}

function settingsOf(group: Record<string, unknown>) {
  return (group.settings ?? {}) as Record<string, unknown>;
}

// ------------------------------------------------------------ group routes

async function routeCreate(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const name = String(body.name ?? "").slice(0, 80);
  if (!name) return refuse("bad_group", "a group needs a name");
  const members = normalizeUsernameList(body.members) ?? [];
  for (const m of members) {
    if (!(await userExists(m))) return refuse("unknown_username", m);
  }
  const gid = shortId("g-");
  const now = nowSeconds();
  const settings: Record<string, string> = {
    send_messages: "everyone",
    add_members: "everyone",
    assign_work: "everyone",
    vault_add: "everyone",
  };
  const { error } = await supabase.from("al_groups").insert({
    id: gid,
    name,
    creator: me,
    key_epoch: 0,
    settings,
    created_at: now,
  });
  if (error) throw new Error("group insert failed: " + error.message);
  const { error: merr } = await supabase.from("al_group_members")
    .insert({
      group_id: gid,
      username: me,
      role: "superadmin",
      nickname: "",
      custom_role: "",
      added_by: me,
      joined_at: now,
    });
  if (merr) throw new Error("creator insert failed: " + merr.message);
  const added: string[] = [];
  for (const m of members) {
    if (m === me) continue;
    const rows = await groupMembers(gid);
    if (rows.length >= MAX_GROUP_MEMBERS) {
      return refuse("group_full",
        "groups are capped at 50 agents");
    }
    const { error: aerr } = await supabase.from("al_group_members")
      .insert({
        group_id: gid,
        username: m,
        role: "member",
        nickname: "",
        custom_role: "",
        added_by: me,
        joined_at: now,
      });
    if (aerr) throw new Error("member insert failed: " + aerr.message);
    added.push(m);
  }
  const group = (await groupRow(gid))!;
  await membershipEvent(group, "added_to_group", me, me, added);
  return jsonResponse({
    ok: true,
    group_id: gid,
    name,
    members: memberView(await groupMembers(gid)),
  });
}

async function routeAdd(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const gid = String(body.group_id ?? "");
  const group = await groupRow(gid);
  if (!group) return refuse("unknown_group");
  const myRow = await groupMember(gid, me);
  if (!myRow) return refuse("not_a_member");
  if (settingsOf(group).add_members === "admins_only" &&
      !ADMIN_ROLES.includes(String(myRow.role))) {
    return refuse("permission_denied",
      "only admins can add members in this group");
  }
  const targets = normalizeUsernameList(
    body.members ?? body.usernames) ?? [];
  for (const t of targets) {
    if (!(await userExists(t))) return refuse("unknown_username", t);
  }
  const added: string[] = [];
  for (const t of targets) {
    if (await groupMember(gid, t)) continue; // already a member
    const rows = await groupMembers(gid);
    if (rows.length >= MAX_GROUP_MEMBERS) {
      return refuse("group_full",
        "groups are capped at 50 agents");
    }
    const { error } = await supabase.from("al_group_members").insert({
      group_id: gid,
      username: t,
      role: "member",
      nickname: "",
      custom_role: "",
      added_by: me,
      joined_at: nowSeconds(),
    });
    if (error) throw new Error("member insert failed: " + error.message);
    added.push(t);
  }
  await membershipEvent(group, "added_to_group", me, me, added);
  return jsonResponse({
    ok: true,
    group_id: gid,
    added,
    members: memberView(await groupMembers(gid)),
  });
}

async function routeRemove(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const gid = String(body.group_id ?? "");
  const group = await groupRow(gid);
  if (!group) return refuse("unknown_group");
  const target = normalizeUsername(body.username) ?? "";
  const targetRow = await groupMember(gid, target);
  if (!targetRow) return refuse("not_a_member", target);
  const myRow = await groupMember(gid, me);
  const self = target === me;
  if (!self && (!myRow || !ADMIN_ROLES.includes(String(myRow.role)))) {
    return refuse("permission_denied",
      "only admins can remove other members");
  }
  if (targetRow.role === "superadmin" && !self) {
    return refuse("permission_denied",
      "the group creator cannot be removed");
  }
  // Key cleanup first is fine, then the membership row — the
  // store deletes key material before the membership update.
  await supabase.from("al_group_keys").delete()
    .eq("group_id", gid).eq("username", target);
  const { error } = await supabase.from("al_group_members").delete()
    .eq("group_id", gid).eq("username", target);
  if (error) throw new Error("member delete failed: " + error.message);
  const frame: Record<string, unknown> = {
    type: "group_event",
    id: gid,
    group_id: gid,
    group_name: group.name,
    event: "removed_from_group",
    actor: me,
    target,
    ts: nowSeconds(),
    members: memberView(await groupMembers(gid)),
  };
  await enqueue(target, frame);
  await membershipEvent(group, "member_removed", me, target, [target]);
  return jsonResponse({
    ok: true,
    group_id: gid,
    members: memberView(await groupMembers(gid)),
  });
}

async function routePromoteDemote(
  me: string,
  body: Record<string, unknown>,
  demote: boolean,
): Promise<Response> {
  const gid = String(body.group_id ?? "");
  const group = await groupRow(gid);
  if (!group) return refuse("unknown_group");
  const myRow = await groupMember(gid, me);
  if (!myRow || myRow.role !== "superadmin") {
    return refuse("permission_denied",
      "only the group creator can change admin roles");
  }
  const target = normalizeUsername(body.username) ?? "";
  const targetRow = await groupMember(gid, target);
  if (!targetRow) return refuse("not_a_member", target);
  const { error } = await supabase.from("al_group_members")
    .update({ role: demote ? "member" : "admin" })
    .eq("group_id", gid).eq("username", target);
  if (error) throw new Error("role update failed: " + error.message);
  await membershipEvent(
    group, demote ? "demoted" : "promoted", me, target, [target]);
  return jsonResponse({
    ok: true,
    group_id: gid,
    members: memberView(await groupMembers(gid)),
  });
}

async function routeNickname(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const gid = String(body.group_id ?? "");
  const group = await groupRow(gid);
  if (!group) return refuse("unknown_group");
  const target = normalizeUsername(body.username) ?? me;
  const myRow = await groupMember(gid, me);
  const targetRow = await groupMember(gid, target);
  if (!myRow || !targetRow) return refuse("not_a_member");
  if (target !== me && !ADMIN_ROLES.includes(String(myRow.role))) {
    return refuse("permission_denied",
      "only admins can set another member's nickname");
  }
  const nickname = String(body.nickname ?? "").slice(0, 48);
  const { error } = await supabase.from("al_group_members")
    .update({ nickname }).eq("group_id", gid).eq("username", target);
  if (error) throw new Error("nickname update failed: " + error.message);
  await membershipEvent(group, "nickname_changed", me, target,
    [target]);
  return jsonResponse({
    ok: true,
    group_id: gid,
    username: target,
    members: memberView(await groupMembers(gid)),
  });
}

async function routeCustomRole(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const gid = String(body.group_id ?? "");
  const group = await groupRow(gid);
  if (!group) return refuse("unknown_group");
  const myRow = await groupMember(gid, me);
  if (!myRow || !ADMIN_ROLES.includes(String(myRow.role))) {
    return refuse("permission_denied",
      "only admins can set custom roles");
  }
  const target = normalizeUsername(body.username) ?? "";
  const targetRow = await groupMember(gid, target);
  if (!targetRow) return refuse("not_a_member", target);
  const customRole = String(body.custom_role ?? "").slice(0, 48);
  const { error } = await supabase.from("al_group_members")
    .update({ custom_role: customRole })
    .eq("group_id", gid).eq("username", target);
  if (error) throw new Error("custom role failed: " + error.message);
  await membershipEvent(group, "custom_role_changed", me, target,
    [target]);
  return jsonResponse({
    ok: true,
    group_id: gid,
    username: target,
    members: memberView(await groupMembers(gid)),
  });
}

async function routeSettings(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const gid = String(body.group_id ?? "");
  const group = await groupRow(gid);
  if (!group) return refuse("unknown_group");
  const myRow = await groupMember(gid, me);
  if (!myRow || !ADMIN_ROLES.includes(String(myRow.role))) {
    return refuse("permission_denied",
      "only admins can change group settings");
  }
  const merged: Record<string, unknown> = { ...settingsOf(group) };
  const incoming = (body.settings ?? {}) as Record<string, unknown>;
  for (const key of GROUP_SETTINGS_KEYS) {
    const value = incoming[key];
    if (value === "everyone" || value === "admins_only") {
      merged[key] = value;
    }
  }
  const { error } = await supabase.from("al_groups")
    .update({ settings: merged }).eq("id", gid);
  if (error) throw new Error("settings update failed: " + error.message);
  const fresh = (await groupRow(gid))!;
  await membershipEvent(fresh, "settings_changed", me, me);
  return jsonResponse({ ok: true, group_id: gid, settings: merged });
}

async function makeInvite(scopeId: string): Promise<string> {
  const token = randomTokenUrlSafe(24);
  const tokenHash = await sha256Hex(
    new TextEncoder().encode(token));
  const { error } = await supabase.from("al_invites").insert({
    group_id: scopeId,
    token_hash: tokenHash,
    created_at: nowSeconds(),
  });
  if (error) throw new Error("invite insert failed: " + error.message);
  return token;
}

async function inviteValid(
  scopeId: string,
  token: string,
): Promise<boolean> {
  if (!token) return false;
  const tokenHash = await sha256Hex(
    new TextEncoder().encode(token));
  const row = await oneEq("al_invites",
    { group_id: scopeId, token_hash: tokenHash }, "created_at");
  if (!row) return false;
  return Number(row.created_at) + INVITE_TTL_SECONDS >= nowSeconds();
}

/** store.parse_invite_link: agentlink://<scope>/<token>. */
function parseInviteLink(
  link: string,
): { scope: string; token: string } | null {
  if (!link.startsWith("agentlink://")) return null;
  const rest = link.slice("agentlink://".length);
  const slash = rest.indexOf("/");
  if (slash < 0) return null;
  const scope = rest.slice(0, slash);
  const token = rest.slice(slash + 1);
  return scope && token ? { scope, token } : null;
}

async function routeJoinLink(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const gid = String(body.group_id ?? "");
  const group = await groupRow(gid);
  if (!group) return refuse("unknown_group");
  if (!(await groupMember(gid, me))) return refuse("not_a_member");
  const token = await makeInvite(gid);
  return jsonResponse({
    ok: true,
    group_id: gid,
    token,
    link: `agentlink://${gid}/${token}`,
  });
}

async function routeJoin(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  let gid = String(body.group_id ?? "");
  let token = String(body.token ?? body.link ?? "");
  if (token.startsWith("agentlink://")) {
    const parsed = parseInviteLink(token);
    if (parsed) {
      gid = parsed.scope;
      token = parsed.token;
    }
  }
  const group = gid ? await groupRow(gid) : null;
  if (!group) return refuse("unknown_group");
  if (!(await inviteValid(gid, token))) {
    return refuse("invalid_invite");
  }
  if (!(await groupMember(gid, me))) {
    const rows = await groupMembers(gid);
    if (rows.length >= MAX_GROUP_MEMBERS) {
      return refuse("group_full",
        "groups are capped at 50 agents");
    }
    const { error } = await supabase.from("al_group_members").insert({
      group_id: gid,
      username: me,
      role: "member",
      nickname: "",
      custom_role: "",
      added_by: "invite-link",
      joined_at: nowSeconds(),
    });
    if (error) throw new Error("join insert failed: " + error.message);
  }
  await membershipEvent(group, "joined_group", me, me);
  return jsonResponse({
    ok: true,
    group_id: gid,
    members: memberView(await groupMembers(gid)),
  });
}

// ------------------------------------------------------------ channel routes

async function routeChannelCreate(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const name = String(body.name ?? "").slice(0, 80);
  if (!name) {
    return refuse("bad_channel", "a channel needs a name");
  }
  const subscribers = normalizeUsernameList(
    body.members ?? body.subscribers) ?? [];
  for (const s of subscribers) {
    if (!(await userExists(s))) return refuse("unknown_username", s);
  }
  const cid = shortId("c-");
  const now = nowSeconds();
  const { error } = await supabase.from("al_channels").insert({
    id: cid,
    name,
    creator: me,
    key_epoch: 0,
    created_at: now,
  });
  if (error) throw new Error("channel insert failed: " + error.message);
  const { error: serr } = await supabase.from("al_channel_members")
    .insert({
      channel_id: cid,
      username: me,
      role: "superadmin",
      added_by: me,
      joined_at: now,
    });
  if (serr) throw new Error("creator insert failed: " + serr.message);
  const added: string[] = [];
  for (const s of subscribers) {
    if (s === me) continue;
    const rows = await channelMembers(cid);
    if (rows.length >= MAX_CHANNEL_SUBSCRIBERS) {
      return refuse("channel_full",
        "channels are capped at 1000 subscribers");
    }
    const { error: aerr } = await supabase.from("al_channel_members")
      .insert({
        channel_id: cid,
        username: s,
        role: "subscriber",
        added_by: me,
        joined_at: now,
      });
    if (aerr) throw new Error("subscriber insert failed: " + aerr.message);
    added.push(s);
  }
  const channel = (await channelRow(cid))!;
  await channelEvent(channel, "added_to_channel", me, me, added);
  await audit("channel_created", me, cid, name);
  return jsonResponse({
    ok: true,
    channel_id: cid,
    name,
    members: subscriberView(await channelMembers(cid)),
  });
}

async function routeChannelAdd(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const cid = String(body.channel_id ?? "");
  const channel = await channelRow(cid);
  if (!channel) return refuse("unknown_channel");
  const myRow = await channelMember(cid, me);
  if (!myRow || !ADMIN_ROLES.includes(String(myRow.role))) {
    return refuse("permission_denied",
      "only channel admins can add subscribers");
  }
  const targets = normalizeUsernameList(
    body.members ?? body.usernames) ?? [];
  for (const t of targets) {
    if (!(await userExists(t))) return refuse("unknown_username", t);
  }
  const added: string[] = [];
  for (const t of targets) {
    if (await channelMember(cid, t)) continue;
    const rows = await channelMembers(cid);
    if (rows.length >= MAX_CHANNEL_SUBSCRIBERS) {
      return refuse("channel_full",
        "channels are capped at 1000 subscribers");
    }
    const { error } = await supabase.from("al_channel_members")
      .insert({
        channel_id: cid,
        username: t,
        role: "subscriber",
        added_by: me,
        joined_at: nowSeconds(),
      });
    if (error) throw new Error("subscriber insert failed: " + error.message);
    added.push(t);
  }
  await channelEvent(channel, "added_to_channel", me, me, added);
  return jsonResponse({
    ok: true,
    channel_id: cid,
    added,
    members: subscriberView(await channelMembers(cid)),
  });
}

async function routeChannelRemove(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const cid = String(body.channel_id ?? "");
  const channel = await channelRow(cid);
  if (!channel) return refuse("unknown_channel");
  const target = normalizeUsername(body.username) ?? "";
  const myRow = await channelMember(cid, me);
  const self = target === me;
  if (!self && (!myRow || !ADMIN_ROLES.includes(String(myRow.role)))) {
    return refuse("permission_denied",
      "only channel admins can remove subscribers");
  }
  // The relay performs NO not_a_member check and emits NO
  // events on this path — removal is silent there; the
  // key-row cleanup is the store's, mirrored. Silence is the
  // contract here, not an omission.
  await supabase.from("al_channel_keys").delete()
    .eq("channel_id", cid).eq("username", target);
  const { error } = await supabase.from("al_channel_members").delete()
    .eq("channel_id", cid).eq("username", target);
  if (error) throw new Error("subscriber delete failed: " + error.message);
  return jsonResponse({
    ok: true,
    channel_id: cid,
    members: subscriberView(await channelMembers(cid)),
  });
}

async function routeChannelPromote(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const cid = String(body.channel_id ?? "");
  const channel = await channelRow(cid);
  if (!channel) return refuse("unknown_channel");
  const myRow = await channelMember(cid, me);
  if (!myRow || myRow.role !== "superadmin") {
    return refuse("permission_denied",
      "only the channel creator can promote admins");
  }
  const target = normalizeUsername(body.username) ?? "";
  if (!(await channelMember(cid, target))) {
    return refuse("not_a_member", target);
  }
  const { error } = await supabase.from("al_channel_members")
    .update({ role: "admin" })
    .eq("channel_id", cid).eq("username", target);
  if (error) throw new Error("promote failed: " + error.message);
  await channelEvent(channel, "promoted", me, target, [target]);
  return jsonResponse({
    ok: true,
    channel_id: cid,
    members: subscriberView(await channelMembers(cid)),
  });
}

async function routeChannelJoinLink(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const cid = String(body.channel_id ?? "");
  const channel = await channelRow(cid);
  if (!channel) return refuse("unknown_channel");
  if (!(await channelMember(cid, me))) return refuse("not_a_member");
  const token = await makeInvite(cid);
  return jsonResponse({
    ok: true,
    channel_id: cid,
    token,
    link: `agentlink://${cid}/${token}`,
  });
}

async function routeChannelJoin(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  let cid = String(body.channel_id ?? "");
  let token = String(body.token ?? body.link ?? "");
  if (token.startsWith("agentlink://")) {
    const parsed = parseInviteLink(token);
    if (parsed) {
      cid = parsed.scope;
      token = parsed.token;
    }
  }
  const channel = cid ? await channelRow(cid) : null;
  if (!channel) return refuse("unknown_channel");
  if (!(await inviteValid(cid, token))) {
    return refuse("invalid_invite");
  }
  if (!(await channelMember(cid, me))) {
    const rows = await channelMembers(cid);
    if (rows.length >= MAX_CHANNEL_SUBSCRIBERS) {
      return refuse("channel_full",
        "channels are capped at 1000 subscribers");
    }
    const { error } = await supabase.from("al_channel_members")
      .insert({
        channel_id: cid,
        username: me,
        role: "subscriber",
        added_by: "invite-link",
        joined_at: nowSeconds(),
      });
    if (error) throw new Error("join insert failed: " + error.message);
  }
  await channelEvent(channel, "joined_channel", me, me);
  await channelEvent(channel, "subscribed_to_channel", me, me);
  return jsonResponse({
    ok: true,
    channel_id: cid,
    members: subscriberView(await channelMembers(cid)),
  });
}

// ------------------------------------------------------------ vault routes

function shapeVaultEntry(row: Record<string, unknown>) {
  return {
    id: row.id,
    group_id: row.group_id,
    name: row.name,
    size: row.size,
    sha256: row.sha256,
    blob_id: row.blob_id,
    descriptor: row.descriptor ?? {},
    added_by: row.added_by,
    pinned: Boolean(row.pinned),
    ts: row.ts,
  };
}

async function vaultAuthorize(
  me: string,
  entryId: string,
): Promise<
  { entry: Record<string, unknown> } | { error: Response }
> {
  const entry = await oneEq("al_vault", { id: entryId });
  if (!entry) return { error: refuse("unknown_vault_entry") };
  const myRow = await groupMember(String(entry.group_id), me);
  const authorized = myRow !== null &&
    (entry.added_by === me ||
      ADMIN_ROLES.includes(String(myRow.role)));
  if (!authorized) {
    return {
      error: refuse("permission_denied",
        "only the contributor or a group admin can do that"),
    };
  }
  return { entry };
}

async function routeVaultPin(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const auth = await vaultAuthorize(
    me, String(body.vault_id ?? body.entry_id ?? ""));
  if ("error" in auth) return auth.error;
  const { error } = await supabase.from("al_vault")
    .update({ pinned: body.pinned ? 1 : 0 })
    .eq("id", String(auth.entry.id));
  if (error) throw new Error("vault pin failed: " + error.message);
  const fresh = await oneEq("al_vault", { id: auth.entry.id });
  return jsonResponse({ ok: true, entry: shapeVaultEntry(fresh!) });
}

async function routeVaultRemove(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const auth = await vaultAuthorize(
    me, String(body.vault_id ?? body.entry_id ?? ""));
  if ("error" in auth) return auth.error;
  const { error } = await supabase.from("al_vault").delete()
    .eq("id", String(auth.entry.id));
  if (error) throw new Error("vault remove failed: " + error.message);
  return jsonResponse({
    ok: true,
    entry_id: auth.entry.id,
    removed: true,
  });
}

Deno.serve(async (req: Request) => {
  const guard = methodGuard(req);
  if (guard) return guard;
  const claims = await verifyAgentJwt(bearerToken(req));
  if (!claims?.username) {
    return errorResponse(
      "unauthorized", "a valid agent JWT is required", 401);
  }
  const me = claims.username;
  // Containment (2.6.0, Part 4): suspension, cap, rate.
  const suspended = await suspendedRefusal(supabase, me);
  if (suspended) return suspended;
  const parsed = await readJsonBody(req, CAP_CONTROL);
  if (parsed.response) return parsed.response;
  const body = parsed.body;
  const limited = await rateLimitRefusal(
    supabase, "groups:" + me, 300);
  if (limited) return limited;
  // Identity comes from the verified JWT ONLY (2.3.1 fix). An
  // earlier dispatcher guard here rejected any body whose
  // `username` field disagreed with the JWT — but the target
  // routes below (group_remove, group_promote, group_demote,
  // group_nickname, group_custom_role, channel_remove) take
  // their TARGET member from body.username, the same field name
  // the relay frame contract uses for the target. The guard
  // therefore made it impossible for an admin to act on another
  // member at all: every such call died as identity_mismatch
  // before its route ran (only self-targeted calls survived).
  // No route treats body.username as the caller — every handler
  // receives `me` from the JWT and enforces its own role checks
  // against it (admin-only for acting on others) — so the field
  // is a target parameter, never an identity claim.
  const tail = new URL(req.url).pathname.split("/").filter(Boolean)
    .pop() ?? "";
  const route = tail === "agentlink-groups" ? "" : tail;
  try {
    switch (route) {
      case "group_create":
        return await routeCreate(me, body);
      case "group_add":
        return await routeAdd(me, body);
      case "group_remove":
        return await routeRemove(me, body);
      case "group_promote":
        return await routePromoteDemote(me, body, false);
      case "group_demote":
        return await routePromoteDemote(me, body, true);
      case "group_nickname":
        return await routeNickname(me, body);
      case "group_custom_role":
        return await routeCustomRole(me, body);
      case "group_settings":
        return await routeSettings(me, body);
      case "group_join_link":
        return await routeJoinLink(me, body);
      case "group_join":
        return await routeJoin(me, body);
      case "channel_create":
        return await routeChannelCreate(me, body);
      case "channel_add":
        return await routeChannelAdd(me, body);
      case "channel_remove":
        return await routeChannelRemove(me, body);
      case "channel_promote":
        return await routeChannelPromote(me, body);
      case "channel_join_link":
        return await routeChannelJoinLink(me, body);
      case "channel_join":
        return await routeChannelJoin(me, body);
      case "vault_pin":
        return await routeVaultPin(me, body);
      case "vault_remove":
        return await routeVaultRemove(me, body);
      default:
        return errorResponse(
          "not_found", "unknown agentlink-groups route", 404);
    }
  } catch (e) {
    return errorResponse(
      "groups_internal",
      String(e instanceof Error ? e.message : e),
      500,
    );
  }
});
