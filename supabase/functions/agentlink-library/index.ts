// AgentLink v2.0 — library Edge Function (coverage phase). The
// delivery-library reads cross users, groups and chains, so
// their visibility rule (sender OR recipient OR chain-next OR
// group member, evaluated over the newest 1000 entries) is a
// service-role computation, mirroring store.search_library /
// store.get_library_entry + relay._on_library_fetch exactly —
// including WHICH content column a caller receives (the
// recipient's copy, the sender's own copy, the chain-next copy,
// or the group copy, picked by the caller's relation to the
// delivery; the client decrypts).
//
//   POST /search   {q?, sender?, group_id?, hash_prefix?}
//                  -> {entries} (newest first, cap 100)
//   POST /fetch    {library_id} -> {entry, content}
//
//   All endpoints: POST, Authorization: Bearer <agent supabase_jwt>.
//
// Deploy: supabase functions deploy agentlink-library
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_JWT_SECRET.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  bearerToken,
  errorResponse,
  jsonResponse,
  methodGuard,
  verifyAgentJwt,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

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

async function isGroupMember(
  groupId: string,
  username: string,
): Promise<boolean> {
  if (!groupId) return false;
  if (await oneEq("al_group_members",
    { group_id: groupId, username }, "username")) {
    return true;
  }
  return (await oneEq("al_channel_members",
    { channel_id: groupId, username }, "username")) !== null;
}

function visible(
  row: Record<string, unknown>,
  me: string,
  memberGroups: Set<string>,
): boolean {
  if (row.sender === me || row.to_user === me) return true;
  if (row.chain_next && row.chain_next === me) return true;
  if (row.group_id && memberGroups.has(String(row.group_id))) {
    return true;
  }
  return false;
}

async function myGroups(me: string): Promise<Set<string>> {
  const groups = await selectEq("al_group_members",
    { username: me }, "group_id");
  const channels = await selectEq("al_channel_members",
    { username: me }, "channel_id");
  return new Set([
    ...groups.map((r) => String(r.group_id)),
    ...channels.map((r) => String(r.channel_id)),
  ]);
}

function refuse(reason: string, detail = ""): Response {
  return errorResponse(reason, detail, 400);
}

async function routeSearch(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const { data, error } = await supabase.from("al_library")
    .select("*").order("ts", { ascending: false }).limit(1000);
  if (error) throw new Error("library read failed: " + error.message);
  const memberGroups = await myGroups(me);
  const q = String(body.q ?? "").toLowerCase();
  const sender = String(body.sender ?? "");
  const groupId = String(body.group_id ?? "");
  const hashPrefix = String(body.hash_prefix ?? "");
  const out: Record<string, unknown>[] = [];
  for (const row of (data ?? []) as Record<string, unknown>[]) {
    if (!visible(row, me, memberGroups)) continue;
    if (q && !String(row.filename ?? "").toLowerCase().includes(q)) {
      continue;
    }
    if (sender && row.sender !== sender) continue;
    if (groupId && row.group_id !== groupId) continue;
    if (hashPrefix &&
        !String(row.sha256 ?? "").startsWith(hashPrefix)) {
      continue;
    }
    out.push(row);
    if (out.length >= 100) break;
  }
  return jsonResponse({ ok: true, entries: out });
}

async function routeFetch(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const entry = await oneEq("al_library",
    { id: String(body.library_id ?? "") });
  if (!entry) return refuse("unknown_library_entry");
  // store.get_library_entry's entitlement: a party of the
  // entry (sender / recipient / chain-next / group member)
  // whose work still exists.
  let entitled = entry.sender === me || entry.to_user === me ||
    (Boolean(entry.chain_next) && entry.chain_next === me);
  if (!entitled && entry.group_id) {
    entitled = await isGroupMember(String(entry.group_id), me);
  }
  const work = await oneEq("al_work",
    { id: String(entry.work_id ?? "") }, "id");
  if (!entitled || !work) return refuse("permission_denied");
  const delivery = await oneEq("al_work_deliveries",
    { id: String(entry.delivery_id ?? "") });
  if (!delivery) return refuse("unknown_library_entry");
  let content: unknown;
  if (entry.to_user === me) content = delivery.content_enc ?? {};
  else if (entry.sender === me) content = delivery.content_self ?? {};
  else if (entry.chain_next && entry.chain_next === me) {
    const next = (delivery.content_next ?? {}) as Record<
      string,
      unknown
    >;
    content = next[me] ?? {};
  } else content = delivery.content_group ?? {};
  return jsonResponse({ ok: true, entry, content });
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
  const body = await req.json().catch(() => ({})) as Record<
    string,
    unknown
  >;
  if (body.username !== undefined && body.username !== me) {
    return errorResponse(
      "identity_mismatch",
      "the library belongs to the JWT's agent; body username disagrees",
      403,
    );
  }
  const tail = new URL(req.url).pathname.split("/").filter(Boolean)
    .pop() ?? "";
  const route = tail === "agentlink-library" ? "" : tail;
  try {
    switch (route) {
      case "search":
        return await routeSearch(me, body);
      case "fetch":
        return await routeFetch(me, body);
      default:
        return errorResponse(
          "not_found", "unknown agentlink-library route", 404);
    }
  } catch (e) {
    return errorResponse(
      "library_internal",
      String(e instanceof Error ? e.message : e),
      500,
    );
  }
});
