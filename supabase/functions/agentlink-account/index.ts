// AgentLink v2.0 — account Edge Function (coverage phase). The
// service-role seat for the account-level requests whose relay
// handlers compute over the whole registry:
//
//   POST /directory    relay._on_directory: every registered
//                      agent (the store's column set), each row
//                      completed with activeness (the Phase 3
//                      ladder over al_activeness), the COMPUTED
//                      trust score (store.compute_trust's
//                      formula, ported exactly), the decision
//                      fields and the legacy-auth flag. The
//                      relay-memory-only fields state their
//                      serverless truth: compliance core {} /
//                      core_compliant null / connection_pattern
//                      "" (a relay process's connection memory
//                      does not exist here), and the server_*
//                      fields are omitted — there are no live
//                      servers to describe in serverless mode.
//   POST /capabilities relay._on_update_capabilities: the
//                      signature over the canonical string is
//                      verified against the registered signing
//                      key before the own-row write.
//   POST /deregister   relay._on_deregister + store.remove_user:
//                      the blocker checks and the 21-step
//                      cascade, ported exactly. Conversations,
//                      audit, vault entries and created
//                      groups/channels are KEPT, as the store
//                      keeps them; blob metadata is removed but
//                      R2 bytes are kept, as the store keeps
//                      them.
//
//   All endpoints: POST, Authorization: Bearer <agent supabase_jwt>.
//
// Deploy: supabase functions deploy agentlink-account
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_JWT_SECRET.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  bearerToken,
  errorResponse,
  jsonResponse,
  methodGuard,
  nowSeconds,
  verifyAgentJwt,
  verifyEd25519,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const NON_TERMINAL_WORK_STATUSES = [
  "assigned", "in_progress", "changes_requested", "delivered",
  "awaiting_approval", "awaiting_agent",
];

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

function refuse(reason: string, detail = ""): Response {
  return errorResponse(reason, detail, 400);
}

// ------------------------------------------------------------ trust

/** store.compute_trust, ported line for line. */
async function computeTrust(username: string): Promise<number> {
  const works = await selectEq("al_work", { assignee: username },
    "status, deadline, updated_at");
  const { count: changes } = await supabase.from("al_audit_log")
    .select("seq", { count: "exact", head: true })
    .eq("kind", "work_changes_requested").eq("target", username);
  const { count: badProofs } = await supabase.from("al_audit_log")
    .select("seq", { count: "exact", head: true })
    .eq("kind", "delivery_proof_verified").eq("actor", username)
    .eq("status", "false");
  let score = 50;
  const now = nowSeconds();
  for (const r of works) {
    const status = String(r.status);
    if (status === "completed" || status === "covered") {
      score += 4;
    } else if (status === "delivered" ||
        status === "awaiting_approval") {
      score += 1;
    }
    const deadline = Number(r.deadline ?? 0);
    if (deadline) {
      if (status === "completed" &&
          Number(r.updated_at ?? 0) > deadline) {
        score -= 6;
      } else if (!["completed", "covered", "delivered",
          "awaiting_approval"].includes(status) && now > deadline) {
        score -= 6;
      }
    }
  }
  score -= 6 * (changes ?? 0);
  score -= 10 * (badProofs ?? 0);
  return Math.max(0, Math.min(100, score));
}

// ------------------------------------------------------------ directory

function decisionFields(row: Record<string, unknown>) {
  let detail: Record<string, unknown> = {};
  const raw = row.decision_link_detail;
  if (raw && typeof raw === "object") {
    detail = raw as Record<string, unknown>;
  } else if (typeof raw === "string" && raw) {
    try {
      detail = JSON.parse(raw);
    } catch {
      detail = {};
    }
  }
  const declaredRaw = String(row.decision_link ?? "");
  const declared = ["linked", "pending"].includes(declaredRaw)
    ? declaredRaw
    : "";
  const mode = String(row.mode ?? "autonomous");
  const detailMode = ["config", "in_process", "handlers",
    "convention", "none"].includes(String(detail.mode ?? ""))
    ? String(detail.mode)
    : "";
  return {
    decision_link: declared,
    decision_state: mode === "manual"
      ? "operator"
      : (declared || "undeclared"),
    decision_mode: detailMode,
    decision_verified: Boolean(detail.verified),
  };
}

async function routeDirectory(
  _me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const query = String(body.query ?? "");
  const capability = String(body.capability ?? "");
  const { data, error } = await supabase.from("al_users")
    .select(
      "username, display_name, pubkey, sign_pub, capabilities, " +
        "cap_desc, mode, decision_link, decision_link_detail, " +
        "delivery_ack, auth_method, designation, last_seen, " +
        "recovery_hash, recovery_used_at, created_at")
    .order("username", { ascending: true });
  if (error) throw new Error("directory read failed: " + error.message);
  const users: Record<string, unknown>[] = [];
  for (const raw of (data ?? []) as Record<string, unknown>[]) {
    const row: Record<string, unknown> = { ...raw };
    if (query && !String(row.username).includes(query)) continue;
    let caps: unknown = row.capabilities;
    if (typeof caps === "string") {
      try {
        caps = JSON.parse(caps);
      } catch {
        caps = [];
      }
    }
    row.capabilities = Array.isArray(caps) ? caps : [];
    if (capability &&
        !(row.capabilities as unknown[]).includes(capability)) {
      continue;
    }
    // Presentation rule (autonomy law): anything that is not an
    // explicit 'manual' presents as autonomous.
    row.mode = row.mode === "manual" ? "manual" : "autonomous";
    const act = await oneEq("al_activeness",
      { username: String(row.username) }, "state");
    row.online = act !== null &&
      (act.state === "online" || act.state === "suspect");
    row.trust_score = await computeTrust(String(row.username));
    row.core = {};
    row.core_compliant = null;
    row.connection_pattern = "";
    Object.assign(row, decisionFields(row));
    row.auth_legacy = ["secret", "resume"]
      .includes(String(row.auth_method ?? ""));
    delete row.secret;
    users.push(row);
  }
  users.sort((a, b) => {
    const ao = a.online ? 0 : 1;
    const bo = b.online ? 0 : 1;
    if (ao !== bo) return ao - bo;
    return String(a.username).localeCompare(String(b.username));
  });
  return jsonResponse({ ok: true, users });
}

// ------------------------------------------------------------ capabilities

async function routeCapabilities(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const caps = ((body.capabilities as unknown[]) ?? [])
    .map((c) => String(c));
  const desc = String(body.description ?? "");
  const sig = String(body.sig ?? "");
  const userRow = await oneEq("al_users", { username: me },
    "sign_pub");
  const canonical = new TextEncoder().encode(
    `caps|${me}|${caps.join(",")}|${desc}`);
  const ok = sig && userRow?.sign_pub
    ? await verifyEd25519(
      String(userRow.sign_pub), canonical, sig).catch(() => false)
    : false;
  if (!ok) {
    return refuse("bad_signature",
      "capability declaration did not verify");
  }
  const { error } = await supabase.from("al_users").update({
    capabilities: JSON.stringify(caps),
    cap_desc: desc,
  }).eq("username", me);
  if (error) throw new Error("capabilities update failed: " + error.message);
  return jsonResponse({
    ok: true, capabilities: caps, description: desc,
  });
}

// ------------------------------------------------------------ deregister

async function countWhere(
  table: string,
  build: (q: any) => any,
): Promise<number> {
  const { count, error } = await build(
    supabase.from(table).select("*", { count: "exact", head: true }));
  if (error) throw new Error(table + " count failed: " + error.message);
  return count ?? 0;
}

async function removalBlockers(me: string): Promise<string[]> {
  const blockers: string[] = [];
  const queued = await countWhere("al_queue",
    (q: any) => q.eq("to_username", me));
  if (queued) {
    blockers.push(`${queued} undelivered frame(s) in the offline queue`);
  }
  const { data: works } = await supabase.from("al_work")
    .select("id")
    .or(`assignee.eq.${me},assigner.eq.${me}`)
    .in("status", NON_TERMINAL_WORK_STATUSES);
  if ((works ?? []).length) {
    blockers.push(
      `${(works ?? []).length} non-terminal work item(s) as ` +
        "assigner/assignee");
  }
  const liveChains = await countWhere("al_chains", (q: any) =>
    q.eq("creator", me).in("status", ["running", "paused"]));
  if (liveChains) {
    blockers.push(`${liveChains} live chain(s) created by this agent`);
  }
  // Live steps in OTHER agents' chains that target this agent.
  const { data: liveRows } = await supabase.from("al_chains")
    .select("id").in("status", ["running", "paused"])
    .neq("creator", me);
  const liveIds = new Set(
    (liveRows ?? []).map((r: any) => String(r.id)));
  let stepHits = 0;
  if (liveIds.size) {
    const { data: steps } = await supabase.from("al_chain_steps")
      .select("chain_id, target, assignees")
      .in("status", ["pending", "active"]);
    for (const s of (steps ?? []) as Record<string, unknown>[]) {
      if (!liveIds.has(String(s.chain_id))) continue;
      const assignees = (s.assignees as unknown[]) ?? [];
      if (s.target === me || assignees.includes(me)) stepHits++;
    }
  }
  if (stepHits) {
    blockers.push(
      `${stepHits} live chain step(s) in other agents' chains ` +
        "target this agent");
  }
  return blockers;
}

async function deleteWhere(
  table: string,
  match: Record<string, unknown>,
): Promise<number> {
  const { data, error } = await supabase.from(table).delete()
    .match(match).select();
  if (error) throw new Error(table + " delete failed: " + error.message);
  return (data ?? []).length;
}

async function routeDeregister(
  me: string,
): Promise<Response> {
  const userRow = await oneEq("al_users", { username: me },
    "username");
  if (!userRow) return refuse("unknown_username");
  const blockers = await removalBlockers(me);
  if (blockers.length) {
    return refuse("deregister_blocked", blockers.join("; "));
  }
  // store._removal_steps, predicate for predicate, in order;
  // every step is recorded (zeros included), as the store
  // records them. KEPT deliberately (not in the cascade):
  // al_audit_log, created groups/channels, al_vault entries,
  // R2 blob bytes. Two store predicates have no Supabase
  // column — work_checkpoints.by_user and invites.created_by
  // do not exist in the al_ schema — so those steps run on
  // their surviving predicate / record 0, exactly what the
  // columns allow.
  const removed: Record<string, number> = {};
  const { data: workRows } = await supabase.from("al_work")
    .select("id").or(`assignee.eq.${me},assigner.eq.${me}`);
  const workIds = (workRows ?? []).map((w: any) => String(w.id));
  const myChains = await selectEq("al_chains", { creator: me },
    "id");
  const chainIds = myChains.map((c) => String(c.id));
  const deleteIn = async (
    table: string,
    column: string,
    ids: string[],
  ): Promise<number> => {
    if (!ids.length) return 0;
    const { data, error } = await supabase.from(table).delete()
      .in(column, ids).select();
    if (error) {
      throw new Error(table + " delete failed: " + error.message);
    }
    return (data ?? []).length;
  };
  const deleteOr = async (
    table: string,
    orClause: string,
  ): Promise<number> => {
    const { data, error } = await supabase.from(table).delete()
      .or(orClause).select();
    if (error) {
      throw new Error(table + " delete failed: " + error.message);
    }
    return (data ?? []).length;
  };
  removed.work_deliveries =
    (await deleteIn("al_work_deliveries", "work_id", workIds)) +
    await deleteWhere("al_work_deliveries", { deliverer: me });
  removed.work_checkpoints = await deleteIn(
    "al_work_checkpoints", "work_id", workIds);
  removed.work = await deleteIn("al_work", "id", workIds);
  removed.chain_steps = await deleteIn(
    "al_chain_steps", "chain_id", chainIds);
  removed.chains = await deleteIn("al_chains", "id", chainIds);
  removed.queue = await deleteWhere("al_queue",
    { to_username: me });
  removed.message_reads = await deleteWhere("al_message_reads",
    { reader: me });
  removed.group_keys = await deleteWhere("al_group_keys",
    { username: me });
  removed.group_members = await deleteWhere("al_group_members",
    { username: me });
  removed.channel_keys = await deleteWhere("al_channel_keys",
    { username: me });
  removed.channel_members = await deleteWhere(
    "al_channel_members", { username: me });
  removed.invites = 0; // no created_by column in al_invites
  removed.upload_sessions = await deleteOr(
    "al_upload_sessions", `owner.eq.${me},for_user.eq.${me}`);
  removed.alerts = await deleteWhere("al_alerts", { subject: me });
  removed.blobs = await deleteOr(
    "al_blobs", `owner.eq.${me},for_user.eq.${me}`);
  removed.library = await deleteOr(
    "al_library", `sender.eq.${me},to_user.eq.${me}`);
  removed.grant_approvals = await deleteWhere(
    "al_grant_approvals", { username: me });
  removed.grant_receipts = await deleteWhere(
    "al_grant_receipts", { username: me });
  removed.grants = await deleteWhere("al_grants",
    { username: me });
  removed.agent_connectors = await deleteWhere(
    "al_agent_connectors", { username: me });
  removed.users = await deleteWhere("al_users", { username: me });
  const total = Object.values(removed)
    .reduce((a, b) => a + b, 0);
  const { error } = await supabase.from("al_audit_log").insert({
    ts: nowSeconds(),
    kind: "user_removed",
    actor: me,
    target: me,
    group_id: "",
    work_id: "",
    status: `via=self;rows=${total}`,
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
  return jsonResponse({ ok: true, username: me, removed, total });
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
      "the account belongs to the JWT's agent; body username disagrees",
      403,
    );
  }
  const tail = new URL(req.url).pathname.split("/").filter(Boolean)
    .pop() ?? "";
  const route = tail === "agentlink-account" ? "" : tail;
  try {
    switch (route) {
      case "directory":
        return await routeDirectory(me, body);
      case "capabilities":
        return await routeCapabilities(me, body);
      case "deregister":
        return await routeDeregister(me);
      default:
        return errorResponse(
          "not_found", "unknown agentlink-account route", 404);
    }
  } catch (e) {
    return errorResponse(
      "account_internal",
      String(e instanceof Error ? e.message : e),
      500,
    );
  }
});
