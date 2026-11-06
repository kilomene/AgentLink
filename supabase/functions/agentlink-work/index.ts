// AgentLink v2.0 — work Edge Function (coverage phase). The
// service-role seat for the work lifecycle's multi-writer
// sequences, which the Phase 1 RLS policies deliberately cannot
// express whole from an agent JWT: assignment (per-assignee
// validation + custody frames + decision-link notices), delivery
// (proof verification, cover batch, alert resolution, library
// indexing) and work actions (approval gates, chain pause /
// advance). Every route mirrors relay.py's handler check order,
// error reasons, audit kinds and frame shapes EXACTLY — the
// client cannot tell which transport answered.
//
//   All endpoints: POST, Authorization: Bearer <agent supabase_jwt>.
//   The JWT's username claim is the only identity.
//
//   POST /assign        the relay's _on_assign
//   POST /deliver       the relay's _on_deliver_work
//   POST /action        the relay's _on_work_action (+ chain
//                       pause/advance)
//   POST /chain_create  the relay's _on_chain_create (+ first
//                       step release)
//   POST /chain_cancel  the relay's _on_chain_cancel
//
// Single-writer work operations (inbox reads, progress,
// checkpoint, resume-failed) do NOT live here — they are
// PostgREST paths in the client transport, where RLS expresses
// them whole.
//
// Deploy: supabase functions deploy agentlink-work
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_JWT_SECRET, AGENTLINK_REQUIRE_OVERSIGHT (optional).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  bearerToken,
  errorResponse,
  jsonResponse,
  methodGuard,
  normalizeUsername,
  nowSeconds,
  verifyAgentJwt,
  verifyEd25519,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const ADMIN_ROLES = ["admin", "superadmin"];
const PRIORITY_WEIGHT: Record<string, number> = {
  normal: 0,
  high: 1,
  urgent: 2,
};
const WORK_TRANSITIONS: Record<string, string[]> = {
  assigned: ["in_progress", "delivered", "awaiting_approval",
    "covered", "awaiting_agent"],
  in_progress: ["delivered", "awaiting_approval", "covered",
    "awaiting_agent"],
  changes_requested: ["in_progress", "delivered",
    "awaiting_approval", "covered", "awaiting_agent"],
  delivered: ["completed", "changes_requested"],
  awaiting_approval: ["completed", "changes_requested"],
  awaiting_agent: ["assigned"],
  covered: [],
  completed: [],
};
const REQUIRE_OVERSIGHT =
  (Deno.env.get("AGENTLINK_REQUIRE_OVERSIGHT") ?? "") === "1";

function randomHex(n: number): string {
  const bytes = new Uint8Array(Math.ceil(n / 2));
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0"))
    .join("").slice(0, n);
}

/** protocol.new_id + the store's per-kind truncation, mirrored. */
function nid(prefix: string, total: number): string {
  return (prefix + randomHex(32)).slice(0, total);
}

function isEnvelope(x: unknown): boolean {
  return !!x && typeof x === "object" &&
    Boolean((x as Record<string, unknown>).ct);
}

/** relay._valid_oversight, verbatim (shape only). */
function validOversight(ov: unknown): boolean {
  if (!ov || typeof ov !== "object" || Array.isArray(ov)) return false;
  const o = ov as Record<string, unknown>;
  if (o.alg !== "x25519-chacha20poly1305") return false;
  return ["eph_pub", "nonce", "ct"].every(
    (k) => typeof o[k] === "string" && Boolean(o[k]),
  );
}

function oversightGate(body: Record<string, unknown>): boolean {
  if (!REQUIRE_OVERSIGHT) return true;
  return validOversight(body.oversight);
}

function parseDeadline(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return Math.trunc(v);
  if (typeof v === "string" && v) {
    const ms = Date.parse(v);
    if (Number.isFinite(ms)) return Math.trunc(ms / 1000);
  }
  return null;
}

// ------------------------------------------------------------ store reads

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

async function roleOf(groupId: string, username: string) {
  const row = await oneEq(
    "al_group_members",
    { group_id: groupId, username },
    "role",
  );
  return row ? String(row.role) : null;
}

async function membersOf(groupId: string) {
  return await selectEq("al_group_members", { group_id: groupId });
}

async function groupRow(groupId: string) {
  return await oneEq("al_groups", { id: groupId });
}

// ------------------------------------------------------------ audit + queue

async function audit(
  kind: string,
  actor: string,
  opts: {
    target?: string;
    group_id?: string;
    work_id?: string;
    status?: string;
    priority?: string;
    ref_id?: string;
    oversight?: unknown;
  } = {},
): Promise<void> {
  const oversight = opts.oversight === undefined || opts.oversight === null
    ? ""
    : (typeof opts.oversight === "string"
      ? opts.oversight
      : JSON.stringify(opts.oversight));
  const { error } = await supabase.from("al_audit_log").insert({
    ts: nowSeconds(),
    kind,
    actor,
    target: opts.target ?? "",
    group_id: opts.group_id ?? "",
    work_id: opts.work_id ?? "",
    status: opts.status ?? "",
    priority: opts.priority ?? "",
    size: 0,
    mentions: [],
    ref_id: opts.ref_id ?? "",
    sender_nickname: "",
    sender_role: "",
    sender_custom_role: "",
    oversight,
    content_envelope: "",
  });
  if (error) throw new Error("audit insert failed: " + error.message);
}

/** The custody queue insert (SupabaseStore.enqueue's shape). In
 * serverless mode the queue+signal pair is the live channel:
 * frames the relay would deliver live-only ride custody here,
 * exactly-once by the receiver's mailbox claim, so an update can
 * never be lost that the relay would have delivered. */
async function enqueue(
  toUsername: string,
  frame: Record<string, unknown>,
): Promise<void> {
  const { error } = await supabase.from("al_queue").insert({
    to_username: toUsername,
    payload: frame,
    priority: PRIORITY_WEIGHT[String(frame.priority ?? "normal")] ?? 0,
    ts: nowSeconds(),
  });
  if (error) throw new Error("queue insert failed: " + error.message);
}

// ------------------------------------------------------------ work shaping

function shapeWork(
  row: Record<string, unknown>,
  deliveries?: Record<string, unknown>[],
  checkpoint?: Record<string, unknown> | null,
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...row };
  out.content_enc = (row.content_enc ?? {}) as unknown;
  out.content_self = (row.content_self ?? {}) as unknown;
  out.content_group = (row.content_group ?? null) as unknown;
  if (deliveries !== undefined) {
    out.deliveries = deliveries.map((d) => ({
      ...d,
      content_enc: d.content_enc ?? {},
      content_self: d.content_self ?? {},
      content_group: d.content_group ?? null,
      content_next: d.content_next ?? null,
    }));
  }
  if (checkpoint !== undefined && checkpoint !== null) {
    out.checkpoint = checkpoint;
  }
  return out;
}

async function getWork(
  workId: string,
): Promise<Record<string, unknown> | null> {
  const row = await oneEq("al_work", { id: workId });
  if (!row) return null;
  const { data: drows } = await supabase.from("al_work_deliveries")
    .select("*").eq("work_id", workId).order("ts", { ascending: true });
  const cp = await oneEq("al_work_checkpoints", { work_id: workId });
  return shapeWork(row, (drows ?? []) as Record<string, unknown>[], cp);
}

async function getWorkRaw(
  workId: string,
): Promise<Record<string, unknown> | null> {
  return await oneEq("al_work", { id: workId });
}

async function setWorkStatus(
  workId: string,
  status: string,
): Promise<Record<string, unknown> | null> {
  const current = await getWorkRaw(workId);
  if (!current) return null;
  const cur = String(current.status);
  const allowed = WORK_TRANSITIONS[cur] ?? [];
  if (status !== cur && !allowed.includes(status)) {
    throw new Error(`invalid transition ${cur} -> ${status}`);
  }
  const { error } = await supabase.from("al_work")
    .update({ status, updated_at: nowSeconds() })
    .eq("id", workId);
  if (error) throw new Error("work status update failed: " + error.message);
  return await getWork(workId);
}

// ------------------------------------------------------------ chains

function shapeChain(
  row: Record<string, unknown>,
  steps: Record<string, unknown>[],
): Record<string, unknown> {
  const out: Record<string, unknown> = { ...row };
  out.steps = [...steps]
    .sort((a, b) => Number(a.position) - Number(b.position))
    .map((s) => ({
      ...s,
      assignees: s.assignees ?? [],
      envelopes: s.envelopes ?? {},
      content_group: s.content_group ?? null,
      handoff: s.handoff ?? [],
    }));
  return out;
}

async function getChain(
  chainId: string,
): Promise<Record<string, unknown> | null> {
  const row = await oneEq("al_chains", { id: chainId });
  if (!row) return null;
  const steps = await selectEq("al_chain_steps", { chain_id: chainId });
  return shapeChain(row, steps);
}

async function setChainStatus(chainId: string, status: string) {
  const patch: Record<string, unknown> = {
    status,
    updated_at: nowSeconds(),
  };
  if (status === "paused") patch.paused_since = nowSeconds();
  const { error } = await supabase.from("al_chains").update(patch)
    .eq("id", chainId);
  if (error) throw new Error("chain status failed: " + error.message);
  return await getChain(chainId);
}

async function setStepStatus(
  stepId: string,
  status: string,
  workId = "",
) {
  const patch: Record<string, unknown> = { status };
  if (workId) patch.work_id = workId;
  const { error } = await supabase.from("al_chain_steps").update(patch)
    .eq("id", stepId);
  if (error) throw new Error("step status failed: " + error.message);
}

async function resolveAlerts(kind: string, subject: string) {
  const { error } = await supabase.from("al_alerts")
    .update({ status: "resolved", resolved_at: nowSeconds() })
    .eq("kind", kind).eq("subject", subject).eq("status", "open");
  if (error) throw new Error("alert resolve failed: " + error.message);
}

async function openAlert(kind: string, subject: string, detail = "") {
  const existing = await selectEq("al_alerts",
    { kind, subject, status: "open" });
  if (existing.length) return existing[0];
  const row = {
    id: nid("a-", 14),
    kind,
    subject,
    detail,
    status: "open",
    reminders: 0,
    last_reminder_at: 0,
    created_at: nowSeconds(),
    resolved_at: 0,
  };
  const { error } = await supabase.from("al_alerts").insert(row);
  if (error) throw new Error("alert insert failed: " + error.message);
  return row;
}

async function createWorkRow(
  fields: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const now = nowSeconds();
  const row = {
    id: nid("w-", 14),
    attempt: 1,
    progress_percent: 0,
    progress_at: 0,
    proof_hash: "",
    proof_ts: 0,
    proof_sig: "",
    proof_verified: 0,
    status: "assigned",
    chain_id: "",
    chain_step: 0,
    batch_id: null,
    created_at: now,
    updated_at: now,
    ...fields,
  };
  const { error } = await supabase.from("al_work").insert(row);
  if (error) throw new Error("work insert failed: " + error.message);
  return (await getWork(String(row.id)))!;
}

/** relay._release_step: create a pending step's work rows from
 * its PRE-CREATED envelopes and dispatch them instantly. */
async function releaseStep(
  chain: Record<string, unknown>,
  step: Record<string, unknown>,
): Promise<void> {
  const gid = (step.group_id as string) ||
    (chain.group_id as string) || null;
  let assignees: string[] = [...((step.assignees as string[]) ?? [])];
  const envelopes = (step.envelopes ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  if (step.target_type === "member") {
    const members = gid ? await membersOf(gid) : [];
    const now = nowSeconds();
    let pick = "";
    for (const m of members) {
      const u = String(m.username);
      if (u === chain.creator) continue;
      const act = await oneEq("al_activeness", { username: u },
        "state, beat_at");
      const alive = act &&
        (act.state === "online" || act.state === "suspect") &&
        now - Number(act.beat_at ?? 0) <= 60;
      if (alive) {
        pick = u;
        break;
      }
    }
    if (!pick) {
      const first = members.find(
        (m) => String(m.username) !== chain.creator,
      );
      if (first) pick = String(first.username);
    }
    assignees = pick ? [pick] : [];
  }
  const batchId = assignees.length > 1 ? nid("batch-", 20) : null;
  let firstWork: Record<string, unknown> | null = null;
  for (const assignee of assignees) {
    const pair = envelopes[assignee] ?? {};
    let role = "";
    if (gid) {
      const mrow = (await membersOf(gid)).find(
        (m) => m.username === assignee,
      );
      role = String(mrow?.custom_role ?? "");
    }
    const work = await createWorkRow({
      assigner: chain.creator,
      assignee,
      group_id: gid,
      content_enc: pair.enc ?? {},
      content_self: pair.self ?? pair.enc ?? {},
      content_group: step.content_group ?? null,
      deadline: step.deadline ?? null,
      batch_id: batchId,
      priority: step.priority ?? "normal",
      auto_reassign: 1,
      assignee_role: role,
      chain_id: chain.id,
      chain_step: step.position,
      require_approval: step.require_approval ? 1 : 0,
    });
    const view = { ...work, prev_deliverables: step.handoff ?? [] };
    await enqueue(assignee, {
      type: "work_assigned",
      work: view,
      chain_id: chain.id,
      chain_step: step.position,
    });
    if (!firstWork) firstWork = work;
  }
  if (firstWork) {
    await setStepStatus(String(step.id), "active",
      String(firstWork.id));
  }
}

/** relay._advance_chain: VERIFIED + ACCEPTED delivery only —
 * this runs from the complete action. A cancelled chain never
 * advances. */
async function advanceChain(work: Record<string, unknown>) {
  const chain = await getChain(String(work.chain_id));
  if (!chain || !["running", "paused"].includes(String(chain.status))) {
    return;
  }
  const steps = chain.steps as Record<string, unknown>[];
  const step = steps.find((s) => s.work_id === work.id);
  if (!step || step.status === "completed") return;
  await setStepStatus(String(step.id), "completed");
  const entries = await selectEq("al_library", { work_id: work.id });
  const handoff = entries.map((e) => ({
    library_id: e.id,
    filename: e.filename,
    sha256: e.sha256,
    size: e.size,
    sender: e.sender,
  }));
  const nxt = steps.find(
    (s) => Number(s.position) === Number(step.position) + 1,
  );
  if (!nxt) {
    await setChainStatus(String(chain.id), "completed");
    await resolveAlerts("chain_paused", String(chain.id));
    await enqueue(String(chain.creator), {
      type: "chain_event",
      event: "completed",
      chain_id: chain.id,
    });
    await audit("chain_completed", String(chain.creator), {
      group_id: String(chain.group_id ?? ""),
      status: String(chain.id),
    });
    if ((Deno.env.get("AGENTLINK_ALERT_CHAIN_COMPLETED") ?? "1") !== "0") {
      await openAlert("chain_completed", String(chain.id),
        "chain finished all steps");
    }
    return;
  }
  // set_step_handoff: the handoff list rides the next step, and
  // each library entry's chain_next extends to the next
  // assignees (the store's single-value column, set per
  // assignee — last wins, as in the store).
  const nxtAssignees = (nxt.assignees as string[]) ?? [];
  const { error } = await supabase.from("al_chain_steps")
    .update({ handoff }).eq("id", String(nxt.id));
  if (error) throw new Error("step handoff failed: " + error.message);
  for (const entry of handoff) {
    for (const nxtUser of nxtAssignees) {
      await supabase.from("al_library")
        .update({ chain_next: nxtUser })
        .eq("id", String(entry.library_id));
    }
  }
  if (chain.status === "paused") {
    await setChainStatus(String(chain.id), "running");
    await resolveAlerts("chain_paused", String(chain.id));
  }
  const fresh = await getChain(String(chain.id));
  const nxtFresh = (fresh!.steps as Record<string, unknown>[]).find(
    (s) => s.id === nxt.id,
  );
  if (nxtFresh) await releaseStep(fresh!, nxtFresh);
}

// ------------------------------------------------------------ routes

function refuse(reason: string, detail = ""): Response {
  return errorResponse(reason, detail, 400);
}

async function routeAssign(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const gid = (body.group_id as string) || null;
  let group: Record<string, unknown> | null = null;
  if (gid) {
    group = await groupRow(gid);
    if (!group) return refuse("unknown_group");
    const role = await roleOf(gid, me);
    if (role === null) return refuse("not_a_member");
    const settings = (group.settings ?? {}) as Record<string, unknown>;
    if (settings.assign_work === "admins_only" &&
        !ADMIN_ROLES.includes(role)) {
      return refuse("permission_denied",
        "only admins can assign work in this group");
    }
  }
  const targetRole = body.target_role as string | undefined;
  let batchId: string | null = null;
  if (targetRole) {
    if (!gid) {
      return refuse("bad_assign", "role assignment needs a group");
    }
    const members = await membersOf(gid!);
    const holders = members
      .filter((m) => String(m.custom_role ?? "").toLowerCase() ===
        String(targetRole).toLowerCase())
      .map((m) => String(m.username));
    if (!holders.length) {
      return refuse("empty_role",
        `nobody in this group holds the role '${targetRole}'`);
    }
    const requested = ((body.assignees as unknown[]) ?? [])
      .map((a) => normalizeUsername(a) ?? "").sort();
    if (JSON.stringify(requested) !==
        JSON.stringify([...holders].sort())) {
      return refuse("role_mismatch",
        "assignees must be exactly the current role holders");
    }
    batchId = nid("batch-", 20);
  }
  let priority = String(body.priority ?? "normal");
  if (!["normal", "high", "urgent"].includes(priority)) {
    priority = "normal";
  }
  const deadline = parseDeadline(body.deadline);
  const autoReassign = body.auto_reassign === undefined ||
      body.auto_reassign === null
    ? true
    : Boolean(body.auto_reassign);
  const requireApproval = Boolean(body.require_approval);
  const contentGroup = body.content_group ?? null;
  const envelopes = (body.envelopes ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  if ("title" in body || "instructions" in body) {
    return refuse("plaintext_not_allowed",
      "work content must be end-to-end encrypted");
  }
  if (!oversightGate(body)) {
    return refuse("oversight_required",
      "this relay requires an oversight wrap on content envelopes");
  }
  const created: Record<string, unknown>[] = [];
  const notices: Record<string, unknown>[] = [];
  for (const raw of (body.assignees as unknown[]) ?? []) {
    const assignee = normalizeUsername(raw);
    if (assignee === null || !(await userExists(assignee))) {
      return refuse("unknown_username", String(raw));
    }
    if (group !== null && (await roleOf(gid!, assignee)) === null) {
      return refuse("assignee_not_in_group", assignee);
    }
    const pair = envelopes[assignee] ?? {};
    if (!isEnvelope(pair.enc)) {
      return refuse("bad_assign",
        `missing encrypted content for ${assignee}`);
    }
    let assigneeRole = "";
    if (gid) {
      const mrow = (await membersOf(gid)).find(
        (m) => m.username === assignee,
      );
      assigneeRole = String(mrow?.custom_role ?? "");
    }
    const work = await createWorkRow({
      assigner: me,
      assignee,
      group_id: gid,
      content_enc: pair.enc,
      content_self: pair.self ?? pair.enc,
      content_group: contentGroup,
      deadline,
      batch_id: batchId,
      priority,
      auto_reassign: autoReassign ? 1 : 0,
      assignee_role: assigneeRole,
      require_approval: requireApproval ? 1 : 0,
    });
    const profile = await oneEq("al_users", { username: assignee },
      "mode, decision_link");
    const linkPending = assignee !== me && profile !== null &&
      String(profile.mode ?? "autonomous") === "autonomous" &&
      String(profile.decision_link ?? "") === "pending";
    if (linkPending) {
      const notice = {
        kind: "decision_link_pending",
        assignee,
        work_id: work.id,
        message: `@${assignee}'s connection has not declared ` +
          "a decision link — left alone, its unattended " +
          "runtime will not answer or execute work on " +
          "its own, so this work is delivered to its " +
          "connection and queues there. Nothing counts " +
          "as accepted until the agent itself delivers, " +
          "with proof.",
      };
      work.notice = notice;
      notices.push(notice);
      await enqueue(me, {
        type: "work_update",
        work,
        note: notice.message,
      });
      await audit("decision_link_notice", "system", {
        target: assignee,
        group_id: gid ?? "",
        work_id: String(work.id),
        status: "decision_link_pending",
      });
    }
    created.push(work);
    await enqueue(assignee, { type: "work_assigned", work });
    await audit("work_assigned", me, {
      target: assignee,
      group_id: gid ?? "",
      work_id: String(work.id),
      status: "assigned",
      priority,
      oversight: body.oversight,
    });
    if (requireApproval) {
      await audit("approval_gate_set", me, {
        target: assignee,
        group_id: gid ?? "",
        work_id: String(work.id),
        status: "require_approval",
        priority,
      });
    }
  }
  if (!created.length) {
    return refuse("bad_assign", "no assignees");
  }
  const out: Record<string, unknown> = { work: created };
  if (notices.length) out.notices = notices;
  return jsonResponse({ ok: true, ...out });
}

async function routeDeliver(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const work = await getWorkRaw(String(body.work_id ?? ""));
  if (!work) return refuse("unknown_work");
  if (work.assignee !== me) {
    return refuse("permission_denied",
      "only the assignee can deliver this work");
  }
  const attempt = body.attempt;
  if (attempt !== undefined && attempt !== null &&
      Number(attempt) !== Number(work.attempt ?? 1)) {
    await audit("stale_attempt_delivery", me, {
      target: String(work.assigner),
      group_id: String(work.group_id ?? ""),
      work_id: String(work.id),
      status: `attempt ${attempt}`,
    });
    return refuse("stale_attempt",
      `this assignment was reassigned; attempt ${attempt} is closed`);
  }
  if (!["assigned", "in_progress", "changes_requested"]
      .includes(String(work.status))) {
    return refuse("bad_status",
      `work is ${work.status}, cannot deliver`);
  }
  // Signed delivery proof (Ed25519): canonical payload
  // work_id|content_hash|timestamp|deliverer, verified against
  // the deliverer's REGISTERED signing key. The verdict is
  // audited either way; a bad proof is rejected.
  const proof = (body.proof ?? {}) as Record<string, unknown>;
  const canonical = new TextEncoder().encode(
    `${work.id}|${proof.hash ?? ""}|${proof.ts ?? ""}|${me}`,
  );
  const userRow = await oneEq("al_users", { username: me },
    "sign_pub");
  const signPub = String(userRow?.sign_pub ?? "");
  let verified = false;
  if (proof.sig && signPub) {
    verified = await verifyEd25519(
      signPub, canonical, String(proof.sig));
  }
  await audit("delivery_proof_verified", me, {
    target: String(work.assigner),
    group_id: String(work.group_id ?? ""),
    work_id: String(work.id),
    status: verified ? "true" : "false",
  });
  if (!verified) {
    return refuse("bad_proof",
      "delivery signature did not verify");
  }
  if ("body" in body || "files" in body) {
    return refuse("plaintext_not_allowed",
      "deliveries must be end-to-end encrypted");
  }
  if (!isEnvelope(body.content_enc)) {
    return refuse("bad_delivery",
      "missing encrypted delivery content");
  }
  if (!oversightGate(body)) {
    return refuse("oversight_required",
      "this relay requires an oversight wrap on content envelopes");
  }
  // store.add_delivery: the delivery row, the proof columns,
  // then the gated status move.
  const did = nid("d-", 14);
  const { error: derr } = await supabase.from("al_work_deliveries")
    .insert({
      id: did,
      work_id: work.id,
      deliverer: me,
      content_enc: body.content_enc,
      content_self: body.content_self ?? body.content_enc,
      content_group: body.content_group ?? null,
      content_next: body.content_next ?? null,
      ts: nowSeconds(),
    });
  if (derr) throw new Error("delivery insert failed: " + derr.message);
  const { error: perr } = await supabase.from("al_work").update({
    proof_hash: String(proof.hash ?? ""),
    proof_ts: Number(proof.ts ?? 0) || 0,
    proof_sig: String(proof.sig ?? ""),
    proof_verified: 1,
    updated_at: nowSeconds(),
  }).eq("id", String(work.id));
  if (perr) throw new Error("proof update failed: " + perr.message);
  let updated = await setWorkStatus(
    String(work.id),
    work.require_approval ? "awaiting_approval" : "delivered",
  );
  // Delivery library index: metadata only, supplied in the
  // clear envelope.
  const libraryFiles = (body.library as Record<string, unknown>[]) ??
    [];
  if (libraryFiles.length && updated?.deliveries) {
    const deliveries = updated.deliveries as Record<string, unknown>[];
    const lastDelivery = deliveries[deliveries.length - 1];
    for (const f of libraryFiles) {
      const { error } = await supabase.from("al_library").insert({
        id: nid("lib-", 16),
        delivery_id: String(lastDelivery.id),
        work_id: String(work.id),
        filename: String(f.name ?? ""),
        size: Number(f.size ?? 0) || 0,
        sha256: String(f.sha256 ?? ""),
        sender: String(work.assignee),
        to_user: String(work.assigner),
        group_id: String(work.group_id ?? ""),
        chain_next: "",
        ts: nowSeconds(),
      });
      if (error) throw new Error("library insert failed: " + error.message);
    }
    updated = await getWork(String(work.id));
  }
  await resolveAlerts("reassignment", String(work.id));
  await enqueue(String(work.assigner), {
    type: "work_update",
    work: updated,
  });
  await audit("work_delivered", me, {
    target: String(work.assigner),
    work_id: String(work.id),
    status: String(updated!.status),
    priority: String(work.priority ?? "normal"),
    oversight: body.oversight,
  });
  if (updated!.status === "awaiting_approval") {
    await audit("work_awaiting_approval", me, {
      target: String(work.assigner),
      group_id: String(work.group_id ?? ""),
      work_id: String(work.id),
      status: "awaiting_approval",
      priority: String(work.priority ?? "normal"),
    });
  }
  // Role batch: this delivery satisfies the whole batch.
  if (work.batch_id) {
    const siblings = await selectEq("al_work",
      { batch_id: work.batch_id });
    for (const sib of siblings) {
      if (String(sib.id) === String(work.id)) continue;
      if (!["assigned", "in_progress", "changes_requested"]
          .includes(String(sib.status))) continue;
      const { error } = await supabase.from("al_work").update({
        status: "covered", updated_at: nowSeconds(),
      }).eq("id", String(sib.id));
      if (error) throw new Error("cover failed: " + error.message);
      const covered = await getWork(String(sib.id));
      await enqueue(String(sib.assignee), {
        type: "work_update", work: covered, covered_by: work.id,
      });
      await enqueue(String(work.assigner), {
        type: "work_update", work: covered, covered_by: work.id,
      });
      await audit("work_covered", me, {
        target: String(sib.assignee),
        group_id: String(sib.group_id ?? ""),
        work_id: String(sib.id),
        status: "covered",
      });
    }
  }
  return jsonResponse({ ok: true, work: updated });
}

async function routeAction(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const work = await getWorkRaw(String(body.work_id ?? ""));
  if (!work) return refuse("unknown_work");
  const action = String(body.action ?? "");
  let status = "";
  const gated = work.status === "awaiting_approval";
  if (gated) {
    let isAdmin = false;
    if (work.group_id) {
      const role = await roleOf(String(work.group_id), me);
      isAdmin = role !== null && ADMIN_ROLES.includes(role);
    }
    if (work.assigner !== me && !isAdmin) {
      return refuse("permission_denied",
        "only the assigner or a group admin can decide an approval gate");
    }
    if (action === "approve" || action === "complete") {
      status = "completed";
    } else if (action === "reject" || action === "request_changes") {
      status = "changes_requested";
    } else {
      return refuse("bad_action", action);
    }
  } else {
    if (work.assigner !== me) {
      return refuse("permission_denied", "only the assigner can do that");
    }
    if (work.status !== "delivered") {
      return refuse("bad_status",
        `work is ${work.status}, not delivered`);
    }
    if (action === "complete") status = "completed";
    else if (action === "request_changes") status = "changes_requested";
    else return refuse("bad_action", action);
  }
  const updated = await setWorkStatus(String(work.id), status);
  if (gated) {
    await audit(
      status === "completed" ? "work_approved" : "work_approval_rejected",
      me, {
        target: String(work.assignee),
        group_id: String(work.group_id ?? ""),
        work_id: String(work.id),
        status,
      });
  }
  await audit("work_" + status, me, {
    target: String(work.assignee),
    work_id: String(work.id),
    status,
  });
  if (work.chain_id) {
    if (status === "changes_requested") {
      await setChainStatus(String(work.chain_id), "paused");
      await audit("chain_paused", me, {
        group_id: String(work.group_id ?? ""),
        work_id: String(work.id),
        status: String(work.chain_id),
      });
    } else if (status === "completed") {
      await advanceChain(work);
    }
  }
  await enqueue(String(work.assignee), {
    type: "work_update",
    work: updated,
    note: body.note ?? null,
  });
  return jsonResponse({ ok: true, work: updated });
}

async function routeChainCreate(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const steps = (body.steps as Record<string, unknown>[]) ?? [];
  if (!steps.length) {
    return refuse("bad_chain", "a chain needs at least one step");
  }
  const gid = (body.group_id as string) || null;
  if (gid) {
    if (!(await groupRow(gid))) return refuse("unknown_group");
    if ((await roleOf(gid, me)) === null) {
      return refuse("not_a_member");
    }
  }
  for (const st of steps) {
    for (const a of (st.assignees as unknown[]) ?? []) {
      if (!(await userExists(String(a)))) {
        return refuse("unknown_username", String(a));
      }
    }
  }
  const now = nowSeconds();
  const chainId = nid("chain-", 18);
  const { error } = await supabase.from("al_chains").insert({
    id: chainId,
    creator: me,
    group_id: gid ?? "",
    name: String(body.name ?? ""),
    status: "running",
    paused_since: 0,
    created_at: now,
    updated_at: now,
  });
  if (error) throw new Error("chain insert failed: " + error.message);
  for (let i = 0; i < steps.length; i++) {
    const st = steps[i];
    const { error: serr } = await supabase.from("al_chain_steps")
      .insert({
        id: nid("step-", 16),
        chain_id: chainId,
        position: i + 1,
        target_type: String(st.target_type ?? "user"),
        target: String(st.target ?? ""),
        group_id: String(st.group_id ?? "") || gid || "",
        assignees: st.assignees ?? [],
        envelopes: st.envelopes ?? {},
        content_group: st.content_group ?? null,
        deadline: parseDeadline(st.deadline),
        priority: String(st.priority ?? "normal"),
        require_approval: st.require_approval ? 1 : 0,
        status: "pending",
        work_id: "",
        handoff: [],
        created_at: now,
      });
    if (serr) throw new Error("step insert failed: " + serr.message);
  }
  const chain = await getChain(chainId);
  const first = (chain!.steps as Record<string, unknown>[])[0];
  await releaseStep(chain!, first);
  await audit("chain_created", me, {
    group_id: gid ?? "",
    status: chainId,
  });
  return jsonResponse({ ok: true, chain: await getChain(chainId) });
}

async function routeChainCancel(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const chain = await getChain(String(body.chain_id ?? ""));
  if (!chain) return refuse("unknown_chain");
  let isAdmin = false;
  if (chain.group_id) {
    const role = await roleOf(String(chain.group_id), me);
    isAdmin = role !== null && ADMIN_ROLES.includes(role);
  }
  if (me !== chain.creator && !isAdmin) {
    return refuse("permission_denied",
      "only the chain creator (or a group admin) can cancel a chain");
  }
  if (chain.status === "completed" || chain.status === "cancelled") {
    return refuse("bad_status", `chain is ${chain.status}`);
  }
  await setChainStatus(String(chain.id), "cancelled");
  const involved = new Set<string>([String(chain.creator)]);
  for (const st of chain.steps as Record<string, unknown>[]) {
    if (st.status === "pending") {
      await setStepStatus(String(st.id), "cancelled");
    }
    for (const a of (st.assignees as string[]) ?? []) involved.add(a);
    if (st.work_id) {
      const w = await getWorkRaw(String(st.work_id));
      if (w) involved.add(String(w.assignee));
    }
  }
  for (const user of involved) {
    if (user === me) continue;
    await enqueue(user, {
      type: "chain_event",
      event: "cancelled",
      chain_id: chain.id,
      by: me,
    });
  }
  await audit("chain_cancelled", me, {
    group_id: String(chain.group_id ?? ""),
    status: String(chain.id),
  });
  return jsonResponse({ ok: true, chain: await getChain(String(chain.id)) });
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
      "the work belongs to the JWT's agent; body username disagrees",
      403,
    );
  }
  const tail = new URL(req.url).pathname.split("/").filter(Boolean)
    .pop() ?? "";
  const route = tail === "agentlink-work" ? "" : tail;
  try {
    switch (route) {
      case "assign":
        return await routeAssign(me, body);
      case "deliver":
        return await routeDeliver(me, body);
      case "action":
        return await routeAction(me, body);
      case "chain_create":
        return await routeChainCreate(me, body);
      case "chain_cancel":
        return await routeChainCancel(me, body);
      default:
        return errorResponse(
          "not_found",
          "route must be /assign, /deliver, /action, " +
            "/chain_create or /chain_cancel",
          404,
        );
    }
  } catch (e) {
    return errorResponse(
      "work_internal",
      String(e instanceof Error ? e.message : e),
      500,
    );
  }
});
