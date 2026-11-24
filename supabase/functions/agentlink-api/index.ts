// AgentLink control-plane API (point 42A) — Supabase Edge Function.
//
// HTTP control plane for the OPERATOR's surfaces: dashboard data,
// directory/capability search, alert listing, and metadata-only
// operator actions (revoke a trusted dashboard device).
//
// HARD RULE: this function receives and returns METADATA ONLY. It
// never sees message/file contents — E2E ciphertext moves exclusively
// through the relay WebSocket data plane. Requests require the
// operator's dashboard bearer (checked against al_dashboard_sessions
// token hashes) except /health and the agent route below.
//
// AGENT ROUTE (2.6.1, Fix 2, v217): POST /key_mismatch is
// AGENT-authenticated (the agent JWT, the account/liveness/groups
// pattern: verifyAgentJwt, then the suspension switch, then the
// durable per-agent rate layer) - NOT operator-authenticated.
// A recipient that cannot open a message reports it here:
// the Edge verifies an audit row kind=message with this
// ref_id and the caller as its target (the reporter must be
// the message's recipient), records one al_key_mismatch row
// per (message_id, recipient_epoch) - the unique key IS the
// dedupe, a repeat answers {ok:true, deduped:true} - writes
// one audit row kind=key_mismatch (NOT a content kind; the
// dashboard CONTENT_KINDS are untouched), and enqueues an
// RTDB transit-inbox frame to the SENDER so its client can
// reseal to the recipient's CURRENT published key and resend
// once. The frame rides the same mechanism DM delivery uses:
// PUT /inbox/<sender>/<item_id> = {frame, expires_at, ts}
// (doorbell.py put_inbox's shape), written with a Google
// OAuth2 token minted from the service account, exactly as
// the doorbell Edge writes its taps. The frame's node key is
// deterministic (km-<message_id>-<epoch>), so a repeat
// delivery overwrites the same node instead of duplicating
// it - a deduped repeat still re-attempts the frame. A frame
// that cannot land is a 502: the record already landed, so a
// retry answers deduped and delivers the frame then.
//
// Deploy: supabase functions deploy agentlink-api
// Secrets: SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY are injected by
// the platform; the service key never leaves Supabase.
// FIREBASE_SERVICE_ACCOUNT_JSON + FIREBASE_DATABASE_URL are the
// doorbell Edge's RTDB secrets, reused here for the inbox frame.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { isOffline, TIMING } from "../_shared/rules.ts";
import {
  bearerToken,
  CAP_CONTROL,
  env,
  escapeIlike,
  mintGoogleAccessToken,
  rateLimitRefusal,
  readJsonBody,
  sanitizeKey,
  selectOne,
  suspendedRefusal,
  verifyAgentJwt,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function authed(req: Request): Promise<boolean> {
  const token = (req.headers.get("authorization") ?? "").replace(
    /^Bearer\s+/i,
    "",
  );
  if (!token) return false;
  const { data } = await supabase
    .from("al_dashboard_sessions")
    .select("expires_at")
    .eq("token_hash", await sha256(token))
    .limit(1);
  return Boolean(data?.length) &&
    (data![0].expires_at as number) > Math.floor(Date.now() / 1000);
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

// ------------------------------------------------- RTDB inbox frame
// (2.6.1, Fix 2): the doorbell Edge's rtdb() helper, mirrored -
// a Google OAuth2 access token minted from the service account
// writes the transit inbox node, because a server leg holds no
// agent custom token. The path is doorbell.py put_inbox's:
// /inbox/<sanitized user>/<item_id>.

async function rtdb(
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<unknown> {
  const base = env("FIREBASE_DATABASE_URL").replace(/\/+$/, "");
  if (!base) {
    throw new Error("FIREBASE_DATABASE_URL is not set in this function's env");
  }
  const resp = await fetch(base + "/" + path + ".json", {
    method,
    headers: {
      authorization: "Bearer " + token,
      "content-type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error("RTDB " + method + " " + path + ": HTTP " + resp.status);
  }
  return resp.status === 204 ? null : await resp.json().catch(() => null);
}

// ------------------------------------------------- key_mismatch
// Agent route (2.6.1, Fix 2): {message_id, recipient_epoch}.
// The caller must be the message's recipient (verified
// against the audit row, one refusal shape - no oracle),
// the notice is deduped on (message_id, recipient_epoch),
// one audit row kind=key_mismatch is written (fresh only),
// and an RTDB inbox frame is enqueued to the sender.
async function routeKeyMismatch(req: Request): Promise<Response> {
  if (req.method !== "POST") {
    return json({ error: "method_not_allowed" }, 405);
  }
  const claims = await verifyAgentJwt(bearerToken(req));
  if (!claims?.username) {
    return json({ error: "unauthorized" }, 401);
  }
  const me = claims.username;
  const suspended = await suspendedRefusal(supabase, me);
  if (suspended) return suspended;
  const parsed = await readJsonBody(req, CAP_CONTROL);
  if (parsed.response) return parsed.response;
  const body = parsed.body;
  const limited = await rateLimitRefusal(
    supabase, "api:key_mismatch:" + me, 60);
  if (limited) return limited;
  const now = Math.floor(Date.now() / 1000);
  const messageId = String(body.message_id ?? "");
  const recipientEpoch = Number(body.recipient_epoch ?? 0);
  if (!messageId || !Number.isInteger(recipientEpoch) ||
      recipientEpoch < 1) {
    return json({
      error: "invalid_request",
      detail: "message_id and a recipient_epoch >= 1 are required",
    }, 400);
  }
  // Recipient verification: an audit row kind=message with
  // this ref_id must exist with the caller as its target.
  // One refusal shape for "no such message" and "not the
  // recipient" — the message id alone must not become an
  // existence oracle.
  let auditRow: Record<string, unknown> | null = null;
  try {
    auditRow = await selectOne(supabase, "al_audit_log",
      "actor, target", { kind: "message", ref_id: messageId });
  } catch (e) {
    return json({ error: String(e instanceof Error ? e.message : e) }, 500);
  }
  if (!auditRow || String(auditRow.target ?? "") !== me) {
    return json({
      error: "not_recipient",
      detail: "no message with that id was addressed to this agent",
    }, 403);
  }
  const sender = String(auditRow.actor ?? "");
  if (!sender) {
    return json({
      error: "not_recipient",
      detail: "no message with that id was addressed to this agent",
    }, 403);
  }
  // Dedupe on (message_id, recipient_epoch): the unique key
  // in al_key_mismatch. A conflict is the repeat, not an error.
  const mismatchId = "km-" + crypto.randomUUID();
  const { error: insertError } = await supabase
    .from("al_key_mismatch")
    .insert({
      id: mismatchId,
      message_id: messageId,
      reporter: me,
      sender,
      recipient_epoch: recipientEpoch,
      created_at: now,
    });
  let deduped = false;
  if (insertError) {
    if (String((insertError as { code?: unknown }).code) === "23505" ||
        /duplicate|unique/i.test(String(insertError.message))) {
      deduped = true;
    } else {
      return json({ error: insertError.message }, 500);
    }
  }
  if (!deduped) {
    // One audit row, fresh notices only: kind=key_mismatch
    // is NOT a content kind (dashboard CONTENT_KINDS
    // untouched) - it is the healing signal, with the
    // recipient epoch as its status.
    const { error: auditError } = await supabase
      .from("al_audit_log")
      .insert({
        ts: now,
        kind: "key_mismatch",
        actor: me,
        target: sender,
        group_id: "",
        work_id: "",
        status: String(recipientEpoch),
        priority: "",
        size: 0,
        mentions: [],
        ref_id: messageId,
        sender_nickname: "",
        sender_role: "",
        sender_custom_role: "",
        oversight: "",
        content_envelope: "",
      });
    if (auditError) {
      return json({ error: auditError.message }, 500);
    }
  }
  // RTDB inbox frame to the SENDER, via the same mechanism
  // DM delivery uses (doorbell.py put_inbox's node shape).
  // The node key is deterministic per (message, epoch), so a
  // repeat delivery overwrites the same node - a deduped
  // repeat still re-attempts the frame, and a 502 here is
  // retryable into exactly that path.
  const itemId = "km-" + messageId + "-" + recipientEpoch;
  try {
    const token = await mintGoogleAccessToken();
    await rtdb(token, "PUT",
      "inbox/" + sanitizeKey(sender) + "/" +
        sanitizeKey(itemId), {
        frame: {
          type: "key_mismatch",
          message_id: messageId,
          from: me,
          recipient_epoch: recipientEpoch,
        },
        expires_at: 0,
        ts: { ".sv": "timestamp" },
      });
  } catch (e) {
    console.error("key_mismatch frame delivery failed for " +
      messageId + ": " + String(e));
    return json({
      error: "key_mismatch_delivery_failed",
      detail: "the mismatch was recorded but the inbox frame " +
        "to the sender did not land; retry to deliver it",
      deduped,
    }, 502);
  }
  return json({
    ok: true,
    deduped,
    ...(deduped ? {} : { mismatch_id: mismatchId }),
  });
}

// Capabilities normalization (2.2.0): rows written before the
// account Edge's array fix carry a jsonb STRING (double-encoded
// JSON text) instead of an array. Every reader here sees the one
// true shape — an array of strings — whatever the row's vintage.
function capsArray(value: unknown): string[] {
  let caps: unknown = value;
  if (typeof caps === "string") {
    try {
      caps = JSON.parse(caps);
    } catch {
      caps = [];
    }
  }
  return Array.isArray(caps) ? caps.map((c) => String(c)) : [];
}

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^.*agentlink-api/, "") || "/";
  const now = Math.floor(Date.now() / 1000);

  if (path === "/health") {
    return json({ ok: true, service: "agentlink-api", ts: now });
  }
  // Agent route (2.6.1, Fix 2): agent-JWT auth, NOT the
  // operator bearer below - it bypasses the operator check.
  if (path === "/key_mismatch") {
    return await routeKeyMismatch(req);
  }
  if (!(await authed(req))) {
    return json({ error: "unauthorized" }, 401);
  }

  // Agent wall: presence (heartbeat-derived), activity + metadata.
  if (path === "/agents") {
    const { data } = await supabase.from("al_users")
      .select(
        "username, display_name, capabilities, cap_desc, last_seen, created_at",
      )
      .order("username");
    const users = (data ?? []).map((u) => ({
      ...u,
      capabilities: capsArray(u.capabilities),
      online: !isOffline(u.last_seen as number, now),
    }));
    return json({ users });
  }

  // Directory / capability search (point 33): online agents first.
  // The client's directory() rides the ACCOUNT Edge (routeDirectory
  // there is the fleet's search path); this operator view honors
  // the same query contract (2.0.10 alignment): `q`/`query` match
  // CASE-INSENSITIVELY over username AND display_name — the old
  // handler ignored the query entirely, and the account Edge's
  // case-sensitive includes() made "Phoenix" find nothing.
  if (path === "/directory") {
    const capability = url.searchParams.get("capability") ?? "";
    const q = (url.searchParams.get("q") ??
      url.searchParams.get("query") ?? "")
      .trim().replace(/^@+/, "").toLowerCase();
    const { data } = await supabase.from("al_users")
      .select("username, display_name, capabilities, cap_desc, last_seen")
      .order("username");
    let users = (data ?? []).map((u) => ({
      ...u,
      capabilities: capsArray(u.capabilities),
      online: !isOffline(u.last_seen as number, now),
    }));
    if (q) {
      users = users.filter((u) =>
        String(u.username ?? "").toLowerCase().includes(q) ||
        String(u.display_name ?? "").toLowerCase().includes(q)
      );
    }
    if (capability) {
      users = users.filter((u) =>
        (u.capabilities as string[]).some(
          (c) => c.toLowerCase() === capability.toLowerCase(),
        )
      );
    }
    users.sort((a, b) =>
      Number(b.online) - Number(a.online) ||
      a.username.localeCompare(b.username)
    );
    return json({ users });
  }

  // Work board + chains (metadata only).
  if (path === "/work") {
    const { data: work } = await supabase.from("al_work")
      .select(
        "id, assigner, assignee, group_id, status, priority, batch_id, chain_id, chain_step, attempt, progress_percent, progress_at, proof_verified, deadline, created_at, updated_at",
      )
      .order("updated_at", { ascending: false }).limit(200);
    const { data: chains } = await supabase.from("al_chains")
      .select("*").order("updated_at", { ascending: false }).limit(100);
    return json({ work: work ?? [], chains: chains ?? [] });
  }

  // Conversations metadata: the audit trail's envelope details.
  if (path === "/conversations") {
    const { data } = await supabase.from("al_audit_log")
      .select(
        "ts, kind, actor, target, group_id, work_id, status, priority, size, mentions, ref_id",
      )
      .order("seq", { ascending: false }).limit(500);
    return json({ activity: data ?? [] });
  }

  // Delivery library search (metadata only; entitlement lives in the
  // relay — this operator view lists the index).
  if (path === "/library") {
    const q = url.searchParams.get("q") ?? "";
    let query = supabase.from("al_library").select("*")
      .order("ts", { ascending: false }).limit(100);
    // Injection hygiene (2.6.0): the ilike pattern's
    // metacharacters in the operator's query are escaped so
    // the value matches literally — a % in q can no longer
    // widen this into a pattern scan of the whole index.
    if (q) query = query.ilike("filename", `%${escapeIlike(q)}%`);
    const { data } = await query;
    return json({ entries: data ?? [] });
  }

  // Fleet alerts (point 37).
  if (path === "/alerts") {
    const { data } = await supabase.from("al_alerts")
      .select("*").order("created_at", { ascending: false }).limit(100);
    return json({ alerts: data ?? [] });
  }

  // Operator action (metadata-only): revoke a trusted dashboard device.
  if (path === "/devices/revoke" && req.method === "POST") {
    // Ingress cap (2.6.0, Part 4): this is the only body this
    // Edge reads; it is read under CAP_CONTROL. (The other
    // routes are parameter reads with no body.) This Edge is
    // operator-authenticated throughout — no agent caller, so
    // the suspension switch and per-agent rates do not apply.
    const parsed = await readJsonBody(req, CAP_CONTROL);
    if (parsed.response) return parsed.response;
    const body = parsed.body;
    const token = String(body.token ?? "");
    if (!token) return json({ error: "token required" }, 400);
    const { error } = await supabase.from("al_dashboard_sessions")
      .delete().eq("token_hash", await sha256(token));
    if (error) return json({ error: error.message }, 500);
    return json({ revoked: true, trust_seconds: TIMING.DEVICE_TRUST_SECONDS });
  }

  return json({ error: "not found" }, 404);
});
