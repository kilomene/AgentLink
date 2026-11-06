// AgentLink v2.0 — grants Edge Function (coverage phase
// REWRITE). In serverless mode this function IS the grant
// broker. The Phase 2 version of this file was a recorder —
// statement/ceremony/inventory records plus a receipt append
// pipe — on the stated ground that "authorization stays in the
// Python broker". That broker lives in the relay process, and
// the relay process does not exist in serverless mode: leaving
// the recorder as-is would have left every grant/connector
// request half-wired. Nothing from Phase 2 was ever deployed,
// so the fix at the source is to seat the broker here, whole:
//
//   statement verification (the relay's exact payload bytes and
//   refusal strings), the ceremony (request/allow/revoke), the
//   connector inventory validation + capability synthesis
//   (grants.py's pins C10/C11: granular, never rounded up), the
//   authorization gate (grant state -> identity binding ->
//   red lines -> rate limits), approval decisions, and the
//   SIGNED RECEIPT CHAIN — minted here with the platform key
//   from al_grant_meta, the same key record the relay uses, so
//   the chain is continuous across transports and any Python
//   verifier (grants.py) checks these receipts unchanged.
//
// The Phase 2 "/receipt" append pipe is REMOVED: its only
// consumer was the relay-resident broker appending receipts it
// had minted itself; with the broker seated here, an append
// pipe would let any agent forge entries into its own audit
// chain. Receipts are minted by the gate/report paths inside
// this function and nowhere else.
//
//   All endpoints: POST, Authorization: Bearer <agent supabase_jwt>.
//   The JWT's username claim is the only identity.
//
//   POST /request           signed statement kind=request
//   POST /allow             signed statement kind=allow
//   POST /ceremony          alias of /allow (Phase 2 name)
//   POST /revoke            signed statement kind=revoke
//   POST /query             {grant, connectors, derived_capabilities}
//   POST /connector_update  signed statement kind=connector +
//                           top-level `connectors` inventory
//   POST /action            the broker gate (refusals are DATA,
//                           exactly as the relay answers)
//   POST /report            consume an authorization token and
//                           write its executed/error receipt
//   POST /approvals         the caller's approval queue
//   POST /decide            signed statement kind=decide
//
// Deploy: supabase functions deploy agentlink-grants
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_JWT_SECRET.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  b64encode,
  bearerToken,
  errorResponse,
  jsonResponse,
  methodGuard,
  nowSeconds,
  sha256Bytes,
  signEd25519,
  verifyAgentJwt,
  verifyEd25519,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const STATEMENT_TTL_SECONDS = 300;
const AUTHZ_TTL_SECONDS = 120;
const MAX_CONNECTORS = 64;
const NAME_RE = /^[a-z0-9][a-z0-9_-]{0,39}$/;
const ACTION_RE = /^[a-z0-9][a-z0-9_.-]{0,59}$/;
const CLASS_RE = /^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$/;
const PAYMENT_SEGMENTS = new Set([
  "card", "cards", "atm", "payment", "payments", "pay", "charge",
  "charges", "billing", "credit", "debit", "checkout",
  "invoice_payment",
]);
const ACTION_CLASS_CAPABILITIES: Record<string, string> = {
  "mail.read": "email.receive",
  "mail.send": "email.send",
  "mail.draft": "email.draft",
  "calendar.read": "calendar.read",
  "calendar.write": "calendar.write",
  "drive.read": "drive.read",
  "drive.write": "drive.write",
};
const GRANT_RATE_LIMITS: Record<string, number> = {
  "mail.read": 600,
  "mail.send": 120,
  "calendar.read": 600,
  "calendar.write": 300,
  "drive.read": 600,
  "drive.write": 300,
};
const DEFAULT_RATE_LIMIT = 300;
const RECEIPT_FIELDS = [
  "id", "username", "ts", "scope", "connector", "action",
  "target", "work_ref", "status", "detail",
] as const;

// ------------------------------------------------------------ small helpers

function randomHex(n: number): string {
  const bytes = new Uint8Array(Math.ceil(n / 2));
  crypto.getRandomValues(bytes);
  return [...bytes].map((b) => b.toString(16).padStart(2, "0"))
    .join("").slice(0, n);
}

function toHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** json.dumps(..., sort_keys=True, separators=(",", ":")) with
 * ensure_ascii — the receipt canonical form, byte-identical to
 * grants.py's. */
function canonicalJson(value: unknown): string {
  const raw = JSON.stringify(sortDeep(value));
  return raw.replace(/[\u007f-\uffff]/g, (ch) =>
    "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
}

function sortDeep(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortDeep);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value).sort()) {
      out[k] = sortDeep((value as Record<string, unknown>)[k]);
    }
    return out;
  }
  return value;
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

async function audit(
  kind: string,
  actor: string,
  opts: {
    target?: string;
    work_id?: string;
    status?: string;
    ref_id?: string;
  } = {},
): Promise<void> {
  const { error } = await supabase.from("al_audit_log").insert({
    ts: nowSeconds(),
    kind,
    actor,
    target: opts.target ?? "",
    group_id: "",
    work_id: opts.work_id ?? "",
    status: opts.status ?? "",
    priority: "",
    size: 0,
    mentions: [],
    ref_id: opts.ref_id ?? "",
    sender_nickname: "",
    sender_role: "",
    sender_custom_role: "",
    oversight: "",
    content_envelope: "",
  });
  if (error) throw new Error("audit insert failed: " + error.message);
}

async function openAlert(kind: string, subject: string, detail = "") {
  const existing = await selectEq("al_alerts",
    { kind, subject, status: "open" });
  if (existing.length) return;
  const { error } = await supabase.from("al_alerts").insert({
    id: ("a-" + randomHex(32)).slice(0, 14),
    kind,
    subject,
    detail,
    status: "open",
    reminders: 0,
    last_reminder_at: 0,
    created_at: nowSeconds(),
    resolved_at: 0,
  });
  if (error) throw new Error("alert insert failed: " + error.message);
}

// ------------------------------------------------------------ statements

/** protocol.grant_statement_payload, byte for byte. */
function statementPayload(
  kind: string,
  username: string,
  ts: number,
  fields: Record<string, unknown>,
): Uint8Array {
  const lines = ["agentlink-grant-v1", kind, username, String(ts)];
  for (const k of Object.keys(fields).sort()) {
    let v = fields[k];
    if (typeof v === "boolean") v = v ? "true" : "false";
    lines.push(`${k}=${v}`);
  }
  return new TextEncoder().encode(lines.join("\n"));
}

/** relay._verify_grant_statement: returns the statement or null;
 * the caller speaks the route's refusal string (the relay's
 * protocol errors, which the client renders as refusals). */
async function verifyStatement(
  body: Record<string, unknown>,
  username: string,
  expectedKind: string,
): Promise<Record<string, unknown> | null> {
  const stmt = body.statement as Record<string, unknown> | undefined;
  const sig = body.sig as string | undefined;
  if (!stmt || typeof stmt !== "object" || !sig) return null;
  if (stmt.kind !== expectedKind) return null;
  const ts = Number(stmt.ts ?? 0);
  if (!ts || Math.abs(nowSeconds() - ts) > STATEMENT_TTL_SECONDS) {
    return null;
  }
  const userRow = await oneEq("al_users", { username }, "sign_pub");
  const signPub = String(userRow?.sign_pub ?? "");
  if (!signPub) return null;
  const fields: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(stmt)) {
    if (k !== "kind" && k !== "ts") fields[k] = v;
  }
  const payload = statementPayload(expectedKind, username, ts, fields);
  const ok = await verifyEd25519(signPub, payload, sig)
    .catch(() => false);
  return ok ? stmt : null;
}

// ------------------------------------------------------------ inventory

function lawfulActionClass(cls: unknown): cls is string {
  if (typeof cls !== "string" || !CLASS_RE.test(cls)) return false;
  return !(cls as string).split(".")
    .some((seg) => PAYMENT_SEGMENTS.has(seg));
}

/** grants.validate_inventory: WHOLE-or-None. */
function validateInventory(
  raw: unknown,
): Record<string, unknown>[] | null {
  if (raw === null || raw === undefined) return [];
  if (!Array.isArray(raw) || raw.length > MAX_CONNECTORS) return null;
  const seen = new Set<string>();
  const out: Record<string, unknown>[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== "object") return null;
    const e = entry as Record<string, unknown>;
    const name = String(e.name ?? "").trim().toLowerCase();
    if (!NAME_RE.test(name) || seen.has(name)) return null;
    seen.add(name);
    const actionsRaw = (e.actions ?? {}) as Record<string, unknown>;
    if (typeof actionsRaw !== "object" || actionsRaw === null ||
        Object.keys(actionsRaw).length > 64) {
      return null;
    }
    const actions: Record<string, string> = {};
    for (const [aname, acls] of Object.entries(actionsRaw)) {
      if (!ACTION_RE.test(aname)) return null;
      const cls = String(acls).trim().toLowerCase();
      if (!lawfulActionClass(cls)) return null;
      actions[aname] = cls;
    }
    const cleanList = (value: unknown, cap: number) =>
      (Array.isArray(value) ? value : [])
        .map((v) => String(v).trim())
        .filter(Boolean)
        .map((v) => v.slice(0, cap))
        .slice(0, 32);
    out.push({
      name,
      service: String(e.service || name).slice(0, 40),
      label: String(e.label || name).slice(0, 80),
      linked: e.linked === undefined ? true : Boolean(e.linked),
      oauth_scopes: cleanList(e.oauth_scopes, 60),
      actions,
      capabilities: cleanList(e.capabilities, 40),
    });
  }
  return out;
}

/** grants.derived_capabilities: what the vault SIGNIFIES —
 * granular and never rounded up (pins C10/C11). */
function derivedCapabilities(
  inventory: Record<string, unknown>[],
): string[] {
  const caps = new Set<string>();
  for (const entry of inventory) {
    if (!entry.linked) continue;
    for (const c of (entry.capabilities as string[]) ?? []) {
      caps.add(c);
    }
    const actions = (entry.actions ?? {}) as Record<string, string>;
    for (const cls of Object.values(actions)) {
      caps.add(ACTION_CLASS_CAPABILITIES[cls] ?? cls);
    }
  }
  return [...caps].sort();
}

async function inventoryDigest(
  inventory: Record<string, unknown>[],
): Promise<string> {
  const canonical = JSON.stringify(sortDeep(inventory));
  return toHex(await sha256Bytes(new TextEncoder().encode(canonical)));
}

async function loadInventory(
  username: string,
): Promise<Record<string, unknown>[]> {
  const row = await oneEq("al_agent_connectors", { username },
    "inventory");
  if (!row) return [];
  try {
    const parsed = JSON.parse(String(row.inventory ?? "[]"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

// ------------------------------------------------------------ grant rows

function grantSummary(row: Record<string, unknown> | null) {
  if (!row) return null;
  return {
    status: row.status,
    grantor: row.grantor ?? "",
    granted_by: row.granted_by ?? "",
    granted_at: row.granted_at ?? 0,
    ceremony_at: row.ceremony_at ?? 0,
    requested_at: row.requested_at ?? 0,
    request_reason: String(row.request_reason ?? "").slice(0, 200),
    coverage: "connector_vault",
  };
}

async function grantRow(username: string) {
  return await oneEq("al_grants", { username });
}

// ------------------------------------------------------------ receipts

async function platformKey(): Promise<{ seed: string; pub: string }> {
  const row = await oneEq("al_grant_meta",
    { key: "receipt_signing_key" }, "value");
  if (row?.value) {
    const [seed, pub] = String(row.value).split(":");
    if (seed && pub) return { seed, pub };
  }
  // Mint on first use, exactly as the store does.
  const seedBytes = new Uint8Array(32);
  crypto.getRandomValues(seedBytes);
  const seed = b64encode(seedBytes);
  const pkcs8 = new Uint8Array(48);
  pkcs8.set(
    [
      0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b,
      0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
    ],
    0,
  );
  pkcs8.set(seedBytes, 16);
  const key = await crypto.subtle.importKey(
    "pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"],
  );
  const spki = new Uint8Array(
    await crypto.subtle.exportKey("spki", key));
  const pub = b64encode(spki.slice(spki.length - 32));
  const { error } = await supabase.from("al_grant_meta").insert({
    key: "receipt_signing_key",
    value: `${seed}:${pub}`,
  });
  if (error) throw new Error("platform key mint failed: " + error.message);
  return { seed, pub };
}

function receiptCanonical(rec: Record<string, unknown>): string {
  const view: Record<string, unknown> = {};
  for (const k of RECEIPT_FIELDS) view[k] = rec[k];
  return canonicalJson(view);
}

async function chainTip(): Promise<Record<string, unknown> | null> {
  const { data, error } = await supabase.from("al_grant_receipts")
    .select("*").order("seq", { ascending: false }).limit(1);
  if (error) throw new Error("receipt tip failed: " + error.message);
  const row = (data ?? [])[0] as Record<string, unknown> | undefined;
  if (!row) return null;
  try {
    row.detail = JSON.parse(String(row.detail ?? "{}"));
  } catch {
    row.detail = {};
  }
  return row;
}

/** store.add_grant_receipt: the signed, hash-chained append.
 * detail is coerced to {} unless it is an object or a list,
 * exactly as the store coerces. A prev_hash unique conflict
 * (a concurrent mint elsewhere) retries against the new tip. */
async function addReceipt(fields: {
  username: string;
  scope: string;
  connector: string;
  action: string;
  target: string;
  work_ref: string;
  status: string;
  detail: unknown;
}): Promise<Record<string, unknown>> {
  const key = await platformKey();
  // The store coerces detail to {} unless it is a dict — a list
  // does not survive either.
  const detail = fields.detail &&
      typeof fields.detail === "object" &&
      !Array.isArray(fields.detail)
    ? fields.detail
    : {};
  for (let attempt = 0; attempt < 6; attempt++) {
    const prev = await chainTip();
    const rec: Record<string, unknown> = {
      id: "rcpt-" + randomHex(32),
      username: fields.username,
      ts: nowSeconds(),
      scope: fields.scope,
      connector: fields.connector,
      action: fields.action,
      target: fields.target,
      work_ref: fields.work_ref,
      status: fields.status,
      detail,
      prev_hash: "",
      sig: "",
    };
    if (prev) {
      const prevCanonical = receiptCanonical(prev);
      const digest = await sha256Bytes(new TextEncoder().encode(
        prevCanonical + "|" + String(prev.sig)));
      rec.prev_hash = toHex(digest);
    }
    rec.sig = await signEd25519(
      key.seed, new TextEncoder().encode(receiptCanonical(rec)));
    const { error } = await supabase.from("al_grant_receipts")
      .insert({
        id: rec.id,
        username: rec.username,
        ts: rec.ts,
        scope: rec.scope,
        connector: rec.connector,
        action: rec.action,
        target: rec.target,
        work_ref: rec.work_ref,
        status: rec.status,
        detail: JSON.stringify(detail),
        prev_hash: rec.prev_hash,
        sig: rec.sig,
      });
    if (!error) return rec;
    if (!String(error.message).includes("duplicate") &&
        !String(error.message).includes("unique")) {
      throw new Error("receipt insert failed: " + error.message);
    }
  }
  throw new Error("receipt chain contention: could not append");
}

// ------------------------------------------------------------ the gate

function redLineReason(action: string): string {
  const a = action.toLowerCase();
  if (a.startsWith("security.")) {
    return "red line: changing security settings on a core " +
      "account stays approval-gated";
  }
  if (a.startsWith("access.") ||
      ["share", "share_access", "grant_access"].includes(a)) {
    return "red line: granting access to third parties stays " +
      "approval-gated";
  }
  if (["delete_all", "delete.bulk", "bulk_delete"].includes(a) ||
      a.startsWith("bulk_") || a.startsWith("bulk.") ||
      a.endsWith(".bulk")) {
    return "red line: bulk deletion stays approval-gated";
  }
  return "";
}

async function mintAuthz(fields: {
  username: string;
  connector: string;
  action: string;
  scope: string;
  params: unknown;
  work_ref: string;
  approval_id: string;
}): Promise<string> {
  const token = "authz-" + randomHex(32);
  const paramsCanonical = canonicalJson(fields.params ?? {});
  const paramsHash = toHex(
    await sha256Bytes(new TextEncoder().encode(paramsCanonical)));
  const { error } = await supabase.from("al_grant_authz").insert({
    token,
    username: fields.username,
    connector: fields.connector,
    action: fields.action,
    scope: fields.scope,
    params_hash: paramsHash,
    work_ref: fields.work_ref,
    approval_id: fields.approval_id,
    expires: nowSeconds() + AUTHZ_TTL_SECONDS,
  });
  if (error) throw new Error("authz mint failed: " + error.message);
  return token;
}

/** grants.GrantBroker.authorize — the gate, in the broker's
 * order, with the broker's strings. Every outcome (including
 * refusal) also writes its `grant_action` activity audit row
 * where the relay writes one. */
async function authorize(
  username: string,
  body: Record<string, unknown>,
  opts: {
    skipRedLine?: boolean;
    skipRate?: boolean;
    approvalId?: string;
  } = {},
): Promise<Record<string, unknown>> {
  const connector = String(body.connector ?? "");
  const action = String(body.action ?? "");
  const workRef = String(body.work_ref ?? "");
  const params = body.params ?? {};
  // The broker derives the receipt target from the params
  // (grants._target_of): the first truthy of to/target/id/with.
  const target = (() => {
    const p = (params ?? {}) as Record<string, unknown>;
    for (const k of ["to", "target", "id", "with"]) {
      if (p[k]) return String(p[k]);
    }
    return "";
  })();

  const receipted = async (
    status: string,
    scope: string,
    detail: Record<string, unknown>,
  ) => {
    const rec = await addReceipt({
      username, scope, connector, action, target,
      work_ref: workRef, status, detail,
    });
    await audit("grant_action", username, {
      target,
      work_id: workRef,
      status,
      ref_id: String(rec.id),
    });
    return rec;
  };
  const refusal = async (
    reason: string,
    outcomeReason: string,
    scope = "",
  ) => {
    const rec = await receipted("refused", scope, { reason });
    return { status: "refused", receipt_id: rec.id, reason: outcomeReason };
  };

  const inventory = await loadInventory(username);
  const entry = inventory.find((e) => e.name === connector);
  if (!entry) {
    return await refusal(
      `connector '${connector}' is not in @${username}'s connector vault`,
      `connector '${connector}' is not in @${username}'s connector ` +
        "vault — the grant covers the connectors the owner has " +
        "linked, and this is not one of them",
    );
  }
  if (!entry.linked) {
    return await refusal(
      `connector '${connector}' is not linked`,
      `connector '${connector}' is in the vault but not linked`,
    );
  }
  const actions = (entry.actions ?? {}) as Record<string, string>;
  const scope = actions[action];
  if (scope === undefined || !lawfulActionClass(scope)) {
    return await refusal(
      `connector '${connector}' declares no action '${action}'`,
      `connector '${connector}' declares no action '${action}'`,
    );
  }
  const grant = await grantRow(username);
  if (!grant || grant.status !== "active") {
    const state = !grant
      ? "no grant on record"
      : `grant status is '${grant.status}'`;
    const rec = await receipted("refused", scope, {
      reason: `no active grant (${state})`,
    });
    return {
      status: "refused",
      receipt_id: rec.id,
      reason: `@${username} holds no active grant (${state}); ` +
        "the agent must ask its owner for the one-time " +
        "permission and the owner must allow it",
    };
  }
  const userRow = await oneEq("al_users", { username }, "sign_pub");
  const bound = String(grant.bound_sign_pub ?? "");
  if (!bound || bound !== String(userRow?.sign_pub ?? "")) {
    return await refusal(
      "the grant is bound to a different identity",
      "the grant is bound to a different identity than the " +
        "one presenting this name",
      scope,
    );
  }
  if (!opts.skipRedLine) {
    const reason = redLineReason(action);
    if (reason) {
      const approvalId = "gappr-" + randomHex(32);
      const { error } = await supabase.from("al_grant_approvals")
        .insert({
          id: approvalId,
          username,
          ts: nowSeconds(),
          scope,
          connector,
          action,
          target,
          params: JSON.stringify(params ?? {}),
          work_ref: workRef,
          reason,
          status: "awaiting_approval",
          decided_by: "",
          decided_at: 0,
          receipt_id: "",
        });
      if (error) {
        throw new Error("approval insert failed: " + error.message);
      }
      const rec = await receipted("approval_queued", scope, {
        reason, approval_id: approvalId,
      });
      return {
        status: "awaiting_approval",
        approval_id: approvalId,
        receipt_id: rec.id,
        reason,
      };
    }
  }
  if (!opts.skipRate) {
    const limit = GRANT_RATE_LIMITS[scope] ?? DEFAULT_RATE_LIMIT;
    const since = nowSeconds() - 3600;
    const { data, error } = await supabase.from("al_grant_receipts")
      .select("id")
      .eq("username", username).eq("scope", scope)
      .eq("status", "executed").gte("ts", since);
    if (error) throw new Error("rate count failed: " + error.message);
    if ((data ?? []).length >= limit) {
      const rec = await receipted("rate_limited", scope, {
        reason: `platform rate limit for action class ${scope} reached`,
        limit,
        window_seconds: 3600,
      });
      await openAlert(
        "grant_rate_limit",
        `${username}:${scope}`,
        `@${username} tripped the platform rate limit for ` +
          `action class ${scope} (${limit} actions / 3600s) — ` +
          "further actions in this class fail closed until " +
          "the window clears",
      );
      return {
        status: "rate_limited",
        receipt_id: rec.id,
        reason: `platform rate limit reached for action class ` +
          `${scope}; the action failed closed and a fleet ` +
          "alert was raised",
      };
    }
  }
  const token = await mintAuthz({
    username,
    connector,
    action,
    scope,
    params,
    work_ref: workRef,
    approval_id: opts.approvalId ?? "",
  });
  const out: Record<string, unknown> = {
    status: "authorized",
    authorization: token,
    scope,
  };
  if (opts.approvalId) out.approval_id = opts.approvalId;
  return out;
}

/** grants.GrantBroker.record_execution — the report path. */
function boundedResult(result: unknown): Record<string, unknown> {
  const raw = JSON.stringify(sortDeep(result ?? {}));
  if (raw.length <= 4096) return { result: result ?? {} };
  return { result_summary: raw.slice(0, 1000), truncated: true };
}

async function recordExecution(
  username: string,
  body: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const token = String(body.authorization ?? "");
  // Single-use: the row is consumed by the read.
  const { data, error } = await supabase.from("al_grant_authz")
    .delete().eq("token", token).select();
  if (error) throw new Error("authz consume failed: " + error.message);
  const rec0 = (data ?? [])[0] as Record<string, unknown> | undefined;
  if (!rec0 || rec0.username !== username ||
      Number(rec0.expires ?? 0) <= nowSeconds()) {
    return {
      status: "refused",
      reason: "unknown, consumed or expired authorization — " +
        "no receipt written",
    };
  }
  let status = String(body.status ?? "");
  let errorText = String(body.error ?? "");
  if (status !== "executed" && status !== "error") {
    status = "error";
    // The broker builds this string AFTER the reassignment, so
    // it always reads 'error' — mirrored as built.
    errorText = errorText || "bad reported status 'error'";
  }
  const detail: Record<string, unknown> = status === "executed"
    ? boundedResult(body.result)
    : { reason: errorText || "connector error" };
  if (rec0.approval_id) detail.approval_id = rec0.approval_id;
  const rec = await addReceipt({
    username,
    scope: String(rec0.scope),
    connector: String(rec0.connector),
    action: String(rec0.action),
    target: "",
    work_ref: String(rec0.work_ref ?? ""),
    status,
    detail,
  });
  if (rec0.approval_id) {
    const { error: aerr } = await supabase.from("al_grant_approvals")
      .update({ status: "executed", receipt_id: String(rec.id) })
      .eq("id", String(rec0.approval_id));
    if (aerr) throw new Error("approval receipt link failed: " + aerr.message);
  }
  await audit("grant_action", username, {
    target: "",
    work_id: String(rec0.work_ref ?? ""),
    status,
    ref_id: String(rec.id),
  });
  const out: Record<string, unknown> = {
    status, receipt_id: rec.id,
  };
  if (status === "executed") out.result = body.result ?? {};
  else out.reason = detail.reason;
  return out;
}

// ------------------------------------------------------------ routes

function refuse(reason: string): Response {
  return errorResponse(reason, "", 400);
}

async function routeRequest(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const stmt = await verifyStatement(body, me, "request");
  if (!stmt) return refuse("grant statement did not verify");
  const requestId = String(stmt.request_id ?? "").slice(0, 64);
  if (!requestId) {
    return refuse("request statement carries no request id");
  }
  const existing = await grantRow(me);
  if (!existing || existing.status !== "active") {
    const row = {
      username: me,
      status: "requested",
      scopes: "[]",
      granted_by: "",
      grantor: "",
      granted_at: 0,
      ceremony_at: 0,
      bound_sign_pub: "",
      request_id: requestId,
      requested_at: nowSeconds(),
      request_reason: String(stmt.reason ?? "").slice(0, 500),
      updated_at: nowSeconds(),
    };
    const { error } = await supabase.from("al_grants")
      .upsert(row, { onConflict: "username" });
    if (error) throw new Error("grant request failed: " + error.message);
  }
  return jsonResponse({
    ok: true, grant: grantSummary(await grantRow(me)),
  });
}

async function routeAllow(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const stmt = await verifyStatement(body, me, "allow");
  if (!stmt) return refuse("grant statement did not verify");
  const requestId = String(stmt.request_id ?? "");
  const grantor = String(stmt.grantor ?? "").slice(0, 80);
  const userRow = await oneEq("al_users", { username: me },
    "sign_pub");
  const { data, error } = await supabase.from("al_grants")
    .update({
      status: "active",
      scopes: "[]",
      granted_by: grantor,
      grantor,
      granted_at: nowSeconds(),
      ceremony_at: Number(stmt.ts ?? 0),
      bound_sign_pub: String(userRow?.sign_pub ?? ""),
      updated_at: nowSeconds(),
    })
    .eq("username", me).eq("status", "requested")
    .eq("request_id", requestId)
    .select();
  if (error) throw new Error("grant allow failed: " + error.message);
  if (!(data ?? []).length) {
    return refuse(
      "no pending permission request matches this allow — " +
        "the agent must ask first");
  }
  return jsonResponse({
    ok: true, grant: grantSummary(await grantRow(me)),
  });
}

async function routeRevoke(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const stmt = await verifyStatement(body, me, "revoke");
  if (!stmt) return refuse("grant statement did not verify");
  const { data, error } = await supabase.from("al_grants")
    .update({
      status: "revoked",
      granted_by: "agent-owner",
      updated_at: nowSeconds(),
    })
    .eq("username", me).eq("status", "active")
    .select();
  if (error) throw new Error("grant revoke failed: " + error.message);
  return jsonResponse({
    ok: true,
    grant: grantSummary(await grantRow(me)),
    revoked: (data ?? []).length > 0,
  });
}

async function routeQuery(
  me: string,
): Promise<Response> {
  const inventory = await loadInventory(me);
  return jsonResponse({
    ok: true,
    grant: grantSummary(await grantRow(me)),
    connectors: inventory,
    derived_capabilities: derivedCapabilities(inventory),
  });
}

async function routeConnectorUpdate(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const stmt = await verifyStatement(body, me, "connector_update");
  if (!stmt) return refuse("connector statement did not verify");
  const inventory = validateInventory(body.connectors);
  if (inventory === null) {
    await audit("connector_inventory_refused", me, {});
    return refuse("connector inventory failed validation");
  }
  const digest = await inventoryDigest(inventory);
  if (digest !== String(stmt.inventory_digest ?? "")) {
    return refuse(
      "inventory digest does not match the signed statement");
  }
  const { error } = await supabase.from("al_agent_connectors")
    .upsert({
      username: me,
      inventory: JSON.stringify(inventory),
      updated_at: nowSeconds(),
    }, { onConflict: "username" });
  if (error) throw new Error("inventory save failed: " + error.message);
  return jsonResponse({
    ok: true,
    connectors: inventory.length,
    derived_capabilities: derivedCapabilities(inventory),
  });
}

async function routeApprovals(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  let q = supabase.from("al_grant_approvals").select("*")
    .eq("username", me)
    .order("ts", { ascending: false }).limit(50);
  if (body.status) q = q.eq("status", String(body.status));
  const { data, error } = await q;
  if (error) throw new Error("approvals read failed: " + error.message);
  const approvals = (data ?? []).map((r) => {
    const row = { ...(r as Record<string, unknown>) };
    try {
      row.params = JSON.parse(String(row.params ?? "{}"));
    } catch {
      row.params = {};
    }
    return row;
  });
  return jsonResponse({ ok: true, approvals });
}

async function routeDecide(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const stmt = await verifyStatement(body, me, "decide");
  if (!stmt) return refuse("grant statement did not verify");
  const approvalId = String(stmt.approval_id ?? "");
  const approval = await oneEq("al_grant_approvals",
    { id: approvalId });
  if (!approval || approval.username !== me) {
    return refuse("no such approval in this agent's queue");
  }
  if (approval.status !== "awaiting_approval") {
    return refuse(`approval already decided (${approval.status})`);
  }
  const approved = Boolean(stmt.approved);
  const decidedBy = String(stmt.decided_by ?? "").slice(0, 80);
  const newStatus = approved ? "approved" : "rejected";
  const { error } = await supabase.from("al_grant_approvals")
    .update({
      status: newStatus,
      decided_by: decidedBy,
      decided_at: nowSeconds(),
    }).eq("id", approvalId);
  if (error) throw new Error("decide failed: " + error.message);
  await audit(`grant_approval_${newStatus}`, me, {
    status: newStatus,
  });
  if (!approved) {
    return jsonResponse({
      ok: true, status: "rejected", approval_id: approvalId,
    });
  }
  // The owner's decision IS the red-line pass; the rest of the
  // gate re-runs in full.
  let params: unknown = {};
  try {
    params = JSON.parse(String(approval.params ?? "{}"));
  } catch {
    params = {};
  }
  const outcome = await authorize(me, {
    connector: approval.connector,
    action: approval.action,
    params,
    work_ref: approval.work_ref,
  }, { skipRedLine: true, skipRate: true, approvalId });
  return jsonResponse({ ok: true, ...outcome });
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
      "the grant belongs to the JWT's agent; body username disagrees",
      403,
    );
  }
  const tail = new URL(req.url).pathname.split("/").filter(Boolean)
    .pop() ?? "";
  const route = tail === "agentlink-grants" ? "" : tail;
  try {
    switch (route) {
      case "request":
        return await routeRequest(me, body);
      case "allow":
      case "ceremony":
        return await routeAllow(me, body);
      case "revoke":
        return await routeRevoke(me, body);
      case "query":
        return await routeQuery(me);
      case "connector_update":
        return await routeConnectorUpdate(me, body);
      case "action":
        // Refusals are data — the relay always answers ok with
        // the outcome; the client branches on outcome.status.
        return jsonResponse({
          ok: true, ...(await authorize(me, body)),
        });
      case "report":
        return jsonResponse({
          ok: true, ...(await recordExecution(me, body)),
        });
      case "approvals":
        return await routeApprovals(me, body);
      case "decide":
        return await routeDecide(me, body);
      default:
        return errorResponse(
          "not_found", "unknown agentlink-grants route", 404);
    }
  } catch (e) {
    return errorResponse(
      "grants_internal",
      String(e instanceof Error ? e.message : e),
      500,
    );
  }
});
