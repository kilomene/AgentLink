// AgentLink v2.5.0 — liveness Edge Function (Life Signs,
// migration v213). The verification seat for the proof machinery:
// the sweep issues challenges (Postgres), daemons answer them by
// signing the nonce with their identity key, runtimes countersign
// proofs and nature declarations — THIS function verifies every
// Ed25519 signature against the registry key and records the
// verdict through the v213 apply functions. The platform verifies
// and keeps time; it never signs or answers on an agent's behalf.
//
//   All endpoints: POST, Authorization: Bearer <agent supabase_jwt>.
//   The JWT's username claim is the only identity.
//
//   POST /challenge  my outstanding challenge (or none)
//   POST /answer     daemon receipt: {challenge_id, ts, sig} —
//                    sig over receipt_payload(username,
//                    challenge_id, nonce, 'daemon', ts); the tier
//                    is inside the signed bytes and this route
//                    only ever records the DAEMON tier
//   POST /prove      runtime proof: {ts, sig} over
//                    prove_payload(username, ts) — the stronger
//                    tier, recorded only here
//   POST /declare    nature declaration: {profile, ts, sig} over
//                    declare_payload(username, canonical profile,
//                    ts); appended to the signed history by
//                    al_liveness_apply_declaration
//   POST /drift      spec drift: {fields, ts, sig} over
//                    drift_payload(username, sorted fields, ts)
//                    — field names only; a fresh declaration
//                    carries the new values and clears the flag
//   POST /dossier-status  the daemon's signed dossier flag:
//                    {status, deposited_at, version, ts, sig}
//                    over dossier_status_payload(...) — a FLAG
//                    + a date only; dossier content lives solely
//                    in the owner's Drive archive, never here
//   POST /peer       nature-fit surface for assignment:
//                    {username} -> the peer's declared nature +
//                    machine + current grade + last proofs
//                    (operational metadata, fleet-visible like
//                    the directory; never content)
//
// Canonical payload strings are defined in agentlink/liveness.py
// and mirrored here byte-for-byte (one law, two places).
//
// Deploy: supabase functions deploy agentlink-liveness
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_JWT_SECRET.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  bearerToken,
  env,
  errorResponse,
  jsonResponse,
  methodGuard,
  mintGoogleAccessToken,
  normalizeUsername,
  nowSeconds,
  sanitizeKey,
  selectOne,
  verifyAgentJwt,
  verifyEd25519,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** Canonical JSON: sorted keys, compact separators — the mirror
 * of liveness.py canonical_json. */
function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonicalJson).join(",") + "]";
  }
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) =>
    JSON.stringify(k) + ":" + canonicalJson(obj[k])
  ).join(",") + "}";
}

function receiptPayload(username: string, challengeId: string,
  nonce: string, tier: string, ts: number): string {
  return `agentlink-liveness-receipt-v1|${username}|${challengeId}` +
    `|${nonce}|${tier}|${ts}`;
}

function provePayload(username: string, ts: number): string {
  return `agentlink-liveness-prove-v1|${username}|${ts}`;
}

// Build Integrity Attestation (2.5.2, v215) — mirrors of
// agentlink/liveness.py. The manifest digest rides INSIDE
// the signed bytes (v2 payloads): a build that strips
// attestation cannot produce these signatures' meaning, and
// a digest-less receipt from an agent recorded at >= 2.5.2
// is rejected outright (attestation_required) — a visible
// state, never a silent pass. The verdict itself is computed
// in the database from the registered release digest (THE
// STREET RULE: the platform judges; clients supply signed
// evidence only).
function receiptPayloadV2(username: string, cid: string,
  nonce: string, tier: string, digest: string,
  ts: number): string {
  return `agentlink-liveness-receipt-v2|${username}|${cid}` +
    `|${nonce}|${tier}|${digest}|${ts}`;
}

function provePayloadV2(username: string, digest: string,
  ts: number): string {
  return `agentlink-liveness-prove-v2|${username}|${digest}` +
    `|${ts}`;
}

function attestPayload(username: string, version: string,
  digest: string, ts: number): string {
  return `agentlink-build-attest-v1|${username}|${version}` +
    `|${digest}|${ts}`;
}

const DIGEST_RE = /^[0-9a-f]{64}$/;

/** The client version the platform RECORDED at this agent's
 * login (never the caller's say-so in this request). */
async function recordedClientVersion(
  username: string): Promise<string> {
  const row = await selectOne(supabase, "al_activeness",
    "client_version", { username });
  return String(row?.client_version ?? "");
}

function semverGte(a: string, b: string): boolean {
  const pa = a.split(".").map((x) => parseInt(x, 10) || 0);
  const pb = b.split(".").map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d > 0;
  }
  return true;
}

/** The version a digest BELONGS to, per the platform's own
 * register; falls back to the login-recorded version when
 * the digest is registered nowhere (a modified build of the
 * running version — the attestation fn judges it). */
async function versionForDigest(username: string,
  digest: string): Promise<string> {
  const row = await selectOne(supabase, "al_releases",
    "version", { manifest_sha256: digest });
  if (row?.version) return String(row.version);
  return await recordedClientVersion(username);
}

function declarePayload(username: string, profile: unknown,
  ts: number): string {
  return `agentlink-nature-declare-v1|${username}|` +
    `${canonicalJson(profile)}|${ts}`;
}

function driftPayload(username: string, fields: string[],
  ts: number): string {
  return `agentlink-liveness-drift-v1|${username}|` +
    `${[...fields].sort().join(",")}|${ts}`;
}

const DOSSIER_STATUSES = ["current", "stale", "missing",
  "deposit-parked"];

function dossierStatusPayload(username: string, status: string,
  depositedAt: number, version: number, ts: number): string {
  return `agentlink-dossier-status-v1|${username}|${status}|` +
    `${depositedAt}|${version}|${ts}`;
}

// ------------------------------------------------ live layer
// (owner's real-time ruling, 2026-11-11): every Life Signs fact
// propagates on the live layer at the moment it is verified.
// The /liveness/<user> RTDB node is composed HERE (and by the
// doorbell tapper at sweep transitions) from the RECORD layer's
// truth — the sweep-computed grade + proof summary + as_of
// server stamp. The mirror of liveness.py compose_liveness_node.

async function rtdb(token: string, method: string, path: string,
  body?: unknown): Promise<unknown> {
  const base = env("FIREBASE_DATABASE_URL").replace(/\/+$/, "");
  if (!base) {
    throw new Error(
      "FIREBASE_DATABASE_URL is not set in this function's env");
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
    throw new Error(
      "RTDB " + method + " " + path + ": HTTP " + resp.status);
  }
  return resp.status === 204 ? null
    : await resp.json().catch(() => null);
}

function composeNode(
  lv: Record<string, unknown> | null,
  user: Record<string, unknown> | null,
): Record<string, unknown> {
  const daemonAt = Number(lv?.last_daemon_receipt_at ?? 0);
  const runtimeAt = Number(lv?.last_runtime_proof_at ?? 0);
  const loginAt = Number(user?.last_seen ?? 0);
  let tier = "";
  let at = 0;
  for (const [t, v] of [["runtime", runtimeAt],
    ["daemon", daemonAt], ["login", loginAt]] as [string, number][]) {
    if (v > at) { tier = t; at = v; }
  }
  return {
    grade: String(lv?.grade ?? "") || "unproven",
    nature_version: Number(lv?.judged_nature_version ?? 0),
    persistence_class: String(lv?.judged_class ?? ""),
    last_proof_tier: tier,
    last_proof_at: at,
    daemon_only: Boolean(lv?.daemon_only),
    spec_drift: Boolean(String(lv?.spec_drift ?? "")),
    nature_compliant: Boolean(lv?.nature_compliant),
    dossier_status: String(lv?.dossier_status ?? "") || "missing",
    // Build integrity (2.5.2): the platform's verdict, mirrored
    // from the record (al_liveness.build_* are written only by
    // al_build_apply_attestation).
    build_integrity: String(lv?.build_integrity ?? "") ||
      "unattested",
    build_version: String(lv?.build_version ?? ""),
    build_digest: String(lv?.build_digest ?? "").slice(0, 12),
  };
}

/** Push the agent's live node from the record. Fail-soft: the
 * record has landed; a failed push is retried by the tapper /
 * next event, and surfaces mark the node stale by its as_of —
 * a stale node is never dressed as current. */
async function pushLiveNode(username: string): Promise<void> {
  try {
    const lv = await selectOne(supabase, "al_liveness", "*",
      { username });
    const user = await selectOne(supabase, "al_users", "last_seen",
      { username });
    const node = composeNode(lv, user);
    node.as_of = { ".sv": "timestamp" };
    const token = await mintGoogleAccessToken();
    await rtdb(token, "PATCH",
      "liveness/" + sanitizeKey(username), node);
  } catch (e) {
    console.error("liveness node push failed for " + username +
      ": " + String(e));
  }
}

/** Evaluate the agent's grade NOW (the scoped sweep — the same
 * function the pg_cron fleet sweep loops) and push the node:
 * proof → verified → graded → live, in one request. */
async function evaluate(username: string): Promise<void> {
  try {
    const { error } = await supabase.rpc(
      "al_sweep_liveness_agent", { p_username: username });
    if (error) throw new Error(error.message);
  } catch (e) {
    console.error("liveness evaluation failed for " + username +
      ": " + String(e));
  }
  await pushLiveNode(username);
}

async function signPubOf(username: string): Promise<string> {
  const row = await selectOne(supabase, "al_users", "sign_pub",
    { username });
  return String(row?.sign_pub ?? "");
}

async function verified(username: string, payload: string,
  sig: unknown): Promise<boolean> {
  if (!sig) return false;
  const pub = await signPubOf(username);
  if (!pub) return false;
  return await verifyEd25519(
    pub, new TextEncoder().encode(payload), String(sig));
}

Deno.serve(async (req) => {
  const guard = methodGuard(req);
  if (guard) return guard;
  const claims = await verifyAgentJwt(bearerToken(req));
  if (!claims) {
    return errorResponse("unauthorized",
      "agent JWT did not verify", 401);
  }
  const me = claims.username;
  const url = new URL(req.url);
  const route = url.pathname.split("/").filter(Boolean).pop() ?? "";
  const body = await req.json().catch(() => ({})) as
    Record<string, unknown>;
  const now = nowSeconds();

  try {
    if (route === "challenge") {
      const { data, error } = await supabase
        .from("al_liveness_challenges")
        .select("id,nonce,issued_at,expires_at")
        .eq("username", me).eq("answered_at", 0)
        .gt("expires_at", now)
        .order("issued_at", { ascending: false }).limit(1);
      if (error) throw new Error(error.message);
      const ch = data && data.length ? data[0] : null;
      return jsonResponse({ ok: true, challenge: ch });
    }

    if (route === "answer") {
      const challengeId = String(body.challenge_id ?? "");
      const ts = Number(body.ts ?? 0);
      if (!challengeId || !ts) {
        return errorResponse("bad_receipt",
          "challenge_id and ts are required", 400);
      }
      const ch = await selectOne(supabase, "al_liveness_challenges",
        "id,username,nonce,issued_at,expires_at,answered_at",
        { id: challengeId });
      if (!ch || String(ch.username) !== me) {
        return errorResponse("unknown_challenge",
          "no such challenge for this agent", 404);
      }
      if (Number(ch.answered_at ?? 0) > 0) {
        return errorResponse("already_answered",
          "this challenge already has its receipt", 409);
      }
      if (ts > Number(ch.expires_at)) {
        return errorResponse("challenge_expired",
          "the receipt was signed after the challenge expired",
          410);
      }
      if (Math.abs(now - ts) > 900) {
        return errorResponse("stale_receipt",
          "receipt timestamp is outside the acceptance window",
          400);
      }
      // Build attestation (2.5.2): the digest rides inside
      // the signed receipt (v2 payload). A digest-less
      // receipt from an agent the platform recorded at
      // >= 2.5.2 is a build with attestation stripped —
      // rejected loudly, never silently beating.
      const digest = String(body.build_digest ?? "");
      const hasDigest = DIGEST_RE.test(digest);
      if (!hasDigest) {
        const recorded = await recordedClientVersion(me);
        if (recorded && semverGte(recorded, "2.5.2")) {
          return errorResponse("attestation_required",
            "this agent is recorded at client " + recorded +
            " but its receipt carries no build digest — " +
            "attestation is part of the signed receipt since " +
            "2.5.2 and cannot be stripped quietly", 403);
        }
      }
      const ok = await verified(me,
        hasDigest
          ? receiptPayloadV2(me, challengeId, String(ch.nonce),
            "daemon", digest, ts)
          : receiptPayload(me, challengeId, String(ch.nonce),
            "daemon", ts),
        body.sig);
      if (!ok) {
        return errorResponse("bad_signature",
          "receipt signature did not verify against the "
          + "registry key", 403);
      }
      const { data, error } = await supabase.rpc(
        "al_liveness_apply_receipt",
        hasDigest
          ? { p_username: me, p_challenge_id: challengeId,
              p_tier: "daemon", p_ts: ts,
              p_version: await versionForDigest(me, digest),
              p_digest: digest }
          : { p_username: me, p_challenge_id: challengeId,
              p_tier: "daemon", p_ts: ts });
      if (error) throw new Error(error.message);
      await evaluate(me);
      const lv = await selectOne(supabase, "al_liveness", "grade",
        { username: me });
      return jsonResponse({ ok: true, recorded: data === true,
        tier: "daemon", last_daemon_receipt_at: ts,
        grade: String(lv?.grade ?? "") });
    }

    if (route === "prove") {
      const ts = Number(body.ts ?? 0);
      if (!ts || Math.abs(now - ts) > 600) {
        return errorResponse("stale_proof",
          "proof timestamp is outside the acceptance window",
          400);
      }
      const digest = String(body.build_digest ?? "");
      const hasDigest = DIGEST_RE.test(digest);
      if (!hasDigest) {
        const recorded = await recordedClientVersion(me);
        if (recorded && semverGte(recorded, "2.5.2")) {
          return errorResponse("attestation_required",
            "this agent is recorded at client " + recorded +
            " but its proof carries no build digest — " +
            "attestation is part of the signed proof since " +
            "2.5.2 and cannot be stripped quietly", 403);
        }
      }
      const ok = await verified(me,
        hasDigest ? provePayloadV2(me, digest, ts)
          : provePayload(me, ts),
        body.sig);
      if (!ok) {
        return errorResponse("bad_signature",
          "proof signature did not verify against the "
          + "registry key", 403);
      }
      const { error } = await supabase.rpc(
        "al_liveness_apply_prove",
        hasDigest
          ? { p_username: me, p_ts: ts,
              p_version: await versionForDigest(me, digest),
              p_digest: digest }
          : { p_username: me, p_ts: ts });
      if (error) throw new Error(error.message);
      await evaluate(me);
      const lv = await selectOne(supabase, "al_liveness", "grade",
        { username: me });
      return jsonResponse({ ok: true, tier: "runtime",
        last_runtime_proof_at: ts,
        grade: String(lv?.grade ?? "") });
    }

    if (route === "declare") {
      const ts = Number(body.ts ?? 0);
      const profile = body.profile as Record<string, unknown>;
      if (!profile || typeof profile !== "object") {
        return errorResponse("bad_declaration",
          "a nature profile object is required", 400);
      }
      if (!ts || Math.abs(now - ts) > 600) {
        return errorResponse("stale_declaration",
          "declaration timestamp is outside the acceptance "
          + "window", 400);
      }
      const ok = await verified(me,
        declarePayload(me, profile, ts), body.sig);
      if (!ok) {
        return errorResponse("bad_signature",
          "declaration signature did not verify against the "
          + "registry key", 403);
      }
      const { data, error } = await supabase.rpc(
        "al_liveness_apply_declaration",
        { p_username: me, p_profile: profile,
          p_signature: String(body.sig), p_ts: ts });
      if (error) {
        return errorResponse("bad_declaration",
          String(error.message), 400);
      }
      await evaluate(me);
      return jsonResponse({ ok: true,
        nature_version: Number(data ?? 0), declared_at: ts });
    }

    if (route === "drift") {
      // Spec drift: the agent's signed self-report that its
      // machine changed vs the declared snapshot (field names
      // only). Recorded on al_liveness + pushed to the node;
      // a fresh declaration clears it.
      const ts = Number(body.ts ?? 0);
      const fields = Array.isArray(body.fields)
        ? body.fields.map((f) => String(f)).filter(Boolean)
        : [];
      if (!ts || Math.abs(now - ts) > 600 || !fields.length) {
        return errorResponse("bad_drift_report",
          "fields and a fresh ts are required", 400);
      }
      const ok = await verified(me,
        driftPayload(me, fields, ts), body.sig);
      if (!ok) {
        return errorResponse("bad_signature",
          "drift report signature did not verify", 403);
      }
      const { error } = await supabase.rpc(
        "al_liveness_apply_drift",
        { p_username: me, p_fields: fields.join(","), p_ts: ts });
      if (error) throw new Error(error.message);
      await pushLiveNode(me);
      return jsonResponse({ ok: true, spec_drift: fields });
    }

    if (route === "dossier-status") {
      // Dossier flag: the daemon's signed report of its Drive
      // dossier state (flag + deposit date ONLY — dossier
      // content never transits this platform; it lives solely
      // in the owner's Drive archive).
      const ts = Number(body.ts ?? 0);
      const status = String(body.status ?? "");
      const depositedAt = Number(body.deposited_at ?? 0);
      const version = Number(body.version ?? 0);
      if (!ts || Math.abs(now - ts) > 600 ||
        !DOSSIER_STATUSES.includes(status)) {
        return errorResponse("bad_dossier_status",
          "a valid status and a fresh ts are required", 400);
      }
      const ok = await verified(me,
        dossierStatusPayload(me, status, depositedAt, version,
          ts), body.sig);
      if (!ok) {
        return errorResponse("bad_signature",
          "dossier status signature did not verify", 403);
      }
      const { error } = await supabase.rpc(
        "al_liveness_apply_dossier_status",
        { p_username: me, p_status: status,
          p_deposited_at: depositedAt, p_version: version,
          p_ts: ts });
      if (error) throw new Error(error.message);
      await pushLiveNode(me);
      return jsonResponse({ ok: true, dossier_status: status });
    }

    if (route === "attest") {
      // The BUILD STATEMENT (2.5.2): signed at login and on
      // the start that follows every update. The statement is
      // EVIDENCE — the digest of the manifest the client
      // installed from, signed with its identity key. The
      // verdict is computed in the database against the
      // registered release digest (al_build_apply_attestation)
      // and pushed to the live node. Nothing the client says
      // here is believed beyond its signature.
      const version = String(body.version ?? "");
      const digest = String(body.manifest_sha256 ?? "");
      const ts = Number(body.ts ?? 0);
      if (!version || !DIGEST_RE.test(digest) || !ts ||
        Math.abs(now - ts) > 600) {
        return errorResponse("bad_attestation",
          "version, a sha256 manifest digest and a fresh ts " +
          "are required", 400);
      }
      const ok = await verified(me,
        attestPayload(me, version, digest, ts), body.sig);
      if (!ok) {
        return errorResponse("bad_signature",
          "build statement signature did not verify against " +
          "the registry key", 403);
      }
      const { data, error } = await supabase.rpc(
        "al_build_apply_attestation",
        { p_username: me, p_version: version,
          p_digest: digest, p_source: "statement", p_ts: ts });
      if (error) throw new Error(error.message);
      await pushLiveNode(me);
      return jsonResponse({ ok: true,
        build_integrity: String(data ?? "unattested"),
        version, digest });
    }

    if (route === "peer") {
      const peer = normalizeUsername(body.username);
      if (!peer) {
        return errorResponse("bad_username",
          "a peer username is required", 400);
      }
      const row = await selectOne(supabase, "al_users",
        "username,persistence_class,suspect_after_s,dark_after_s,"
        + "expected_gap_s,nature_profile,nature_version,"
        + "nature_declared_at",
        { username: peer });
      if (!row) {
        return errorResponse("unknown_agent",
          "no registered agent by that name", 404);
      }
      const lv = await selectOne(supabase, "al_liveness",
        "grade,grade_since,daemon_only,last_daemon_receipt_at,"
        + "last_runtime_proof_at,judged_nature_version,"
        + "nature_compliant,spec_drift,dossier_status,"
        + "dossier_deposited_at,build_version,build_digest,"
        + "build_integrity,build_attested_at",
        { username: peer });
      return jsonResponse({ ok: true, username: peer,
        nature: row.nature_profile ?? null,
        nature_version: Number(row.nature_version ?? 0),
        nature_declared_at: Number(row.nature_declared_at ?? 0),
        liveness: lv ?? null });
    }

    return errorResponse("unknown_route",
      "routes: challenge | answer | prove | declare | drift | "
      + "dossier-status | attest | peer", 404);
  } catch (e) {
    return errorResponse("liveness_failed",
      String(e instanceof Error ? e.message : e), 500);
  }
});
