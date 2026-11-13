// AgentLink v2.0 — blobs Edge Function (coverage phase). The
// service-role seat for the blob operations the Phase 2 r2sign
// contract deliberately cannot serve: it presigns whole-blob
// GET/PUT only for EXISTING al_blobs rows, and chunk objects
// have no row by design (they are "{session_id}-{index}" keys,
// not blobs). Deletion, chunk upload and session-finish
// assembly therefore live here, mirroring relay.py's handlers
// exactly:
//
//   POST /delete          _on_blob_delete (owner, or a group
//                         admin of the blob's group; object
//                         deleted FIRST, then the meta row)
//   POST /chunk           _on_blob_chunk (session ownership,
//                         per-chunk SHA-256 verified BEFORE the
//                         object write)
//   POST /session_finish  _on_blob_session_finish (completeness
//                         -> assembly -> whole-bytes SHA-256 ->
//                         channel membership re-check -> final
//                         object + meta + session cleanup +
//                         the blob_upload_completed audit)
//
// Single-writer blob paths (blob_put, blob_get, session start /
// status) are PostgREST + r2sign paths in the client transport.
//
//   All endpoints: POST, Authorization: Bearer <agent supabase_jwt>.
//
// Deploy: supabase functions deploy agentlink-blobs
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_JWT_SECRET, R2_ACCOUNT_ID, R2_BUCKET,
// R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  b64decode,
  bearerToken,
  CAP_BLOB,
  errorResponse,
  jsonResponse,
  methodGuard,
  nowSeconds,
  presignR2Url,
  r2ConfigFromEnv,
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
const PRESIGN_SECONDS = 900;

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

async function r2(
  method: "GET" | "PUT" | "DELETE",
  key: string,
  body?: Uint8Array,
): Promise<Response> {
  const cfg = r2ConfigFromEnv();
  if (!cfg) throw new Error("r2_not_configured");
  const url = await presignR2Url(cfg, method, key, PRESIGN_SECONDS);
  return await fetch(url, { method, body });
}

async function routeDelete(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const blobId = String(body.blob_id ?? "");
  const meta = await oneEq("al_blobs", { id: blobId });
  let allowed = false;
  if (meta) {
    if (meta.owner === me) {
      allowed = true;
    } else if (meta.for_group) {
      const row = await oneEq("al_group_members", {
        group_id: meta.for_group, username: me,
      }, "role");
      allowed = row !== null &&
        ADMIN_ROLES.includes(String(row.role));
    }
  }
  if (!allowed) return refuse("permission_denied");
  const resp = await r2("DELETE", blobId);
  if (resp.status >= 300 && resp.status !== 404) {
    return refuse("blob_store_failed",
      `object store answered HTTP ${resp.status}`);
  }
  const { error } = await supabase.from("al_blobs").delete()
    .eq("id", blobId);
  if (error) throw new Error("blob meta delete failed: " + error.message);
  return jsonResponse({ ok: true, blob_id: blobId, deleted: true });
}

function parseChunks(raw: unknown): number[] {
  try {
    const v = typeof raw === "string" ? JSON.parse(raw) : raw;
    return Array.isArray(v) ? v.map((x) => Number(x)) : [];
  } catch {
    return [];
  }
}

async function routeChunk(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const sessionId = String(body.session_id ?? "");
  const sess = await oneEq("al_upload_sessions",
    { session_id: sessionId });
  if (!sess || sess.owner !== me) return refuse("unknown_session");
  let data: Uint8Array;
  try {
    data = b64decode(String(body.data_b64 ?? ""));
  } catch {
    return refuse("bad_chunk");
  }
  const digest = await sha256Hex(data);
  if (digest !== String(body.chunk_sha ?? "")) {
    return refuse("bad_chunk_hash");
  }
  const index = Number(body.index ?? 0);
  const resp = await r2("PUT", `${sessionId}-${index}`, data);
  if (resp.status >= 300) {
    return refuse("blob_store_failed",
      `object store answered HTTP ${resp.status}`);
  }
  const have = [...new Set([...parseChunks(sess.chunks), index])]
    .sort((a, b) => a - b);
  const { error } = await supabase.from("al_upload_sessions")
    .update({ chunks: JSON.stringify(have) })
    .eq("session_id", sessionId);
  if (error) throw new Error("chunk record failed: " + error.message);
  return jsonResponse({ ok: true, have });
}

async function routeSessionFinish(
  me: string,
  body: Record<string, unknown>,
): Promise<Response> {
  const sessionId = String(body.session_id ?? "");
  const sess = await oneEq("al_upload_sessions",
    { session_id: sessionId });
  if (!sess || sess.owner !== me) return refuse("unknown_session");
  const size = Number(sess.size ?? 0);
  const chunkSize = Number(sess.chunk_size ?? 0);
  const total = size && chunkSize
    ? Math.ceil(size / chunkSize)
    : 0;
  const have = parseChunks(sess.chunks).sort((a, b) => a - b);
  const complete = have.length === total &&
    have.every((v, i) => v === i);
  if (!complete) {
    return refuse("incomplete_upload",
      `have ${have.length} of ${total} chunks`);
  }
  const parts: Uint8Array[] = [];
  let assembled = 0;
  for (let i = 0; i < total; i++) {
    const resp = await r2("GET", `${sessionId}-${i}`);
    if (resp.status === 404) {
      return refuse("incomplete_upload",
        `chunk ${i} object missing`);
    }
    if (resp.status >= 300) {
      return refuse("blob_fetch_failed",
        `object store answered HTTP ${resp.status}`);
    }
    const buf = new Uint8Array(await resp.arrayBuffer());
    parts.push(buf);
    assembled += buf.length;
  }
  const whole = new Uint8Array(assembled);
  let off = 0;
  for (const p of parts) {
    whole.set(p, off);
    off += p.length;
  }
  const ctSha = await sha256Hex(whole);
  if (ctSha !== String(sess.ct_sha ?? "")) {
    return refuse("bad_whole_hash");
  }
  const finChannel = String(body.for_channel ?? "");
  if (finChannel) {
    const member = await oneEq("al_channel_members", {
      channel_id: finChannel, username: me,
    }, "username");
    if (!member) return refuse("not_a_member");
  }
  const blobId = "b-" + ctSha;
  const put = await r2("PUT", blobId, whole);
  if (put.status >= 300) {
    return refuse("blob_store_failed",
      `object store answered HTTP ${put.status}`);
  }
  for (let i = 0; i < total; i++) {
    await r2("DELETE", `${sessionId}-${i}`);
  }
  const { error } = await supabase.from("al_blobs").insert({
    id: blobId,
    owner: me,
    for_user: String(sess.for_user ?? ""),
    for_group: String(sess.for_group ?? ""),
    for_channel: finChannel,
    whole_sha: String(sess.whole_sha ?? ""),
    size,
    created_at: nowSeconds(),
  });
  if (error) throw new Error("blob meta insert failed: " + error.message);
  await supabase.from("al_upload_sessions").delete()
    .eq("session_id", sessionId);
  const { error: aerr } = await supabase.from("al_audit_log").insert({
    ts: nowSeconds(),
    kind: "blob_upload_completed",
    actor: me,
    target: String(sess.for_user ?? ""),
    group_id: String(sess.for_group ?? ""),
    work_id: blobId,
    status: "",
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
  if (aerr) throw new Error("audit insert failed: " + aerr.message);
  return jsonResponse({ ok: true, blob_id: blobId, size });
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
  // Containment (2.6.0, Part 4): suspension, cap, rate. The
  // cap is CAP_BLOB (8 MiB): the chunk route carries one chunk
  // as base64 in the body. The rate is 600/min — a legitimate
  // multi-chunk upload is the fleet's bursty case and gets
  // headroom, not a squeeze.
  const suspended = await suspendedRefusal(supabase, me);
  if (suspended) return suspended;
  const parsed = await readJsonBody(req, CAP_BLOB);
  if (parsed.response) return parsed.response;
  const body = parsed.body;
  const limited = await rateLimitRefusal(
    supabase, "blobs:" + me, 600);
  if (limited) return limited;
  // Injection hygiene: blob/session ids become R2 keys. The
  // platform's ids are [A-Za-z0-9._-] only; anything carrying
  // a path separator or traversal segment is refused before
  // it can shape a key. (presignR2Url also encodes each key
  // segment — this is the second layer, at the door.)
  for (const idField of ["blob_id", "session_id"]) {
    const v = body[idField];
    if (v !== undefined &&
        (typeof v !== "string" ||
         !/^[A-Za-z0-9._-]+$/.test(v) || v.includes(".."))) {
      return errorResponse("invalid_request",
        idField + " is not a well-formed platform id", 400);
    }
  }
  if (body.username !== undefined && body.username !== me) {
    return errorResponse(
      "identity_mismatch",
      "the blob belongs to the JWT's agent; body username disagrees",
      403,
    );
  }
  const tail = new URL(req.url).pathname.split("/").filter(Boolean)
    .pop() ?? "";
  const route = tail === "agentlink-blobs" ? "" : tail;
  try {
    switch (route) {
      case "delete":
        return await routeDelete(me, body);
      case "chunk":
        return await routeChunk(me, body);
      case "session_finish":
        return await routeSessionFinish(me, body);
      default:
        return errorResponse(
          "not_found", "unknown agentlink-blobs route", 404);
    }
  } catch (e) {
    return errorResponse(
      "blobs_internal",
      String(e instanceof Error ? e.message : e),
      500,
    );
  }
});
