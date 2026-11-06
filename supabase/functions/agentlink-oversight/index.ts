// AgentLink v2.0 — owner-oversight Edge Function (Phase 2,
// V2-BLUEPRINT "Dashboard" route). The v1 dashboard opened oversight
// wraps server-side inside the operator's authenticated session
// (agentlink/dashboard.py _oversight_open); in v2 the dashboard is
// static on Pages, so THIS function is the only place the oversight
// private key exists, and plaintext leaves it only over the
// authenticated path below.
//
// AUTH: the caller presents {session_token} — the dashboard's
// trusted-device session token. It is validated exactly the way
// agentlink-api validates its bearer: SHA-256 hex of the token
// against al_dashboard_sessions.token_hash, not expired
// (expires_at is epoch seconds). The dashboard PASSWORD is never
// handled here — session issuance stays wherever it lives today;
// this function only consumes the resulting session token. (The
// token may also arrive as an Authorization: Bearer header.)
// ADDITIONALLY (v2.0 integration alignment with dashboard-v2 +
// agentlink-dashboard): an operator JWT — HS256-verified against
// AGENTLINK_JWT_SECRET, carrying the operator claim minted by the
// dashboard-login function — is accepted as the Bearer credential,
// since that is what the static dashboard actually presents.
//
//   POST {items:[{id, oversight, content_envelope?}]}   (batch —
//     the dashboard-v2 conversations contract) -> {id: fields}
//     where fields mirrors dashboard.py _content_fields:
//     {text, content_kind, file_name, title}; items whose wrap
//     does not open are OMITTED (the view leaves them sealed).
//   POST {credentials_for: <username>}  -> {entries:[...]} from
//     the user's al_users.vault_content wrap ({kind:"vault_content",
//     entries}); {entries: []} when the user has no vault content.
//   POST {session_token, envelope, content_envelope?}
//     envelope: one oversight wrap, as a JSON object or the JSON
//     TEXT stored in al_audit_log.oversight / al_users.vault_content
//       {v, alg:"x25519-chacha20poly1305", eph_pub, nonce, ct,
//        kind?: "content" | "content_key"}
//     -> kind "content" (or kind-less): the wrap seals the content
//        payload JSON itself; returns
//        {ok:true, kind:"content", content:<parsed JSON or null>,
//         plaintext_utf8:<string|null>, plaintext_b64:<base64>}
//     -> kind "content_key": the wrap seals a raw symmetric key
//        (group/channel/file key); the caller must also pass
//        content_envelope {nonce, ct} (al_audit_log.content_
//        envelope's shape) and the KEY IS NEVER RETURNED — only
//        the content it opens, under the same response shape.
//        Without content_envelope: 400 needs_content_envelope.
//     401 {error:"unauthorized"}  no / unknown / expired session
//     422 {error:"sealed"}         the wrap does not open (wrong key
//                                  or corrupt envelope) — content is
//                                  never guessed or faked, mirroring
//                                  dashboard.py returning None.
//   POST {file_item:{oversight, content_envelope}} |
//        {vault_file:{descriptor}} |
//        {library_file:{work_id, sha256, filename, size}}
//     -> the file's verified plaintext BYTES (v2.0.5 — the owner's
//        v1 in-chat media ruling of 2026-11-03 carried into v2:
//        media renders/plays in the thread, every file downloads
//        in place, Library + Vault downloads included). Inline
//        payloads must pass protocol.verify_file; blob payloads
//        are decrypted via the descriptor's oversight key wrap and
//        must match sha256 + size. Any failure is 404
//        {error:"file_unavailable"} — unverified bytes are never
//        served, mirroring v1's file routes. File keys are used
//        inside this function only and never returned.
//
// THE SCHEME (crypto.py, mirrored byte-for-byte): ephemeral X25519
// -> HKDF-SHA256(salt=None, info=b"agentlink-e2ee-v1", len 32) ->
// ChaCha20Poly1305, 12-byte nonce, tag appended to ct. WebCrypto
// has neither ChaCha20-Poly1305 nor (portably) X25519, so
// ../_shared/v200.ts carries small self-contained routines for both
// (RFC 7748 ladder + RFC 8439 AEAD over BigInt). COMPLETENESS: the
// decryption is FULLY implemented and was cross-verified during
// the Phase-2 build against envelopes produced by the real Python
// crypto.py (encrypt_to_pubkey -> this code opened them, and the
// X25519 output matched the Python cryptography library on fixed
// vectors) — see ~/workspace/drill-evidence/v200/phase2-edge.md.
// No part of the decrypt path is stubbed.
//
// OVERSIGHT_PRIVATE_KEY: base64 of the raw 32-byte X25519 private
// key (the "private_key" value of the oversight key file crypto.py
// writes). If the env value is instead the key file's JSON text,
// its private_key field is used — the same tolerance dashboard.py's
// loader shows the file. The value is never logged or returned.
//
// Deploy: supabase functions deploy oversight
// DEPLOY SLUG: the static frontend (dashboard-v2/js/data.js) calls
// POST {edgeBase}/oversight, so this function is deployed under
// the slug `oversight` (Supabase routes by slug, not by source
// directory name) — the same arrangement as agentlink-dashboard
// deploying as `dashboard-login`.
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// OVERSIGHT_PRIVATE_KEY, R2_ACCOUNT_ID, R2_BUCKET,
// R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY (the R2 set serves the
// blob-form file route; same values the blobs function holds).

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  b64decode,
  b64encode,
  bearerToken,
  CORS_HEADERS,
  decryptWithKey,
  env,
  errorResponse,
  jsonResponse,
  methodGuard,
  nowSeconds,
  openSealedEnvelope,
  presignR2Url,
  r2ConfigFromEnv,
  selectOne,
  sha256Hex,
  verifyAgentJwt,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

async function sessionValid(token: string): Promise<boolean> {
  if (!token) return false;
  const row = await selectOne(supabase, "al_dashboard_sessions", "expires_at", {
    token_hash: await sha256Hex(token),
  });
  return Boolean(row) && Number(row?.expires_at ?? 0) > nowSeconds();
}

/** The dashboard-v2 path: an operator JWT (minted by the
 * dashboard-login function) presented as Bearer. Verified HS256
 * against AGENTLINK_JWT_SECRET via the shared verifier; the
 * operator claim is required — an ordinary AGENT jwt never opens
 * oversight. */
async function operatorAuthorized(req: Request): Promise<boolean> {
  const token = bearerToken(req);
  if (!token || token.split(".").length !== 3) return false;
  const claims = await verifyAgentJwt(token).catch(() => null);
  if (!claims) return false;
  return claims.operator === true || claims.app_role === "operator";
}

function oversightPrivateKeyB64(): string {
  const raw = env("OVERSIGHT_PRIVATE_KEY");
  if (!raw) {
    throw new Error("OVERSIGHT_PRIVATE_KEY is not set in this function's env");
  }
  const trimmed = raw.trim();
  if (trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed) as Record<string, unknown>;
      if (typeof parsed.private_key === "string") return parsed.private_key;
    } catch {
      // fall through to the plain-base64 interpretation below
    }
  }
  return trimmed;
}

interface Wrap {
  kind?: string;
  eph_pub?: string;
  nonce?: string;
  ct?: string;
  ciphertext?: string;
  wrapped_key?: Wrap;
  [k: string]: unknown;
}

function parseWrap(value: unknown): Wrap | null {
  if (typeof value === "string") {
    try {
      return parseWrap(JSON.parse(value));
    } catch {
      return null;
    }
  }
  if (value && typeof value === "object") return value as Wrap;
  return null;
}

function contentResponse(plaintext: Uint8Array): Response {
  let utf8: string | null = null;
  let parsed: unknown = null;
  try {
    utf8 = new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  } catch {
    utf8 = null;
  }
  if (utf8 !== null) {
    try {
      const obj = JSON.parse(utf8);
      // dashboard.py _content_fields: only a JSON OBJECT counts as
      // content; scalars stay unrendered there, mirrored here by
      // content:null while the exact bytes still ride plaintext_*.
      parsed = obj && typeof obj === "object" && !Array.isArray(obj)
        ? obj
        : null;
    } catch {
      parsed = null;
    }
  }
  return jsonResponse({
    ok: true,
    kind: "content",
    content: parsed,
    plaintext_utf8: utf8,
    plaintext_b64: b64encode(plaintext),
  });
}

/** Open one oversight wrap to its CONTENT plaintext bytes — the
 * exact semantics of dashboard.py _oversight_open: kind "content"
 * (or kind-less) opens directly; kind "content_key" unwraps the
 * symmetric key and opens the sibling content envelope (the raw
 * key never leaves this function); the legacy wrapped_key shape
 * opens for parity. Throws on any failure (the caller decides
 * between the single-path 422 and batch omission). */
async function openWrapToBytes(
  priv: string,
  wrap: Wrap,
  contentEnvelope: { nonce?: string; ct?: string } | null,
): Promise<Uint8Array> {
  if (wrap.kind === "content_key") {
    if (!contentEnvelope?.nonce || !contentEnvelope.ct) {
      throw new Error("needs_content_envelope");
    }
    const key = await openSealedEnvelope(priv, wrap as {
      eph_pub: string;
      nonce: string;
      ct: string;
    });
    return decryptWithKey(key, {
      nonce: String(contentEnvelope.nonce),
      ct: String(contentEnvelope.ct),
    });
  }
  if (wrap.wrapped_key && typeof wrap.wrapped_key === "object") {
    const key = await openSealedEnvelope(priv, wrap.wrapped_key as {
      eph_pub: string;
      nonce: string;
      ct: string;
    });
    return decryptWithKey(key, {
      nonce: String(wrap.nonce ?? ""),
      ct: String(wrap.ciphertext ?? wrap.ct ?? ""),
    });
  }
  if (wrap.eph_pub && wrap.nonce && (wrap.ct || wrap.ciphertext)) {
    return openSealedEnvelope(priv, {
      eph_pub: String(wrap.eph_pub),
      nonce: String(wrap.nonce),
      ct: String(wrap.ct ?? wrap.ciphertext),
    });
  }
  throw new Error("invalid_envelope");
}

/** protocol.verify_file, mirrored: True only if the size and
 * sha256 of the decoded inline bytes match the payload header. */
async function verifyInlinePayload(
  f: Record<string, unknown>,
): Promise<boolean> {
  try {
    const raw = b64decode(String(f.data_b64 ?? ""));
    return raw.length === Number(f.size) &&
      (await sha256Hex(raw)) === String(f.sha256 ?? "");
  } catch {
    return false;
  }
}

/** Blob-form verified flag for the batch fields, mirroring
 * dashboard.py _attach_file: the descriptor's oversight wrap must
 * yield the file key AND the blob object must have a meta row.
 * The byte route below re-verifies the full sha256 over the
 * decrypted plaintext before serving a single byte — this flag
 * only decides what the thread renders. */
async function blobFormVerified(
  priv: string,
  f: Record<string, unknown>,
): Promise<boolean> {
  try {
    const wrap = parseWrap(f.oversight);
    if (!wrap || !f.blob_id || !f.blob_nonce) return false;
    const key = await openSealedEnvelope(priv, wrap as {
      eph_pub: string;
      nonce: string;
      ct: string;
    });
    if (key.length !== 32) return false;
    const row = await selectOne(supabase, "al_blobs", "id", {
      id: String(f.blob_id),
    });
    return Boolean(row);
  } catch {
    return false;
  }
}

/** dashboard.py _content_fields, mirrored: only a JSON OBJECT is
 * content; anything else returns null and the item stays sealed.
 * v2.0.5 (owner's v1 in-chat media ruling, 2026-11-03, carried
 * into v2): when the content object carries a file, the fields
 * also carry the file's TRUE plaintext metadata (mime / size /
 * sha256 from the payload itself — never the envelope size) and
 * its carriage form + verified flag, so the thread can render
 * media inline and offer real downloads. Bytes never ride this
 * batch response; they are served by the file routes below. */
async function fieldsFromPlaintext(
  priv: string,
  plaintext: Uint8Array,
): Promise<Record<string, unknown> | null> {
  let obj: Record<string, unknown>;
  try {
    obj = JSON.parse(new TextDecoder().decode(plaintext)) as Record<string, unknown>;
  } catch {
    return null;
  }
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return null;
  const f = (obj.file && typeof obj.file === "object")
    ? obj.file as Record<string, unknown>
    : {};
  const text = obj.body || obj.instructions || obj.note || "";
  const fields: Record<string, unknown> = {
    text: typeof text === "string" ? text : String(text),
    content_kind: obj.kind || f.kind || "text",
    file_name: f.filename || f.name || "",
    title: obj.title || "",
  };
  if (fields.file_name) {
    fields.file_mime = typeof f.mime === "string" && f.mime
      ? f.mime
      : "application/octet-stream";
    fields.file_size = typeof f.size === "number" ? f.size : null;
    fields.file_kind = typeof f.kind === "string" ? f.kind : "";
    fields.file_sha256 = typeof f.sha256 === "string" ? f.sha256 : "";
    if (typeof f.data_b64 === "string") {
      fields.file_form = "inline";
      fields.file_verified = await verifyInlinePayload(f);
    } else if (f.blob_id) {
      fields.file_form = "blob";
      fields.file_verified = await blobFormVerified(priv, f);
    }
  }
  return fields;
}

function fileUnavailable(): Response {
  return errorResponse(
    "file_unavailable",
    "the file's bytes could not be verified under oversight",
    404,
  );
}

/** Fetch + decrypt + fully verify blob bytes via a descriptor's
 * nested oversight wrap (kind content_key -> file key), mirroring
 * dashboard.py _blob_descriptor_bytes, with the v1 fail-closed
 * rule: sha256 + size over the DECRYPTED plaintext must match the
 * descriptor before a single byte is served. */
async function blobDescriptorBytes(
  priv: string,
  desc: Record<string, unknown>,
): Promise<Uint8Array | null> {
  try {
    const wrap = parseWrap(desc.oversight);
    if (!wrap || !desc.blob_id || !desc.blob_nonce) return null;
    const key = await openSealedEnvelope(priv, wrap as {
      eph_pub: string;
      nonce: string;
      ct: string;
    });
    if (key.length !== 32) return null;
    const cfg = r2ConfigFromEnv();
    if (!cfg) return null;
    const url = await presignR2Url(cfg, "GET", String(desc.blob_id), 900);
    const resp = await fetch(url);
    if (!resp.ok) return null;
    const ct = new Uint8Array(await resp.arrayBuffer());
    const plain = decryptWithKey(key, {
      nonce: String(desc.blob_nonce),
      ct: b64encode(ct),
    });
    if (typeof desc.size === "number" && plain.length !== desc.size) {
      return null;
    }
    if (desc.sha256 && (await sha256Hex(plain)) !== String(desc.sha256)) {
      return null;
    }
    return plain;
  } catch {
    return null;
  }
}

/** Serve one file payload (a content object's `file`, a delivery
 * file entry, or a vault descriptor) as verified raw bytes —
 * the v2 form of v1's GET /api/file/<item_id> + /api/blob routes.
 * Inline payloads must pass protocol.verify_file; blob payloads
 * must pass the full decrypt + sha256 + size verification. Every
 * failure is the same plain 404: unverified bytes are never
 * served. Media mime types are served inline (the dashboard
 * renders/plays them in the thread); everything else downloads. */
async function serveFilePayload(
  priv: string,
  f: Record<string, unknown> | null,
): Promise<Response> {
  if (!f || typeof f !== "object") return fileUnavailable();
  let bytes: Uint8Array | null = null;
  if (typeof f.data_b64 === "string") {
    try {
      const raw = b64decode(f.data_b64);
      if (raw.length === Number(f.size) &&
        (await sha256Hex(raw)) === String(f.sha256 ?? "")) {
        bytes = raw;
      }
    } catch {
      bytes = null;
    }
  } else if (f.blob_id) {
    bytes = await blobDescriptorBytes(priv, f);
  }
  if (!bytes) return fileUnavailable();
  const mime = typeof f.mime === "string" && f.mime
    ? f.mime
    : "application/octet-stream";
  const name = String(f.name || f.filename || "download")
    .replace(/["\r\n]/g, "");
  const inline = mime.startsWith("image/") || mime.startsWith("video/") ||
    mime.startsWith("audio/");
  return new Response(bytes, {
    headers: {
      "Content-Type": mime,
      "Content-Disposition": (inline ? "inline" : "attachment") +
        `; filename="${name}"`,
      "X-Content-SHA256": String(f.sha256 ?? ""),
      "Cache-Control": "private, no-store",
      // Browsers enforce CORS on the byte route exactly as on the
      // JSON routes: without these headers Safari/Chrome refuse to
      // expose the body to the dashboard and every file renders
      // "unavailable" even though verification passed (owner's
      // phone, 2026-11-06 — Node-side proofs could not see it
      // because Node fetch does not enforce CORS). Pinned by
      // tests/test_v200_integration.py::test_file_route_response_carries_cors.
      ...CORS_HEADERS,
      "access-control-expose-headers":
        "x-content-sha256, content-disposition, content-type",
    },
  });
}

/** dashboard.py _match_delivery_file, mirrored: find the
 * delivery-content file backing a library entry — exact sha256
 * match wins; filename+size is the fallback. */
function matchDeliveryFile(
  obj: Record<string, unknown>,
  entry: Record<string, unknown>,
): Record<string, unknown> | null {
  const cands: Record<string, unknown>[] = [];
  if (Array.isArray(obj.files)) {
    for (const f of obj.files) {
      if (f && typeof f === "object") {
        cands.push(f as Record<string, unknown>);
      }
    }
  }
  if (obj.file && typeof obj.file === "object") {
    cands.push(obj.file as Record<string, unknown>);
  }
  const sha = String(entry.sha256 ?? "");
  const name = String(entry.filename ?? "");
  const size = Number(entry.size ?? 0);
  for (const f of cands) {
    if (sha && f.sha256 === sha) return f;
  }
  for (const f of cands) {
    if (name && (f.name === name || f.filename === name) &&
      (!size || Number(f.size ?? 0) === size)) {
      return f;
    }
  }
  return null;
}

Deno.serve(async (req: Request) => {
  const guard = methodGuard(req);
  if (guard) return guard;
  const body = await req.json().catch(() => ({})) as Record<string, unknown>;

  const sessionToken = String(body.session_token ?? "") || bearerToken(req);
  if (!(await sessionValid(sessionToken)) && !(await operatorAuthorized(req))) {
    return errorResponse(
      "unauthorized",
      "a valid dashboard session is required",
      401,
    );
  }

  let priv: string;
  try {
    priv = oversightPrivateKeyB64();
  } catch (e) {
    return errorResponse(
      "oversight_not_configured",
      String(e instanceof Error ? e.message : e),
      500,
    );
  }

  // ---- batch contract (dashboard-v2 conversations) ---------------
  if (Array.isArray(body.items)) {
    const out: Record<string, unknown> = {};
    for (const raw of body.items as Record<string, unknown>[]) {
      const id = String(raw?.id ?? "");
      const wrap = parseWrap(raw?.oversight);
      if (!id || !wrap) continue;
      const ce = parseWrap(raw?.content_envelope) as
        | { nonce?: string; ct?: string }
        | null;
      try {
        const fields = await fieldsFromPlaintext(
          priv,
          await openWrapToBytes(priv, wrap, ce),
        );
        if (fields) out[id] = fields;
      } catch {
        // stays sealed: omitted, exactly dashboard.py's None
      }
    }
    return jsonResponse(out);
  }

  // ---- credentials contract (dashboard-v2 credentials view) ------
  if (typeof body.credentials_for === "string" && body.credentials_for) {
    const row = await selectOne(supabase, "al_users", "vault_content", {
      username: body.credentials_for,
    });
    const wrap = parseWrap(row?.vault_content);
    if (!wrap) return jsonResponse({ entries: [] });
    try {
      const plaintext = await openWrapToBytes(priv, wrap, null);
      const payload = JSON.parse(new TextDecoder().decode(plaintext)) as
        Record<string, unknown>;
      const entries = payload?.kind === "vault_content" &&
          Array.isArray(payload.entries)
        ? payload.entries
        : [];
      return jsonResponse({ entries });
    } catch (e) {
      const msg = String(e instanceof Error ? e.message : e);
      if (msg.includes("OVERSIGHT_PRIVATE_KEY")) {
        return errorResponse("oversight_not_configured", msg, 500);
      }
      return errorResponse("sealed", "the vault content did not open", 422);
    }
  }

  // ---- file byte routes (v2.0.5, owner's v1 in-chat media ruling)
  // The thread renders images/video/audio inline and downloads
  // every other file IN the conversation; the Library and the
  // group Vault download the same way. Bytes leave only after
  // full verification (see serveFilePayload) — every failure is
  // a plain 404 file_unavailable, never unverified bytes.
  //   POST {file_item:{oversight, content_envelope}} — one
  //     conversation item's file (statelessly re-derived from its
  //     wraps, exactly v1's _inline_file_bytes discipline).
  //   POST {vault_file:{descriptor}} — a group-vault entry's
  //     stored blob descriptor (dashboard.py _vault_bytes).
  //   POST {library_file:{work_id, sha256, filename, size}} — a
  //     delivery-library entry, resolved through its work's
  //     work_delivered audit rows (dashboard.py _library_bytes).
  if (body.file_item && typeof body.file_item === "object") {
    const fi = body.file_item as Record<string, unknown>;
    const wrap = parseWrap(fi.oversight);
    if (!wrap) return fileUnavailable();
    const ce = parseWrap(fi.content_envelope) as
      | { nonce?: string; ct?: string }
      | null;
    try {
      const plaintext = await openWrapToBytes(priv, wrap, ce);
      const obj = JSON.parse(new TextDecoder().decode(plaintext)) as
        Record<string, unknown>;
      const f = obj?.file && typeof obj.file === "object"
        ? obj.file as Record<string, unknown>
        : null;
      return await serveFilePayload(priv, f);
    } catch {
      return fileUnavailable();
    }
  }

  if (body.vault_file && typeof body.vault_file === "object") {
    const vf = body.vault_file as Record<string, unknown>;
    const desc = parseWrap(vf.descriptor) as
      | Record<string, unknown>
      | null;
    return await serveFilePayload(priv, desc);
  }

  if (body.library_file && typeof body.library_file === "object") {
    const lf = body.library_file as Record<string, unknown>;
    const workId = String(lf.work_id ?? "");
    if (!workId) return fileUnavailable();
    const { data, error } = await supabase
      .from("al_audit_log")
      .select("oversight, content_envelope")
      .eq("kind", "work_delivered")
      .eq("work_id", workId)
      .order("ts", { ascending: false })
      .limit(10);
    if (error || !data) return fileUnavailable();
    for (const row of data as Record<string, unknown>[]) {
      const wrap = parseWrap(row.oversight);
      if (!wrap) continue;
      const ce = parseWrap(row.content_envelope) as
        | { nonce?: string; ct?: string }
        | null;
      try {
        const plaintext = await openWrapToBytes(priv, wrap, ce);
        const obj = JSON.parse(new TextDecoder().decode(plaintext)) as
          Record<string, unknown>;
        if (!obj || typeof obj !== "object") continue;
        const match = matchDeliveryFile(obj, lf);
        if (match) return await serveFilePayload(priv, match);
      } catch {
        // this delivery row does not open/match — try the next
      }
    }
    return fileUnavailable();
  }

  // ---- single-envelope contract (original) -----------------------
  const wrap = parseWrap(body.envelope);
  if (!wrap) {
    return errorResponse(
      "invalid_envelope",
      "envelope must be an oversight wrap object or its JSON text",
      400,
    );
  }
  const contentEnvelope = parseWrap(body.content_envelope) as
    | { nonce?: string; ct?: string }
    | null;

  try {
    return contentResponse(
      await openWrapToBytes(priv, wrap, contentEnvelope),
    );
  } catch (e) {
    // A tag mismatch / bad shared secret lands here: the item stays
    // sealed (422), exactly dashboard.py's None. Config defects keep
    // their own message so the operator can tell them apart, and the
    // structural refusals keep their original 400s.
    const msg = String(e instanceof Error ? e.message : e);
    if (msg.includes("OVERSIGHT_PRIVATE_KEY")) {
      return errorResponse("oversight_not_configured", msg, 500);
    }
    if (msg === "needs_content_envelope") {
      return errorResponse(
        "needs_content_envelope",
        "a content_key wrap opens nothing alone: pass the sibling " +
          "content_envelope {nonce, ct}",
        400,
      );
    }
    if (msg === "invalid_envelope") {
      return errorResponse(
        "invalid_envelope",
        "envelope carries no openable wrap (eph_pub/nonce/ct missing)",
        400,
      );
    }
    return errorResponse("sealed", "the oversight wrap did not open", 422);
  }
});
