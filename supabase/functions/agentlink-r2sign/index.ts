// AgentLink v2.0 — R2 presign Edge Function (Phase 2, V2-BLUEPRINT
// "Files" route). Agents hold NO R2 credential: they present the
// Supabase JWT from agentlink-login, and this function — after a
// membership check against the al_blobs row — mints a 15-minute
// presigned URL (full AWS SigV4, implemented in ../_shared/v200.ts
// with WebCrypto HMAC) and the bytes then flow agent <-> R2
// directly. Files never enter Supabase or Firebase.
//
//   POST  Authorization: Bearer <agent supabase_jwt>
//         {action:"get"|"put", blob_id}
//     ->  {url, expires_in:900, method:"GET"|"PUT"}
//     401 {error:"unauthorized"}      bad / expired JWT
//     403 {error:"forbidden"}         blob unknown OR not entitled
//     400 {error:"invalid_request"}   bad action / blob_id
//
// ENTITLEMENT mirrors the al_blobs columns (schema.sql): the caller
// (the JWT's username claim — never a body field) is entitled when
// it is the blob's owner, its for_user, a CURRENT member of its
// for_group (al_group_members), or a CURRENT member of its
// for_channel (al_channel_members). Unknown blob and unentitled
// blob return the SAME 403, so the endpoint is not a blob-existence
// oracle. NOTE for "put": blob ids are ciphertext SHA-256 based
// (schema.sql) and a put for a NEW blob has no al_blobs row yet —
// by the no-oracle rule above it is refused like any unknown blob;
// registering the row first (the v1 upload-session flow's job)
// stays a precondition of signing, and that boundary is deliberate:
// this function never invents entitlement for an unregistered id.
//
// Deploy: supabase functions deploy agentlink-r2sign
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_JWT_SECRET, R2_ACCOUNT_ID, R2_BUCKET,
// R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  bearerToken,
  errorResponse,
  jsonResponse,
  methodGuard,
  presignR2Url,
  r2ConfigFromEnv,
  selectOne,
  verifyAgentJwt,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const PRESIGN_TTL_SECONDS = 900; // 15 minutes (blueprint)

Deno.serve(async (req: Request) => {
  const guard = methodGuard(req);
  if (guard) return guard;

  const claims = await verifyAgentJwt(bearerToken(req));
  if (!claims?.username) {
    return errorResponse("unauthorized", "a valid agent JWT is required", 401);
  }
  const username = claims.username;

  const body = await req.json().catch(() => ({})) as Record<string, unknown>;
  const action = String(body.action ?? "");
  const blobId = String(body.blob_id ?? "");
  if ((action !== "get" && action !== "put") || !blobId || blobId.length > 512) {
    return errorResponse(
      "invalid_request",
      "body must be {action:'get'|'put', blob_id}",
      400,
    );
  }

  const blob = await selectOne(
    supabase,
    "al_blobs",
    "id, owner, for_user, for_group, for_channel",
    { id: blobId },
  );

  let entitled = false;
  if (blob) {
    if (blob.owner === username || blob.for_user === username) {
      entitled = true;
    } else if (blob.for_group) {
      const member = await selectOne(supabase, "al_group_members", "username", {
        group_id: String(blob.for_group),
        username,
      });
      entitled = Boolean(member);
    } else if (blob.for_channel) {
      const member = await selectOne(supabase, "al_channel_members", "username", {
        channel_id: String(blob.for_channel),
        username,
      });
      entitled = Boolean(member);
    }
  }
  if (!entitled) {
    return errorResponse(
      "forbidden",
      "the caller is not entitled to this blob",
      403,
    );
  }

  try {
    const method = action === "get" ? "GET" : "PUT";
    const url = await presignR2Url(
      r2ConfigFromEnv(),
      method,
      blobId,
      PRESIGN_TTL_SECONDS,
    );
    return jsonResponse({ url, method, expires_in: PRESIGN_TTL_SECONDS });
  } catch (e) {
    return errorResponse(
      "r2sign_internal",
      String(e instanceof Error ? e.message : e),
      500,
    );
  }
});
