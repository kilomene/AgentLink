// AgentLink v2.0 — login Edge Function (Phase 2, V2-BLUEPRINT
// "Login" route). Replaces the relay's key-signed hello +
// recovery-key reclaim with a stateless HTTP ceremony:
//
//   POST {method:"challenge", username}
//     -> {nonce, exp, relay, expires_in}
//   POST {method:"verify", username, nonce, exp, signature}
//     -> {supabase_jwt, firebase_token, expires_in}
//   POST {method:"recovery", username, recovery_key,
//         new_sign_pub, new_pubkey}
//     -> {supabase_jwt, firebase_token, expires_in, recovery_key}
//   POST {method:"register", username, sign_pub, pubkey}
//     -> {supabase_jwt, firebase_token, expires_in, recovery_key}
//
// Registration (v2.0.8) is FIRST-COME and fully automatic — the
// v1 relay's claiming hello, restored: a well-formed username
// nobody holds is claimed on the spot, bound to the identity
// keys the agent generated on its own machine. No password, no
// approval, no operator involvement exists anywhere in this
// ceremony. The account's recovery key is minted here, returned
// ONCE in this response, and stored only as its SHA-256 — the
// same issuance contract as the recovery method's rotation. A
// name that already has a row is refused {error:"username_taken"}
// and NOTHING is written: a taken name can only be re-entered
// through the recovery method with the key its owner holds.
//
// The challenge is STATELESS (no table needed): nonce =
// HMAC-SHA256-hex(AGENTLINK_LOGIN_HMAC, "<username>|<sign_pub>|<exp>")
// with exp = now + 60 (protocol.AUTH_CHALLENGE_TTL_SECONDS). The
// verify step recomputes the HMAC against the CURRENT al_users row,
// so a nonce dies the moment the key rotates, the expiry passes, or
// the HMAC does not match — there is nothing stored to replay
// against. The signature is verified over EXACTLY the relay's
// canonical bytes (protocol.auth_challenge_payload, mirrored in
// ../_shared/v200.ts) with this function's relay identity
// (env AGENTLINK_LOGIN_RELAY_ID, default "agentlink-login-v2")
// standing in the <relay> field — the same binding the relay got
// from its own server_id, under a v2 name the v2 client signs for.
//
// Failure shapes MIRROR the relay's _error payloads (relay.py):
// key failures are {error:"key_auth_failed", detail:"key-signed
// hello refused: the signature did not verify against the
// registered identity key"} and recovery failures are
// {error:"recovery_failed", detail:"recovery refused: ..."} — the
// same two detail strings the relay uses, so clients see one
// vocabulary across v1 and v2. No user-existence oracle beyond the
// relay's own: an unknown username / a row with no sign_pub gets a
// challenge computed over an empty sign_pub (indistinguishable on
// the wire) and then fails verify as key_auth_failed, exactly as
// the relay's challenge fails closed for such rows; recovery
// against an unknown username returns the relay's own
// "no such registered username" refusal, as relay.py does.
//
// RATE LIMITING (honest note): Edge instances are short-lived and
// do not share memory, so the per-instance fixed-window limiter
// below is a speed bump, not a platform guarantee — it mirrors the
// SPIRIT of the relay's per-username recovery-attempt counter
// (relay.py _recovery_attempts, which only logs). Durable,
// cross-instance rate limiting belongs in front of this function
// (platform / gateway limits) or in a future Postgres counter; it
// is NOT claimed here. Failed attempts never mutate the user row,
// exactly as a failed relay recovery/key hello changes nothing.
//
// Deploy: supabase functions deploy agentlink-login
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
// and AGENTLINK_JWT_SECRET are platform/project secrets;
// AGENTLINK_LOGIN_HMAC, FIREBASE_SERVICE_ACCOUNT_JSON are function
// secrets; AGENTLINK_LOGIN_RELAY_ID is optional config.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  authChallengePayload,
  b64decode,
  constantTimeEqual,
  Ed25519UnsupportedError,
  env,
  errorResponse,
  hmacSha256Hex,
  insertRow,
  jsonResponse,
  methodGuard,
  mintFirebaseCustomToken,
  mintSupabaseJwt,
  normalizeUsername,
  nowSeconds,
  patchRows,
  randomTokenUrlSafe,
  selectOne,
  sha256Hex,
  verifyEd25519,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const RELAY_ID = env("AGENTLINK_LOGIN_RELAY_ID") || "agentlink-login-v2";
const CHALLENGE_TTL_SECONDS = 60; // protocol.AUTH_CHALLENGE_TTL_SECONDS

const KEY_AUTH_FAILED_DETAIL =
  "key-signed hello refused: the signature did not verify against " +
  "the registered identity key";
const RECOVERY_UNKNOWN_DETAIL = "recovery refused: no such registered username";
const RECOVERY_FAILED_DETAIL =
  "recovery refused: the recovery key did not verify for this username";

// Per-instance fixed-window limiter (see the header's honest note).
const WINDOW_SECONDS = 60;
const LIMITS: Record<string, number> = {
  challenge: 30,
  verify: 20,
  recovery: 10,
  register: 10,
};
const attempts = new Map<string, { window: number; count: number }>();

function rateLimited(kind: string, username: string, ip: string): boolean {
  const key = kind + "|" + username + "|" + ip;
  const now = nowSeconds();
  const cur = attempts.get(key);
  if (!cur || now - cur.window >= WINDOW_SECONDS) {
    attempts.set(key, { window: now, count: 1 });
    return false;
  }
  cur.count += 1;
  return cur.count > (LIMITS[kind] ?? 20);
}

async function issueTokens(username: string) {
  const supabaseJwt = await mintSupabaseJwt(username);
  const firebaseToken = await mintFirebaseCustomToken(username);
  // The serverless welcome frame: advertise the owner-oversight
  // PUBLIC key with the session tokens, exactly as the v1 relay's
  // welcome frame did, so a zero-config agent adopts it at login
  // and seals an oversight wrap on every content send (the
  // dashboard's WhatsApp-style readability depends on it). The
  // private key never leaves the operator vault; this is public
  // material, safe on the wire. Absent the env, the field is
  // omitted and clients keep their locally configured key (or
  // none) — no behavior change.
  const oversightPubkey = env("AGENTLINK_OVERSIGHT_PUBKEY");
  return {
    ok: true,
    supabase_jwt: supabaseJwt,
    firebase_token: firebaseToken,
    expires_in: 3600,
    ...(oversightPubkey ? { oversight_pubkey: oversightPubkey } : {}),
  };
}

async function challengeNonce(
  username: string,
  signPub: string,
  exp: number,
): Promise<string> {
  const secret = env("AGENTLINK_LOGIN_HMAC");
  if (!secret) {
    throw new Error("AGENTLINK_LOGIN_HMAC is not set in this function's env");
  }
  return await hmacSha256Hex(secret, username + "|" + signPub + "|" + exp);
}

function isRawKey32(b64: unknown): boolean {
  if (typeof b64 !== "string" || !b64) return false;
  try {
    return b64decode(b64).length === 32;
  } catch {
    return false;
  }
}

Deno.serve(async (req: Request) => {
  const guard = methodGuard(req);
  if (guard) return guard;
  const body = await req.json().catch(() => ({})) as Record<string, unknown>;
  // method comes from the body ({username, method}); a path suffix
  // (/challenge, /verify, /recovery) is accepted as an alias.
  const pathTail = new URL(req.url).pathname.split("/").filter(Boolean).pop();
  const method = String(body.method ?? pathTail ?? "").toLowerCase();
  const username = normalizeUsername(body.username);
  if (!username) {
    return errorResponse("invalid_username", "username is not well-formed", 400);
  }
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "";

  try {
    // ------------------------------------------------ challenge
    if (method === "challenge") {
      if (rateLimited("challenge", username, ip)) {
        return errorResponse("rate_limited", "too many challenges; retry shortly", 429);
      }
      const row = await selectOne(supabase, "al_users", "sign_pub", {
        username,
      });
      // Unknown user / no key on record: HMAC over an empty sign_pub.
      // The response shape is identical either way (no oracle).
      const signPub = String(row?.sign_pub ?? "");
      const exp = nowSeconds() + CHALLENGE_TTL_SECONDS;
      const nonce = await challengeNonce(username, signPub, exp);
      // `expires` aliases `exp`: the Python client (transport_v2)
      // reads `expires`; both names carry the same value (v2.0
      // integration alignment — the canonical payload uses this int).
      return jsonResponse({ nonce, exp, expires: exp, relay: RELAY_ID, expires_in: CHALLENGE_TTL_SECONDS });
    }

    // --------------------------------------------------- verify
    if (method === "verify") {
      if (rateLimited("verify", username, ip)) {
        return errorResponse("rate_limited", "too many verify attempts; retry shortly", 429);
      }
      const fail = () => errorResponse("key_auth_failed", KEY_AUTH_FAILED_DETAIL, 401);
      const nonce = String(body.nonce ?? "");
      // Accept `exp` or its `expires` alias (the Python client sends
      // both; v2.0 integration alignment).
      const exp = Number(body.exp ?? body.expires ?? 0);
      const signature = String(body.signature ?? "");
      if (!nonce || !signature || !Number.isInteger(exp)) return fail();
      const now = nowSeconds();
      // The challenge's own expiry, checked before verification,
      // exactly as the relay checks it.
      if (exp <= now || exp > now + CHALLENGE_TTL_SECONDS + 5) return fail();
      const row = await selectOne(supabase, "al_users", "sign_pub", {
        username,
      });
      const signPub = String(row?.sign_pub ?? "");
      if (!signPub) return fail();
      const expectedNonce = await challengeNonce(username, signPub, exp);
      if (!constantTimeEqual(expectedNonce, nonce)) return fail();
      let ok = false;
      try {
        ok = await verifyEd25519(
          signPub,
          authChallengePayload(nonce, RELAY_ID, username, exp),
          signature,
        );
      } catch (e) {
        if (e instanceof Ed25519UnsupportedError) {
          return errorResponse("ed25519_unsupported", e.message, 500);
        }
        throw e;
      }
      if (!ok) return fail();
      await patchRows(supabase, "al_users", { username }, {
        last_seen: nowSeconds(),
        auth_method: "key-v2",
      });
      // Decision-link declaration (v2.0 coverage): the verify may
      // carry the client's declaration as ADDITIVE fields — the
      // serverless home of the relay hello's decision_link /
      // decision_link_detail. Persisted with the relay setters'
      // EXACT validation (store.set_decision_link /
      // set_decision_link_detail): the state lands only when it
      // is 'linked' or 'pending'; the detail lands only when it
      // is an object whose mode is lawful, stored as the cleaned
      // {mode, verified, checked_at} JSON text. Anything else is
      // ignored — never an error, never a partial write of a bad
      // shape — so the dashboard-visible state is the same truth
      // on both transports.
      const declaredLink = body.decision_link;
      if (declaredLink === "linked" || declaredLink === "pending") {
        await patchRows(supabase, "al_users", { username }, {
          decision_link: declaredLink,
        });
      }
      const declaredDetail = body.decision_link_detail;
      if (declaredDetail && typeof declaredDetail === "object" &&
          !Array.isArray(declaredDetail)) {
        const d = declaredDetail as Record<string, unknown>;
        const mode = String(d.mode ?? "");
        if (["config", "in_process", "handlers", "convention",
             "none"].includes(mode)) {
          await patchRows(supabase, "al_users", { username }, {
            decision_link_detail: JSON.stringify({
              mode,
              verified: Boolean(d.verified),
              checked_at: Number.isFinite(Number(d.checked_at))
                ? Math.trunc(Number(d.checked_at)) : 0,
            }),
          });
        }
      }
      return jsonResponse(await issueTokens(username));
    }

    // ------------------------------------------------- recovery
    if (method === "recovery") {
      if (rateLimited("recovery", username, ip)) {
        return errorResponse("rate_limited", "too many recovery attempts; retry shortly", 429);
      }
      const row = await selectOne(
        supabase,
        "al_users",
        "recovery_hash, sign_pub",
        { username },
      );
      if (!row) {
        // relay.py: a recovery hello against NO row is refused
        // recovery_failed and never becomes a fresh claim.
        return errorResponse("recovery_failed", RECOVERY_UNKNOWN_DETAIL, 401);
      }
      const presented = String(body.recovery_key ?? "");
      const storedHash = String(row.recovery_hash ?? "");
      const presentedHash = presented ? await sha256Hex(presented) : "";
      // Constant-time compare; an unenrolled row ('' hash) fails
      // here too — the relay lumps both as the same refusal.
      if (
        !presented || !storedHash ||
        !constantTimeEqual(presentedHash, storedHash)
      ) {
        return errorResponse("recovery_failed", RECOVERY_FAILED_DETAIL, 401);
      }
      // v1.7.0 semantics: the verified recovery rebinds the account
      // to the agent's FRESH identity keys. Both must be raw
      // 32-byte keys in crypto.py's standard base64.
      const newSignPub = String(body.new_sign_pub ?? "");
      const newPubkey = String(body.new_pubkey ?? "");
      if (!isRawKey32(newSignPub) || !isRawKey32(newPubkey)) {
        return errorResponse(
          "invalid_key_material",
          "new_sign_pub and new_pubkey must be base64 raw 32-byte keys",
          400,
        );
      }
      const now = nowSeconds();
      // The used key BURNS and its successor is issued in the same
      // response, returned ONCE (only its SHA-256 is stored). The
      // legacy account secret rotates too, mirroring relay.py's
      // recovery path (set_secret of a fresh secret; hash only is
      // stored — v2 never uses or returns that secret).
      const newRecoveryKey = randomTokenUrlSafe(32);
      const rotatedSecret = randomTokenUrlSafe(24);
      await patchRows(supabase, "al_users", { username }, {
        sign_pub: newSignPub,
        pubkey: newPubkey,
        secret: await sha256Hex(rotatedSecret),
        recovery_hash: await sha256Hex(newRecoveryKey),
        recovery_used_at: now,
        auth_method: "recovery",
        last_seen: now,
      });
      // Grant rebind (relay.py, v1.8.0): an ACTIVE grant follows
      // the proven identity to its new signing key.
      await patchRows(
        supabase,
        "al_grants",
        { username, status: "active" },
        { bound_sign_pub: newSignPub, updated_at: now },
        (q) => q.neq("bound_sign_pub", newSignPub),
      );
      const tokens = await issueTokens(username);
      return jsonResponse({ ...tokens, recovery_key: newRecoveryKey });
    }

    // ------------------------------------------------- register
    if (method === "register") {
      if (rateLimited("register", username, ip)) {
        return errorResponse("rate_limited", "too many registration attempts; retry shortly", 429);
      }
      // First-come claim of an unheld name (v2.0.8 — see the
      // header). Key material is validated exactly as the
      // recovery method validates a rebind: raw 32-byte keys in
      // crypto.py's standard base64.
      const signPub = String(body.sign_pub ?? "");
      const pubkey = String(body.pubkey ?? "");
      if (!isRawKey32(signPub) || !isRawKey32(pubkey)) {
        return errorResponse(
          "invalid_key_material",
          "sign_pub and pubkey must be base64 raw 32-byte keys",
          400,
        );
      }
      const existing = await selectOne(
        supabase,
        "al_users",
        "username",
        { username },
      );
      if (existing) {
        // A taken name is never re-issued and nothing is
        // written: the only way back into it is the recovery
        // method with the key the account's owner holds.
        return errorResponse(
          "username_taken",
          "that username is already registered; if it is yours, " +
            "reclaim it with your recovery key",
          409,
        );
      }
      const now = nowSeconds();
      // The recovery key is minted here and returned ONCE in
      // this response; only its SHA-256 is stored — the
      // recovery method's issuance contract. The legacy account
      // secret is born hashed the same way (v2 never uses or
      // returns it).
      const newRecoveryKey = randomTokenUrlSafe(32);
      const bornSecret = randomTokenUrlSafe(24);
      // The decision-link declaration rides registration with
      // the verify step's exact validation (additive fields;
      // anything unlawful is ignored, never an error).
      const secret = await sha256Hex(bornSecret);
      const row: Record<string, unknown> = {
        username,
        secret,
        sign_pub: signPub,
        pubkey,
        created_at: now,
        last_seen: now,
        auth_method: "register",
        recovery_hash: await sha256Hex(newRecoveryKey),
      };
      if (body.decision_link === "linked" || body.decision_link === "pending") {
        row.decision_link = body.decision_link;
      }
      // Registration designation (v1.6.0 contract): declared at
      // registration only — 'test' files the identity under the
      // dashboard's probe segregation; anything else is the
      // column default (production). After registration only
      // the operator path changes it.
      if (body.designation === "test" || body.designation === "production") {
        row.designation = body.designation;
      }
      const declaredDetail = body.decision_link_detail;
      if (declaredDetail && typeof declaredDetail === "object" &&
          !Array.isArray(declaredDetail)) {
        const d = declaredDetail as Record<string, unknown>;
        const mode = String(d.mode ?? "");
        if (["config", "in_process", "handlers", "convention",
             "none"].includes(mode)) {
          row.decision_link_detail = JSON.stringify({
            mode,
            verified: Boolean(d.verified),
            checked_at: Number.isFinite(Number(d.checked_at))
              ? Math.trunc(Number(d.checked_at)) : 0,
          });
        }
      }
      try {
        await insertRow(supabase, "al_users", row);
      } catch (e) {
        // A simultaneous claim of the same name: the loser's
        // insert fails on the key — report the truth (taken),
        // never a fake internal error.
        const raced = await selectOne(
          supabase,
          "al_users",
          "username",
          { username },
        );
        if (raced) {
          return errorResponse(
            "username_taken",
            "that username is already registered; if it is yours, " +
              "reclaim it with your recovery key",
            409,
          );
        }
        throw e;
      }
      const tokens = await issueTokens(username);
      return jsonResponse({ ...tokens, recovery_key: newRecoveryKey });
    }

    return errorResponse(
      "unknown_method",
      "method must be challenge, verify, recovery or register",
      400,
    );
  } catch (e) {
    // Config defects (missing env, unreadable service-account JSON)
    // surface as a named 500 — never as a fake auth failure, and
    // the message names env NAMES only, never values.
    return errorResponse("login_internal", String(e instanceof Error ? e.message : e), 500);
  }
});
