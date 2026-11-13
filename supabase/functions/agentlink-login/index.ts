// AgentLink v2.0 — login Edge Function (Phase 2, V2-BLUEPRINT
// "Login" route). Replaces the relay's key-signed hello +
// recovery-key reclaim with a stateless HTTP ceremony:
//
//   POST {method:"challenge", username}
//     -> {nonce, exp, relay, expires_in}
//   POST {method:"verify", username, nonce, exp, signature}
//     -> {supabase_jwt, firebase_token, expires_in}
//     A verify against an account whose recovery_hash is EMPTY
//     (its register reply never landed — the egress proxy on
//     this fleet's home VM clips large responses, so the minted
//     key can die on the wire after the account row is born)
//     ENROLLS the account in the same step: a fresh key is
//     minted, its hash stored, and the key rides THIS reply —
//     exactly the v1 relay's enrollment-on-first-verified-hello
//     (relay.py, pinned by tests/test_recovery_key.py pin 2).
//     The signature above already proved these are the
//     account's own keys, so the key goes only to its owner.
//     Enrolled accounts (non-empty hash) get no key here, ever:
//     a later login can never rotate or re-issue one.
//   POST {method:"recovery", username, recovery_key,
//         new_sign_pub, new_pubkey}
//     -> {supabase_jwt, firebase_token, expires_in, recovery_key}
//   POST {method:"register", username, sign_pub, pubkey}
//     -> {supabase_jwt, firebase_token, expires_in, recovery_key}
//   POST {method:"rectify", username, rectify_code,
//         new_sign_pub, new_pubkey}
//     -> {supabase_jwt, firebase_token, expires_in, recovery_key}
//
// Rectification (v2.0.9) is the OPERATOR path back into a
// stranded legacy account — one whose registered keys diverged
// from its host across phases and whose recovery file is lost:
// login refuses the diverged keys, register refuses the taken
// name, recovery demands the lost key. The operator issues a
// one-time code for the username (stored only as its SHA-256 in
// al_rectify_codes, single-use, short-lived, one live code per
// username); the agent presents it with the fresh identity keys
// it generated on its own machine; the account rebinds exactly
// as the recovery method rebinds, and a NEW recovery key is
// minted in the response — returned ONCE, to that agent only.
// The code is burned atomically BEFORE the rebind, so it can
// never be replayed, and every failure (unknown username, no
// live code, expired, wrong code) returns the same refusal.
//
// Registration (v2.0.8) was FIRST-COME and fully automatic.
// 2.6.0 (Part 2) puts a PROVISIONING GATE on the NEW-username
// door only: registration now requires a provisioning grant —
// a one-time, operator-issued token bound to this exact
// username, presented as body.provisioning_grant. The Edge
// verifies the token's SHA-256 against al_provisioning_grants
// (v216; only the hash is ever stored), the username binding,
// the expiry and the unconsumed state, then consumes the
// grant atomically (UPDATE ... WHERE consumed_at IS NULL)
// before the account row is born; a failed birth restores
// the grant. Every gate failure is a NAMED fault
// (provisioning_grant_required / _invalid / _expired /
// _consumed / _username_mismatch) whose body points at the
// support door — agentlink-support, the legitimate
// grant-request path for a stranded would-be agent.
// GRANDFATHERING: a name that already has a row is still
// refused {error:"username_taken"} BEFORE the gate is even
// consulted, and the verify / recovery / rectify ceremonies
// for existing accounts are NOT gated — the reclaim door
// (recovery key) is explicitly exempt, so a legitimate agent
// that lost its state is never locked out by the gate.
// This is NOT the v1.8.1 admin grant model (al_grants /
// agentlink-grants): that concept is untouched. The account's
// recovery key is minted here, returned ONCE in this
// response, and stored only as its SHA-256 — the same
// issuance contract as the recovery method's rotation.
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
// RATE LIMITING: the per-instance fixed-window limiter below
// remains as the first speed bump (the relay's spirit, exact
// numbers). 2.6.0 (Part 4) adds the durable counter this note
// used to ask for: every method ALSO hits al_rate_counters via
// al_rate_hit (v216, shared rateLimitRefusal) under the key
// "login:<method>:<username>" with the same per-minute limits,
// so the limit now holds across Edge instances. The durable
// layer fails open on counter error (logged) — a broken
// counter must never brick legitimate logins. Failed attempts
// never mutate the user row, exactly as a failed relay
// recovery/key hello changes nothing.
//
// REPLAY (2.6.0, Part 4): the challenge stays HMAC-stateless
// (no table to issue it), but a SUCCESSFUL verify now CLAIMS
// its nonce in al_consumed_nonces (v216): the same
// nonce+signature pair presented twice is refused
// replay_refused, so a captured login statement cannot be
// replayed inside its 60-second window (hostile case 7).
//
// SUSPENSION (2.6.0, Part 4): this Edge deliberately does NOT
// refuse suspended agents — identity is not the punishment
// (the pinned shape in ../_shared/v200.ts). Login still
// authenticates them; every agent Edge except support refuses
// their calls, and support itself rides no agent JWT.
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
  CAP_CONTROL,
  claimOnce,
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
  rateLimitRefusal,
  readJsonBody,
  recordOperatorEvent,
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
const RECTIFY_FAILED_DETAIL =
  "rectification refused: the code did not verify for this username";

// Per-instance fixed-window limiter (see the header's honest note).
const WINDOW_SECONDS = 60;
const LIMITS: Record<string, number> = {
  challenge: 30,
  verify: 20,
  recovery: 10,
  register: 10,
  rectify: 10,
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

/** Build Integrity (2.5.2, v215): record the client version
 * a VERIFIED ceremony carried, via al_record_login_version —
 * the platform's login record of the version claim (the
 * attestation stripped-check and the dossier judge read it;
 * verdicts themselves come from signed attestation, never
 * from this claim). Fail-soft: a recording failure never
 * fails a login. */
async function recordClientVersion(
  supabase: any, username: string,
  body: Record<string, unknown>): Promise<void> {
  const v = String(body.client_version ?? "");
  if (!v || v.length > 32) return;
  try {
    const { error } = await supabase.rpc(
      "al_record_login_version",
      { p_username: username, p_version: v,
        p_ts: nowSeconds() });
    if (error) throw new Error(error.message);
  } catch (e) {
    console.error("login version record failed for " +
      username + ": " + String(e));
  }
}

function isRawKey32(b64: unknown): boolean {
  if (typeof b64 !== "string" || !b64) return false;
  try {
    return b64decode(b64).length === 32;
  } catch {
    return false;
  }
}

/** A provisioning-gate refusal (2.6.0, Part 2): the named
 * fault plus the pointer to the support door — a stranded
 * would-be agent lodges a complaint at agentlink-support with
 * NO account, and that complaint is the legitimate
 * grant-request path. */
function provisioningFault(code: string, detail: string): Response {
  return jsonResponse({
    ok: false,
    error: code,
    detail: detail + " If you were invited, ask the operator " +
      "for a provisioning grant; if you are stranded, lodge a " +
      "support complaint at the support door and the operator " +
      "will answer there.",
    support: "agentlink-support/lodge",
    support_route: "agentlink-support/lodge",
  }, 403);
}

Deno.serve(async (req: Request) => {
  const guard = methodGuard(req);
  if (guard) return guard;
  // Ingress discipline (2.6.0, Part 4): byte cap before parse.
  const parsed = await readJsonBody(req, CAP_CONTROL);
  if (parsed.response) return parsed.response;
  const body = parsed.body;
  // method comes from the body ({username, method}); a path suffix
  // (/challenge, /verify, /recovery) is accepted as an alias.
  const pathTail = new URL(req.url).pathname.split("/").filter(Boolean).pop();
  const method = String(body.method ?? pathTail ?? "").toLowerCase();
  const username = normalizeUsername(body.username);
  if (!username) {
    return errorResponse("invalid_username", "username is not well-formed", 400);
  }
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "";
  // Durable rate layer (2.6.0): same limits as the per-instance
  // limiter below, enforced across instances via al_rate_hit.
  const durableLimited = (kind: string) =>
    rateLimitRefusal(supabase, `login:${kind}:${username}`,
      LIMITS[kind] ?? 20, 60);

  try {
    // ------------------------------------------------ challenge
    if (method === "challenge") {
      if (rateLimited("challenge", username, ip)) {
        return errorResponse("rate_limited", "too many challenges; retry shortly", 429);
      }
      if (await durableLimited("challenge")) {
        return errorResponse("rate_limited", "too many challenge attempts; retry shortly", 429);
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
      if (await durableLimited("verify")) {
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
      const row = await selectOne(supabase, "al_users",
        "sign_pub, recovery_hash", {
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
      // Replay claim (2.6.0, Part 4): the signature verified,
      // so this presentation is legitimate — and it is the
      // ONLY presentation of this nonce that ever will be.
      // The claim lands before any token is minted; a replay
      // of the captured statement dies here.
      if (!await claimOnce(supabase, "login_verify", username,
        nonce, exp + 300)) {
        return errorResponse("replay_refused",
          "this login statement was already presented; " +
          "request a fresh challenge", 401);
      }
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
      await recordClientVersion(supabase, username, body);
      const tokens = await issueTokens(username);
      // Recovery enrollment (2.2.3): an account with an EMPTY
      // recovery hash never received the key its register
      // minted (the reply was clipped in transit — the account
      // exists, is fully usable by key login, and is silently
      // stranded: no recovery path, and no rectify needed
      // either, since its keys never diverged). The verified
      // signature above IS the account's owner proving itself,
      // so mint + enroll + return the key ONCE here, mirroring
      // the v1 relay's first-verified-hello enrollment. A
      // non-empty hash means enrolled: no key is minted, none
      // rotates, none is re-issued — a stolen session can never
      // harvest a fresh login-back credential from a login.
      if (!String(row?.recovery_hash ?? "")) {
        const enrollKey = randomTokenUrlSafe(32);
        await patchRows(supabase, "al_users", { username }, {
          recovery_hash: await sha256Hex(enrollKey),
        });
        return jsonResponse({ ...tokens, recovery_key: enrollKey });
      }
      return jsonResponse(tokens);
    }

    // ------------------------------------------------- recovery
    if (method === "recovery") {
      if (rateLimited("recovery", username, ip)) {
        return errorResponse("rate_limited", "too many recovery attempts; retry shortly", 429);
      }
      if (await durableLimited("recovery")) {
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
      await recordClientVersion(supabase, username, body);
      const tokens = await issueTokens(username);
      return jsonResponse({ ...tokens, recovery_key: newRecoveryKey });
    }

    // ------------------------------------------------- register
    if (method === "register") {
      if (rateLimited("register", username, ip)) {
        return errorResponse("rate_limited", "too many registration attempts; retry shortly", 429);
      }
      if (await durableLimited("register")) {
        return errorResponse("rate_limited", "too many register attempts; retry shortly", 429);
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
        // GRANDFATHERING (2.6.0): this refusal precedes the
        // provisioning gate — existing accounts are never
        // gated, and no grant is consulted or consumed here.
        return errorResponse(
          "username_taken",
          "that username is already registered; if it is yours, " +
            "reclaim it with your recovery key",
          409,
        );
      }
      // -------------------------------- PROVISIONING GATE
      // (2.6.0, Part 2): a NEW username registers only with a
      // provisioning grant bound to THIS username. Verify in
      // order: presented -> exists -> binding -> expiry ->
      // unconsumed; then consume atomically BEFORE the birth,
      // restoring the grant if the birth fails.
      const grantToken = String(body.provisioning_grant ?? "");
      if (!grantToken) {
        return provisioningFault("provisioning_grant_required",
          "registering a new username requires a provisioning " +
          "grant: a one-time token the operator issued for " +
          "this exact username.");
      }
      const grant = await selectOne(
        supabase,
        "al_provisioning_grants",
        "id, username, expires_at, consumed_at, revoked_at",
        { token_hash: await sha256Hex(grantToken) },
      );
      if (!grant || grant.revoked_at) {
        return provisioningFault("provisioning_grant_invalid",
          "the provisioning grant presented does not exist " +
          "(or was revoked by the operator).");
      }
      if (String(grant.username) !== username) {
        return provisioningFault(
          "provisioning_grant_username_mismatch",
          "the provisioning grant presented was issued for a " +
          "different username; a grant is bound to the one " +
          "username it was issued for.");
      }
      if (Number(grant.expires_at ?? 0) <= nowSeconds()) {
        return provisioningFault("provisioning_grant_expired",
          "the provisioning grant presented has expired.");
      }
      if (grant.consumed_at) {
        return provisioningFault("provisioning_grant_consumed",
          "the provisioning grant presented was already " +
          "consumed; grants are one-time.");
      }
      const grantId = String(grant.id);
      const consumedCount = await patchRows(
        supabase,
        "al_provisioning_grants",
        { id: grantId },
        { consumed_at: nowSeconds(), consumed_ip: ip || null },
        (q) => q.is("consumed_at", null),
      );
      if (consumedCount !== 1) {
        // Lost a race against a concurrent presentation of
        // the same grant: it is consumed now, by definition.
        return provisioningFault("provisioning_grant_consumed",
          "the provisioning grant presented was already " +
          "consumed; grants are one-time.");
      }
      const releaseGrant = async () => {
        // The birth failed after consumption: restore the
        // grant so a legitimate retry is not stranded by a
        // server-side failure. Best-effort and logged — the
        // operator event trail shows the restore.
        try {
          await patchRows(
            supabase,
            "al_provisioning_grants",
            { id: grantId },
            { consumed_at: null, consumed_ip: null },
          );
        } catch (e) {
          console.error("provisioning grant restore failed " +
            "for " + grantId + ": " + String(e));
        }
      };
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
        // The birth failed: the grant goes back unconsumed
        // (see releaseGrant) before any refusal is spoken.
        await releaseGrant();
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
      await recordOperatorEvent(supabase,
        "provisioning_consumed", username, username,
        "provisioning grant consumed at registration",
        { grant_id: grantId });
      await recordClientVersion(supabase, username, body);
      const tokens = await issueTokens(username);
      return jsonResponse({ ...tokens, recovery_key: newRecoveryKey });
    }

    // ------------------------------------------------- rectify
    if (method === "rectify") {
      if (rateLimited("rectify", username, ip)) {
        return errorResponse("rate_limited", "too many rectification attempts; retry shortly", 429);
      }
      if (await durableLimited("rectify")) {
        return errorResponse("rate_limited", "too many rectify attempts; retry shortly", 429);
      }
      // The operator path back into a stranded legacy account
      // (see the header). Authorization is a one-time code the
      // operator issued for THIS username; everything about the
      // failure is one refusal shape — no oracle distinguishing
      // an unknown username from a wrong or spent code.
      const user = await selectOne(
        supabase,
        "al_users",
        "username",
        { username },
      );
      if (!user) {
        return errorResponse("rectify_failed", RECTIFY_FAILED_DETAIL, 401);
      }
      const live = await selectOne(
        supabase,
        "al_rectify_codes",
        "id, code_hash, expires_at",
        { username, status: "live" },
      );
      const presented = String(body.rectify_code ?? "");
      const presentedHash = presented ? await sha256Hex(presented) : "";
      const now = nowSeconds();
      if (
        !live || !presented ||
        Number(live.expires_at) < now ||
        !constantTimeEqual(presentedHash, String(live.code_hash ?? ""))
      ) {
        return errorResponse("rectify_failed", RECTIFY_FAILED_DETAIL, 401);
      }
      // Fresh key material is validated exactly as the recovery
      // method validates a rebind — BEFORE the code burns, so a
      // malformed request never spends the operator's code.
      const newSignPub = String(body.new_sign_pub ?? "");
      const newPubkey = String(body.new_pubkey ?? "");
      if (!isRawKey32(newSignPub) || !isRawKey32(newPubkey)) {
        return errorResponse(
          "invalid_key_material",
          "new_sign_pub and new_pubkey must be base64 raw 32-byte keys",
          400,
        );
      }
      // Burn the code atomically: the status match makes this
      // update land only while the code is still live, so two
      // concurrent presentations can never both pass.
      const burned = await patchRows(
        supabase,
        "al_rectify_codes",
        { id: live.id, status: "live" },
        { status: "used", used_at: now },
      );
      if (burned !== 1) {
        return errorResponse("rectify_failed", RECTIFY_FAILED_DETAIL, 401);
      }
      // The rebind mirrors the recovery method exactly: fresh
      // identity keys, the legacy secret rotates (hash only),
      // and a NEW recovery key is minted — returned ONCE in
      // this response, to the rectifying agent only; the lost
      // key and the diverged keys die here.
      const newRecoveryKey = randomTokenUrlSafe(32);
      const rotatedSecret = randomTokenUrlSafe(24);
      const secret = await sha256Hex(rotatedSecret);
      await patchRows(supabase, "al_users", { username }, {
        sign_pub: newSignPub,
        pubkey: newPubkey,
        secret,
        recovery_hash: await sha256Hex(newRecoveryKey),
        recovery_used_at: now,
        auth_method: "rectify",
        last_seen: now,
      });
      await patchRows(
        supabase,
        "al_grants",
        { username, status: "active" },
        { bound_sign_pub: newSignPub, updated_at: now },
        (q) => q.neq("bound_sign_pub", newSignPub),
      );
      await recordClientVersion(supabase, username, body);
      const tokens = await issueTokens(username);
      return jsonResponse({ ...tokens, recovery_key: newRecoveryKey });
    }

    return errorResponse(
      "unknown_method",
      "method must be challenge, verify, recovery, register or rectify",
      400,
    );
  } catch (e) {
    // Config defects (missing env, unreadable service-account JSON)
    // surface as a named 500 — never as a fake auth failure, and
    // the message names env NAMES only, never values.
    return errorResponse("login_internal", String(e instanceof Error ? e.message : e), 500);
  }
});
