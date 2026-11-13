// AgentLink v2.0 — dashboard operator-auth Edge Function (Phase 7).
// Source directory: supabase/functions/agentlink-dashboard/.
// DEPLOY SLUG: the static frontend (dashboard-v2/js/data.js) calls
// POST {edgeBase}/dashboard-login, so this function is deployed
// under the slug `dashboard-login` (Supabase routes by slug, not by
// source directory name). See the Phase 7 evidence note for the
// deploy procedure; nothing in the frontend is changed by this
// phase.
//
// This closes the gap Phase 5 documented in dashboard-v2/README.md
// ("Operator-auth contract"): until now the dashboard had a login
// contract and no function behind it. This function is the v2
// mirror of the v1 dashboard's auth semantics (agentlink/
// dashboard.py):
//
//   * ONE-TIME login with the operator password. On success the
//     server issues a trusted-device token; ONLY its SHA-256 hash
//     is stored (al_dashboard_sessions.token_hash, the schema.sql
//     shape store.py create_session writes).
//   * The session persists for 7 DAYS (DEVICE_TRUST_SECONDS in
//     agentlink/timing.py), then one fresh login is needed.
//   * Sessions are revocable: logout deletes the session row
//     server-side, effective immediately.
//   * Login attempts are rate-limited per IP: MAX_FAILURES failed
//     attempts inside FAILURE_WINDOW seconds lock further attempts
//     until the window drains (dashboard.py's numbers, verbatim).
//
// ROUTES (all POST; bodies are JSON):
//
//   Login   {password}
//     -> 200 {ok:true, device_token, access_token, session_token,
//             supabase_jwt, expires_in, session_expires_in}
//     -> 401 uniform {ok:false, error:"invalid_credentials"} on ANY
//             mismatch (missing / empty / wrong password are the
//             same answer — no oracle about which part failed)
//     -> 429 {ok:false, error:"rate_limited"} past the failure cap
//   Refresh {action:"refresh", device_token}   (the README's
//             "second route": re-mint the JWT from the device
//             token; session_token is accepted as an alias, as is
//             an Authorization: Bearer <device token> header)
//     -> 200 same token fields with a fresh access_token; the
//             device token itself does NOT rotate and its 7-day
//             expiry does NOT extend (trusted-device semantics,
//             not a sliding session)
//     -> 401 uniform, when the session is unknown or expired
//   Logout  {action:"logout", session_token}   (device_token is
//             accepted as an alias for the same field)
//     -> 200 {ok:true} — idempotent: an unknown token is already
//             logged out, so it gets the same answer
//
// FIELD NAMES — the frontend wins (Phase 7 instruction): data.js
// reads j.device_token and j.access_token, so those are the
// canonical response names. session_token / supabase_jwt are the
// same two values under the Phase 7 brief's names, returned as
// aliases so both contracts are satisfied by one response; the
// frontend ignores the extra fields. expires_in is the JWT
// lifetime (3600s); session_expires_in is the device token's
// 7-day lifetime, named separately so the two are never confused.
//
// THE PASSWORD NEVER LIVES HERE IN PLAINTEXT. The function's only
// password material is the function secret named
// DASHBOARD_PASSWORD_SHA256: the SHA-256 hex of the operator
// password, computed at deploy time from the deploy vault (the
// password itself is never set as a function secret, never
// logged, and exists in this process only as the login request's
// field, hashed immediately and compared in constant time). The
// presented password is hashed with the same SHA-256 and the two
// hex digests are compared with constantTimeEqual from the shared
// module — raw passwords are never compared, stored or returned.
//
// THE OPERATOR JWT is minted by a LOCAL variant of the shared
// mintSupabaseJwt (the shared file is reused, not edited): same
// HS256 scheme, same AGENTLINK_JWT_SECRET, same stable `sub`
// derivation, same 3600s TTL — plus the operator claims this
// phase's RLS helper (al_jwt_is_operator) reads: the boolean claim
// operator=true AND the string claim app_role="operator" (the two
// documented spellings; see migration-v200-operator.sql), with
// username="operator" for audit readability. The username alone
// grants nothing; the operator claims are the authority.
//
// RATE LIMITING (honest note, same caveat as agentlink-login):
// Edge instances are short-lived and do not share memory, so the
// per-instance limiter below mirrors dashboard.py's per-IP rule in
// spirit and exact numbers, but durable cross-instance limiting
// belongs in front of this function (platform / gateway limits).
// It is a speed bump with the right shape, not a platform
// guarantee, and it is not claimed as more.
//
// Deploy: see the Phase 7 evidence (deploy under the
// `dashboard-login` slug; migration-v200-operator.sql applied
// first).
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY
// and AGENTLINK_JWT_SECRET are platform/project secrets;
// DASHBOARD_PASSWORD_SHA256 is a function secret set at deploy
// time from the vault-computed hash.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  b64urlEncode,
  b64urlEncodeText,
  CAP_CONTROL,
  constantTimeEqual,
  env,
  errorResponse,
  hmacSha256,
  insertRow,
  jsonResponse,
  methodGuard,
  nowSeconds,
  randomTokenUrlSafe,
  readJsonBody,
  selectOne,
  sha256Hex,
  stableSubForUsername,
  SUPABASE_JWT_TTL_SECONDS,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

// Mirror of agentlink/timing.py DEVICE_TRUST_SECONDS and of
// dashboard.py SESSION_TTL: the trusted device lives 7 days.
const SESSION_TTL_SECONDS = 7 * 24 * 3600;
// Mirror of dashboard.py's login rate limit, verbatim numbers.
const MAX_FAILURES = 5;
const FAILURE_WINDOW_SECONDS = 300;

const OPERATOR_USERNAME = "operator";

// ------------------------------------------------------- rate limit
// Per-instance failure log per IP (see the header's honest note).
const failures = new Map<string, number[]>();

function rateLimited(ip: string): boolean {
  const now = nowSeconds();
  const recent = (failures.get(ip) ?? []).filter(
    (t) => now - t < FAILURE_WINDOW_SECONDS,
  );
  failures.set(ip, recent);
  return recent.length >= MAX_FAILURES;
}

function recordFailure(ip: string): void {
  const list = failures.get(ip) ?? [];
  list.push(nowSeconds());
  failures.set(ip, list);
}

function clientIp(req: Request): string {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "";
}

// ---------------------------------------------------- operator JWT
// Local variant of mintSupabaseJwt (shared module, reused not
// edited): identical header, signing and `sub` derivation, with
// the operator claims added. HS256 is assembled from the shared
// primitives (hmacSha256 + b64urlEncode) exactly as the shared
// module assembles it internally.
async function mintOperatorJwt(): Promise<string> {
  const secret = env("AGENTLINK_JWT_SECRET");
  if (!secret) {
    throw new Error("AGENTLINK_JWT_SECRET is not set in this function's env");
  }
  const now = nowSeconds();
  const input = b64urlEncodeText(JSON.stringify({ alg: "HS256", typ: "JWT" })) +
    "." +
    b64urlEncodeText(JSON.stringify({
      sub: await stableSubForUsername(OPERATOR_USERNAME),
      role: "authenticated",
      username: OPERATOR_USERNAME,
      operator: true,
      app_role: "operator",
      aud: "authenticated",
      exp: now + SUPABASE_JWT_TTL_SECONDS,
      iat: now,
    }));
  const signature = b64urlEncode(await hmacSha256(
    new TextEncoder().encode(secret),
    new TextEncoder().encode(input),
  ));
  return input + "." + signature;
}

function tokenResponse(deviceToken: string, accessToken: string): Response {
  return jsonResponse({
    ok: true,
    // Canonical names — the ones dashboard-v2/js/data.js reads.
    device_token: deviceToken,
    access_token: accessToken,
    // Phase 7 brief names for the same two values.
    session_token: deviceToken,
    supabase_jwt: accessToken,
    // JWT lifetime (SUPABASE_JWT_TTL_SECONDS, 3600).
    expires_in: SUPABASE_JWT_TTL_SECONDS,
    // Trusted-device lifetime (7 days), named separately.
    session_expires_in: SESSION_TTL_SECONDS,
  });
}

function invalidCredentials(): Response {
  // One uniform refusal for every credential failure — missing,
  // empty, malformed or wrong — so the wire reveals nothing about
  // which part failed (dashboard.py answers every bad login with
  // the same "Wrong password." page; this is its JSON shape).
  return errorResponse(
    "invalid_credentials",
    "invalid credentials",
    401,
  );
}

function presentedDeviceToken(body: Record<string, unknown>): string {
  return String(body.device_token ?? body.session_token ?? "");
}

// Validate a trusted-device token against al_dashboard_sessions
// exactly as agentlink-oversight / store.session_valid do:
// SHA-256 hex of the token against token_hash, expiry in epoch
// seconds, via the service role (the table has no other reader).
async function sessionRow(
  token: string,
): Promise<Record<string, unknown> | null> {
  if (!token) return null;
  const row = await selectOne(supabase, "al_dashboard_sessions", "expires_at", {
    token_hash: await sha256Hex(token),
  });
  if (!row || Number(row.expires_at ?? 0) <= nowSeconds()) return null;
  return row;
}

Deno.serve(async (req: Request) => {
  const guard = methodGuard(req);
  if (guard) return guard;
  // Ingress cap (2.6.0, Part 4). Operator-only Edge: no agent
  // caller, so suspension/per-agent rates do not apply; the
  // per-IP login failure limiter below is unchanged.
  const parsed = await readJsonBody(req, CAP_CONTROL);
  if (parsed.response) return parsed.response;
  const body = parsed.body;
  const action = String(body.action ?? "").toLowerCase();
  const ip = clientIp(req);

  try {
    // ----------------------------------------------------- logout
    if (action === "logout") {
      const token = presentedDeviceToken(body) ||
        (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
      if (!token) {
        return errorResponse(
          "invalid_request",
          "logout requires a session_token",
          400,
        );
      }
      // Revoke server-side, immediately (dashboard.py /logout ->
      // store.revoke_session). Deleting an unknown hash is a
      // no-op, so logout stays idempotent and oracle-free.
      const tokenHash = await sha256Hex(token);
      const { error } = await supabase.from("al_dashboard_sessions")
        .delete().eq("token_hash", tokenHash);
      if (error) {
        throw new Error("al_dashboard_sessions delete failed: " + error.message);
      }
      return jsonResponse({ ok: true });
    }

    // ---------------------------------------------------- refresh
    // The README contract's second route: a still-valid device
    // token re-mints the short-lived operator JWT. No password is
    // involved and no new session row is created.
    if (
      action === "refresh" ||
      (action === "" && body.password === undefined &&
        presentedDeviceToken(body) !== "")
    ) {
      const token = presentedDeviceToken(body) ||
        (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
      if (!(await sessionRow(token))) return invalidCredentials();
      return tokenResponse(token, await mintOperatorJwt());
    }

    // ------------------------------------------------------ login
    if (action !== "" && action !== "login") {
      return errorResponse(
        "unknown_action",
        "action must be login, refresh or logout",
        400,
      );
    }
    if (rateLimited(ip)) {
      return errorResponse(
        "rate_limited",
        "too many failed login attempts; retry after the window drains",
        429,
      );
    }
    const configuredHash = env("DASHBOARD_PASSWORD_SHA256").trim().toLowerCase();
    if (!/^[0-9a-f]{64}$/.test(configuredHash)) {
      // A missing or malformed function secret is a deploy defect,
      // never a credential failure — name the env NAME only.
      throw new Error(
        "DASHBOARD_PASSWORD_SHA256 is not set (or is not a SHA-256 hex digest) in this function's env",
      );
    }
    const password = typeof body.password === "string" ? body.password : "";
    const presentedHash = password ? await sha256Hex(password) : "";
    if (
      !password ||
      !constantTimeEqual(presentedHash, configuredHash)
    ) {
      recordFailure(ip);
      return invalidCredentials();
    }

    // Success (dashboard.py /login, mirrored): mint a fresh
    // trusted-device token, store ONLY its SHA-256 hash with a
    // 7-day expiry, and return the raw token exactly once.
    const deviceToken = randomTokenUrlSafe(32);
    const now = nowSeconds();
    await insertRow(supabase, "al_dashboard_sessions", {
      token_hash: await sha256Hex(deviceToken),
      created_at: now,
      expires_at: now + SESSION_TTL_SECONDS,
    });
    return tokenResponse(deviceToken, await mintOperatorJwt());
  } catch (e) {
    // Config defects surface as a named 500 — never as a fake
    // credential failure, and the message names env NAMES only,
    // never values.
    return errorResponse(
      "dashboard_login_internal",
      String(e instanceof Error ? e.message : e),
      500,
    );
  }
});
