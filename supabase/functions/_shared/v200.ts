// AgentLink v2.0 — shared Edge helpers (Phase 2).
//
// Dependency-free on purpose: the four v2 functions instantiate the
// Supabase service-role client exactly the way the existing functions
// do (createClient from esm.sh/@supabase/supabase-js@2, SUPABASE_URL +
// SUPABASE_SERVICE_ROLE_KEY injected by the platform) and pass it to
// the small wrappers at the bottom of this file. Nothing in this
// module reads a secret at import time or logs one, ever — env
// access is lazy (inside the mint/sign functions) and by NAME only.
//
// Formats mirrored from the Python tree (do not drift):
//   * Ed25519 keys + signatures are STANDARD base64 of the raw
//     32-byte public key / 64-byte signature (agentlink/crypto.py).
//   * The key-auth challenge payload is protocol.auth_challenge_
//     payload: "agentlink-auth-v1\n<nonce>\n<relay>\n<username>\n
//     <expires>" (agentlink/protocol.py).
//   * Recovery keys are secrets.token_urlsafe(32); only their
//     SHA-256 hex is ever stored (al_users.recovery_hash).
//   * Oversight envelopes are crypto.encrypt_to_pubkey's shape
//     {v, alg:"x25519-chacha20poly1305", eph_pub, nonce, ct} (+ a
//     "kind" of "content"|"content_key"): ephemeral X25519 ->
//     HKDF-SHA256(salt=None, info=b"agentlink-e2ee-v1", len 32) ->
//     ChaCha20Poly1305 (12-byte nonce, 16-byte tag appended to ct).

// ------------------------------------------------------------------ env

export function env(name: string): string {
  // Deno.env under Supabase Edge; empty string when unset. Values are
  // never returned to callers of the HTTP functions or logged.
  const d = (globalThis as unknown as {
    Deno?: { env?: { get(n: string): string | undefined } };
  }).Deno;
  return d?.env?.get(name) ?? "";
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

// ------------------------------------------------------- base64 / hex

const B64_ALPHABET =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

export function b64encode(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i];
    const b = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const c = i + 2 < bytes.length ? bytes[i + 2] : 0;
    out += B64_ALPHABET[a >> 2];
    out += B64_ALPHABET[((a & 3) << 4) | (b >> 4)];
    out += i + 1 < bytes.length ? B64_ALPHABET[((b & 15) << 2) | (c >> 6)] : "=";
    out += i + 2 < bytes.length ? B64_ALPHABET[c & 63] : "=";
  }
  return out;
}

/** Decode STANDARD base64 (Python base64.b64encode form). Also
 * tolerates the URL-safe alphabet and missing padding, because rows
 * written by different client generations mix the two. Throws on
 * any other defect — callers treat a throw as "malformed". */
export function b64decode(text: string): Uint8Array {
  const clean = String(text ?? "").trim().replace(/-/g, "+")
    .replace(/_/g, "/").replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/]*$/.test(clean) || clean.length % 4 === 1) {
    throw new Error("invalid base64");
  }
  const rev = new Map<string, number>();
  [...B64_ALPHABET].forEach((ch, i) => rev.set(ch, i));
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const ch of clean) {
    acc = (acc << 6) | (rev.get(ch) as number);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

export function b64urlEncode(bytes: Uint8Array): string {
  return b64encode(bytes).replace(/\+/g, "-").replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function b64urlEncodeText(text: string): string {
  return b64urlEncode(new TextEncoder().encode(text));
}

export function hexEncode(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexDecode(hex: string): Uint8Array {
  const clean = String(hex ?? "").trim();
  if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(2 * i, 2 * i + 2), 16);
  }
  return out;
}

/** Mirror of Python secrets.token_urlsafe(n): base64url, no padding. */
export function randomTokenUrlSafe(nBytes = 32): string {
  const buf = new Uint8Array(nBytes);
  crypto.getRandomValues(buf);
  return b64urlEncode(buf);
}

// ------------------------------------------------- hashing / compare

export async function sha256Bytes(data: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data));
}

export async function sha256Hex(
  data: string | Uint8Array,
): Promise<string> {
  const bytes = typeof data === "string"
    ? new TextEncoder().encode(data)
    : data;
  return hexEncode(await sha256Bytes(bytes));
}

export async function hmacSha256(
  key: Uint8Array,
  data: Uint8Array,
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey("raw", key, {
    name: "HMAC",
    hash: "SHA-256",
  }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, data));
}

export async function hmacSha256Hex(
  keyText: string,
  dataText: string,
): Promise<string> {
  return hexEncode(await hmacSha256(
    new TextEncoder().encode(keyText),
    new TextEncoder().encode(dataText),
  ));
}

/** Constant-time equality for hash / MAC strings and byte arrays.
 * Length is compared first (lengths of hashes are not secret);
 * content comparison never short-circuits. */
export function constantTimeEqual(
  a: string | Uint8Array,
  b: string | Uint8Array,
): boolean {
  const x = typeof a === "string" ? new TextEncoder().encode(a) : a;
  const y = typeof b === "string" ? new TextEncoder().encode(b) : b;
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// ------------------------------------------------------------- Ed25519

export class Ed25519UnsupportedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "Ed25519UnsupportedError";
  }
}

/** Verify an Ed25519 signature (base64 key + signature, the
 * crypto.py encodings) over payload via WebCrypto. Returns false
 * for a bad signature or malformed key material; THROWS
 * Ed25519UnsupportedError when the runtime's WebCrypto has no
 * Ed25519 at all — a platform defect the operator must see, not a
 * failed login to hide inside a false. */
export async function verifyEd25519(
  signPubB64: string,
  payload: Uint8Array,
  signatureB64: string,
): Promise<boolean> {
  let pub: Uint8Array;
  let sig: Uint8Array;
  try {
    pub = b64decode(signPubB64);
    sig = b64decode(signatureB64);
  } catch {
    return false;
  }
  if (pub.length !== 32 || sig.length !== 64) return false;
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "raw",
      pub,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
  } catch (e) {
    throw new Ed25519UnsupportedError(
      "WebCrypto in this runtime does not support Ed25519 " +
        "(crypto.subtle.importKey {name:'Ed25519'} failed); the " +
        "Supabase Edge (Deno) runtime is required for agentlink-login: " +
        String(e),
    );
  }
  try {
    return await crypto.subtle.verify("Ed25519", key, sig, payload);
  } catch (e) {
    // Some runtimes accept the import but reject verify for the
    // same missing-algorithm reason; that is still "unsupported",
    // not "bad signature" — but only reclassify the well-known
    // algorithm errors, everything else is a verification failure.
    if (/not supported|unsupported|unrecognized/i.test(String(e))) {
      throw new Ed25519UnsupportedError(
        "WebCrypto verify {name:'Ed25519'} unsupported in this runtime: " +
          String(e),
      );
    }
    return false;
  }
}

/** The PKCS#8 DER prefix for an Ed25519 private key (RFC 8410):
 * SEQUENCE { INTEGER 0, SEQUENCE { OID 1.3.101.112 }, OCTET STRING
 * { OCTET STRING <32-byte seed> } }. WebCrypto imports Ed25519
 * private keys only as PKCS#8, while the platform stores the raw
 * seed (crypto.py's encoding) — this prefix is the whole bridge. */
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65,
  0x70, 0x04, 0x22, 0x04, 0x20,
]);

/** Sign payload with an Ed25519 seed (base64, crypto.py's
 * encoding) via WebCrypto — the platform receipt key's serverless
 * hand (agentlink-grants mints the same signed receipt chain the
 * Python broker mints, from the same al_grant_meta key, so the
 * chain is one chain across transports). Returns the base64
 * signature (crypto.py's encoding). THROWS
 * Ed25519UnsupportedError when the runtime's WebCrypto has no
 * Ed25519 — a platform defect the operator must see. */
export async function signEd25519(
  seedB64: string,
  payload: Uint8Array,
): Promise<string> {
  let seed: Uint8Array;
  try {
    seed = b64decode(seedB64);
  } catch {
    throw new Error("receipt signing seed is not valid base64");
  }
  if (seed.length !== 32) {
    throw new Error("receipt signing seed must be 32 bytes");
  }
  const pkcs8 = new Uint8Array(
    ED25519_PKCS8_PREFIX.length + seed.length,
  );
  pkcs8.set(ED25519_PKCS8_PREFIX, 0);
  pkcs8.set(seed, ED25519_PKCS8_PREFIX.length);
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "Ed25519" },
      false,
      ["sign"],
    );
  } catch (e) {
    throw new Ed25519UnsupportedError(
      "WebCrypto in this runtime does not support Ed25519 " +
        "signing (crypto.subtle.importKey {name:'Ed25519'} " +
        "failed); the Supabase Edge (Deno) runtime is required: " +
        String(e),
    );
  }
  const sig = await crypto.subtle.sign("Ed25519", key, payload);
  return b64encode(new Uint8Array(sig));
}

/** EXACT mirror of protocol.auth_challenge_payload (protocol.py):
 * the bytes a key-signed hello signs. */
export function authChallengePayload(
  nonce: string,
  relay: string,
  username: string,
  expires: number,
): Uint8Array {
  return new TextEncoder().encode(
    "agentlink-auth-v1\n" + String(nonce) + "\n" + String(relay) + "\n" +
      String(username) + "\n" + String(expires),
  );
}

/** Mirror of protocol.normalize_username + USERNAME_RE. */
export function normalizeUsername(raw: unknown): string | null {
  if (typeof raw !== "string") return null;
  const u = raw.trim().replace(/^@+/, "").toLowerCase();
  return /^[a-z0-9][a-z0-9._-]{1,30}$/.test(u) ? u : null;
}

/** List form of normalizeUsername for member/subscriber lists
 * (agentlink-groups). Returns null when the input is not an
 * array at all (callers treat null as "no list given"). Entries
 * that fail normalization are KEPT as their raw string form so
 * the caller's user-exists check refuses them as
 * unknown_username — the relay's behavior — instead of silently
 * dropping a mistyped member. */
export function normalizeUsernameList(raw: unknown): string[] | null {
  if (raw === undefined || raw === null) return null;
  if (!Array.isArray(raw)) return null;
  return raw.map((item) => normalizeUsername(item) ?? String(item ?? ""));
}

// ----------------------------------------------------------------- JWT

function jwtEncode(header: unknown, claims: unknown): string {
  return b64urlEncodeText(JSON.stringify(header)) + "." +
    b64urlEncodeText(JSON.stringify(claims));
}

async function hs256Sign(secret: string, signingInput: string) {
  return b64urlEncode(await hmacSha256(
    new TextEncoder().encode(secret),
    new TextEncoder().encode(signingInput),
  ));
}

/** Stable Supabase `sub` for a username.
 * CHOICE (documented): sub = the first 16 bytes of
 * SHA-256("agentlink-v2-sub:" + username), hex-formatted as a UUID
 * with the version (4) and variant (10xx) bits forced, exactly like
 * a random v4 UUID. Supabase's authenticated role expects `sub` to
 * parse as a UUID (auth.uid()); a bare username string would not.
 * The derivation is deterministic, so the same agent always lands
 * on the same sub across logins and devices, it reveals nothing
 * beyond the username's hash, and no mapping table is needed. */
export async function stableSubForUsername(
  username: string,
): Promise<string> {
  const digest = await sha256Bytes(
    new TextEncoder().encode("agentlink-v2-sub:" + username),
  );
  const b = digest.slice(0, 16);
  b[6] = (b[6] & 0x0f) | 0x40; // version 4
  b[8] = (b[8] & 0x3f) | 0x80; // variant 10xx
  const h = hexEncode(b);
  return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) +
    "-" + h.slice(16, 20) + "-" + h.slice(20, 32);
}

export const SUPABASE_JWT_TTL_SECONDS = 3600;

/** Mint the scoped Supabase JWT (HS256, AGENTLINK_JWT_SECRET). */
export async function mintSupabaseJwt(username: string): Promise<string> {
  const secret = env("AGENTLINK_JWT_SECRET");
  if (!secret) {
    throw new Error("AGENTLINK_JWT_SECRET is not set in this function's env");
  }
  const now = nowSeconds();
  const input = jwtEncode(
    { alg: "HS256", typ: "JWT" },
    {
      sub: await stableSubForUsername(username),
      role: "authenticated",
      username,
      aud: "authenticated",
      exp: now + SUPABASE_JWT_TTL_SECONDS,
      iat: now,
    },
  );
  return input + "." + await hs256Sign(secret, input);
}

export interface AgentClaims {
  sub?: string;
  username?: string;
  role?: string;
  aud?: string | string[];
  exp?: number;
  iat?: number;
  [k: string]: unknown;
}

/** Verify an agent JWT minted by mintSupabaseJwt (HS256 against
 * AGENTLINK_JWT_SECRET, expiry checked). Returns the claims or null.
 * Used by agentlink-r2sign and agentlink-grants: the username claim
 * — never a body field — is the caller's identity. */
export async function verifyAgentJwt(
  token: string,
): Promise<AgentClaims | null> {
  const secret = env("AGENTLINK_JWT_SECRET");
  if (!secret || !token) return null;
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const expected = await hs256Sign(secret, parts[0] + "." + parts[1]);
  if (!constantTimeEqual(expected, parts[2])) return null;
  let claims: AgentClaims;
  try {
    claims = JSON.parse(new TextDecoder().decode(b64decode(
      parts[1].replace(/-/g, "+").replace(/_/g, "/"),
    )));
  } catch {
    return null;
  }
  if (typeof claims.exp !== "number" || claims.exp <= nowSeconds()) {
    return null;
  }
  if (typeof claims.username !== "string" || !claims.username) return null;
  return claims;
}

export function bearerToken(req: Request): string {
  return (req.headers.get("authorization") ?? "").replace(/^Bearer\s+/i, "");
}

// ------------------------------------------------- Firebase custom token

export const FIREBASE_TOKEN_AUD =
  "https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit";

interface FirebaseServiceAccount {
  client_email: string;
  private_key: string; // PEM (PKCS8) — value never logged/returned
  [k: string]: unknown;
}

function parseServiceAccount(raw: string): FirebaseServiceAccount {
  let sa: FirebaseServiceAccount;
  try {
    sa = JSON.parse(raw);
  } catch {
    throw new Error(
      "FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON",
    );
  }
  if (!sa.client_email || !sa.private_key) {
    throw new Error(
      "FIREBASE_SERVICE_ACCOUNT_JSON lacks client_email / private_key",
    );
  }
  return sa;
}

function pemToDer(pem: string): Uint8Array {
  const body = pem.replace(/-----BEGIN [^-]+-----/, "")
    .replace(/-----END [^-]+-----/, "").replace(/\s+/g, "");
  return b64decode(body);
}

async function importFirebaseSigningKey(pem: string): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      "pkcs8",
      pemToDer(pem),
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["sign"],
    );
  } catch (e) {
    throw new Error(
      "could not import the Firebase service-account PKCS8 key via " +
        "WebCrypto RSASSA-PKCS1-v1_5/SHA-256: " + String(e),
    );
  }
}

/** Mint a Firebase Auth custom token (RS256). The uid is the
 * SANITIZED username (sanitizeKey) — the same form the client uses
 * for RTDB path segments and that the RTDB rules compare auth.uid
 * against (integration alignment, v2.0: doorbell.py is the source of
 * truth for the uid form; identical to the raw username for plain
 * usernames, different only where RTDB forbids the character).
 * iss and sub are BOTH the service account's client_email and aud
 * is the identitytoolkit URL, per Firebase's custom-token spec;
 * lifetime is capped at 3600s by Firebase, and we use exactly that. */
export async function mintFirebaseCustomToken(
  username: string,
): Promise<string> {
  const raw = env("FIREBASE_SERVICE_ACCOUNT_JSON");
  if (!raw) {
    throw new Error(
      "FIREBASE_SERVICE_ACCOUNT_JSON is not set in this function's env",
    );
  }
  const sa = parseServiceAccount(raw);
  const now = nowSeconds();
  const input = jwtEncode(
    { alg: "RS256", typ: "JWT" },
    {
      iss: sa.client_email,
      sub: sa.client_email,
      aud: FIREBASE_TOKEN_AUD,
      iat: now,
      exp: now + 3600,
      uid: sanitizeKey(username),
      claims: { username },
    },
  );
  const key = await importFirebaseSigningKey(sa.private_key);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(input),
  );
  return input + "." + b64urlEncode(new Uint8Array(sig));
}

// ---------------------------------------------------------- R2 presign

export interface R2Config {
  accountId: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string; // value never logged/returned
}

export function r2ConfigFromEnv(): R2Config {
  const cfg = {
    accountId: env("R2_ACCOUNT_ID"),
    bucket: env("R2_BUCKET"),
    accessKeyId: env("R2_ACCESS_KEY_ID"),
    secretAccessKey: env("R2_SECRET_ACCESS_KEY"),
  };
  const missing = Object.entries({
    R2_ACCOUNT_ID: cfg.accountId,
    R2_BUCKET: cfg.bucket,
    R2_ACCESS_KEY_ID: cfg.accessKeyId,
    R2_SECRET_ACCESS_KEY: cfg.secretAccessKey,
  }).filter(([, v]) => !v).map(([k]) => k);
  if (missing.length) {
    throw new Error("missing R2 env: " + missing.join(", "));
  }
  return cfg;
}

function rfc3986Encode(text: string): string {
  return encodeURIComponent(text).replace(
    /[!'()*]/g,
    (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase(),
  );
}

/** Full AWS Signature Version 4 presigned URL for Cloudflare R2
 * (S3-compatible, region "auto", UNSIGNED-PAYLOAD, host the only
 * signed header). Implemented with WebCrypto HMAC — no SDK, no
 * placeholders. Expiry is the caller's (the function passes 900s). */
export async function presignR2Url(
  cfg: R2Config,
  method: "GET" | "PUT" | "DELETE",
  objectKey: string,
  expiresSeconds: number,
): Promise<string> {
  const host = cfg.accountId + ".r2.cloudflarestorage.com";
  const region = "auto";
  const service = "s3";
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, ""); // YYYYMMDDTHHMMSSZ
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = dateStamp + "/" + region + "/" + service +
    "/aws4_request";
  const canonicalUri = "/" + cfg.bucket + "/" +
    objectKey.split("/").map(rfc3986Encode).join("/");
  const query: Record<string, string> = {
    "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
    "X-Amz-Credential": cfg.accessKeyId + "/" + credentialScope,
    "X-Amz-Date": amzDate,
    "X-Amz-Expires": String(expiresSeconds),
    "X-Amz-SignedHeaders": "host",
  };
  const canonicalQuery = Object.keys(query).sort()
    .map((k) => rfc3986Encode(k) + "=" + rfc3986Encode(query[k]))
    .join("&");
  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQuery,
    "host:" + host + "\n",
    "host",
    "UNSIGNED-PAYLOAD",
  ].join("\n");
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    hexEncode(await sha256Bytes(new TextEncoder().encode(canonicalRequest))),
  ].join("\n");
  const enc = new TextEncoder();
  const kDate = await hmacSha256(
    enc.encode("AWS4" + cfg.secretAccessKey),
    enc.encode(dateStamp),
  );
  const kRegion = await hmacSha256(kDate, enc.encode(region));
  const kService = await hmacSha256(kRegion, enc.encode(service));
  const kSigning = await hmacSha256(kService, enc.encode("aws4_request"));
  const signature = hexEncode(
    await hmacSha256(kSigning, enc.encode(stringToSign)),
  );
  return "https://" + host + canonicalUri + "?" + canonicalQuery +
    "&X-Amz-Signature=" + signature;
}

// ------------------------------------------- oversight envelope opening
//
// The exact scheme of crypto.py (see header). WebCrypto has no
// ChaCha20-Poly1305 and (portably) no X25519, so both are small
// self-contained routines below: the RFC 7748 Montgomery ladder
// over BigInt field arithmetic, and the RFC 8439 AEAD built from a
// ChaCha20 block function + a BigInt Poly1305. HKDF-SHA256 is
// expand/extract over the WebCrypto HMAC above (salt=None in the
// Python means a 32-byte zero salt — RFC 5869's default).

const CURVE_P = (1n << 255n) - 19n;

function decodeLittleEndian(bytes: Uint8Array): bigint {
  let n = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
  return n;
}

function encodeLittleEndian(n: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let v = n;
  for (let i = 0; i < len; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/** X25519 scalar multiplication (RFC 7748 §5): clamped scalar,
 * Montgomery ladder, affine result u = x1 * z1^(p-2) mod p. */
export function x25519(
  scalar32: Uint8Array,
  uBytes32: Uint8Array,
): Uint8Array {
  const k = new Uint8Array(scalar32);
  k[0] &= 248;
  k[31] &= 127;
  k[31] |= 64;
  const scalar = decodeLittleEndian(k);
  const x1 = decodeLittleEndian(uBytes32) & ((1n << 255n) - 1n);
  const a24 = 121665n;
  let x2 = 1n;
  let z2 = 0n;
  let x3 = x1;
  let z3 = 1n;
  let swap = 0n;
  const cswap = (a: bigint, b: bigint, bit: bigint): [bigint, bigint] =>
    bit === 1n ? [b, a] : [a, b];
  for (let t = 254; t >= 0; t--) {
    const kT = (scalar >> BigInt(t)) & 1n;
    swap ^= kT;
    [x2, x3] = cswap(x2, x3, swap);
    [z2, z3] = cswap(z2, z3, swap);
    swap = kT;
    const A = (x2 + z2) % CURVE_P;
    const AA = (A * A) % CURVE_P;
    const B = (x2 - z2 + CURVE_P) % CURVE_P;
    const BB = (B * B) % CURVE_P;
    const E = (AA - BB + CURVE_P) % CURVE_P;
    const C = (x3 + z3) % CURVE_P;
    const D = (x3 - z3 + CURVE_P) % CURVE_P;
    const DA = (D * A) % CURVE_P;
    const CB = (C * B) % CURVE_P;
    const daPlusCb = (DA + CB) % CURVE_P;
    const daMinusCb = (DA - CB + CURVE_P) % CURVE_P;
    x3 = (daPlusCb * daPlusCb) % CURVE_P;
    z3 = (x1 * daMinusCb * daMinusCb) % CURVE_P;
    x2 = (AA * BB) % CURVE_P;
    z2 = (E * (AA + a24 * E)) % CURVE_P;
  }
  [x2, x3] = cswap(x2, x3, swap);
  [z2, z3] = cswap(z2, z3, swap);
  const result = (x2 * modPow(z2, CURVE_P - 2n, CURVE_P)) % CURVE_P;
  return encodeLittleEndian(result, 32);
}

/** HKDF-SHA256 (RFC 5869), salt=null -> 32 zero bytes (the
 * cryptography library's salt=None behaviour), info as given. */
export async function hkdfSha256(
  ikm: Uint8Array,
  info: Uint8Array,
  length: number,
  salt: Uint8Array | null = null,
): Promise<Uint8Array> {
  const prk = await hmacSha256(salt ?? new Uint8Array(32), ikm);
  const out = new Uint8Array(length);
  let t: Uint8Array = new Uint8Array(0);
  let offset = 0;
  for (let counter = 1; offset < length; counter++) {
    const data = new Uint8Array(t.length + info.length + 1);
    data.set(t, 0);
    data.set(info, t.length);
    data[data.length - 1] = counter;
    t = await hmacSha256(prk, data);
    out.set(t.subarray(0, Math.min(t.length, length - offset)), offset);
    offset += t.length;
  }
  return out;
}

function rotl32(v: number, c: number): number {
  return ((v << c) | (v >>> (32 - c))) >>> 0;
}

function quarterRound(x: Uint32Array, a: number, b: number, c: number, d: number) {
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 16);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 12);
  x[a] = (x[a] + x[b]) >>> 0; x[d] = rotl32(x[d] ^ x[a], 8);
  x[c] = (x[c] + x[d]) >>> 0; x[b] = rotl32(x[b] ^ x[c], 7);
}

function chacha20Block(key: Uint8Array, counter: number, nonce: Uint8Array): Uint8Array {
  const constants = new TextEncoder().encode("expand 32-byte k");
  const state = new Uint32Array(16);
  const view = (buf: Uint8Array, off: number) =>
    (buf[off] | (buf[off + 1] << 8) | (buf[off + 2] << 16) |
      (buf[off + 3] << 24)) >>> 0;
  for (let i = 0; i < 4; i++) state[i] = view(constants, 4 * i);
  for (let i = 0; i < 8; i++) state[4 + i] = view(key, 4 * i);
  state[12] = counter >>> 0;
  for (let i = 0; i < 3; i++) state[13 + i] = view(nonce, 4 * i);
  const work = new Uint32Array(state);
  for (let round = 0; round < 10; round++) {
    quarterRound(work, 0, 4, 8, 12);
    quarterRound(work, 1, 5, 9, 13);
    quarterRound(work, 2, 6, 10, 14);
    quarterRound(work, 3, 7, 11, 15);
    quarterRound(work, 0, 5, 10, 15);
    quarterRound(work, 1, 6, 11, 12);
    quarterRound(work, 2, 7, 8, 13);
    quarterRound(work, 3, 4, 9, 14);
  }
  const out = new Uint8Array(64);
  for (let i = 0; i < 16; i++) {
    const v = (work[i] + state[i]) >>> 0;
    out[4 * i] = v & 0xff;
    out[4 * i + 1] = (v >>> 8) & 0xff;
    out[4 * i + 2] = (v >>> 16) & 0xff;
    out[4 * i + 3] = (v >>> 24) & 0xff;
  }
  return out;
}

function chacha20Xor(
  key: Uint8Array,
  counter: number,
  nonce: Uint8Array,
  data: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(data.length);
  for (let off = 0, ctr = counter; off < data.length; off += 64, ctr++) {
    const block = chacha20Block(key, ctr, nonce);
    const n = Math.min(64, data.length - off);
    for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ block[i];
  }
  return out;
}

const POLY_P = (1n << 130n) - 5n;

function poly1305Mac(key32: Uint8Array, msg: Uint8Array): Uint8Array {
  const rBytes = new Uint8Array(key32.subarray(0, 16));
  rBytes[3] &= 15;
  rBytes[7] &= 15;
  rBytes[11] &= 15;
  rBytes[15] &= 15;
  rBytes[4] &= 252;
  rBytes[8] &= 252;
  rBytes[12] &= 252;
  const r = decodeLittleEndian(rBytes);
  const s = decodeLittleEndian(key32.subarray(16, 32));
  let acc = 0n;
  for (let off = 0; off < msg.length; off += 16) {
    const chunk = msg.subarray(off, Math.min(off + 16, msg.length));
    const block = new Uint8Array(chunk.length + 1);
    block.set(chunk, 0);
    block[chunk.length] = 1;
    acc = ((acc + decodeLittleEndian(block)) * r) % POLY_P;
  }
  return encodeLittleEndian((acc + s) % (1n << 128n), 16);
}

function pad16(data: Uint8Array): Uint8Array {
  const rem = data.length % 16;
  // RFC 8439 pad16 is ZERO bytes when the length is already a
  // multiple of 16 — returning the data itself here (the old
  // code) silently doubled it in the MAC input and made every
  // ciphertext whose length is a multiple of 16 fail its tag
  // check (a 32-byte file key's wrap, above all).
  return rem === 0 ? new Uint8Array(0) : new Uint8Array(16 - rem);
}

function u64le(n: number): Uint8Array {
  const out = new Uint8Array(8);
  let v = BigInt(n);
  for (let i = 0; i < 8; i++) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** ChaCha20-Poly1305 AEAD DECRYPT (RFC 8439 §2.8), the exact
 * construction Python's ChaCha20Poly1305 uses: ct carries the
 * 16-byte tag appended. AAD is empty in the AgentLink scheme.
 * Throws on tag mismatch — callers must fail closed. */
export function chacha20Poly1305Decrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ctWithTag: Uint8Array,
): Uint8Array {
  if (key.length !== 32) throw new Error("chacha key must be 32 bytes");
  if (nonce.length !== 12) throw new Error("chacha nonce must be 12 bytes");
  if (ctWithTag.length < 16) throw new Error("ciphertext shorter than tag");
  const ct = ctWithTag.subarray(0, ctWithTag.length - 16);
  const tag = ctWithTag.subarray(ctWithTag.length - 16);
  const polyKey = chacha20Block(key, 0, nonce).subarray(0, 32);
  const macData = new Uint8Array(
    ct.length + pad16(ct).length + 16,
  );
  macData.set(ct, 0);
  macData.set(u64le(0), ct.length + pad16(ct).length); // aad length = 0
  macData.set(u64le(ct.length), ct.length + pad16(ct).length + 8);
  const expected = poly1305Mac(polyKey, macData);
  if (!constantTimeEqual(expected, new Uint8Array(tag))) {
    throw new Error("chacha20poly1305 tag mismatch");
  }
  return chacha20Xor(key, 1, nonce, ct);
}

/** Mirror of crypto.decrypt_with_key: envelope {nonce, ct} under a
 * raw symmetric key (group/channel/file content envelopes). */
export function decryptWithKey(
  key: Uint8Array,
  envelope: { nonce: string; ct: string },
): Uint8Array {
  return chacha20Poly1305Decrypt(
    key,
    b64decode(envelope.nonce),
    b64decode(envelope.ct),
  );
}

export const E2EE_INFO = new TextEncoder().encode("agentlink-e2ee-v1");

/** Mirror of crypto.Identity.decrypt_envelope / OversightKey.
 * decrypt_envelope for ONE oversight wrap: ephemeral X25519 ->
 * HKDF-SHA256(info="agentlink-e2ee-v1", 32) -> ChaCha20Poly1305.
 * oversightPrivB64 is the raw 32-byte X25519 private key, base64 —
 * the same value OVERSIGHT key files carry as "private_key". */
export async function openSealedEnvelope(
  oversightPrivB64: string,
  envelope: { eph_pub: string; nonce: string; ct: string },
): Promise<Uint8Array> {
  const priv = b64decode(oversightPrivB64);
  if (priv.length !== 32) {
    throw new Error("oversight private key must be 32 bytes (base64)");
  }
  const ephPub = b64decode(envelope.eph_pub);
  if (ephPub.length !== 32) throw new Error("eph_pub must be 32 bytes");
  const shared = x25519(priv, ephPub);
  if (shared.every((b) => b === 0)) {
    throw new Error("x25519 produced an all-zero shared secret");
  }
  const key = await hkdfSha256(shared, E2EE_INFO, 32);
  return chacha20Poly1305Decrypt(
    key,
    b64decode(envelope.nonce),
    b64decode(envelope.ct),
  );
}

// --------------------------------------- service-role DB wrappers
//
// Thin wrappers over the supabase-js client the FUNCTIONS create
// (createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY), the
// agentlink-api/agentlink-events pattern). The client type is the
// real supabase-js client at runtime; it is typed loosely here so
// this module stays import-free.

// deno-lint-ignore no-explicit-any
type ServiceClient = any;

export async function selectOne(
  client: ServiceClient,
  table: string,
  columns: string,
  match: Record<string, unknown>,
): Promise<Record<string, unknown> | null> {
  let q = client.from(table).select(columns);
  for (const [k, v] of Object.entries(match)) q = q.eq(k, v);
  const { data, error } = await q.limit(1);
  if (error) throw new Error(table + " select failed: " + error.message);
  return (data && data.length ? data[0] : null) as
    | Record<string, unknown>
    | null;
}

export async function patchRows(
  client: ServiceClient,
  table: string,
  match: Record<string, unknown>,
  body: Record<string, unknown>,
  extra?: (q: ServiceClient) => ServiceClient,
): Promise<number> {
  let q = client.from(table).update(body);
  for (const [k, v] of Object.entries(match)) q = q.eq(k, v);
  if (extra) q = extra(q);
  const { data, error } = await q.select("*");
  if (error) throw new Error(table + " update failed: " + error.message);
  return Array.isArray(data) ? data.length : 0;
}

export async function insertRow(
  client: ServiceClient,
  table: string,
  body: Record<string, unknown>,
): Promise<void> {
  const { error } = await client.from(table).insert(body);
  if (error) throw new Error(table + " insert failed: " + error.message);
}

// -------------------------------------------------------- HTTP helpers

export const CORS_HEADERS: Record<string, string> = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, OPTIONS",
  "access-control-allow-headers":
    "authorization, content-type, apikey, x-client-info",
};

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json", ...CORS_HEADERS },
  });
}

/** Structured error: {ok:false, error:<code>, detail:<human text>}.
 * For login failures the code + detail strings are the RELAY's own
 * (key_auth_failed / recovery_failed, relay.py's _error payloads). */
export function errorResponse(
  code: string,
  detail: string,
  status: number,
): Response {
  return jsonResponse({ ok: false, error: code, detail }, status);
}

export function methodGuard(req: Request): Response | null {
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: CORS_HEADERS });
  }
  if (req.method !== "POST") {
    return errorResponse(
      "method_not_allowed",
      "this function accepts POST only",
      405,
    );
  }
  return null;
}

// ------------------------------------------- Firebase / Google OAuth2
//
// Service-account JWT bearer flow (RFC 7523) for Google APIs —
// used by agentlink-doorbell to write RTDB with an OAuth2 access
// token (the Admin-style server leg; agents themselves only ever
// hold custom tokens). The assertion JWT is RS256, iss = sub =
// client_email, aud = the token endpoint, scope as requested.

/** Mirror of agentlink/doorbell.py sanitize_key / user_key /
 * conversation_key: percent-encode every byte RTDB forbids in a
 * key (. $ # [ ] /) plus AgentLink's separators (: | %), space and
 * control characters, as uppercase %XX. Deterministic, reversible. */
export function sanitizeKey(raw: string): string {
  const unsafe = new Set([".", "$", "#", "[", "]", "/", ":", "|", "%", " "]);
  let out = "";
  for (const ch of String(raw)) {
    const code = ch.codePointAt(0) ?? 0;
    if (unsafe.has(ch) || code < 0x20 || code === 0x7f || code > 0x7e) {
      // Non-ASCII: encode each UTF-8 byte (doorbell.py encodes the
      // character ordinal; for the ASCII ids AgentLink issues the
      // two agree — divergence is confined to non-ASCII ids, which
      // usernames/conversation ids are not).
      if (code > 0x7e && !unsafe.has(ch)) {
        for (const b of new TextEncoder().encode(ch)) {
          out += "%" + b.toString(16).toUpperCase().padStart(2, "0");
        }
      } else {
        out += "%" + code.toString(16).toUpperCase().padStart(2, "0");
      }
    } else {
      out += ch;
    }
  }
  return out;
}

export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";
export const FIREBASE_RTDB_SCOPES = [
  "https://www.googleapis.com/auth/firebase.database",
  "https://www.googleapis.com/auth/userinfo.email",
];

/** Mint a Google OAuth2 access token for the given scopes from
 * FIREBASE_SERVICE_ACCOUNT_JSON (service-account JWT flow).
 * Tokens are short-lived (<= 3600s); no caching is done here —
 * Edge invocations are event-driven and low-volume by design, and
 * a cached token in a warm instance is an optimization, not a
 * correctness need. Throws a named config error when the env is
 * missing/malformed; upstream Google errors surface their HTTP
 * status only — the assertion and key are never logged/returned. */
export async function mintGoogleAccessToken(
  scopes: string[] = FIREBASE_RTDB_SCOPES,
): Promise<string> {
  const raw = env("FIREBASE_SERVICE_ACCOUNT_JSON");
  if (!raw) {
    throw new Error(
      "FIREBASE_SERVICE_ACCOUNT_JSON is not set in this function's env",
    );
  }
  const sa = parseServiceAccount(raw);
  const now = nowSeconds();
  const input = jwtEncode(
    { alg: "RS256", typ: "JWT" },
    {
      iss: sa.client_email,
      sub: sa.client_email,
      aud: GOOGLE_TOKEN_URL,
      scope: scopes.join(" "),
      iat: now,
      exp: now + 3600,
    },
  );
  const key = await importFirebaseSigningKey(sa.private_key);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(input),
  );
  const assertion = input + "." + b64urlEncode(new Uint8Array(sig));
  const form = new URLSearchParams({
    grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
    assertion,
  });
  const resp = await fetch(GOOGLE_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form.toString(),
  });
  if (!resp.ok) {
    throw new Error(
      "Google OAuth2 token exchange failed: HTTP " + resp.status,
    );
  }
  const data = await resp.json().catch(() => ({})) as Record<
    string,
    unknown
  >;
  if (typeof data.access_token !== "string" || !data.access_token) {
    throw new Error("Google OAuth2 token exchange returned no access_token");
  }
  return data.access_token;
}
