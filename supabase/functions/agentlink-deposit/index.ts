// AgentLink v2.5.1 — deposit Edge Function (the platform
// deposit inbox, migration v214). The ONE deposit destination
// of the stock client, hardened as a platform built-in:
//
//   POST /   Authorization: Bearer <agent supabase_jwt>
//            The JWT's username claim is the only identity.
//
//   kind "dossier": {kind, agent, files: {name: base64}}
//     The Agent Dossier deposit set. agent must equal the JWT
//     username; files must carry DOSSIER.json; the document's
//     username must equal the JWT username; and the document's
//     Ed25519 signature must verify against the registry key
//     (al_users.sign_pub) over the canonical JSON of the
//     document sans signature — dossier.py's signing scheme,
//     mirrored byte-for-byte. When dossier-chain.jsonl rides
//     along, its tail entry must bind this exact document
//     (version + content hash), so a deposit cannot pair a
//     genuine document with a foreign chain.
//   kind "message": one sealed archive record (the client's
//     normalized validate_record shape). Plaintext fields are
//     refused; a sealed oversight envelope is required; the
//     record's sender must equal the JWT username (an agent
//     deposits its own sends; the drain files the record under
//     every participant, as the archive has always done).
//
// A verified deposit lands in al_deposit_inbox (service role)
// and is answered {confirmed: true, inbox_id, deposit_key} —
// anything else, the client treats as NOT deposited and keeps
// the deposit queued (fail-closed). Retries are idempotent:
// (agent, kind, deposit_key) is unique and content-derived, so
// a re-deposit answers confirmed with duplicate: true.
//
// Custody: the inbox is a transit custody on the way to the
// owner's Drive trees (the operator drain files dossiers into
// AgentLink System/<agent>/ and message chains into AgentLink
// Archive/<agent>/). No dossier content is rendered, listed,
// or served anywhere platform-side — the inbox has no read
// route at all.
//
// Deploy: supabase functions deploy agentlink-deposit
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_JWT_SECRET.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  bearerToken,
  CAP_DEPOSIT,
  errorResponse,
  jsonResponse,
  methodGuard,
  rateLimitRefusal,
  readJsonBody,
  selectOne,
  suspendedRefusal,
  verifyAgentJwt,
  verifyEd25519,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

/** Canonical JSON: sorted keys, compact separators — the mirror
 * of liveness.py canonical_json (and dossier.py's sign base). */
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

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0")).join("");
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function signPubOf(username: string): Promise<string> {
  const row = await selectOne(supabase, "al_users", "sign_pub",
    { username });
  return String(row?.sign_pub ?? "");
}

async function landInbox(agent: string, kind: string,
  depositKey: string, payload: Record<string, unknown>,
  facts: Record<string, unknown> = {}) {
  const { data, error } = await supabase
    .from("al_deposit_inbox")
    .insert({ agent, kind, deposit_key: depositKey, payload,
      ...facts })
    .select("id")
    .limit(1);
  if (error) {
    if (String(error.code) === "23505" ||
        String(error.message).includes("al_deposit_inbox_key_uq")) {
      const existing = await selectOne(supabase, "al_deposit_inbox",
        "id", { agent, kind, deposit_key: depositKey });
      return jsonResponse({ ok: true, confirmed: true,
        duplicate: true, inbox_id: Number(existing?.id ?? 0),
        deposit_key: depositKey });
    }
    throw new Error(error.message);
  }
  return jsonResponse({ ok: true, confirmed: true,
    inbox_id: Number(data?.[0]?.id ?? 0), deposit_key: depositKey });
}

Deno.serve(async (req) => {
  const guard = methodGuard(req);
  if (guard) return guard;
  const claims = await verifyAgentJwt(bearerToken(req));
  if (!claims) {
    return errorResponse("unauthorized",
      "agent JWT did not verify", 401);
  }
  const me = claims.username as string;
  // Containment (2.6.0, Part 4): suspension first, then the
  // payload cap, then the rate limit — all before any file is
  // decoded or any state is touched (hostile case 9). The cap
  // is CAP_DEPOSIT (8 MiB): a dossier deposit is a base64 file
  // SET and legitimately multi-MiB; before 2.6.0 this Edge had
  // NO cap at all. The rate is 60/min: deposits are rare,
  // deliberate acts, and 60 is wide headroom over the client's
  // retry cadence.
  const suspended = await suspendedRefusal(supabase, me);
  if (suspended) return suspended;
  const parsed = await readJsonBody(req, CAP_DEPOSIT);
  if (parsed.response) return parsed.response;
  const body = parsed.body;
  const limited = await rateLimitRefusal(
    supabase, "deposit:" + me, 60);
  if (limited) return limited;

  try {
    // ------------------------------------------------ dossier
    if (body.kind === "dossier") {
      if (String(body.agent ?? "") !== me) {
        return errorResponse("agent_mismatch",
          "a dossier deposit names its own agent only", 403);
      }
      const files = body.files as Record<string, unknown>;
      if (!files || typeof files !== "object" ||
          typeof files["DOSSIER.json"] !== "string") {
        return errorResponse("bad_deposit",
          "dossier deposit needs files with DOSSIER.json", 400);
      }
      // Ingress hygiene (2.6.0): file names become Drive
      // names and, in the operator drain, local temp paths.
      // The legitimate set is flat names plus the
      // "dossier-history/" prefix — traversal segments,
      // backslashes and absolute names are refused here so
      // no downstream surface ever has to trust them.
      for (const name of Object.keys(files)) {
        if (name.length > 200 || name.startsWith("/") ||
            name.includes("\\") ||
            name.split("/").includes("..")) {
          return errorResponse("bad_deposit",
            "dossier file name is not a lawful deposit name: " +
            name.slice(0, 80), 400);
        }
      }
      let doc: Record<string, unknown>;
      try {
        doc = JSON.parse(new TextDecoder().decode(
          b64ToBytes(String(files["DOSSIER.json"]))));
      } catch {
        return errorResponse("bad_deposit",
          "DOSSIER.json is not decodable JSON", 400);
      }
      // Dossier schema: /2 is current (2.6.0 — the machine
      // spec section is retired); /1 stays acceptable from
      // pre-2.6.0 agents, which keep working unchanged.
      if (!["agentlink-dossier/1",
            "agentlink-dossier/2"].includes(
              String(doc.schema ?? "")) ||
          String(doc.username ?? "") !== me) {
        return errorResponse("bad_deposit",
          "dossier document is not this agent's dossier", 400);
      }
      const pub = await signPubOf(me);
      if (!pub) {
        return errorResponse("unknown_agent",
          "no registry key for this agent", 404);
      }
      const unsigned: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(doc)) {
        if (k !== "signature") unsigned[k] = v;
      }
      const ok = await verifyEd25519(pub,
        new TextEncoder().encode(canonicalJson(unsigned)),
        String(doc.signature ?? ""));
      if (!ok) {
        return errorResponse("bad_signature",
          "dossier signature did not verify against the " +
          "registry key", 403);
      }
      const contentSha = await sha256Hex(canonicalJson(unsigned));
      const version = Number(doc.dossier_version ?? 0);
      if (!version) {
        return errorResponse("bad_deposit",
          "dossier document carries no version", 400);
      }
      const chainB64 = files["dossier-chain.jsonl"];
      if (typeof chainB64 === "string" && chainB64) {
        const lines = new TextDecoder().decode(b64ToBytes(chainB64))
          .split("\n").filter((l) => l.trim());
        let tail: Record<string, unknown> | null = null;
        try {
          tail = JSON.parse(lines[lines.length - 1]);
        } catch {
          tail = null;
        }
        if (!tail || Number(tail.dossier_version) !== version ||
            String(tail.sha256) !== contentSha ||
            String(tail.signature) !== String(doc.signature)) {
          return errorResponse("bad_deposit",
            "dossier chain tail does not bind this document",
            400);
        }
      }
      // Street Rule (2.5.2, v215): the dossier facts the
      // platform judges currency by are stamped HERE, from
      // the signature-verified document itself — never from
      // the agent's separate status report (which is kept as
      // a claim in the record). After the land, the verdict
      // is re-judged at once so a filed dossier reads current
      // immediately; the per-minute sweep keeps it honest as
      // time, nature and versions move.
      const identity = (doc.identity ?? {}) as
        Record<string, unknown>;
      const facts = {
        dossier_version: version,
        nature_version: Number(
          (doc.how_it_works as Record<string, unknown> || {})
            .nature_version ?? 0) || null,
        client_version: String(identity.client_version ?? "")
          || null,
      };
      const landed = await landInbox(me, "dossier",
        `dossier-v${version}-${contentSha}`, { files }, facts);
      try {
        const { error } = await supabase.rpc(
          "al_refresh_dossier_verdict", { p_username: me });
        if (error) throw new Error(error.message);
      } catch (e) {
        console.error("dossier verdict refresh failed for " +
          me + ": " + String(e));
      }
      return landed;
    }

    // ------------------------------------------------ message
    for (const bad of ["body", "plaintext", "text"]) {
      if (body[bad]) {
        return errorResponse("plaintext_refused",
          `archive record carries plaintext field ${bad} — ` +
          "sealed envelopes only", 400);
      }
    }
    const mid = String(body.message_id ?? "");
    const conv = String(body.conversation_id ?? "");
    const parts = Array.isArray(body.participants)
      ? body.participants.map(String).filter(Boolean) : [];
    const sealed = body.oversight as Record<string, unknown>;
    if (!mid || !conv || !parts.length ||
        !sealed || typeof sealed !== "object" || !sealed.ct) {
      return errorResponse("bad_record",
        "archive record needs message_id, conversation_id, " +
        "participants and a sealed oversight envelope", 400);
    }
    if (String(body.sender ?? "") !== me) {
      return errorResponse("sender_mismatch",
        "an agent deposits its own sends only", 403);
    }
    const record: Record<string, unknown> = {
      message_id: mid,
      conversation_id: conv,
      participants: parts,
      sender: me,
      kind: String(body.kind ?? "dm"),
      ts: Number(body.ts ?? 0),
      oversight: sealed,
      oversight_kind: String(body.oversight_kind ?? "content"),
      mode: body.mode === "disappearing" ? "disappearing"
        : "standard",
    };
    if (body.audit_seq !== undefined && body.audit_seq !== null) {
      record.audit_seq = Number(body.audit_seq);
    }
    if (body.file && typeof body.file === "object") {
      record.file = body.file;
    }
    return await landInbox(me, "message", mid, { record });
  } catch (e) {
    return errorResponse("deposit_failed", String(e), 500);
  }
});
