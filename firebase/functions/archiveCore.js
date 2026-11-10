"use strict";
/*
 * Owner-archive CORE (Disappearing Mode v2) — the platform-portable
 * half of the archive service. This file is the JS twin of
 * agentlink/archive.py and MUST stay behaviour-compatible with it:
 * same record validation (sealed-only, plaintext refused), same
 * per-agent/per-conversation layout, same append-only hash chain
 * (sha256 over prevHash + canonical JSON of the entry minus its
 * own "hash" field, canonical = JSON with recursively sorted keys
 * and no whitespace, matching Python json.dumps(sort_keys=True,
 * separators=(",", ":")) for the plain JSON values records carry).
 *
 * PORTABILITY BOUNDARY (owner's diversification ruling): everything
 * in this file is pure logic over a *store* object with
 * {readChain(agent, conversationId) -> Promise<entries>,
 *  appendLine(agent, conversationId, line) -> Promise<void>}.
 * The store is the only platform-specific piece: Drive REST here
 * on Firebase (driveStore.js), an in-memory store in tests, a
 * local directory in the Python twin. The core never imports
 * firebase-admin, googleapis, or any host API, so it re-homes
 * between Supabase Edge and Firebase Cloud Functions untouched.
 */
const crypto = require("node:crypto");

class ArchiveError extends Error {}

function conversationIdDm(a, b) {
  const [lo, hi] = [String(a), String(b)].sort();
  return `dm:${lo}:${hi}`;
}
function conversationIdGroup(gid) { return `group:${gid}`; }
function conversationIdChannel(cid) { return `channel:${cid}`; }

function canonical(value) {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map(canonical).join(",") + "]";
  }
  const keys = Object.keys(value).sort();
  return "{" + keys.map(
    (k) => JSON.stringify(k) + ":" + canonical(value[k])).join(",") + "}";
}

function entryHash(prevHash, entry) {
  const body = {};
  for (const k of Object.keys(entry)) {
    if (k !== "hash") body[k] = entry[k];
  }
  return crypto.createHash("sha256")
    .update((prevHash || "") + canonical(body), "utf8")
    .digest("hex");
}

function validateRecord(record) {
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new ArchiveError("archive record is not an object");
  }
  for (const bad of ["body", "plaintext", "text"]) {
    if (record[bad]) {
      throw new ArchiveError(
        `archive record carries plaintext field ${bad} — refused ` +
        "(sealed envelopes only)");
    }
  }
  const mid = String(record.message_id || "");
  const conv = String(record.conversation_id || "");
  const parts = (record.participants || []).map(String).filter(Boolean);
  if (!mid || !conv || parts.length === 0) {
    throw new ArchiveError(
      "archive record needs message_id, conversation_id and at " +
      "least one participant");
  }
  const sealed = record.oversight;
  if (!sealed || typeof sealed !== "object" || !sealed.ct) {
    throw new ArchiveError(
      "archive record has no sealed oversight envelope — refused " +
      "(fail-closed deposit)");
  }
  const out = {
    message_id: mid,
    conversation_id: conv,
    participants: parts,
    sender: String(record.sender || ""),
    kind: String(record.kind || "dm"),
    ts: Number(record.ts || Math.floor(Date.now() / 1000)),
    oversight: sealed,
    oversight_kind: String(record.oversight_kind || "content"),
  };
  if (record.file) out.file = record.file;
  return out;
}

function verifyChain(entries) {
  let prev = "";
  for (const e of entries) {
    if (e.prev !== prev) return false;
    if (entryHash(prev, e) !== e.hash) return false;
    prev = e.hash;
  }
  return true;
}

/*
 * Deposit one record into EVERY participant's chain (a conversation
 * is filed under every participant — DESIGN-BRIEF rule 5).
 * Returns {confirmed, entry_id, hashes: {agent: hash}, folders}.
 */
async function deposit(store, record) {
  const entry = validateRecord(record);
  const hashes = {};
  for (const agent of entry.participants) {
    const existing = await store.readChain(agent, entry.conversation_id);
    const prev = existing.length ? existing[existing.length - 1].hash : "";
    const link = Object.assign({}, entry, { prev });
    link.hash = entryHash(prev, link);
    await store.appendLine(agent, entry.conversation_id,
      JSON.stringify(link));
    hashes[agent] = link.hash;
  }
  return {
    confirmed: true,
    entry_id: entry.message_id,
    hashes,
    folders: Object.keys(hashes).sort(),
  };
}

async function readConversation(store, agent, conversationId) {
  const entries = await store.readChain(agent, conversationId);
  if (!verifyChain(entries)) {
    throw new ArchiveError(
      `archive chain for ${agent}/${conversationId} FAILS ` +
      "verification (tamper-evident chain broken)");
  }
  return entries;
}

/*
 * Oversight open (the dashboard read path's decrypt): the AgentLink
 * envelope scheme — ephemeral X25519 -> HKDF-SHA256 (salt = 32 zero
 * bytes, info "agentlink-e2ee-v1") -> ChaCha20-Poly1305 (ct carries
 * the 16-byte tag appended, as Python's ChaCha20Poly1305 emits).
 * Pure node:crypto; wire-compatible with agentlink/crypto.py.
 */
function _x25519Private(rawB64) {
  const raw = Buffer.from(rawB64, "base64");
  // PKCS8 wrap for a raw 32-byte X25519 private key.
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b656e04220420", "hex"), raw]);
  return crypto.createPrivateKey(
    { key: pkcs8, format: "der", type: "pkcs8" });
}
function _x25519Public(rawB64) {
  const raw = Buffer.from(rawB64, "base64");
  const spki = Buffer.concat([
    Buffer.from("302a300506032b656e032100", "hex"), raw]);
  return crypto.createPublicKey(
    { key: spki, format: "der", type: "spki" });
}

function decryptEnvelope(oversightPrivB64, envelope) {
  const shared = crypto.diffieHellman({
    privateKey: _x25519Private(oversightPrivB64),
    publicKey: _x25519Public(Buffer.from(
      envelope.eph_pub, "base64").toString("base64")),
  });
  const key = Buffer.from(crypto.hkdfSync(
    "sha256", shared, Buffer.alloc(32),
    Buffer.from("agentlink-e2ee-v1"), 32));
  const nonce = Buffer.from(envelope.nonce, "base64");
  const ctAll = Buffer.from(envelope.ct, "base64");
  const tag = ctAll.subarray(ctAll.length - 16);
  const data = ctAll.subarray(0, ctAll.length - 16);
  const decipher = crypto.createDecipheriv(
    "chacha20-poly1305", key, nonce, { authTagLength: 16 });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(data), decipher.final()]);
}

/*
 * Render one conversation for the operator dashboard: open each
 * entry's oversight wrap server-side (operator session only — the
 * caller enforces that) and return the message payloads in chain
 * order. Group/channel entries wrap the room CONTENT KEY: those
 * open to the key bytes, and the caller pairs them with the room
 * envelopes it already holds; here they are reported as key
 * entries, never as plaintext bodies.
 */
function renderEntries(oversightPrivB64, entries) {
  return entries.map((e) => {
    const plain = decryptEnvelope(oversightPrivB64, e.oversight);
    if (e.oversight_kind === "content_key") {
      return {
        message_id: e.message_id, ts: e.ts, sender: e.sender,
        kind: "content_key", key_b64: plain.toString("base64"),
      };
    }
    return {
      message_id: e.message_id, ts: e.ts, sender: e.sender,
      kind: "content", payload: JSON.parse(plain.toString("utf8")),
    };
  });
}

module.exports = {
  ArchiveError,
  conversationIdDm,
  conversationIdGroup,
  conversationIdChannel,
  canonical,
  entryHash,
  validateRecord,
  verifyChain,
  deposit,
  readConversation,
  decryptEnvelope,
  renderEntries,
};
