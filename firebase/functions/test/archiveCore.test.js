"use strict";
/*
 * Archive core tests — run with `node --test test/` (no Firebase
 * emulator needed for the portable core: the store is in-memory).
 * The two PARITY tests pin byte-compatibility with the Python
 * twin (agentlink/archive.py + agentlink/crypto.py): the chain
 * hash and the oversight envelope scheme must agree across
 * languages, or the service cannot re-home between Supabase Edge
 * and Firebase without invalidating the archive.
 */
const test = require("node:test");
const assert = require("node:assert/strict");
const core = require("../archiveCore");

class MemStore {
  constructor() { this.chains = new Map(); }
  _key(a, c) { return `${a}/${c}`; }
  async readChain(a, c) {
    return (this.chains.get(this._key(a, c)) || [])
      .map((l) => JSON.parse(l));
  }
  async appendLine(a, c, line) {
    const k = this._key(a, c);
    if (!this.chains.has(k)) this.chains.set(k, []);
    this.chains.get(k).push(line);
  }
}

const REC = {
  message_id: "m-vec-1",
  conversation_id: "dm:alice:bob",
  participants: ["alice", "bob"],
  sender: "alice",
  kind: "dm",
  ts: 1700000000,
  oversight: {
    v: 1, alg: "x25519-chacha20poly1305",
    eph_pub: "EPH", nonce: "NONCE", ct: "CT",
  },
  oversight_kind: "content",
};

test("PARITY: chain hash matches agentlink/archive.py", () => {
  const entry = core.validateRecord(REC);
  entry.prev = "";
  // Vector computed by Python archive.entry_hash on this record.
  assert.equal(core.entryHash("", entry),
    "c18853bca346584fbe8e8fa34f2fc7e6395ae7449bbf02b1427362ced1aa1a03");
});

test("PARITY: oversight envelope opens (X25519/HKDF/ChaCha)", () => {
  // Vector sealed by Python crypto.encrypt_to_pubkey.
  const priv = "EOa/qyRutR/JHm+Wq4mFTuiEnu6dr05oHnA/8onSL2Q=";
  const env = {
    v: 1, alg: "x25519-chacha20poly1305",
    eph_pub: "jSjS7ofyB0QKnepOAWeWbI1n5aiAk0gNzrYUjsu2Enk=",
    nonce: "14kSdS7+E5sxM0+x",
    ct: "DESslEQ0EEMXyWLWQqQ2peSxjP/Itt82aT4JMj0AFi4AaPh6DRAkH1Eo6J4Lp2DpWM5TPJUN1IU=",
  };
  const plain = core.decryptEnvelope(priv, env).toString("utf8");
  assert.equal(JSON.parse(plain).body, "parity check");
});

test("deposit files under EVERY participant and chains", async () => {
  const store = new MemStore();
  const conf = await core.deposit(store, REC);
  assert.equal(conf.confirmed, true);
  assert.deepEqual(conf.folders, ["alice", "bob"]);
  for (const a of ["alice", "bob"]) {
    const entries = await core.readConversation(
      store, a, "dm:alice:bob");
    assert.equal(entries.length, 1);
    assert.equal(entries[0].oversight.ct, "CT");
  }
  const conf2 = await core.deposit(store, {
    ...REC, message_id: "m-vec-2", ts: 1700000060 });
  const entries = await core.readConversation(
    store, "alice", "dm:alice:bob");
  assert.equal(entries.length, 2);
  assert.equal(entries[1].prev, entries[0].hash);
  assert.equal(conf2.hashes.alice, entries[1].hash);
});

test("tamper breaks chain verification", async () => {
  const store = new MemStore();
  await core.deposit(store, REC);
  const k = "alice/dm:alice:bob";
  const line = JSON.parse(store.chains.get(k)[0]);
  line.ts = 999;
  store.chains.set(k, [JSON.stringify(line)]);
  await assert.rejects(
    () => core.readConversation(store, "alice", "dm:alice:bob"),
    core.ArchiveError);
});

test("plaintext and unsealed records are refused", async () => {
  const store = new MemStore();
  await assert.rejects(
    () => core.deposit(store, { ...REC, body: "hello" }),
    core.ArchiveError);
  await assert.rejects(
    () => core.deposit(store, { ...REC, oversight: null }),
    core.ArchiveError);
  await assert.rejects(
    () => core.deposit(store, { ...REC, oversight: { nonce: "x" } }),
    core.ArchiveError);
});
