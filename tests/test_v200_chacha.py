"""Regression pin for the _shared ChaCha20-Poly1305 decrypt.

The TS pad16() once returned the data itself when its length
was already a multiple of 16, doubling it in the Poly1305 MAC
input — every ciphertext whose length was a multiple of 16 then
failed its tag check in the Edge layer. A file key is always 32
bytes, so EVERY content_key wrap of a file key failed oversight
verification and blob-form files could never render or download
in the dashboard (found live 2026-11-06, v2.0.5 media proof).

Vectors are generated with Python's ChaCha20Poly1305 (the
client's own primitive) at plaintext lengths straddling the
mod-16 boundary; the TS decrypt must return the exact plaintext
for each, and must throw on a tampered ciphertext.
"""
import base64
import json
import shutil
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "supabase" / "functions" / "_shared" / "v200.ts"
LENGTHS = (0, 1, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 100, 256)

RUNNER = """
import { readFileSync } from "node:fs";
import { chacha20Poly1305Decrypt } from %s;
const V = JSON.parse(readFileSync(process.argv[2], "utf8"));
const key = Buffer.from(V.key, "base64");
const nonce = Buffer.from(V.nonce, "base64");
let fails = 0;
for (const v of V.vecs) {
  try {
    const out = chacha20Poly1305Decrypt(key, nonce, Buffer.from(v.ct, "base64"));
    if (!Buffer.from(out).equals(Buffer.from(v.pt, "base64"))) fails++;
  } catch { fails++; }
}
try {
  const ct = Buffer.from(V.vecs[5].ct, "base64"); ct[3] ^= 1;
  chacha20Poly1305Decrypt(key, nonce, ct); fails++;
} catch { /* tamper must throw */ }
process.exit(fails ? 1 : 0);
"""


def test_ts_chacha_decrypts_python_vectors_at_every_length(tmp_path):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available")
    key, nonce = bytes(range(32)), bytes(range(12))
    vecs = []
    for n in LENGTHS:
        pt = (bytes(range(256)) * 2)[:n]
        ct = ChaCha20Poly1305(key).encrypt(nonce, pt, None)
        vecs.append({"n": n,
                     "pt": base64.b64encode(pt).decode(),
                     "ct": base64.b64encode(ct).decode()})
    vectors = tmp_path / "vectors.json"
    vectors.write_text(json.dumps({
        "key": base64.b64encode(key).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "vecs": vecs}))
    runner = tmp_path / "run.mjs"
    runner.write_text(RUNNER % json.dumps(str(SHARED)))
    proc = subprocess.run([node, str(runner), str(vectors)],
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, (
        "TS chacha20Poly1305Decrypt failed Python vectors "
        f"(lengths {LENGTHS}): {proc.stdout} {proc.stderr}")
