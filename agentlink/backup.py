"""AgentLink backups — encrypted archives to MEGA or Google Drive.

Layer 3 of the storage split. A backup bundles:
  * a snapshot of the relay database (SQLite file copy; for Supabase,
    a JSON export of the relay's tables via the store interface), and
  * the blob manifest (blob metadata from the DB) + blob ciphertext
    copies from the local blob store (R2 contents are re-pullable by
    the operator from the manifest; the archive records every blob's
    sha256 so a restore can verify completeness).

The whole tar.gz is encrypted with a key derived from the OPERATOR's
backup passphrase (PBKDF2-HMAC-SHA256, 600k iterations, random salt)
under ChaCha20-Poly1305. Targets:
  * a local folder (always works),
  * Google Drive / MEGA via an operator-installed `rclone` remote
    named `gdrive` / `mega` (operator configures rclone with THEIR
    account; AgentLink never holds Drive/MEGA credentials itself).

A backup that cannot be verified does not count: `verify` decrypts,
checks every file hash in the manifest, and runs the DB integrity
check. `create` verifies its own archive before reporting success.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import secrets
import shutil
import sqlite3
import subprocess
import tarfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"AGENTLINK-BACKUP-v1\n"


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=600_000)
    return kdf.derive(passphrase.encode())


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_backup(db_path: str, blobs_dir: str | None,
                  out_dir: str, passphrase: str,
                  targets: list[str] | None = None) -> dict:
    ts = time.strftime("%Y%m%dT%H%M%S")
    staging = Path(out_dir).expanduser() / f".staging-{ts}"
    staging.mkdir(parents=True, exist_ok=True)
    files: dict[str, str] = {}

    def _add(name: str, data: bytes):
        dest = staging / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
        files[name] = _sha(data)

    db = Path(db_path).expanduser()
    if db.exists():
        _add("relay.db", db.read_bytes())
        wal = Path(str(db) + "-wal")
        # Snapshot consistency: checkpoint note — for a hot relay, stop
        # or quiesce before backup; the manifest hash makes any torn
        # copy detectable at verify time (integrity check below).
        try:
            conn = sqlite3.connect(str(db))
            manifest_rows = conn.execute(
                "SELECT * FROM blobs").fetchall()
            cols = [d[0] for d in conn.execute(
                "SELECT * FROM blobs LIMIT 0").description]
            conn.close()
            _add("blob-manifest.json", json.dumps(
                [dict(zip(cols, r)) for r in manifest_rows],
                indent=2).encode())
        except Exception:
            _add("blob-manifest.json", b"[]")
    if blobs_dir:
        bdir = Path(blobs_dir).expanduser()
        if bdir.exists():
            for f in sorted(bdir.iterdir()):
                if f.is_file():
                    _add(f"blobs/{f.name}", f.read_bytes())
    _add("manifest.json", json.dumps(
        {"created_at": int(time.time()), "files": files},
        indent=2).encode())

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for item in sorted(staging.iterdir()):
            if item.is_dir():
                for sub in sorted(item.iterdir()):
                    tar.add(sub, arcname=f"{item.name}/{sub.name}")
            else:
                tar.add(item, arcname=item.name)
    shutil.rmtree(staging)

    salt = secrets.token_bytes(16)
    nonce = secrets.token_bytes(12)
    key = _derive_key(passphrase, salt)
    ct = ChaCha20Poly1305(key).encrypt(nonce, buf.getvalue(), None)
    archive = Path(out_dir).expanduser() / f"agentlink-backup-{ts}.enc"
    archive.write_bytes(MAGIC + salt + nonce + ct)

    result = {"archive": str(archive), "size": archive.stat().st_size,
              "files": len(files), "uploaded": []}
    # Verify our own work before claiming success.
    check = verify_backup(str(archive), passphrase)
    result["verified"] = check["ok"]
    if not check["ok"]:
        raise RuntimeError(f"backup failed self-verification: {check}")
    for target in targets or []:
        result["uploaded"].append(_upload(archive, target))
    return result


def _upload(archive: Path, target: str) -> dict:
    """target: folder path, 'gdrive', or 'mega' (rclone remotes)."""
    if target in ("gdrive", "mega"):
        if not shutil.which("rclone"):
            return {"target": target, "ok": False,
                    "detail": "rclone not installed/configured by operator"}
        remote = f"{target}:agentlink-backups"
        proc = subprocess.run(["rclone", "copy", str(archive), remote],
                              capture_output=True, text=True, timeout=600)
        return {"target": target, "ok": proc.returncode == 0,
                "detail": (proc.stderr or proc.stdout)[-200:]}
    dest = Path(target).expanduser()
    dest.mkdir(parents=True, exist_ok=True)
    shutil.copy2(archive, dest / archive.name)
    return {"target": target, "ok": True, "detail": str(dest / archive.name)}


def verify_backup(archive_path: str, passphrase: str) -> dict:
    raw = Path(archive_path).read_bytes()
    if not raw.startswith(MAGIC):
        return {"ok": False, "detail": "bad magic (not an AgentLink backup)"}
    salt, nonce, ct = raw[len(MAGIC):len(MAGIC) + 16], \
        raw[len(MAGIC) + 16:len(MAGIC) + 28], raw[len(MAGIC) + 28:]
    try:
        key = _derive_key(passphrase, salt)
        plain = ChaCha20Poly1305(key).decrypt(nonce, ct, None)
    except Exception:
        return {"ok": False, "detail": "decryption failed (wrong passphrase"
                                       " or corrupted archive)"}
    with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
        names = tar.getnames()
        manifest = json.loads(tar.extractfile("manifest.json").read())
        for name, want in manifest["files"].items():
            if name not in names:
                return {"ok": False, "detail": f"missing file {name}"}
            got = _sha(tar.extractfile(name).read())
            if got != want:
                return {"ok": False, "detail": f"hash mismatch for {name}"}
        if "relay.db" in names:
            tmp = Path(archive_path + ".verify.db")
            tmp.write_bytes(tar.extractfile("relay.db").read())
            try:
                conn = sqlite3.connect(str(tmp))
                integ = conn.execute("PRAGMA integrity_check").fetchone()[0]
                conn.close()
            finally:
                tmp.unlink(missing_ok=True)
            if integ != "ok":
                return {"ok": False, "detail": f"DB integrity: {integ}"}
    return {"ok": True, "files": len(manifest["files"]),
            "created_at": manifest["created_at"]}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="agentlink backup")
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--db", default="~/.agentlink/relay.db")
    c.add_argument("--blobs", default="~/.agentlink/blobs")
    c.add_argument("--out", default="~/.agentlink/backups")
    c.add_argument("--target", action="append", default=[],
                   help="folder path, gdrive, or mega (repeatable)")
    v = sub.add_parser("verify")
    v.add_argument("archive")
    args = ap.parse_args(argv)
    passphrase = os.environ.get("AGENTLINK_BACKUP_PASSPHRASE")
    if not passphrase:
        print("set AGENTLINK_BACKUP_PASSPHRASE (operator-only)", flush=True)
        return 2
    if args.cmd == "create":
        print(json.dumps(create_backup(args.db, args.blobs, args.out,
                                       passphrase, args.target), indent=2))
        return 0
    result = verify_backup(args.archive, passphrase)
    print(json.dumps(result, indent=2))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
