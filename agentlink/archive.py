"""Owner archive — Disappearing Mode v2 (2.4.0).

The durable record of every disappearing chat lives in the
owner's archive (Google Drive in production), NOT in Supabase:
delivery copies erase on the 24h per-side clocks, the archive
never erases. This module is the PLATFORM-PORTABLE CORE of the
archive service (owner's compute-diversification ruling,
2026-11-10): deposit validation, the per-agent folder layout,
and the append-only hash chain are pure functions of a record
dict plus a *backend* — a backend is any object with
``deposit(record) -> confirmation``. The same core runs:

* inside the Firebase Cloud Function that hosts the production
  deposit/read service (workstream d — the JS twin of this core
  lives in ``firebase/functions/archiveCore.js`` and MUST stay
  byte-compatible on the chain hash);
* inside the sandbox/drill harness against a local directory
  (the local directory IS the Drive folder layout, staged);
* on this VM against the real Drive through the proven
  ``hatch_gws_cli`` route (``DriveCliBackend``).

Portability boundary: everything above the backend interface is
portable (validation, layout, chaining, read/verify). The
backend is the only platform-specific piece — Drive REST +
service credential on Firebase, Drive CLI on this VM, plain
files in the sandbox. NO component that can erase (client
sweeps, pg_cron, Firebase housekeeping) holds an archive
credential or a code path to a backend: permanence is
structural (DESIGN-BRIEF rule 5).

Sealed-only law: a record carries the OVERSIGHT-SEALED copy
(an ``encrypt_for`` envelope — ``ct``/``nonce``/``eph_pub``)
or an oversight-sealed content-key wrap. A record carrying a
plaintext body is REFUSED, loudly — the archive never sees
plaintext, on any backend, ever.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


class ArchiveError(Exception):
    """A deposit or read failed — fail-closed: the caller must
    treat the send/erase as blocked, never proceed silently."""


def conversation_id_dm(a: str, b: str) -> str:
    lo, hi = sorted([str(a), str(b)])
    return f"dm:{lo}:{hi}"


def conversation_id_group(gid: str) -> str:
    return f"group:{gid}"


def conversation_id_channel(cid: str) -> str:
    return f"channel:{cid}"


def _canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True,
                      separators=(",", ":"),
                      default=str).encode()


def entry_hash(prev_hash: str, entry: dict) -> str:
    """One link of the append-only chain: sha256 over the
    previous link's hash + the canonical entry (hash field
    itself excluded). Tamper-evident: editing or reordering
    any stored entry breaks every later link."""
    body = {k: v for k, v in entry.items() if k != "hash"}
    return hashlib.sha256(
        (prev_hash or "").encode() + _canonical(body)).hexdigest()


def validate_record(record: dict) -> dict:
    """Validate + normalize one deposit record. Raises
    ArchiveError on anything unsealed, plaintext-bearing, or
    structurally incomplete — a deposit that cannot be proven
    sealed is not a deposit."""
    if not isinstance(record, dict):
        raise ArchiveError("archive record is not an object")
    for bad in ("body", "plaintext", "text"):
        if record.get(bad):
            raise ArchiveError(
                f"archive record carries plaintext field {bad!r} — "
                "refused (sealed envelopes only)")
    mid = str(record.get("message_id") or "")
    conv = str(record.get("conversation_id") or "")
    parts = [str(p) for p in (record.get("participants") or [])
             if p]
    if not mid or not conv or not parts:
        raise ArchiveError(
            "archive record needs message_id, conversation_id "
            "and at least one participant")
    sealed = record.get("oversight")
    if not (isinstance(sealed, dict) and sealed.get("ct")):
        raise ArchiveError(
            "archive record has no sealed oversight envelope — "
            "refused (fail-closed deposit)")
    out = {
        "message_id": mid,
        "conversation_id": conv,
        "participants": parts,
        "sender": str(record.get("sender") or ""),
        "kind": str(record.get("kind") or "dm"),
        "ts": int(record.get("ts") or time.time()),
        "oversight": sealed,
        "oversight_kind": str(
            record.get("oversight_kind") or "content"),
    }
    if record.get("file"):
        out["file"] = record["file"]
    return out


def verify_chain(entries: list[dict]) -> bool:
    """Recompute a conversation chain (entries in stored
    order); False on any tamper, gap, or reorder."""
    prev = ""
    for e in entries:
        if e.get("prev") != prev:
            return False
        if entry_hash(prev, e) != e.get("hash"):
            return False
        prev = e["hash"]
    return True


class LocalArchiveBackend:
    """The archive layout on a plain directory tree — the
    sandbox form of the Drive archive, and the staging form
    for the Drive backends. Layout (DESIGN-BRIEF rule 5):

        <root>/<agent>/<conversation_id>/chain.jsonl

    One append-only hash-chained file per (agent,
    conversation); a deposit is filed under EVERY
    participant, so a conversation lives in each
    participant's folder and no agent's chats mix."""

    def __init__(self, root):
        self.root = Path(root).expanduser()

    def _chain_path(self, agent: str, conversation_id: str) -> Path:
        safe = conversation_id.replace("/", "_")
        return self.root / agent / safe / "chain.jsonl"

    def _last_hash(self, path: Path) -> str:
        if not path.exists():
            return ""
        last = ""
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    last = json.loads(line).get("hash") or last
                except Exception:
                    continue
        return last

    def deposit(self, record: dict) -> dict:
        entry = validate_record(record)
        entry_id = entry["message_id"]
        hashes = {}
        for agent in entry["participants"]:
            path = self._chain_path(agent, entry["conversation_id"])
            path.parent.mkdir(parents=True, exist_ok=True)
            prev = self._last_hash(path)
            link = dict(entry)
            link["prev"] = prev
            link["hash"] = entry_hash(prev, link)
            with open(path, "a") as fh:
                fh.write(json.dumps(link, default=str) + "\n")
            hashes[agent] = link["hash"]
        return {"confirmed": True, "entry_id": entry_id,
                "hashes": hashes,
                "folders": sorted(hashes)}

    def read_conversation(self, agent: str,
                            conversation_id: str) -> list[dict]:
        path = self._chain_path(agent, conversation_id)
        if not path.exists():
            return []
        out = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
        return out


class DriveCliBackend:
    """The archive on the owner's real Google Drive, written
    through this VM's proven Drive route (``hatch_gws_cli`` —
    the same tool + account as the daily encrypted backups;
    the CLI holds its own auth, no Drive credential lives in
    this process). Used by the VM-hosted harness to prove REAL
    deposits; the production Firebase function performs the
    same layout via Drive REST with its server-side credential.

    Deposits stage the identical local layout, then upload the
    conversation's chain file into the configured Drive folder
    (append-evidence: each upload is the chain file as of that
    deposit, sealed envelopes only)."""

    def __init__(self, staging_root, drive_folder_id: str,
                 cli: str = "/opt/hatch/bin/hatch_gws_cli"):
        self.local = LocalArchiveBackend(staging_root)
        self.drive_folder_id = drive_folder_id
        self.cli = cli

    def deposit(self, record: dict) -> dict:
        import subprocess
        conf = self.local.deposit(record)
        conv = validate_record(record)["conversation_id"]
        for agent in conf["folders"]:
            path = self.local._chain_path(agent, conv)
            name = f"{agent}__{conv.replace(':', '_')}__chain.jsonl"
            staged = path.parent / name
            staged.write_bytes(path.read_bytes())
            res = subprocess.run(
                [self.cli, "drive", "+upload", str(staged),
                 "--parent", self.drive_folder_id,
                 "--format", "json"],
                capture_output=True, text=True, timeout=120)
            if res.returncode != 0:
                raise ArchiveError(
                    "Drive upload failed for "
                    f"{agent}/{conv}: {res.stderr[:200]}")
        conf["drive_folder"] = self.drive_folder_id
        return conf

    def read_conversation(self, agent: str,
                            conversation_id: str) -> list[dict]:
        return self.local.read_conversation(agent, conversation_id)


def https_deposit(url: str, record: dict, token: str = "",
                  timeout: float = 30.0) -> dict:
    """Deposit via the archive service's HTTPS endpoint (the
    Firebase function's ``archiveDeposit``). Returns the
    service's confirmation; raises ArchiveError on ANY doubt —
    a non-200, an undecodable body, or a body that does not
    explicitly confirm. Fail-closed by construction."""
    import urllib.request
    from . import proxycreds
    entry = validate_record(record)
    data = json.dumps(entry).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-Archive-Token", token)
    try:
        with proxycreds.open_url(req, timeout=timeout) as resp:
            raw = resp.read()
    except Exception as exc:
        raise ArchiveError(f"archive deposit call failed: {exc}")
    try:
        conf = json.loads(raw or b"")
    except Exception:
        raise ArchiveError("archive deposit reply undecodable")
    if not conf.get("confirmed"):
        raise ArchiveError(
            f"archive deposit not confirmed: {str(conf)[:160]}")
    return conf
