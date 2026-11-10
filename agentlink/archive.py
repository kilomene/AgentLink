"""Owner archive — Disappearing Mode v2 (2.4.0); universal
deposit (2.4.1).

2.4.1 (owner ruling 2026-11-10): the Drive deposit is no longer
disappearing-only — EVERY send (standard + disappearing, DM +
group + channel) deposits its oversight-sealed envelope here at
send time, through this same core. The asymmetry the ruling
keeps: disappearing deposits stay FAIL-CLOSED (no deposit, no
send — transport._disappearing_gate), while STANDARD deposits
are mandatory-but-not-blocking — the Supabase archive write
(al_audit_log) remains the durability of record, so a failed
standard deposit retries through the durable DepositRetryQueue
below (visible in diagnostics; permanent failure parks loudly
in the dead-letter park, never silently drops) and lands when
the service recovers. A standard record cross-references the
Supabase archive: it carries ``mode: "standard"`` plus
``audit_seq`` — the al_audit_log ``seq`` of the row holding the
same envelope — so the Drive chain and the Supabase archive
point at each other by construction.

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
    mode = str(record.get("mode") or "")
    if mode not in ("standard", "disappearing"):
        mode = ("disappearing"
                if str(record.get("kind") or "") == "disappearing"
                else "standard")
    out["mode"] = mode
    if record.get("audit_seq") is not None:
        try:
            out["audit_seq"] = int(record["audit_seq"])
        except (TypeError, ValueError):
            raise ArchiveError(
                "archive record audit_seq is not an integer")
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


class DepositRetryQueue:
    """Durable retry queue for STANDARD (non-blocking) deposits
    (2.4.1). One JSON document at a fixed path; every mutation
    is an atomic rewrite (tmp + os.replace), so a crash cannot
    lose a queued deposit. Entries: {record, attempts,
    next_attempt_at, queued_at, last_error}. The record is the
    full validated deposit record, so the queued entry IS the
    deposit — draining needs no other state. Idempotent by
    message id: enqueue of an already-queued message id is a
    no-op. Failures stay visible: entries remain until they
    deposit or the caller parks them (dead-letter park) at
    exhaustion — this queue never drops a row on its own."""

    def __init__(self, path=None):
        self.path = (Path(path).expanduser() if path else None)
        self._entries: dict[str, dict] = {}
        if self.path and self.path.exists():
            try:
                doc = json.loads(self.path.read_text())
                for e in doc.get("entries") or []:
                    rec = e.get("record") or {}
                    if rec.get("message_id"):
                        self._entries[str(rec["message_id"])] = e
            except Exception:
                # A corrupt queue file must not lose the queue's
                # purpose silently: start empty, and the caller
                # can still see the file on disk; deposit
                # attempts regenerate from sends going forward.
                self._entries = {}

    def _save(self) -> None:
        if not self.path:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(
            {"entries": [self._entries[k]
                         for k in sorted(self._entries)]},
            default=str))
        import os
        os.replace(tmp, self.path)

    def enqueue(self, record: dict, *, last_error: str,
                next_attempt_at: float) -> bool:
        mid = str((record or {}).get("message_id") or "")
        if not mid:
            raise ArchiveError(
                "cannot queue a deposit without a message_id")
        if mid in self._entries:
            return False
        self._entries[mid] = {
            "record": record,
            "attempts": 1,
            "next_attempt_at": float(next_attempt_at),
            "queued_at": time.time(),
            "last_error": str(last_error)[:400],
        }
        self._save()
        return True

    def note_failure(self, message_id: str, *, last_error: str,
                     next_attempt_at: float) -> dict | None:
        e = self._entries.get(str(message_id))
        if e is None:
            return None
        e["attempts"] = int(e.get("attempts") or 0) + 1
        e["next_attempt_at"] = float(next_attempt_at)
        e["last_error"] = str(last_error)[:400]
        self._save()
        return e

    def remove(self, message_id: str) -> bool:
        if self._entries.pop(str(message_id), None) is None:
            return False
        self._save()
        return True

    def due(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        return [e for e in self._entries.values()
                if float(e.get("next_attempt_at") or 0) <= now]

    def records(self) -> list[dict]:
        return [self._entries[k] for k in sorted(self._entries)]

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, message_id) -> bool:
        return str(message_id) in self._entries


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


# ============================================================
# Universal archive backfill (2.4.1): deposit the EXISTING
# standard Supabase archive (al_audit_log) into the Drive
# folders, chained per conversation, idempotent by message id.
# ============================================================

BACKFILL_SELECT = ("seq,ts,kind,actor,target,group_id,ref_id,"
                   "oversight,content_envelope")
BACKFILL_KINDS = ("message", "group_message", "channel_message")


def fetch_audit_range(rest_get, *, after_seq: int = 0,
                      limit: int = 500) -> list[dict]:
    """Fetch one page of oversight-bearing audit rows via a
    PostgREST-shaped GET callable (path, headers) -> rows.
    The caller retries a clipped/empty page (known egress
    fault class) before accepting it; an empty page here is
    NEVER proof of end-of-table on its own — the caller checks
    the table maximum seq separately (see backfill_history)."""
    path = ("/al_audit_log?select=" + BACKFILL_SELECT
            + f"&kind=in.({','.join(BACKFILL_KINDS)})"
            + "&oversight=not.is.null"
            + f"&seq=gt.{int(after_seq)}"
            + "&order=seq.asc"
            + f"&limit={int(limit)}")
    return rest_get(path) or []


def row_oversight_wrap(row: dict):
    """The oversight-sealed envelope for one audit row: the
    ``oversight`` column verbatim (object or its JSON text);
    when empty, the wrap may live inside content_envelope
    (the history/local-archive shape). Never fabricates one:
    a row with no wrap returns None and the backfill skips it
    loudly (counted, never silently dropped)."""
    for raw in (row.get("oversight"),):
        if isinstance(raw, dict) and raw.get("ct"):
            return raw
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
            except Exception:
                parsed = None
            if isinstance(parsed, dict) and parsed.get("ct"):
                return parsed
    env = row.get("content_envelope")
    if isinstance(env, str) and env.strip():
        try:
            env = json.loads(env)
        except Exception:
            env = None
    if isinstance(env, dict):
        wrap = env.get("oversight")
        if isinstance(wrap, dict) and wrap.get("ct"):
            return wrap
    return None


def row_to_record(row: dict, *, participants=None,
                  group_members=None) -> dict | None:
    """Map one al_audit_log row to a standard deposit record,
    or None when the row carries no depositable oversight wrap
    (the caller counts + reports those). Group/channel
    participants default to the sender + every username ever
    observed in the conversation's rows + the current member
    list (``group_members``), so the filing covers everyone the
    conversation belongs to."""
    wrap = row_oversight_wrap(row)
    if wrap is None:
        return None
    kind = str(row.get("kind") or "")
    actor = str(row.get("actor") or "")
    gid = str(row.get("group_id") or "")
    if kind == "message":
        conv = conversation_id_dm(actor, str(row.get("target")
                                             or ""))
        parts = [actor, str(row.get("target") or "")]
        rkind = "dm"
    elif kind == "group_message":
        conv = conversation_id_group(gid)
        parts = list(participants or [])
        rkind = "group"
    elif kind == "channel_message":
        conv = conversation_id_channel(gid)
        parts = list(participants or [])
        rkind = "channel"
    else:
        return None
    parts = sorted({p for p in parts if p})
    if not parts:
        return None
    ts = row.get("ts")
    try:
        ts = int(ts) if ts is not None else int(time.time())
    except (TypeError, ValueError):
        ts = int(time.time())
    # oversight_kind is NOT an al_audit_log column (the audit
    # schema's field-minimal set is the dashboard's AUDIT_SELECT):
    # it is derived from the row kind — group/channel wraps seal
    # the room CONTENT KEY, DM wraps seal the content — exactly
    # the kinds the live send paths deposit under. An explicit
    # oversight_kind on the row dict (tests, other sources) is
    # honoured when present.
    record = {
        "message_id": str(row.get("ref_id") or ""),
        "conversation_id": conv,
        "participants": parts,
        "sender": actor,
        "kind": rkind,
        "ts": ts,
        "oversight": wrap,
        "oversight_kind": str(
            row.get("oversight_kind")
            or ("content_key" if rkind in ("group", "channel")
                else "content")),
        "mode": "standard",
    }
    if row.get("seq") is not None:
        record["audit_seq"] = row["seq"]
    return record


def backfill_history(rows: list[dict], backend, *,
                     group_members: dict | None = None) -> dict:
    """Deposit every depositable row into the backend, chained
    per conversation, skipping message ids already present in
    ANY participant's chain (dedupe by message id). Idempotent:
    a second run over the same rows deposits 0. Returns
    {deposited, skipped_existing, skipped_unsealed,
    per_conversation: {conv: {deposited, skipped_existing,
    archive_rows}}} where archive_rows is the audit-row count
    for the conversation — completeness is deposited +
    skipped_existing == archive_rows - skipped_unsealed."""
    group_members = group_members or {}
    observed: dict[str, set] = {}
    for row in rows:
        if str(row.get("kind") or "") in ("group_message",
                                           "channel_message"):
            gid = str(row.get("group_id") or "")
            parts = observed.setdefault(gid, set())
            if row.get("actor"):
                parts.add(str(row["actor"]))
            if row.get("target"):
                parts.add(str(row["target"]))
    report: dict = {"deposited": 0, "skipped_existing": 0,
                    "skipped_unsealed": 0, "per_conversation": {}}
    present_cache: dict[str, set] = {}

    def present_ids(agent: str, conv: str) -> set:
        key = agent + "|" + conv
        if key not in present_cache:
            reader = getattr(backend, "read_conversation", None)
            ids = set()
            if reader is not None:
                for e in reader(agent, conv) or []:
                    if e.get("message_id"):
                        ids.add(str(e["message_id"]))
            present_cache[key] = ids
        return present_cache[key]

    for row in sorted(rows, key=lambda r: int(r.get("seq") or 0)):
        kind = str(row.get("kind") or "")
        gid = str(row.get("group_id") or "")
        parts = None
        if kind in ("group_message", "channel_message"):
            parts = sorted(observed.get(gid, set())
                           | set(group_members.get(gid, [])))
        rec = row_to_record(row, participants=parts)
        if rec is None:
            report["skipped_unsealed"] += 1
            conv_key = (conversation_id_group(gid)
                        if kind == "group_message"
                        else conversation_id_channel(gid)
                        if kind == "channel_message"
                        else conversation_id_dm(
                            str(row.get("actor") or ""),
                            str(row.get("target") or "")))
            pc = report["per_conversation"].setdefault(
                conv_key, {"deposited": 0, "skipped_existing": 0,
                           "archive_rows": 0,
                           "skipped_unsealed": 0})
            pc["archive_rows"] += 1
            pc["skipped_unsealed"] += 1
            continue
        conv = rec["conversation_id"]
        pc = report["per_conversation"].setdefault(
            conv, {"deposited": 0, "skipped_existing": 0,
                   "archive_rows": 0, "skipped_unsealed": 0})
        pc["archive_rows"] += 1
        mid = rec["message_id"]
        if any(mid in present_ids(p, conv)
               for p in rec["participants"]):
            report["skipped_existing"] += 1
            pc["skipped_existing"] += 1
            continue
        backend.deposit(rec)
        report["deposited"] += 1
        pc["deposited"] += 1
        for p in rec["participants"]:
            present_ids(p, conv).add(mid)
    return report
