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

TWO-COPY LAW (2.5.0, owner correction 2026-11-11): every
archive deposit of a REAL conversation lands TWO copies in the
agent's archive subfolder — the SEALED hash-chained file
(tamper evidence of record; this module's chain) and, beside
it, a READABLE transcript (``<conversation>.readable.md``)
rendered from the plaintext the DEPOSITOR already holds at
deposit time (sender-side or participant-side local plaintext —
NEVER produced by breaking the seal server-side; a depositor
with no plaintext deposits the chain only and the gap is a
visible note in its deposit report). SEALED for proof, READABLE
for the owner. PRIVACY POSTURE (owner's explicit order): the
readable copies are plaintext in the owner's own Drive, in the
owner's own archive, at the owner's order — his archive, his
call; the sealed chain remains the copy that proves nothing was
altered. Media entries render as a readable placeholder line
(name/size/sha256), never a fake inline.

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

    def deposit(self, record: dict, readable_entry=None) -> dict:
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
        readable = None
        if readable_entry is not None:
            # TWO-COPY LAW: the readable transcript lands beside
            # the chain, rendered from the depositor's own
            # plaintext (see the module docstring).
            try:
                readable = self.deposit_readable(
                    entry["participants"],
                    entry["conversation_id"], readable_entry)
            except Exception as exc:  # noqa: BLE001 - visible gap
                readable = {"status": "error",
                            "reason": str(exc)[:160]}
        conf = {"confirmed": True, "entry_id": entry_id,
                "hashes": hashes,
                "folders": sorted(hashes)}
        if readable is not None:
            conf["readable"] = readable
        return conf

    # -- readable transcripts (TWO-COPY LAW, 2.5.0) --------------
    def _readable_entries_path(self, agent: str,
                               conversation_id: str) -> Path:
        return self._chain_path(agent, conversation_id).parent / \
            "readable-entries.jsonl"

    def _readable_path(self, agent: str,
                       conversation_id: str) -> Path:
        return self._chain_path(agent, conversation_id).parent / \
            "readable.md"

    def read_readable_entries(self, agent: str,
                              conversation_id: str) -> list[dict]:
        path = self._readable_entries_path(agent, conversation_id)
        if not path.exists():
            return []
        out = []
        for line in path.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    continue
        return out

    def deposit_readable(self, participants, conversation_id: str,
                         entry: dict) -> dict:
        """File ONE plaintext entry (the depositor's own —
        sender/participant side) into every participant's
        readable transcript beside the chain, re-rendering the
        .md from the full entry set (dedupe by message id, so
        re-deposits and multi-participant renders converge).
        Returns {status, entries, files}."""
        entry = validate_readable_entry(entry)
        files = []
        count = 0
        for agent in participants:
            entries = self.read_readable_entries(
                agent, conversation_id)
            if not any(e.get("message_id") == entry["message_id"]
                       for e in entries):
                entries.append(entry)
                epath = self._readable_entries_path(
                    agent, conversation_id)
                epath.parent.mkdir(parents=True, exist_ok=True)
                with open(epath, "a") as fh:
                    fh.write(json.dumps(entry, default=str) + "\n")
            chain = self.read_conversation(agent, conversation_id)
            head = chain[-1]["hash"] if chain else ""
            md = render_transcript(conversation_id, participants,
                                   entries, chain_head=head)
            mpath = self._readable_path(agent, conversation_id)
            mpath.parent.mkdir(parents=True, exist_ok=True)
            mpath.write_text(md)
            files.append(str(mpath))
            count = len({e["message_id"] for e in entries})
        return {"status": "stored", "entries": count,
                "files": files}

    def deposit_readable_many(self, participants,
                              conversation_id: str,
                              entries) -> dict:
        """Bulk form (operator backfill): file many entries,
        render ONCE per participant."""
        norm = [validate_readable_entry(e) for e in entries]
        files = []
        count = 0
        for agent in participants:
            existing = self.read_readable_entries(
                agent, conversation_id)
            known = {e.get("message_id") for e in existing}
            fresh = [e for e in norm
                     if e["message_id"] not in known]
            if fresh:
                epath = self._readable_entries_path(
                    agent, conversation_id)
                epath.parent.mkdir(parents=True, exist_ok=True)
                with open(epath, "a") as fh:
                    for e in fresh:
                        fh.write(json.dumps(e, default=str) + "\n")
                existing = existing + fresh
            chain = self.read_conversation(agent, conversation_id)
            head = chain[-1]["hash"] if chain else ""
            md = render_transcript(conversation_id, participants,
                                   existing, chain_head=head)
            mpath = self._readable_path(agent, conversation_id)
            mpath.parent.mkdir(parents=True, exist_ok=True)
            mpath.write_text(md)
            files.append(str(mpath))
            count = len({e["message_id"] for e in existing})
        return {"status": "stored", "entries": count,
                "files": files}

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

    def _upload(self, staged: Path) -> None:
        import subprocess
        res = subprocess.run(
            [self.cli, "drive", "+upload", str(staged),
             "--parent", self.drive_folder_id,
             "--format", "json"],
            capture_output=True, text=True, timeout=120)
        if res.returncode != 0:
            raise ArchiveError(
                f"Drive upload failed for {staged.name}: "
                f"{res.stderr[:200]}")

    def deposit(self, record: dict, readable_entry=None) -> dict:
        conf = self.local.deposit(record,
                                  readable_entry=readable_entry)
        conv = validate_record(record)["conversation_id"]
        for agent in conf["folders"]:
            path = self.local._chain_path(agent, conv)
            name = f"{agent}__{conv.replace(':', '_')}__chain.jsonl"
            staged = path.parent / name
            staged.write_bytes(path.read_bytes())
            self._upload(staged)
            # TWO-COPY LAW: the readable transcript uploads
            # beside the chain file (same folder, same naming
            # discipline) whenever the depositor held plaintext.
            rpath = self.local._readable_path(agent, conv)
            if readable_entry is not None and rpath.exists():
                rname = (f"{agent}__{conv.replace(':', '_')}"
                         f"__readable.md")
                rstaged = path.parent / rname
                rstaged.write_bytes(rpath.read_bytes())
                self._upload(rstaged)
        conf["drive_folder"] = self.drive_folder_id
        return conf

    def deposit_readable(self, participants, conversation_id: str,
                         entry: dict) -> dict:
        out = self.local.deposit_readable(participants,
                                          conversation_id, entry)
        for agent in participants:
            rpath = self.local._readable_path(agent,
                                              conversation_id)
            if rpath.exists():
                conv = conversation_id
                rname = (f"{agent}__{conv.replace(':', '_')}"
                         f"__readable.md")
                staged = rpath.parent / rname
                staged.write_bytes(rpath.read_bytes())
                self._upload(staged)
        out["drive_folder"] = self.drive_folder_id
        return out

    def deposit_readable_many(self, participants,
                              conversation_id: str,
                              entries) -> dict:
        out = self.local.deposit_readable_many(
            participants, conversation_id, entries)
        for agent in participants:
            rpath = self.local._readable_path(agent,
                                              conversation_id)
            if rpath.exists():
                rname = (f"{agent}__"
                         f"{conversation_id.replace(':', '_')}"
                         f"__readable.md")
                staged = rpath.parent / rname
                staged.write_bytes(rpath.read_bytes())
                self._upload(staged)
        out["drive_folder"] = self.drive_folder_id
        return out

    def read_conversation(self, agent: str,
                            conversation_id: str) -> list[dict]:
        return self.local.read_conversation(agent, conversation_id)


# ----------------------------------------------------------------------
# Readable transcripts — the owner's reading copy (TWO-COPY LAW,
# 2.5.0). Rendered ONLY from plaintext the depositor already
# holds (its own sent messages, or a participant's local
# mailbox) — never by opening the sealed chain server-side.
# ----------------------------------------------------------------------

def validate_readable_entry(entry: dict) -> dict:
    """One readable entry: {message_id, sender, ts, text} or
    {message_id, sender, ts, file: {name, size, sha256}}.
    Anything else is refused — the readable copy carries message
    plaintext and file FACTS only, never blobs or envelopes."""
    if not isinstance(entry, dict):
        raise ArchiveError("readable entry is not an object")
    mid = str(entry.get("message_id") or "")
    sender = str(entry.get("sender") or "")
    if not mid or not sender:
        raise ArchiveError("readable entry needs message_id + sender")
    try:
        ts = int(entry.get("ts") or 0)
    except (TypeError, ValueError):
        raise ArchiveError("readable entry ts is not an integer")
    out = {"message_id": mid, "sender": sender, "ts": ts}
    f = entry.get("file")
    if isinstance(f, dict) and f:
        out["file"] = {"name": str(f.get("name") or "file"),
                       "size": int(f.get("size") or 0),
                       "sha256": str(f.get("sha256") or "")}
        if entry.get("text"):
            out["text"] = str(entry["text"])
    elif entry.get("text") is not None:
        out["text"] = str(entry.get("text") or "")
    else:
        raise ArchiveError(
            "readable entry carries neither text nor file facts")
    return out


def _fmt_ts(ts: int) -> str:
    import datetime
    try:
        return datetime.datetime.fromtimestamp(
            int(ts), datetime.timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return f"ts {ts}"


def render_transcript(conversation_id: str, participants,
                      entries, *, chain_head: str = "") -> str:
    """The deterministic readable rendering. Sorted by
    (ts, message_id), deduped by message id. The header binds
    the rendering to the depositor's entry set (render hash)
    and to the sealed chain (head hash at render time), so a
    tampered readable file is detectable: re-rendering from the
    entry set must reproduce it byte-for-byte, and the head must
    match the chain it sits beside."""
    seen: dict[str, dict] = {}
    for e in entries:
        e = validate_readable_entry(e)
        seen.setdefault(e["message_id"], e)
    ordered = sorted(seen.values(),
                     key=lambda e: (e["ts"], e["message_id"]))
    render_hash = hashlib.sha256(
        _canonical(ordered)).hexdigest()
    lines = [
        f"# {conversation_id}",
        "",
        f"Participants: {', '.join(str(p) for p in participants)}",
        "Archive copies: SEALED chain (tamper evidence of record)"
        " + this READABLE transcript (the owner's reading copy).",
        f"Entries: {len(ordered)} · Chain head at render: "
        f"{chain_head or 'none'} · Render hash: {render_hash}",
        "",
    ]
    for e in ordered:
        stamp = _fmt_ts(e["ts"])
        if "file" in e:
            f = e["file"]
            line = (f"[{stamp}] {e['sender']}: [file: {f['name']} "
                    f"— {f['size']} bytes — sha256 "
                    f"{f['sha256'] or 'unknown'}]")
            if e.get("text"):
                line += f" {e['text']}"
            lines.append(line)
        else:
            text = e.get("text") or ""
            parts = text.split("\n")
            lines.append(f"[{stamp}] {e['sender']}: {parts[0]}")
            for extra in parts[1:]:
                lines.append(f"  {extra}")
    return "\n".join(lines) + "\n"


def verify_readable(md_text: str, entries,
                    chain_entries=None) -> tuple[bool, str]:
    """Detect a tampered readable file: (1) re-rendering from
    the depositor's entry set must reproduce the file exactly
    (modulo the chain-head line, which legitimately advances as
    the chain grows — the head recorded IN the file is used for
    the re-render); (2) when the sealed chain is supplied, the
    readable entry set must match the chain's message set and
    the recorded head must be one of the chain's hashes."""
    head = ""
    for line in md_text.splitlines():
        if "Chain head at render:" in line:
            head = line.split("Chain head at render:")[1].split(
                "·")[0].strip()
            break
    conv = ""
    for line in md_text.splitlines():
        if line.startswith("# "):
            conv = line[2:].strip()
            break
    participants = []
    for line in md_text.splitlines():
        if line.startswith("Participants: "):
            participants = [p.strip() for p in
                            line[len("Participants: "):].split(",")]
            break
    expected = render_transcript(conv, participants, entries,
                                 chain_head=head)
    if expected != md_text:
        return False, "readable file does not match its entry set"
    if chain_entries is not None:
        chain_ids = [c.get("message_id") for c in chain_entries]
        entry_ids = {validate_readable_entry(e)["message_id"]
                     for e in entries}
        if not entry_ids.issubset(set(chain_ids)):
            return False, ("readable entries are not a subset of "
                           "the sealed chain")
        hashes = {c.get("hash") for c in chain_entries}
        if head and head not in hashes:
            return False, ("recorded chain head is not in the "
                           "sealed chain")
    return True, "ok"


def backfill_entries_from_mailbox(mailbox_db_path, owner: str
                                  ) -> dict:
    """OPERATOR BACKFILL (2.5.0): build readable entries from a
    PARTICIPANT's local mailbox (participant-side plaintext —
    the agent's own journal of what it sent and received; the
    seal is never opened). Returns
    {conversation_id: {"participants": [...], "entries": [...]}}
    plus a "_gaps" list naming journal rows that carried no
    renderable plaintext (visible, never silently skipped)."""
    import sqlite3
    db = sqlite3.connect(str(mailbox_db_path))
    try:
        rows = db.execute(
            "SELECT id, ts, from_user, to_user, group_id, msg "
            "FROM items ORDER BY ts, id").fetchall()
    finally:
        db.close()
    convs: dict[str, dict] = {}
    gaps = []
    for mid, ts, frm, to, gid, msg_raw in rows:
        try:
            msg = json.loads(msg_raw or "{}")
        except Exception:
            gaps.append({"message_id": mid,
                         "reason": "journal row not JSON"})
            continue
        body = msg.get("body")
        file = msg.get("file")
        if body is None and not file:
            gaps.append({"message_id": mid,
                         "reason": "no plaintext in journal row"})
            continue
        entry = {"message_id": mid, "sender": frm or owner,
                 "ts": int(msg.get("ts") or ts or 0)}
        if file:
            entry["file"] = {
                "name": str(file.get("name") or "file"),
                "size": int(file.get("size") or 0),
                "sha256": str(file.get("sha256") or "")}
            if body:
                entry["text"] = str(body)
        else:
            entry["text"] = str(body or "")
        if gid:
            conv = conversation_id_group(gid)
            parts = convs.setdefault(
                conv, {"participants": set(), "entries": []})
            parts["participants"].add(frm or owner)
            parts["participants"].add(owner)
        else:
            other = to if frm == owner else frm
            conv = conversation_id_dm(owner, other or "")
            parts = convs.setdefault(
                conv, {"participants": {owner, other},
                       "entries": []})
        parts["entries"].append(entry)
    out = {}
    for conv, data in convs.items():
        out[conv] = {
            "participants": sorted(p for p in
                                   data["participants"] if p),
            "entries": data["entries"]}
    out["_gaps"] = gaps
    return out


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
