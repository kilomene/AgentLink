"""SQLite state for the AgentLink relay.

Tables: users, offline queue, groups, group members, invite tokens,
work items and work deliveries. All access is serialised with a lock;
the relay is a single event loop, so this is cheap and race-free.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from pathlib import Path

from .protocol import new_id, new_secret, now_ts

DEFAULT_SETTINGS = {
    "send_messages": "everyone",      # everyone | admins_only
    "add_members": "everyone",        # everyone | admins_only
    "assign_work": "everyone",        # everyone | admins_only
    "vault_add": "everyone",          # everyone | admins_only
}

MAX_GROUP_MEMBERS = 50
PRIORITY_WEIGHT = {"normal": 0, "high": 1, "urgent": 2}
MAX_CHANNEL_SUBSCRIBERS = 1000
CHUNK_SIZE = 1024 * 1024

# Canonical invite lifetime (v1.1.0): the Supabase al_invites shape
# stores token + created_at only, so validity is defined as
# created_at + INVITE_TTL_SECONDS >= now. create_invite shifts
# created_at so a custom ttl_seconds keeps its exact meaning.
INVITE_TTL_SECONDS = 7 * 24 * 3600  # 1 MiB resumable-upload chunk


class UsernameTaken(Exception):
    pass


class GroupFull(Exception):
    pass


class InvalidTransition(Exception):
    """Fail-closed state machine: illegal work-status jump (point 32)."""


class NotFound(Exception):
    pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 'Highly classified' handling: 0700 dir, 0600 DB file, WAL,
        # integrity-checked on startup. The DB holds ciphertext and
        # metadata only — no private keys, and owner-secrets only as
        # SHA-256 hashes (see claim()).
        try:
            import os
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        integrity = self._db.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"relay DB integrity check failed: {integrity}")
        try:
            import os
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        with self._lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    secret TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    pubkey TEXT NOT NULL DEFAULT '',
                    sign_pub TEXT NOT NULL DEFAULT '',
                    capabilities TEXT NOT NULL DEFAULT '[]',
                    cap_desc TEXT NOT NULL DEFAULT '',
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS queue (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    to_username TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0,
                    ts INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_queue_to ON queue(to_username, seq);
                CREATE TABLE IF NOT EXISTS groups (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    creator TEXT NOT NULL,
                    settings TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    nickname TEXT NOT NULL DEFAULT '',
                    custom_role TEXT NOT NULL DEFAULT '',
                    added_by TEXT NOT NULL DEFAULT '',
                    joined_at INTEGER NOT NULL,
                    PRIMARY KEY (group_id, username)
                );
                CREATE TABLE IF NOT EXISTS group_keys (
                    group_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    wrapped TEXT NOT NULL,
                    PRIMARY KEY (group_id, username)
                );
                CREATE TABLE IF NOT EXISTS invites (
                    token TEXT PRIMARY KEY,
                    group_id TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS work (
                    id TEXT PRIMARY KEY,
                    assigner TEXT NOT NULL,
                    assignee TEXT NOT NULL,
                    group_id TEXT,
                    content_enc TEXT NOT NULL DEFAULT '',
                    content_self TEXT NOT NULL DEFAULT '',
                    batch_id TEXT,
                    chain_id TEXT NOT NULL DEFAULT '',
                    chain_step INTEGER NOT NULL DEFAULT 0,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    auto_reassign INTEGER NOT NULL DEFAULT 1,
                    assignee_role TEXT NOT NULL DEFAULT '',
                    require_approval INTEGER NOT NULL DEFAULT 0,
                    content_group TEXT NOT NULL DEFAULT '',
                    priority TEXT NOT NULL DEFAULT 'normal',
                    progress_percent INTEGER NOT NULL DEFAULT 0,
                    progress_at INTEGER NOT NULL DEFAULT 0,
                    proof_hash TEXT NOT NULL DEFAULT '',
                    proof_ts INTEGER NOT NULL DEFAULT 0,
                    proof_sig TEXT NOT NULL DEFAULT '',
                    proof_verified INTEGER NOT NULL DEFAULT 0,
                    deadline INTEGER,
                    status TEXT NOT NULL DEFAULT 'assigned',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_work_assignee ON work(assignee, status);
                CREATE INDEX IF NOT EXISTS idx_work_assigner ON work(assigner, status);
                CREATE TABLE IF NOT EXISTS work_deliveries (
                    id TEXT PRIMARY KEY,
                    work_id TEXT NOT NULL,
                    deliverer TEXT NOT NULL,
                    content_enc TEXT NOT NULL DEFAULT '',
                    content_self TEXT NOT NULL DEFAULT '',
                    content_group TEXT NOT NULL DEFAULT '',
                    content_next TEXT NOT NULL DEFAULT '',
                    ts INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS blobs (
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    for_user TEXT NOT NULL DEFAULT '',
                    for_group TEXT NOT NULL DEFAULT '',
                    for_channel TEXT NOT NULL DEFAULT '',
                    whole_sha TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dashboard_sessions (
                    token_hash TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    group_id TEXT NOT NULL DEFAULT '',
                    work_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT '',
                    priority TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    mentions TEXT NOT NULL DEFAULT '[]',
                    ref_id TEXT NOT NULL DEFAULT '',
                    sender_nickname TEXT NOT NULL DEFAULT '',
                    sender_role TEXT NOT NULL DEFAULT '',
                    sender_custom_role TEXT NOT NULL DEFAULT '',
                    oversight TEXT NOT NULL DEFAULT '',
                    content_envelope TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    reminders INTEGER NOT NULL DEFAULT 0,
                    last_reminder_at INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    resolved_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS library (
                    id TEXT PRIMARY KEY,
                    delivery_id TEXT NOT NULL DEFAULT '',
                    work_id TEXT NOT NULL DEFAULT '',
                    filename TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT '',
                    sender TEXT NOT NULL DEFAULT '',
                    to_user TEXT NOT NULL DEFAULT '',
                    group_id TEXT NOT NULL DEFAULT '',
                    chain_next TEXT NOT NULL DEFAULT '',
                    ts INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS chains (
                    id TEXT PRIMARY KEY,
                    creator TEXT NOT NULL,
                    group_id TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'running',
                    paused_since INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chain_steps (
                    id TEXT PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    target_type TEXT NOT NULL DEFAULT 'user',
                    target TEXT NOT NULL DEFAULT '',
                    group_id TEXT NOT NULL DEFAULT '',
                    assignees TEXT NOT NULL DEFAULT '[]',
                    envelopes TEXT NOT NULL DEFAULT '{}',
                    content_group TEXT NOT NULL DEFAULT '',
                    deadline INTEGER,
                    priority TEXT NOT NULL DEFAULT 'normal',
                    status TEXT NOT NULL DEFAULT 'pending',
                    work_id TEXT NOT NULL DEFAULT '',
                    handoff TEXT NOT NULL DEFAULT '[]',
                    require_approval INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vault (
                    id TEXT PRIMARY KEY,
                    group_id TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT '',
                    blob_id TEXT NOT NULL DEFAULT '',
                    descriptor TEXT NOT NULL DEFAULT '{}',
                    added_by TEXT NOT NULL DEFAULT '',
                    pinned INTEGER NOT NULL DEFAULT 0,
                    ts INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS work_checkpoints (
                    work_id TEXT PRIMARY KEY,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    by_user TEXT NOT NULL DEFAULT '',
                    content_assigner TEXT NOT NULL DEFAULT '',
                    content_group TEXT NOT NULL DEFAULT '',
                    ts INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS channels (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    creator TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS channel_members (
                    channel_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'subscriber',
                    added_by TEXT NOT NULL DEFAULT '',
                    joined_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, username)
                );
                CREATE TABLE IF NOT EXISTS channel_keys (
                    channel_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    wrapped TEXT NOT NULL,
                    PRIMARY KEY (channel_id, username)
                );
                CREATE TABLE IF NOT EXISTS upload_sessions (
                    session_id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    for_user TEXT NOT NULL DEFAULT '',
                    for_group TEXT NOT NULL DEFAULT '',
                    whole_sha TEXT NOT NULL DEFAULT '',
                    ct_sha TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    chunk_size INTEGER NOT NULL DEFAULT 0,
                    chunks TEXT NOT NULL DEFAULT '[]',
                    created_at INTEGER NOT NULL
                );
                """
            )
            self._db.commit()
            self._migrate_v11()

    def _migrate_v11(self) -> None:
        """v1.1.0 schema alignment (idempotent, runs on every open):
        invites -> canonical Supabase shape (token/created_at; the
        stored token stays the SHA-256 hash, created_at is back-derived
        as expires_at - INVITE_TTL_SECONDS so validity is preserved
        exactly for default-TTL invites); upload_sessions drops the
        for_channel column (channel scope is asserted by the relay at
        session start and carried on the finish frame); audit_log
        gains the sender identity columns; work + chain_steps gain
        require_approval."""
        db = self._db
        cols = [r[1] for r in db.execute("PRAGMA table_info(invites)")]
        if cols and "token_hash" in cols:
            db.execute(
                "CREATE TABLE invites_v11 ("
                " token TEXT PRIMARY KEY, group_id TEXT NOT NULL,"
                " created_by TEXT NOT NULL,"
                " created_at INTEGER NOT NULL)")
            db.execute(
                "INSERT INTO invites_v11 (token, group_id, created_by,"
                " created_at) SELECT token_hash, group_id, created_by,"
                " expires_at - ? FROM invites", (INVITE_TTL_SECONDS,))
            db.execute("DROP TABLE invites")
            db.execute("ALTER TABLE invites_v11 RENAME TO invites")
        cols = [r[1] for r in
                db.execute("PRAGMA table_info(upload_sessions)")]
        if "for_channel" in cols:
            db.execute(
                "CREATE TABLE upload_sessions_v11 ("
                " session_id TEXT PRIMARY KEY, owner TEXT NOT NULL,"
                " for_user TEXT NOT NULL DEFAULT '',"
                " for_group TEXT NOT NULL DEFAULT '',"
                " whole_sha TEXT NOT NULL DEFAULT '',"
                " ct_sha TEXT NOT NULL DEFAULT '',"
                " size INTEGER NOT NULL DEFAULT 0,"
                " chunk_size INTEGER NOT NULL DEFAULT 0,"
                " chunks TEXT NOT NULL DEFAULT '[]',"
                " created_at INTEGER NOT NULL)")
            db.execute(
                "INSERT INTO upload_sessions_v11 SELECT session_id,"
                " owner, for_user, for_group, whole_sha, ct_sha, size,"
                " chunk_size, chunks, created_at FROM upload_sessions")
            db.execute("DROP TABLE upload_sessions")
            db.execute("ALTER TABLE upload_sessions_v11"
                       " RENAME TO upload_sessions")

        def _add(table, column, ddl):
            existing = [r[1] for r in
                        db.execute(f"PRAGMA table_info({table})")]
            if existing and column not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        _add("audit_log", "sender_nickname",
             "sender_nickname TEXT NOT NULL DEFAULT ''")
        _add("audit_log", "sender_role",
             "sender_role TEXT NOT NULL DEFAULT ''")
        _add("audit_log", "sender_custom_role",
             "sender_custom_role TEXT NOT NULL DEFAULT ''")
        _add("audit_log", "oversight",
             "oversight TEXT NOT NULL DEFAULT ''")
        _add("audit_log", "content_envelope",
             "content_envelope TEXT NOT NULL DEFAULT ''")
        _add("work", "require_approval",
             "require_approval INTEGER NOT NULL DEFAULT 0")
        _add("chain_steps", "require_approval",
             "require_approval INTEGER NOT NULL DEFAULT 0")
        db.commit()

    # -- blob metadata (ciphertext lives in the blob store) ----------------
    def put_blob_meta(self, blob_id, owner, for_user="", for_group="",
                      size=0, for_channel="", whole_sha=""):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO blobs (id, owner, for_user,"
                " for_group, for_channel, whole_sha, size, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (blob_id, owner, for_user, for_group, for_channel,
                 whole_sha, size, now_ts()))
            self._db.commit()

    def find_blob_by_whole_sha(self, whole_sha, owner="", for_user="",
                               for_group="", for_channel=""):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM blobs WHERE whole_sha = ? AND owner = ?"
                " AND for_user = ? AND for_group = ? AND for_channel = ?"
                " ORDER BY created_at LIMIT 1",
                (whole_sha, owner, for_user, for_group, for_channel)).fetchone()
        return dict(row) if row else None

    def get_blob_meta(self, blob_id):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM blobs WHERE id = ?", (blob_id,)).fetchone()
        return dict(row) if row else None

    def delete_blob_meta(self, blob_id):
        with self._lock:
            self._db.execute("DELETE FROM blobs WHERE id = ?", (blob_id,))
            self._db.commit()

    def list_blob_meta(self):
        with self._lock:
            rows = self._db.execute("SELECT * FROM blobs ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # -- fleet alerts (point 37) --------------------------------------------------
    def open_alert(self, kind: str, subject: str, detail: str = "") -> dict:
        """One alert per incident: an already-open alert for the same
        kind+subject is returned, never duplicated."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM alerts WHERE kind = ? AND subject = ?"
                " AND status = 'open'", (kind, subject)).fetchone()
            if row is not None:
                return dict(row)
            aid = new_id("a-")[:14]
            self._db.execute(
                "INSERT INTO alerts (id, kind, subject, detail, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (aid, kind, subject, detail, now_ts()))
            self._db.commit()
            row = self._db.execute(
                "SELECT * FROM alerts WHERE id = ?", (aid,)).fetchone()
        return dict(row)

    def resolve_alerts(self, kind: str, subject: str) -> int:
        with self._lock:
            cur = self._db.execute(
                "UPDATE alerts SET status = 'resolved', resolved_at = ?"
                " WHERE kind = ? AND subject = ? AND status = 'open'",
                (now_ts(), kind, subject))
            self._db.commit()
        return cur.rowcount

    def bump_reminder(self, alert_id: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE alerts SET reminders = reminders + 1,"
                " last_reminder_at = ? WHERE id = ?",
                (now_ts(), alert_id))
            self._db.commit()

    def list_alerts(self, status: str | None = None,
                    limit: int = 100) -> list[dict]:
        with self._lock:
            if status:
                rows = self._db.execute(
                    "SELECT * FROM alerts WHERE status = ?"
                    " ORDER BY created_at DESC LIMIT ?",
                    (status, limit)).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM alerts ORDER BY created_at DESC"
                    " LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def oldest_urgent_queued(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT to_username, MIN(ts) AS since FROM queue"
                " WHERE priority >= 2 GROUP BY to_username").fetchall()
        return [dict(r) for r in rows]

    # -- delivery library (point 38a) ----------------------------------------------
    def add_library_entries(self, delivery_id: str, work: dict,
                            files: list[dict]) -> list[dict]:
        ids = []
        with self._lock:
            for f in files:
                lid = new_id("lib-")[:16]
                self._db.execute(
                    "INSERT INTO library (id, delivery_id, work_id,"
                    " filename, size, sha256, sender, to_user, group_id,"
                    " ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (lid, delivery_id, work["id"], f.get("name", ""),
                     int(f.get("size") or 0), f.get("sha256", ""),
                     work["assignee"], work["assigner"],
                     work["group_id"] or "", now_ts()))
                ids.append(lid)
            self._db.commit()
        if not ids:
            return []
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM library WHERE id IN (%s)"
                % ",".join("?" * len(ids)), tuple(ids)).fetchall()
        return [dict(r) for r in rows]

    def _library_visible(self, row: dict, requester: str) -> bool:
        if row["sender"] == requester or row["to_user"] == requester:
            return True
        if row.get("chain_next") and row["chain_next"] == requester:
            return True
        if row["group_id"]:
            return self.role_of(row["group_id"], requester) is not None
        return False

    def search_library(self, requester: str, q: str = "", sender: str = "",
                       group_id: str = "", hash_prefix: str = "",
                       limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM library ORDER BY ts DESC LIMIT 1000"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if not self._library_visible(d, requester):
                continue
            if q and q.lower() not in d["filename"].lower():
                continue
            if sender and d["sender"] != sender:
                continue
            if group_id and d["group_id"] != group_id:
                continue
            if hash_prefix and not d["sha256"].startswith(hash_prefix):
                continue
            out.append(d)
            if len(out) >= limit:
                break
        return out

    def library_entry(self, library_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM library WHERE id = ?",
                (library_id,)).fetchone()
        return dict(row) if row else None

    def library_all(self, limit: int = 200) -> list[dict]:
        """Operator (dashboard) view: all library metadata."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM library ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    # -- work chains (point 41) ---------------------------------------------------------
    def create_chain(self, creator: str, group_id: str, name: str,
                     steps: list[dict]) -> dict:
        cid = new_id("chain-")[:18]
        ts = now_ts()
        with self._lock:
            self._db.execute(
                "INSERT INTO chains (id, creator, group_id, name, status,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, 'running',"
                " ?, ?)", (cid, creator, group_id or "", name, ts, ts))
            for i, st in enumerate(steps):
                self._db.execute(
                    "INSERT INTO chain_steps (id, chain_id, position,"
                    " target_type, target, group_id, assignees, envelopes,"
                    " content_group, deadline, priority, status,"
                    " require_approval, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                    " 'pending', ?, ?)",
                    (new_id("step-")[:16], cid, i + 1,
                     st.get("target_type", "user"), st.get("target", ""),
                     st.get("group_id", "") or group_id or "",
                     json.dumps(st.get("assignees") or []),
                     json.dumps(st.get("envelopes") or {}),
                     json.dumps(st["content_group"])
                     if st.get("content_group") else "",
                     st.get("deadline"), st.get("priority", "normal"),
                     1 if st.get("require_approval") else 0, ts))
            self._db.commit()
        return self.get_chain(cid)

    def get_chain(self, chain_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM chains WHERE id = ?", (chain_id,)).fetchone()
            if row is None:
                return None
            srows = self._db.execute(
                "SELECT * FROM chain_steps WHERE chain_id = ?"
                " ORDER BY position", (chain_id,)).fetchall()
        chain = dict(row)
        steps = []
        for r in srows:
            d = dict(r)
            d["assignees"] = json.loads(d["assignees"] or "[]")
            d["envelopes"] = json.loads(d["envelopes"] or "{}")
            try:
                d["content_group"] = json.loads(d["content_group"]
                                                or "null")
            except Exception:
                d["content_group"] = None
            d["handoff"] = json.loads(d["handoff"] or "[]")
            steps.append(d)
        chain["steps"] = steps
        return chain

    def set_chain_status(self, chain_id: str, status: str) -> dict:
        with self._lock:
            paused = now_ts() if status == "paused" else 0
            self._db.execute(
                "UPDATE chains SET status = ?,"
                " paused_since = CASE WHEN ? = 'paused' THEN ?"
                " ELSE paused_since END, updated_at = ? WHERE id = ?",
                (status, status, paused, now_ts(), chain_id))
            self._db.commit()
        return self.get_chain(chain_id)

    def set_step_status(self, step_id: str, status: str,
                        work_id: str = "") -> None:
        with self._lock:
            if work_id:
                self._db.execute(
                    "UPDATE chain_steps SET status = ?, work_id = ?"
                    " WHERE id = ?", (status, work_id, step_id))
            else:
                self._db.execute(
                    "UPDATE chain_steps SET status = ? WHERE id = ?",
                    (status, step_id))
            self._db.commit()

    def set_step_handoff(self, step_id: str, handoff: list,
                         next_assignees: list[str]) -> None:
        """Attach step N's deliverables to step N+1 and extend library
        entitlement for those deliverables to the next assignees."""
        with self._lock:
            self._db.execute(
                "UPDATE chain_steps SET handoff = ? WHERE id = ?",
                (json.dumps(handoff), step_id))
            for entry in handoff:
                for nxt in next_assignees:
                    self._db.execute(
                        "UPDATE library SET chain_next = ? WHERE id = ?",
                        (nxt, entry.get("library_id", "")))
            self._db.commit()

    def library_for_work(self, work_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM library WHERE work_id = ? ORDER BY ts",
                (work_id,)).fetchall()
        return [dict(r) for r in rows]

    def groups_for_user(self, username: str) -> list[dict]:
        """Every group the user belongs to, with their membership row
        and the group settings — the reconnect resync source (43e)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT group_id FROM group_members WHERE username = ?",
                (username,)).fetchall()
        out = []
        for r in rows:
            g = self.get_group(r["group_id"])
            if g is None:
                continue
            members = self.members(g["id"])
            mine = next((m for m in members
                         if m["username"] == username), None)
            out.append({"group_id": g["id"], "name": g["name"],
                        "settings": g["settings"], "my": mine,
                        "members": members})
        return out

    def channels_for_user(self, username: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT channel_id, role FROM channel_members"
                " WHERE username = ?", (username,)).fetchall()
        out = []
        for r in rows:
            c = self.get_channel(r["channel_id"])
            if c:
                out.append({"channel_id": c["id"], "name": c["name"],
                            "my_role": r["role"]})
        return out

    def step_by_work(self, work_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM chain_steps WHERE work_id = ?",
                (work_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["assignees"] = json.loads(d["assignees"] or "[]")
        return d

    def list_chains_meta(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM chains ORDER BY updated_at DESC LIMIT ?",
                (limit,)).fetchall()
        out = []
        for r in rows:
            chain = self.get_chain(r["id"])
            for st in chain["steps"]:
                st.pop("envelopes", None)
                st.pop("content_group", None)
                if st.get("work_id"):
                    w = self.get_work(st["work_id"])
                    if w:
                        st["work_status"] = w["status"]
                        st["progress_percent"] = w.get(
                            "progress_percent", 0)
                        st["assignee"] = w["assignee"]
            out.append(chain)
        return out

    def chains_for_user(self, username: str) -> list[dict]:
        chains = self.list_chains_meta(200)
        out = []
        for c in chains:
            involved = {c["creator"]}
            for st in c["steps"]:
                involved.update(st.get("assignees") or [])
                if st.get("assignee"):
                    involved.add(st["assignee"])
            if username in involved:
                out.append(c)
        return out

    # -- group vault (point 38b) ------------------------------------------------------
    def vault_add(self, group_id: str, descriptor: dict, added_by: str,
                  pinned: bool = False) -> dict:
        vid = new_id("v-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO vault (id, group_id, name, size, sha256,"
                " blob_id, descriptor, added_by, pinned, ts)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (vid, group_id, descriptor.get("name", ""),
                 int(descriptor.get("size") or 0),
                 descriptor.get("sha256", ""),
                 descriptor.get("blob_id", ""), json.dumps(descriptor),
                 added_by, 1 if pinned else 0, now_ts()))
            self._db.commit()
            row = self._db.execute(
                "SELECT * FROM vault WHERE id = ?", (vid,)).fetchone()
        out = dict(row)
        out["descriptor"] = json.loads(out["descriptor"] or "{}")
        out["pinned"] = bool(out["pinned"])
        return out

    def vault_list(self, group_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM vault WHERE group_id = ?"
                " ORDER BY pinned DESC, ts DESC", (group_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["descriptor"] = json.loads(d["descriptor"] or "{}")
            d["pinned"] = bool(d["pinned"])
            out.append(d)
        return out

    def vault_entry(self, vault_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM vault WHERE id = ?", (vault_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["descriptor"] = json.loads(d["descriptor"] or "{}")
        d["pinned"] = bool(d["pinned"])
        return d

    def vault_set_pinned(self, vault_id: str, pinned: bool) -> dict | None:
        with self._lock:
            self._db.execute(
                "UPDATE vault SET pinned = ? WHERE id = ?",
                (1 if pinned else 0, vault_id))
            self._db.commit()
        return self.vault_entry(vault_id)

    def vault_remove(self, vault_id: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM vault WHERE id = ?", (vault_id,))
            self._db.commit()
        return cur.rowcount > 0

    def vault_meta(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id, group_id, name, size, sha256, added_by,"
                " pinned, ts FROM vault ORDER BY pinned DESC, ts DESC"
                " LIMIT 500").fetchall()
        return [dict(r) for r in rows]

    # -- dashboard sessions (trusted devices, 7-day) -------------------------
    def create_session(self, token_hash: str, expires_at: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO dashboard_sessions (token_hash, created_at,"
                " expires_at) VALUES (?, ?, ?)",
                (token_hash, now_ts(), expires_at))
            self._db.commit()

    def session_valid(self, token_hash: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT expires_at FROM dashboard_sessions"
                " WHERE token_hash = ?", (token_hash,)).fetchone()
        return bool(row) and row["expires_at"] >= now_ts()

    def revoke_session(self, token_hash: str) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM dashboard_sessions WHERE token_hash = ?",
                (token_hash,))
            self._db.commit()

    # -- append-only metadata audit log ---------------------------------------
    def audit(self, kind: str, actor: str, target: str = "",
              group_id: str = "", work_id: str = "", status: str = "",
              priority: str = "", size: int = 0, mentions=None,
              ref_id: str = "", sender_nickname: str = "",
              sender_role: str = "", sender_custom_role: str = "",
              oversight: str = "", content_envelope: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit_log (ts, kind, actor, target, group_id,"
                " work_id, status, priority, size, mentions, ref_id,"
                " sender_nickname, sender_role, sender_custom_role,"
                " oversight, content_envelope)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now_ts(), kind, actor, target, group_id, work_id, status,
                 priority, int(size or 0), json.dumps(mentions or []),
                 ref_id, sender_nickname or "", sender_role or "",
                 sender_custom_role or "", oversight or "",
                 content_envelope or ""))
            self._db.commit()

    def list_audit(self, limit: int = 300) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                'SELECT ts, kind, actor AS "from", target AS "to",'
                " group_id, work_id, status, priority, size, mentions,"
                " ref_id, sender_nickname, sender_role, sender_custom_role,"
                " oversight, content_envelope"
                " FROM audit_log"
                " ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["mentions"] = json.loads(d.get("mentions") or "[]")
                except Exception:
                    d["mentions"] = []
                try:
                    d["oversight"] = json.loads(d.get("oversight") or "null")
                except Exception:
                    d["oversight"] = None
                try:
                    d["content_envelope"] = json.loads(
                        d.get("content_envelope") or "null")
                except Exception:
                    d["content_envelope"] = None
                out.append(d)
            return out
        return [dict(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- users -----------------------------------------------------------
    def claim(self, username: str, display_name: str, pubkey: str = "",
              sign_pub: str = "", capabilities=None,
              cap_desc: str = "") -> str:
        secret = new_secret()
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO users (username, secret, display_name, pubkey,"
                    " sign_pub, capabilities, cap_desc, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    # Only the SHA-256 hash is stored — the relay DB never
                    # holds a usable secret.
                    (username, _hash_token(secret), display_name, pubkey,
                     sign_pub, json.dumps(capabilities or []), cap_desc,
                     now_ts()),
                )
                self._db.commit()
            except sqlite3.IntegrityError:
                raise UsernameTaken(username)
        return secret

    def pubkey_of(self, username: str) -> str:
        with self._lock:
            row = self._db.execute(
                "SELECT pubkey FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row["pubkey"] if row else ""

    def set_pubkey(self, username: str, pubkey: str) -> None:
        if not pubkey:
            return
        with self._lock:
            self._db.execute(
                "UPDATE users SET pubkey = ? WHERE username = ?",
                (pubkey, username))
            self._db.commit()

    def touch(self, username: str) -> None:
        """Heartbeat-derived presence, backend-wide (point 29: 'dead'
        means no heartbeat ANYWHERE, on any relay sharing the backend)."""
        with self._lock:
            self._db.execute(
                "UPDATE users SET last_seen = ? WHERE username = ?",
                (now_ts(), username))
            self._db.commit()

    def last_seen_of(self, username: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT last_seen FROM users WHERE username = ?",
                (username,)).fetchone()
        return int(row["last_seen"]) if row else 0

    def set_capabilities(self, username: str, capabilities,
                         cap_desc: str = "") -> None:
        with self._lock:
            self._db.execute(
                "UPDATE users SET capabilities = ?, cap_desc = ?"
                " WHERE username = ?",
                (json.dumps(capabilities or []), cap_desc, username))
            self._db.commit()

    def sign_pub_of(self, username: str) -> str:
        with self._lock:
            row = self._db.execute(
                "SELECT sign_pub FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row["sign_pub"] if row else ""

    def set_sign_pub(self, username: str, sign_pub: str) -> None:
        if not sign_pub:
            return
        with self._lock:
            self._db.execute(
                "UPDATE users SET sign_pub = ? WHERE username = ?",
                (sign_pub, username))
            self._db.commit()

    def verify(self, username: str, secret: str | None) -> bool:
        if not secret:
            return False
        with self._lock:
            row = self._db.execute(
                "SELECT secret FROM users WHERE username = ?", (username,)
            ).fetchone()
        return bool(row) and row["secret"] == _hash_token(secret)

    def exists(self, username: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row is not None

    def set_display_name(self, username: str, display_name: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE users SET display_name = ? WHERE username = ?",
                (display_name, username),
            )
            self._db.commit()

    def list_users(self, query: str = "", capability: str = "") -> list[dict]:
        with self._lock:
            if query:
                rows = self._db.execute(
                    "SELECT username, display_name, pubkey, sign_pub,"
                    " capabilities, cap_desc, last_seen, created_at"
                    " FROM users"
                    " WHERE username LIKE ? ORDER BY username",
                    (f"%{query}%",),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT username, display_name, pubkey, sign_pub,"
                    " capabilities, cap_desc, last_seen, created_at"
                    " FROM users ORDER BY username"
                ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["capabilities"] = json.loads(d.get("capabilities")
                                                   or "[]")
                except Exception:
                    d["capabilities"] = []
                if capability and capability.lower() not in \
                        [c.lower() for c in d["capabilities"]]:
                    continue
                out.append(d)
            return out

    # -- offline queue ----------------------------------------------------
    def enqueue(self, to_username: str, payload: dict) -> None:
        weight = PRIORITY_WEIGHT.get(str(payload.get("priority") or "normal"), 0)
        with self._lock:
            self._db.execute(
                "INSERT INTO queue (to_username, payload, priority, ts)"
                " VALUES (?, ?, ?, ?)",
                (to_username, json.dumps(payload), weight, now_ts()),
            )
            self._db.commit()

    def dequeue_all(self, to_username: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM queue WHERE to_username = ?"
                " ORDER BY priority DESC, seq ASC",
                (to_username,),
            ).fetchall()
            self._db.execute("DELETE FROM queue WHERE to_username = ?", (to_username,))
            self._db.commit()
        out = []
        for r in rows:
            frame = json.loads(r["payload"])
            frame["queued"] = True
            out.append(frame)
        return out

    # -- groups ------------------------------------------------------------
    def create_group(self, name: str, creator: str, settings: dict | None) -> str:
        gid = new_id("g-")[:14]
        merged = dict(DEFAULT_SETTINGS)
        if settings:
            for k in DEFAULT_SETTINGS:
                if k in settings:
                    merged[k] = settings[k]
        with self._lock:
            self._db.execute(
                "INSERT INTO groups (id, name, creator, settings, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (gid, name, creator, json.dumps(merged), now_ts()),
            )
            self._db.commit()
        self.add_member(gid, creator, role="superadmin", added_by=creator)
        return gid

    def get_group(self, group_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM groups WHERE id = ?", (group_id,)
            ).fetchone()
        if row is None:
            return None
        g = dict(row)
        g["settings"] = json.loads(g["settings"])
        return g

    def set_settings(self, group_id: str, settings: dict) -> dict:
        g = self.get_group(group_id)
        if g is None:
            raise NotFound(group_id)
        merged = dict(g["settings"])
        for k in DEFAULT_SETTINGS:
            if k in settings:
                merged[k] = settings[k]
        with self._lock:
            self._db.execute(
                "UPDATE groups SET settings = ? WHERE id = ?",
                (json.dumps(merged), group_id),
            )
            self._db.commit()
        return merged

    def add_member(self, group_id: str, username: str, role: str = "member",
                   added_by: str = "") -> bool:
        with self._lock:
            existing = self._db.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND username = ?",
                (group_id, username)).fetchone()
            if existing:
                return False
            count = self._db.execute(
                "SELECT COUNT(*) AS n FROM group_members WHERE group_id = ?",
                (group_id,)).fetchone()["n"]
            if count >= MAX_GROUP_MEMBERS:
                raise GroupFull(group_id)
            cur = self._db.execute(
                "INSERT OR IGNORE INTO group_members"
                " (group_id, username, role, added_by, joined_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (group_id, username, role, added_by, now_ts()),
            )
            self._db.commit()
        return cur.rowcount > 0

    def remove_member(self, group_id: str, username: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM group_members WHERE group_id = ? AND username = ?",
                (group_id, username),
            )
            self._db.execute(
                "DELETE FROM group_keys WHERE group_id = ? AND username = ?",
                (group_id, username))
            self._db.commit()
        return cur.rowcount > 0

    def set_nickname(self, group_id: str, username: str, nickname: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE group_members SET nickname = ?"
                " WHERE group_id = ? AND username = ?",
                (nickname[:48], group_id, username))
            self._db.commit()

    def set_custom_role(self, group_id: str, username: str, custom_role: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE group_members SET custom_role = ?"
                " WHERE group_id = ? AND username = ?",
                (custom_role[:48], group_id, username))
            self._db.commit()

    # -- group keys (wrapped ciphertext only; relay cannot unwrap) ---------
    def set_group_key(self, group_id: str, username: str, epoch: int,
                      wrapped: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO group_keys (group_id, username, epoch, wrapped)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT(group_id, username) DO UPDATE SET"
                " epoch = excluded.epoch, wrapped = excluded.wrapped",
                (group_id, username, epoch, json.dumps(wrapped)))
            self._db.commit()

    def group_key_for(self, group_id: str, username: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT epoch, wrapped FROM group_keys"
                " WHERE group_id = ? AND username = ?",
                (group_id, username)).fetchone()
        if row is None:
            return None
        return {"epoch": row["epoch"], "wrapped": json.loads(row["wrapped"])}

    def group_key_epoch(self, group_id: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COALESCE(MAX(epoch), 0) AS e FROM group_keys"
                " WHERE group_id = ?", (group_id,)).fetchone()
        return int(row["e"])

    def set_role(self, group_id: str, username: str, role: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE group_members SET role = ?"
                " WHERE group_id = ? AND username = ?",
                (role, group_id, username),
            )
            self._db.commit()

    def role_of(self, group_id: str, username: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT role FROM group_members"
                " WHERE group_id = ? AND username = ?",
                (group_id, username),
            ).fetchone()
        return row["role"] if row else None

    def members(self, group_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT username, role, nickname, custom_role, added_by,"
                " joined_at FROM group_members"
                " WHERE group_id = ? ORDER BY joined_at",
                (group_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def all_groups(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT g.id, g.name, g.creator, g.created_at,"
                " (SELECT COUNT(*) FROM group_members m"
                "  WHERE m.group_id = g.id) AS member_count"
                " FROM groups g ORDER BY g.created_at").fetchall()
        return [dict(r) for r in rows]

    # -- invites -------------------------------------------------------------
    def create_invite(self, group_id: str, created_by: str,
                      ttl_seconds: int = INVITE_TTL_SECONDS) -> str:
        """Canonical shape (Supabase al_invites): the row stores the
        token's SHA-256 AS the token column plus created_at; validity
        is created_at + INVITE_TTL_SECONDS >= now. created_at is
        shifted by (ttl - INVITE_TTL) so a custom ttl_seconds keeps
        its exact meaning."""
        token = secrets.token_urlsafe(24)
        created_at = now_ts() + int(ttl_seconds) - INVITE_TTL_SECONDS
        with self._lock:
            self._db.execute(
                "INSERT INTO invites (token, group_id, created_by,"
                " created_at) VALUES (?, ?, ?, ?)",
                (_hash_token(token), group_id, created_by, created_at),
            )
            self._db.commit()
        return token

    def invite_valid(self, group_id: str, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            row = self._db.execute(
                "SELECT created_at FROM invites WHERE token = ?"
                " AND group_id = ?",
                (_hash_token(token), group_id),
            ).fetchone()
        return bool(row) and \
            row["created_at"] + INVITE_TTL_SECONDS >= now_ts()

    @staticmethod
    def invite_link(group_id: str, token: str) -> str:
        return f"agentlink://join/{group_id}?token={token}"

    @staticmethod
    def parse_invite_link(link: str) -> tuple[str, str] | None:
        # agentlink://join/<group_id>?token=<token>
        try:
            rest = link.split("join/", 1)[1]
            gid, _, qs = rest.partition("?")
            token = qs.split("token=", 1)[1].split("&")[0]
            return gid, token
        except (IndexError, AttributeError):
            return None

    # -- work ------------------------------------------------------------------
    def create_work(self, assigner: str, assignee: str, group_id: str | None,
                    content_enc: dict, content_self: dict,
                    deadline: int | None, batch_id: str | None = None,
                    priority: str = "normal", auto_reassign: bool = True,
                    assignee_role: str = "",
                    content_group: dict | None = None,
                    chain_id: str = "", chain_step: int = 0,
                    require_approval: bool = False) -> dict:
        wid = new_id("w-")[:14]
        ts = now_ts()
        with self._lock:
            self._db.execute(
                "INSERT INTO work (id, assigner, assignee, group_id,"
                " content_enc, content_self, content_group, batch_id,"
                " chain_id, chain_step,"
                " priority, auto_reassign, assignee_role, deadline,"
                " require_approval, status, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                " 'assigned', ?, ?)",
                (wid, assigner, assignee, group_id, json.dumps(content_enc),
                 json.dumps(content_self),
                 json.dumps(content_group) if content_group else "",
                 batch_id, chain_id, chain_step, priority,
                 1 if auto_reassign else 0,
                 assignee_role, deadline, 1 if require_approval else 0,
                 ts, ts),
            )
            self._db.commit()
        return self.get_work(wid)

    # -- state machine (point 32: no skipping states, fail-closed) ------------
    WORK_TRANSITIONS = {
        "assigned": {"in_progress", "delivered", "awaiting_approval",
                     "covered", "awaiting_agent"},
        "in_progress": {"delivered", "awaiting_approval", "covered",
                        "awaiting_agent"},
        "changes_requested": {"in_progress", "delivered",
                              "awaiting_approval", "covered",
                              "awaiting_agent"},
        "delivered": {"completed", "changes_requested"},
        # Approval gate (v1.1.0): a proven delivery on gated work parks
        # here until the assigner (or a group admin) decides.
        "awaiting_approval": {"completed", "changes_requested"},
        "awaiting_agent": {"assigned"},
        "covered": set(),
        "completed": set(),
    }

    def set_checkpoint(self, work_id: str, attempt: int, by_user: str,
                       content_assigner: dict | None,
                       content_group: dict | None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO work_checkpoints (work_id, attempt, by_user,"
                " content_assigner, content_group, ts)"
                " VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(work_id) DO UPDATE SET"
                " attempt = excluded.attempt, by_user = excluded.by_user,"
                " content_assigner = excluded.content_assigner,"
                " content_group = excluded.content_group,"
                " ts = excluded.ts",
                (work_id, attempt, by_user,
                 json.dumps(content_assigner) if content_assigner else "",
                 json.dumps(content_group) if content_group else "",
                 now_ts()))
            self._db.commit()

    def get_checkpoint(self, work_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM work_checkpoints WHERE work_id = ?",
                (work_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        for k in ("content_assigner", "content_group"):
            try:
                d[k] = json.loads(d[k]) if d[k] else None
            except Exception:
                d[k] = None
        return d

    def reassign_work(self, work_id: str, new_assignee: str) -> dict:
        """Dead-agent reassignment: attempt increments (dedup key is
        work_id + attempt), progress resets, status returns to
        'assigned' for the replacement."""
        with self._lock:
            self._db.execute(
                "UPDATE work SET assignee = ?, attempt = attempt + 1,"
                " status = 'assigned', progress_percent = 0,"
                " updated_at = ? WHERE id = ?",
                (new_assignee, now_ts(), work_id))
            self._db.commit()
        return self.get_work(work_id)

    def set_awaiting_agent(self, work_id: str) -> dict:
        with self._lock:
            self._db.execute(
                "UPDATE work SET status = 'awaiting_agent', updated_at = ?"
                " WHERE id = ?", (now_ts(), work_id))
            self._db.commit()
        return self.get_work(work_id)

    def open_work(self, statuses=("assigned", "in_progress")) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id FROM work WHERE status IN (%s)"
                % ",".join("?" * len(statuses)), tuple(statuses)).fetchall()
        return [self.get_work(r["id"]) for r in rows]

    def set_work_progress(self, work_id: str, percent: int) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT status FROM work WHERE id = ?", (work_id,)).fetchone()
            if row is None:
                raise NotFound(work_id)
            status = row["status"]
            if status == "assigned":
                status = "in_progress"
            self._db.execute(
                "UPDATE work SET progress_percent = ?, progress_at = ?,"
                " status = ?, updated_at = ? WHERE id = ?",
                (percent, now_ts(), status, now_ts(), work_id))
            self._db.commit()
        return self.get_work(work_id)

    def cover_batch(self, batch_id: str, delivered_work_id: str) -> list[dict]:
        """Role assignment: one delivery satisfies the batch — every
        other open copy in the batch closes as 'covered'."""
        if not batch_id:
            return []
        with self._lock:
            rows = self._db.execute(
                "SELECT id FROM work WHERE batch_id = ? AND id != ?"
                " AND status IN ('assigned', 'in_progress',"
                " 'changes_requested')",
                (batch_id, delivered_work_id)).fetchall()
            ids = [r["id"] for r in rows]
            for wid in ids:
                self._db.execute(
                    "UPDATE work SET status = 'covered', updated_at = ?"
                    " WHERE id = ?", (now_ts(), wid))
            self._db.commit()
        return [self.get_work(wid) for wid in ids]

    def resolve_role(self, group_id: str, role_name: str) -> list[str]:
        """Usernames of group members holding a custom role (case-insensitive)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT username FROM group_members WHERE group_id = ?"
                " AND LOWER(custom_role) = LOWER(?) ORDER BY joined_at",
                (group_id, role_name)).fetchall()
        return [r["username"] for r in rows]

    # -- trust score ---------------------------------------------------------
    def compute_trust(self, username: str) -> int:
        """Server-computed trust, 0-100, from REAL work history only.

        Formula (documented in README; messages never count):
          start 50 (neutral)
          +4 per completed assignment (as assignee)
          +1 per delivered assignment
          -6 per changes-requested round against the assignee
          -6 per missed deadline (deadline passed while not completed,
             or completed after the deadline)
          -10 per invalid signed-delivery proof
          clamped to [0, 100].
        """
        with self._lock:
            rows = self._db.execute(
                "SELECT status, deadline, updated_at FROM work"
                " WHERE assignee = ?", (username,)).fetchall()
            changes = self._db.execute(
                "SELECT COUNT(*) AS n FROM audit_log WHERE kind ="
                " 'work_changes_requested' AND target = ?",
                (username,)).fetchone()["n"]
            bad_proofs = self._db.execute(
                "SELECT COUNT(*) AS n FROM audit_log WHERE kind ="
                " 'delivery_proof_verified' AND actor = ? AND status ="
                " 'false'", (username,)).fetchone()["n"]
        score = 50
        now = now_ts()
        for r in rows:
            if r["status"] in ("completed", "covered"):
                score += 4
            elif r["status"] in ("delivered", "awaiting_approval"):
                score += 1
            if r["deadline"]:
                if r["status"] == "completed" and                         r["updated_at"] > r["deadline"]:
                    score -= 6
                elif r["status"] not in ("completed", "covered",
                                         "delivered", "awaiting_approval") \
                        and now > r["deadline"]:
                    score -= 6
        score -= 6 * changes
        score -= 10 * bad_proofs
        return max(0, min(100, score))

    def get_work(self, work_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM work WHERE id = ?", (work_id,)
            ).fetchone()
            deliveries = []
            if row is not None:
                drows = self._db.execute(
                    "SELECT * FROM work_deliveries WHERE work_id = ? ORDER BY ts",
                    (work_id,),
                ).fetchall()
                deliveries = [
                    {**dict(d),
                     "content_enc": json.loads(d["content_enc"] or "{}"),
                     "content_self": json.loads(d["content_self"] or "{}"),
                     "content_group": json.loads(d["content_group"]
                                                 or "null"),
                     "content_next": json.loads(d["content_next"]
                                                or "null")
                     if "content_next" in d.keys() else None}
                    for d in drows
                ]
        if row is None:
            return None
        w = dict(row)
        w["content_enc"] = json.loads(w["content_enc"] or "{}")
        w["content_self"] = json.loads(w["content_self"] or "{}")
        try:
            w["content_group"] = json.loads(w["content_group"] or "null")
        except Exception:
            w["content_group"] = None
        w["deliveries"] = deliveries
        cp = self.get_checkpoint(work_id)
        if cp is not None:
            w["checkpoint"] = cp
        return w

    def list_work_meta(self) -> list[dict]:
        """Metadata only (parties, status, times) — for the dashboard."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, assigner, assignee, group_id, status, priority,"
                " batch_id, progress_percent, progress_at, proof_verified,"
                " proof_hash, deadline, chain_id, chain_step, attempt,"
                " require_approval, created_at, updated_at FROM work"
                " ORDER BY updated_at DESC LIMIT 200").fetchall()
        return [dict(r) for r in rows]

    # -- channels (broadcast: admins post, subscribers read) -------------------
    def create_channel(self, name: str, creator: str) -> str:
        cid = new_id("c-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO channels (id, name, creator, created_at)"
                " VALUES (?, ?, ?, ?)", (cid, name, creator, now_ts()))
            self._db.commit()
        self.add_subscriber(cid, creator, role="superadmin", added_by=creator)
        return cid

    def get_channel(self, channel_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM channels WHERE id = ?",
                (channel_id,)).fetchone()
        return dict(row) if row else None

    def add_subscriber(self, channel_id: str, username: str,
                       role: str = "subscriber", added_by: str = "") -> bool:
        with self._lock:
            existing = self._db.execute(
                "SELECT 1 FROM channel_members WHERE channel_id = ?"
                " AND username = ?", (channel_id, username)).fetchone()
            if existing:
                return False
            count = self._db.execute(
                "SELECT COUNT(*) AS n FROM channel_members"
                " WHERE channel_id = ?", (channel_id,)).fetchone()["n"]
            if count >= MAX_CHANNEL_SUBSCRIBERS:
                raise GroupFull(channel_id)
            cur = self._db.execute(
                "INSERT OR IGNORE INTO channel_members (channel_id,"
                " username, role, added_by, joined_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (channel_id, username, role, added_by, now_ts()))
            self._db.commit()
        return cur.rowcount > 0

    def remove_subscriber(self, channel_id: str, username: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM channel_members WHERE channel_id = ?"
                " AND username = ?", (channel_id, username))
            self._db.execute(
                "DELETE FROM channel_keys WHERE channel_id = ?"
                " AND username = ?", (channel_id, username))
            self._db.commit()
        return cur.rowcount > 0

    def channel_role_of(self, channel_id: str, username: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT role FROM channel_members WHERE channel_id = ?"
                " AND username = ?", (channel_id, username)).fetchone()
        return row["role"] if row else None

    def set_channel_role(self, channel_id: str, username: str,
                         role: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE channel_members SET role = ? WHERE channel_id = ?"
                " AND username = ?", (role, channel_id, username))
            self._db.commit()

    def channel_members(self, channel_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT username, role, added_by, joined_at"
                " FROM channel_members WHERE channel_id = ?"
                " ORDER BY joined_at", (channel_id,)).fetchall()
        return [dict(r) for r in rows]

    def all_channels(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT c.id, c.name, c.creator, c.created_at,"
                " (SELECT COUNT(*) FROM channel_members m"
                "  WHERE m.channel_id = c.id) AS member_count"
                " FROM channels c ORDER BY c.created_at").fetchall()
        return [dict(r) for r in rows]

    def set_channel_key(self, channel_id: str, username: str, epoch: int,
                        wrapped: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO channel_keys (channel_id, username, epoch,"
                " wrapped) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(channel_id, username) DO UPDATE SET"
                " epoch = excluded.epoch, wrapped = excluded.wrapped",
                (channel_id, username, epoch, json.dumps(wrapped)))
            self._db.commit()

    def channel_key_for(self, channel_id: str, username: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT epoch, wrapped FROM channel_keys"
                " WHERE channel_id = ? AND username = ?",
                (channel_id, username)).fetchone()
        if row is None:
            return None
        return {"epoch": row["epoch"], "wrapped": json.loads(row["wrapped"])}

    # -- chunked upload sessions -------------------------------------------------
    def create_upload_session(self, owner: str, whole_sha: str, ct_sha: str,
                              size: int, chunk_size: int, for_user: str = "",
                              for_group: str = "",
                              for_channel: str = "") -> str:
        sid = new_id("u-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO upload_sessions (session_id, owner, for_user,"
                " for_group, whole_sha, ct_sha, size,"
                " chunk_size, chunks, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', ?)",
                (sid, owner, for_user, for_group, whole_sha,
                 ct_sha, size, chunk_size, now_ts()))
            self._db.commit()
        return sid

    def get_upload_session(self, session_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM upload_sessions WHERE session_id = ?",
                (session_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["chunks"] = json.loads(d["chunks"])
        # Canonical sessions carry no channel scope (v1.1.0); the key
        # stays present (empty) so relay consumers keep a stable shape.
        # The relay asserts channel scope from the finish frame.
        d.setdefault("for_channel", "")
        return d

    def record_chunk(self, session_id: str, index: int) -> list[int]:
        sess = self.get_upload_session(session_id)
        if sess is None:
            raise NotFound(session_id)
        chunks = sorted(set(sess["chunks"]) | {index})
        with self._lock:
            self._db.execute(
                "UPDATE upload_sessions SET chunks = ? WHERE session_id = ?",
                (json.dumps(chunks), session_id))
            self._db.commit()
        return chunks

    def delete_upload_session(self, session_id: str) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM upload_sessions WHERE session_id = ?",
                (session_id,))
            self._db.commit()

    def escalate_work_priority(self, work_id: str) -> dict:
        with self._lock:
            self._db.execute(
                "UPDATE work SET priority = 'urgent', updated_at = ?"
                " WHERE id = ?", (now_ts(), work_id))
            self._db.commit()
        return self.get_work(work_id)

    def set_work_status(self, work_id: str, status: str) -> dict:
        current = self.get_work(work_id)
        if current is None:
            raise NotFound(work_id)
        allowed = self.WORK_TRANSITIONS.get(current["status"], set())
        if status != current["status"] and status not in allowed:
            raise InvalidTransition(
                f"{current['status']} -> {status} is not a legal"
                " transition (states cannot be skipped)")
        with self._lock:
            self._db.execute(
                "UPDATE work SET status = ?, updated_at = ? WHERE id = ?",
                (status, now_ts(), work_id),
            )
            self._db.commit()
        return self.get_work(work_id)

    def add_delivery(self, work_id: str, deliverer: str, content_enc: dict,
                     content_self: dict, proof: dict | None = None,
                     content_group: dict | None = None,
                     content_next: dict | None = None) -> dict:
        did = new_id("d-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO work_deliveries (id, work_id, deliverer,"
                " content_enc, content_self, content_group, content_next,"
                " ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (did, work_id, deliverer, json.dumps(content_enc),
                 json.dumps(content_self),
                 json.dumps(content_group) if content_group else "",
                 json.dumps(content_next) if content_next else "",
                 now_ts()),
            )
            if proof:
                self._db.execute(
                    "UPDATE work SET proof_hash = ?, proof_ts = ?,"
                    " proof_sig = ?, proof_verified = ? WHERE id = ?",
                    (proof.get("hash", ""), int(proof.get("ts") or 0),
                     proof.get("sig", ""),
                     1 if proof.get("verified") else 0, work_id))
            self._db.commit()
        with self._lock:
            row = self._db.execute(
                "SELECT require_approval FROM work WHERE id = ?",
                (work_id,)).fetchone()
        gated = bool(row and row["require_approval"])
        self.set_work_status(
            work_id, "awaiting_approval" if gated else "delivered")
        return self.get_work(work_id)

    def list_work(self, username: str, status: str | None = None,
                  group_id: str | None = None) -> list[dict]:
        """Work where the user is assignee OR assigner."""
        q = ("SELECT id FROM work WHERE (assignee = ? OR assigner = ?)")
        args: list = [username, username]
        if status:
            q += " AND status = ?"
            args.append(status)
        if group_id:
            q += " AND group_id = ?"
            args.append(group_id)
        q += " ORDER BY created_at"
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [self.get_work(r["id"]) for r in rows]
