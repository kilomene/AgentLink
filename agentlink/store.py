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
}

MAX_GROUP_MEMBERS = 50


class UsernameTaken(Exception):
    pass


class GroupFull(Exception):
    pass


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
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS queue (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    to_username TEXT NOT NULL,
                    payload TEXT NOT NULL,
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
                    token_hash TEXT PRIMARY KEY,
                    group_id TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS work (
                    id TEXT PRIMARY KEY,
                    assigner TEXT NOT NULL,
                    assignee TEXT NOT NULL,
                    group_id TEXT,
                    content_enc TEXT NOT NULL DEFAULT '',
                    content_self TEXT NOT NULL DEFAULT '',
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
                    ts INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS blobs (
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    for_user TEXT NOT NULL DEFAULT '',
                    for_group TEXT NOT NULL DEFAULT '',
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
                    status TEXT NOT NULL DEFAULT ''
                );
                """
            )
            self._db.commit()

    # -- blob metadata (ciphertext lives in the blob store) ----------------
    def put_blob_meta(self, blob_id, owner, for_user="", for_group="",
                      size=0):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO blobs (id, owner, for_user,"
                " for_group, size, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (blob_id, owner, for_user, for_group, size, now_ts()))
            self._db.commit()

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
              group_id: str = "", work_id: str = "", status: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit_log (ts, kind, actor, target, group_id,"
                " work_id, status) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (now_ts(), kind, actor, target, group_id, work_id, status))
            self._db.commit()

    def list_audit(self, limit: int = 300) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                'SELECT ts, kind, actor AS "from", target AS "to",'
                " group_id, work_id, status FROM audit_log"
                " ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- users -----------------------------------------------------------
    def claim(self, username: str, display_name: str, pubkey: str = "") -> str:
        secret = new_secret()
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO users (username, secret, display_name, pubkey,"
                    " created_at) VALUES (?, ?, ?, ?, ?)",
                    # Only the SHA-256 hash is stored — the relay DB never
                    # holds a usable secret.
                    (username, _hash_token(secret), display_name, pubkey,
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

    def list_users(self, query: str = "") -> list[dict]:
        with self._lock:
            if query:
                rows = self._db.execute(
                    "SELECT username, display_name, pubkey, created_at FROM users"
                    " WHERE username LIKE ? ORDER BY username",
                    (f"%{query}%",),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT username, display_name, pubkey, created_at FROM users"
                    " ORDER BY username"
                ).fetchall()
        return [dict(r) for r in rows]

    # -- offline queue ----------------------------------------------------
    def enqueue(self, to_username: str, payload: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO queue (to_username, payload, ts) VALUES (?, ?, ?)",
                (to_username, json.dumps(payload), now_ts()),
            )
            self._db.commit()

    def dequeue_all(self, to_username: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM queue WHERE to_username = ? ORDER BY seq",
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
                      ttl_seconds: int = 7 * 24 * 3600) -> str:
        token = secrets.token_urlsafe(24)
        with self._lock:
            self._db.execute(
                "INSERT INTO invites (token_hash, group_id, created_by, expires_at)"
                " VALUES (?, ?, ?, ?)",
                (_hash_token(token), group_id, created_by, now_ts() + ttl_seconds),
            )
            self._db.commit()
        return token

    def invite_valid(self, group_id: str, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            row = self._db.execute(
                "SELECT expires_at FROM invites WHERE token_hash = ? AND group_id = ?",
                (_hash_token(token), group_id),
            ).fetchone()
        return bool(row) and row["expires_at"] >= now_ts()

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
                    deadline: int | None) -> dict:
        wid = new_id("w-")[:14]
        ts = now_ts()
        with self._lock:
            self._db.execute(
                "INSERT INTO work (id, assigner, assignee, group_id,"
                " content_enc, content_self, deadline, status, created_at,"
                " updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, 'assigned', ?, ?)",
                (wid, assigner, assignee, group_id, json.dumps(content_enc),
                 json.dumps(content_self), deadline, ts, ts),
            )
            self._db.commit()
        return self.get_work(wid)

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
                     "content_self": json.loads(d["content_self"] or "{}")}
                    for d in drows
                ]
        if row is None:
            return None
        w = dict(row)
        w["content_enc"] = json.loads(w["content_enc"] or "{}")
        w["content_self"] = json.loads(w["content_self"] or "{}")
        w["deliveries"] = deliveries
        return w

    def list_work_meta(self) -> list[dict]:
        """Metadata only (parties, status, times) — for the dashboard."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, assigner, assignee, group_id, status,"
                " created_at, updated_at FROM work ORDER BY updated_at DESC"
                " LIMIT 200").fetchall()
        return [dict(r) for r in rows]

    def set_work_status(self, work_id: str, status: str) -> dict:
        with self._lock:
            self._db.execute(
                "UPDATE work SET status = ?, updated_at = ? WHERE id = ?",
                (status, now_ts(), work_id),
            )
            self._db.commit()
        return self.get_work(work_id)

    def add_delivery(self, work_id: str, deliverer: str, content_enc: dict,
                     content_self: dict) -> dict:
        did = new_id("d-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO work_deliveries (id, work_id, deliverer,"
                " content_enc, content_self, ts) VALUES (?, ?, ?, ?, ?, ?)",
                (did, work_id, deliverer, json.dumps(content_enc),
                 json.dumps(content_self), now_ts()),
            )
            self._db.commit()
        self.set_work_status(work_id, "delivered")
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
