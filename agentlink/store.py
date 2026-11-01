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


class UsernameTaken(Exception):
    pass


class NotFound(Exception):
    pass


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        with self._lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    secret TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
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
                    added_by TEXT NOT NULL DEFAULT '',
                    joined_at INTEGER NOT NULL,
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
                    title TEXT NOT NULL,
                    instructions TEXT NOT NULL DEFAULT '',
                    attachments TEXT NOT NULL DEFAULT '[]',
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
                    body TEXT NOT NULL DEFAULT '',
                    files TEXT NOT NULL DEFAULT '[]',
                    ts INTEGER NOT NULL
                );
                """
            )
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- users -----------------------------------------------------------
    def claim(self, username: str, display_name: str) -> str:
        secret = new_secret()
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO users (username, secret, display_name, created_at)"
                    " VALUES (?, ?, ?, ?)",
                    (username, secret, display_name, now_ts()),
                )
                self._db.commit()
            except sqlite3.IntegrityError:
                raise UsernameTaken(username)
        return secret

    def verify(self, username: str, secret: str | None) -> bool:
        if not secret:
            return False
        with self._lock:
            row = self._db.execute(
                "SELECT secret FROM users WHERE username = ?", (username,)
            ).fetchone()
        return bool(row) and row["secret"] == secret

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
                    "SELECT username, display_name, created_at FROM users"
                    " WHERE username LIKE ? ORDER BY username",
                    (f"%{query}%",),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT username, display_name, created_at FROM users"
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
            self._db.commit()
        return cur.rowcount > 0

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
                "SELECT username, role, added_by, joined_at FROM group_members"
                " WHERE group_id = ? ORDER BY joined_at",
                (group_id,),
            ).fetchall()
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
                    title: str, instructions: str, attachments: list,
                    deadline: int | None) -> dict:
        wid = new_id("w-")[:14]
        ts = now_ts()
        with self._lock:
            self._db.execute(
                "INSERT INTO work (id, assigner, assignee, group_id, title,"
                " instructions, attachments, deadline, status, created_at,"
                " updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'assigned', ?, ?)",
                (wid, assigner, assignee, group_id, title, instructions,
                 json.dumps(attachments), deadline, ts, ts),
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
                    {**dict(d), "files": json.loads(d["files"])} for d in drows
                ]
        if row is None:
            return None
        w = dict(row)
        w["attachments"] = json.loads(w["attachments"])
        w["deliveries"] = deliveries
        return w

    def set_work_status(self, work_id: str, status: str) -> dict:
        with self._lock:
            self._db.execute(
                "UPDATE work SET status = ?, updated_at = ? WHERE id = ?",
                (status, now_ts(), work_id),
            )
            self._db.commit()
        return self.get_work(work_id)

    def add_delivery(self, work_id: str, deliverer: str, body: str,
                     files: list) -> dict:
        did = new_id("d-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO work_deliveries (id, work_id, deliverer, body,"
                " files, ts) VALUES (?, ?, ?, ?, ?, ?)",
                (did, work_id, deliverer, body, json.dumps(files), now_ts()),
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
