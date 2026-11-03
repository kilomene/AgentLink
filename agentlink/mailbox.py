"""The canonical local mailbox (v1.3.7).

Before v1.3.7 an inbound message lived only in the client process's
memory (``Agent.messages``): a receiving process could flush its
queue, mark items read, and die — and the item never reached the
store the agent's own intelligence reads. Work assignments already
had a durable local journal (``TaskJournal``); messages had nothing.

The mailbox is that missing journal — ONE canonical SQLite store in
the agent's state dir (``<state_dir>/mailbox.db``), written with the
same permissions discipline as the work journal (state dir 0700,
file 0600, commit per write, a lock for thread safety). The delivery
contract built on top of it:

* an inbound item is journaled BEFORE it is processed, and only
  then acked to the relay (``{"type": "ack", "ids": [...]}``) — the
  relay releases custody of its queued copy on ack, so delivery is
  not complete until the item is durable here;
* an item is marked *taken* at the exact moment the agent's
  intelligence takes it in (registered handler invocation, or the
  autonomous runtime's decision-backed read) — the same points that
  have always produced read receipts, now backed by this journal;
* journaled-but-not-taken items replay to the intelligence on the
  next start, oldest first, exactly once;
* the relay's history (audit) backfills this same store, so an
  agent's local history is complete even for items that predated
  the mailbox or arrived while a different process held the line.
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from pathlib import Path


class Mailbox:
    """SQLite-backed durable mailbox for one agent.

    ``owner`` is the agent's username: it decides which items are
    inbound (everything not sent by the owner) and resolves the DM
    conversation filter. Item dicts are stored verbatim — the exact
    msg dict the client builds for handlers — under their message
    id; the relational columns are only an index over that dict.
    """

    def __init__(self, path: Path | str, owner: str = ""):
        self.path = Path(path).expanduser()
        self.owner = owner or ""
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path),
                                   check_same_thread=False)
        with self._lock:
            self._db.execute(
                "CREATE TABLE IF NOT EXISTS items ("
                " id TEXT PRIMARY KEY, ts INTEGER, kind TEXT,"
                " from_user TEXT, to_user TEXT, group_id TEXT,"
                " channel_id TEXT, msg TEXT NOT NULL DEFAULT '{}',"
                " taken INTEGER NOT NULL DEFAULT 0,"
                " journaled_at INTEGER NOT NULL DEFAULT 0)")
            self._db.commit()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- writes ------------------------------------------------------

    def put_if_absent(self, item: dict, taken: bool | None = None) -> bool:
        """Journal ``item`` if its id is new. Returns True when the
        item was newly inserted (the caller then owns first-sight
        duties: ack, dispatch), False when it was already journaled
        (a duplicate delivery — never reprocess).

        ``taken`` defaults from direction: the owner's own sent
        items are complete the moment they are sent (taken=1);
        inbound items start untaken (taken=0) until the agent's
        intelligence actually takes them in."""
        mid = item.get("id") if isinstance(item, dict) else None
        if not mid:
            return False
        if taken is None:
            taken = bool(self.owner and item.get("from") == self.owner)
        with self._lock:
            cur = self._db.execute(
                "INSERT OR IGNORE INTO items (id, ts, kind, from_user,"
                " to_user, group_id, channel_id, msg, taken,"
                " journaled_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (str(mid), int(item.get("ts") or item.get("time") or 0),
                 str(item.get("kind") or "text"),
                 item.get("from"), item.get("to"),
                 item.get("group_id"), item.get("channel_id"),
                 json.dumps(item, default=str), 1 if taken else 0,
                 int(time.time())))
            self._db.commit()
            return cur.rowcount > 0

    def replace_msg(self, item: dict) -> bool:
        """Replace the stored msg dict for an existing id, keeping
        its taken flag and journal time. Used when a sealed history
        stub (journaled because its row could not be decrypted) is
        superseded by the real, decrypted item arriving live."""
        mid = item.get("id") if isinstance(item, dict) else None
        if not mid:
            return False
        with self._lock:
            cur = self._db.execute(
                "UPDATE items SET ts = ?, kind = ?, from_user = ?,"
                " to_user = ?, group_id = ?, channel_id = ?, msg = ?"
                " WHERE id = ?",
                (int(item.get("ts") or item.get("time") or 0),
                 str(item.get("kind") or "text"),
                 item.get("from"), item.get("to"),
                 item.get("group_id"), item.get("channel_id"),
                 json.dumps(item, default=str), str(mid)))
            self._db.commit()
            return cur.rowcount > 0

    def mark_taken(self, ids) -> None:
        """Mark items taken in by the agent's intelligence."""
        if isinstance(ids, str):
            ids = [ids]
        ids = [str(i) for i in (ids or []) if i]
        if not ids:
            return
        with self._lock:
            self._db.executemany(
                "UPDATE items SET taken = 1 WHERE id = ?",
                [(i,) for i in ids])
            self._db.commit()

    # -- reads ---------------------------------------------------------

    def get(self, item_id: str) -> dict | None:
        """The stored msg dict for ``item_id``, or None."""
        with self._lock:
            row = self._db.execute(
                "SELECT msg FROM items WHERE id = ?",
                (str(item_id),)).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row[0])
        except Exception:
            return None

    def taken_of(self, item_id: str) -> bool | None:
        """The taken flag for ``item_id`` (None when absent)."""
        with self._lock:
            row = self._db.execute(
                "SELECT taken FROM items WHERE id = ?",
                (str(item_id),)).fetchone()
        return None if row is None else bool(row[0])

    def pending_takein(self) -> list[dict]:
        """Journaled items the intelligence has NOT taken in yet,
        oldest first — the replay set for the next start. Inbound
        items only: the owner's own sent items are born taken, and
        work records (kind="work") are excluded — the TaskJournal /
        work-resume path is the work system of record, so a work
        first-sight record here must never replay as a message."""
        with self._lock:
            rows = self._db.execute(
                "SELECT msg FROM items WHERE taken = 0"
                " AND kind != 'work'"
                " AND (from_user IS NULL OR from_user != ?)"
                " ORDER BY ts ASC, journaled_at ASC",
                (self.owner,)).fetchall()
        out = []
        for r in rows:
            try:
                out.append(json.loads(r[0]))
            except Exception:
                continue
        return out

    def list_items(self, limit: int = 50, before_ts: int | None = None,
                   conversation: str | None = None,
                   unread_only: bool = False) -> list[dict]:
        """Full rows ({"msg", "taken", "journaled_at"}), newest
        first. ``conversation`` is a peer username (that DM, both
        directions), ``"group:<id>"`` or ``"channel:<id>"``;
        ``before_ts`` pages strictly older items; ``unread_only``
        keeps only not-taken-in items."""
        sql = "SELECT msg, taken, journaled_at FROM items WHERE 1 = 1"
        args: list = []
        if unread_only:
            sql += " AND taken = 0"
        if before_ts is not None:
            sql += " AND ts < ?"
            args.append(int(before_ts))
        if conversation:
            conv = str(conversation)
            if conv.startswith("group:"):
                sql += " AND group_id = ?"
                args.append(conv[len("group:"):])
            elif conv.startswith("channel:"):
                sql += " AND channel_id = ?"
                args.append(conv[len("channel:"):])
            else:
                sql += (" AND ((from_user = ? AND to_user = ?)"
                        " OR (from_user = ? AND to_user = ?))")
                args.extend([conv, self.owner, self.owner, conv])
        sql += " ORDER BY ts DESC, journaled_at DESC LIMIT ?"
        args.append(max(0, int(limit)))
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
        out = []
        for msg_json, taken, journaled_at in rows:
            try:
                msg = json.loads(msg_json)
            except Exception:
                continue
            out.append({"msg": msg, "taken": bool(taken),
                        "journaled_at": int(journaled_at or 0)})
        return out

    def inbox(self, limit: int = 50, before_ts: int | None = None,
              conversation: str | None = None,
              unread_only: bool = False) -> list[dict]:
        """The stored msg dicts, newest first (see list_items)."""
        return [r["msg"] for r in self.list_items(
            limit=limit, before_ts=before_ts, conversation=conversation,
            unread_only=unread_only)]

    def count(self) -> int:
        with self._lock:
            row = self._db.execute("SELECT COUNT(*) FROM items").fetchone()
        return int(row[0]) if row else 0

    def flush(self) -> None:
        """Force any pending write to disk (every write already
        commits; this is the pre-update belt pin, mirroring
        TaskJournal.flush)."""
        with self._lock:
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            try:
                self._db.close()
            except Exception:
                pass
