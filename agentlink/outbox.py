"""Persistent send outbox (2.0.10, class B).

A send that meets a dead network window used to fail in the
caller's hands: group sends timed out and were lost from the
sender's own journal (beulah, 2026-11-06 23:13–23:24 — three
sends vanished, then a wedged outbound path needed a daemon
restart), and phoenix's daemon died silently inside a proxy
desync window. The doctrine this module carries:

* A send is DURABLE before it is attempted. The fully-built,
  fully-sealed frame is journaled here (JSON, atomic replace,
  mode 600 — the same discipline as the pending-reads journal);
  the frame carries its client-generated id, and the server
  honours that id, so a replay can never double-post.
* The caller gets an honest immediate answer: ``queued`` with
  the frame's id. Delivery state then matures through the
  delivery view (class D) — queued is a state, not a loss.
* A background flusher retries due entries with exponential
  backoff. Entries survive daemon restarts; a proxy window can
  delay a send, never lose it.

Only TRANSPORT failures queue. A server refusal is a verdict
about the send itself and propagates to the caller unchanged.

2.3.0 BOUND (the retry-discipline law): "delay, never lose"
gained its other half — a flush entry gets at most
:data:`MAX_FLUSH_ATTEMPTS` delivery attempts (5, the client's one
retry policy). An entry that exhausts them is PARKED
(status "parked"): it leaves the due set forever, stays in the
journal as the durable record, and the flusher hands it to the
dead-letter park so the failure is operator-visible. The
~7,863-retry storm of 2026-11-07 is what an unbounded version of
this loop does to a poison entry; the bound is the fix. (The
5s-doubling retry SCHEDULE below is unchanged — it spaces the
attempts the policy allows.)
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .retry import DEFAULT_MAX_ATTEMPTS

#: Backoff between flush attempts of one entry: 5s doubling,
#: capped at 5 minutes. A proxy rotation window is seconds to a
#: few minutes; the cap keeps the allowed attempts well-spaced.
FLUSH_INTERVAL_BASE_S = 5
FLUSH_INTERVAL_CAP_S = 300

#: The flush attempt budget (2.3.0): the shared client retry
#: policy's cap, applied to outbox entries. Attempt number
#: MAX_FLUSH_ATTEMPTS failing parks the entry.
MAX_FLUSH_ATTEMPTS = DEFAULT_MAX_ATTEMPTS


class Outbox:
    """The durable outbox journal: ``outbox-<username>.json`` in
    the agent's state dir, mapping frame id -> entry."""

    def __init__(self, path):
        self.path = Path(path)
        self._entries: dict[str, dict] = {}
        self._load()

    # -- persistence ------------------------------------------------
    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return
        except Exception:
            return
        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and value.get("frame"):
                    self._entries[str(key)] = value

    def _save(self) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._entries))
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- operations ---------------------------------------------------
    def add(self, frame: dict) -> dict:
        """Journal ``frame`` for delivery (idempotent by frame
        id: re-adding a live entry returns it unchanged)."""
        fid = str(frame.get("id") or "")
        if not fid:
            raise ValueError("outbox frames must carry a client id")
        existing = self._entries.get(fid)
        if existing is not None and existing.get("status") == "pending":
            return existing
        entry = {"id": fid, "frame": frame, "ts": int(time.time()),
                 "attempts": 0, "next_ts": 0, "status": "pending",
                 "last_error": ""}
        self._entries[fid] = entry
        self._save()
        return entry

    def get(self, frame_id: str) -> dict | None:
        return self._entries.get(str(frame_id))

    def pending(self) -> list[dict]:
        return [e for e in self._entries.values()
                if e.get("status") == "pending"]

    def parked(self) -> list[dict]:
        """Entries that exhausted the attempt budget (2.3.0):
        out of the retry set forever, kept as the record."""
        return [e for e in self._entries.values()
                if e.get("status") == "parked"]

    def due(self, now: int | None = None) -> list[dict]:
        now = int(time.time()) if now is None else now
        return [e for e in self.pending()
                if int(e.get("next_ts") or 0) <= now]

    def mark_sent(self, frame_id: str) -> None:
        if self._entries.pop(str(frame_id), None) is not None:
            self._save()

    def mark_failed(self, frame_id: str, error: str = "") -> dict | None:
        entry = self._entries.get(str(frame_id))
        if entry is None:
            return None
        entry["attempts"] = int(entry.get("attempts") or 0) + 1
        entry["last_error"] = str(error)[:200]
        if entry["attempts"] >= MAX_FLUSH_ATTEMPTS:
            # The budget is spent (2.3.0): park — never due again,
            # never deleted; the flusher dead-letters it.
            entry["status"] = "parked"
            entry["next_ts"] = 0
            self._save()
            return entry
        wait = min(FLUSH_INTERVAL_CAP_S,
                   FLUSH_INTERVAL_BASE_S * (2 ** min(entry["attempts"] - 1, 6)))
        entry["next_ts"] = int(time.time()) + wait
        self._save()
        return entry

    def __len__(self) -> int:
        return len(self.pending())
