"""Retry discipline for the AgentLink client (2.3.0).

Before 2.3.0, retry policy lived wherever a loop happened to be:
the outbox flushed forever, custody acks retried on the next
signal, and one production agent retried a single poison delivery
~7,863 times — a retry storm that burned both metered Supabase
budgets (egress + log ingestion) and helped restrict the whole
organization (2026-11-08). The ratified split architecture makes
retry discipline ONE policy, applied everywhere a delivery is
retried:

* **Hard cap.** A delivery gets at most ``max_attempts`` attempts
  (default 5). There is no code path that retries a delivery
  unboundedly. (The signal-stream supervisor is not a delivery —
  it is a connection, and it keeps its own reconnect-forever
  contract with a bounded backoff cap.)
* **Exponential backoff.** Waits double from ``base_delay_s``,
  capped at ``max_delay_s``, with jitter — derived from the
  attempt count, so the schedule is a pure function tests can pin.
* **Dead-letter park.** An item that exhausts the cap is PARKED,
  never dropped and never retried again: the park writes a JSONL
  record (what, to whom, how many attempts, the last error, when)
  to the park file and keeps an in-memory list the daemon surfaces
  in diagnostics. A parked item is an operator-visible fact, not
  a silent disappearance — custody rows in Supabase are NEVER
  deleted by parking; the park governs the CLIENT's retrying.

This module is deliberately transport-free: it knows nothing of
Supabase or Firebase, only attempts, delays and parking.
"""

from __future__ import annotations

import json
import random
import threading
import time

__all__ = [
    "DEFAULT_MAX_ATTEMPTS",
    "RetryPolicy",
    "DeadLetterPark",
]

#: The one delivery-retry budget for the whole client (2.3.0).
DEFAULT_MAX_ATTEMPTS = 5


class RetryPolicy:
    """Attempt counting + backoff schedule for one delivery class.

    ``delay_for(attempt)`` is the wait BEFORE retry number
    ``attempt + 1`` (attempt is 0-based: the first failure waits
    ``delay_for(0)``). ``exhausted(attempts)`` is the cap test —
    a delivery that has been attempted ``max_attempts`` times is
    done, forever.
    """

    def __init__(self, max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 base_delay_s: float = 1.0, max_delay_s: float = 60.0,
                 jitter: bool = True):
        self.max_attempts = max(1, int(max_attempts))
        self.base_delay_s = float(base_delay_s)
        self.max_delay_s = float(max_delay_s)
        self.jitter = bool(jitter)

    def exhausted(self, attempts: int) -> bool:
        """True when a delivery attempted ``attempts`` times has
        used its whole budget and must park."""
        return int(attempts) >= self.max_attempts

    def delay_for(self, attempt: int) -> float:
        """Backoff before the next retry after ``attempt``
        failures (0-based): base, 2x, 4x, ... capped, jittered
        into [0.5x, 1.0x] of the nominal wait when jitter is on."""
        attempt = max(0, int(attempt))
        nominal = min(self.max_delay_s,
                      self.base_delay_s * (2 ** attempt))
        if self.jitter:
            return nominal * (0.5 + random.random() * 0.5)
        return nominal


class DeadLetterPark:
    """Where exhausted deliveries go to be SEEN, not retried.

    Records are dicts: {kind, item_id, to, attempts, last_error,
    parked_at, detail}. The park keeps them in memory (the daemon
    surfaces them via diagnostics) and, when a path is given,
    appends each record as one JSON line to the park file
    (<state_dir>/dead-letter.jsonl) so a restart never loses the
    fact that something parked. Writes are fail-soft: a park file
    that cannot be written never crashes a delivery path — the
    in-memory record still stands.
    """

    def __init__(self, path: str = ""):
        self.path = str(path or "")
        self._records: list[dict] = []
        self._lock = threading.Lock()

    def park(self, kind: str, item_id: str, *, to: str = "",
             attempts: int = 0, last_error: str = "",
             detail: dict | None = None) -> dict:
        """Park one exhausted delivery and return its record."""
        record = {
            "kind": str(kind), "item_id": str(item_id),
            "to": str(to or ""), "attempts": int(attempts or 0),
            "last_error": str(last_error or ""),
            "parked_at": int(time.time()),
            "detail": detail or {},
        }
        with self._lock:
            self._records.append(record)
            if self.path:
                try:
                    with open(self.path, "a", encoding="utf-8") as fh:
                        fh.write(json.dumps(record) + "\n")
                except OSError:
                    pass
        return record

    def records(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._records]

    def __len__(self) -> int:
        with self._lock:
            return len(self._records)
