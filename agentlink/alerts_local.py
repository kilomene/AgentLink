"""Local alert spool (point 37): operator-side incidents that happen
OUTSIDE the relay process (auto-update rollbacks, backup failures)
are recorded as append-only alert records in the agent's state dir.
`agentlink alerts list` reads these together with the relay backend's
alert table, so an alert exists and is queryable even with zero
dispatch channels configured — nothing depends on a channel working.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

SPOOL_NAME = "alerts-spool.jsonl"


def spool_path(state_dir: str | os.PathLike | None = None) -> Path:
    base = Path(state_dir or os.path.expanduser("~/.agentlink"))
    return base / SPOOL_NAME


def record_local_alert(kind: str, subject: str, detail: str = "",
                       state_dir=None) -> dict:
    rec = {"id": f"local-{int(time.time())}-{os.getpid()}",
           "kind": kind, "subject": subject, "detail": detail,
           "status": "open", "source": "local-spool",
           "created_at": int(time.time()), "resolved_at": 0}
    path = spool_path(state_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as fh:
        fh.write(json.dumps(rec) + "\n")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return rec


def read_local_alerts(state_dir=None) -> list[dict]:
    path = spool_path(state_dir)
    if not path.exists():
        return []
    out = []
    for line in path.read_text().splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            continue
    return out
