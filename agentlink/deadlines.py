"""Deadlines — ONE canonical clock: Pacific Time (point 36).

The owner's strict rule: every deadline in AgentLink is Pacific Time
(America/Los_Angeles). A deadline given without a timezone is Pacific
by definition — there is no other interpretation anywhere in the
system. Storage is the exact epoch instant derived from that Pacific
wall-clock; every envelope carries BOTH the epoch and the Pacific
display string WITH its UTC offset (e.g. ``2026-11-05 17:00 PT
(UTC-7)``) so no agent on any host timezone can misread it. Rendering
a deadline in a viewer's local zone is forbidden.
"""

from __future__ import annotations

import re
from datetime import datetime
from zoneinfo import ZoneInfo

PACIFIC = ZoneInfo("America/Los_Angeles")

_ISO_NAIVE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$")


def parse_deadline(value) -> int:
    """Parse a deadline into an epoch instant.

    Accepts: an epoch int/float (returned as-is), a naive ISO string
    (``2026-11-05 17:00`` — interpreted as Pacific wall-clock), or an
    offset-aware ISO string (converted to the same instant).
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)
    s = str(value).strip()
    if s.isdigit():
        return int(s)
    m = _ISO_NAIVE.match(s)
    if m:
        y, mo, d, h, mi, sec = (int(x) if x else 0 for x in m.groups())
        dt = datetime(y, mo, d, h, mi, sec, tzinfo=PACIFIC)
        return int(dt.timestamp())
    dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=PACIFIC)
    return int(dt.timestamp())


def pacific_display(epoch: int | None) -> str:
    """'2026-11-05 17:00 PT (UTC-7)' — always Pacific, always with the
    UTC offset, regardless of the host's local timezone."""
    if not epoch:
        return ""
    dt = datetime.fromtimestamp(int(epoch), tz=PACIFIC)
    offset = dt.utcoffset()
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    hours, minutes = divmod(total_minutes, 60)
    off = f"UTC{sign}{hours}" + (f":{minutes:02d}" if minutes else "")
    return f"{dt:%Y-%m-%d %H:%M} PT ({off})"


def pressure_thresholds(created_at: int, deadline: int) -> dict:
    """Warning points for the deadline-pressure engine (point 36).

    Defaults: warn at 50% of the window elapsed, and at 1 hour
    remaining. For short windows (< 2h) the '1 hour remaining' point
    scales to 75% elapsed so tests and short tasks still get both
    warnings. All comparisons are against epoch instants — timezone
    can never shift them.
    """
    window = max(1, int(deadline) - int(created_at))
    warn_50 = int(created_at) + window // 2
    if window <= 2 * 3600:
        warn_late = int(created_at) + (3 * window) // 4
    else:
        warn_late = int(deadline) - 3600
    return {"window": window, "warn_50_at": warn_50,
            "warn_late_at": warn_late}
