"""Conversation census — the immortality gate (v1.3.2).

Owner's law (2026-11-02): NO update, fix, restart, migration or
cleanup may EVER cause a conversation, group, channel or message to
disappear. A lost conversation takes the projects inside it with it.

The census is the measurable form of that law: the set of
conversation keys with their per-conversation item-id sets, plus
the group/channel id sets — computed from the
STORE (the audit log's content rows + the group/channel tables),
never from any windowed view. Two censuses can be diffed; the diff
names exactly what a loss would be.

The gate is wired into the paths where loss historically hides:

* relay startup runs :meth:`CensusGuard.verify` against a durable
  baseline file kept beside the relay's state (outside the code
  directory, so updates never touch it). The baseline only ever
  GROWS (union). A boot that finds baseline content missing from
  the store opens a ``census_loss`` alert + audit row and logs at
  ERROR — loudly, never silently — then re-baselines so one loss
  produces one alert, not one per boot.
* the updater accepts an optional guard: census before the swap,
  census after the health check; any loss rolls the update back
  and fails it (see updater.py).
* ``agentlink census`` exposes the same computation to any
  migration/cleanup tooling: snapshot before, verify after.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path


def conversation_key(row: dict) -> str:
    """The dashboard's conversation key for one content audit row —
    the same derivation Relay._conversations uses."""
    if row.get("group_id"):
        return "group:" + row["group_id"]
    pair = sorted(x for x in (row.get("from"), row.get("to")) if x)
    return "dm:" + "|".join(pair)


def compute_census(store) -> dict:
    """The full census of a store: every conversation that exists,
    every item id in it, and the group/channel id sets. (Membership
    rosters are deliberately NOT censused: members joining/leaving
    is ordinary product life — what the law protects is the
    EXISTENCE of conversations, groups, channels and messages.)"""
    convs: dict[str, set] = {}
    for r in store.list_content_audit():
        item_id = r.get("ref_id") or r.get("work_id") or ""
        if not item_id:
            continue
        convs.setdefault(conversation_key(r), set()).add(item_id)
    return {
        "conversations": {k: sorted(v) for k, v in sorted(convs.items())},
        "groups": sorted(g["id"] for g in store.all_groups()),
        "channels": sorted(c["id"] for c in store.all_channels()),
    }


def census_digest(census: dict) -> str:
    return hashlib.sha256(json.dumps(
        census, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def census_summary(census: dict) -> dict:
    return {
        "conversations": len(census.get("conversations", {})),
        "items": sum(len(v)
                     for v in census.get("conversations", {}).values()),
        "groups": len(census.get("groups", [])),
        "channels": len(census.get("channels", [])),
        "digest": census_digest(census),
    }


def _set_losses(before_map: dict, after_map: dict) -> dict:
    """{key: [values present in before but gone from after]} for a
    {key: [values]} map; wholly-missing keys report all values."""
    out = {}
    for key, values in before_map.items():
        after_values = set(after_map.get(key, []))
        gone = [v for v in values if v not in after_values]
        if gone:
            out[key] = gone
    return out


def diff_census(before: dict, after: dict) -> dict:
    """LOSSES ONLY: what exists in ``before`` but not in ``after``.
    Additions are not losses and never appear here."""
    return {
        "conversations_missing": sorted(
            k for k in before.get("conversations", {})
            if k not in after.get("conversations", {})),
        "items_missing": _set_losses(before.get("conversations", {}),
                                     after.get("conversations", {})),
        "groups_missing": sorted(
            g for g in before.get("groups", [])
            if g not in after.get("groups", [])),
        "channels_missing": sorted(
            c for c in before.get("channels", [])
            if c not in after.get("channels", [])),
    }


def losses_found(diff: dict) -> bool:
    return any(diff.get(k) for k in (
        "conversations_missing", "items_missing", "groups_missing",
        "channels_missing"))


def describe_losses(diff: dict) -> str:
    parts = []
    if diff.get("conversations_missing"):
        parts.append("conversations gone: "
                     + ", ".join(diff["conversations_missing"][:5]))
    lost_items = {k: v for k, v in diff.get("items_missing", {}).items()
                  if k not in diff.get("conversations_missing", [])}
    if lost_items:
        parts.append("items gone: " + "; ".join(
            f"{k} (-{len(v)})" for k, v in list(lost_items.items())[:5]))
    if diff.get("groups_missing"):
        parts.append("groups gone: "
                     + ", ".join(diff["groups_missing"][:5]))
    if diff.get("channels_missing"):
        parts.append("channels gone: "
                     + ", ".join(diff["channels_missing"][:5]))
    return " | ".join(parts) or "no losses"


def merge_census(a: dict, b: dict) -> dict:
    """Union of two censuses — a baseline may only ever grow."""
    convs = {}
    for k in sorted(set(a.get("conversations", {}))
                    | set(b.get("conversations", {}))):
        convs[k] = sorted(set(a.get("conversations", {}).get(k, []))
                          | set(b.get("conversations", {}).get(k, [])))
    return {
        "conversations": convs,
        "groups": sorted(set(a.get("groups", []))
                         | set(b.get("groups", []))),
        "channels": sorted(set(a.get("channels", []))
                           | set(b.get("channels", []))),
    }


class CensusLossError(Exception):
    """Raised when a census comparison finds lost content."""

    def __init__(self, diff: dict):
        self.diff = diff
        super().__init__("conversation census loss: "
                         + describe_losses(diff))


def alert_loss(store, diff: dict) -> None:
    """The loud part of the gate: an alert row on the fleet-alerts
    surface + an audit row, so the loss is on the record forever.
    Best-effort by design — a store that cannot record the alert
    must not swallow the raise that follows."""
    detail = describe_losses(diff)
    try:
        store.open_alert("census_loss", "conversation-census", detail)
    except Exception:
        pass
    try:
        store.audit("census_loss_detected", "system",
                    status=detail[:200])
    except Exception:
        pass


class CensusGuard:
    """Before/after census enforcement around one store, with a
    durable baseline file. Used by the relay boot gate, the updater,
    and the ``agentlink census`` tooling."""

    def __init__(self, store, baseline_path):
        self.store = store
        self.baseline_path = Path(baseline_path).expanduser()

    def compute(self) -> dict:
        return compute_census(self.store)

    def load_baseline(self) -> dict | None:
        try:
            data = json.loads(self.baseline_path.read_text())
            census = data.get("census")
            return census if isinstance(census, dict) else None
        except Exception:
            return None

    def save_baseline(self, census: dict) -> None:
        self.baseline_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "digest": census_digest(census),
                   "census": census}
        tmp = self.baseline_path.with_suffix(
            self.baseline_path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=1, sort_keys=True))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.baseline_path)

    def snapshot(self) -> dict:
        """Take the baseline now (the BEFORE of a guarded
        operation) and return the census."""
        census = self.compute()
        self.save_baseline(census)
        return census

    def accept_current(self) -> dict:
        """Re-baseline to what the store holds NOW. Called only
        after a loss has been surfaced loudly (alert + audit), so a
        known loss alerts once rather than on every check."""
        return self.snapshot()

    def verify(self) -> dict:
        """Compare the store against the durable baseline.

        * No baseline yet: adopt the current census (protection
          starts now) — returns {"status": "adopted"}.
        * Losses vs baseline: alert loudly and raise
          CensusLossError. The baseline is NOT advanced.
        * No losses: the baseline unions forward to include any
          additions — returns {"status": "ok"}."""
        current = self.compute()
        baseline = self.load_baseline()
        if baseline is None:
            self.save_baseline(current)
            return {"status": "adopted",
                    **census_summary(current)}
        diff = diff_census(baseline, current)
        if losses_found(diff):
            alert_loss(self.store, diff)
            raise CensusLossError(diff)
        merged = merge_census(baseline, current)
        if merged != baseline:
            self.save_baseline(merged)
        return {"status": "ok", **census_summary(current)}
