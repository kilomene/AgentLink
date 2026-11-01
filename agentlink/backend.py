"""Backend selection for the AgentLink relay.

Data-layer adapter pattern — one store interface, two backends with
identical semantics:

* ``sqlite``   — local SQLite file. Dev/test default, fully verified.
* ``supabase`` — Supabase Postgres (production). Shared by every relay,
  which is what makes failover lossless. Needs SUPABASE_URL and
  SUPABASE_SERVICE_KEY in the relay operator's environment, and the
  schema in deploy/supabase-schema.sql applied to the project.

Select with AGENTLINK_BACKEND or ``agentlink relay --backend``.
"""

from __future__ import annotations

import os

from .store import Store


def create_store(kind: str | None = None, db_path: str = "~/.agentlink/relay.db",
                 supabase_url: str | None = None,
                 supabase_key: str | None = None):
    kind = (kind or os.environ.get("AGENTLINK_BACKEND") or "sqlite").lower()
    if kind == "sqlite":
        return Store(db_path)
    if kind == "supabase":
        from .supabase_store import SupabaseStore
        return SupabaseStore(
            supabase_url or os.environ.get("SUPABASE_URL", ""),
            supabase_key or os.environ.get("SUPABASE_SERVICE_KEY", ""))
    raise ValueError(f"unknown backend {kind!r} (use sqlite|supabase)")
