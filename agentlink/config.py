"""AgentLink configuration — the fixed endpoint lives HERE and nowhere else.

Every client in this package resolves its endpoint through
:func:`resolve_endpoint`. An agent that installs AgentLink needs nothing
else: the default below is baked in. Self-hosters override it with the
``--endpoint`` flag or the ``AGENTLINK_ENDPOINT`` environment variable.

FIXED PRODUCTION ENDPOINT (owner-given 2026-11-01): x.novamail.store
    relay     wss://x.novamail.store/ws
    dashboard https://x.novamail.store
At deploy time x.novamail.store gets its OWN individual Cloudflare DNS
record (never a *.novamail.store wildcard route) pointing at the relay
host, with a TLS reverse proxy routing /ws to the relay websocket port
and / to the dashboard port. That DNS/proxy step is a deployment action
for the operator — changing the endpoint here is never needed again.
"""

from __future__ import annotations

import os

# THE fixed endpoint. This is the single place it is defined.
DEFAULT_ENDPOINT = "wss://x.novamail.store/ws"
DASHBOARD_URL = "https://x.novamail.store"

ENV_VAR = "AGENTLINK_ENDPOINT"
FALLBACK_ENV_VAR = "AGENTLINK_FALLBACK_ENDPOINTS"


def resolve_endpoint(explicit: str | None = None) -> str:
    """explicit flag > AGENTLINK_ENDPOINT env > DEFAULT_ENDPOINT."""
    if explicit:
        return explicit
    env = os.environ.get(ENV_VAR)
    if env:
        return env
    return DEFAULT_ENDPOINT


def resolve_fallbacks(explicit: list[str] | None = None) -> list[str]:
    """Failover endpoints, in order. The home endpoint always comes
    first (see resolve_endpoint); these are only ridden while home is
    unavailable."""
    if explicit:
        return list(explicit)
    env = os.environ.get(FALLBACK_ENV_VAR)
    if env:
        return [e.strip() for e in env.split(",") if e.strip()]
    return []
