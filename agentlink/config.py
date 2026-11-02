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
OVERSIGHT_PUBKEY_ENV_VAR = "AGENTLINK_OVERSIGHT_PUBKEY"
SELF_UPDATE_ENV_VAR = "AGENTLINK_SELF_UPDATE"
UPDATE_CHECK_SECONDS_ENV_VAR = "AGENTLINK_UPDATE_CHECK_SECONDS"


def self_update_enabled() -> bool:
    """In-daemon self-update (v1.1.8): the running agent checks for
    updates ITSELF, inside its own serve loop — no host cron, systemd
    timer or any other host facility is involved, so an agent on a
    cron-less sandbox still keeps itself current. Default ON; an
    operator (or a test suite) disables it with
    ``AGENTLINK_SELF_UPDATE=0`` (also off/false/no)."""
    v = os.environ.get(SELF_UPDATE_ENV_VAR)
    if v is None:
        return True
    return v.strip().lower() not in ("0", "off", "false", "no", "")


def resolve_update_check_seconds() -> float:
    """Interval between in-daemon self-update checks. The law lives
    in ``timing.UPDATE_CHECK_SECONDS`` (15 minutes); the
    ``AGENTLINK_UPDATE_CHECK_SECONDS`` env var is an operator/test
    override (staged demos and hostile-environment proofs shorten
    it) and never changes the shipped default."""
    from .timing import UPDATE_CHECK_SECONDS
    raw = os.environ.get(UPDATE_CHECK_SECONDS_ENV_VAR)
    if raw:
        try:
            seconds = float(raw)
        except ValueError:
            seconds = 0.0
        if seconds > 0:
            return seconds
    return float(UPDATE_CHECK_SECONDS)


def resolve_oversight_pubkey(explicit: str | None = None) -> str:
    """Owner-oversight public key (base64 X25519) for this client.

    Precedence: explicit argument > AGENTLINK_OVERSIGHT_PUBKEY env >
    the relay-advertised value from the welcome frame (the Agent
    adopts that one itself at connect time when nothing is configured
    locally — the env is the override). Returns "" when no oversight
    key is configured: the client then sends no oversight wrap."""
    if explicit:
        return explicit
    return os.environ.get(OVERSIGHT_PUBKEY_ENV_VAR) or ""


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
