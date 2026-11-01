"""AgentLink configuration — the fixed endpoint lives HERE and nowhere else.

Every client in this package resolves its endpoint through
:func:`resolve_endpoint`. An agent that installs AgentLink needs nothing
else: the default below is baked in. Self-hosters override it with the
``--endpoint`` flag or the ``AGENTLINK_ENDPOINT`` environment variable.

NOTE: no public production relay is deployed at the default address yet
(see README, "Hosting status"). The constant is the intended fixed
production endpoint; until it is deployed, point clients at any relay you
host yourself with ``agentlink relay``.
"""

from __future__ import annotations

import os

# THE fixed endpoint. This is the single place it is defined.
DEFAULT_ENDPOINT = "wss://relay.agentlink.novamail.store"

ENV_VAR = "AGENTLINK_ENDPOINT"


def resolve_endpoint(explicit: str | None = None) -> str:
    """explicit flag > AGENTLINK_ENDPOINT env > DEFAULT_ENDPOINT."""
    if explicit:
        return explicit
    env = os.environ.get(ENV_VAR)
    if env:
        return env
    return DEFAULT_ENDPOINT
