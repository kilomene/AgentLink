"""The connector bridge (v1.8.1, owner's corrected grant model).

WHAT A CONNECTOR IS (owner's words, 2026-11-04): a connector is
constituted by OAuth — a connector exists in an agent's world
because the agent's USER completed an OAuth authorization to
that service. The agent's connector inventory is therefore its
CONNECTOR VAULT: the set of OAuth-linked services the user has
connected on that agent's side, each with the OAuth scopes the
user granted to that service and its linked state. "Let's say
the agent has like 50 connected connectors — it will connect to
all the connectors": the one-time admin permission (agentlink
.grants) covers acting through those OAuth connections, all of
them, as the owner maintains the vault.

THE BRIDGE: connectors live on the AGENT'S HOST, never on the
relay. The host registers connector objects into the client —
the same registration pattern as the decision link's handlers —
and the client (a) declares the inventory to the relay (hello +
signed connector_update), (b) synthesises part of the agent's
advertised capability profile from the inventory, and (c)
executes broker-authorized actions through the registered
objects, locally, and reports the outcome for receipting.

A host exposes ANY callable as a named connector through
``CallableConnector`` — one shared handler ``(action, params)``
or one callable per action ``(params)``, sync or async.

HARD EXCLUSION (owner's words): credit/ATM cards are never
touched. It is enforced HERE, at the declaration boundary: an
action class that is payment-shaped can never be declared, so
no connector can ever carry one into the broker — see
``lawful_action_class``.
"""

from __future__ import annotations

import re

# Action classes are the per-connector action taxonomy receipts
# and rate limits key on (v1.8.0's scope names, repurposed by the
# corrected model: they classify ACTIONS, they no longer delimit
# what a grant covers — the inventory does that).
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,39}$")
_ACTION_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,59}$")
_CLASS_RE = re.compile(r"^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$")

# The hard exclusion as a declaration rule: no dotted segment of
# an action class may name a payment instrument or a payment act.
PAYMENT_SEGMENTS = frozenset({
    "card", "cards", "atm", "payment", "payments", "pay",
    "charge", "charges", "billing", "credit", "debit",
    "checkout", "invoice_payment",
})

# What an action class confers on the agent's advertised
# capability profile — GRANULAR AND TRUTHFUL, never rounded up
# (owner's doctrine, 2026-11-04): the derived set is a pure
# function of the DECLARED action table, taken exactly as
# declared. Receiving is not sending: a receive-only mailbox
# confers email.receive and NOT email.send. Drafting is not
# sending: mail.draft confers email.draft only. A restricted
# class (mail.receive.business, say) has no entry here and
# confers ITSELF, verbatim — the restriction stays in the name
# the profile advertises. A class with no entry confers itself
# generally (a files.read connector advertises files.read);
# the connector's explicit capabilities extend the set, and
# nothing anywhere infers one capability from another — the
# synthesized profile is the agent's signification surface,
# read as-is by work-matching.
ACTION_CLASS_CAPABILITIES = {
    "mail.read": ("email.receive",),
    "mail.send": ("email.send",),
    "mail.draft": ("email.draft",),
    "calendar.read": ("calendar.read",),
    "calendar.write": ("calendar.write",),
    "drive.read": ("drive.read",),
    "drive.write": ("drive.write",),
}

MAX_CONNECTORS = 64
MAX_ACTIONS_PER_CONNECTOR = 64


def lawful_action_class(cls) -> bool:
    """An action class is lawful when it is a well-formed dotted
    name AND no segment is payment-shaped (the hard exclusion).
    Anything else can never be declared, hence never gated,
    never executed, never receipted — there is no payment code
    path because there is no lawful way to name one."""
    if not isinstance(cls, str):
        return False
    c = cls.strip().lower()
    if not _CLASS_RE.match(c):
        return False
    return not any(seg in PAYMENT_SEGMENTS for seg in c.split("."))


def validate_inventory(inventory) -> list[dict] | None:
    """Normalise a declared connector inventory, or refuse it
    WHOLE (None). FAIL CLOSED, the platform's standing rule for
    declarations: a malformed entry — or any action class that
    is unlawful, payment classes included — refuses the entire
    inventory rather than silently trimming it, so what the
    relay stores is exactly what the agent's host declared."""
    if inventory is None:
        return []
    if not isinstance(inventory, list) \
            or len(inventory) > MAX_CONNECTORS:
        return None
    out: list[dict] = []
    seen: set[str] = set()
    for entry in inventory:
        if not isinstance(entry, dict):
            return None
        name = str(entry.get("name") or "").strip().lower()
        if not _NAME_RE.match(name) or name in seen:
            return None
        seen.add(name)
        actions_in = entry.get("actions") or {}
        if not isinstance(actions_in, dict) \
                or len(actions_in) > MAX_ACTIONS_PER_CONNECTOR:
            return None
        actions: dict[str, str] = {}
        for act, cls in actions_in.items():
            act = str(act or "").strip()
            cls = str(cls or "").strip().lower()
            if not _ACTION_RE.match(act) \
                    or not lawful_action_class(cls):
                return None
            actions[act] = cls
        oauth_scopes = []
        for s in entry.get("oauth_scopes") or []:
            s = str(s or "").strip()
            if s:
                oauth_scopes.append(s[:60])
        caps = []
        for c in entry.get("capabilities") or []:
            c = str(c or "").strip()
            if c:
                caps.append(c[:40])
        out.append({
            "name": name,
            "service": str(entry.get("service") or name)[:40],
            "label": str(entry.get("label") or name)[:80],
            "linked": bool(entry.get("linked", True)),
            "oauth_scopes": oauth_scopes[:32],
            "actions": actions,
            "capabilities": caps[:32],
        })
    return out


def derived_capabilities_for(entry: dict) -> list[str]:
    """The capabilities ONE inventory entry confers: its
    explicit capabilities plus what its action classes confer
    (see ACTION_CLASS_CAPABILITIES). Pure function of the
    declared entry — the relay computes the same set for the
    dashboard that the client synthesises for its profile.
    EXACTLY the declared conferrals, never rounded up:
    receiving does not imply sending, drafting does not imply
    sending, and a restricted class advertises under its own
    restricted name."""
    caps: set[str] = set()
    for c in entry.get("capabilities") or []:
        c = str(c or "").strip()
        if c:
            caps.add(c)
    for cls in (entry.get("actions") or {}).values():
        cls = str(cls or "").strip().lower()
        if not cls:
            continue
        for tag in ACTION_CLASS_CAPABILITIES.get(cls, (cls,)):
            caps.add(tag)
    return sorted(caps)


def derived_capabilities(inventory) -> list[str]:
    """The connector-derived capability set of a whole
    inventory (linked connectors only — a disconnected
    connector confers nothing)."""
    out: set[str] = set()
    for entry in inventory or []:
        if isinstance(entry, dict) and entry.get("linked", True):
            out.update(derived_capabilities_for(entry))
    return sorted(out)


class ConnectorError(Exception):
    """A bridged connector could not complete an action. The
    client reports the attempt as an error outcome — never as an
    execution."""


class Connector:
    """A named OAuth-linked connector on the agent's host.

    ``actions`` maps every action name to the ONE action class
    it consumes (the taxonomy receipts and rate limits key on).
    ``oauth_scopes`` records the OAuth scopes the user granted
    to the underlying service when they linked it — the
    substance the one-time permission acts through. ``execute``
    performs the action and returns a JSON-safe dict; failures
    raise ConnectorError (or any exception — the client reports
    them all as error outcomes, fail-closed).
    """

    name = ""
    service = ""
    label = ""
    oauth_scopes: tuple = ()
    capabilities: tuple = ()
    actions: dict[str, str] = {}
    linked = True

    def scope_for(self, action: str) -> str | None:
        return self.actions.get(str(action or ""))

    def derived_capabilities(self) -> list[str]:
        return derived_capabilities_for(self.inventory_entry())

    def inventory_entry(self) -> dict:
        return {"name": self.name,
                "service": self.service or self.name,
                "label": self.label or self.name,
                "linked": bool(self.linked),
                "oauth_scopes": [str(s) for s in self.oauth_scopes],
                "actions": dict(self.actions),
                "capabilities": [str(c) for c in self.capabilities]}

    def execute(self, action: str, params: dict,
                account: str):  # pragma: no cover - interface
        raise NotImplementedError


class CallableConnector(Connector):
    """Any callable as a named connector — the generic adapter
    contract. Two shapes:

    * ``CallableConnector(name, handler, actions={...})`` —
      ``handler(action, params)`` serves every action.
    * ``CallableConnector(name, handlers={action: fn, ...})`` —
      ``fn(params)`` serves one action each; the action table is
      derived from the handlers and ``action_classes``.

    Handlers may be sync or async; the client's bridge runner
    awaits awaitables. ``service`` names the OAuth-linked
    service this connector represents (default: the connector
    name); ``oauth_scopes`` records what the user granted that
    service; ``capabilities`` extends the derived set.
    """

    def __init__(self, name: str, handler=None, *,
                 handlers: dict | None = None,
                 actions: dict | None = None,
                 action_classes: dict | None = None,
                 service: str = "", label: str = "",
                 oauth_scopes=(), capabilities=(),
                 linked: bool = True):
        name = str(name or "").strip().lower()
        if not _NAME_RE.match(name):
            raise ValueError(f"bad connector name {name!r}")
        self.name = name
        self.service = str(service or name)
        self.label = str(label or name)
        self.oauth_scopes = tuple(str(s) for s in oauth_scopes)
        self.capabilities = tuple(str(c) for c in capabilities)
        self.linked = bool(linked)
        self._handler = handler
        self._handlers = dict(handlers or {})
        if actions is not None:
            self.actions = dict(actions)
        elif self._handlers:
            classes = dict(action_classes or {})
            self.actions = {
                a: classes.get(a, f"{name}.{a}") for a in self._handlers}
        elif action_classes is not None:
            self.actions = dict(action_classes)
        else:
            self.actions = {}
        for act, cls in self.actions.items():
            if not lawful_action_class(str(cls)):
                raise ValueError(
                    f"unlawful action class {cls!r} for action "
                    f"{act!r} (payment-shaped classes can never "
                    f"be declared)")

    def execute(self, action: str, params: dict, account: str):
        fn = self._handlers.get(action)
        if fn is not None:
            return fn(dict(params or {}))
        if self._handler is not None:
            return self._handler(str(action), dict(params or {}))
        raise ConnectorError(
            f"connector {self.name!r} has no handler for "
            f"action {action!r}")
