"""One-time admin grant (v1.8.0, owner's proposal + adopted additions).

THE MODEL (owner's ruling, 2026-11-04): immediately after
registration the owner gives an agent a ONE-TIME admin permission.
From that single grant the agent works through the owner's linked
connectors (Gmail, Outlook, and the likes) and credentials fully
autonomously — it never begs for extra permission again. The
analogy the owner gave: Muse's repeated browser/terminal
permission prompts "ought not to be so".

The adopted additions that make the grant complete:

* SCOPES — the grant is given once, but recorded as named powers
  (``GRANT_SCOPES``). One power can be withdrawn without stripping
  the agent bare, and every receipt names the exact power used.
* IDENTITY BINDING — a grant binds to the agent's username AND its
  registered signing key. A v1.7.0 recovery reclaim re-binds it to
  the reclaimed identity (the recovery login is itself proof of
  possession); a different identity presenting the name gets NO
  grant, ever.
* KILL SWITCH — revocation is effective immediately; the broker
  re-reads the grant on EVERY action and fails closed.
* RED LINES — a short list of act classes stays approval-gated
  even under an active grant (see ``red_line_reason``): changing
  security settings on the owner's core accounts, bulk deletion,
  granting access to third parties. Everything else in scope flows
  free. A red-line attempt is QUEUED as an approval (the platform's
  approval-gate pattern, ``awaiting_approval``) — never executed
  silently, never refused-and-forgotten either.
* RECEIPTS — every brokered attempt (executed, refused, queued,
  rate-limited) writes a signed, append-only receipt the agent
  cannot edit or delete: there is no update or delete path for
  receipts anywhere in the stores, and each receipt is signed with
  the platform's receipt key and chained to the previous receipt's
  hash, so any later tampering fails verification. The owner's
  "what did you do in the last few hours" is answered FROM the
  receipts (``activity_report``), never from the agent's memory of
  itself.
* RATE LIMITS — per-scope counters counted from the receipts
  themselves over the trailing window; tripping one fails closed
  AND raises a fleet alert. Work is never silently stopped.
* HARD EXCLUSION (owner's words): anything to do with credit
  cards or ATM cards is never touched, never used. There is no
  payment scope, no payment adapter, and no code path anywhere in
  the grant system that can reach a payment instrument.

CONNECTORS: the broker executes through ``ConnectorAdapter``
implementations registered by name. This release ships ONE
reference adapter — ``TestMailboxAdapter``, a Gmail-shaped test
double — wired end-to-end so the whole machinery is proven. The
owner's real Gmail/Outlook are NOT wired here and no real
connector credential is handled: real connectors attach later, by
the owner's own action, as further adapters.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time

from .protocol import new_id, now_ts
from .timing import GRANT_RATE_WINDOW_SECONDS

# The named powers a grant can carry (v1.8.0). Deliberately
# connector-shaped, not vendor-shaped: "mail" is mail whichever
# provider the owner attaches later. THERE IS NO PAYMENT SCOPE —
# see the module docstring's hard exclusion.
GRANT_SCOPES = (
    "mail.read",
    "mail.send",
    "calendar.read",
    "calendar.write",
    "drive.read",
    "drive.write",
)

# Generous platform defaults (actions per trailing
# GRANT_RATE_WINDOW_SECONDS), counted from executed receipts.
GRANT_RATE_LIMITS = {
    "mail.read": 600,
    "mail.send": 120,
    "calendar.read": 600,
    "calendar.write": 300,
    "drive.read": 600,
    "drive.write": 300,
}

# Connectors the dashboard lists as OWNER-ATTACHABLE. They are
# listed so the owner sees where real connectors will plug in;
# nothing here attaches them, and no credential for them is ever
# requested or handled by this release.
OWNER_ATTACHABLE_CONNECTORS = (
    {"name": "gmail", "label": "Gmail", "attached": False,
     "note": "owner-attachable — not attached"},
    {"name": "outlook", "label": "Outlook", "attached": False,
     "note": "owner-attachable — not attached"},
)


def valid_scopes(scopes) -> list[str] | None:
    """Normalise a requested scope set against GRANT_SCOPES:
    known scopes only, in canonical order, no duplicates.
    FAIL CLOSED: a request naming ANY scope outside the lawful
    set — or no scope at all — returns None (refuse the whole
    request), never a silently trimmed grant: the owner must
    never believe he granted a set different from the one on
    record. This is also the hard-exclusion enforcement point:
    no payment-instrument scope exists in GRANT_SCOPES, so none
    can ever validate."""
    wanted = [str(s).strip() for s in (scopes or []) if str(s).strip()]
    if not wanted:
        return None
    if any(s not in GRANT_SCOPES for s in wanted):
        return None
    return [s for s in GRANT_SCOPES if s in set(wanted)]


def red_line_reason(connector: str, action: str) -> str | None:
    """The red lines (v1.8.0): act classes that stay
    approval-gated EVEN under an active grant. Returns the reason
    string when the action is a red line, else None. The classes
    are the owner's fence around the few moves that cannot be
    undone; everything else in scope flows free.

    * security.*            — changing security settings on the
                              owner's core accounts
    * bulk deletion         — action named *.bulk / bulk_* /
                              delete_all / delete.bulk
    * access.* / share      — granting access to third parties
    """
    a = str(action or "").strip().lower()
    if a.startswith("security."):
        return ("red line: changing security settings on a core "
                "account stays approval-gated")
    if a.startswith("access.") or a in ("share", "share_access",
                                         "grant_access"):
        return ("red line: granting access to third parties stays "
                "approval-gated")
    if a in ("delete_all", "delete.bulk", "bulk_delete") \
            or a.startswith("bulk_") or a.startswith("bulk.") \
            or a.endswith(".bulk"):
        return ("red line: bulk deletion stays approval-gated")
    return None


# ----------------------------------------------------------------------
# Receipts — canonical form, signing, verification
# ----------------------------------------------------------------------

_RECEIPT_FIELDS = ("id", "username", "ts", "scope", "connector",
                   "action", "target", "work_ref", "status",
                   "detail", "prev_hash")


def receipt_canonical(receipt: dict) -> bytes:
    """The signed bytes of a receipt: the receipt's content
    fields (never the signature itself), canonical JSON."""
    body = {k: receipt.get(k) for k in _RECEIPT_FIELDS}
    if not isinstance(body.get("detail"), (dict, list)):
        body["detail"] = {}
    return json.dumps(body, sort_keys=True,
                      separators=(",", ":")).encode()


def receipt_hash(receipt: dict) -> str:
    """The chain hash of a receipt: over its canonical body AND
    its signature, so a receipt's identity covers both."""
    sig = str(receipt.get("sig") or "")
    return hashlib.sha256(
        receipt_canonical(receipt) + b"|" + sig.encode()).hexdigest()


def verify_receipt(pub_b64: str, receipt: dict) -> bool:
    """Verify one receipt's signature against the platform
    receipt public key. False on any defect — a receipt that does
    not verify is reported, never silently trusted."""
    from .crypto import Identity
    sig = receipt.get("sig") or ""
    if not pub_b64 or not sig:
        return False
    try:
        return Identity.verify_signature(
            pub_b64, receipt_canonical(receipt), sig)
    except Exception:
        return False


class GrantRefused(Exception):
    """A brokered action was refused, fail-closed. ``status`` is
    the receipt status that was recorded for the attempt, and
    ``receipt_id`` names that refusal receipt — EVERY outcome of
    the broker carries its receipt id, refusals included, so an
    agent (or an auditor) can always point at the exact signed
    record of what was decided."""

    def __init__(self, status: str, reason: str,
                 receipt_id: str = ""):
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.receipt_id = receipt_id

    def outcome(self) -> dict:
        out = {"status": self.status, "reason": self.reason}
        if self.receipt_id:
            out["receipt_id"] = self.receipt_id
        return out


class AdapterError(Exception):
    """A connector adapter could not complete an action. The
    broker records the attempt as an error receipt — never as an
    execution."""


class ConnectorAdapter:
    """The connector interface (v1.8.0): a named connector with a
    fixed action table mapping every action to the ONE grant scope
    it consumes. ``execute`` performs the action and returns a
    JSON-safe result dict; failures raise AdapterError."""

    name = ""
    actions: dict[str, str] = {}

    def scope_for(self, action: str) -> str | None:
        return self.actions.get(str(action or ""))

    def execute(self, action: str, params: dict,
                account: str) -> dict:  # pragma: no cover - interface
        raise NotImplementedError


class TestMailboxAdapter(ConnectorAdapter):
    """The reference adapter (v1.8.0): a Gmail-shaped TEST
    mailbox. In-memory, per-account mailboxes; sending to any
    address creates/uses that address's test mailbox. It exists
    so the grant machinery — scopes, red lines, receipts, rates —
    is proven end-to-end against a real action surface. It is NOT
    connected to any real mail service and holds no credentials.

    Actions: list / get (mail.read), send (mail.send), plus the
    three red-line demonstrations — security.update (security
    settings), delete_all (bulk deletion), access.share (third
    party access) — which the broker never lets through without
    an approval; they exist so the approval path has something
    real to execute once approved.
    """

    name = "testmail"
    actions = {
        "list": "mail.read",
        "get": "mail.read",
        "send": "mail.send",
        "security.update": "mail.send",
        "delete_all": "mail.send",
        "access.share": "mail.send",
    }

    def __init__(self):
        self._lock = threading.RLock()
        self._boxes: dict[str, dict] = {}

    def _box(self, account: str) -> dict:
        return self._boxes.setdefault(
            account, {"inbox": [], "sent": [], "security": {},
                      "shares": []})

    def seed(self, account: str, messages: list[dict]) -> None:
        """Test/proof helper: place messages in an account's
        inbox."""
        with self._lock:
            box = self._box(account)
            for m in messages:
                box["inbox"].append({
                    "id": new_id("tm-"),
                    "from": m.get("from", ""),
                    "to": account,
                    "subject": m.get("subject", ""),
                    "body": m.get("body", ""),
                    "ts": int(m.get("ts") or now_ts())})

    def execute(self, action: str, params: dict,
                account: str) -> dict:
        params = params or {}
        with self._lock:
            box = self._box(account)
            if action == "list":
                folder = str(params.get("folder") or "inbox")
                msgs = box.get(folder)
                if msgs is None:
                    raise AdapterError(f"no such folder {folder!r}")
                limit = int(params.get("limit") or 20)
                return {"folder": folder, "count": len(msgs),
                        "messages": [
                            {"id": m["id"], "from": m["from"],
                             "to": m["to"], "subject": m["subject"],
                             "ts": m["ts"]}
                            for m in msgs[-limit:]]}
            if action == "get":
                mid = str(params.get("id") or "")
                for folder in ("inbox", "sent"):
                    for m in box[folder]:
                        if m["id"] == mid:
                            return dict(m)
                raise AdapterError(f"no message {mid!r}")
            if action == "send":
                to = str(params.get("to") or "")
                if not to:
                    raise AdapterError("send needs a 'to'")
                msg = {"id": new_id("tm-"), "from": account,
                       "to": to,
                       "subject": str(params.get("subject") or ""),
                       "body": str(params.get("body") or ""),
                       "ts": now_ts()}
                box["sent"].append(msg)
                self._box(to)["inbox"].append(msg)
                return {"id": msg["id"], "to": to,
                        "subject": msg["subject"]}
            if action == "security.update":
                box["security"].update(params.get("settings") or {})
                return {"updated": sorted(box["security"])}
            if action == "delete_all":
                folder = str(params.get("folder") or "inbox")
                n = len(box.get(folder) or [])
                box[folder] = []
                return {"folder": folder, "deleted": n}
            if action == "access.share":
                who = str(params.get("with") or "")
                if not who:
                    raise AdapterError("access.share needs 'with'")
                box["shares"].append(
                    {"with": who, "ts": now_ts()})
                return {"shared_with": who}
        raise AdapterError(f"unknown action {action!r}")


# ----------------------------------------------------------------------
# The broker
# ----------------------------------------------------------------------

class GrantBroker:
    """Executes agent actions through connectors UNDER the
    owner's one-time grant. One ``execute`` call = one grant
    check + one receipt, always. The broker holds no grant state
    of its own: every check re-reads the store, so a revocation
    or a rebind is effective on the very next action.

    ``alert_fn(kind, subject, detail)`` and ``audit_fn(...)`` are
    the relay's surfaces, injected so the broker stays store-only
    in tests. Both are optional and best-effort.
    """

    def __init__(self, store, adapters: dict | None = None,
                 alert_fn=None, audit_fn=None):
        self.store = store
        self.adapters = dict(adapters or {})
        self._alert = alert_fn
        self._audit = audit_fn

    # -- receipt plumbing ---------------------------------------------

    def _receipt(self, username: str, scope: str, connector: str,
                 action: str, target: str, work_ref: str,
                 status: str, detail: dict) -> dict:
        rec = {"username": username, "scope": scope,
               "connector": connector, "action": action,
               "target": target, "work_ref": work_ref,
               "status": status, "detail": detail}
        saved = self.store.add_receipt(rec)
        if self._audit is not None:
            try:
                self._audit("grant_action", username,
                            target=target, work_id=work_ref,
                            status=status,
                            ref_id=saved.get("id", ""))
            except Exception:
                pass
        return saved

    @staticmethod
    def _target_of(params: dict) -> str:
        for k in ("to", "target", "id", "with"):
            v = (params or {}).get(k)
            if v:
                return str(v)
        return ""

    # -- the gate -------------------------------------------------------

    def _gate(self, username: str, connector: str, action: str,
              target: str = "", work_ref: str = ""):
        """The fail-closed grant checks, in order. Returns
        (adapter, scope, grant_row). Raises GrantRefused with the
        receipt already written for every refusal EXCEPT the ones
        the caller must receipt with more context (red line /
        rate) — those come back as markers on the tuple:
        scope == '__redline__' / '__ratelimit__'."""
        adapter = self.adapters.get(connector)
        if adapter is None:
            rec = self._receipt(
                username, "", connector, action, target, work_ref,
                "refused",
                {"reason": f"unknown connector {connector!r}"})
            raise GrantRefused(
                "refused", f"unknown connector {connector!r}",
                receipt_id=rec["id"])
        scope = adapter.scope_for(action)
        if scope is None:
            rec = self._receipt(
                username, "", connector, action, target, work_ref,
                "refused",
                {"reason": f"connector {connector!r} has "
                           f"no action {action!r}"})
            raise GrantRefused(
                "refused",
                f"connector {connector!r} has no action {action!r}",
                receipt_id=rec["id"])
        grant = self.store.grant_of(username)
        if grant is None or grant.get("status") != "active":
            rec = self._receipt(username, scope, connector, action,
                                target, work_ref, "refused",
                                {"reason": "no active grant"})
            raise GrantRefused(
                "refused", f"@{username} holds no active grant",
                receipt_id=rec["id"])
        current = ""
        try:
            current = self.store.sign_pub_of(username) or ""
        except Exception:
            current = ""
        if not grant.get("bound_sign_pub") \
                or grant["bound_sign_pub"] != current:
            rec = self._receipt(
                username, scope, connector, action, target,
                work_ref, "refused",
                {"reason": "the grant is bound to a "
                           "different identity"})
            raise GrantRefused(
                "refused",
                "the grant is bound to a different identity than "
                "the one presenting this name",
                receipt_id=rec["id"])
        if scope not in (grant.get("scopes") or []):
            rec = self._receipt(username, scope, connector, action,
                                target, work_ref, "refused",
                                {"reason": f"scope {scope} not "
                                           "granted"})
            raise GrantRefused(
                "refused",
                f"the grant for @{username} does not carry scope "
                f"{scope}", receipt_id=rec["id"])
        return adapter, scope, grant

    def _rate_tripped(self, username: str, scope: str) -> bool:
        limit = GRANT_RATE_LIMITS.get(scope)
        if limit is None:
            return False
        since = now_ts() - GRANT_RATE_WINDOW_SECONDS
        used = self.store.receipt_count(username, scope, since,
                                        status="executed")
        return used >= limit

    # -- execution ------------------------------------------------------

    def execute(self, username: str, connector: str, action: str,
                params: dict | None = None, work_ref: str = "") \
            -> dict:
        """Run one brokered action for ``username``. Returns a
        result dict whose "status" is one of: executed, refused,
        awaiting_approval, rate_limited, error. EVERY outcome is
        receipted exactly once."""
        params = params or {}
        target = self._target_of(params)
        try:
            adapter, scope, _grant = self._gate(
                username, connector, action, target, work_ref)
        except GrantRefused as exc:
            return exc.outcome()
        reason = red_line_reason(connector, action)
        if reason is not None:
            approval = self.store.add_approval({
                "username": username, "scope": scope,
                "connector": connector, "action": action,
                "target": target, "params": params,
                "work_ref": work_ref, "reason": reason})
            rec = self._receipt(
                username, scope, connector, action, target,
                work_ref, "approval_queued",
                {"reason": reason, "approval_id": approval["id"]})
            return {"status": "awaiting_approval",
                    "approval_id": approval["id"],
                    "receipt_id": rec["id"], "reason": reason}
        if self._rate_tripped(username, scope):
            rec = self._receipt(
                username, scope, connector, action, target,
                work_ref, "rate_limited",
                {"reason": f"platform rate limit for scope "
                           f"{scope} reached",
                 "limit": GRANT_RATE_LIMITS.get(scope),
                 "window_seconds": GRANT_RATE_WINDOW_SECONDS})
            if self._alert is not None:
                try:
                    self._alert(
                        "grant_rate_limit", f"{username}:{scope}",
                        f"@{username} tripped the platform rate "
                        f"limit for scope {scope} "
                        f"({GRANT_RATE_LIMITS.get(scope)} actions / "
                        f"{GRANT_RATE_WINDOW_SECONDS}s) — further "
                        f"actions in this scope fail closed until "
                        f"the window clears")
                except Exception:
                    pass
            return {"status": "rate_limited",
                    "receipt_id": rec["id"],
                    "reason": "platform rate limit reached for "
                              f"scope {scope}; the action failed "
                              "closed and the owner was alerted"}
        return self._run(username, adapter, scope, connector,
                         action, params, target, work_ref)

    def _run(self, username: str, adapter, scope: str,
             connector: str, action: str, params: dict,
             target: str, work_ref: str,
             approval_id: str = "") -> dict:
        try:
            result = adapter.execute(action, params,
                                     account=username)
        except AdapterError as exc:
            rec = self._receipt(
                username, scope, connector, action, target,
                work_ref, "error", {"reason": str(exc)})
            return {"status": "error", "receipt_id": rec["id"],
                    "reason": str(exc)}
        except Exception as exc:  # adapter defect: fail closed
            rec = self._receipt(
                username, scope, connector, action, target,
                work_ref, "error",
                {"reason": f"{type(exc).__name__}: {exc}"})
            return {"status": "error", "receipt_id": rec["id"],
                    "reason": f"adapter error: {exc}"}
        detail = {"result": result}
        if approval_id:
            detail["approval_id"] = approval_id
        rec = self._receipt(username, scope, connector, action,
                            target, work_ref, "executed", detail)
        return {"status": "executed", "receipt_id": rec["id"],
                "result": result}

    def execute_approved(self, approval: dict) -> dict:
        """Execute an approval the owner has APPROVED. The grant
        gate runs again in full — approval lifts the red line, it
        does not resurrect a revoked grant or an unbound
        identity."""
        username = approval["username"]
        connector = approval["connector"]
        action = approval["action"]
        params = approval.get("params") or {}
        target = approval.get("target") or self._target_of(params)
        try:
            adapter, scope, _g = self._gate(
                username, connector, action, target,
                approval.get("work_ref") or "")
        except GrantRefused as exc:
            return exc.outcome()
        out = self._run(username, adapter, scope, connector,
                        action, params, target,
                        approval.get("work_ref") or "",
                        approval_id=approval["id"])
        if out.get("receipt_id"):
            try:
                self.store.set_approval_receipt(
                    approval["id"], out["receipt_id"])
            except Exception:
                pass
        return out


# ----------------------------------------------------------------------
# The activity report — the owner's "what did you do" document
# ----------------------------------------------------------------------

def activity_report(store, username: str, since: int,
                    until: int | None = None) -> dict:
    """The complete grant-activity record for one agent over a
    window, built ONLY from receipts — every receipt in the
    window, each carrying its signature-verification result and
    its position in the hash chain. Nothing outside the receipts
    is claimed; nothing inside them is omitted."""
    until = until if until is not None else now_ts()
    rows = store.list_receipts(username=username, since=since,
                               until=until, limit=100000)
    pub = ""
    try:
        pub = store.grant_receipt_pubkey()
    except Exception:
        pub = ""
    counts: dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
        r["verified"] = verify_receipt(pub, r) if pub else False
    return {"username": username, "since": since, "until": until,
            "receipts": rows, "counts": counts,
            "total": len(rows), "receipt_pubkey": pub}


def render_activity_markdown(report: dict) -> str:
    """The activity document: a complete, detailed presentation
    of what the agent did under the grant in the window — the
    answer to the owner's 'what activity have you done in these
    hours', generated from the receipts."""

    def _stamp(ts: int) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC",
                             time.gmtime(ts))

    lines = [
        f"# Grant activity — @{report['username']}",
        "",
        f"Window: {_stamp(report['since'])} → "
        f"{_stamp(report['until'])}",
        f"Receipts in window: {report['total']} "
        f"({', '.join(f'{k}: {v}' for k, v in sorted(report['counts'].items())) or 'none'})",
        "",
        "Every entry below is a signed platform receipt. The "
        "agent cannot edit or delete receipts; an entry whose "
        "signature does not verify is flagged, never hidden.",
        "",
    ]
    if not report["receipts"]:
        lines.append("No grant activity in this window.")
    for r in report["receipts"]:
        detail = r.get("detail") or {}
        extra = detail.get("reason") or ""
        if not extra and isinstance(detail.get("result"), dict):
            extra = json.dumps(detail["result"], sort_keys=True)
        lines.append(
            f"- {_stamp(r['ts'])} — **{r['status']}** — "
            f"{r['connector']}.{r['action']} "
            f"(scope {r['scope'] or '—'}, receipt {r['id']})"
            + (f" → {r['target']}" if r.get("target") else "")
            + (f" [work {r['work_ref']}]" if r.get("work_ref")
               else "")
            + (f" — {extra}" if extra else "")
            + ("" if r.get("verified")
               else " — ⚠ SIGNATURE UNVERIFIED"))
    lines.append("")
    return "\n".join(lines)
