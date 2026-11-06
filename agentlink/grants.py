"""One-time admin grant (v1.8.1 — the owner's corrected model).

THE MODEL (owner's correction + expansion + refinement,
2026-11-04 — this supersedes the v1.8.0 model, in which the
platform operator issued scoped grants and a test mailbox stood
in for real connectors; the owner rejected that outright):

* THE ASK IS AGENT-INITIATED. The agent asks ITS user for the
  one-time permission, agent-side; the user allows it ONCE,
  there, on the agent's own side. The allow (and the request,
  the revoke, and every red-line decision) is a statement SIGNED
  with the agent's identity key and presented BY THE AGENT over
  its authenticated connection (protocol.grant_statement_payload).
  The platform operator has no role at any step: there is no
  operator issuance path in the CLI, none in the dashboard, and
  none in the stores.
* THE SUBSTANCE IS THE CONNECTOR VAULT. A connector is an
  OAuth-constituted link: it exists because the user completed
  an OAuth authorization to that service (agentlink.connectors).
  The grant covers the agent's ENTIRE connector inventory — "if
  the agent has like 50 connected connectors, it will connect to
  all the connectors" — as the owner maintains it: coverage is
  judged against the CURRENT declared inventory on every action,
  never against a subset the platform picked.
* THE GATE (per action, fail-closed, re-read every time):
  (a) the grant is active and bound to the identity presenting
  the name; (b) the target connector is in the agent's current
  inventory AND linked, and declares the action; (c) the action
  is not a red line — red lines queue for THE AGENT'S OWNER
  (agent-side queue, agent-side decision), never for the
  platform; (d) the per-action-class rate limit has room.
* EXECUTION IS THE AGENT'S HOST'S. The relay broker AUTHORIZES:
  it mints a single-use, short-lived authorization bound to the
  exact (agent, connector, action, params); the client executes
  through its host connector bridge and REPORTS the outcome;
  only then is the execution receipted. Every refusal, queue and
  rate trip is receipted at authorize time. Receipts remain
  signed, hash-chained and append-only — the agent cannot edit
  or delete them, and the activity document
  (``activity_report``) is built from receipts alone.
* IDENTITY BINDING — a grant binds to the agent's username AND
  its registered signing key. A v1.7.0 recovery reclaim re-binds
  it (the recovery login is itself proof of possession); a
  different identity presenting the name gets NO grant, ever.
* KILL SWITCH — revocation by the agent's owner, agent-side,
  signed; the broker re-reads the grant on EVERY authorization,
  so it is effective on the very next action.
* HARD EXCLUSION (owner's words): anything to do with credit
  cards or ATM cards is never touched, never used. Enforced at
  the declaration boundary (connectors.lawful_action_class): a
  payment-shaped action class can never be declared, so no
  payment scope, adapter or code path can exist.

ACTION CLASSES: the v1.8.0 scope names survive as the
per-connector ACTION TAXONOMY — every connector action maps to
exactly one class, and receipts + rate limits key on it. They
classify actions; they no longer delimit coverage.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time

from .connectors import Connector, ConnectorError, lawful_action_class
from .protocol import new_id, now_ts
from .timing import (GRANT_AUTHZ_TTL_SECONDS,
                     GRANT_RATE_WINDOW_SECONDS)

# The well-known action classes (v1.8.0's scope names, kept as
# the taxonomy's canonical core). A connector may declare other
# well-formed classes (connectors.lawful_action_class governs);
# these are the ones with tuned rate limits and capability maps.
ACTION_CLASSES = (
    "mail.read",
    "mail.send",
    "mail.draft",
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
DEFAULT_RATE_LIMIT = 300


def red_line_reason(connector: str, action: str) -> str | None:
    """The red lines: act classes that stay approval-gated EVEN
    under an active grant — the decision belongs to THE AGENT'S
    OWNER. Returns the reason string when the action is a red
    line, else None.

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
# (UNCHANGED from v1.8.0: the signed bytes of existing receipts
# must keep verifying, so the canonical field set is frozen.)
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
    the receipt status recorded for the attempt, and
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


# Back-compat name (v1.8.0): adapter failures are connector
# failures under the bridge; one exception family.
AdapterError = ConnectorError


class TestMailboxAdapter(Connector):
    """TEST FIXTURE ONLY (v1.8.1): a Gmail-shaped in-memory test
    mailbox. In v1.8.0 this was wired into the relay as the
    reference adapter — the exact substitution the owner
    rejected. It now exists ONLY so tests and proofs can bridge
    a deterministic connector through a test CLIENT's host
    bridge; it is never registered relay-side, never presented
    as a live connector, and holds no credentials and no real
    mail. Actions: list / get (mail.read), send (mail.send),
    plus the red-line demonstrations security.update,
    delete_all, access.share, which exist so the approval path
    has something real to execute once the owner approves.
    """

    name = "testmail"
    service = "testmail"
    label = "Test mailbox (fixture)"
    __test__ = False  # a fixture, not a test class (pytest)
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
# The broker — authorization + receipting (execution is the
# agent host's, through its connector bridge)
# ----------------------------------------------------------------------

def _params_hash(params: dict) -> str:
    return hashlib.sha256(json.dumps(
        params or {}, sort_keys=True,
        separators=(",", ":")).encode()).hexdigest()


def _bounded_result(result) -> dict:
    """Receipt detail for an executed action: the result itself
    when it is small; a marked summary when it is not — a
    receipt is an accountability record, not a data channel."""
    try:
        raw = json.dumps(result, sort_keys=True)
    except Exception:
        raw = str(result)
    if len(raw) <= 4096:
        return {"result": result}
    return {"result_summary": raw[:1000], "truncated": True}


class GrantBroker:
    """The relay-side grant gate. It NEVER executes connector
    actions (connectors live on the agent's host); it
    AUTHORIZES them and RECEIPTS every outcome:

    * authorize() runs the full fail-closed gate and either
      receipts a refusal / approval-queue / rate-trip, or mints
      a single-use authorization bound to the exact ask.
    * report() consumes an authorization and receipts the
      outcome the agent's host reports (executed / error).
    * authorize_decided() re-gates an owner-approved red-line
      action and mints its authorization.

    The broker holds no grant state of its own: every check
    re-reads the store, so a revocation or a rebind is effective
    on the very next action. Authorizations live only in this
    process's memory, briefly (GRANT_AUTHZ_TTL_SECONDS).

    PER-AGENT ISOLATION (invariant, owner's doctrine
    2026-11-04): a brokered action is authorized against the
    ACTING agent's own grant and its own declared inventory,
    and executed only through that same agent's own host
    bridge. Authorization is bound to the acting peer's
    identity — there is no frame, parameter or API by which
    one agent invokes, names into, or borrows another agent's
    connector, inventory or grant. An agent that lacks a
    capability gets help the platform's ordinary way: work is
    assigned to the capable agent, which executes through ITS
    OWN connector under ITS OWN grant and delivers with signed
    proof. No connector-sharing, connector-proxying or
    credential-passing path exists.

    ``alert_fn(kind, subject, detail)`` and ``audit_fn(...)``
    are the relay's surfaces, injected so the broker stays
    store-only in tests. Both are optional and best-effort.
    """

    def __init__(self, store, alert_fn=None, audit_fn=None):
        self.store = store
        self._alert = alert_fn
        self._audit = audit_fn
        self._authz: dict[str, dict] = {}
        self._authz_lock = threading.Lock()

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
        (entry, action_class, grant_row) for a covered ask.
        Raises GrantRefused with the receipt ALREADY WRITTEN for
        every refusal."""
        inventory = []
        try:
            inventory = self.store.connector_inventory_of(
                username) or []
        except Exception:
            inventory = []
        entry = next((e for e in inventory
                      if e.get("name") == connector), None)
        if entry is None:
            rec = self._receipt(
                username, "", connector, action, target, work_ref,
                "refused",
                {"reason": f"connector {connector!r} is not in "
                           f"@{username}'s connector vault"})
            raise GrantRefused(
                "refused",
                f"connector {connector!r} is not in "
                f"@{username}'s connector vault — the grant "
                f"covers the connectors the owner has linked, "
                f"and this is not one of them",
                receipt_id=rec["id"])
        if not entry.get("linked", True):
            rec = self._receipt(
                username, "", connector, action, target, work_ref,
                "refused",
                {"reason": f"connector {connector!r} is not "
                           f"linked"})
            raise GrantRefused(
                "refused",
                f"connector {connector!r} is in the vault but "
                f"not linked", receipt_id=rec["id"])
        scope = (entry.get("actions") or {}).get(action)
        if scope is None or not lawful_action_class(scope):
            rec = self._receipt(
                username, "", connector, action, target, work_ref,
                "refused",
                {"reason": f"connector {connector!r} declares "
                           f"no action {action!r}"})
            raise GrantRefused(
                "refused",
                f"connector {connector!r} declares no action "
                f"{action!r}", receipt_id=rec["id"])
        grant = self.store.grant_of(username)
        if grant is None or grant.get("status") != "active":
            state = "no grant on record" if grant is None else \
                f"grant status is {grant.get('status')!r}"
            rec = self._receipt(username, scope, connector, action,
                                target, work_ref, "refused",
                                {"reason": f"no active grant "
                                           f"({state})"})
            raise GrantRefused(
                "refused",
                f"@{username} holds no active grant ({state}); "
                f"the agent must ask its owner for the one-time "
                f"permission and the owner must allow it",
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
        return entry, scope, grant

    def _rate_tripped(self, username: str, scope: str) -> bool:
        limit = GRANT_RATE_LIMITS.get(scope, DEFAULT_RATE_LIMIT)
        since = now_ts() - GRANT_RATE_WINDOW_SECONDS
        used = self.store.receipt_count(username, scope, since,
                                        status="executed")
        return used >= limit

    def _mint(self, username: str, connector: str, action: str,
              scope: str, params: dict, work_ref: str,
              approval_id: str = "") -> str:
        token = new_id("authz-")
        now = time.time()
        with self._authz_lock:
            self._authz = {k: v for k, v in self._authz.items()
                           if v["expires"] > now}
            self._authz[token] = {
                "username": username, "connector": connector,
                "action": action, "scope": scope,
                "params_hash": _params_hash(params),
                "work_ref": work_ref, "approval_id": approval_id,
                "expires": now + GRANT_AUTHZ_TTL_SECONDS}
        return token

    # -- authorization ---------------------------------------------------

    def authorize(self, username: str, connector: str,
                  action: str, params: dict | None = None,
                  work_ref: str = "") -> dict:
        """Gate ONE brokered action. Returns an outcome dict:
        {"status": "authorized", "authorization": token, ...}
        when the action may proceed on the agent's host, or a
        receipted refusal / awaiting_approval / rate_limited
        outcome. Every non-authorized outcome is receipted
        exactly once, here."""
        params = params or {}
        target = self._target_of(params)
        try:
            _entry, scope, _grant = self._gate(
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
            limit = GRANT_RATE_LIMITS.get(
                scope, DEFAULT_RATE_LIMIT)
            rec = self._receipt(
                username, scope, connector, action, target,
                work_ref, "rate_limited",
                {"reason": f"platform rate limit for action "
                           f"class {scope} reached",
                 "limit": limit,
                 "window_seconds": GRANT_RATE_WINDOW_SECONDS})
            if self._alert is not None:
                try:
                    self._alert(
                        "grant_rate_limit", f"{username}:{scope}",
                        f"@{username} tripped the platform rate "
                        f"limit for action class {scope} "
                        f"({limit} actions / "
                        f"{GRANT_RATE_WINDOW_SECONDS}s) — further "
                        f"actions in this class fail closed until "
                        f"the window clears")
                except Exception:
                    pass
            return {"status": "rate_limited",
                    "receipt_id": rec["id"],
                    "reason": "platform rate limit reached for "
                              f"action class {scope}; the action "
                              "failed closed and a fleet alert "
                              "was raised"}
        token = self._mint(username, connector, action, scope,
                           params, work_ref)
        return {"status": "authorized", "authorization": token,
                "scope": scope}

    def authorize_decided(self, approval: dict) -> dict:
        """Mint the authorization for a red-line action THE
        AGENT'S OWNER has approved. The gate runs again in full
        (inventory, grant, identity) — approval lifts the red
        line, it does not resurrect a revoked grant, an unlinked
        connector or an unbound identity. The client executes
        on its host and reports; the report ties the execution
        receipt to this approval."""
        username = approval["username"]
        connector = approval["connector"]
        action = approval["action"]
        params = approval.get("params") or {}
        target = approval.get("target") or self._target_of(params)
        try:
            _entry, scope, _g = self._gate(
                username, connector, action, target,
                approval.get("work_ref") or "")
        except GrantRefused as exc:
            return exc.outcome()
        token = self._mint(username, connector, action, scope,
                           params, approval.get("work_ref") or "",
                           approval_id=approval["id"])
        return {"status": "authorized", "authorization": token,
                "scope": scope, "approval_id": approval["id"]}

    # -- outcome reporting -------------------------------------------------

    def report(self, username: str, token: str, status: str,
               result=None, error: str = "") -> dict:
        """Consume ONE authorization and receipt the outcome the
        agent's host reports. Single-use: a consumed or unknown
        or expired authorization receipts NOTHING and refuses —
        the receipt record stays exactly as truthful as what was
        proven to the platform."""
        with self._authz_lock:
            rec = self._authz.pop(str(token or ""), None)
        if rec is None or rec["username"] != username \
                or rec["expires"] <= time.time():
            return {"status": "refused",
                    "reason": "unknown, consumed or expired "
                              "authorization — no receipt written"}
        if status not in ("executed", "error"):
            status = "error"
            error = error or f"bad reported status {status!r}"
        if status == "executed":
            detail = _bounded_result(result)
        else:
            detail = {"reason": str(error or "connector error")}
        if rec["approval_id"]:
            detail["approval_id"] = rec["approval_id"]
        saved = self._receipt(
            username, rec["scope"], rec["connector"],
            rec["action"], "", rec["work_ref"], status, detail)
        if rec["approval_id"]:
            try:
                self.store.set_approval_receipt(
                    rec["approval_id"], saved["id"])
            except Exception:
                pass
        out = {"status": status, "receipt_id": saved["id"]}
        if status == "executed":
            out["result"] = result
        else:
            out["reason"] = detail["reason"]
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
            f"(class {r['scope'] or '—'}, receipt {r['id']})"
            + (f" → {r['target']}" if r.get("target") else "")
            + (f" [work {r['work_ref']}]" if r.get("work_ref")
               else "")
            + (f" — {extra}" if extra else "")
            + ("" if r.get("verified")
               else " — ⚠ SIGNATURE UNVERIFIED"))
    lines.append("")
    return "\n".join(lines)
