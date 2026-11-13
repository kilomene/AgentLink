"""Operator provisioning grants (v2.6.0, SPEC Part 2) — the
operator CLI's client half.

`agentlink operator provisioning issue --username <u>
[--ttl-hours N]` and `... revoke --username <u>` call the
oversight Edge's operator routes (provisioning_issue /
provisioning_revoke on agentlink-oversight, built by WS-B).
Those routes ride the oversight function's own operator auth —
checked server-side immediately before the operator acts: a
valid dashboard session token OR an operator JWT (HS256,
operator claim) presented as Bearer. There is no lesser door
and no client-side precedent for holding that credential, so
this CLI reads it the way the Edge expects it:

  AGENTLINK_OPERATOR_TOKEN — a dashboard session token or an
  operator JWT, held in the operator's environment only. It is
  sent as the Bearer header and as the body's session_token
  (the two shapes the oversight function accepts), and it is
  NEVER printed, logged, or written to disk by this module.

Issue returns the raw provisioning grant EXACTLY ONCE (only its
SHA-256 is stored server-side); the CLI prints it once, with
handling instructions, and keeps no copy. Revoke voids
unconsumed grants for the username (or one grant by id).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from . import proxycreds
from .protocol import normalize_username
from .transport_v2 import ServerlessConfig

OPERATOR_TOKEN_ENV = "AGENTLINK_OPERATOR_TOKEN"


class OperatorError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _operator_token() -> str:
    token = os.environ.get(OPERATOR_TOKEN_ENV) or ""
    if not token:
        raise OperatorError(
            "operator_credential_missing",
            f"set {OPERATOR_TOKEN_ENV} to a dashboard session "
            f"token or operator JWT for the oversight Edge — "
            f"the credential the oversight function itself "
            f"checks (dashboard session or operator claim); "
            f"there is no other door")
    return token


def oversight_call(action: str, payload: dict | None = None,
                   timeout: float = 30.0) -> dict:
    """One operator act on the agentlink-oversight Edge. Rides
    the hardened proxy-racing opener like every other client
    call. Raises OperatorError with the server's named fault
    on any refusal — never a silent success."""
    token = _operator_token()
    cfg = ServerlessConfig.from_env()
    url = cfg.supabase_url + "/functions/v1/agentlink-oversight"
    body = {"action": action, **(payload or {}),
            "session_token": token}
    data = json.dumps(body).encode()
    last: Exception | None = None
    for attempt in range(5):
        req = urllib.request.Request(
            url, data=data, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {token}"})
        try:
            with proxycreds.open_url(req, timeout=timeout) as resp:
                raw, status = resp.read(), resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
            try:
                raw = exc.read()
            except Exception:
                raw = b""
        except Exception as exc:  # transport weather — retry
            last = exc
            raw, status = b"", 0
        if status == 407 or (status and not raw) or status == 0:
            proxycreds.reset_winner()
            last = OperatorError(
                "proxy_window",
                f"attempt {attempt + 1}: HTTP {status} no body")
            if attempt + 1 < 5:
                time.sleep(min(20.0, 1.5 * (2 ** attempt)))
            continue
        try:
            out = json.loads(raw.decode() or "{}")
        except Exception:
            out = {"raw": raw.decode(errors="replace")[:300]}
        if status != 200 or out.get("error"):
            raise OperatorError(
                str(out.get("error") or f"http_{status}"),
                str(out.get("detail") or out)[:300])
        return out
    raise OperatorError("unreachable",
                        f"oversight Edge unreachable: {last}")


def provisioning_issue(username: str,
                       ttl_hours: int | None = None) -> dict:
    """Issue a one-time provisioning grant for a NEW username.
    The reply carries the raw token ONCE (``provisioning_grant``
    in the returned dict) — the caller prints it once and keeps
    no copy."""
    uname = normalize_username(username)
    if uname is None:
        raise OperatorError("invalid_username",
                            f"bad username {username!r}")
    payload: dict = {"username": uname}
    if ttl_hours is not None:
        payload["ttl_hours"] = int(ttl_hours)
    return oversight_call("provisioning_issue", payload)


def provisioning_revoke(username: str | None = None,
                        grant_id: str | None = None) -> dict:
    """Revoke unconsumed provisioning grants — by username
    (every open grant for the name) or by grant id."""
    payload: dict = {}
    if grant_id:
        payload["grant_id"] = str(grant_id)
    if username:
        uname = normalize_username(username)
        if uname is None:
            raise OperatorError("invalid_username",
                                f"bad username {username!r}")
        payload["username"] = uname
    if not payload:
        raise OperatorError(
            "invalid_request",
            "revoke needs a username or a grant id")
    return oversight_call("provisioning_revoke", payload)
