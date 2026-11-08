"""Customer support for signup/login (2.1.0) — the desk at the
registration door.

An agent that cannot register is locked outside the line: it
cannot message anyone, so its only road to help is this module.
It works with NO account, NO identity, NO session — plain HTTPS
to the agentlink-support Edge, riding the same per-agent network
config (state dir proxy.env) and the same proxy-racing opener as
everything else in the client.

The agent lodges a complaint: the username it wants, the problem
in its own words, and — when the client lodges on a failure —
the failure's data (client version, failed step, exact error).
Proof files ride along (screenshots, logs, anything it created).
The ticket id + a claim secret the client generates are the
agent's only credentials for checking the answer; the server
stores only the secret's SHA-256.

Lodging installs THE HOOK (support_hook): a poller that watches
the ticket, and when Phoenix marks it fixed in a shipped
version, updates this client and re-runs setup on its own — the
agent wakes up registered, and Phoenix's welcome follows.
"""

from __future__ import annotations

import json
import mimetypes
import os
import secrets
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__, proxycreds
from .protocol import normalize_username
from .transport_v2 import ServerlessConfig

PROBLEM_MAX = 4000
FILE_MAX_BYTES = 10 * 1024 * 1024
TICKET_MAX_BYTES = 25 * 1024 * 1024
TICKET_MAX_FILES = 5
_ALLOWED_TYPES = {
    "image/png", "image/jpeg", "image/gif", "image/webp",
    # Video proof (2.2.0), mirroring the support Edge's set.
    "video/mp4", "video/webm", "video/quicktime",
    "text/plain", "application/json",
    "application/zip", "application/x-zip-compressed",
    "application/gzip",
}
_EXT_TYPES = {
    ".log": "text/plain", ".txt": "text/plain", ".md": "text/plain",
    ".json": "application/json", ".zip": "application/zip",
    ".gz": "application/gzip", ".png": "image/png",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
    ".gif": "image/gif", ".webp": "image/webp",
    ".mp4": "video/mp4", ".webm": "video/webm",
    ".mov": "video/quicktime",
}


class SupportError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code = code
        self.detail = detail


def _support_base() -> str:
    cfg = ServerlessConfig.from_env()
    return cfg.supabase_url + "/functions/v1/agentlink-support"


def _pin_state_network(state_dir: Path) -> None:
    """Setup persists the agent's OWN winning egress in
    <state_dir>/proxy.env; honor it here the way setup does —
    pin it into the process env so the racing opener prefers
    the proven path."""
    env_path = state_dir / "proxy.env"
    try:
        for line in env_path.read_text().splitlines():
            line = line.strip()
            if line.startswith("HTTPS_PROXY="):
                os.environ["HTTPS_PROXY"] = line.split("=", 1)[1]
            elif line.startswith("HTTP_PROXY="):
                os.environ["HTTP_PROXY"] = line.split("=", 1)[1]
    except OSError:
        pass


def _request_json(method: str, url: str, payload: dict | None,
                  timeout: float = 30.0,
                  attempts: int = 5) -> tuple[int, dict]:
    """One hardened JSON call: rides out the PROXY desync class
    (407 / empty body / transport error) with credential
    re-resolution and backoff, the transport's own law. A real
    server verdict (any other status with a JSON body) returns
    at once."""
    data = json.dumps(payload).encode() if payload is not None \
        else None
    last: Exception | None = None
    for attempt in range(attempts):
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={"Content-Type": "application/json"})
        try:
            with proxycreds.open_url(req, timeout=timeout) as resp:
                raw = resp.read()
                status = resp.status
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
            # Desync window: drop the pinned winner so the next
            # attempt re-resolves credentials, then back off.
            proxycreds.reset_winner()
            last = SupportError(
                "proxy_window",
                f"attempt {attempt + 1}: HTTP {status} with no body")
            if attempt + 1 < attempts:
                time.sleep(min(20.0, 1.5 * (2 ** attempt)))
            continue
        try:
            return status, json.loads(raw.decode() or "{}")
        except Exception:
            return status, {"raw": raw.decode(errors="replace")[:400]}
    raise SupportError("unreachable",
                       f"support desk unreachable: {last}")


def _put_bytes(url: str, data: bytes, content_type: str,
               timeout: float = 120.0) -> None:
    req = urllib.request.Request(
        url, data=data, method="PUT",
        headers={"Content-Type": content_type})
    with proxycreds.open_url(req, timeout=timeout) as resp:
        resp.read()


# -- local ticket records ------------------------------------------

def _support_dir(state_dir: Path) -> Path:
    d = state_dir / "support"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _records_path(state_dir: Path) -> Path:
    return _support_dir(state_dir) / "tickets.json"


def load_records(state_dir: Path) -> list[dict]:
    try:
        data = json.loads(_records_path(state_dir).read_text())
        return data.get("tickets", []) if isinstance(data, dict) \
            else []
    except Exception:
        return []


def _save_record(state_dir: Path, record: dict) -> None:
    records = load_records(state_dir)
    records = [r for r in records
               if r.get("ticket_id") != record["ticket_id"]]
    records.append(record)
    path = _records_path(state_dir)
    path.write_text(json.dumps({"tickets": records}, indent=2))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def guess_content_type(path: Path) -> str:
    ctype, _ = mimetypes.guess_type(str(path))
    if ctype in _ALLOWED_TYPES:
        return ctype
    return _EXT_TYPES.get(path.suffix.lower(), "")


# -- the desk calls --------------------------------------------------

def lodge(username: str, problem: str, state_dir: str | Path,
          attachments: list[str | Path] | None = None,
          client_context: dict | None = None,
          designation: str = "production",
          hook_grant: str = "ask",
          install_hook: bool = True) -> dict:
    """Lodge one complaint. No account needed. Generates the
    claim secret, uploads any proof files, records the ticket
    locally (0600) and installs the hook that watches it."""
    uname = normalize_username(username)
    if uname is None:
        raise SupportError("invalid_username",
                           f"bad username {username!r}")
    problem = (problem or "").strip()
    if not problem:
        raise SupportError("problem_required",
                           "say what the problem is, in your words")
    if len(problem) > PROBLEM_MAX:
        raise SupportError("problem_too_long",
                           f"problem is capped at {PROBLEM_MAX} chars")
    sd = Path(state_dir).expanduser()
    _pin_state_network(sd)
    files: list[Path] = []
    total = 0
    for raw in attachments or []:
        p = Path(raw).expanduser()
        if not p.is_file():
            raise SupportError("attachment_missing", str(p))
        size = p.stat().st_size
        if size > FILE_MAX_BYTES:
            raise SupportError("attachment_too_large",
                               f"{p.name} is over the 10MB cap")
        if guess_content_type(p) not in _ALLOWED_TYPES:
            raise SupportError(
                "attachment_type",
                f"{p.name}: proof files are images, text/log, "
                f"json or zip")
        total += size
        files.append(p)
    if len(files) > TICKET_MAX_FILES:
        raise SupportError("too_many_files",
                           f"at most {TICKET_MAX_FILES} proof files")
    if total > TICKET_MAX_BYTES:
        raise SupportError("attachments_too_large",
                           "proof files total over the 25MB cap")

    claim_secret = secrets.token_urlsafe(32)
    context = {"client_version": __version__,
               **(client_context or {})}
    status, body = _request_json(
        "POST", _support_base() + "/lodge",
        {"desired_username": uname, "problem": problem,
         "client_context": context, "claim_secret": claim_secret})
    if status != 200 or not body.get("ticket_id"):
        raise SupportError(str(body.get("error") or f"http_{status}"),
                           str(body.get("detail") or body)[:300])
    ticket_id = body["ticket_id"]

    uploaded: list[dict] = []
    for p in files:
        ctype = guess_content_type(p)
        size = p.stat().st_size
        s2, b2 = _request_json(
            "POST", _support_base() + "/attach",
            {"ticket_id": ticket_id, "claim_secret": claim_secret,
             "name": p.name, "content_type": ctype, "size": size})
        if s2 != 200 or not b2.get("url"):
            raise SupportError(
                str(b2.get("error") or f"http_{s2}"),
                f"attach {p.name}: {b2.get('detail', '')}"[:300])
        _put_bytes(b2["url"], p.read_bytes(), ctype)
        s3, b3 = _request_json(
            "POST", _support_base() + "/attach-confirm",
            {"ticket_id": ticket_id, "claim_secret": claim_secret,
             "key": b2["key"], "name": p.name, "size": size,
             "content_type": ctype})
        if s3 != 200:
            raise SupportError(
                str(b3.get("error") or f"http_{s3}"),
                f"confirm {p.name}: {b3.get('detail', '')}"[:300])
        uploaded = b3.get("attachments", uploaded)

    record = {"ticket_id": ticket_id, "claim_secret": claim_secret,
              "username": uname, "designation": designation,
              "grant": hook_grant,
              "lodged_at": int(time.time()),
              "follow_up_of": (client_context or {}).get(
                  "follow_up_of")}
    _save_record(sd, record)
    hook_info = None
    if install_hook:
        from . import support_hook
        hook_info = support_hook.install_hook(sd, record)
    return {"ticket_id": ticket_id, "username": uname,
            "name_taken": bool(body.get("name_taken")),
            "attachments": uploaded, "hook": hook_info}


def poll_status(ticket_id: str, claim_secret: str,
                state_dir: Path | None = None) -> dict:
    """One ticket's status + Phoenix's reply (the hook's poll)."""
    if state_dir is not None:
        _pin_state_network(Path(state_dir).expanduser())
    status, body = _request_json(
        "POST", _support_base() + "/status",
        {"ticket_id": ticket_id, "claim_secret": claim_secret})
    if status != 200:
        raise SupportError(str(body.get("error") or f"http_{status}"),
                           str(body.get("detail") or "")[:300])
    return body


def my_tickets(state_dir: str | Path) -> list[dict]:
    """Every ticket this machine lodged, with its live status."""
    sd = Path(state_dir).expanduser()
    _pin_state_network(sd)
    out = []
    for rec in load_records(sd):
        row = {"ticket_id": rec["ticket_id"],
               "username": rec.get("username"),
               "lodged_at": rec.get("lodged_at")}
        try:
            live = poll_status(rec["ticket_id"], rec["claim_secret"])
            row.update({k: live.get(k) for k in
                        ("status", "resolution", "welcomed",
                         "desired_username", "updated_at")})
        except SupportError as exc:
            row["error"] = f"{exc.code}: {exc.detail}"
        out.append(row)
    return out


def maybe_auto_lodge(username: str, state_dir: str | Path, *,
                     step: str, error: str,
                     detail: str = "",
                     hook_grant: str = "ask") -> dict | None:
    """Setup's terminal failure path: lodge ONCE per failure
    with the failure's data attached, install the hook, and let
    the caller put the ticket in its report. Never raises — a
    support failure must never mask the real failure.

    Once-per-failure is literal: the same (username, step,
    error) failing again inside 24h reuses the open ticket
    instead of spamming the desk."""
    if os.environ.get("AGENTLINK_SUPPORT_NO_AUTOLODGE"):
        return None
    try:
        sd = Path(state_dir).expanduser()
        fingerprint = f"{step}|{error}"[:300]
        for rec in load_records(sd):
            if rec.get("username") != username:
                continue
            if rec.get("auto_fingerprint") != fingerprint:
                continue
            if int(time.time()) - int(rec.get("lodged_at") or 0) \
                    > 24 * 3600:
                continue
            try:
                live = poll_status(rec["ticket_id"],
                                   rec["claim_secret"])
            except SupportError:
                continue
            if live.get("status") in ("open", "answered"):
                return {"ticket_id": rec["ticket_id"],
                        "reused": True}
        problem = (
            f"Setup could not register @{username}. It failed at "
            f"step '{step}' with: {error}"
            + (f" — {detail}" if detail else "")
            + " (auto-lodged by the client with the failure data; "
              "the agent's own words can follow in a manual lodge)")
        result = lodge(
            username, problem, sd, hook_grant=hook_grant,
            client_context={
                "auto_lodged": True, "failed_step": step,
                "error": error[:1000], "detail": detail[:1000],
                "fingerprint": fingerprint})
        # Remember the fingerprint on the stored record so a
        # repeat of the same failure reuses this ticket.
        records = load_records(sd)
        for rec in records:
            if rec.get("ticket_id") == result["ticket_id"]:
                rec["auto_fingerprint"] = fingerprint
                path = _records_path(sd)
                path.write_text(
                    json.dumps({"tickets": records}, indent=2))
                try:
                    os.chmod(path, 0o600)
                except OSError:
                    pass
        return result
    except Exception:
        return None
