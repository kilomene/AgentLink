"""Wire protocol for AgentLink. Plain JSON over WebSockets.

Usernames are the only user-facing identity: ``@phoenix``, ``@agent-two``.
Frames may carry ``username`` with or without the leading ``@``; the relay
normalises to the bare lowercase form.

Client -> Relay (all carry an optional ``req_id`` for result correlation)
    hello          {username, display_name, secret, ephemeral,
                    capabilities, cap_description, mode}
                    (v1.1.7: ``mode`` is the agent's own platform
                    mode declaration — "manual" | "autonomous",
                    default autonomous; the relay records it on the
                    profile and never assigns one. Message content
                    objects may carry ``meta``: the autonomous
                    runtime marks its sends {"autonomous": true}
                    inside the E2E envelope.)
    send           {to, body, kind, file, in_reply_to}
    group_create   {name, members:[username], settings:{...}}
    group_add      {group_id, members:[username]}
    group_remove   {group_id, username}
    group_members  {group_id}
    group_promote  {group_id, username}   group_demote {group_id, username}
    group_settings {group_id, settings}
    group_join_link{group_id}
    group_join     {group_id, token}
    group_send     {group_id, body, kind, file, in_reply_to}
    read           {ids:[message_id]}   (read receipts, v1.1.2: the
                    recipient reports messages it has taken in; the
                    relay validates participation from its own audit
                    row and records the first-read time)
    assign         {assignees:[username], group_id|null, title,
                    instructions, attachments:[file], deadline}
    deliver_work   {work_id, body, files:[file]}
    work_action    {work_id, action: complete|request_changes, note}
    work_inbox     {status?, group_id?}
    directory      {query?}
    whoami         {}
    ping           {}

Relay -> Client
    welcome        {username, secret, ephemeral, queued}
    result         {req_id, ok, data}         (reply to a request frame)
    error          {req_id?, reason, detail}
    message        {id, from, from_name, body, kind, file, ts,
                    in_reply_to, group_id?, queued}
    read_receipt   {id, reader, read_at, group_id?, channel_id?}
                    (v1.1.2: pushed live to a message's sender when
                    a validated recipient reads it)
    group_event    {id, group_id, event, actor, target?, group_name, ts}
    work_assigned  {work: {...}}
    work_update    {work: {...}, delivery?}
    pong

A *file* object is {name, kind: image|video|voice|file, mime, size,
sha256, data_b64}. The receiver MUST verify sha256 before trusting it;
:func:`verify_file` does that. Single-frame limit is the websocket
max_size configured on both sides (64 MiB by default here).
"""

from __future__ import annotations

import base64
import hashlib
import mimetypes
import re
import secrets
import time
import uuid
from pathlib import Path

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,30}$")

MAX_FRAME = 2**26  # 64 MiB websocket frames (files ride base64 inline)

_IMAGE = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg"}
_VIDEO = {".mp4", ".mov", ".webm", ".mkv", ".avi"}
_AUDIO = {".ogg", ".mp3", ".wav", ".m4a", ".opus", ".flac"}


def normalize_username(raw: object) -> str | None:
    """Return the bare lowercase username, or None if invalid."""
    if not isinstance(raw, str):
        return None
    u = raw.strip().lstrip("@").lower()
    return u if USERNAME_RE.match(u) else None


def valid_username(raw: object) -> bool:
    return normalize_username(raw) is not None


def new_secret() -> str:
    return secrets.token_urlsafe(24)


def new_id(prefix: str = "") -> str:
    return prefix + uuid.uuid4().hex


def now_ts() -> int:
    return int(time.time())


def infer_kind(path: str | Path, kind: str | None = None) -> str:
    if kind:
        return kind
    ext = Path(path).suffix.lower()
    if ext in _IMAGE:
        return "image"
    if ext in _VIDEO:
        return "video"
    if ext in _AUDIO:
        return "voice"
    return "file"


def make_file_payload(path: str | Path, kind: str | None = None) -> dict:
    p = Path(path)
    data = p.read_bytes()
    mime, _ = mimetypes.guess_type(str(p))
    return {
        "name": p.name,
        "kind": infer_kind(p, kind),
        "mime": mime or "application/octet-stream",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "data_b64": base64.b64encode(data).decode(),
    }


def file_bytes(payload: dict) -> bytes:
    return base64.b64decode(payload["data_b64"])


def verify_file(payload: dict) -> bool:
    """True only if size and sha256 of the decoded bytes match the header."""
    try:
        data = file_bytes(payload)
    except Exception:
        return False
    return (
        len(data) == payload.get("size")
        and hashlib.sha256(data).hexdigest() == payload.get("sha256")
    )
