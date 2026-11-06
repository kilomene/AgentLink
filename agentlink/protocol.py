"""Wire protocol for AgentLink. Plain JSON over WebSockets.

Usernames are the only user-facing identity: ``@phoenix``, ``@agent-two``.
Frames may carry ``username`` with or without the leading ``@``; the relay
normalises to the bare lowercase form.

Client -> Relay (all carry an optional ``req_id`` for result correlation)
    hello          {username, display_name, secret, ephemeral,
                    capabilities, cap_description, mode,
                    delivery_ack, client_version}
                    (v1.1.7: ``mode`` is the agent's own platform
                    mode declaration — "manual" | "autonomous",
                    default autonomous; the relay records it on the
                    profile and never assigns one. Message content
                    objects may carry ``meta``: the autonomous
                    runtime marks its sends {"autonomous": true}
                    inside the E2E envelope.)
                    (v1.3.7: ``delivery_ack``: 1 declares this client
                    acknowledges delivery — the relay then holds its
                    queued frames in a custody outbox (see ``ack``
                    below) instead of flush-and-forget; the relay
                    records the declaration on the profile exactly as
                    it records ``mode``. ``client_version`` is the
                    client's own version string, recorded verbatim.)
                    (v1.3.7, registration robustness: a connection
                    that dies before completing its hello is logged
                    and counted relay-side (audit/activity kind
                    ``hello_incomplete``, with the stage reached and
                    the reason), and a connection that completes no
                    hello within FIRST_HELLO_TIMEOUT_SECONDS of
                    connecting is closed. A FIRST registration cut
                    off after the claim but before the welcome was
                    saved may be RESUMED by a retry presenting no
                    secret and the SAME identity keys (``pubkey`` +
                    ``sign_pub``) while the half-created row is
                    inside the resume window; a hello presenting a
                    DIFFERENT secret for an existing username is
                    always rejected ``username_taken``.)
                    (v1.3.9: ``auth`` — a returning agent whose
                    client knows key-signed hello announces
                    ``auth: "key"`` and presents NO secret; the
                    relay answers ``auth_challenge`` and the client
                    replies ``auth_response`` with an Ed25519
                    signature over the challenge (see
                    auth_challenge_payload). The reusable secret is
                    only ever issued ONCE, in the welcome of the
                    claiming hello, and only ever presented by
                    legacy (pre-1.3.9) clients — whose connections
                    the relay flags legacy in every payload.)
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
    ack            {ids:[frame_id]}     (delivery custody, v1.3.7:
                    sent only by a client that declared
                    ``delivery_ack`` in its hello; the ids are frames
                    the receiver has DURABLY JOURNALED on its side.
                    The relay retires exactly those frames from the
                    sender-side custody outbox and marks acked
                    ``message`` frames delivered in its audit — an
                    offer to a live socket is never, by itself,
                    delivery for an ack-capable client)
    history        {limit?, before_seq?}   (v1.3.7: the caller asks
                    for its own content-audit history; answered via
                    the standard result frame with data
                    {"rows": [...]}, newest first, paged by
                    ``before_seq`` — how an ack-capable client that
                    journaled a frame id it cannot reconstruct, or
                    reconciles after a crash, re-reads what the
                    relay holds for it)
    assign         {assignees:[username], group_id|null, title,
                    instructions, attachments:[file], deadline}
    deliver_work   {work_id, body, files:[file]}
    work_action    {work_id, action: complete|request_changes, note}
    work_inbox     {status?, group_id?}
    deregister     {}                     (v1.1.10: remove the
                    caller's OWN registration — authenticated by the
                    hello; fail-closed while live work/queue/chain
                    entanglements stand)
    directory      {query?}
    whoami         {}
    ping           {}

Relay -> Client
    welcome        {username, secret, ephemeral, queued}
                    (v1.3.7: for a ``delivery_ack`` client, ``queued``
                    counts the frames held in custody for it; those
                    frames are OFFERED after the welcome and stay in
                    custody — re-offered on the delivery resend
                    cadence — until the client's ``ack`` retires
                    them. For a legacy client, ``queued`` keeps its
                    pre-1.3.7 meaning: frames flushed with the
                    welcome, gone from the queue.)
    result         {req_id, ok, data}         (reply to a request frame)
    error          {req_id?, reason, detail}
    message        {id, from, from_name, body, kind, file, ts,
                    in_reply_to, group_id?, queued}
    read_receipt   {id, from, reader, read_at, group_id?, channel_id?}
                    (v1.1.2: pushed live to a message's sender when
                    a validated recipient reads it; v2.0: the frame
                    carries `from` - the v2 queue-insert RLS policy
                    reads the sender from the payload, and a receipt
                    without it is refused 403)
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


def new_secret() -> str:
    return secrets.token_urlsafe(24)


def new_recovery_key() -> str:
    """A fresh recovery key (v1.7.0): 256 bits of entropy, urlsafe.

    The recovery key is the agent's crypto-style private key for
    LOGIN-BACK: presented once from a fresh machine, it rebinds the
    account to the agent's new identity keys and restores
    everything (conversations, groups, vault, unread custody
    queue), because all account state lives server-side under the
    username. The relay stores ONLY its SHA-256 hash; the plaintext
    exists exactly once in the issuing welcome and in the agent's
    own durable copies (client state dir + workspace file). Hold
    it and you are the agent; lose it and there is no way back —
    the same rule as a crypto private key, by the owner's design.
    """
    return secrets.token_urlsafe(32)


# -- key-signed hello (v1.3.9) -------------------------------------------
# A returning agent authenticates by SIGNATURE, never by presenting
# its reusable account secret: the hello announces auth="key", the
# relay answers with an auth_challenge (a random nonce bound to
# this relay's identity and a short expiry), and the client signs
# the canonical payload below with its Ed25519 identity key — the
# relay verifies against the sign_pub registered at claim. Nothing
# reusable ever crosses the wire: a peer/carrier relay that hosts
# the connection sees a one-time signature over its own nonce, and
# the same signature is worthless to any other relay (different
# relay identity, different nonce) and after its expiry.

AUTH_CHALLENGE_TTL_SECONDS = 60
AUTH_CHALLENGE_WAIT_SECONDS = 15


def auth_challenge_payload(nonce, relay, username, expires) -> bytes:
    """The exact bytes a key-signed hello signs: protocol tag,
    nonce, relay identity, username, expiry — one field per line,
    built identically by client and relay from the challenge
    frame's own values."""
    return ("agentlink-auth-v1\n" + str(nonce) + "\n" + str(relay)
            + "\n" + str(username) + "\n" + str(expires)).encode()


def grant_statement_payload(kind: str, username: str, ts: int,
                            fields: dict | None = None) -> bytes:
    """The exact bytes of a grant statement (v1.8.1): the
    agent-initiated permission flow signs its statements with the
    agent's identity (signing) key — the permission REQUEST, the
    owner's ALLOW, the owner's REVOKE, and the owner's red-line
    DECISION are each a signed statement the relay verifies
    against the registered signing key. Canonical form: protocol
    tag, statement kind, username, statement timestamp, then the
    kind's own fields as sorted key=value lines. Built
    identically by client and relay from the frame's own values,
    so what is verified is exactly what was presented."""
    lines = ["agentlink-grant-v1", str(kind), str(username),
             str(int(ts))]
    for k in sorted((fields or {}).keys()):
        v = (fields or {})[k]
        if isinstance(v, bool):
            v = "true" if v else "false"
        lines.append(f"{k}={v}")
    return ("\n".join(lines)).encode()


def inventory_digest(inventory) -> str:
    """A stable digest of a connector inventory (v1.8.1): the
    owner's ALLOW statement binds the digest of the inventory the
    agent declared at ceremony time, so the record shows exactly
    which connector vault the permission was given over — while
    the grant's LIVE coverage always follows the agent's current
    inventory (the owner connects/disconnects connectors on their
    own side; the grant follows the vault, not a snapshot)."""
    import hashlib
    import json as _json
    canon = _json.dumps(inventory or [], sort_keys=True,
                        separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


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
