"""Firebase Realtime Database live layer for AgentLink v2.0+.

RTDB is the LIVE layer (owner-ratified split architecture,
2026-11-09 — see ``V2-BLUEPRINT.md`` and the 2.3.0 design record):
signals, presence/activeness, doorbell taps, the message TRANSIT
queue (inbox), typing/work signals and the directory working copy
live here. Content in transit is the caller's E2EE envelope —
ciphertext this module never opens. The DURABLE record stays in
Supabase: the journal/ACK custody in ``al_queue`` and the permanent
archive in ``al_audit_log`` are the delivery guarantee for standard
messages — Firebase may lose every signal and every transit copy
and nothing standard is lost, because a receiver that wakes (or
reconnects) reconciles against its unacked Supabase queue, on a
signal, never on a poll. DISAPPEARING messages are the one
exception by design: they ride the transit queue ONLY, expire, and
are never archived anywhere.

Structure (see ``firebase/database.rules.json`` and
``firebase/README.md``)::

    /signals/<conversation_key>  = {latest_item_id, counter, ts}
    /presence/<user_key>         = {state, ts, connected_at,
                                    client_version, transport}
    /doorbell/<user_key>         = {kind, ref, ts}
    /inbox/<user_key>/<item_id>  = {frame, expires_at, ts}
    /directory/<user_key>        = {username, pubkey, sign_pub,
                                    capabilities, cap_desc,
                                    designation, mode, updated_at}

Keys: RTDB keys may not contain ``. $ # [ ] /`` (or control chars),
while AgentLink conversation ids look like ``dm:alice|bob`` and
usernames may contain ``.``. :func:`sanitize_key` percent-encodes
every unsafe byte, so the mapping is deterministic and reversible;
the SAME sanitized form is the Firebase custom-token ``uid`` (the
login Edge function mints the token with ``uid = sanitize_key(
username)``), which is what makes the rules' ``auth.uid === $user``
checks line up with the node keys.

Auth: this client holds a Firebase *custom token* (minted by the
login Edge function) and exchanges it for an ID token through the
Identity Toolkit REST API (``accounts:signInWithCustomToken``),
refreshing through the Secure Token API. The API key comes from
configuration — it is a public client identifier, never a secret —
and nothing in this module ever sees a service key or a service
account credential. The Admin SDK / service account bypasses RTDB
rules entirely; that path belongs to the Edge outbox tapper, never
to an agent.

=================================================================
ACTIVENESS (2.3.0 — the owner-ratified connection-based ladder,
2026-11-09; SUPERSEDES the 2026-11-05 hyper-sensitive 5s law,
which the owner himself flagged as a quota-eater)
=================================================================

Presence is CONNECTION-based: the connection is the presence fact.
Three presence signals ride the ONE node ``/presence/<user_key>``:

(a) **Connection + disconnect.** The connect write (below) marks
    the agent online; a CLEAN shutdown writes ``state: "offline"``
    itself before exiting (``clear_presence``) — offline instantly,
    at any beat age. Where a client holds the native Firebase SDK,
    ``onDisconnect`` writes the same offline record server-side the
    moment its socket dies. This REST client cannot register a
    true ``onDisconnect`` (the REST API exposes no disconnect
    hook); its honest bound for an UNCLEAN death (kill, freeze,
    power loss) is the ladder: the last server-timestamped beat
    ages out and every reader converges on "offline" within
    SUSPECT_MAX_AGE_S + one read (~7 minutes). That bound — not
    the old 15 seconds — is the trade the owner ratified when he
    ordered the metronome stopped: presence costs almost nothing,
    and unclean-death detection is minutes, not seconds.

(b) **Heartbeat beats.** An explicit health-proof beat every
    :data:`BEAT_INTERVAL_S` (180s), server-timestamped
    (``{".sv": "timestamp"}``), from an INDEPENDENT thread owned
    by this module — never from a message/work loop, so a stuck
    worker cannot stop the beats (and a frozen process, whose
    socket may linger, is caught precisely because its beats
    stop). Beats touch RTDB ONLY: nothing periodic ever reaches
    Edge or PostgREST — and since 2.3.0 nothing periodic reaches
    Postgres either (the activeness mirror is deleted; presence
    lives here alone).

(c) **Connection metadata** on the same node: ``connected_at``
    (server timestamp of the connect), ``client_version`` and
    ``transport`` — written at connect, carried by every beat's
    merged node.

THE LADDER — :func:`activeness_state` in this module is the
single source of truth::

    disconnect fired (stored offline)              -> "offline"
    beat age <= ONLINE_MAX_AGE_S  (240s)           -> "online"
    beat age <= SUSPECT_MAX_AGE_S (420s)           -> "suspect"
    older                                          -> "offline"

"suspect" is a DISTINCT state, never folded into either side:
the agent may be mid-reconnect; work must not be reassigned on
suspect alone.

Scoped presence subscriptions: an agent watches ONLY its
counterparties (DM partners, group/channel co-members, current
assigners/assignees) — never the whole fleet; only the dashboard
subscribes fleet-wide. :class:`ScopedPresenceWatcher` takes a
provider callable returning the current counterparty username
set and keeps one presence stream per counterparty path,
re-scoping (adding/removing paths) whenever the provider's set
changes. If quota math ever demands fan-out relief, the valve
lives HERE, in this subscription layer — own-node beats are
already at the ratified 180s cadence and are not a valve.
"""

from __future__ import annotations

import http.client
import json
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import proxycreds

__all__ = [
    "BEAT_INTERVAL_S",
    "DIGEST_EVERY_N_BEATS",
    "DIGEST_INTERVAL_S",
    "ONLINE_MAX_AGE_S",
    "SUSPECT_MAX_AGE_S",
    "ACTIVENESS_STATES",
    "DIRECTORY_FIELDS",
    "INBOX_FIELDS",
    "DoorbellClient",
    "DoorbellError",
    "ScopedPresenceWatcher",
    "activeness_of_record",
    "activeness_state",
    "build_counterparty_set",
    "conversation_id_for_channel",
    "conversation_id_for_dm",
    "conversation_id_for_group",
    "presence_is_online",
    "sanitize_key",
    "unsanitize_key",
    "user_key",
]

# -- the activeness ladder (SINGLE SOURCE OF TRUTH) ----------------
#: Heartbeat cadence: one health-proof beat write to my OWN
#: presence node every 180 seconds (2.3.0, owner-ratified: the
#: connection is the presence fact; the beat only proves the
#: process still lives. Was 5s under the 2026-11-05 law, which
#: the owner retired as a quota-eater on 2026-11-09.) RTDB only.
BEAT_INTERVAL_S = 180
#: Beat age at or below this (one beat + 60s grace) reads "online".
ONLINE_MAX_AGE_S = 240
#: Beat age at or below this (two beats + grace) reads "suspect";
#: beyond it, or on a fired disconnect, the agent reads "offline".
SUSPECT_MAX_AGE_S = 420

#: Read timeout on a live event stream's socket. RTDB holds an
#: idle stream open with periodic keep-alive events, so a healthy
#: stream produces a line far more often than this; a stream that
#: has produced NOTHING for this long is not quiet, it is
#: half-open — the path died silently (an egress proxy desync can
#: eat the connection without surfacing an error) and no event
#: will ever arrive on it again. The timeout converts that silent
#: death into an ordinary stream failure: the supervisor
#: reconnects and slow-sync engages, so delivery degrades to the
#: 60s fallback instead of stalling forever while presence — on
#: its independent REST beats — stays green. (Before 2.0.6 the
#: stream opener CLEARED the socket timeout entirely, on the
#: theory that the listen loop's reconnect covers drops; a
#: half-open stream never drops, it just never speaks. Found live
#: in the 2.0.6 exercise, 2026-11-06.)
STREAM_READ_TIMEOUT_S = 90

#: The fan-out valve: raw presence fan-out at circle-10 would
#: download ~19.9 GB/mo against the 10 GB free tier at the old 5s
#: cadence, so every client ALSO maintains a coalesced digest node
#: (/digest/<user_key>). Peers subscribed to the digest download a
#: fraction of the raw stream; activeness-critical counterparties
#: stay on raw presence. Since 2.3.0 the beat itself rides the
#: 180s cadence, so the digest refreshes once per beat
#: (DIGEST_INTERVAL_S == BEAT_INTERVAL_S) — the valve's relief is
#: now mostly the raw-fan-out avoidance, and a digest record still
#: carries the same {state, ts} shape, so activeness_of_record
#: reads it unchanged.
DIGEST_INTERVAL_S = 180
DIGEST_EVERY_N_BEATS = DIGEST_INTERVAL_S // BEAT_INTERVAL_S

ACTIVENESS_STATES = ("online", "suspect", "offline")


def activeness_state(beat_age_seconds, disconnect_fired: bool = False) -> str:
    """THE ladder. Pure function; every consumer (client, dashboard,
    sweeps) derives state through these exact boundaries:

    * ``disconnect_fired`` (onDisconnect / explicit offline) wins
      over any age — offline instantly;
    * no beat on record (``None``) is offline;
    * age <= ONLINE_MAX_AGE_S -> "online";
    * age <= SUSPECT_MAX_AGE_S -> "suspect" (distinct state);
    * anything older -> "offline".

    Negative ages (clock skew between writer and reader) clamp to
    online: a beat from the near future is fresh by any measure.
    """
    if disconnect_fired:
        return "offline"
    if beat_age_seconds is None:
        return "offline"
    try:
        age = float(beat_age_seconds)
    except (TypeError, ValueError):
        return "offline"
    if age <= ONLINE_MAX_AGE_S:
        return "online"
    if age <= SUSPECT_MAX_AGE_S:
        return "suspect"
    return "offline"


def _record_ts_ms(record: dict) -> int:
    try:
        ts = int(record.get("ts") or 0)
    except (TypeError, ValueError):
        return 0
    if 0 < ts < 10**12:  # seconds, not milliseconds
        ts *= 1000
    return ts


def activeness_of_record(record, now_ms: int | None = None,
                         disconnect_fired: bool = False) -> str:
    """Ladder state of a stored presence record. A stored
    ``state: "offline"`` IS a fired disconnect (the onDisconnect /
    clean-close write); any other record is judged by beat age."""
    if not isinstance(record, dict):
        return "offline"
    if record.get("state") == "offline":
        return "offline"
    ts_ms = _record_ts_ms(record)
    if ts_ms <= 0:
        return "offline"
    if now_ms is None:
        now_ms = int(time.time() * 1000)
    return activeness_state((now_ms - ts_ms) / 1000.0,
                            disconnect_fired=disconnect_fired)


def presence_is_online(record, now_ms: int | None = None) -> bool:
    """True only at the ladder's TOP rung — suspect is NOT online."""
    return activeness_of_record(record, now_ms=now_ms) == "online"


def build_counterparty_set(dm_peers=(), group_members=(),
                           channel_members=(), assignees=(),
                           assigners=(), exclude=()) -> set:
    """The scoped-subscription set: DM partners + group/channel
    co-members + current assignees/assigners, minus exclusions
    (typically the agent itself). Plain usernames, unsanitized —
    sanitization happens at the path layer."""
    out = set()
    for group in (dm_peers, group_members, channel_members,
                  assignees, assigners):
        for name in group or ():
            if name:
                out.add(str(name))
    for name in exclude or ():
        out.discard(str(name))
    return out


_IDENTITY_URL = ("https://identitytoolkit.googleapis.com/v1/"
                 "accounts:signInWithCustomToken")
_SECURETOKEN_URL = "https://securetoken.googleapis.com/v1/token"

# The ONLY fields a /signals write may carry: ids and counters,
# never content (a signal can only cause a fetch).
SIGNAL_FIELDS = frozenset({"latest_item_id", "counter", "ts"})
DOORBELL_FIELDS = frozenset({"kind", "ref", "ts"})
PRESENCE_FIELDS = frozenset(
    {"state", "ts", "connected_at", "client_version", "transport"})
# The ONLY fields an /inbox transit node may carry (2.3.0): the
# frame is the caller's E2EE envelope dict — ciphertext, never
# opened here — plus its expiry. No plaintext field exists.
INBOX_FIELDS = frozenset({"frame", "expires_at", "ts"})
# The ONLY fields a /directory working-copy entry may carry
# (2.3.0): public directory data only — the Supabase al_directory
# row stays the master record; this is its live-layer copy.
DIRECTORY_FIELDS = frozenset(
    {"username", "pubkey", "sign_pub", "capabilities", "cap_desc",
     "designation", "mode", "updated_at"})

_UNSAFE = frozenset(".$#[]/:| \t\r\n")


class DoorbellError(Exception):
    """Any doorbell-leg failure (auth exchange, REST, stream)."""


def sanitize_key(raw: str) -> str:
    """Map an arbitrary AgentLink id to a safe RTDB key segment.

    Percent-encodes ``%`` itself first, then every character RTDB
    forbids in a key (``. $ # [ ] /``) plus the separators AgentLink
    ids use (``:`` and ``|``) and whitespace/control characters.
    Deterministic and reversible via :func:`unsanitize_key`.
    Example: ``dm:alice|bob`` -> ``dm%3Aalice%7Cbob``.
    """
    out = []
    for ch in str(raw):
        if ch == "%" or ch in _UNSAFE or ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("%%%02X" % ord(ch))
        else:
            out.append(ch)
    return "".join(out)


def unsanitize_key(key: str) -> str:
    """Inverse of :func:`sanitize_key`."""
    out = []
    i = 0
    while i < len(key):
        if key[i] == "%" and i + 3 <= len(key):
            try:
                out.append(chr(int(key[i + 1:i + 3], 16)))
                i += 3
                continue
            except ValueError:
                pass
        out.append(key[i])
        i += 1
    return "".join(out)


def user_key(username: str) -> str:
    """The RTDB node key (and Firebase uid) for a username."""
    return sanitize_key(username)


def conversation_id_for_dm(a: str, b: str) -> str:
    """Canonical DM conversation id: ``dm:<lower>|<higher>`` —
    the same party pair the audit log records as actor/target."""
    lo, hi = sorted([str(a), str(b)])
    return f"dm:{lo}|{hi}"


def conversation_id_for_group(group_id: str) -> str:
    """Group conversation id: the group id itself (the value the
    audit log carries in ``group_id``)."""
    return str(group_id)


def conversation_id_for_channel(channel_id: str) -> str:
    """Channel conversation id: the channel id itself (audit rows
    carry it in ``group_id`` for channel frames)."""
    return str(channel_id)


def conversation_key(conversation_id: str) -> str:
    """RTDB-safe key for a conversation id (see sanitize_key)."""
    return sanitize_key(conversation_id)


def _read_body(resp) -> bytes:
    """Read a response body, tolerating a stream clipped AFTER
    the payload arrived: http.client raises IncompleteRead when
    a chunked response loses its terminating chunk (this host's
    egress proxy does exactly that, intermittently), and the
    exception's .partial carries the bytes that DID arrive —
    the same doctrine blobstore's R2 reader and transport_v2's
    opener follow. Completeness is judged by the body's own
    parser downstream.

    B4 partial-wedge detector (2.4.0, twin of transport_v2's):
    a PROVABLE truncation (Content-Length exceeds the partial
    bytes) raises instead of returning clipped bytes as if
    they were the payload."""
    try:
        return resp.read()
    except http.client.IncompleteRead as exc:
        partial = exc.partial or b""
        expected = None
        try:
            headers = getattr(resp, "headers", None)
            raw = headers.get("Content-Length") if headers \
                else None
            expected = int(raw) if raw is not None else None
        except Exception:
            expected = None
        if expected is not None and len(partial) < expected:
            raise DoorbellError(
                f"partial wedge: body truncated at "
                f"{len(partial)}/{expected} bytes mid-response "
                f"(tunnel connection failed)") from exc
        return partial


def _sleep(seconds: float) -> None:
    """The doorbell's own sleep hook (see transport_v2._sleep
    for why this indirection exists: never patch time.sleep
    itself — it is shared by every thread in the process)."""
    time.sleep(seconds)


def _default_opener(method, url, headers, body):
    """Proxy-aware opener: (method, url, headers, body
    bytes|None) -> (status, headers dict, body bytes). HTTP
    errors are RETURNED, not raised, so callers decide what a
    status means. Routes through proxycreds.open_url so the
    egress proxy credential is resolved FRESH at dial time
    (the process-env proxy is pinned at process start and goes
    stale when the runtime rotates the credential)."""
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with proxycreds.open_url(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), _read_body(resp)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), _read_body(exc) or b""


def _default_stream_opener(url, headers):
    """Open an RTDB event stream; returns an iterable of raw
    lines (bytes). Raises DoorbellError on any failure to open.
    The CONNECT goes through proxycreds.open_url (fresh
    credential at dial time, like every other leg); on the live
    socket the dial timeout is replaced with
    STREAM_READ_TIMEOUT_S — long enough that a healthy stream's
    keep-alives never trip it, finite so a silently half-open
    stream fails loudly into the supervised listen loop's
    reconnect + slow-sync fallback instead of blocking the
    listen loop forever."""
    req = urllib.request.Request(url, method="GET")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        resp = proxycreds.open_url(req, timeout=30)
    except Exception as exc:
        raise DoorbellError(f"stream open failed: {exc}") from exc
    try:
        sock = resp.fp.raw._sock
        if sock is not None:
            sock.settimeout(STREAM_READ_TIMEOUT_S)
    except Exception:
        pass
    if getattr(resp, "status", 200) >= 400:
        raise DoorbellError(f"stream HTTP {resp.status}")
    return resp


class DoorbellClient:
    """RTDB REST client: token exchange, presence + heartbeat,
    signals, doorbell taps, streaming listens.

    ``opener`` / ``stream_opener`` are injectable for tests and
    drills; the defaults are the urllib implementations above
    (the same stdlib HTTP approach ``supabase_store`` uses — no
    new dependencies).
    """

    def __init__(self, project_id: str = "", api_key: str = "",
                 database_url: str = "", opener=None,
                 stream_opener=None, root_prefix: str = ""):
        self.project_id = project_id or ""
        self.api_key = api_key or ""
        if database_url:
            self.database_url = database_url.rstrip("/")
        elif self.project_id:
            self.database_url = (
                f"https://{self.project_id}-default-rtdb.firebaseio.com")
        else:
            self.database_url = ""
        #: Optional RTDB root prefix (2.3.0): every path this
        #: client touches is namespaced under it ("sandbox230"
        #: -> /sandbox230/presence/...). Drills and tests run
        #: under a prefix so production nodes are never touched;
        #: production clients pass "" (the default).
        self.root_prefix = str(root_prefix or "").strip("/")
        self._opener = opener or _default_opener
        self._stream_opener = stream_opener or _default_stream_opener
        self._custom_token = ""
        self._id_token = ""
        self._refresh_token = ""
        self._id_token_expires_at = 0.0  # time.monotonic() deadline
        # Presence session metadata (signal (c)): kept so beats and
        # the clean-close write carry the full node shape.
        self._presence_meta = {"client_version": "", "transport": ""}
        # Heartbeat thread state. The beat loop is OWNED HERE, on
        # its own daemon thread — structurally independent of any
        # message/work loop the caller runs.
        self._hb_stop = threading.Event()
        self._hb_thread = None
        self._hb_username = ""
        self._hb_last_ok = 0.0  # time.monotonic() of last good beat
        self._hb_state = "offline"
        self._hb_lock = threading.Lock()

    # -- token exchange ------------------------------------------------
    def set_custom_token(self, custom_token: str) -> None:
        """Hold a fresh custom token (from the login Edge function)
        and drop any ID token minted from an older one."""
        self._custom_token = custom_token or ""
        self._id_token = ""
        self._refresh_token = ""
        self._id_token_expires_at = 0.0

    @property
    def has_token(self) -> bool:
        return bool(self._id_token)

    def exchange_custom_token(self, custom_token: str | None = None) -> str:
        """Custom token -> ID token via Identity Toolkit REST."""
        if custom_token:
            self.set_custom_token(custom_token)
        if not self._custom_token:
            raise DoorbellError("no Firebase custom token to exchange")
        if not self.api_key:
            raise DoorbellError("no Firebase API key configured")
        url = f"{_IDENTITY_URL}?key={urllib.parse.quote(self.api_key)}"
        body = json.dumps({"token": self._custom_token,
                           "returnSecureToken": True}).encode()
        status, _h, raw = self._call(
            "POST", url, {"Content-Type": "application/json"}, body)
        if status >= 400:
            raise DoorbellError(f"custom-token exchange HTTP {status}")
        try:
            data = json.loads(raw or b"{}")
            self._id_token = str(data["idToken"])
            self._refresh_token = str(data.get("refreshToken") or "")
            expires_in = float(data.get("expiresIn") or 3600)
        except Exception as exc:
            raise DoorbellError(
                f"custom-token exchange malformed reply: {exc}") from exc
        self._id_token_expires_at = time.monotonic() + expires_in - 60
        return self._id_token

    def _refresh_id_token(self) -> str:
        if not self._refresh_token:
            return self.exchange_custom_token()
        url = f"{_SECURETOKEN_URL}?key={urllib.parse.quote(self.api_key)}"
        body = urllib.parse.urlencode(
            {"grant_type": "refresh_token",
             "refresh_token": self._refresh_token}).encode()
        status, _h, raw = self._call(
            "POST", url,
            {"Content-Type": "application/x-www-form-urlencoded"}, body)
        if status >= 400:
            # A dead refresh token falls back to the custom token
            # exactly once (the transport re-logins on real expiry).
            return self.exchange_custom_token()
        data = json.loads(raw or b"{}")
        self._id_token = str(data["id_token"])
        self._refresh_token = str(data.get("refresh_token")
                                  or self._refresh_token)
        expires_in = float(data.get("expires_in") or 3600)
        self._id_token_expires_at = time.monotonic() + expires_in - 60
        return self._id_token

    def id_token(self) -> str:
        """A live ID token, exchanging/refreshing as needed."""
        if self._id_token and time.monotonic() < self._id_token_expires_at:
            return self._id_token
        if self._refresh_token:
            return self._refresh_id_token()
        return self.exchange_custom_token()

    def _call(self, method, url, headers, body):
        """One opener call with the PROXY-class ride-out
        (2.0.10): the presence/token legs ride the same egress
        credential rotation as the transport's calls, so they
        get the same doctrine — on an HTTP 407 or a connection
        failure carrying the proxy's refusal, abdicate the
        resolver's cached winner, back off, and retry inside a
        bounded budget (credential resolution is fresh at every
        dial). Any other outcome returns / raises at once. This
        is the read/write path for presence beats and the
        activeness mirror's RTDB leg: a desync window degrades
        them to a delay, never to a dark agent."""
        attempt = 0
        while True:
            try:
                status, resp_headers, raw = self._opener(
                    method, url, headers, body)
            except Exception as exc:
                low = str(exc).lower()
                if attempt + 1 < 5 and (
                        "407" in low
                        or "proxy authentication" in low
                        or "tunnel connection failed" in low):
                    proxycreds.reset_winner()
                    _sleep(min(5.0, float(2 ** attempt))
                           if attempt else 0.0)
                    attempt += 1
                    continue
                # The doorbell's public contract is DoorbellError:
                # a raw urllib failure (an EOF mid-handshake, a
                # reset) must never leak through it — swift's
                # 2.0.9 slow-sync thread died on exactly such a
                # URLError escaping the token exchange (2.2.0).
                raise DoorbellError(
                    f"doorbell call failed: {exc}") from exc
            if status == 407 and attempt + 1 < 5:
                proxycreds.reset_winner()
                _sleep(min(5.0, float(2 ** attempt))
                       if attempt else 0.0)
                attempt += 1
                continue
            return status, resp_headers, raw

    # -- REST plumbing ---------------------------------------------------
    def _path(self, path: str) -> str:
        """Apply the root prefix (see __init__): every RTDB path
        this client reads, writes or streams is namespaced."""
        if self.root_prefix:
            return f"{self.root_prefix}/{path}"
        return path

    def _url(self, path: str) -> str:
        if not self.database_url:
            raise DoorbellError("no Firebase database URL configured")
        return (f"{self.database_url}/{self._path(path)}.json"
                f"?auth={urllib.parse.quote(self.id_token())}")

    def _rest(self, method: str, path: str, payload=None):
        body = json.dumps(payload).encode() if payload is not None else None
        headers = {"Content-Type": "application/json"} if body else {}
        status, _h, raw = self._call(method, self._url(path), headers, body)
        if status == 401:
            # Stale token: force one re-exchange and retry once.
            self._id_token = ""
            self._id_token_expires_at = 0.0
            status, _h, raw = self._call(
                method, self._url(path), headers, body)
        if status >= 400:
            raise DoorbellError(f"RTDB {method} {path} HTTP {status}")
        if not raw:
            return None
        try:
            return json.loads(raw)
        except Exception:
            return None

    # -- presence: connect / beat / disconnect -------------------------
    def set_presence(self, username: str, client_version: str = "",
                     transport: str = "serverless-rest") -> dict:
        """Connect write — signals (a)+(c): the full presence node
        {state: online, ts, connected_at (both server-timestamped),
        client_version, transport}. Also arms this client's local
        ladder at "online" with the beat clock starting now."""
        self._presence_meta = {"client_version": str(client_version or ""),
                               "transport": str(transport or "")}
        payload = {"state": "online",
                   "ts": {".sv": "timestamp"},
                   "connected_at": {".sv": "timestamp"},
                   "client_version": self._presence_meta["client_version"],
                   "transport": self._presence_meta["transport"]}
        self._rest("PUT", f"presence/{user_key(username)}", payload)
        with self._hb_lock:
            self._hb_last_ok = time.monotonic()
            self._hb_state = "online"
        return payload

    def beat_presence(self, username: str) -> dict:
        """One heartbeat beat — signal (b): a server-timestamped
        write to MY OWN presence node only. PATCH merges, so the
        metadata from the connect write rides along untouched.
        Raises DoorbellError when the beat does not land (the
        ladder ages from the last LANDED beat, never from an
        attempted one)."""
        payload = {"state": "online", "ts": {".sv": "timestamp"}}
        self._rest("PATCH", f"presence/{user_key(username)}", payload)
        with self._hb_lock:
            self._hb_last_ok = time.monotonic()
        return payload

    def beat_digest(self, username: str) -> dict:
        """One coalesced digest write — the fan-out valve's writer
        half: /digest/<user_key> carries the same {state, ts,
        client_version, transport} shape as the presence node,
        refreshed once per beat since 2.3.0 (DIGEST_INTERVAL_S ==
        BEAT_INTERVAL_S). Peers subscribed to the digest avoid the
        raw fan-out; my own presence node is untouched by this."""
        payload = {"state": "online",
                   "ts": {".sv": "timestamp"},
                   "client_version": self._presence_meta["client_version"],
                   "transport": self._presence_meta["transport"]}
        self._rest("PATCH", f"digest/{user_key(username)}", payload)
        return payload

    def clear_presence(self, username: str) -> dict:
        """Clean-disconnect write — the REST client's equivalent
        of onDisconnect firing: explicit offline, full node shape,
        written BEFORE the client exits (never a bare delete)."""
        payload = {"state": "offline",
                   "ts": {".sv": "timestamp"},
                   "connected_at": {".sv": "timestamp"},
                   "client_version": self._presence_meta["client_version"],
                   "transport": self._presence_meta["transport"]}
        self._rest("PUT", f"presence/{user_key(username)}", payload)
        with self._hb_lock:
            self._hb_state = "offline"
        return payload

    def read_presence(self, username: str) -> dict | None:
        got = self._rest("GET", f"presence/{user_key(username)}")
        return got if isinstance(got, dict) else None

    def activeness(self, username: str, now_ms: int | None = None) -> str:
        """Ladder state of another agent's presence record."""
        return activeness_of_record(self.read_presence(username),
                                    now_ms=now_ms)

    def is_online(self, username: str) -> bool:
        return self.activeness(username) == "online"

    # -- heartbeat loop (independent thread) ----------------------------
    @property
    def heartbeat_state(self) -> str:
        with self._hb_lock:
            return self._hb_state

    @property
    def heartbeat_running(self) -> bool:
        return self._hb_thread is not None and self._hb_thread.is_alive()

    def start_heartbeat(self, username: str, interval_s: float = None,
                        on_beat=None, on_transition=None) -> threading.Thread:
        """Start the beat loop on its OWN daemon thread.

        Independence is structural: the loop lives here, iterates
        on a private stop-event, and shares no lock, queue or
        callback path with any message/work loop — a caller whose
        worker is wedged cannot delay a beat. ``interval_s``
        defaults to BEAT_INTERVAL_S (180s, the ratified 2.3.0
        health-proof cadence); the override exists ONLY so
        drills/tests can scale virtual time — production callers
        pass nothing. ``on_beat(ok)`` fires per attempt;
        ``on_transition(state)`` fires when MY ladder state changes
        (the transport tracks transitions locally — since 2.3.0
        no Supabase mirror hangs on it; presence is Firebase-only).
        Beats themselves touch RTDB only.
        """
        self.stop_heartbeat(fire_offline=False)
        self._hb_stop = threading.Event()
        self._hb_username = str(username)
        interval = BEAT_INTERVAL_S if interval_s is None \
            else float(interval_s)

        def _loop():
            beats = 0
            while not self._hb_stop.is_set():
                ok = True
                try:
                    self.beat_presence(self._hb_username)
                except Exception:
                    ok = False
                if ok:
                    beats += 1
                    if beats % DIGEST_EVERY_N_BEATS == 0:
                        # Fan-out valve: refresh my digest node on
                        # its coalesced cadence. Fail-soft — a missed
                        # digest never fails the beat itself.
                        try:
                            self.beat_digest(self._hb_username)
                        except Exception:
                            pass
                if on_beat is not None:
                    try:
                        on_beat(ok)
                    except Exception:
                        pass
                with self._hb_lock:
                    last_ok = self._hb_last_ok
                    prev = self._hb_state
                age = None if not last_ok else \
                    time.monotonic() - last_ok
                state = activeness_state(age, disconnect_fired=False)
                if state != prev:
                    with self._hb_lock:
                        self._hb_state = state
                    if on_transition is not None:
                        try:
                            on_transition(state)
                        except Exception:
                            pass
                self._hb_stop.wait(interval)

        self._hb_thread = threading.Thread(
            target=_loop, name="agentlink-heartbeat", daemon=True)
        self._hb_thread.start()
        return self._hb_thread

    def stop_heartbeat(self, fire_offline: bool = True) -> None:
        """Stop the beat loop (stop event + join). This method does
        NOT itself write offline or fire the transition callback —
        ``fire_offline`` is retained for call-site compatibility and
        is currently informational only. The offline write is
        clear_presence() and the ladder/mirror transition is the
        transport's stop_activeness step; callers doing a clean
        shutdown run those explicitly. (Doc corrected at v2.0
        integration — the Phase 6 drills caught the mismatch.)"""
        self._hb_stop.set()
        thread, self._hb_thread = self._hb_thread, None
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    # -- signals -----------------------------------------------------------
    def tap_signal(self, conversation_id: str,
                   latest_item_id: str) -> dict:
        """Wake a conversation: PATCH its signal node with the new
        latest item id, a bumped counter and the server timestamp.

        The counter is read-modify-write; a lost increment under a
        race is harmless by design (a signal can only cause a
        fetch — see README's forgery argument). The payload is
        EXACTLY {latest_item_id, counter, ts}: ids and counters,
        never content.
        """
        key = conversation_key(conversation_id)
        current = self._rest("GET", f"signals/{key}")
        counter = 0
        if isinstance(current, dict):
            try:
                counter = int(current.get("counter") or 0)
            except (TypeError, ValueError):
                counter = 0
        payload = {"latest_item_id": str(latest_item_id),
                   "counter": counter + 1,
                   "ts": {".sv": "timestamp"}}
        self._rest("PATCH", f"signals/{key}", payload)
        return payload

    def read_signal(self, conversation_id: str) -> dict | None:
        got = self._rest("GET",
                         f"signals/{conversation_key(conversation_id)}")
        return got if isinstance(got, dict) else None

    # -- doorbell taps -------------------------------------------------------
    def tap_doorbell(self, target_username: str, kind: str,
                     ref: str) -> dict:
        """Tap ANOTHER agent's doorbell (work/control wakeups):
        PUT /doorbell/<target> = {kind, ref, ts}. The rules allow
        exactly this cross-write and forbid writing your own.
        ``ref`` is an id (work id, assignment id) — never content.
        """
        payload = {"kind": str(kind), "ref": str(ref),
                   "ts": {".sv": "timestamp"}}
        self._rest("PUT", f"doorbell/{user_key(target_username)}", payload)
        return payload

    def read_doorbell(self, username: str) -> dict | None:
        """Read MY doorbell (the rules allow reading no other)."""
        got = self._rest("GET", f"doorbell/{user_key(username)}")
        return got if isinstance(got, dict) else None

    # -- transit inbox (2.3.0: the live layer carries messages) ------
    def put_inbox(self, target_username: str, item_id: str,
                  frame: dict, expires_at: int = 0) -> dict:
        """Push one frame into ANOTHER agent's transit inbox:
        PUT /inbox/<target>/<item_id> = {frame, expires_at, ts}.
        The frame is the caller's E2EE envelope dict — ciphertext,
        never opened here; the node carries NO other field
        (INBOX_FIELDS pins the shape). ``expires_at`` (epoch
        seconds, 0 = no expiry) is the disappearing contract: the
        consumer discards expired items unopened."""
        payload = {"frame": frame, "expires_at": int(expires_at or 0),
                   "ts": {".sv": "timestamp"}}
        self._rest("PUT",
                   f"inbox/{user_key(target_username)}/"
                   f"{sanitize_key(str(item_id))}", payload)
        return payload

    def read_inbox(self, username: str) -> dict:
        """Read MY whole transit inbox: {item_id: node} ({} when
        empty). The boot/reconnect reconciliation read — the
        stream is the live path; this is its snapshot twin."""
        got = self._rest("GET", f"inbox/{user_key(username)}")
        return got if isinstance(got, dict) else {}

    def delete_inbox_item(self, username: str, item_id: str) -> None:
        """Consume one of MY inbox items: delete its node. Called
        only after the frame is durably journaled locally —
        deleting is the transit ack."""
        self._rest("DELETE",
                   f"inbox/{user_key(username)}/"
                   f"{sanitize_key(str(item_id))}")

    def listen_inbox(self, username: str, callback,
                     stop_event=None) -> None:
        """Block on MY /inbox/<user_key> stream. callback(item_id,
        node) fires per item: the initial snapshot delivers every
        held item, later puts deliver the new/changed item, and a
        delete delivers (item_id, None). The consumer's live path
        — no polling exists anywhere in this design."""
        key = user_key(username)

        def _cb(path, data):
            if path in ("/", "", None):
                if isinstance(data, dict):
                    for item_id, node in data.items():
                        callback(str(item_id), node)
                return
            callback(str(path).lstrip("/"), data)

        try:
            self._stream(f"inbox/{key}", _cb, stop_event=stop_event)
        except DoorbellError:
            raise
        except Exception as exc:
            raise DoorbellError(
                f"inbox stream for {username} failed: {exc}") from exc

    # -- directory working copy (2.3.0) --------------------------------
    def publish_directory(self, entry: dict) -> dict:
        """Publish MY directory working copy: PUT
        /directory/<my_key> with exactly DIRECTORY_FIELDS (public
        data only). The Supabase al_directory row stays the master
        record — this is its live-layer copy, written by the same
        agent at login and whenever its entry changes; the rules
        allow writing only your OWN node."""
        payload = {k: entry.get(k) for k in sorted(DIRECTORY_FIELDS)}
        payload["updated_at"] = {".sv": "timestamp"}
        name = str(entry.get("username") or "")
        self._rest("PUT", f"directory/{user_key(name)}", payload)
        return payload

    def read_directory(self, username: str) -> dict | None:
        """Read one agent's directory working copy (any authed
        agent may read any entry — it is public data)."""
        got = self._rest("GET", f"directory/{user_key(username)}")
        return got if isinstance(got, dict) else None

    # -- streaming listens ----------------------------------------------------
    def _stream(self, path: str, callback, stop_event=None) -> None:
        """Consume one RTDB SSE stream for ``path`` (no leading
        slash, no .json). callback(event_path, data) per put/patch.
        Returns when the stream ends or stop_event fires; raises
        DoorbellError on failure. The blocking line iteration is
        the connection whose life presence signal (a) rides on."""
        if not self.database_url:
            raise DoorbellError("no Firebase database URL configured")
        url = (f"{self.database_url}/{self._path(path)}.json"
               f"?auth={urllib.parse.quote(self.id_token())}")
        lines = self._stream_opener(url, {"Accept": "text/event-stream"})
        event = ""
        for raw_line in lines:
            if stop_event is not None and stop_event.is_set():
                return
            line = (raw_line.decode("utf-8", "replace")
                    if isinstance(raw_line, bytes) else str(raw_line))
            line = line.strip()
            if line.startswith("event:"):
                event = line.split(":", 1)[1].strip()
            elif line.startswith("data:"):
                if event in ("put", "patch"):
                    try:
                        payload = json.loads(line.split(":", 1)[1].strip())
                    except Exception:
                        payload = None
                    if isinstance(payload, dict):
                        callback(str(payload.get("path") or "/"),
                                 payload.get("data"))
                event = ""
            elif not line:
                event = ""

    def listen_signals(self, callback, on_error=None,
                       stop_event=None) -> None:
        """Block on the /signals event stream, invoking
        ``callback(path, data)`` per put/patch event. Intended for
        a dedicated thread. Raises DoorbellError on failure (after
        invoking ``on_error`` when given) so the caller can engage
        its slow-sync fallback and its reconnect policy."""
        try:
            self._stream("signals", callback, stop_event=stop_event)
        except DoorbellError:
            if on_error is not None:
                on_error()
            raise
        except Exception as exc:
            if on_error is not None:
                on_error()
            raise DoorbellError(f"signal stream failed: {exc}") from exc

    def listen_presence(self, username: str, callback,
                        stop_event=None) -> None:
        """Block on ONE counterparty's /presence/<user_key> stream.
        callback(username, record) per event — the scoped
        subscription primitive; fleet-wide listening is the
        dashboard's job, never an agent's."""
        key = user_key(username)

        def _cb(_path, data):
            callback(str(username), data)

        try:
            self._stream(f"presence/{key}", _cb, stop_event=stop_event)
        except DoorbellError:
            raise
        except Exception as exc:
            raise DoorbellError(
                f"presence stream for {username} failed: {exc}") from exc

    def listen_digest(self, username: str, callback,
                      stop_event=None) -> None:
        """Block on ONE counterparty's /digest/<user_key> stream —
        the coalesced fan-out valve's reader half. Same callback
        shape as listen_presence; the digest record carries the
        same {state, ts} fields, so the ladder reads it unchanged
        (up to DIGEST_INTERVAL_S staler — display-grade)."""
        key = user_key(username)

        def _cb(_path, data):
            callback(str(username), data)

        try:
            self._stream(f"digest/{key}", _cb, stop_event=stop_event)
        except DoorbellError:
            raise
        except Exception as exc:
            raise DoorbellError(
                f"digest stream for {username} failed: {exc}") from exc


class ScopedPresenceWatcher:
    """Scoped presence subscriptions for ONE agent.

    ``provider`` is a callable returning the CURRENT counterparty
    username set (DM partners, group/channel co-members, current
    assigners/assignees — see build_counterparty_set). The watcher
    keeps exactly one presence stream thread per counterparty:
    :meth:`refresh` diffs the provider's set against the live set,
    starting streams for new counterparties and stopping streams
    for departed ones. An agent NEVER subscribes fleet-wide; only
    the dashboard does that, and it does not use this class.

    ``on_change(username, record, state)`` fires per presence
    event with the ladder state already derived through
    :func:`activeness_of_record` — the single source of truth.

    Fan-out valve: with ``fanout="digest"`` (the production-scale
    mode from the Phase 1 quota proof), counterparty streams ride
    the coalesced /digest nodes instead of the raw fan-out,
    EXCEPT usernames in ``critical`` (activeness-critical
    counterparties: current work assignees/assigners), which stay
    on raw /presence. The default ``fanout="presence"`` keeps every
    stream raw (small fleets, and the mode the scoping pins were
    written against).
    """

    def __init__(self, client: DoorbellClient, provider, on_change,
                 fanout: str = "presence", critical=None):
        if fanout not in ("presence", "digest"):
            raise ValueError(f"unknown fanout mode {fanout!r}")
        self._client = client
        self._provider = provider
        self._on_change = on_change
        self._fanout = fanout
        self._critical = {str(u) for u in (critical or set())}
        self._threads = {}  # username -> (stop_event, thread)
        self._lock = threading.Lock()

    def _path_for(self, username: str) -> str:
        if self._fanout == "digest" and username not in self._critical:
            return f"digest/{user_key(username)}"
        return f"presence/{user_key(username)}"

    def subscribed_usernames(self) -> set:
        with self._lock:
            return set(self._threads.keys())

    def subscribed_paths(self) -> set:
        """The exact RTDB paths currently streamed — the pin the
        scoping tests assert against the counterparty set."""
        return {self._path_for(u) for u in self.subscribed_usernames()}

    def _run_user(self, username: str, stop_event: threading.Event):
        def _cb(_u, record):
            state = activeness_of_record(record)
            try:
                self._on_change(username, record, state)
            except Exception:
                pass
        try:
            if self._path_for(username).startswith("digest/"):
                self._client.listen_digest(username, _cb,
                                           stop_event=stop_event)
            else:
                self._client.listen_presence(username, _cb,
                                             stop_event=stop_event)
        except DoorbellError:
            pass  # a dead counterparty stream is that peer's
            # ladder problem (its beats age out), never a crash here

    def refresh(self) -> set:
        """Re-scope subscriptions to the provider's current set.
        Returns the live username set after the diff."""
        desired = {str(u) for u in (self._provider() or set()) if u}
        with self._lock:
            current = set(self._threads.keys())
            for username in current - desired:
                stop_event, _t = self._threads.pop(username)
                stop_event.set()
            for username in desired - current:
                stop_event = threading.Event()
                thread = threading.Thread(
                    target=self._run_user, args=(username, stop_event),
                    name=f"agentlink-presence-{username}", daemon=True)
                self._threads[username] = (stop_event, thread)
                thread.start()
            return set(self._threads.keys())

    def close(self) -> None:
        with self._lock:
            threads = list(self._threads.values())
            self._threads.clear()
        for stop_event, _t in threads:
            stop_event.set()
