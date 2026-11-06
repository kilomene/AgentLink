"""Serverless transport for AgentLink v2.0 (Phase 3+4; daemon port
landed in the v2.0 daemon-loop phase).

Dual-transport note: AgentLink ships two transports. The SERVERLESS
transport (this module) is the default since 2.0.1 — the v1 relay
was retired at the v2.0 cutover, and defaulting to it stranded
every auto-updated agent on a dead endpoint (beulah, frozen from
2026-11-04 until this fix). The RELAY transport (``client.py``:
websockets to a home/peer relay) remains only as an explicit
opt-in for private relay deployments::

    AGENTLINK_TRANSPORT=serverless   # this module (default)
    AGENTLINK_TRANSPORT=relay        # client.py (explicit opt-in)

``client.py``'s daemon loop is wired onto this module behind that
flip (``Agent._start_serverless``): login, the supervision threads
(signal stream + slow-sync + scoped presence watcher), the send /
fetch / ack data path, and the request surface's read/send subset
(directory, group/channel keys, memberships, read receipts). The
module also stays import-clean and fully usable on its own (an
agent — or a test — can drive login / send / fetch / ack / presence
with nothing but this file, :mod:`agentlink.doorbell`, and the
protocol constants).

What moves where (blueprint routes, exactly):

* **Login** — Edge challenge-response: the client asks the login
  Edge function for a challenge, signs the CANONICAL payload
  (``protocol.auth_challenge_payload`` — byte-for-byte the string
  the relay's key-signed hello uses: ``agentlink-auth-v1`` /
  nonce / relay / username / expires) with an INJECTED signer
  callable, and exchanges the signature for a scoped Supabase JWT
  plus a Firebase custom token. The signer is injected
  (``callable(bytes) -> base64 signature``) so key material and all
  cryptography stay in ``crypto.py`` / the caller's Identity; this
  module never holds a private key, never encrypts, and NEVER
  decrypts. Edge invocations happen ONLY at login and at a 401
  re-login — event-driven, never periodic.
* **Send** — the caller hands this transport an ALREADY-ENCRYPTED
  content envelope (plus its oversight wrap, exactly as the relay
  path carries them). The transport inserts one ``al_queue`` custody
  row per recipient and one ``al_audit_log`` record — the SAME
  column names and value shapes ``supabase_store.SupabaseStore``
  writes for the relay (``enqueue`` / ``audit`` and the relay's
  ``_on_send`` / group-send frame construction) — then taps the
  conversation's Firebase signal. Content bytes are opaque here:
  they are stored, never opened.
* **Receive** — ``fetch_unacked`` peeks ``al_queue`` rows addressed
  to me in ``seq`` order (custody is NOT released by fetching);
  ``ack`` releases custody only for durably journaled ids, with the
  store's exact match rule (a frame matches by its top-level ``id``,
  a ``work_assigned`` frame by its nested work id) and marks acked
  message audit rows ``delivered``, mirroring the relay's ack path.
* **Presence backup** — :meth:`ServerlessTransport.
  update_presence_backup` upserts ``al_connections`` and touches
  ``al_users.last_seen``. It runs ONLY on activeness TRANSITIONS
  (login -> online, suspect, offline, logout): the client's ladder
  state is tracked locally and the mirror is written when — and
  only when — it changes (a test pins the call structure). The
  live activeness system itself (5s beats, connection metadata,
  the 10/15s ladder) lives in :mod:`agentlink.doorbell` and
  touches Firebase RTDB ONLY: nothing periodic ever reaches Edge
  or PostgREST.
* **Slow-sync fallback** — when the Firebase signal stream fails,
  :attr:`slow_sync_active` engages and :meth:`run_slow_sync` polls
  the unacked queue on :data:`SLOW_SYNC_INTERVAL_SECONDS` (60s),
  only while the doorbell is down. The stream itself reconnects
  without limit: first retry immediate, backoff capped at
  :data:`RECONNECT_BACKOFF_CAP_S` (5s).
* **Token refresh** — the Supabase JWT is refreshed BEFORE it
  expires: a timer armed from the token's own ``exp`` claim fires
  at ``exp - JWT_REFRESH_MARGIN_S`` and re-runs the login
  ceremony. Event-driven from the token, never a polling loop;
  the 401 re-login remains as backstop.

Security shape: the agent holds ONLY the anon key (a public client
identifier) plus its own scoped JWT (RLS is the perimeter). No
service key is accepted, stored, or sent anywhere by this module.
"""

from __future__ import annotations

import base64
import http.client
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from . import proxycreds
from .doorbell import (DoorbellClient, DoorbellError,
                       ScopedPresenceWatcher,
                       conversation_id_for_dm,
                       conversation_id_for_group)
from .protocol import auth_challenge_payload, new_id, now_ts
from .store import CONTENT_AUDIT_KINDS, PRIORITY_WEIGHT

__all__ = [
    "SLOW_SYNC_INTERVAL_SECONDS",
    "RECONNECT_BACKOFF_CAP_S",
    "JWT_REFRESH_MARGIN_S",
    "SERVERLESS_SERVER_ID",
    "ServerlessConfig",
    "ServerlessTransport",
    "TransportError",
    "Refusal",
    "next_backoff_s",
    "transport_mode",
]

#: Slow-sync cadence (seconds): the fallback poll while Firebase
#: is unreachable. 60s is the blueprint's degraded-mode contract —
#: never faster, and the loop runs only while the doorbell is down.
SLOW_SYNC_INTERVAL_SECONDS = 60

#: Reconnection backoff cap (seconds): the signal stream retries
#: WITHOUT LIMIT — first retry immediate, then doubling — but no
#: wait ever exceeds this cap.
RECONNECT_BACKOFF_CAP_S = 5

#: The Supabase JWT is re-logged-in this many seconds BEFORE its
#: exp claim, armed as a timer from the token itself.
JWT_REFRESH_MARGIN_S = 120


def next_backoff_s(attempt: int) -> float:
    """Reconnect wait for the ``attempt``-th consecutive failure
    (0-based): 0 (immediate first retry), 1, 2, 4, then capped at
    RECONNECT_BACKOFF_CAP_S forever — unlimited retries, bounded
    waits."""
    if attempt <= 0:
        return 0.0
    return float(min(RECONNECT_BACKOFF_CAP_S, 2 ** (attempt - 1)))


def _jwt_exp(jwt: str) -> int:
    """The exp claim of a JWT (payload read, signature NOT checked
    — the client only schedules its own refresh from it; the
    server verifies the signature on every call). 0 if unreadable."""
    try:
        payload_b64 = jwt.split(".")[1]
        payload_b64 += "=" * (-len(payload_b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload_b64))
        return int(data.get("exp") or 0)
    except Exception:
        return 0

#: The al_connections server_id/endpoint this transport records:
#: there is no relay; the "server" is the serverless stack itself.
SERVERLESS_SERVER_ID = "serverless"
SERVERLESS_ENDPOINT = "serverless://supabase+firebase"

#: PostgREST select for audit reads — byte-identical to
#: SupabaseStore._AUDIT_SELECT_SEQ (seq is the cursor column).
_AUDIT_SELECT_SEQ = ("select=seq,ts,kind,actor,target,group_id,"
                     "work_id,status,priority,size,mentions,ref_id,"
                     "sender_nickname,sender_role,sender_custom_role,"
                     "oversight,content_envelope")


class TransportError(Exception):
    """Any serverless-transport failure (login, PostgREST, shape)."""


class Refusal(TransportError):
    """A contract refusal carrying the RELAY's own reason string
    (``unknown_work``, ``permission_denied``, ``bad_proof``, ...).

    The relay answers a refused request with an error frame whose
    reason the client surfaces as ``RequestFailed(reason, detail)``;
    the serverless paths raise this instead, and client.py's
    serverless request router maps it back to the identical
    ``RequestFailed`` — so a handler calling an operation in
    serverless mode sees exactly what the relay path would have
    raised, never a transport-flavoured paraphrase."""

    def __init__(self, reason, detail=""):
        self.reason = str(reason)
        self.detail = str(detail or "")
        super().__init__(
            f"{self.reason}: {self.detail}" if self.detail
            else self.reason)


def transport_mode(env: dict | None = None) -> str:
    """The configured transport: ``"serverless"`` or ``"relay"``.

    Reads ``AGENTLINK_TRANSPORT`` (default ``"serverless"`` since
    2.0.1: the v1 relay is retired, so the old relay default
    stranded every updated agent that had no flip set — beulah's
    heartbeat froze on 2026-11-04 and never recovered on 2.0.0;
    the coordinator's client wiring consumes this).
    """
    env = os.environ if env is None else env
    mode = str(env.get("AGENTLINK_TRANSPORT") or "serverless").strip().lower()
    return "relay" if mode == "relay" else "serverless"


class ServerlessConfig:
    """Configuration for the serverless transport.

    ``anon_key`` is the Supabase anon (public) key — safe for a
    client to hold; RLS, not key secrecy, is the perimeter. There
    is deliberately NO service-key field anywhere in this config.
    """

    def __init__(self, supabase_url: str = "", anon_key: str = "",
                 firebase_project_id: str = "",
                 firebase_api_key: str = "",
                 firebase_database_url: str = "",
                 login_edge_url: str = "",
                 table_prefix: str = "al_"):
        self.supabase_url = (supabase_url or "").rstrip("/")
        self.anon_key = anon_key or ""
        self.firebase_project_id = firebase_project_id or ""
        self.firebase_api_key = firebase_api_key or ""
        self.firebase_database_url = firebase_database_url or ""
        self.login_edge_url = (login_edge_url or "").rstrip("/")
        self.table_prefix = table_prefix or ""

    # Production endpoints, baked in at 2.0.1 so a stock daemon
    # connects with ZERO configuration: the v2.0 fleet could not
    # come back after the relay retired because every value below
    # existed only as an env var on the coordinator's own host
    # (beulah's 2.0.0 had none of them and kept dialing the dead
    # relay). Every value here is a PUBLIC client coordinate — the
    # anon key is the RLS-guarded public key the dashboard serves
    # to the world in its config.js; RLS, not key secrecy, is the
    # perimeter (this class's own contract). Env always overrides.
    PRODUCTION_DEFAULTS = {
        "AGENTLINK_SUPABASE_URL":
            "https://gqmzwbmmloklrkvxlmdc.supabase.co",
        "AGENTLINK_SUPABASE_ANON_KEY":
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBh"
            "YmFzZSIsInJlZiI6ImdxbXp3Ym1tbG9rbHJrdnhsbWRjIiwicm9s"
            "ZSI6ImFub24iLCJpYXQiOjE3OTM1NzMxOTIsImV4cCI6MjEwOTE"
            "0OTE5Mn0.trixR09C_xLZZ1LC7VnB9DXuVG3ABZZrrZ0ZQx7xd6A",
        "AGENTLINK_FIREBASE_PROJECT": "agentlink-84609",
        "AGENTLINK_FIREBASE_DATABASE_URL":
            "https://agentlink-84609-default-rtdb.firebaseio.com",
        "AGENTLINK_LOGIN_EDGE_URL":
            "https://gqmzwbmmloklrkvxlmdc.supabase.co"
            "/functions/v1/agentlink-login",
    }

    @classmethod
    def from_env(cls, env: dict | None = None) -> "ServerlessConfig":
        env = os.environ if env is None else env
        d = cls.PRODUCTION_DEFAULTS
        return cls(
            supabase_url=env.get("AGENTLINK_SUPABASE_URL",
                                 d["AGENTLINK_SUPABASE_URL"]),
            anon_key=env.get("AGENTLINK_SUPABASE_ANON_KEY",
                             d["AGENTLINK_SUPABASE_ANON_KEY"]),
            firebase_project_id=env.get(
                "AGENTLINK_FIREBASE_PROJECT",
                d["AGENTLINK_FIREBASE_PROJECT"]),
            firebase_api_key=env.get("AGENTLINK_FIREBASE_API_KEY", ""),
            firebase_database_url=env.get(
                "AGENTLINK_FIREBASE_DATABASE_URL",
                d["AGENTLINK_FIREBASE_DATABASE_URL"]),
            login_edge_url=env.get("AGENTLINK_LOGIN_EDGE_URL",
                                   d["AGENTLINK_LOGIN_EDGE_URL"]),
            table_prefix=env.get("AGENTLINK_SUPABASE_TABLE_PREFIX",
                                 "al_"))

    def table(self, name: str) -> str:
        """Prefixed PostgREST table name (``queue`` -> ``al_queue``)."""
        if name.startswith(self.table_prefix):
            return name
        return self.table_prefix + name

    @property
    def rest_base(self) -> str:
        return self.supabase_url + "/rest/v1"


def _read_body(resp) -> bytes:
    """Read a response body, tolerating a stream clipped AFTER
    the payload arrived: http.client raises IncompleteRead when
    a chunked response loses its terminating chunk (this host's
    egress proxy does exactly that, intermittently), and the
    exception's .partial carries the bytes that DID arrive —
    the same doctrine blobstore's R2 reader follows. Whether
    those bytes are the complete payload is judged by the
    body's own parser downstream: a truly truncated body still
    fails there, unchanged."""
    try:
        return resp.read()
    except http.client.IncompleteRead as exc:
        return exc.partial or b""


def _default_opener(method, url, headers, body):
    """Proxy-aware opener with supabase_store's contract: HTTP
    errors are RETURNED as (status, headers, body), never
    raised. Routes through proxycreds.open_url so the egress
    proxy credential is resolved FRESH at dial time (the
    process-env proxy is pinned at process start and goes
    stale when the runtime rotates the credential — v1.8.1
    pins PX1-PX6 wire this module the same way)."""
    req = urllib.request.Request(url, data=body, method=method)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with proxycreds.open_url(req, timeout=30) as resp:
            return resp.status, dict(resp.headers), _read_body(resp)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers or {}), _read_body(exc) or b""


def _loads(val, default):
    """Tolerant JSON decode, mirroring supabase_store._loads:
    jsonb columns may hand back a parsed value or a JSON string."""
    if val is None:
        return default
    if isinstance(val, str):
        if not val:
            return default
        try:
            return json.loads(val)
        except Exception:
            return default
    return val


def _ack_id_matches(frame, wanted) -> bool:
    """The store's ack match rule, verbatim semantics (see
    supabase_store._ack_id_matches): a frame matches by top-level
    id; a work_assigned frame matches by its nested work id."""
    if str(frame.get("id") or "") in wanted:
        return True
    if frame.get("type") == "work_assigned":
        work = frame.get("work") or {}
        return str(work.get("id") or "") in wanted
    return False


def _shape_audit_row(r: dict) -> dict:
    """Shape one raw al_audit_log row exactly as
    SupabaseStore._shape_audit does (actor->from, target->to,
    mentions/oversight/content_envelope JSON-decoded)."""
    out = {"ts": r.get("ts"), "kind": r.get("kind"),
           "from": r.get("actor"), "to": r.get("target"),
           "group_id": r.get("group_id"), "work_id": r.get("work_id"),
           "status": r.get("status"), "priority": r.get("priority", ""),
           "size": r.get("size", 0),
           "mentions": _loads(r.get("mentions"), []),
           "ref_id": r.get("ref_id", ""),
           "sender_nickname": r.get("sender_nickname", ""),
           "sender_role": r.get("sender_role", ""),
           "sender_custom_role": r.get("sender_custom_role", ""),
           "oversight": _loads(r.get("oversight"), None),
           "content_envelope": _loads(r.get("content_envelope"), None)}
    if r.get("seq") is not None:
        try:
            out["seq"] = int(r["seq"])
        except (TypeError, ValueError):
            out["seq"] = r["seq"]
    return out


class ServerlessTransport:
    """Login / send / fetch / ack / presence over Supabase +
    Firebase, with no relay anywhere in the path.

    ``signer`` is the injected Ed25519 signing callable
    (``callable(bytes) -> base64 str | bytes`` — e.g.
    ``Identity.sign`` bound, which returns base64 str). ``opener``
    is injectable for tests and is shared with the doorbell client
    unless a separate ``doorbell_opener`` is given.
    """

    def __init__(self, config: ServerlessConfig | None = None,
                 opener=None, stream_opener=None, doorbell=None):
        self.config = config or ServerlessConfig.from_env()
        self._opener = opener or _default_opener
        self.doorbell = doorbell or DoorbellClient(
            project_id=self.config.firebase_project_id,
            api_key=self.config.firebase_api_key,
            database_url=self.config.firebase_database_url,
            opener=opener, stream_opener=stream_opener)
        self.username = ""
        self._signer = None
        self._jwt = ""
        self._jwt_expires_at = 0
        #: True while the Firebase signal stream is down and the
        #: 60-second slow-sync fallback is the wakeup path.
        self.slow_sync_active = False
        #: Conversation keys tapped most recently (diagnostics).
        self.last_signal_error = ""
        # Activeness: my last ladder state (transition detection
        # for the Supabase mirror) + the pre-expiry refresh timer.
        self._activeness_state = "offline"
        self._refresh_timer = None
        self.last_refresh_error = ""
        self.last_mirror_error = ""
        self.client_version = ""
        # Scoped presence subscriptions (counterparties only).
        self._counterparty_provider = None
        self._presence_watcher = None
        self._presence_callback = None
        # Decision-link declaration (v2.0 coverage): the client's
        # current declared state + detail, carried on every login
        # ceremony's verify (the Edge persists it to the agent's
        # al_users row with the relay setters' validation) and
        # re-sent verbatim on token-refresh re-logins, so a refresh
        # can never regress the dashboard-visible state to a stale
        # declaration.
        self._decision_link = ""
        self._decision_detail = None

    # -- PostgREST plumbing -------------------------------------------
    def _headers(self, prefer: str = "") -> dict:
        headers = {"apikey": self.config.anon_key,
                   "Authorization": f"Bearer {self._jwt or self.config.anon_key}",
                   "Accept": "application/json"}
        if prefer:
            headers["Prefer"] = prefer
        return headers

    def _rest(self, method: str, table: str, query: str = "",
              body=None, prefer: str = "", _retried: bool = False):
        """One PostgREST call with the agent JWT. A 401 triggers
        exactly one event-driven re-login and one retry — the ONLY
        refresh path, and it never loops."""
        if not self.config.supabase_url:
            raise TransportError("no Supabase URL configured")
        path = f"{self.config.rest_base}/{self.config.table(table)}"
        if query:
            path += "?" + query
        headers = self._headers(prefer)
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        status, _h, raw = self._opener(method, path, headers, data)
        if status == 401 and not _retried and self._signer is not None \
                and self.username:
            self._login(self.username, self._signer)
            return self._rest(method, table, query, body, prefer,
                              _retried=True)
        if status >= 400:
            raise TransportError(
                f"PostgREST {method} {table} HTTP {status}")
        if not raw:
            return None
        return json.loads(raw)

    @staticmethod
    def _eq(col: str, val) -> str:
        return f"{col}=eq.{urllib.parse.quote(str(val), safe='')}"

    # -- login -----------------------------------------------------------
    def _edge_post(self, suffix: str, payload: dict) -> dict:
        if not self.config.login_edge_url:
            raise TransportError("no login Edge URL configured")
        url = f"{self.config.login_edge_url}/{suffix}"
        body = json.dumps(payload).encode()
        status, _h, raw = self._opener(
            "POST", url, {"Content-Type": "application/json",
                          "apikey": self.config.anon_key}, body)
        if status >= 400:
            raise TransportError(f"login Edge {suffix} HTTP {status}")
        try:
            return json.loads(raw or b"{}")
        except Exception as exc:
            raise TransportError(
                f"login Edge {suffix} malformed reply") from exc

    def _login(self, username: str, signer) -> dict:
        """The challenge-response ceremony (no presence writes —
        see login()). Kept separate so the 401 path can re-run it
        without re-entering the presence backup."""
        challenge = self._edge_post("challenge", {"username": username})
        nonce = str(challenge.get("nonce") or "")
        relay = str(challenge.get("relay") or "")
        # The ceremony IS the login: record the identity up front,
        # so the transport is fully logged in the moment the JWT
        # lands (whoami / send / fetch guards, the 401 re-login
        # backstop, and the pre-expiry refresh timer all read
        # self.username / self._signer). Previously _login stored
        # the JWT but left both unset, so direct _login callers
        # (drills, verify harness) were half-logged-in: whoami
        # answered username "" and every guarded call raised
        # "login required" despite a valid JWT. login() sets the
        # same two fields first, so this is a no-op there.
        self.username = str(username)
        self._signer = signer
        # The Edge returns the expiry as `exp` with an `expires`
        # alias; accept either (v2.0 integration alignment).
        expires = challenge.get("expires") or challenge.get("exp")
        if not nonce or not relay or expires is None:
            raise TransportError(
                "login Edge challenge missing nonce/relay/expires")
        payload = auth_challenge_payload(nonce, relay, username, expires)
        signature = signer(payload)
        if isinstance(signature, bytes):
            import base64 as _b64
            signature = _b64.b64encode(signature).decode()
        verify = {
            "username": username, "nonce": nonce, "relay": relay,
            "exp": expires, "expires": expires,
            "signature": str(signature)}
        # Decision-link declaration (v2.0 coverage): the verify is
        # the one authenticated, extensible point of the ceremony,
        # so the declaration rides it — additive fields the Edge
        # persists to al_users (relay-setter validation) on verify
        # success. The relay hello contract is untouched.
        if self._decision_link in ("linked", "pending"):
            verify["decision_link"] = self._decision_link
        if isinstance(self._decision_detail, dict):
            verify["decision_link_detail"] = self._decision_detail
        reply = self._edge_post("verify", verify)
        jwt = str(reply.get("supabase_jwt") or reply.get("access_token")
                  or reply.get("jwt") or "")
        custom = str(reply.get("firebase_custom_token")
                     or reply.get("firebase_token") or "")
        if not jwt:
            raise TransportError("login Edge verify returned no JWT")
        self._jwt = jwt
        # Refresh scheduling reads the token's OWN exp claim (the
        # Edge reply's expires_at is only a fallback): the refresh
        # is armed from the credential itself, never polled for.
        self._jwt_expires_at = _jwt_exp(jwt)
        if not self._jwt_expires_at:
            try:
                self._jwt_expires_at = int(reply.get("expires_at") or 0)
            except (TypeError, ValueError):
                self._jwt_expires_at = 0
        self._schedule_token_refresh()
        if custom:
            self.doorbell.set_custom_token(custom)
            try:
                self.doorbell.exchange_custom_token()
            except DoorbellError as exc:
                # Login itself succeeded; a dead doorbell leg means
                # slow-sync from the start, never a failed login.
                self.slow_sync_active = True
                self.last_signal_error = str(exc)
        return {"username": username, "jwt_expires_at": self._jwt_expires_at,
                "doorbell": bool(custom)}

    # -- pre-expiry token refresh (event-driven, from the token) -----
    def seconds_until_refresh(self, now: int | None = None) -> float | None:
        """Seconds until the armed refresh fires: exp - margin -
        now, clamped at 0 (an already-due token refreshes at
        once). None when the token carries no readable exp."""
        if not self._jwt_expires_at:
            return None
        now = int(time.time()) if now is None else int(now)
        return max(0.0, float(self._jwt_expires_at
                              - JWT_REFRESH_MARGIN_S - now))

    def _schedule_token_refresh(self) -> None:
        if self._refresh_timer is not None:
            self._refresh_timer.cancel()
            self._refresh_timer = None
        delay = self.seconds_until_refresh()
        if delay is None or not self._signer or not self.username:
            return
        timer = threading.Timer(delay, self._refresh_login)
        timer.daemon = True
        timer.start()
        self._refresh_timer = timer

    def _refresh_login(self) -> None:
        """Timer-fired pre-expiry re-login. On failure the error
        is recorded and the 401 re-login backstop remains — a
        failed refresh never kills the session silently."""
        if not self._signer or not self.username:
            return
        try:
            self._login(self.username, self._signer)
        except Exception as exc:  # noqa: BLE001 - recorded, not raised
            self.last_refresh_error = str(exc)

    # -- activeness transitions + the transition-only mirror ----------
    @property
    def activeness_state(self) -> str:
        return self._activeness_state

    def _transition_activeness(self, state: str) -> bool:
        """Record a ladder transition and mirror it — THE ONLY
        path that writes the Supabase activeness mirror. Same
        state again is a no-op (returns False, zero writes):
        beats may fire a thousand times inside one state and the
        mirror does not move."""
        if state == self._activeness_state:
            return False
        self._activeness_state = state
        self._mirror_activeness(state)
        return True

    def _mirror_activeness(self, state: str) -> None:
        """Supabase mirror of ONE transition: the al_activeness
        row (Phase 1's table — {username, state, updated_at}; the
        write is fail-soft until the coordinator confirms that
        table's final column contract, and any failure is kept in
        last_mirror_error, never raised into the beat path) plus
        the durable backup: al_connections upsert + al_users
        last_seen touch via update_presence_backup."""
        try:
            self._rest("POST", "activeness", body={
                "username": self.username, "state": state,
                "beat_at": now_ts(),
                "client_version": self.client_version,
                "transport": ("slow-sync" if self.slow_sync_active
                              else "rtdb"),
                "updated_at": now_ts()},
                prefer="return=minimal,resolution=merge-duplicates")
        except TransportError as exc:
            self.last_mirror_error = str(exc)
        self.update_presence_backup(online=(state != "offline"))

    def _on_beat_transition(self, state: str) -> None:
        """Heartbeat-thread callback: a ladder change detected by
        the doorbell's beat loop becomes a mirrored transition."""
        self._transition_activeness(state)

    def start_activeness(self) -> None:
        """Bring activeness up after login: the Firebase presence
        connect write (with metadata) and the independent 5s
        heartbeat thread. The connect IS the offline->online
        transition, so the mirror fires exactly once here."""
        if not self.username:
            raise TransportError("login required before activeness")
        if self.doorbell.has_token:
            try:
                self.doorbell.set_presence(
                    self.username, client_version=self.client_version,
                    transport="serverless-rest")
                self.doorbell.start_heartbeat(
                    self.username,
                    on_transition=self._on_beat_transition)
            except DoorbellError as exc:
                self.slow_sync_active = True
                self.last_signal_error = str(exc)
        self._transition_activeness("online")

    def stop_activeness(self) -> None:
        """Clean activeness shutdown: stop beats, write the
        Firebase offline (the REST clean-close write), and mirror
        the online->offline transition."""
        if self.username and self.doorbell.has_token:
            self.doorbell.stop_heartbeat(fire_offline=True)
            try:
                self.doorbell.clear_presence(self.username)
            except DoorbellError:
                pass
        self._transition_activeness("offline")

    def login(self, username: str, signer, client_version: str = "",
              decision_link: str | None = None,
              decision_link_detail: dict | None = None) -> dict:
        """Full login: Edge challenge-response, Firebase token
        exchange, then activeness (presence connect + heartbeat +
        the login transition's mirror write).

        ``decision_link`` / ``decision_link_detail`` are the
        client's decision-link declaration (the relay hello's
        ``decision_link`` / ``decision_link_detail`` fields): when
        given, they are stored on the transport and carried on
        this ceremony's verify AND on every later refresh
        re-login, so the declaration the dashboard reads from
        al_users is always the client's current truth."""
        self.username = str(username)
        self._signer = signer
        if decision_link is not None:
            self._decision_link = str(decision_link or "")
        if decision_link_detail is not None:
            self._decision_detail = decision_link_detail
        if client_version:
            self.client_version = client_version
        elif not self.client_version:
            try:
                from . import __version__
                self.client_version = str(__version__)
            except Exception:
                self.client_version = ""
        result = self._login(self.username, signer)
        self.start_activeness()
        return result

    def logout(self) -> None:
        """Clean disconnect: activeness shutdown (Firebase
        offline write + offline mirror transition), refresh timer
        cancelled, tokens dropped."""
        if self._refresh_timer is not None:
            self._refresh_timer.cancel()
            self._refresh_timer = None
        self.stop_activeness()
        if self._presence_watcher is not None:
            self._presence_watcher.close()
            self._presence_watcher = None
        self._jwt = ""
        self._signer = None

    def update_presence_backup(self, online: bool = True) -> None:
        """Supabase presence BACKUP: upsert my al_connections row
        and touch al_users.last_seen.

        Called ONLY from _mirror_activeness — i.e. ONLY on ladder
        transitions (structure-pinned by test). Live activeness
        is Firebase's job; periodic Supabase writes would burn
        the egress budget for nothing.
        """
        if not self.username:
            return
        self._rest("POST", "connections", body={
            "username": self.username,
            "server_id": SERVERLESS_SERVER_ID,
            "endpoint": SERVERLESS_ENDPOINT if online else "",
            "home_endpoint": SERVERLESS_ENDPOINT,
            "updated_at": now_ts()},
            prefer="return=minimal,resolution=merge-duplicates")
        self._rest("PATCH", "users", self._eq("username", self.username),
                   body={"last_seen": now_ts()}, prefer="return=minimal")

    # -- scoped presence subscriptions ----------------------------------
    def set_counterparty_provider(self, provider) -> None:
        """Install the subscription-set provider: a callable
        returning the CURRENT counterparty username set (DM
        partners, group/channel co-members, current assigners /
        assignees — build it with doorbell.build_counterparty_set
        from membership data). Scoped subscriptions re-derive
        from it on every refresh; the agent never subscribes
        fleet-wide."""
        self._counterparty_provider = provider
        if self._presence_watcher is not None:
            self._presence_watcher._provider = provider

    def start_presence_watch(self, on_change, fanout: str = "presence",
                             critical=None) -> ScopedPresenceWatcher:
        """Start (or restart) scoped presence watching.
        on_change(username, record, state) per counterparty
        presence event, state already ladder-derived.

        ``fanout`` / ``critical`` pass through to the watcher:
        the default (``"presence"``) keeps every counterparty on
        raw /presence (small fleets); the daemon wiring passes
        ``fanout="digest"`` with the activeness-critical work
        counterparties in ``critical`` (Phase 1 quota valve —
        peer records ride 30s-coalesced digest nodes, critical
        counterparties stay raw)."""
        if self._counterparty_provider is None:
            raise TransportError(
                "set_counterparty_provider required before "
                "start_presence_watch (scoped subscriptions only)")
        if self._presence_watcher is not None:
            self._presence_watcher.close()
        self._presence_callback = on_change
        self._presence_watcher = ScopedPresenceWatcher(
            self.doorbell, self._counterparty_provider, on_change,
            fanout=fanout, critical=critical)
        self._presence_watcher.refresh()
        return self._presence_watcher

    def refresh_presence_subscriptions(self) -> set:
        """Re-scope presence streams after a membership change:
        new counterparties gain a stream, departed ones lose
        theirs. Returns the live subscribed username set."""
        if self._presence_watcher is None:
            return set()
        return self._presence_watcher.refresh()

    # -- send ---------------------------------------------------------------
    def _enqueue(self, to_username: str, frame: dict) -> None:
        """One al_queue custody row — the exact body shape of
        SupabaseStore.enqueue (payload as a JSON string, priority
        as the PRIORITY_WEIGHT integer, ts epoch seconds)."""
        weight = PRIORITY_WEIGHT.get(str(frame.get("priority")
                                         or "normal"), 0)
        self._rest("POST", "queue", body={
            "to_username": to_username,
            "payload": json.dumps(frame),
            "priority": weight, "ts": now_ts()},
            prefer="return=minimal")

    def _audit(self, kind, target="", group_id="", status="",
               priority="", size=0, mentions=None, ref_id="",
               sender_nickname="", sender_role="",
               sender_custom_role="", oversight="",
               content_envelope="", work_id="") -> None:
        """One al_audit_log row — the exact body shape of
        SupabaseStore.audit (mentions JSON-string, oversight and
        content_envelope as JSON strings or "")."""
        self._rest("POST", "audit_log", body={
            "ts": now_ts(), "kind": kind, "actor": self.username,
            "target": target, "group_id": group_id,
            "work_id": work_id,
            "status": status, "priority": priority,
            "size": int(size or 0),
            "mentions": json.dumps(mentions or []), "ref_id": ref_id,
            "sender_nickname": sender_nickname or "",
            "sender_role": sender_role or "",
            "sender_custom_role": sender_custom_role or "",
            "oversight": oversight or "",
            "content_envelope": content_envelope or ""},
            prefer="return=minimal")

    def _tap(self, conversation_id: str, item_id: str) -> None:
        """Best-effort signal tap: a failed tap never fails a send
        (custody is in Supabase; the signal is only a wakeup)."""
        if not self.doorbell.has_token:
            return
        try:
            self.doorbell.tap_signal(conversation_id, item_id)
        except DoorbellError as exc:
            self.slow_sync_active = True
            self.last_signal_error = str(exc)

    def send_dm(self, to: str, content: dict, *,
                message_id: str | None = None, mentions=None,
                priority: str = "normal", in_reply_to=None,
                oversight=None, from_name: str = "",
                from_pubkey: str = "") -> dict:
        """Send one 1:1 message. ``content`` is the caller's
        E2EE envelope (opaque here — never opened); ``oversight``
        is the owner-oversight wrap dict the relay path carries.

        Builds the relay's message frame shape, enqueues it for
        the recipient, records the al_audit_log 'message' row the
        relay's _on_send records, then taps the DM signal.
        Returns {"id", "to", "queued": True} (serverless delivery
        is custody-first: everything is 'queued' until acked).
        """
        if not self.username:
            raise TransportError("login required before send_dm")
        to_user = str(to)
        mid = message_id or new_id()
        frame = {"type": "message", "id": mid,
                 "from": self.username, "from_name": from_name,
                 "from_pubkey": from_pubkey,
                 "sender_nickname": "", "sender_role": "",
                 "sender_custom_role": "",
                 "oversight": oversight,
                 "mentions": list(mentions or []),
                 "priority": (priority if priority in
                              ("normal", "high", "urgent") else "normal"),
                 "content": content, "ts": now_ts(),
                 "in_reply_to": in_reply_to, "group_id": None}
        self._enqueue(to_user, frame)
        self._audit(
            "message", target=to_user, status="sent",
            priority=frame["priority"],
            size=len(str((content or {}).get("ct") or "")),
            mentions=frame["mentions"], ref_id=mid,
            oversight=json.dumps(oversight) if oversight else "",
            content_envelope=json.dumps(content) if content else "")
        self._tap(conversation_id_for_dm(self.username, to_user), mid)
        return {"id": mid, "to": to_user, "queued": True}

    def send_group_frame(self, group_id: str, content: dict, *,
                         members, message_id: str | None = None,
                         mentions=None, priority: str = "normal",
                         in_reply_to=None, oversight=None,
                         from_name: str = "", from_pubkey: str = "",
                         group_name: str = "",
                         sender_nickname: str = "",
                         sender_role: str = "",
                         sender_custom_role: str = "") -> dict:
        """Send one group/channel frame: the relay's group message
        frame enqueued for every member except the sender, ONE
        al_audit_log 'group_message' row carrying the content
        envelope (as the relay's group path records), and ONE
        signal tap for the conversation regardless of member
        count (the blueprint's fan-out rule)."""
        if not self.username:
            raise TransportError("login required before send_group_frame")
        mid = message_id or new_id()
        frame = {"type": "message", "id": mid,
                 "from": self.username, "from_name": from_name,
                 "from_pubkey": from_pubkey,
                 "sender_nickname": sender_nickname,
                 "sender_role": sender_role,
                 "sender_custom_role": sender_custom_role,
                 "mentions": list(mentions or []),
                 "priority": (priority if priority in
                              ("normal", "high", "urgent") else "normal"),
                 "content": content, "ts": now_ts(),
                 "oversight": oversight,
                 "in_reply_to": in_reply_to, "group_id": group_id,
                 "group_name": group_name}
        recipients = [str(m) for m in (members or [])
                      if str(m) != self.username]
        for member in recipients:
            self._enqueue(member, dict(frame))
        self._audit(
            "group_message", group_id=group_id, status="sent",
            priority=frame["priority"],
            size=len(str((content or {}).get("ct") or "")),
            mentions=frame["mentions"], ref_id=mid,
            sender_nickname=sender_nickname, sender_role=sender_role,
            sender_custom_role=sender_custom_role,
            oversight=json.dumps(oversight) if oversight else "",
            content_envelope=json.dumps(content) if content else "")
        self._tap(conversation_id_for_group(group_id), mid)
        return {"id": mid, "group_id": group_id, "queued": recipients}

    def send_channel_frame(self, channel_id: str, content: dict, *,
                           members, message_id: str | None = None,
                           mentions=None, priority: str = "normal",
                           in_reply_to=None, oversight=None,
                           from_name: str = "", from_pubkey: str = "",
                           channel_name: str = "",
                           sender_role: str = "") -> dict:
        """Send one channel frame. NOT the group path: the relay's
        canonical delivered channel frame carries ``channel_id``
        (and ``group_id: None``) — the receiving client's dispatch
        keys channel frames by ``channel_id`` FIRST, so a
        group-shaped frame (channel id sitting in ``group_id``)
        would be keyed against the wrong key store and dropped.
        The frame built here is the relay's exact shape
        (relay._on_channel_send), the audit row is the relay's
        'channel_message' kind with the channel id in group_id
        (as the audit log represents channels), and the signal tap
        names the channel's conversation id — the channel id
        itself, one tap regardless of subscriber count."""
        if not self.username:
            raise TransportError("login required before send_channel_frame")
        mid = message_id or new_id()
        frame = {"type": "message", "id": mid,
                 "from": self.username, "from_name": from_name,
                 "from_pubkey": from_pubkey,
                 "sender_nickname": "", "sender_role": sender_role,
                 "sender_custom_role": "",
                 "oversight": oversight,
                 "mentions": list(mentions or []),
                 "priority": (priority if priority in
                              ("normal", "high", "urgent") else "normal"),
                 "content": content, "ts": now_ts(),
                 "in_reply_to": in_reply_to, "group_id": None,
                 "channel_id": channel_id, "channel_name": channel_name}
        recipients = [str(m) for m in (members or [])
                      if str(m) != self.username]
        for member in recipients:
            self._enqueue(member, dict(frame))
        self._audit(
            "channel_message", group_id=channel_id, status="sent",
            priority=frame["priority"],
            size=len(str((content or {}).get("ct") or "")),
            mentions=frame["mentions"], ref_id=mid,
            sender_role=sender_role,
            oversight=json.dumps(oversight) if oversight else "",
            content_envelope=json.dumps(content) if content else "")
        self._tap(conversation_id_for_group(channel_id), mid)
        return {"id": mid, "channel_id": channel_id,
                "queued": recipients}

    # -- receive: fetch / ack ------------------------------------------------
    def fetch_unacked(self, username: str | None = None) -> list[dict]:
        """Peek my custody queue WITHOUT releasing it: rows in
        seq order, each {"seq", "ts", "frame"} with the frame
        parsed and stamped queued=True — the pending_frames
        contract. Custody ends only at ack()."""
        user = str(username or self.username)
        if not user:
            raise TransportError("fetch_unacked needs a username")
        rows = self._rest(
            "GET", "queue",
            self._eq("to_username", user)
            + "&select=seq,to_username,payload,priority,ts"
            + "&order=seq.asc") or []
        out = []
        for r in rows:
            frame = _loads(r.get("payload"), None)
            if not isinstance(frame, dict):
                continue
            frame["queued"] = True
            out.append({"seq": r.get("seq"), "ts": r.get("ts"),
                        "frame": frame})
        return out

    def ack(self, ids) -> list[dict]:
        """Release custody for durably journaled frame ids — the
        client.py ack contract ({"type": "ack", "ids": [...]})
        executed against the store directly: match MY queue rows
        by the store's rule, delete them BY SEQ, and mark acked
        message rows 'delivered' in al_audit_log (the relay's
        _on_ack + set_audit_status semantics, kind-scoped exactly
        as the store scopes it). Unknown ids retire nothing.
        Returns the acked frames in seq order."""
        wanted = {str(i) for i in (ids or []) if i}
        if not wanted or not self.username:
            return []
        rows = self._rest(
            "GET", "queue",
            self._eq("to_username", self.username)
            + "&select=seq,payload&order=seq.asc") or []
        seqs, acked = [], []
        for r in rows:
            frame = _loads(r.get("payload"), None)
            if not isinstance(frame, dict):
                continue
            if _ack_id_matches(frame, wanted):
                seqs.append(r["seq"])
                acked.append(frame)
        if seqs:
            self._rest("DELETE", "queue",
                       "seq=in.(" + ",".join(str(s) for s in seqs) + ")",
                       prefer="return=minimal")
        for frame in acked:
            if frame.get("type") == "message" and frame.get("id"):
                self._rest(
                    "PATCH", "audit_log",
                    self._eq("ref_id", str(frame["id"]))
                    + "&kind=in.(message,group_message,channel_message)",
                    body={"status": "delivered"},
                    prefer="return=minimal")
        return acked

    def fetch_conversation(self, peer: str | None = None,
                           group_id: str | None = None,
                           limit: int = 200) -> list[dict]:
        """Read a thread back from al_audit_log: content-kind rows
        (CONTENT_AUDIT_KINDS) for the DM with ``peer`` (either
        direction) or for ``group_id``, oldest first, shaped
        exactly as the store shapes audit rows. This is metadata +
        ciphertext envelopes — reading them decrypts nothing."""
        if not self.username:
            raise TransportError("login required before fetch_conversation")
        kinds = ",".join(CONTENT_AUDIT_KINDS)
        base = _AUDIT_SELECT_SEQ + f"&kind=in.({kinds})"
        # The window is selected SERVER-side: the newest ``limit``
        # rows by seq (desc + limit), reversed back to oldest-first
        # below. Fetching the whole thread and slicing locally put
        # the entire history on the wire for every read — on a
        # lossy link the response truncates and the read fails
        # outright (proven live 2026-11-06: the exercise's history
        # check clipped at a fixed byte ceiling on every attempt).
        # limit=0/None keeps the unbounded full read.
        lim = int(limit) if limit else 0
        order = "&order=seq.desc" if lim else "&order=seq.asc"
        if group_id:
            query = (base + "&" + self._eq("group_id", group_id)
                     + order)
        elif peer:
            peer_q = urllib.parse.quote(str(peer), safe="")
            me_q = urllib.parse.quote(self.username, safe="")
            query = (base + "&or=(and(actor.eq." + me_q
                     + ",target.eq." + peer_q + "),and(actor.eq."
                     + peer_q + ",target.eq." + me_q + "))"
                     + order)
        else:
            raise TransportError(
                "fetch_conversation needs peer= or group_id=")
        if lim:
            query += f"&limit={lim}"
        rows = self._rest("GET", "audit_log", query) or []
        shaped = [_shape_audit_row(r) for r in rows]
        if lim:
            shaped.reverse()
        if group_id:
            return shaped
        pair = {self.username, str(peer)}
        mine = [r for r in shaped
                if {r.get("from"), r.get("to")} == pair]
        return mine

    # -- directory / keys / memberships (the daemon's read path) ---------
    # The reads the client daemon's request surface needs, executed
    # against the same tables/views the relay's store reads — same
    # shapes out, so client.py's consumers (pubkey_of,
    # _ensure_group_key, _resync_memberships) cannot tell which
    # transport answered. RLS is the perimeter: every read runs
    # under the agent's own scoped JWT.

    def directory_entry(self, username: str) -> dict | None:
        """One row of the al_directory safe-column view (username,
        display_name, pubkey, sign_pub, capabilities, ...) or
        None. The view never carries secret-bearing columns."""
        rows = self._rest(
            "GET", "directory",
            self._eq("username", str(username))
            + "&select=username,display_name,pubkey,sign_pub,"
              "capabilities,cap_desc,mode,designation,last_seen") or []
        return rows[0] if rows else None

    def group_key_for(self, group_id: str,
                      username: str | None = None) -> dict | None:
        """My wrapped group key record {"epoch", "wrapped"} —
        SupabaseStore.group_key_for's exact return shape."""
        user = str(username or self.username)
        rows = self._rest(
            "GET", "group_keys",
            self._eq("group_id", str(group_id)) + "&"
            + self._eq("username", user)
            + "&select=epoch,wrapped") or []
        if not rows:
            return None
        return {"epoch": int(rows[0]["epoch"]),
                "wrapped": _loads(rows[0].get("wrapped"), None)}

    def channel_key_for(self, channel_id: str,
                        username: str | None = None) -> dict | None:
        """My wrapped channel key record {"epoch", "wrapped"} —
        SupabaseStore.channel_key_for's exact return shape."""
        user = str(username or self.username)
        rows = self._rest(
            "GET", "channel_keys",
            self._eq("channel_id", str(channel_id)) + "&"
            + self._eq("username", user)
            + "&select=epoch,wrapped") or []
        if not rows:
            return None
        return {"epoch": int(rows[0]["epoch"]),
                "wrapped": _loads(rows[0].get("wrapped"), None)}

    def group_members(self, group_id: str) -> list[dict]:
        """Member rows of one group: {username, role, nickname,
        custom_role} — the store's members() columns the client
        consumes."""
        return self._rest(
            "GET", "group_members",
            self._eq("group_id", str(group_id))
            + "&select=username,role,nickname,custom_role,"
              "added_by,joined_at") or []

    def channel_members(self, channel_id: str) -> list[dict]:
        """Subscriber rows of one channel: {username, role,
        added_by, joined_at} (the store's channel_members
        columns)."""
        return self._rest(
            "GET", "channel_members",
            self._eq("channel_id", str(channel_id))
            + "&select=username,role,added_by,joined_at") or []

    def my_memberships(self) -> dict:
        """The relay my_groups result, verbatim shape:
        {"groups": [{group_id, name, settings, my, members}],
         "channels": [{channel_id, name, my_role}]} — built from
        the same tables SupabaseStore.groups_for_user /
        channels_for_user read."""
        if not self.username:
            raise TransportError("login required before my_memberships")
        groups = []
        rows = self._rest(
            "GET", "group_members",
            self._eq("username", self.username)
            + "&select=group_id") or []
        for r in rows:
            gid = r["group_id"]
            grows = self._rest(
                "GET", "groups",
                self._eq("id", gid) + "&select=id,name,settings") or []
            if not grows:
                continue
            members = self.group_members(gid)
            mine = next((m for m in members
                         if m["username"] == self.username), None)
            groups.append({
                "group_id": gid, "name": grows[0].get("name") or "",
                "settings": _loads(grows[0].get("settings"), {}),
                "my": mine, "members": members})
        channels = []
        crows = self._rest(
            "GET", "channel_members",
            self._eq("username", self.username)
            + "&select=channel_id,role") or []
        for r in crows:
            cid = r["channel_id"]
            ch = self._rest(
                "GET", "channels",
                self._eq("id", cid) + "&select=id,name") or []
            if not ch:
                continue
            channels.append({"channel_id": cid,
                             "name": ch[0].get("name") or "",
                             "my_role": r.get("role") or ""})
        return {"groups": groups, "channels": channels}

    # -- read receipts ------------------------------------------------------
    def mark_read(self, ids) -> dict:
        """The relay _on_read contract, executed store-side:
        for each id, the conversation is derived from the
        message's OWN audit row (a reader's claim is never
        trusted), participation is validated (DM addressee /
        group member / channel subscriber; never one's own
        message), the FIRST read wins in al_message_reads, and
        the sender receives a read_receipt frame in its custody
        queue plus a signal tap. Returns the relay's result
        shape: {"read": [ids], "reads": [{"id", "read_at"}]}."""
        if not self.username:
            raise TransportError("login required before mark_read")
        wanted = [str(i) for i in (ids or []) if i][:200]
        recorded = []
        for mid in wanted:
            rows = self._rest(
                "GET", "audit_log",
                self._eq("ref_id", mid)
                + "&select=kind,actor,target,group_id") or []
            meta = rows[0] if rows else None
            if not meta or meta.get("kind") not in (
                    "message", "group_message", "channel_message"):
                continue
            sender = meta.get("actor") or ""
            kind = meta.get("kind")
            gid = meta.get("group_id") or ""
            if not sender or sender == self.username:
                continue
            if kind == "message":
                if self.username != (meta.get("target") or ""):
                    continue
                conv = conversation_id_for_dm(sender, self.username)
            elif kind == "group_message":
                if self.username not in (
                        m["username"] for m in self.group_members(gid)):
                    continue
                conv = conversation_id_for_group(gid)
            else:  # channel_message
                if self.username not in (
                        m["username"] for m in self.channel_members(gid)):
                    continue
                conv = conversation_id_for_group(gid)
            existing = self._rest(
                "GET", "message_reads",
                self._eq("message_id", mid) + "&"
                + self._eq("reader", self.username)
                + "&select=read_at") or []
            if existing:
                read_at = int(existing[0]["read_at"])
            else:
                read_at = now_ts()
                self._rest("POST", "message_reads", body={
                    "message_id": mid, "reader": self.username,
                    "read_at": read_at}, prefer="return=minimal")
            recorded.append({"id": mid, "read_at": read_at})
            self._audit("message_read", target=sender, group_id=gid,
                        status="read", ref_id=mid)
            self._enqueue(sender, {
                "type": "read_receipt", "id": mid,
                "from": self.username,
                "reader": self.username, "read_at": read_at,
                "group_id": gid or None,
                "channel_id": gid if kind == "channel_message"
                else None})
            self._tap(conv, mid)
        return {"read": [r["id"] for r in recorded],
                "reads": recorded}

    # -- doorbell wiring -------------------------------------------------------
    def listen_signals(self, callback) -> bool:
        """Run the Firebase signal stream (blocking; use a
        thread). ``callback(conversation_key, signal)`` fires per
        signal event. On stream failure the slow-sync flag
        engages and False returns — degraded, never dark."""
        def _on_event(path, data):
            self.slow_sync_active = False
            if path in ("/", "", None):
                if isinstance(data, dict):
                    for key, signal in data.items():
                        callback(key, signal)
                return
            callback(str(path).lstrip("/"), data)

        try:
            self.doorbell.listen_signals(_on_event)
            return True
        except DoorbellError as exc:
            self.slow_sync_active = True
            self.last_signal_error = str(exc)
            return False

    def listen_supervised(self, callback, on_frames=None,
                          stop_event=None) -> None:
        """The stream supervisor: listen, and on ANY stream end
        or failure reconnect WITHOUT LIMIT — first retry
        immediate, backoff doubling, every wait capped at
        RECONNECT_BACKOFF_CAP_S (5s). While the stream is down
        slow_sync_active stays engaged, so run_slow_sync (the
        caller's companion thread) is the wakeup path; a stream
        event clears the flag. Runs until stop_event is set —
        intended for a dedicated thread."""
        stop = stop_event or threading.Event()
        attempt = 0
        while not stop.is_set():
            if self.listen_signals(callback):
                attempt = 0
            else:
                attempt += 1
            if stop.is_set():
                return
            delay = next_backoff_s(attempt - 1) if attempt else 0.0
            if delay:
                stop.wait(delay)

    def slow_sync_once(self) -> list[dict]:
        """One slow-sync pass: the unacked fetch a woken agent
        would do. Pure read — ack stays the caller's journal call."""
        return self.fetch_unacked()

    def run_slow_sync(self, on_frames, stop_event=None) -> None:
        """The fallback loop — the ONLY PostgREST poll in this
        design, at SLOW_SYNC_INTERVAL_SECONDS (60s), performing a
        fetch ONLY while slow_sync_active (the doorbell stream is
        down). Intended for a dedicated thread for the transport's
        lifetime; returns when stop_event is set. Beats never come
        through here — they are RTDB-only, on the doorbell's own
        thread, at 5s."""
        stop = stop_event or threading.Event()
        while not stop.is_set():
            if self.slow_sync_active:
                try:
                    frames = self.slow_sync_once()
                    if frames:
                        on_frames(frames)
                except TransportError:
                    pass  # still degraded; the next cadence retries
            stop.wait(SLOW_SYNC_INTERVAL_SECONDS)

    # ================================================================
    # v2.0 coverage: the full request surface (work lifecycle,
    # group/channel administration, vault, blobs, grants, library,
    # account). Two execution shapes, chosen per operation by what
    # the Phase 1 RLS policies can express under the agent's own
    # JWT:
    #
    # * PostgREST directly (this class): reads and single-writer
    #   writes whose checks the transport can perform in the
    #   relay's own order against rows the agent may see — work
    #   inbox / progress / checkpoint / resume-failed, chain
    #   reads, key distribution, group vault add/list, the
    #   credentials-vault pointer, upload-session start/status,
    #   history paging, self-report.
    # * Edge functions (service role): multi-writer sequences,
    #   exact error-code parity where RLS invisibility would
    #   collapse the relay's ordered checks, server-side compute
    #   (blob assembly, receipt signing, trust) and the
    #   service-only tables (invites, grant authz tokens) —
    #   agentlink-work / agentlink-groups / agentlink-grants /
    #   agentlink-blobs / agentlink-library / agentlink-account.
    #
    # Every refusal raises Refusal with the relay's reason string;
    # client.py maps it to the identical RequestFailed.
    # ================================================================

    # -- Edge plumbing -------------------------------------------------
    def _fn_post(self, name: str, route: str, payload: dict,
                 _retried: bool = False) -> dict:
        """POST to a sibling Edge function under the agent JWT.

        The functions base is the login function's parent path
        (``.../functions/v1``). A 401 triggers exactly one
        re-login + retry, mirroring _rest. An Edge refusal body
        (``{error, detail}``) becomes a Refusal carrying the
        relay's reason string the function answered with."""
        if not self.config.login_edge_url:
            raise TransportError("no Edge functions base configured")
        base = self.config.login_edge_url.rsplit("/", 1)[0]
        url = f"{base}/{name}" + (f"/{route}" if route else "")
        headers = {"Content-Type": "application/json",
                   "apikey": self.config.anon_key,
                   "Authorization":
                       f"Bearer {self._jwt or self.config.anon_key}"}
        body = json.dumps(payload).encode()
        status, _h, raw = self._opener("POST", url, headers, body)
        if status == 401 and not _retried \
                and self._signer is not None and self.username:
            self._login(self.username, self._signer)
            return self._fn_post(name, route, payload, _retried=True)
        data: dict = {}
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    data = parsed
            except Exception:
                data = {}
        if status >= 400:
            raise Refusal(str(data.get("error") or f"http_{status}"),
                          str(data.get("detail")
                              or data.get("message") or ""))
        return data

    def _fn_data(self, name: str, route: str, payload: dict) -> dict:
        """_fn_post for the relay-shaped functions: their success
        body is ``{ok: true, ...relay data}``; the caller wants
        the relay data exactly as the relay's result frame carried
        it."""
        data = self._fn_post(name, route, payload)
        return {k: v for k, v in data.items() if k != "ok"}

    @staticmethod
    def _frame_body(frame: dict) -> dict:
        """The request frame minus its type — the Edge route's
        input (the function's identity comes from the JWT, never
        from the body)."""
        return {k: v for k, v in frame.items() if k != "type"}

    # -- decision link ---------------------------------------------------
    def update_decision_link(self, state, detail=None) -> None:
        """The ``decision_link_update`` frame's serverless home:
        a PATCH of my own al_users row, validated EXACTLY as the
        relay's setters validate (state only ever 'linked' or
        'pending'; the detail stored as the cleaned
        {mode, verified, checked_at} JSON text, and only when the
        mode is a lawful one — anything else is a no-op, as on
        the relay). The stored declaration is also refreshed, so
        the next token-refresh login re-declares the newest
        state rather than the login-time one."""
        if not self.username:
            raise TransportError(
                "login required before update_decision_link")
        body: dict = {}
        if str(state or "") in ("linked", "pending"):
            body["decision_link"] = str(state)
            self._decision_link = str(state)
        if isinstance(detail, dict):
            mode = str(detail.get("mode") or "")
            if mode in ("config", "in_process", "handlers",
                        "convention", "none"):
                cleaned = {
                    "mode": mode,
                    "verified": bool(detail.get("verified")),
                    "checked_at": int(detail.get("checked_at") or 0)}
                body["decision_link_detail"] = json.dumps(cleaned)
                self._decision_detail = cleaned
        if body:
            self._rest("PATCH", "users",
                       self._eq("username", self.username),
                       body=body, prefer="return=minimal")

    # -- history backfill --------------------------------------------------
    def fetch_history_page(self, limit: int = 200,
                           before_seq: int | None = None) -> list[dict]:
        """One page of my relay-history equivalent: the store's
        content_audit_for_user contract executed against
        al_audit_log under RLS (the Phase 1 party policy IS the
        party scoping: actor is me, target is me, I am mentioned,
        or the row's group/channel is one I belong to). Content
        kinds only, ``seq < before_seq`` when a cursor is given,
        the NEWEST ``limit`` rows presented OLDEST-first, shaped
        by the same _shape_audit_row the conversation reads use —
        so client.py's sync_history pages and merges serverless
        rows through the identical code path as relay rows."""
        if not self.username:
            raise TransportError(
                "login required before fetch_history_page")
        limit = max(1, min(int(limit or 200), 500))
        kinds = ",".join(CONTENT_AUDIT_KINDS)
        query = _AUDIT_SELECT_SEQ + f"&kind=in.({kinds})"
        if before_seq is not None:
            query += f"&seq=lt.{int(before_seq)}"
        query += f"&order=seq.desc&limit={limit}"
        rows = self._rest("GET", "audit_log", query) or []
        shaped = [_shape_audit_row(r) for r in rows]
        shaped.reverse()
        return shaped

    # -- work: shapes ---------------------------------------------------
    @staticmethod
    def _shape_work_row(row: dict, deliveries=None,
                        checkpoint="absent") -> dict:
        """One al_work row in SupabaseStore.get_work's shape:
        envelope columns JSON-decoded (content_enc / content_self
        default {}, content_group defaults None), deliveries
        expanded + decoded when given, the checkpoint attached
        only when one exists."""
        out = dict(row)
        out["content_enc"] = _loads(out.get("content_enc"), {}) or {}
        out["content_self"] = _loads(out.get("content_self"), {}) or {}
        out["content_group"] = _loads(out.get("content_group"), None)
        if deliveries is not None:
            shaped = []
            for d in deliveries:
                dd = dict(d)
                dd["content_enc"] = _loads(dd.get("content_enc"),
                                           {}) or {}
                dd["content_self"] = _loads(dd.get("content_self"),
                                            {}) or {}
                dd["content_group"] = _loads(dd.get("content_group"),
                                             None)
                if "content_next" in dd:
                    dd["content_next"] = _loads(
                        dd.get("content_next"), None)
                shaped.append(dd)
            out["deliveries"] = shaped
        if checkpoint != "absent" and checkpoint is not None:
            cp = dict(checkpoint)
            for k in ("content_assigner", "content_group"):
                cp[k] = _loads(cp.get(k), None) if cp.get(k) else None
            out["checkpoint"] = cp
        return out

    def _work_row_raw(self, work_id: str) -> dict | None:
        """The raw al_work row under RLS (a non-party's row is
        simply invisible — the relay's unknown_work and a
        stranger's permission_denied collapse here by design of
        the perimeter, never into a leak)."""
        rows = self._rest("GET", "work",
                          self._eq("id", str(work_id))) or []
        return rows[0] if rows else None

    def _work_expand(self, row: dict) -> dict:
        """get_work parity: deliveries (ts ascending) + the
        checkpoint when one exists."""
        wid = row["id"]
        drows = self._rest(
            "GET", "work_deliveries",
            self._eq("work_id", wid) + "&order=ts.asc") or []
        cps = self._rest(
            "GET", "work_checkpoints",
            self._eq("work_id", wid)) or []
        return self._shape_work_row(
            row, drows, cps[0] if cps else "absent")

    def get_work_row(self, work_id: str) -> dict | None:
        row = self._work_row_raw(work_id)
        return self._work_expand(row) if row is not None else None

    # -- work: PostgREST paths -------------------------------------------
    def work_inbox(self, status: str | None = None,
                   group_id: str | None = None) -> dict:
        """The work_inbox result: list_work's contract — work
        where I am assignee OR assigner, optional status / group
        filters, created_at ascending, each row expanded
        (deliveries + checkpoint) exactly as get_work shapes it."""
        if not self.username:
            raise TransportError("login required before work_inbox")
        me = urllib.parse.quote(self.username, safe="")
        query = (f"or=(assignee.eq.{me},assigner.eq.{me})"
                 "&order=created_at.asc")
        if status:
            query += "&" + self._eq("status", status)
        if group_id:
            query += "&" + self._eq("group_id", group_id)
        rows = self._rest("GET", "work", query) or []
        return {"work": [self._work_expand(r) for r in rows]}

    def work_progress(self, frame: dict) -> dict:
        """work_progress executed store-side, in the relay's
        check order: unknown_work -> permission_denied (assignee
        only) -> bad_percent -> bad_status. The write is the
        store's set_work_progress; the assigner receives the
        relay's event frame (with its encrypted note) through
        the custody queue + a signal tap, and group members the
        metadata-only variant — the queue+tap channel is the
        serverless live channel, exactly-once by the mailbox
        claim, so an update the relay would have delivered live
        can never be lost here."""
        wid = str(frame.get("work_id") or "")
        row = self._work_row_raw(wid)
        if row is None:
            raise Refusal("unknown_work")
        if row["assignee"] != self.username:
            raise Refusal("permission_denied",
                          "only the assignee can report progress")
        percent = frame.get("percent")
        if not isinstance(percent, int) \
                or not (0 <= percent <= 100):
            raise Refusal("bad_percent",
                          "percent must be an integer 0-100")
        if row["status"] not in ("assigned", "in_progress",
                                 "changes_requested"):
            raise Refusal("bad_status", f"work is {row['status']}")
        new_status = "in_progress" if row["status"] == "assigned" \
            else row["status"]
        self._rest("PATCH", "work", self._eq("id", wid), body={
            "progress_percent": percent, "progress_at": now_ts(),
            "status": new_status, "updated_at": now_ts()},
            prefer="return=minimal")
        updated = self.get_work_row(wid)
        event = {"type": "work_progress", "work": updated,
                 "percent": percent, "ts": now_ts(),
                 "content_enc": frame.get("content_enc"),
                 "content_self": frame.get("content_self")}
        if row["assigner"] != self.username:
            self._enqueue(row["assigner"], event)
            self._tap(f"work-{wid}", wid)
        if row.get("group_id"):
            meta = {**event, "content_enc": None,
                    "content_self": None}
            for m in self.group_members(row["group_id"]):
                if m["username"] not in (self.username,
                                         row["assigner"]):
                    self._enqueue(m["username"], dict(meta))
            self._tap(row["group_id"], wid)
        self._audit("work_progress", target=row["assigner"],
                    group_id=row.get("group_id") or "",
                    work_id=wid, status=str(percent))
        return {"work": updated}

    def work_checkpoint(self, frame: dict) -> dict:
        """The checkpoint mirror, store-side: unknown_work ->
        permission_denied (assignee only) -> stale_attempt, then
        the store's set_checkpoint upsert (the row travels with
        the assignment), the relay's work_checkpoint frame to the
        assigner, and the work_checkpoint audit row."""
        wid = str(frame.get("work_id") or "")
        row = self._work_row_raw(wid)
        if row is None:
            raise Refusal("unknown_work")
        if row["assignee"] != self.username:
            raise Refusal("permission_denied",
                          "only the assignee can checkpoint")
        try:
            attempt = int(frame.get("attempt")
                          or row.get("attempt") or 1)
        except (TypeError, ValueError):
            attempt = int(row.get("attempt") or 1)
        if attempt != int(row.get("attempt") or 1):
            raise Refusal("stale_attempt")
        work_view = self.get_work_row(wid)
        self._rest("POST", "work_checkpoints", body={
            "work_id": wid, "attempt": attempt,
            "by_user": self.username,
            "content_assigner":
                json.dumps(frame["content_assigner"])
                if frame.get("content_assigner") else "",
            "content_group":
                json.dumps(frame["content_group"])
                if frame.get("content_group") else "",
            "ts": now_ts()},
            prefer="return=minimal,resolution=merge-duplicates")
        if row["assigner"] != self.username:
            self._enqueue(row["assigner"], {
                "type": "work_checkpoint", "work": work_view,
                "content_assigner": frame.get("content_assigner"),
                "by": self.username, "attempt": attempt})
            self._tap(f"work-{wid}", wid)
        self._audit("work_checkpoint", target=row["assigner"],
                    group_id=row.get("group_id") or "",
                    work_id=wid, status=f"attempt {attempt}")
        return {"work_id": wid, "attempt": attempt}

    def work_resume_failed(self, frame: dict) -> dict:
        """resume_failed, store-side: the relay's two audit rows
        (the direct audit carrying the reason, the activity row
        carrying status 'explicit') and the work_update note
        frame to the assigner. The relay performs NO party check
        here beyond the work existing — mirrored exactly."""
        wid = str(frame.get("work_id") or "")
        row = self._work_row_raw(wid)
        if row is None:
            raise Refusal("unknown_work")
        self._audit("resume_failed", target=row["assigner"],
                    group_id=row.get("group_id") or "",
                    work_id=wid,
                    status=str(frame.get("reason") or ""))
        self._audit("resume_failed", target=row["assigner"],
                    group_id=row.get("group_id") or "",
                    work_id=wid, status="explicit")
        if row["assigner"] != self.username:
            self._enqueue(row["assigner"], {
                "type": "work_update",
                "work": self.get_work_row(wid),
                "note": "assignee reported resume_failed"})
            self._tap(f"work-{wid}", wid)
        return {"work_id": wid}

    # -- work: Edge paths (multi-writer sequences) -------------------------
    def work_assign(self, frame: dict) -> dict:
        """assign via agentlink-work: per-assignee validation in
        the relay's order, work-row creation, decision-link
        notices, custody work_assigned frames, audits."""
        return self._fn_data("agentlink-work", "assign",
                             self._frame_body(frame))

    def work_deliver(self, frame: dict) -> dict:
        """deliver_work via agentlink-work: proof verification
        against the registered signing key, the delivery insert,
        proof/status writes, library indexing, cover batch and
        alert resolution — the sequence only a service-role
        writer can complete whole."""
        return self._fn_data("agentlink-work", "deliver",
                             self._frame_body(frame))

    def work_action(self, frame: dict) -> dict:
        """work_action via agentlink-work: approval-gate and
        delivered-state decisions, chain pause/advance."""
        return self._fn_data("agentlink-work", "action",
                             self._frame_body(frame))

    def chain_create(self, frame: dict) -> dict:
        return self._fn_data("agentlink-work", "chain_create",
                             self._frame_body(frame))

    def chain_cancel(self, frame: dict) -> dict:
        return self._fn_data("agentlink-work", "chain_cancel",
                             self._frame_body(frame))

    # -- chains: PostgREST reads -------------------------------------------
    @staticmethod
    def _shape_chain_row(row: dict, steps: list[dict]) -> dict:
        out = dict(row)
        shaped = []
        for s in sorted(steps, key=lambda x: x.get("position", 0)):
            d = dict(s)
            d["assignees"] = _loads(d.get("assignees"), []) or []
            d["envelopes"] = _loads(d.get("envelopes"), {}) or {}
            d["content_group"] = _loads(d.get("content_group"), None)
            d["handoff"] = _loads(d.get("handoff"), []) or []
            shaped.append(d)
        out["steps"] = shaped
        return out

    def chain_row(self, chain_id: str) -> dict | None:
        """get_chain's shape: the chain row + position-ordered
        steps with JSON columns decoded."""
        rows = self._rest("GET", "chains",
                          self._eq("id", str(chain_id))) or []
        if not rows:
            return None
        steps = self._rest(
            "GET", "chain_steps",
            self._eq("chain_id", str(chain_id))
            + "&order=position.asc") or []
        return self._shape_chain_row(rows[0], steps)

    def chain_list(self) -> dict:
        """chain_list: chains_for_user's contract — chains where
        I am the creator or a step assignee (RLS already scopes
        the reads to chains I am a party of; the involved filter
        is applied verbatim on top)."""
        rows = self._rest("GET", "chains",
                          "&order=created_at.desc&limit=200") or []
        out = []
        for r in rows:
            chain = self.chain_row(r["id"])
            if chain is None:
                continue
            involved = {chain["creator"]}
            for st in chain["steps"]:
                involved.update(st.get("assignees") or [])
                if st.get("assignee"):
                    involved.add(st["assignee"])
            if self.username in involved:
                out.append(chain)
        return {"chains": out}

    def chain_get(self, frame: dict) -> dict:
        """chain_get: unknown_chain -> permission_denied (party
        test: creator, a step assignee, or any member of the
        chain's group — evaluated against rows RLS lets me see;
        a chain I have no party path to is invisible and reads
        unknown_chain, the perimeter's no-oracle shape)."""
        chain = self.chain_row(str(frame.get("chain_id") or ""))
        if chain is None:
            raise Refusal("unknown_chain")
        involved = {chain["creator"]}
        for st in chain["steps"]:
            involved.update(st.get("assignees") or [])
        member = False
        if chain.get("group_id"):
            member = any(
                m["username"] == self.username
                for m in self.group_members(chain["group_id"]))
        if self.username not in involved and not member:
            raise Refusal("permission_denied")
        return {"chain": chain}

    def chain_context(self, frame: dict) -> dict:
        """chain_context: the step this work belongs to and the
        NEXT step's assignees (the delivery-time chain-handoff
        read). No step -> the relay's empty shape."""
        wid = str(frame.get("work_id") or "")
        steps = self._rest("GET", "chain_steps",
                           self._eq("work_id", wid)) or []
        if not steps:
            return {"chain_id": "", "next_assignees": []}
        step = steps[0]
        nxt_assignees: list = []
        chain = self.chain_row(step["chain_id"])
        if chain is not None:
            nxt = next((x for x in chain["steps"]
                        if x["position"] == step["position"] + 1),
                       None)
            if nxt is not None:
                nxt_assignees = nxt.get("assignees") or []
        return {"chain_id": step["chain_id"],
                "next_assignees": nxt_assignees}

    # -- groups / channels: reads + key distribution (PostgREST) -----------
    def _group_view(self, group_id: str) -> dict | None:
        rows = self._rest(
            "GET", "groups",
            self._eq("id", str(group_id))
            + "&select=id,name,settings,creator,created_at") or []
        return rows[0] if rows else None

    def _my_group_role(self, group_id: str) -> str | None:
        rows = self._rest(
            "GET", "group_members",
            self._eq("group_id", str(group_id)) + "&"
            + self._eq("username", self.username)
            + "&select=role") or []
        return rows[0]["role"] if rows else None

    def _my_channel_role(self, channel_id: str) -> str | None:
        rows = self._rest(
            "GET", "channel_members",
            self._eq("channel_id", str(channel_id)) + "&"
            + self._eq("username", self.username)
            + "&select=role") or []
        return rows[0]["role"] if rows else None

    def group_members_view(self, frame: dict) -> dict:
        """group_members: unknown_group -> not_a_member, then
        {group_id, name, settings, members} in the store's
        member shape. (A group I cannot see at all — not a
        member — is indistinguishable from a nonexistent one
        under RLS and reads unknown_group; the perimeter's
        no-oracle property, documented in the coverage
        evidence.)"""
        gid = str(frame.get("group_id") or "")
        group = self._group_view(gid)
        if group is None:
            raise Refusal("unknown_group")
        members = self.group_members(gid)
        if not any(m["username"] == self.username for m in members):
            raise Refusal("not_a_member")
        return {"group_id": gid, "name": group.get("name") or "",
                "settings": _loads(group.get("settings"), {}) or {},
                "members": members}

    def channel_members_view(self, frame: dict) -> dict:
        """channel_members: unknown_channel -> not_a_member,
        then {channel_id, name, members}."""
        cid = str(frame.get("channel_id") or "")
        rows = self._rest(
            "GET", "channels",
            self._eq("id", cid) + "&select=id,name,creator") or []
        if not rows:
            raise Refusal("unknown_channel")
        members = self.channel_members(cid)
        if not any(m["username"] == self.username for m in members):
            raise Refusal("not_a_member")
        return {"channel_id": cid,
                "name": rows[0].get("name") or "",
                "members": members}

    def set_group_keys(self, frame: dict) -> dict:
        """set_group_keys, store-side: the relay's admin gate
        (unknown_group -> permission_denied unless my role is
        admin/superadmin), then one wrapped-key row per named
        member (non-members in the map are skipped, exactly as
        the relay skips them) and the relay's group_key frame to
        each recipient through the custody queue."""
        gid = str(frame.get("group_id") or "")
        if self._group_view(gid) is None:
            raise Refusal("unknown_group")
        if self._my_group_role(gid) not in ("admin", "superadmin"):
            raise Refusal("permission_denied",
                          "only admins can distribute group keys")
        epoch = int(frame.get("epoch") or 1)
        wrapped_map = frame.get("wrapped") or {}
        member_names = {m["username"]
                        for m in self.group_members(gid)}
        my_pub = ""
        entry = self.directory_entry(self.username)
        if entry:
            my_pub = entry.get("pubkey") or ""
        for raw_user, wrapped in wrapped_map.items():
            u = str(raw_user)
            if u not in member_names:
                continue
            self._rest("POST", "group_keys", body={
                "group_id": gid, "username": u, "epoch": epoch,
                "wrapped": json.dumps(wrapped)},
                prefer="return=minimal,resolution=merge-duplicates")
            if u != self.username:
                self._enqueue(u, {
                    "type": "group_key", "group_id": gid,
                    "epoch": epoch, "wrapped": wrapped,
                    "from": self.username, "from_pubkey": my_pub})
        self._tap(gid, f"gk-{epoch}")
        return {"group_id": gid, "epoch": epoch}

    def set_channel_keys(self, frame: dict) -> dict:
        """set_channel_keys, store-side — the channel twin of
        set_group_keys (the relay's channel_key frame carries no
        from_pubkey; mirrored)."""
        cid = str(frame.get("channel_id") or "")
        rows = self._rest("GET", "channels",
                          self._eq("id", cid) + "&select=id") or []
        if not rows:
            raise Refusal("unknown_channel")
        if self._my_channel_role(cid) not in ("admin", "superadmin"):
            raise Refusal("permission_denied",
                          "only admins can distribute channel keys")
        epoch = int(frame.get("epoch") or 1)
        wrapped_map = frame.get("wrapped") or {}
        member_names = {m["username"]
                        for m in self.channel_members(cid)}
        for raw_user, wrapped in wrapped_map.items():
            u = str(raw_user)
            if u not in member_names:
                continue
            self._rest("POST", "channel_keys", body={
                "channel_id": cid, "username": u, "epoch": epoch,
                "wrapped": json.dumps(wrapped)},
                prefer="return=minimal,resolution=merge-duplicates")
            if u != self.username:
                self._enqueue(u, {
                    "type": "channel_key", "channel_id": cid,
                    "epoch": epoch, "wrapped": wrapped,
                    "from": self.username})
        self._tap(cid, f"ck-{epoch}")
        return {"channel_id": cid, "epoch": epoch}

    # -- groups / channels: administration (Edge) -------------------------
    def group_admin(self, route: str, frame: dict) -> dict:
        """The whole group/channel admin family via
        agentlink-groups: exact relay error order, caps,
        membership events and invite custody the RLS surface
        cannot express (service-only invites, key-row cleanup,
        plain-member adds under group settings)."""
        return self._fn_data("agentlink-groups", route,
                             self._frame_body(frame))

    # -- group vault (PostgREST) -------------------------------------------
    @staticmethod
    def _shape_vault_row(row: dict) -> dict:
        out = dict(row)
        out["descriptor"] = _loads(out.get("descriptor"), {}) or {}
        out["pinned"] = bool(out.get("pinned"))
        return out

    def vault_add(self, frame: dict) -> dict:
        """vault_add, store-side, in the relay's check order:
        unknown_group -> not_a_member -> the group's vault_add
        admins_only setting -> bad_vault_file (a descriptor
        needs a blob_id). The insert is the store's vault_add."""
        gid = str(frame.get("group_id") or "")
        group = self._group_view(gid)
        if group is None:
            raise Refusal("unknown_group")
        role = self._my_group_role(gid)
        if role is None:
            raise Refusal("not_a_member")
        settings = _loads(group.get("settings"), {}) or {}
        if settings.get("vault_add") == "admins_only" \
                and role not in ("admin", "superadmin"):
            raise Refusal("permission_denied",
                          "only admins can add to this group's vault")
        descriptor = frame.get("descriptor") or {}
        if not descriptor.get("blob_id"):
            raise Refusal("bad_vault_file",
                          "descriptor needs a blob_id")
        entry = {"id": new_id("v-")[:14], "group_id": gid,
                 "name": descriptor.get("name", ""),
                 "size": int(descriptor.get("size") or 0),
                 "sha256": descriptor.get("sha256", ""),
                 "blob_id": descriptor.get("blob_id", ""),
                 "descriptor": descriptor,
                 "added_by": self.username,
                 "pinned": 1 if frame.get("pinned") else 0,
                 "ts": now_ts()}
        rows = self._rest("POST", "vault", body=entry,
                          prefer="return=representation")
        saved = rows[0] if rows else entry
        self._audit("vault_added", group_id=gid,
                    status=descriptor.get("name", ""))
        return {"entry": self._shape_vault_row(saved)}

    def vault_list(self, frame: dict) -> dict:
        """vault_list: member-only; entries ordered pinned
        first, then newest — the store's vault_list order."""
        gid = str(frame.get("group_id") or "")
        if self._group_view(gid) is None:
            raise Refusal("unknown_group")
        if self._my_group_role(gid) is None:
            raise Refusal("not_a_member")
        rows = self._rest(
            "GET", "vault",
            self._eq("group_id", gid)
            + "&order=pinned.desc,ts.desc") or []
        return {"files": [self._shape_vault_row(r) for r in rows]}

    # -- credentials vault pointer (PostgREST, own row) ---------------------
    @staticmethod
    def _valid_oversight_shape(ov) -> bool:
        """The relay's _valid_oversight, verbatim: shape only —
        {alg: x25519-chacha20poly1305, eph_pub, nonce, ct} with
        non-empty string parts."""
        if not isinstance(ov, dict):
            return False
        if ov.get("alg") != "x25519-chacha20poly1305":
            return False
        return all(isinstance(ov.get(k), str) and ov.get(k)
                   for k in ("eph_pub", "nonce", "ct"))

    def _vault_meta(self) -> dict | None:
        rows = self._rest(
            "GET", "users",
            self._eq("username", self.username)
            + "&select=vault_labels,vault_content,vault_blob,"
              "vault_version,vault_entries") or []
        if not rows:
            return None
        r = rows[0]
        return {"blob_id": r.get("vault_blob") or "",
                "labels": r.get("vault_labels") or "",
                "version": int(r.get("vault_version") or 0),
                "entries": int(r.get("vault_entries") or 0)}

    def vault_publish(self, frame: dict) -> dict:
        """vault_publish, store-side: the relay's shape
        validation (bad_vault_publish), then set_vault_meta's
        version guard executed against my own al_users row —
        a publish whose version is BELOW the stored one is
        refused as stale (accepted=false) so a zombie host
        cannot rewind the vault; equal is the idempotent
        re-point. The audit row and the {accepted, version}
        answer (the version re-read after the attempt) are the
        relay's own."""
        blob_id = str(frame.get("blob_id") or "")
        version = frame.get("version")
        entries = frame.get("entry_count")
        labels = frame.get("labels")
        content = frame.get("content")
        if not blob_id or len(blob_id) > 200 \
                or not isinstance(version, int) \
                or not (0 <= version <= 2 ** 31) \
                or not isinstance(entries, int) \
                or not (0 <= entries <= 100000) \
                or (labels is not None
                    and not self._valid_oversight_shape(labels)) \
                or (content is not None
                    and not self._valid_oversight_shape(content)):
            raise Refusal(
                "bad_vault_publish",
                "vault publish needs a blob id, a non-negative "
                "integer revision and entry count, and (when "
                "present) well-formed oversight envelopes")
        current = self._vault_meta() or {}
        stored = int(current.get("version") or 0)
        accepted = version >= stored
        if accepted:
            self._rest("PATCH", "users",
                       self._eq("username", self.username), body={
                           "vault_labels":
                               json.dumps(labels)
                               if labels is not None else "",
                           "vault_content":
                               json.dumps(content)
                               if content is not None else "",
                           "vault_blob": blob_id,
                           "vault_version": int(version),
                           "vault_entries": int(entries)},
                       prefer="return=minimal")
        self._audit("vault_published" if accepted
                    else "vault_publish_stale",
                    ref_id=blob_id, status=f"rev{version}")
        after = self._vault_meta() or {}
        return {"accepted": accepted,
                "version": int(after.get("version") or 0)}

    def vault_fetch_meta(self) -> dict:
        """vault_fetch_meta: {present, blob_id, version,
        entries} — never the labels or content themselves.
        Present mirrors the store's meta truth: a pointer
        exists when a blob id or a labels envelope stands."""
        meta = self._vault_meta()
        if not meta:
            return {"present": False, "blob_id": "", "version": 0,
                    "entries": 0}
        present = bool(meta.get("blob_id") or meta.get("labels"))
        return {"present": present,
                "blob_id": meta.get("blob_id") or "",
                "version": int(meta.get("version") or 0),
                "entries": int(meta.get("entries") or 0)}

    # -- blobs ---------------------------------------------------------------
    def _r2_presign(self, action: str, blob_id: str) -> str:
        """One presigned R2 URL from agentlink-r2sign (the
        entitlement-checked signer). Its refusals arrive as
        Refusals in the relay's vocabulary."""
        data = self._fn_post("agentlink-r2sign", "",
                             {"action": action, "blob_id": blob_id})
        url = str(data.get("url") or "")
        if not url:
            raise TransportError("r2sign returned no URL")
        return url

    def _http_bytes(self, method: str, url: str,
                    data: bytes | None = None) -> tuple[int, bytes]:
        status, _h, raw = self._opener(method, url, {}, data)
        return status, raw or b""

    def blob_put(self, frame: dict) -> dict:
        """blob_put, the small-blob path: the relay's guards in
        its order (bad_blob on undecodable/empty data; for_group
        membership -> not_a_member; for_user existence ->
        unknown_username; neither scope -> bad_blob — a
        channel-only small blob is refused here exactly as the
        relay refuses it, a recorded divergence of the relay's
        own making that parity preserves), then the metadata
        row FIRST (r2sign presigns only for existing rows —
        the entitlement anchor) and the object PUT through the
        presigned URL. A failed PUT answers blob_store_failed,
        the relay's own words for an object-write failure."""
        import base64 as _b64
        import hashlib as _hl
        try:
            data = _b64.b64decode(frame.get("data_b64") or "")
        except Exception:
            raise Refusal("bad_blob")
        if not data:
            raise Refusal("bad_blob", "empty blob")
        for_user = str(frame.get("for_user") or "")
        for_group = str(frame.get("for_group") or "")
        if for_group:
            if self._my_group_role(for_group) is None:
                raise Refusal("not_a_member")
        elif for_user:
            if self.directory_entry(for_user) is None:
                raise Refusal("unknown_username", for_user)
        else:
            raise Refusal("bad_blob",
                          "blob needs for_user or for_group")
        blob_id = "b-" + _hl.sha256(data).hexdigest()
        # put_blob_meta parity: an upsert (the store's INSERT OR
        # REPLACE / merge-duplicates), and whole_sha is NOT
        # recorded on the small-blob path — the relay's own call
        # never passes it, so the row's dedup key stays empty
        # exactly as on the relay. (RLS narrows one corner: a
        # DIFFERENT owner re-putting identical bytes cannot
        # replace the meta row here, where the relay's store
        # would; the object bytes are identical either way, so
        # only the recorded owner can differ.)
        self._rest("POST", "blobs", body={
            "id": blob_id, "owner": self.username,
            "for_user": for_user, "for_group": for_group,
            "for_channel": "", "whole_sha": "",
            "size": len(data), "created_at": now_ts()},
            prefer="return=minimal,resolution=merge-duplicates")
        url = self._r2_presign("put", blob_id)
        status, _raw = self._http_bytes("PUT", url, data)
        if status >= 300:
            raise Refusal("blob_store_failed",
                          "object storage write failed; retry")
        return {"blob_id": blob_id, "size": len(data)}

    def blob_get(self, frame: dict) -> dict:
        """blob_get: the metadata row under RLS IS the
        entitlement check (owner / for_user / group member /
        channel member may read it; anyone else sees nothing
        and hears permission_denied — no oracle, the relay's
        own rule). The object comes back through a presigned
        GET; a missing object is unknown_blob, a failed read
        blob_fetch_failed."""
        import base64 as _b64
        blob_id = str(frame.get("blob_id") or "")
        rows = self._rest("GET", "blobs",
                          self._eq("id", blob_id)) or []
        if not rows:
            raise Refusal("permission_denied",
                          "not a recipient of this blob")
        url = self._r2_presign("get", blob_id)
        status, raw = self._http_bytes("GET", url)
        if status == 404:
            raise Refusal("unknown_blob")
        if status >= 300:
            raise Refusal("blob_fetch_failed",
                          "object storage read failed; retry")
        return {"blob_id": blob_id,
                "data_b64": _b64.b64encode(raw).decode(),
                "size": len(raw)}

    def blob_delete(self, frame: dict) -> dict:
        """blob_delete via agentlink-blobs: owner-or-group-admin
        authorization, object deletion, metadata deletion —
        a service-role sequence."""
        return self._fn_data("agentlink-blobs", "delete",
                             self._frame_body(frame))

    def blob_session_start(self, frame: dict) -> dict:
        """blob_session_start, store-side, in the relay's exact
        order: the scope guards as INDEPENDENT checks (group
        membership, channel membership, user existence — the
        relay tests each scope that is present, in that order),
        then dedup (a completed blob with this whole-file hash
        from me to this exact scope — all four scope columns
        compared, as find_blob_by_whole_sha compares them —
        answers by reference), else a fresh own-row upload
        session with the relay's clamped chunk size. Channel
        scope is asserted here and carried on the finish frame;
        the canonical session row has no channel column."""
        for_user = str(frame.get("for_user") or "")
        for_group = str(frame.get("for_group") or "")
        for_channel = str(frame.get("for_channel") or "")
        if for_group and self._my_group_role(for_group) is None:
            raise Refusal("not_a_member")
        if for_channel \
                and self._my_channel_role(for_channel) is None:
            raise Refusal("not_a_member")
        if for_user and self.directory_entry(for_user) is None:
            raise Refusal("unknown_username", for_user)
        whole_sha = str(frame.get("whole_sha") or "")
        query = (self._eq("whole_sha", whole_sha) + "&"
                 + self._eq("owner", self.username) + "&"
                 + self._eq("for_user", for_user) + "&"
                 + self._eq("for_group", for_group) + "&"
                 + self._eq("for_channel", for_channel))
        found = self._rest("GET", "blobs", query) or []
        if found:
            return {"dedup": True, "blob_id": found[0]["id"]}
        try:
            chunk_size = int(frame.get("chunk_size") or 1048576)
        except (TypeError, ValueError):
            chunk_size = 1048576
        chunk_size = max(1024, min(chunk_size, 1048576))
        session_id = new_id("u-")[:14]
        self._rest("POST", "upload_sessions", body={
            "session_id": session_id, "owner": self.username,
            "for_user": for_user, "for_group": for_group,
            "whole_sha": whole_sha,
            "ct_sha": str(frame.get("ct_sha") or ""),
            "size": int(frame.get("size") or 0),
            "chunk_size": chunk_size, "chunks": "[]",
            "created_at": now_ts()},
            prefer="return=minimal")
        return {"dedup": False, "session_id": session_id,
                "chunk_size": chunk_size}

    def blob_session_status(self, frame: dict) -> dict:
        """blob_session_status from my own session row: {have,
        missing, total} — an unknown (or not-mine) session is
        unknown_session."""
        session_id = str(frame.get("session_id") or "")
        rows = self._rest(
            "GET", "upload_sessions",
            self._eq("session_id", session_id)) or []
        if not rows:
            raise Refusal("unknown_session")
        row = rows[0]
        size = int(row.get("size") or 0)
        chunk_size = int(row.get("chunk_size") or 1048576)
        total = -(-size // chunk_size) if chunk_size else 0
        have = sorted(int(i) for i in
                      (_loads(row.get("chunks"), []) or []))
        missing = [i for i in range(total) if i not in have]
        return {"session_id": session_id, "have": have,
                "missing": missing, "total": total}

    def blob_chunk(self, frame: dict) -> dict:
        """blob_chunk via agentlink-blobs: the chunk object has
        no metadata row for r2sign to anchor to, so the blobs
        function presigns the session-scoped key after checking
        session ownership + the chunk hash itself."""
        return self._fn_data("agentlink-blobs", "chunk",
                             self._frame_body(frame))

    def blob_session_finish(self, frame: dict) -> dict:
        """blob_session_finish via agentlink-blobs: assembly,
        whole-hash verification, final object write, chunk
        cleanup, metadata insert, session retirement and the
        blob_upload_completed audit are one server-side act."""
        return self._fn_data("agentlink-blobs", "session_finish",
                             self._frame_body(frame))

    # -- grants + connectors (Edge broker) -----------------------------------
    def grant_edge(self, route: str, frame: dict) -> dict:
        """Every grant/connector operation via agentlink-grants,
        the broker's serverless seat: statement verification,
        the gate, the persisted single-use authorizations and
        the platform-signed receipt chain all live there (the
        relay process that housed them does not exist here)."""
        return self._fn_data("agentlink-grants", route,
                             self._frame_body(frame))

    # -- library (Edge) --------------------------------------------------------
    def library_edge(self, route: str, frame: dict) -> dict:
        """library_search / library_fetch via agentlink-library:
        the chain_next visibility and the caller-role content
        pick are not PostgREST-expressible."""
        return self._fn_data("agentlink-library", route,
                             self._frame_body(frame))

    # -- account (Edge) ---------------------------------------------------------
    def account_edge(self, route: str, frame: dict) -> dict:
        """directory / update_capabilities / deregister via
        agentlink-account: fleet-wide trust computation, the
        signed capability update and the removal cascade are
        service-role acts."""
        return self._fn_data("agentlink-account", route,
                             self._frame_body(frame))

    # -- misc ---------------------------------------------------------------------
    def self_report(self, frame: dict) -> dict:
        """self_report, store-side: the relay's two audit rows
        (the direct audit + the activity row, both kind
        self_repair with the event as status) and {ok: true}."""
        event = str(frame.get("event") or "")
        self._audit("self_repair", status=event)
        self._audit("self_repair", status=event)
        return {"ok": True}

    def whoami(self) -> dict:
        """whoami: the relay answers from the authenticated
        peer; the serverless peer is the login itself."""
        entry = self.directory_entry(self.username) or {}
        return {"username": self.username,
                "display_name": entry.get("display_name") or "",
                "online": True}
