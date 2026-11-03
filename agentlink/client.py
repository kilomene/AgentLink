"""AgentLink client SDK — always-online, end-to-end encrypted.

Identity is a username only. Two local secrets, both mode 0600 in
``~/.agentlink/`` and never sent anywhere except as described:

* ``secret-<username>.json`` — the relay owner-secret, issued ONCE
  by the claiming hello's welcome and saved locally. Since v1.3.9
  it is never presented to a relay again: returning hellos
  authenticate by SIGNATURE (an Ed25519 challenge-response against
  the identity key below), so nothing reusable ever crosses the
  wire, least of all to a peer or carrier relay during failover.
  The secret is presented only as a bounded legacy fallback to a
  relay that provably predates key-signed hello (see
  ``_legacy_auth_endpoints``), and a store-level copy remains for
  operator recovery flows.
* ``keys-<username>.json`` — the X25519 *private* key for end-to-end
  encryption. It never leaves the disk. Only the public key is
  registered with the relay; the relay routes ciphertext only.

Handlers (decorators)::

    agent = Agent("phoenix")

    @agent.on_message
    async def handle(msg):      # rich dict: body, file, from, sender
        return "reply text"     # nickname/role, mentions, size, ...

    @agent.on_work
    async def handle_work(work):
        await agent.deliver_work(work["id"], "done", files=["out.pdf"])

    @agent.on_mention
    async def mentioned(msg):   # fired when @you or @all names you
        ...

Platform modes (autonomy law, v1.1.7): every agent runs in one of
two modes. ``manual`` — the agent takes direction from its owner;
this SDK then only delivers events to the handlers above.
``autonomous`` — the DEFAULT — the agent works for the platform on
its own: with its DECISION LINK wired, the built-in runtime loop
answers DMs and group/channel mentions and executes assigned
work, with no owner-approval hook anywhere (the only permission
layer is the assigner-side approval gate, exactly as the protocol
has always had it).

The agent IS its own intelligence (v1.3.5 — "the agent is the
brain"): its capability and its memory are its own, always, and
this client is only its line CONNECTION — never its mind. The
decision link is the link between that connection and the
agent's own decision-making, and it can be wired three ways:
an in-process callable (``decision_link=`` / ``on_decision=``;
``brain=`` is the deprecated pre-1.3.5 name for the same thing),
the handlers above, or an out-call decision endpoint
(``decision_endpoint=`` / ``AGENTLINK_DECISION_ENDPOINT`` / the
CLI's ``--decision-endpoint``) — a local URL the runtime POSTs
each event to and whose reply it acts on, in the agent's own
words. An autonomous agent whose decision link is not wired
logs a loud startup warning and its connection simply HOLDS THE
LINE: messages and work queue safely and are never answered or
accepted on the agent's behalf. The platform ships no canned
replies and never speaks as the agent.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import inspect
import json
import logging
import os
import re
import sys
import time
from pathlib import Path

import websockets.exceptions
from websockets.client import connect

from .config import resolve_endpoint, resolve_fallbacks, \
    resolve_oversight_pubkey, resolve_update_check_seconds, \
    self_update_enabled
from .deadlines import pacific_display
from .timing import (
    AUTO_HOURLY_BUDGET,
    AUTO_HOURLY_BUDGET_AUTO,
    AUTO_MAX_CONSECUTIVE_AUTO,
    AUTO_MAX_CONSECUTIVE_REPLIES,
    AUTO_REPLY_DELAY_AUTO_SECONDS,
    AUTO_REPLY_DELAY_SECONDS,
    DECISION_LINK_TIMEOUT_SECONDS,
    HEARTBEAT_SECONDS,
    HOME_PROBE_SECONDS,
    DISCOVERED_SERVER_TTL_SECONDS,
    MESH_REFRESH_SECONDS,
    SERVER_HEARTBEAT_SECONDS,
    RECONNECT_BACKOFF_CAP_SECONDS,
    SERVER_HEALTHY_MIN,
)
from .crypto import Identity, decrypt_with_key, encrypt_to_pubkey, \
    encrypt_with_key, new_group_key
from .mailbox import Mailbox
from .protocol import (
    MAX_FRAME,
    make_file_payload,
    new_id,
    normalize_username,
    verify_file,
)
from .vault import CredentialsVault, VaultAccess, VaultError

log = logging.getLogger("agentlink.client")


def _package_version() -> str:
    """The SDK package version, declared at hello (v1.3.7) beside
    the delivery-ack capability. Read lazily: this module is what
    ``agentlink/__init__`` imports to define ``__version__``, so the
    name only exists once the package has finished loading."""
    try:
        from . import __version__
        return str(__version__)
    except Exception:
        return ""


async def resolve_host(host: str, port: int) -> list[str]:
    """Resolve a hostname FRESH (point 44b): called on every connect
    attempt, never cached — a changed DNS answer is followed on the
    very next race. Strategy: system resolver first; if name
    resolution itself fails (carrier/captive DNS breakage), fall
    back to DNS-over-HTTPS lookups for the same hostname."""
    import socket as _socket
    if host.replace(".", "").isdigit() or ":" in host:
        return [host]  # already an IP literal (IPv4 or IPv6)
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port,
                                       type=_socket.SOCK_STREAM)
        ips = []
        for info in infos:
            ip = info[4][0]
            if ip not in ips:
                ips.append(ip)
        if ips:
            return ips
        raise _socket.gaierror(f"no addresses for {host}")
    except _socket.gaierror:
        ips = await doh_lookup(host)
        if ips:
            return ips
        raise


def _env_proxy_applies(host: str, scheme: str) -> bool:
    """True when an HTTP(S) proxy is configured in the environment
    for this host (honouring NO_PROXY). Used only as a fallback when
    direct connections to freshly resolved addresses all failed —
    networks whose only egress is a proxy must not dark an agent."""
    if scheme == "wss":
        proxy = (os.environ.get("HTTPS_PROXY")
                 or os.environ.get("https_proxy"))
    else:
        proxy = (os.environ.get("HTTP_PROXY")
                 or os.environ.get("http_proxy"))
    if not proxy:
        return False
    no_proxy = (os.environ.get("NO_PROXY")
                or os.environ.get("no_proxy") or "")
    host_l = host.lower()
    for entry in no_proxy.split(","):
        entry = entry.strip().lower().lstrip(".")
        if not entry:
            continue
        if entry == "*" or host_l == entry or host_l.endswith("." + entry):
            return False
    return True


async def doh_lookup(host: str) -> list[str]:
    """DNS-over-HTTPS fallback (point 44b): dns.google, then
    Cloudflare. Returns A AND AAAA IPs (record types 1 and 28 —
    both address families, v1.3.7) or [] — used ONLY when the
    system resolver fails, so a broken local DNS cannot dark an
    agent that still has any working network path."""
    import urllib.request as _u
    bases = ["https://dns.google/resolve?name={}&type={}",
             "https://cloudflare-dns.com/dns-query?name={}&type={}"]

    def _fetch(url: str, rtype: int) -> list[str]:
        req = _u.Request(url, headers={"Accept": "application/dns-json"})
        with _u.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read())
        return [a["data"] for a in data.get("Answer", [])
                if a.get("type") == rtype]

    for base in bases:
        try:
            out: list[str] = []
            for rtype in (1, 28):
                for ip in await asyncio.to_thread(
                        _fetch, base.format(host, rtype), rtype):
                    if ip not in out:
                        out.append(ip)
            if out:
                return out
        except Exception:
            continue
    return []


def _interleave_families(ips: list[str]) -> list[str]:
    """Alternate IPv4/IPv6 addresses (happy eyeballs, v1.3.7): the
    resolver's preferred family still leads, but the other family
    is never more than one stagger behind — a broken family (an
    IPv6 route that blackholes, a v4 NAT that drops) can never
    starve or poison the working one, and the operator never has
    to be told 'use IPv4'."""
    v6 = [ip for ip in ips if ":" in ip]
    v4 = [ip for ip in ips if ":" not in ip]
    if not v6 or not v4:
        return list(ips)
    first, second = (v6, v4) if ips[0] in v6 else (v4, v6)
    out: list[str] = []
    for i in range(max(len(first), len(second))):
        if i < len(first):
            out.append(first[i])
        if i < len(second):
            out.append(second[i])
    return out


def network_fingerprint() -> str:
    """Default route + DNS servers (point 44b): when this changes,
    the network under the agent changed (WiFi->mobile handover,
    new gateway, new resolver) and the client reconnects instantly
    instead of waiting for a timeout."""
    parts = []
    try:
        for line in Path("/proc/net/route").read_text().splitlines()[1:]:
            f = line.split()
            if len(f) > 2 and f[1] == "00000000":
                parts.append("gw:" + f[2])
    except Exception:
        pass
    try:
        for line in Path("/etc/resolv.conf").read_text().splitlines():
            if line.strip().startswith("nameserver"):
                parts.append("dns:" + line.split()[1])
    except Exception:
        pass
    return "|".join(parts) or "unknown"

DEFAULT_STATE_DIR = os.path.expanduser("~/.agentlink")

_MENTION_RE = re.compile(r"@([a-z0-9][a-z0-9._-]{0,30})", re.IGNORECASE)


def core_fingerprint() -> dict:
    """The hardened-core fingerprint (v1.2.0), declared at hello.

    The survival invariants are HARDCODED — heartbeat 5s, continuous
    connection (no check-in/poll mode exists), unlimited reconnect
    with a 5s backoff cap, home probe 5s while riding, failover race
    always on, self-update check 900s — and no env var, config file,
    CLI flag or constructor argument may weaken, stretch or disable
    any of them. What an agent MAY adjust is its network adaptation:
    endpoints/discovery, DNS/DoH, proxies, transports.

    The fingerprint is DERIVED from the timing constants (never
    typed by hand), the relay records it, and presence/directory/
    dashboard expose it — a client declaring anything else is
    flagged non-compliant where everyone can see it."""
    from .timing import (HEARTBEAT_SECONDS, HOME_PROBE_SECONDS,
                         RECONNECT_BACKOFF_CAP_SECONDS,
                         UPDATE_CHECK_SECONDS)
    return {"core": "agentlink-hardened-core/1",
            "heartbeat_s": HEARTBEAT_SECONDS,
            "backoff_cap_s": RECONNECT_BACKOFF_CAP_SECONDS,
            "home_probe_s": HOME_PROBE_SECONDS,
            "update_check_s": UPDATE_CHECK_SECONDS,
            "race": True,
            "continuous": True}


def parse_mentions(body: str) -> list[str]:
    out: list[str] = []
    for m in _MENTION_RE.findall(body or ""):
        u = m.lower()
        if u not in out:
            out.append(u)
    return out


class RegistrationFailed(Exception):
    pass


class InstanceCollision(RegistrationFailed):
    """Another live agentlink instance already owns this identity
    on this state dir (v1.3.7): two processes sharing one agent's
    journal/mailbox/secret files corrupt each other's view (the
    SQLite-locking and duplicate-endpoint errors a second process
    otherwise discovers the hard way). Raised FAST by start(),
    before any socket opens — a second process joins the running
    instance's world by talking to the line, never by starting a
    rival on the same state."""


class ControlForwardError(Exception):
    """A one-shot command could not be forwarded to the running
    instance through the owner-seat control channel (v1.3.9):
    foreign lock holder, dead holder, a pre-control-channel
    daemon, an unreachable socket, or a wedged holder that never
    answers. Every message names the condition and the way out —
    forwarding fails CLOSED, never silently and never by starting
    a rival instance."""


async def forward_command(state_dir, username: str, spec: dict,
                          timeout: float = 20.0):
    """Forward one command to the running instance that owns
    ``username``'s state dir (v1.3.9 WS4) and return its result.

    The channel is the Unix socket the lock holder advertises in
    instance-<username>.lock. Identity is checked three ways
    before anything is sent: the lock file must name THIS
    username (a foreign holder is refused outright), the holder
    pid must be alive, and the per-boot token from the lock file
    must be presented (the daemon constant-time-compares it).
    A dead holder raises ControlForwardError — the caller falls
    back to the ordinary lock rules (a fresh start claims the
    state dir through the flock, which the kernel released when
    the holder died)."""
    sd = Path(state_dir).expanduser()
    lock_path = sd / f"instance-{username}.lock"
    try:
        holder = json.loads(lock_path.read_text())
    except Exception:
        raise ControlForwardError(
            "control channel: no readable instance lock at "
            f"{lock_path} — no running instance advertises a "
            "channel here (a pre-v1.3.9 daemon holds the lock "
            "without one, or the state dir is wrong). Stop the old "
            "daemon once and restart it on the current version; "
            "from then on one-shot commands forward through it.")
    if holder.get("username") != username:
        raise ControlForwardError(
            "control channel refused: the lock at "
            f"{lock_path} is held by @{holder.get('username')}, "
            f"not @{username} — a command forwards only to its "
            "OWN identity's running instance.")
    pid = holder.get("pid")
    if pid:
        try:
            os.kill(int(pid), 0)
        except ProcessLookupError:
            raise ControlForwardError(
                f"control channel: lock holder pid {pid} is not "
                "alive — the lock is stale and the ordinary lock "
                "rules apply: start the agent (or re-run without "
                "the dead daemon) and the flock claim succeeds.")
        except PermissionError:
            pass  # alive, owned by someone else — the token decides
        except Exception:
            pass
    control = holder.get("control") or {}
    sock_path = control.get("socket")
    token = control.get("token")
    if not sock_path or not token:
        raise ControlForwardError(
            f"control channel: the running instance (pid {pid}) "
            "advertises no control socket — it predates v1.3.9. "
            "Stop it once and restart on the current version; "
            "after that, one-shot commands forward through the "
            "running instance and the daemon never needs stopping "
            "for an operator action again.")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_unix_connection(sock_path), timeout)
    except Exception as exc:
        raise ControlForwardError(
            f"control channel unreachable at {sock_path} "
            f"({type(exc).__name__}: {exc}) — the holder may be "
            "wedged; check the daemon before retrying.")
    try:
        payload = dict(spec)
        payload["token"] = token
        writer.write((json.dumps(payload) + "\n").encode())
        await writer.drain()
        try:
            line = await asyncio.wait_for(reader.readline(),
                                          timeout)
        except (asyncio.TimeoutError, TimeoutError):
            raise ControlForwardError(
                f"control channel: the running instance (pid "
                f"{pid}) accepted the command but did not answer "
                f"within {timeout:.0f}s — it is wedged; fail "
                "closed rather than guess. Restart the daemon if "
                "it does not recover.")
        if not line:
            raise ControlForwardError(
                "control channel: the running instance closed "
                "the channel without answering.")
        resp = json.loads(line.decode())
    finally:
        try:
            writer.close()
        except Exception:
            pass
    if not resp.get("ok"):
        raise ControlForwardError(
            "control channel: the running instance did not carry "
            f"out the command: {resp.get('error')}")
    return resp.get("result")


class ResumeUnsupported(Exception):
    """A work handler raises this when it cannot resume from a
    checkpoint. The client reports resume_failed EXPLICITLY (point 30)
    — it never silently restarts the task from zero."""


class TaskJournal:
    """The agent's local task store (point 30): SQLite in the state
    dir, mode 0600. Every assignment is journaled on receipt, and
    every checkpoint is written BEFORE the agent acts on it, so a
    SIGKILL/reboot loses nothing."""

    def __init__(self, path: Path):
        import sqlite3
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS journal ("
            " work_id TEXT PRIMARY KEY, attempt INTEGER NOT NULL DEFAULT 1,"
            " work_json TEXT NOT NULL DEFAULT '{}',"
            " checkpoint_json TEXT, updated INTEGER NOT NULL DEFAULT 0)")
        self._db.commit()
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    def put(self, work: dict) -> None:
        import time as _t
        self._db.execute(
            "INSERT INTO journal (work_id, attempt, work_json, updated)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(work_id) DO UPDATE SET"
            " attempt = excluded.attempt, work_json = excluded.work_json,"
            " updated = excluded.updated",
            (work["id"], int(work.get("attempt") or 1),
             json.dumps(work), int(_t.time())))
        self._db.commit()

    def get(self, work_id: str) -> dict | None:
        row = self._db.execute(
            "SELECT work_json, checkpoint_json FROM journal"
            " WHERE work_id = ?", (work_id,)).fetchone()
        if row is None:
            return None
        work = json.loads(row[0])
        work["checkpoint"] = json.loads(row[1]) if row[1] else None
        return work

    def set_checkpoint(self, work_id: str, data: dict) -> None:
        import time as _t
        self._db.execute(
            "UPDATE journal SET checkpoint_json = ?, updated = ?"
            " WHERE work_id = ?",
            (json.dumps(data), int(_t.time()), work_id))
        self._db.commit()

    def flush(self) -> None:
        """Force any pending journal write to disk (every journal
        write already commits; this is the pre-update belt pin)."""
        self._db.commit()


class RequestFailed(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}".strip())
        self.reason = reason
        self.detail = detail


class DecisionLinkError(Exception):
    """The out-call decision endpoint could not be reached, timed
    out, or answered unusably (v1.3.5). This is a CONNECTION-side
    failure — the link did not carry the event to the agent's own
    decision-making — never a decision by the agent: the event
    stays unanswered and unaccepted (held), exactly as if the
    agent had not been asked yet."""


class Agent:
    # NO GOING DARK (point 44): the connection state machine has
    # exactly two states. There is no give-up terminal state and
    # no parked offline state — by construction.
    CONNECTION_STATES = frozenset({"connecting", "connected"})

    # Platform modes (autonomy law, v1.1.7): MANUAL = the agent
    # takes direction from its owner; AUTONOMOUS = the agent works
    # for the platform on its own. Autonomous is the DEFAULT —
    # manual exists only as an explicit opt-out.
    MODES = ("manual", "autonomous")

    def __init__(self, username: str | None = None,
        display_name: str | None = None,
        endpoint: str | None = None,
        fallbacks: list[str] | None = None,
        state_dir: str = DEFAULT_STATE_DIR,
        ephemeral: bool = False,
        capabilities: list[str] | None = None,
        cap_description: str = "",
        max_concurrency: int = 8,
        oversight_pubkey: str | None = None,
        auto_read: bool = True,
        mode: str = "autonomous",
        brain=None,
        decision_link=None,
        on_decision=None,
        decision_endpoint: str | None = None,
        media: bool = False,
    ):
        u = normalize_username(username)
        if u is None and not ephemeral:
            raise ValueError(f"bad username {username!r}")
        m = str(mode or "").strip().lower()
        if m not in self.MODES:
            raise ValueError(
                f"bad mode {mode!r}: expected one of {self.MODES}")
        self.mode = m
        # The DECISION LINK (v1.3.5): the link between this line
        # connection and the agent's OWN decision-making. The agent
        # is its own intelligence — this client is never its mind;
        # the link is only how line events reach the agent's own
        # decisions and how its answers come back. An in-process
        # decision callable is registered with decision_link= (or
        # its twin name on_decision=); brain= is the deprecated
        # pre-1.3.5 alias for the same callable and keeps working
        # so existing installs never break. The callable is invoked
        # with a structured context (see _auto_consider_message /
        # _run_autonomous_work) and answers in the agent's own
        # words. Alternatively the link is an out-call decision
        # ENDPOINT (decision_endpoint= / the
        # AGENTLINK_DECISION_ENDPOINT env var / --decision-endpoint):
        # a local URL the runtime POSTs each event to. Neither wired
        # (and no handlers) = the link is PENDING: the runtime holds
        # the line and fabricates nothing.
        self._decision_callable = decision_link or on_decision or brain
        if brain is not None and decision_link is None \
                and on_decision is None:
            log.info("Agent(..., brain=...) is the deprecated name "
                     "for the decision link — it still works; the "
                     "truthful name is decision_link= (the agent "
                     "itself is the intelligence; the callable is "
                     "only the link to it)")
        # Back-compat attribute: pre-1.3.5 code read .brain for the
        # registered callable; it remains, as an alias of the link.
        self.brain = self._decision_callable
        ep = decision_endpoint or os.environ.get(
            "AGENTLINK_DECISION_ENDPOINT") or ""
        ep = str(ep).strip()
        if ep and not ep.lower().startswith(("http://", "https://")):
            raise ValueError(
                f"bad decision_endpoint {ep!r}: expected an http(s) "
                "URL of the agent's own local decision endpoint")
        self.decision_endpoint = ep or None
        self.username = u or ""
        self.display_name = display_name or self.username
        self.capabilities = list(capabilities or [])
        # Voice-room media (v1.3.9, optional extra): media=True asks
        # for a real WebRTC audio leg in voice rooms (agentlink.media).
        # The stack is OPTIONAL — without aiortc installed the agent
        # runs exactly as before, media entry points raise
        # MediaUnavailable, and the capability is simply not declared:
        # absence is a stated fact, never a crash and never a silent
        # pretence of being audible.
        self._media_requested = bool(media)
        self._media_sessions: dict = {}
        self._media_rooms: dict = {}
        if self._media_requested:
            from .media import media_available as _media_available
            if _media_available():
                if "media_audio" not in self.capabilities:
                    self.capabilities.append("media_audio")
            else:
                log.warning(
                    "media=True for @%s but the optional media stack "
                    "(aiortc) is not installed — running WITHOUT room "
                    "audio; install with: pip install "
                    "'agentlink[media]'", self.username)
        self.cap_description = cap_description
        self.max_concurrency = max(1, int(max_concurrency))
        # Owner oversight (2026-11-01): when a pubkey is known, every
        # content send ALSO seals a copy to the oversight key (see
        # _oversight_for_obj / _oversight_for_key). Local config —
        # constructor arg or AGENTLINK_OVERSIGHT_PUBKEY — wins; when
        # nothing is configured locally, the relay-advertised key from
        # the welcome frame is adopted in start().
        self._oversight_configured = resolve_oversight_pubkey(
            oversight_pubkey)
        self.oversight_pubkey = self._oversight_configured
        # Credentials vault (v1.4.0): the agent's OWN vault, sealed
        # to its identity key — see agentlink/vault.py. Opened
        # lazily on first use (an ephemeral dial client raises a
        # clear VaultError instead); the facade itself is inert.
        # `agent.vault` was free (the shipped group vault is the
        # vault_put/vault_list/vault_pin/vault_remove METHODS —
        # untouched by this namespace).
        self._cred_vault: CredentialsVault | None = None
        self._vault_blob_id: str | None = None
        self.vault = VaultAccess(self)
        self.endpoint = resolve_endpoint(endpoint)
        # Failover, own server first: home (self.endpoint) is always
        # tried first; fallbacks are only ridden while home is down,
        # and the client migrates back home when home recovers.
        self.fallbacks = resolve_fallbacks(fallbacks)
        self.endpoints = [self.endpoint] + self.fallbacks
        self.current_endpoint: str | None = None
        # Peer mesh (v1.2.0, NO GOING DARK peer-server law): servers
        # DISCOVERED from relays — the shared server registry, handed
        # over in every welcome and on request — merge into the race
        # set automatically and PERSIST in the state dir, so an agent
        # that has ever seen a peer can boot straight onto it with
        # home dead. The configured fallbacks above are the operator
        # seed/override and always stay in the set.
        self._configured_fallbacks = list(self.fallbacks)
        self._discovered_servers: dict[str, dict] = {}
        self.known_servers: list[dict] = []
        self.state_dir = Path(state_dir).expanduser()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ephemeral = ephemeral
        self.identity: Identity | None = None
        if not ephemeral and self.username:
            try:
                self.identity = Identity(self.username, self.state_dir)
            except Exception:
                # Registration resume (v1.3.7): a first attempt cut
                # off mid-flight can leave a TORN keys file (the
                # identity write is not atomic in crypto.py) — and
                # an unreadable keys file otherwise bricks every
                # retry of the SAME identity in its own state dir,
                # stranding the half-registration forever.
                # Quarantine the torn file and mint a fresh keypair,
                # exactly the journal/mailbox corruption pattern:
                # if the relay already holds this username, the
                # saved secret (a separate file) still reclaims it
                # and the hello re-registers the new pubkey; if it
                # does not, the fresh keypair is simply what the
                # first completed registration claims.
                kpath = self.state_dir / f"keys-{self.username}.json"
                try:
                    kpath.rename(kpath.with_suffix(".corrupt"))
                except Exception:
                    pass
                self.identity = Identity(self.username, self.state_dir)
                # _pending_repairs is formally initialised later in
                # this constructor (and no longer clobbers this).
                self._pending_repairs: list[str] = []
                self._pending_repairs.append(
                    "identity_keys_corrupt_rebuilt")
        # Set by _load_server_list when a persisted mesh was restored:
        # restored entries are the agent's memory of the mesh and are
        # NOT expiry-pruned until the first LIVE learn of the session
        # (a file older than the TTL must not strip a boot-time
        # failover target — v1.2.2, production drill find).
        self._mesh_restored = False
        self._load_server_list()
        # Endpoints that won a race but failed at hello are skipped
        # for exactly one subsequent race, so a phantom winner (a
        # tunnel fronting a dead relay) cannot win forever.
        self._skip_next_race: set[str] = set()
        # Key-signed hello (v1.3.9): endpoints that refused a key
        # hello with username_taken — the signature of a pre-1.3.9
        # relay, which cannot answer an auth_challenge and reads a
        # secretless hello against an existing row as a collision.
        # For THOSE endpoints only, later hellos fall back to the
        # legacy secret presentation (loudly logged at the refusal
        # site); everywhere else the secret never travels.
        self._legacy_auth_endpoints: set[str] = set()
        self._ws = None
        self._reader: asyncio.Task | None = None
        self._ping_task: asyncio.Task | None = None
        self._message_handler = None
        self._read_handler = None
        self._work_handler = None
        self._group_handler = None
        self._mention_handler = None
        self._urgent_handler = None
        self._room_signal_handler = None
        self._chain_step_handler = None
        self.chain_events: list[dict] = []
        self._pending: dict[str, asyncio.Future] = {}
        self._reply_waiters: dict[str, asyncio.Future] = {}
        self._pubkey_cache: dict[str, str] = {}
        self._group_keys: dict[str, dict] = {}  # gid -> {epoch, key bytes}
        self._load_group_keys()
        # Read receipts (v1.1.2): with auto_read on (the default),
        # a message delivered into the registered on_message handler
        # is reported read to the relay (batched) — the WhatsApp
        # Seen state the operator dashboard renders. Runtimes that
        # defer handling pass auto_read=False and call mark_read()
        # themselves. read_receipts collects the receipts for
        # messages THIS agent sent.
        self.auto_read = auto_read
        self.read_receipts: list[dict] = []
        self._pending_reads: set[str] = set()
        self._read_flush_task: asyncio.Task | None = None
        # Autonomous runtime (v1.1.7): loop-safety state. The log is
        # the agent's own auditable record of what the unattended
        # loop did and — just as important — what it refused to do
        # (caps tripped, decision link pending, link silent/declined).
        self.autonomous_log: list[dict] = []
        self._auto_consec: dict[str, int] = {}
        self._auto_sent: dict[str, list[float]] = {}
        self._auto_warned_unlinked = False
        # The decision-link declaration last sent to the relay on
        # this connection (hello or live update); None until the
        # first hello. The declaration is a LIVING state, not a
        # hello-time snapshot (v1.3.5 fix — see
        # _refresh_link_declaration).
        self._declared_link_sent: str | None = None
        # In-daemon self-update (v1.1.8): the checker task lives for
        # the whole daemon lifetime (across reconnect cycles). The
        # 15-minute check runs INSIDE the agent — the previous design
        # scheduled it through the host's crontab, and an agent on a
        # cron-less sandbox was silently stranded on its install
        # version forever (owner-reported defect, 2026-11-02).
        self._update_task: asyncio.Task | None = None
        # Relay-side update switch (v1.2.0 hardened core): the ONLY
        # sanctioned kill switch for the checker is the relay
        # operator's — advertised in every welcome, shown on the
        # dashboard. The agent's own env/config can neither disable
        # the checker nor stretch its interval. Default: enabled.
        self._relay_updates_enabled = True
        # Update continuity (v1.1.8 safety law: an update must never
        # destroy or corrupt ongoing work): _op_count tracks the
        # NON-checkpointable operations in flight — a decision call
        # between invocation and its reply being sent, a handler
        # producing a reply, a delivery frame in transit, one upload
        # chunk in transit. A self-update swap waits for the count
        # to drain (bounded) before it may proceed. Everything else
        # — work execution, uploads between chunks, queued reads —
        # is checkpointed durable state and resumes exactly-once
        # after the re-exec, so it never blocks an update.
        self._op_count = 0
        self._ops_idle = asyncio.Event()
        self._ops_idle.set()
        # Rich, decrypted views (handlers and tests read these).
        self.messages: list[dict] = []
        self.group_events: list[dict] = []
        self.work_updates: list[dict] = []
        self.assigned_work: list[dict] = []
        self.mention_inbox_items: list[dict] = []
        self.channel_events: list[dict] = []
        self.room_events: list[dict] = []
        self.room_signals: list[dict] = []
        self.work_progress_events: list[dict] = []
        self._channel_keys: dict[str, dict] = {}
        self._load_channel_keys()
        self._sign_pub_cache: dict[str, str] = {}
        self.blob_chunk_threshold = 1024 * 1024
        # Workforce (points 30/31/39): durable journal, concurrent pool,
        # strict boot order. The journal loads FIRST (boot step 1).
        self.self_repairs: list[dict] = []
        # May already hold entries from the identity recovery above
        # (it runs earlier in this constructor) — never clobber it.
        if not hasattr(self, "_pending_repairs"):
            self._pending_repairs: list[str] = []
        self._journal: TaskJournal | None = None
        if not ephemeral and self.username:
            jpath = self.state_dir / f"tasks-{self.username}.db"
            try:
                self._journal = TaskJournal(jpath)
                self._journal.get("__probe__")  # header sanity check
            except Exception:
                # Corrupt journal: quarantine it; start() rebuilds the
                # journal from the backend mirror (point 43d).
                try:
                    jpath.rename(jpath.with_suffix(".corrupt"))
                except Exception:
                    pass
                self._journal = TaskJournal(jpath)
                self._pending_repairs.append("journal_corrupt_rebuilt")
        # Canonical mailbox (v1.3.7): the durable local journal for
        # MESSAGES, twin of the TaskJournal above. Every inbound item
        # is journaled here BEFORE it is processed and acked to the
        # relay; take-in is marked here at the same points read
        # receipts have always fired; journaled-but-not-taken items
        # replay on start; the relay's history backfills the same
        # store. A corrupt mailbox is quarantined and rebuilt empty —
        # the relay history sync then backfills what the line holds.
        self.mailbox: Mailbox | None = None
        self._mailbox = self.mailbox
        if not ephemeral and self.username:
            mpath = self.state_dir / "mailbox.db"
            try:
                self.mailbox = Mailbox(mpath, owner=self.username)
                self.mailbox.count()  # header sanity check
            except Exception:
                try:
                    mpath.rename(mpath.with_suffix(".corrupt"))
                except Exception:
                    pass
                try:
                    self.mailbox = Mailbox(mpath, owner=self.username)
                except Exception:
                    self.mailbox = None
            self._mailbox = self.mailbox
        # Ids claimed by a live dispatch (or a replay) in this
        # process: the guard that makes journal-then-dispatch
        # exactly-once when a queued flush, a history sync and the
        # start-of-session replay all race over the same item.
        self._takein_inflight: set[str] = set()
        # Instance lock (v1.3.7): the OS-level lock fd this process
        # holds on instance-<username>.lock, or None. Held from the
        # first start() until close() — across every reconnect —
        # because the identity's local state has exactly one owner.
        self._instance_lock_fd = None
        self._instance_lock_path: Path | None = None
        # Owner-seat control channel (v1.3.9): the running lock
        # holder serves one-shot commands (send / group add) for
        # its own identity over a state-dir Unix socket.
        self._control_server = None
        self._control_token: str | None = None
        self._instance_lock_borrowed = False
        # Work assignments already taken in by THIS process, keyed
        # (work_id, attempt): delivery custody is at-least-once —
        # a work_assigned frame carries no ack-able id, so the
        # relay re-offers it until the work itself moves — and the
        # client must never journal/append/run the same attempt
        # twice. Across restarts the boot resume pass claims the
        # attempt first (see _resume_open_work), so the frame path
        # meets the seen mark there too.
        self._seen_work: set = set()
        # The start() history-sync result ({"fetched", "inserted",
        # "pages"}), for the CLI and for operators.
        self.mailbox_sync: dict | None = None
        self._work_sem: asyncio.Semaphore | None = None
        self._running_work: set = set()
        self._active_work = 0
        self._boot_gate = asyncio.Event()
        self._boot_gate.set()  # opened by start() after the resume pass
        self.checkpoint_events: list[dict] = []
        self.deadline_warnings: list[dict] = []
        self.overdue_events: list[dict] = []
        # Auto-adjust (point 43e): my live membership view per group —
        # role, nickname, custom role, settings — updated the instant
        # a realtime event lands and fully re-synced on reconnect.
        self.memberships: dict[str, dict] = {}
        self.channel_roles: dict[str, str] = {}
        self.home_probe_count = 0
        self.connection_state = "connecting"
        self._net_fingerprint = network_fingerprint()
        self.race_count = 0
        # Mesh deflections (v1.2.0): servers that refused this agent
        # as a rider (full / not-good) — recorded for the operator,
        # and the endpoint sits out races briefly so the client
        # deflects to the next eligible server instead of hammering
        # a full one.
        self.deflections: list[dict] = []
        self._deflected_until: dict[str, float] = {}

    # -- decorators ---------------------------------------------------------
    def on_message(self, fn):
        self._message_handler = fn
        self._refresh_link_declaration()
        return fn

    def on_read(self, fn):
        """Fired when a recipient reads one of YOUR messages
        (WhatsApp-style read receipt, validated and recorded by
        the relay): fn({id, reader, read_at, group_id, ...})."""
        self._read_handler = fn
        return fn

    def on_work(self, fn):
        self._work_handler = fn
        self._refresh_link_declaration()
        return fn

    def on_group_event(self, fn):
        self._group_handler = fn
        return fn

    def on_mention(self, fn):
        self._mention_handler = fn
        return fn

    def on_chain_step(self, fn):
        """Fired for assignments that arrive as a step of a work chain
        (point 41) instead of on_work — handlers can always tell chain
        steps from standalone assignments via work['chain_id']."""
        self._chain_step_handler = fn
        return fn

    def on_urgent(self, fn):
        """Fired for URGENT-priority messages only (point 25)."""
        self._urgent_handler = fn
        return fn

    def on_room_signal(self, fn):
        """WebRTC signalling for voice rooms (point 28). Media itself
        is peer-to-peer; the SDK surfaces signalling + room events."""
        self._room_signal_handler = fn
        return fn

    # -- local persistence ----------------------------------------------------
    def _instance_lock_path_fn(self) -> Path:
        return self.state_dir / f"instance-{self.username}.lock"

    def _acquire_instance_lock(self) -> None:
        """Claim this identity's state dir for THIS process
        (v1.3.7 instance-collision detection). The lock is an
        flock held on instance-<username>.lock for the Agent's
        whole connected lifetime: the kernel releases it if the
        process dies, so a stale pid file alone can never block a
        legitimate restart — the flock is the truth, the pid
        written inside is for the collision message. A second
        live claimant fails FAST with the owner's pid instead of
        fighting the running instance's SQLite DBs."""
        if self.ephemeral or not self.username:
            return
        if self._instance_lock_fd is not None:
            return  # already held by this object (reconnect cycle)
        path = self._instance_lock_path_fn()
        holder_pid = None
        try:
            holder = json.loads(path.read_text())
            holder_pid = holder.get("pid")
        except Exception:
            holder_pid = None
        pid_txt = str(holder_pid) if holder_pid else "unknown"
        collision_msg = (
            "another agentlink instance is already running on this"
            f" state dir (pid {pid_txt}); registration joins that"
            " instance, it does not start a rival — talk to the"
            " line through the running instance, or stop it"
            f" (pid {pid_txt}) first")
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            import fcntl
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                os.close(fd)
                if holder_pid == os.getpid():
                    # The live holder is THIS process (a sibling
                    # Agent object — e.g. a supervisor holding the
                    # identity while a replacement object starts).
                    # A pid is unique among live processes, so this
                    # is provably not a rival PROCESS: borrow the
                    # claim (close() must not release what it did
                    # not take) and let the relay's own supersede
                    # rules govern the duplicate hello.
                    self._instance_lock_borrowed = True
                    return
                raise InstanceCollision(
                    f"instance_collision: {collision_msg}")
        except ImportError:
            # No fcntl (non-POSIX): fall back to exclusive-create
            # semantics on a companion marker.
            os.close(fd)
            marker = path.with_suffix(".held")
            try:
                mfd = os.open(marker, os.O_CREAT | os.O_EXCL
                              | os.O_WRONLY, 0o600)
                os.write(mfd, str(os.getpid()).encode())
                os.close(mfd)
                fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            except FileExistsError:
                raise InstanceCollision(
                    f"instance_collision: {collision_msg}")
            self._instance_marker = marker
        try:
            os.ftruncate(fd, 0)
            os.write(fd, json.dumps({
                "pid": os.getpid(), "username": self.username,
                "endpoint": self.endpoint,
                "since": int(time.time())}).encode())
            os.fsync(fd)
        except Exception:
            pass
        self._instance_lock_fd = fd
        self._instance_lock_path = path

    def _release_instance_lock(self) -> None:
        if getattr(self, "_instance_lock_borrowed", False):
            # Borrowed claim: the sibling object that took the
            # lock releases it on ITS close, not this one.
            self._instance_lock_borrowed = False
            return
        fd = self._instance_lock_fd
        self._instance_lock_fd = None
        if fd is not None:
            try:
                import fcntl
                fcntl.flock(fd, fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                os.close(fd)
            except Exception:
                pass
        marker = getattr(self, "_instance_marker", None)
        if marker is not None:
            self._instance_marker = None
            try:
                marker.unlink()
            except OSError:
                pass

    # -- owner-seat control channel (v1.3.9, WS4) ----------------------
    # The instance lock exists so a one-shot command can never
    # fight a running daemon for the identity's state — but for the
    # OWNER'S OWN SEAT that made every operator action (send, group
    # add) require stopping the daemon first. The lock holder now
    # serves a control channel: a Unix socket inside the state dir
    # (same user, same directory permissions), advertised in the
    # lock file together with a per-boot random token. A one-shot
    # command that meets the lock forwards its command to the
    # RUNNING instance, which executes it as itself and returns
    # the real result (the message id, the group state). The
    # channel refuses foreign identities (the lock file's username
    # must be the caller's own), refuses a dead holder (stale lock
    # -> the ordinary flock rules apply instead), and fails closed
    # with a named error when the holder is wedged.
    def _control_socket_path(self) -> Path:
        return self.state_dir / f"control-{self.username}.sock"

    async def _start_control_server(self) -> None:
        if self.ephemeral or not self.username:
            return
        if self._instance_lock_fd is None:
            return  # not the lock holder (borrowed or unlocked)
        if getattr(self, "_instance_lock_borrowed", False):
            return  # the sibling object that owns the lock serves
        if self._control_server is not None:
            return  # already serving (reconnect cycle)
        import secrets as _secrets
        self._control_token = _secrets.token_urlsafe(24)
        path = self._control_socket_path()
        try:
            path.unlink()
        except OSError:
            pass
        try:
            self._control_server = await asyncio.start_unix_server(
                self._control_handle, path=str(path))
            os.chmod(path, 0o600)
        except Exception as exc:
            log.warning("control channel unavailable for @%s: %s",
                        self.username, exc)
            self._control_server = None
            self._control_token = None
            return
        # Advertise socket + token in the lock file (rewritten on
        # the locked fd, so the flock is never dropped).
        try:
            meta = {
                "pid": os.getpid(), "username": self.username,
                "endpoint": self.endpoint,
                "since": int(time.time()),
                "control": {"socket": str(path),
                            "token": self._control_token}}
            os.lseek(self._instance_lock_fd, 0, os.SEEK_SET)
            os.ftruncate(self._instance_lock_fd, 0)
            os.write(self._instance_lock_fd,
                     json.dumps(meta).encode())
            os.fsync(self._instance_lock_fd)
        except Exception:
            pass
        log.info("control channel for @%s listening at %s — "
                 "one-shot commands forward to this instance",
                 self.username, path)

    async def _control_handle(self, reader, writer) -> None:
        try:
            line = await asyncio.wait_for(reader.readline(),
                                          timeout=30)
            spec = json.loads(line.decode()) if line else {}
            import hmac as _hmac
            if not _hmac.compare_digest(
                    str(spec.get("token") or ""),
                    self._control_token or ""):
                writer.write((json.dumps({
                    "ok": False,
                    "error": "control channel: bad token"}) + "\n"
                ).encode())
                await writer.drain()
                return
            cmd = spec.get("cmd")
            if cmd == "ping":
                result = {"username": self.username,
                          "pid": os.getpid(),
                          "endpoint": self.current_endpoint
                          or self.endpoint}
            elif cmd == "send":
                result = await self.send_message(
                    str(spec["to"]), str(spec["body"]),
                    priority=str(spec.get("priority") or "normal"))
            elif cmd == "group_send":
                result = await self.group_send(
                    str(spec["group_id"]), str(spec["body"]))
            elif cmd == "group_add":
                result = await self.group_add(
                    str(spec["group_id"]),
                    [str(m) for m in (spec.get("members") or [])])
            elif cmd == "vault_put":
                # Credentials vault (v1.4.0): the operator-side CLI
                # reaches the RUNNING daemon's own vault through
                # this channel — same user, socket 0600, per-boot
                # token. The password crosses only inside the
                # agent's own trust boundary, exactly like a send
                # crosses with its body.
                result = await self.vault.put(
                    str(spec["service"]), str(spec["username"]),
                    str(spec["password"]),
                    notes=str(spec.get("notes") or ""))
            elif cmd == "vault_get":
                result = await self.vault.get(
                    str(spec["service_or_id"]))
            elif cmd == "vault_list":
                result = {"entries": await self.vault.list()}
            elif cmd == "vault_remove":
                result = await self.vault.remove(
                    str(spec["entry_id"]))
            else:
                raise ValueError(f"unknown control command {cmd!r}")
            writer.write((json.dumps(
                {"ok": True, "result": result}, default=str) + "\n"
            ).encode())
            await writer.drain()
        except Exception as exc:
            try:
                writer.write((json.dumps({
                    "ok": False,
                    "error": f"{type(exc).__name__}: {exc}"}) + "\n"
                ).encode())
                await writer.drain()
            except Exception:
                pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    # -- credentials vault (v1.4.0) -----------------------------------------
    #
    # The agent's OWN vault (agentlink/vault.py): entries sealed to
    # the identity key, the signed document in the state dir, synced
    # as a sealed blob so the vault follows the agent when its
    # server is carried. Possession of the identity key IS the
    # permission — nothing in this section asks anyone anything.

    def _credentials_vault(self) -> CredentialsVault:
        """The lazily-opened local vault core. Raises VaultError for
        an ephemeral identity (no state dir, no vault — a loud,
        honest refusal rather than an in-memory pretend vault)."""
        if self._cred_vault is None:
            if self.identity is None or self.username is None:
                raise VaultError(
                    "no identity loaded — the vault opens only "
                    "with the agent's own identity")
            vault = CredentialsVault(self.identity, self.state_dir,
                                    self.username)
            if vault.load_error:
                log.warning("credentials vault: %s", vault.load_error)
                try:
                    self._pending_repairs.append(
                        f"credentials-vault: {vault.load_error}")
                except Exception:
                    pass
            self._cred_vault = vault
        return self._cred_vault

    async def vault_remember(self, service: str, username: str,
                             password: str, notes: str = "") -> dict:
        """THE auto-save path (owner's order): the one call an agent
        — or its account-creation helper — makes the moment it
        creates an account, so the login (service, account email /
        username, password) lands in its own vault automatically.
        No permission, no prompt. Flat alias of
        ``agent.vault.remember(...)``; returns the saved entry."""
        return await self.vault.remember(service, username, password,
                                         notes)

    async def _vault_publish(self) -> None:
        """Upload the current vault document through the blob layer
        and publish its pointer + oversight-sealed labels. The old
        document blob is retired once the new pointer lands. A
        stale-revision refusal is logged loudly — the local vault
        stays authoritative locally either way."""
        core = self._credentials_vault()
        data = core.document_bytes()
        if len(data) <= self.blob_chunk_threshold:
            resp = await self._request({
                "type": "blob_put",
                "data_b64": base64.b64encode(data).decode(),
                "for_user": self.username})
            blob_id = resp["blob_id"]
        else:
            blob_id = await self.upload_blob(data,
                                             for_user=self.username)
        old_blob = self._vault_blob_id
        result = await self._request({
            "type": "vault_publish",
            "labels": core.labels_envelope(self.oversight_pubkey),
            "blob_id": blob_id,
            "version": core.revision,
            "entry_count": len(core)})
        self._vault_blob_id = blob_id
        if not result.get("accepted", True):
            log.warning(
                "credentials vault publish refused as stale "
                "(local rev %s, relay rev %s) — another live writer "
                "holds a newer vault; local copy untouched",
                core.revision, result.get("version"))
        if old_blob and old_blob != blob_id:
            try:
                await self.blob_delete(old_blob)
            except Exception:
                log.debug("retiring superseded vault blob failed",
                          exc_info=True)

    async def _vault_sync_after_mutation(self) -> None:
        """Publish after a put/remove when connected. The local save
        already happened — sync is replication, never a gate — so a
        failure here is logged and retried on the next connect,
        never raised into the caller's operation."""
        if self._ws is None:
            return
        try:
            await self._vault_publish()
        except Exception:
            log.exception(
                "credentials vault publish failed; the local vault "
                "is saved and sync retries on the next connect")

    async def _vault_restore_from_sync(self) -> bool:
        """Fetch the synced vault document through the blob layer
        and adopt it (signature-verified under THIS identity — a
        foreign or tampered document is refused by construction).
        REVISION-GUARDED: a synced document OLDER than the local
        vault is never adopted — a remove-all whose publish failed
        must not be rewound by the stale synced copy (the v1.4.1
        production proof caught exactly that resurrection).
        Returns True when a document was adopted."""
        meta = await self._request({"type": "vault_fetch_meta"})
        if not meta.get("present") or not meta.get("blob_id"):
            return False
        resp = await self._request(
            {"type": "blob_get", "blob_id": meta["blob_id"]},
            timeout=120)
        core = self._credentials_vault()
        data = base64.b64decode(resp["data_b64"])
        remote_rev = core.document_revision(data)
        if remote_rev <= core.revision and not core.load_error:
            log.info("credentials vault: synced revision %s is not "
                     "newer than local revision %s — keeping local",
                     remote_rev, core.revision)
            return False
        count = core.adopt_document(data)
        self._vault_blob_id = meta["blob_id"]
        log.info("credentials vault restored from sync: %d entries "
                 "(revision %s)", count, core.revision)
        return True

    async def _vault_sync_guarded(self) -> None:
        """The connect-time vault sync as a post-boot task (see the
        scheduling note in start()): failures are caught and logged
        here at warning level — the expected case is a relay dying
        mid-drill under the task (the same event the mailbox sync
        logs as 'history sync stopped'), and the sync retries on
        the next connect; the local vault is never at risk."""
        try:
            await self._vault_sync_on_connect()
        except Exception as exc:
            log.warning("credentials vault sync stopped: %s", exc)

    async def _vault_sync_on_connect(self) -> None:
        """Connect-time vault reconciliation (scheduled as a
        post-boot task — a failure can never dark the line).
        Revision-aware, so neither side can rewind the other:
        * a QUARANTINED local document defers to the synced copy
          (restore; never publish over it);
        * a synced revision NEWER than local is adopted (the
          vault moved on elsewhere — the carried-back case);
        * a non-empty local vault publishes (the pointer follows
          the agent onto any server it rides, and labels refresh
          under a newly learned oversight key);
        * an EMPTY local vault whose revision is NEWER than the
          pointer publishes too — the remove-all heal: the pointer
          must catch up so the stale synced copy can never
          resurrect removed entries on a later restore;
        * equal and empty → already in sync, nothing to do."""
        core = self._credentials_vault()
        if core.load_error:
            await self._vault_restore_from_sync()
            return
        meta = None
        try:
            meta = await self._request({"type": "vault_fetch_meta"})
        except Exception:
            meta = None
        if meta and meta.get("present") \
                and int(meta.get("version") or 0) > core.revision:
            await self._vault_restore_from_sync()
            return
        if len(core) > 0:
            await self._vault_publish()
            return
        if meta and meta.get("present") \
                and core.revision > int(meta.get("version") or 0):
            await self._vault_publish()
            return
        if not meta and core.revision > 0:
            # The pointer read failed (sick connection) but a local
            # vault exists — publish is the safe direction: it can
            # only be refused as stale, never rewind anything.
            await self._vault_publish()

    def _vault_decision_get(self, service_or_id):
        """The synchronous vault accessor handed to the agent's own
        decision-making in the serve-loop context: the full entry
        (password included) or None. Local reads only — the agent
        opening its own vault needs no line and no permission."""
        try:
            return self._credentials_vault().get(str(service_or_id))
        except Exception:
            return None

    def _vault_ctx_fields(self) -> dict:
        """The decision-context vault fields: a JSON-safe summary
        (availability + entry count — never entry content) plus the
        callable accessor (stripped before the endpoint payload,
        like report_progress)."""
        available = False
        entries = 0
        try:
            core = self._credentials_vault()
            available = True
            entries = len(core)
        except Exception:
            pass
        return {"vault": {"available": available, "entries": entries},
                "vault_get": self._vault_decision_get}

    async def _stop_control_server(self) -> None:
        if self._control_server is not None:
            try:
                self._control_server.close()
                # Bounded: wait_closed also waits for in-flight
                # forwarded commands to drain; a wedged caller
                # must never stall the daemon's own close.
                await asyncio.wait_for(
                    self._control_server.wait_closed(), timeout=2)
            except Exception:
                pass
            self._control_server = None
        self._control_token = None
        try:
            self._control_socket_path().unlink()
        except OSError:
            pass

    def _secret_path(self) -> Path:
        return self.state_dir / f"secret-{self.username}.json"

    def _load_secret(self) -> str | None:
        p = self._secret_path()
        if p.exists():
            try:
                return json.loads(p.read_text()).get("secret")
            except Exception:
                return None
        return None

    def _save_secret(self, secret: str) -> None:
        # ATOMIC (v1.3.7, registration resume): the secret is the
        # identity's claim on its username — a process killed
        # mid-write must never leave a torn secret file behind,
        # because the retry would then load garbage, present no
        # secret, and collide with its OWN half-registration
        # (username_taken). Write to a temp file and os.replace,
        # for the secret and for the current.json pointer alike:
        # on disk there is always either the whole old state or
        # the whole new state, never a splice.
        p = self._secret_path()
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"username": self.username,
                                   "secret": secret}))
        os.replace(tmp, p)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        cur = self.state_dir / "current.json"
        ctmp = cur.with_suffix(".json.tmp")
        ctmp.write_text(json.dumps(
            {"username": self.username,
             "display_name": self.display_name}))
        os.replace(ctmp, cur)

    def _group_keys_path(self) -> Path:
        return self.state_dir / f"groupkeys-{self.username}.json"

    def _load_group_keys(self) -> None:
        p = self._group_keys_path()
        if p.exists():
            try:
                for gid, rec in json.loads(p.read_text()).items():
                    self._group_keys[gid] = {
                        "epoch": rec["epoch"],
                        "key": base64.b64decode(rec["key"])}
            except Exception:
                pass

    def _store_group_key(self, gid: str, epoch: int, key: bytes) -> None:
        self._group_keys[gid] = {"epoch": epoch, "key": key}
        data = {g: {"epoch": r["epoch"],
                    "key": base64.b64encode(r["key"]).decode()}
                for g, r in self._group_keys.items()}
        p = self._group_keys_path()
        p.write_text(json.dumps(data))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    def _channel_keys_path(self) -> Path:
        return self.state_dir / f"channelkeys-{self.username}.json"

    def _load_channel_keys(self) -> None:
        p = self._channel_keys_path()
        if p.exists():
            try:
                for cid, rec in json.loads(p.read_text()).items():
                    self._channel_keys[cid] = {
                        "epoch": rec["epoch"],
                        "key": base64.b64decode(rec["key"])}
            except Exception:
                pass

    def _store_channel_key(self, cid: str, epoch: int, key: bytes) -> None:
        self._channel_keys[cid] = {"epoch": epoch, "key": key}
        data = {c: {"epoch": r["epoch"],
                    "key": base64.b64encode(r["key"]).decode()}
                for c, r in self._channel_keys.items()}
        p = self._channel_keys_path()
        p.write_text(json.dumps(data))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass

    def whoami(self) -> dict:
        return {"username": self.username,
                "display_name": self.display_name,
                "endpoint": self.endpoint,
                "endpoints": list(self.endpoints),
                "servers": list(self.known_servers)}

    # -- peer discovery (v1.2.0) ---------------------------------------------
    # The mesh is learned, never configured by hand: every relay's
    # welcome carries the live server registry, and servers() asks
    # again on demand. Learned peers join the race set automatically
    # and persist in the state dir (servers.json) — refreshed on
    # every successful connect — so a rebooted agent with a dead
    # home boots straight onto a known peer.

    def _servers_path(self) -> Path:
        return self.state_dir / "servers.json"

    def _rebuild_endpoints(self) -> None:
        out = [self.endpoint]
        for ep in self._configured_fallbacks:
            if ep and ep not in out:
                out.append(ep)
        now = time.time()
        for ep in sorted(self._discovered_servers):
            if not ep or ep in out:
                continue
            entry = self._discovered_servers[ep]
            # Expiry: a peer nobody has re-advertised within the
            # TTL is forgotten — dead entries (an old bind address,
            # a retired server) must not linger in the race set.
            # Restored-from-disk entries are exempt until the first
            # live learn of the session (see _mesh_restored).
            learned_at = entry.get("learned_at")
            if learned_at is not None and not self._mesh_restored and \
                    now - learned_at > DISCOVERED_SERVER_TTL_SECONDS:
                continue
            # Eligibility (mesh rule): a server whose last-known
            # health is at/below the floor is NOT GOOD — it is never
            # raced. Unknown health (never measured) stays eligible:
            # the relay's own admission gate is the backstop.
            health = entry.get("health")
            if health is not None and health <= SERVER_HEALTHY_MIN:
                continue
            out.append(ep)
        self.endpoints = out

    def _load_server_list(self) -> None:
        if self.ephemeral:
            return
        try:
            data = json.loads(self._servers_path().read_text())
        except Exception:
            return
        if not isinstance(data, dict) or \
                data.get("home") != self.endpoint:
            return  # a list learned under a different home is stale
        entries = data.get("servers") or []
        saved_at = data.get("saved_at") or 0
        for e in entries:
            if isinstance(e, dict):
                # The persisted stamp governs expiry; entries saved
                # by an older build fall back to the file's saved_at.
                e.setdefault("learned_at", saved_at)
        if entries:
            self._mesh_restored = True
        self._learn_servers(entries, persist=False)

    def _persist_server_list(self) -> None:
        if self.ephemeral or not self.known_servers:
            return
        payload = {"version": 1, "home": self.endpoint,
                   "servers": self.known_servers,
                   "saved_at": int(time.time())}
        try:
            p = self._servers_path()
            tmp = p.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(payload, indent=1))
            os.replace(tmp, p)
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        except Exception:
            pass  # persistence is resilience, never a hard failure

    def _learn_servers(self, entries, persist: bool = True) -> None:
        learned: list[dict] = []
        for e in entries or []:
            if not isinstance(e, dict):
                continue
            ep = str(e.get("endpoint") or "").strip().rstrip("/")
            if not ep:
                continue
            entry = {"label": str(e.get("label") or ep),
                     "endpoint": ep,
                     "host_agent": str(e.get("host_agent") or ""),
                     "version": str(e.get("version") or ""),
                     # Carrying (v1.3.0): identity + ownership ride
                     # along so directory/whoami views can say whose
                     # server this is and who is carrying it. Health
                     # -1 = UNRATED (still testing, never raced).
                     "server_id": str(e.get("server_id") or ""),
                     "owner_agent": str(e.get("owner_agent") or ""),
                     "carried_by": str(e.get("carried_by") or ""),
                     "carry_state": str(e.get("carry_state") or ""),
                     "health": (int(e["health"]) if isinstance(
                         e.get("health"), (int, float)) else None),
                     "riders": (int(e["riders"]) if isinstance(
                         e.get("riders"), (int, float)) else None),
                     "capacity": (int(e["capacity"]) if isinstance(
                         e.get("capacity"), (int, float)) else None),
                     # Live advertisements (persist=True) stamp NOW;
                     # a restored list keeps its persisted stamp so
                     # expiry is honest across restarts.
                     "learned_at": (time.time() if persist else
                                    (float(e["learned_at"]) if isinstance(
                                        e.get("learned_at"),
                                        (int, float)) else 0.0))}
            learned.append(entry)
            if ep != self.endpoint:
                self._discovered_servers[ep] = entry
        if learned:
            if persist:
                # A live advertisement: the restored-mesh exemption
                # ends; every entry's stamp is now session-fresh.
                self._mesh_restored = False
            self.known_servers = learned
            self._rebuild_endpoints()
            if persist:
                self._persist_server_list()

    async def servers(self) -> list[dict]:
        """Ask the connected relay for the live mesh (peer
        discovery) and merge what it answers into the race set."""
        data = await self._request({"type": "servers"})
        entries = data.get("servers") or []
        self._learn_servers(entries)
        return entries

    # -- connection -------------------------------------------------------------
    async def _send_raw(self, frame: dict) -> None:
        await self._ws.send(json.dumps(frame))

    async def _open_socket(self, url: str):
        """Open one websocket through the anti-dark path (point 44):
        resolve FRESH via resolve_host (system -> DoH fallback),
        then connect to a resolved address — never a pinned stale
        IP. For wss the TLS server name stays the endpoint host.

        ADDRESS-FAMILY RACING (v1.3.7, happy eyeballs): the
        resolved addresses are interleaved IPv4/IPv6 and the
        connection attempts are RACED with a bounded stagger —
        the first attempt starts at once, the next family/address
        joins a stagger later if the first has not landed, and the
        FIRST success wins. The pre-1.3.7 sequential walk could
        park the whole connect on one blackholed family (a v6
        route that silently drops costs a full TCP timeout before
        v4 is even tried — the foreign-sandbox failure where the
        operator had to be told 'use IPv4'); now a broken family
        never hangs or kills the attempt, and one family's
        failures never poison the other's: losers are cancelled,
        and only when EVERY attempt has failed does the last
        error surface (the caller's unlimited reconnect then
        retries the whole race, backoff cap unchanged)."""
        from urllib.parse import urlparse
        from . import timing as _timing
        stagger = float(getattr(
            _timing, "CONNECT_FAMILY_STAGGER_SECONDS", 0.25) or 0.25)
        p = urlparse(url)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "wss" else 80)
        ips = _interleave_families(await resolve_host(host, port))
        last: Exception | None = None

        def _attempt_kwargs(ip: str):
            netloc = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
            # Path AND query survive: a carried server's alias is
            # the carrier's /ws endpoint + ?carry=<server_id>
            # (v1.3.0) — dropping the query would connect to the
            # carrier's own identity instead of the carried one.
            target = p.path or "/"
            if p.query:
                target += "?" + p.query
            kwargs: dict = {"max_size": MAX_FRAME}
            if ip != host:
                kwargs["extra_headers"] = {"Host": f"{host}:{port}"}
                if p.scheme == "wss":
                    import ssl as _ssl
                    kwargs["ssl"] = _ssl.create_default_context()
                    kwargs["server_hostname"] = host
            return f"{p.scheme}://{netloc}{target}", kwargs

        async def _attempt(ip: str):
            ip_url, kwargs = _attempt_kwargs(ip)
            return await connect(ip_url, **kwargs)

        pending: set = set()
        winner = None
        idx = 0
        loop = asyncio.get_running_loop()
        next_launch = loop.time()
        try:
            while winner is None and (idx < len(ips) or pending):
                now = loop.time()
                if idx < len(ips) and now >= next_launch:
                    pending.add(asyncio.create_task(
                        _attempt(ips[idx])))
                    idx += 1
                    next_launch = now + stagger
                    continue
                timeout = None
                if idx < len(ips):
                    timeout = max(0.0, next_launch - now)
                if not pending:
                    # Every launched attempt already failed; wait
                    # out the stagger before launching the next
                    # (never a busy spin).
                    await asyncio.sleep(timeout or 0.0)
                    continue
                done, pending = await asyncio.wait(
                    pending, timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    if t.exception() is not None:
                        last = t.exception()
                    elif winner is None:
                        winner = t.result()
                    else:
                        # A second success in the same batch: the
                        # race has its winner; close the spare.
                        try:
                            await t.result().close()
                        except Exception:
                            pass
            if winner is not None:
                return winner
        finally:
            # Cancel the losers WITHOUT awaiting their settle: a
            # blackholed attempt's cancellation can itself take
            # until its handshake timeout (the debug trace: winner
            # found at 0.25s, return stalled to 10s by the gather)
            # — the winner must never wait on a loser's corpse.
            # The done callback just reaps the exception so the
            # loop never logs it as unretrieved.
            def _reap(t):
                if not t.cancelled():
                    t.exception()
            for t in pending:
                t.cancel()
                t.add_done_callback(_reap)
        # Network auto-adjust, proxied-egress case (point 44b): some
        # networks only allow egress through an HTTP proxy named in
        # the environment. If every direct address failed and a proxy
        # is configured for this host, let the websockets library use
        # it — an agent on such a network still auto-connects.
        if _env_proxy_applies(host, p.scheme):
            try:
                # The asyncio client honours the environment proxy;
                # the legacy connect() used above has no proxy
                # support, so the fallback goes through it instead.
                from websockets.asyncio.client import (
                    connect as _proxied_connect)
                return await _proxied_connect(url, max_size=MAX_FRAME)
            except Exception as exc:
                last = exc
        raise last if last else ConnectionError(f"cannot reach {url}")

    def _endpoint_rank(self, url: str) -> tuple:
        """Peer selection order (mesh rule): OWN home first — the
        only preference any client may have; then discovered peers
        by highest health, then fewest current riders; configured
        fallbacks and unknown-health peers last (operator seeds —
        eligible, unranked). The platform's relay gets NO preference:
        hosting is peer-to-peer, there is no admin funnel."""
        if url == self.endpoint:
            return (0, 0, 0)
        e = self._discovered_servers.get(url)
        if e is not None and e.get("health") is not None:
            return (1, -int(e["health"]), int(e.get("riders") or 0))
        return (2, 0, 0)

    def _is_deflected(self, url: str) -> bool:
        return time.time() < self._deflected_until.get(url, 0.0)

    def _note_deflection(self, url: str, reason: str) -> None:
        """A server refused this agent as a rider (full, or health
        at/below the floor). Record it and sit the endpoint out of
        races briefly; the retry deflects to the next eligible
        server. The refusal is never terminal and never silent."""
        self._deflected_until[url] = time.time() + 20
        self.deflections.append({"endpoint": url, "reason": reason,
                                 "at": int(time.time())})
        log.warning("deflected by %s (%s); trying the next eligible"
                    " server", url, reason)

    async def _socket_survives(self, url: str) -> bool:
        """Probe with an application ping (v1.2.2): open a socket to
        ``url``, send the protocol's own ``{"type": "ping"}`` frame,
        and require the relay's ``pong`` inside
        RACE_PROBE_DWELL_SECONDS.

        Neither a bare handshake nor a WebSocket control ping can
        prove life: an endpoint fronted by a tunnel (the production
        shape) completes the upgrade — and its edge even answers
        control pings — while the relay behind it is dead; the
        close arrives a beat later. Without a real round-trip the
        dead endpoint kept "winning" every race in the v1.2.0
        production kill-drill. Text frames are what a tunnel
        actually bridges, and only a live relay answers the
        application ping (it does so even before hello): live =
        pong in milliseconds, phantom = close with no frame,
        wedged = silence past the cap."""
        from .timing import RACE_PROBE_DWELL_SECONDS
        ws = None
        try:
            ws = await self._open_socket(url)
            await ws.send('{"type": "ping"}')
            await asyncio.wait_for(ws.recv(),
                                   timeout=RACE_PROBE_DWELL_SECONDS)
            return True
        except Exception:
            return False
        finally:
            if ws is not None:
                try:
                    await ws.close()
                except Exception:
                    pass

    async def _race_endpoints(self) -> str | None:
        """Parallel endpoint race (point 44a): home + every known
        peer are probed CONCURRENTLY — first healthy socket wins,
        back-to-back, no serial waiting through a dead list. Home
        gets a short prefer-home grace inside the race so a healthy
        home is never beaten by a faster peer. Among peers, the
        winner is chosen by mesh rank (health, then load) among the
        sockets that answered inside the grace window."""
        from .timing import CONNECT_RACE_GRACE_SECONDS
        self.race_count += 1
        candidates = [u for u in self.endpoints
                      if not self._is_deflected(u)]
        if self._skip_next_race:
            # One-shot skip: the endpoint(s) that won the last race
            # but failed at hello sit this one out, so the race can
            # reach the next candidate instead of looping on a
            # phantom. Consumed by this race either way.
            fresh = [u for u in candidates
                     if u not in self._skip_next_race]
            self._skip_next_race = set()
            if fresh:
                candidates = fresh
        if not candidates:
            candidates = list(self.endpoints)

        async def _probe(url: str) -> str:
            if not await self._socket_survives(url):
                raise ConnectionError(
                    f"endpoint {url} did not survive the probe dwell")
            return url

        tasks = {asyncio.create_task(_probe(u)): u
                 for u in candidates}
        winners: list[str] = []
        try:
            pending = set(tasks)
            deadline = None
            while pending:
                timeout = None
                if winners and deadline is not None:
                    timeout = max(0.0, deadline
                                  - asyncio.get_event_loop().time())
                    if timeout == 0:
                        break
                done, pending = await asyncio.wait(
                    pending, timeout=timeout,
                    return_when=asyncio.FIRST_COMPLETED)
                for t in done:
                    if t.exception() is None:
                        url = t.result()
                        if url == self.endpoint:
                            return url  # home wins outright
                        winners.append(url)
                        if deadline is None:
                            deadline = (asyncio.get_event_loop().time()
                                        + CONNECT_RACE_GRACE_SECONDS)
                    # failed probes are just out of this race
            if winners:
                return min(winners, key=self._endpoint_rank)
            return None
        finally:
            for t in tasks:
                t.cancel()

    async def start(self, endpoint: str | None = None) -> str:
        if self.identity is None:  # ephemeral dial client
            self.identity = Identity.ephemeral()
        url = endpoint or self.endpoint
        self.current_endpoint = url
        # Instance collision (v1.3.7): claim this identity's state
        # dir BEFORE any socket opens. Raises InstanceCollision
        # immediately when another live process owns it — a
        # registration failure that names its step and its owner,
        # never a SQLite fight discovered three layers down. The
        # lock is held until close(): a start() that fails keeps
        # the claim, because this object IS the instance retrying.
        self._acquire_instance_lock()
        try:
            self._ws = await self._open_socket(url)
        except Exception as exc:
            # Registration failure reporting (v1.3.7): name the
            # step, the endpoint, and the way forward — a bare OS
            # error ("Network is unreachable") is never the final
            # word on a registration.
            raise ConnectionError(
                f"registration failed at step 'connect': endpoint"
                f" {url} did not answer for @{self.username or '?'}"
                f" ({type(exc).__name__}: {exc}). Nothing was"
                f" registered. Retry: check that the endpoint is"
                f" the right one and reachable from this machine —"
                f" the production default is"
                f" wss://x.novamail.store/ws; a first registration"
                f" with this same state dir resumes cleanly once"
                f" the line answers.") from exc
        self._declared_link_sent = self._decision_declaration()
        # Key-signed hello (v1.3.9): a RETURNING identity (one with
        # a saved bootstrap secret) authenticates by SIGNATURE —
        # the hello announces auth="key" and carries NO secret; the
        # relay's auth_challenge is answered in the welcome loop
        # below with an Ed25519 signature from the identity key.
        # The reusable secret is presented ONLY to an endpoint that
        # has already refused a key hello (a pre-1.3.9 relay — see
        # _legacy_auth_endpoints and the welcome loop's refusal
        # handling): a bounded, loudly logged transition fallback,
        # per endpoint, never the default path. A first
        # registration has no saved secret and bootstraps exactly
        # as before: the claim's welcome issues the secret ONCE.
        _saved_secret = None if self.ephemeral else self._load_secret()
        _key_auth = bool(_saved_secret) and \
            url not in self._legacy_auth_endpoints
        await self._send_raw({
            "type": "hello", "username": self.username or None,
            "display_name": self.display_name,
            "pubkey": self.identity.public_key_b64,
            "sign_pub": self.identity.signing_public_key_b64,
            "capabilities": self.capabilities,
            "cap_description": self.cap_description,
            "mode": self.mode,
            "decision_link": self._declared_link_sent,
            # Delivery custody (v1.3.7): this client journals every
            # inbound item into its canonical local mailbox and acks
            # items back — the relay keeps custody of queued frames
            # until the ack, and marks audit delivered only then.
            "delivery_ack": 1,
            "client_version": _package_version(),
            "secret": None if (self.ephemeral or _key_auth)
                      else _saved_secret,
            "auth": "key" if _key_auth else None,
            "ephemeral": self.ephemeral,
            "home_endpoint": self.endpoint,
            "core": core_fingerprint(),
        })
        # Bounded welcome wait (v1.1 hardening): a hello that lands in
        # a bad egress window — or on a relay whose loop is briefly
        # busy — must not park this client on a silent socket forever.
        # On timeout the socket closes and the run() loop retries
        # (unlimited attempts, 5s pacing cap) until a hello lands in a
        # good window; no service restart is ever needed to recover.
        #
        # FIRST-CONTACT WINDOW (v1.3.7): the steady-state 8s bound is
        # race hygiene for an ALREADY-registered agent — the
        # v1.2.3 kill-drill showed two stalled 30s hellos serially
        # costing ~60s of flip time, and a healthy relay answers a
        # reclaim hello in well under a second even through a
        # tunnel. A FIRST registration is a different animal: the
        # relay must claim a brand-new identity (a store write,
        # possibly on a shared backend reached from a slow foreign
        # network), and the cost asymmetry is total — a generous
        # window is paid once in an agent's life, while a first
        # hello cut at 8s can strand the registration entirely
        # (the welcome carries the only copy of the owner-secret).
        # So: while NO completed registration is on record locally
        # (no saved secret — the same fact that makes the retry a
        # fresh claim rather than a reclaim), the welcome wait is
        # FIRST_HELLO_TIMEOUT_SECONDS; the moment a secret exists,
        # every later hello is a reclaim and the 8s bound stands.
        from . import timing as _timing
        from .timing import HELLO_TIMEOUT_SECONDS
        _first_contact = not self.ephemeral and \
            _saved_secret is None
        # The first-contact window is DERIVED from the timing
        # map's own constant — never a free-standing number: the
        # map stays the single source of truth (a test that
        # patches HELLO_TIMEOUT_SECONDS down must see every
        # hello wait shrink with it), while in production
        # (8s shipped) a first registration gets up to the
        # FIRST_HELLO_TIMEOUT_SECONDS target (30s default when
        # the map does not name one) — bounded at 4x the steady
        # window so the two can never drift apart.
        _hello_window = HELLO_TIMEOUT_SECONDS
        if _first_contact:
            _first_target = float(getattr(
                _timing, "FIRST_HELLO_TIMEOUT_SECONDS", 30) or 30)
            _hello_window = max(
                float(HELLO_TIMEOUT_SECONDS),
                min(_first_target,
                    float(HELLO_TIMEOUT_SECONDS) * 4))
        _hello_deadline = (asyncio.get_event_loop().time()
                           + _hello_window)
        while True:
            _left = _hello_deadline - asyncio.get_event_loop().time()
            if _left <= 0:
                try:
                    await self._ws.close()
                except Exception:
                    pass
                raise ConnectionError(
                    f"registration failed at step 'welcome':"
                    f" endpoint {url} accepted the connection but"
                    f" no welcome arrived within {_hello_window:g}s"
                    f" for @{self.username or '?'} (the hello was"
                    f" sent). The relay may already have claimed"
                    f" the identity — retry with this same state"
                    f" dir and the registration resumes; nothing"
                    f" needs to be re-created or renamed.")
            try:
                raw = await asyncio.wait_for(self._ws.recv(),
                                             timeout=_left)
            except asyncio.TimeoutError:
                try:
                    await self._ws.close()
                except Exception:
                    pass
                raise ConnectionError(
                    f"registration failed at step 'welcome':"
                    f" endpoint {url} accepted the connection but"
                    f" no welcome arrived within {_hello_window:g}s"
                    f" for @{self.username or '?'} (the hello was"
                    f" sent). The relay may already have claimed"
                    f" the identity — retry with this same state"
                    f" dir and the registration resumes; nothing"
                    f" needs to be re-created or renamed.")
            except websockets.exceptions.ConnectionClosed as exc:
                # The folk failure (v1.3.7): registration cut off
                # mid-flight. Name it as what it is — and say the
                # part that matters: the same state dir resumes.
                raise ConnectionError(
                    f"registration failed at step 'welcome': the"
                    f" connection to {url} dropped while waiting"
                    f" for the welcome for @{self.username or '?'}"
                    f" ({exc}). The relay may already have claimed"
                    f" the identity — retry with this same state"
                    f" dir and the registration resumes; nothing"
                    f" needs to be re-created or renamed.") from exc
            frame = json.loads(raw)
            if frame.get("type") == "auth_challenge":
                # Key-signed hello (v1.3.9): sign the challenge
                # (nonce | relay | username | expires, the exact
                # canonical payload) with the identity's Ed25519
                # key and answer. The signature is worthless to
                # any other relay and after its expiry — nothing
                # reusable ever leaves this machine.
                from .protocol import auth_challenge_payload
                _payload = auth_challenge_payload(
                    frame.get("nonce"), frame.get("relay"),
                    self.username, frame.get("expires"))
                await self._send_raw({
                    "type": "auth_response",
                    "signature": self.identity.sign(_payload)})
                continue
            if frame.get("type") == "welcome":
                self.username = frame["username"]
                if not self._oversight_configured and \
                        frame.get("oversight_pubkey"):
                    # Relay-advertised oversight key: fleet agents
                    # pick it up with zero manual config. A locally
                    # configured key (env/arg) is the override and is
                    # never replaced by the relay's value.
                    self.oversight_pubkey = str(
                        frame["oversight_pubkey"])
                if not self.ephemeral and \
                        self.identity.path is None:
                    pass
                if frame.get("secret"):
                    self._save_secret(frame["secret"])
                if frame.get("servers"):
                    # Peer discovery (v1.2.0): learn the live mesh
                    # from whichever relay served this hello, merge
                    # it into the race set, and persist it.
                    self._learn_servers(frame["servers"])
                if frame.get("updates_enabled") is not None:
                    # The relay operator's switch (hardened core):
                    # the ONLY sanctioned way the checker is off.
                    self._relay_updates_enabled = bool(
                        frame["updates_enabled"])
                log.info("registered as @%s (%d queued)",
                         self.username, frame.get("queued", 0))
                self._warn_if_unlinked()
                self._reader = asyncio.create_task(self._read_loop())
                # The heartbeat belongs to the CONNECTION, not to
                # run()'s supervision bundle (v1.4.3): a start()-only
                # client (one-shot SDK embeddings, the CLI, tools)
                # previously never pinged, so its shared last_seen
                # froze at the hello and every brother relay read
                # it OFFLINE after the 15s grace while it was
                # connected and active — cross-server room signals
                # addressed to it failed peer_offline (the v1.4.2
                # production room proof caught exactly this).
                if self._ping_task is None or self._ping_task.done():
                    self._ping_task = asyncio.create_task(
                        self._ping_loop())
                # Owner-seat control channel (v1.3.9): once the
                # reader is live, the lock holder starts serving
                # forwarded one-shot commands (send / group add).
                await self._start_control_server()
                # BOOT SEQUENCE (point 39c), strict order, no delays:
                # identity/journal loaded (1) -> connected + presence
                # registered (2) -> fetch open assignments (3) ->
                # resume from checkpoints (4) -> queued frames drain
                # through the read loop (5). Work handlers invoked by
                # arriving frames wait on the boot gate until step 4
                # has run, so resumed work always goes first.
                if not self.ephemeral:
                    self._boot_gate.clear()
                    try:
                        await self._resume_open_work()
                        # Reconnect resync (43e): full role/permission
                        # set + membership caches, in case events were
                        # missed while down or riding another server.
                        await self._resync_memberships()
                        await self.self_check()
                    except Exception:
                        log.exception("resume/resync pass failed")
                    finally:
                        self._boot_gate.set()
                self._load_pending_reads()
                if self._pending_reads:
                    # Receipts that failed to flush while offline
                    # retry on every (re)connect.
                    self._queue_read(next(iter(self._pending_reads)))
                # MAILBOX (v1.3.7), on every (re)connect — start()
                # completing auth is the one place live start and
                # the run() reconnect loop share: backfill the
                # canonical mailbox from the relay's history, then
                # replay whatever was journaled but never taken in
                # (a previous process may have journaled and died
                # before the intelligence ever saw the item). Both
                # are best-effort: a failure here must never dark
                # the line — the items stay journaled / queued and
                # the next start tries again.
                if self.mailbox is not None:
                    try:
                        self.mailbox_sync = await self.sync_history()
                    except Exception:
                        log.exception("mailbox history sync failed")
                    try:
                        await self._replay_mailbox()
                    except Exception:
                        log.exception("mailbox replay failed")
                # CREDENTIALS VAULT (v1.4.0), on every (re)connect:
                # scheduled, NOT awaited inline. Vault sync is
                # replication, never a gate — the local vault is
                # authoritative — and the boot sequence above keeps
                # its exact shape: an inline round-trip here
                # measurably perturbs the live-flush / mailbox
                # replay interleave the delivery guarantee is
                # tuned around (a queued urgent message's handler
                # fired twice inside one poll window when the sync
                # sat inline; the sync as a post-boot task leaves
                # the boot interleave untouched). The task is
                # guarded like the passes above: a sync failure can
                # never dark the line and retries on the next
                # connect.
                if not self.ephemeral:
                    asyncio.create_task(self._vault_sync_guarded())
                return self.username
            if frame.get("type") == "error":
                if _key_auth and _saved_secret and \
                        frame.get("reason") == "username_taken":
                    # A pre-1.3.9 relay cannot answer an
                    # auth_challenge: it read the secretless key
                    # hello against the existing row as a collision.
                    # Mark THIS endpoint legacy — the reconnect
                    # loop's next hello to it presents the secret,
                    # exactly as a pre-1.3.9 client would — and say
                    # so loudly: the fallback is a transition bridge
                    # for old relays, never a silent downgrade.
                    self._legacy_auth_endpoints.add(url)
                    log.warning(
                        "relay at %s refused the key-signed hello "
                        "(username_taken): it predates key-signed "
                        "hello (v1.3.9). Falling back to the legacy "
                        "secret hello for THIS endpoint only; the "
                        "secret never travels to a relay that "
                        "answers challenges.", url)
                await self._ws.close()
                raise RegistrationFailed(
                    f"{frame.get('reason')}: {frame.get('detail', '')}")
        raise RegistrationFailed("connection closed before welcome")

    async def _read_loop(self) -> None:
        try:
            async for raw in self._ws:
                await self._dispatch(json.loads(raw))
        except websockets.exceptions.ConnectionClosed:
            pass

    async def _ping_loop(self) -> None:
        """The connection's heartbeat (v1.4.3 — owned by start(),
        not by run()): a ping every HEARTBEAT_SECONDS for as long
        as the connection lives, plus the last-alive stamp the
        watchdog reads (a stale stamp = a hung process = death).
        Presence derives from these pings on every relay, so they
        must flow for EVERY connected client — daemon or one-shot
        embedding alike. A send failure ends the loop; the reader
        owns disconnect handling and a reconnect re-spawns it."""
        stamp = self.state_dir / f"heartbeat-{self.username}.txt"
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            try:
                if self._ws is not None:
                    await self._send_raw({
                        "type": "ping",
                        "activity": self._activity_state()})
                stamp.write_text(str(int(time.time())))
            except Exception:
                return

    async def close(self) -> None:
        # Owner-seat control channel (v1.3.9): stop serving
        # forwarded commands before the socket and lock go away.
        await self._stop_control_server()
        # Media sessions (v1.3.9): close every live RTC session
        # before the socket goes — a peer must never be left
        # talking to a dead track, and recorders must finalize
        # their files.
        for _sess in list(self._media_sessions.values()):
            try:
                await _sess.close()
            except Exception:
                pass
        self._media_sessions.clear()
        self._media_rooms.clear()
        self._release_instance_lock()
        if self._update_task is not None:
            self._update_task.cancel()
            self._update_task = None
        if self._read_flush_task is not None:
            self._read_flush_task.cancel()
            self._read_flush_task = None
        if self._reader is not None:
            self._reader.cancel()
            self._reader = None
        if self._ping_task is not None:
            self._ping_task.cancel()
            self._ping_task = None
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

    async def serve(self) -> None:
        assert self._ws is not None, "call start() first"
        self._ensure_update_checker()
        if self._reader is not None:
            try:
                await self._reader
            except asyncio.CancelledError:
                # Cancellation is terminal (a supervisor stopping the
                # daemon task): never swallow it into a reconnect.
                if self._reader is not None:
                    self._reader.cancel()
                raise

    # -- in-daemon self-update (v1.1.8) --------------------------------
    # The updater lives WITH the agent. Every UPDATE_CHECK_SECONDS
    # (timing law: 15 min) the running daemon checks the repo itself,
    # applies a verified update through the staged path, and restarts
    # by re-exec — no crontab, no systemd timer, no supervisor, no
    # host facility of any kind is required, so the agent is
    # self-maintaining on any host that can run the agent itself.

    def _ensure_update_checker(self) -> None:
        if self._update_task is not None and not self._update_task.done():
            return
        if self.ephemeral or not self.username:
            return  # dial/ephemeral clients are not installations
        # Hardened core (v1.2.0): self_update_enabled() is consulted
        # for its warning side-effect only — the agent side can no
        # longer switch the checker off. The one sanctioned kill
        # switch is the RELAY operator's, learned from the welcome.
        self_update_enabled()
        if not self._relay_updates_enabled:
            log.warning("self-update: checker NOT armed — disabled"
                        " by the relay operator (relay-side"
                        " AGENTLINK_UPDATES_ENABLED; the state is"
                        " visible on the operator dashboard)")
            return
        self._update_task = asyncio.create_task(self._update_check_loop())

    @contextlib.asynccontextmanager
    async def _critical_op(self, label: str):
        """Mark a non-checkpointable operation in flight (update
        continuity law). While any critical operation runs, a
        self-update swap waits; checkpointable work never enters
        here, so a busy agent still updates on time."""
        self._op_count += 1
        self._ops_idle.clear()
        try:
            yield
        finally:
            self._op_count -= 1
            if self._op_count <= 0:
                self._op_count = 0
                self._ops_idle.set()

    async def _wait_for_ops_drain(self, timeout: float) -> bool:
        """True when no critical operation is in flight (immediately,
        or within ``timeout`` as running operations complete)."""
        if self._op_count == 0:
            return True
        log.info("self-update: waiting up to %gs for %d in-flight"
                 " operation(s) to finish before swapping", timeout,
                 self._op_count)
        try:
            await asyncio.wait_for(self._ops_idle.wait(), timeout)
        except asyncio.TimeoutError:
            pass
        return self._op_count == 0

    async def _pre_update_checkpoint(self) -> None:
        """Update safety law: before a swap/re-exec, flush every
        durable obligation into the agent home.

        * work journal — assignments + checkpoints live in SQLite,
          committed per write; force a final commit here.
        * work checkpoints — written journal-first + relay-mirrored
          by checkpoint() at the moment the agent records them;
          nothing extra is owed at update time.
        * read cursors — attempt an immediate bounded flush of
          pending receipts; whatever remains is already persisted
          to disk (pending-reads-<user>.json) and is picked up by
          the next process on connect.
        The updater itself writes NOTHING in the state dir except
        its own staging/backup areas — identity, config, the
        journal and the state DBs are never touched by an update.
        """
        if self._pending_reads:
            ids = sorted(self._pending_reads)
            try:
                await asyncio.wait_for(
                    self._request({"type": "read", "ids": ids}),
                    timeout=10)
                self._pending_reads.difference_update(ids)
                self._persist_pending_reads()
            except Exception:
                log.info("self-update: %d read receipt(s) could not"
                         " flush pre-update; they are persisted and"
                         " will flush after the restart",
                         len(self._pending_reads))
        if self._journal is not None:
            try:
                self._journal.flush()
            except Exception:
                log.exception("self-update: journal flush failed")
        log.info("self-update: pre-update checkpoint complete"
                 " (journal flushed, %d read receipt(s) pending,"
                 " all durable state in the agent home)",
                 len(self._pending_reads))

    async def _update_check_loop(self) -> None:
        from .timing import UPDATE_DRAIN_WAIT_SECONDS
        from .updater import Updater
        interval = resolve_update_check_seconds()
        feed = Updater(state_dir=self.state_dir).base
        log.info("self-update: in-daemon checker armed — feed %s,"
                 " check every %gs, next check in %gs (no host cron"
                 " required)", feed, interval, interval)
        while True:
            await asyncio.sleep(interval)
            # Phase 1 (worker thread): fetch the manifest, verify
            # every changed file's SHA-256, stage the new tree and
            # smoke-test it — all WITHOUT touching the running code.
            try:
                prepared = await asyncio.to_thread(
                    self._self_update_prepare)
            except Exception:
                log.exception("self-update: prepare crashed; the"
                              " checker continues and will retry")
                continue
            if prepared.get("error"):
                # Loud, and the agent keeps running its current
                # code — a bad feed or a corrupt file never strands
                # or breaks a running agent.
                log.error("self-update: check failed: %s (still"
                          " running current code; will retry next"
                          " check)", prepared["error"])
                continue
            if not prepared.get("prepared"):
                continue  # up to date, or files already match
            # Phase 2 (continuity law): the update is READY. Wait —
            # bounded — for any decision call / delivery / upload
            # chunk in flight to finish. On timeout the update
            # DEFERS to the next check; it never interrupts an
            # operation.
            if not await self._wait_for_ops_drain(
                    UPDATE_DRAIN_WAIT_SECONDS):
                log.warning(
                    "self-update: %s is staged and smoke-tested but"
                    " operations are still in flight after %gs —"
                    " deferring the swap to the next check (an"
                    " update never interrupts a decision call, a"
                    " delivery, or an upload)",
                    prepared["new_version"], UPDATE_DRAIN_WAIT_SECONDS)
                await asyncio.to_thread(self._self_update_discard,
                                        prepared)
                continue
            # Phase 3: checkpoint all durable state to the agent home.
            await self._pre_update_checkpoint()
            # Phase 4 (worker thread): rollback backup + atomic swap
            # + health check (automatic rollback on failure).
            try:
                outcome = await asyncio.to_thread(
                    self._self_update_finish, prepared)
            except Exception:
                log.exception("self-update: apply crashed; the"
                              " checker continues and will retry")
                continue
            if outcome.get("error"):
                log.error("self-update: apply failed: %s (still"
                          " running current code)", outcome["error"])
                continue
            if outcome.get("updated"):
                log.warning("self-update: installed %s -> %s"
                            " (backup %s); restarting self via"
                            " re-exec", outcome.get("from"),
                            outcome.get("to"), outcome.get("backup"))
                self._restart_self()
                # _restart_self returns only when exec was impossible
                # (e.g. empty sys.argv under an embedding host): the
                # new code is on disk; the loop keeps running and
                # later ticks no-op (files already match).

    def _self_update_prepare(self) -> dict:
        """Phase 1 of a check (worker thread; feed I/O never stalls
        the connection loop). Never raises for feed problems — the
        outcome is reported in the returned dict."""
        from .updater import UpdateError, Updater
        up = Updater(state_dir=self.state_dir)
        try:
            manifest = up.fetch_manifest()
            return up.prepare_staged(manifest)
        except UpdateError as exc:
            return {"error": str(exc)}
        except Exception as exc:
            return {"error": f"{type(exc).__name__}: {exc}"}

    def _self_update_finish(self, prepared: dict) -> dict:
        """Phase 4 (worker thread). Never raises for apply problems."""
        from .updater import UpdateError, Updater
        try:
            return Updater(state_dir=self.state_dir).finish_staged(
                prepared)
        except UpdateError as exc:
            return {"updated": False, "error": str(exc)}
        except Exception as exc:
            return {"updated": False,
                    "error": f"{type(exc).__name__}: {exc}"}

    def _self_update_discard(self, prepared: dict) -> None:
        from .updater import Updater
        Updater(state_dir=self.state_dir).discard_staged(prepared)

    def _restart_self(self) -> None:
        """Re-exec the SAME invocation so the new code runs — works
        with no systemd, no cron, no supervisor. On success this
        never returns (the process image is replaced; the new
        process hellos and reconnects through the normal machinery).

        The invocation must be reproduced faithfully: a daemon
        launched as ``python -m agentlink ...`` has sys.argv[0]
        pointing at the package's ``__main__.py`` file, and
        re-running that file as a plain script breaks its relative
        imports (``from .cli import main`` has no package). The
        interpreter's own record of the launch (sys.orig_argv) is
        therefore used verbatim; the __main__.py -> ``-m`` fix-up
        below is the fallback for interpreters without it.
        """
        orig = list(getattr(sys, "orig_argv", None) or [])
        if len(orig) >= 2:
            argv = [sys.executable, *orig[1:]]
        else:
            raw = list(sys.argv)
            if not raw or not raw[0]:
                log.error("self-update: cannot re-exec (empty"
                          " sys.argv); the new code is on disk —"
                          " restart the daemon to pick it up")
                return
            if Path(raw[0]).name == "__main__.py":
                raw = ["-m", Path(raw[0]).parent.name, *raw[1:]]
            argv = [sys.executable, *raw]
        log.warning("self-update: re-exec %s", argv)
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except Exception:
                pass
        try:
            os.execv(argv[0], argv)
        except Exception:
            log.exception("self-update: re-exec failed; the new code"
                          " is on disk — restart the daemon to pick"
                          " it up")

    async def run(self, reconnect_delay: float = 2.0,
                  home_probe_interval: float = HOME_PROBE_SECONDS) -> None:
        """Always online. Heartbeat: a ping every 5 seconds, owned
        by the CONNECTION (start() spawns it — see _ping_loop,
        v1.4.3), independent of the message/work loop — it never
        stops while the client is connected, and presence derives
        from it.

        Failover: home is tried first on every cycle. Fallbacks are
        ridden only while home is unavailable; a home-probe task checks
        home every ``home_probe_interval`` seconds while riding a
        fallback and migrates the connection back home the moment home
        answers. Because relays share one backend, queued messages and
        work follow the agent — nothing is lost or duplicated.
        """
        async def _home_probe():
            while True:
                await asyncio.sleep(min(home_probe_interval,
                                        RECONNECT_BACKOFF_CAP_SECONDS))
                self.home_probe_count += 1
                if self.current_endpoint == self.endpoint:
                    continue
                # Dwell-checked (v1.2.2): a tunneled home completes
                # the handshake even while dead; only a socket that
                # SURVIVES the dwell means home is really back.
                if not await self._socket_survives(self.endpoint):
                    continue
                log.info("home endpoint %s recovered; migrating back",
                         self.endpoint)
                if self._ws is not None:
                    try:
                        await self._ws.close()
                    except Exception:
                        pass
                return

        async def _network_watch():
            from .timing import NETWORK_WATCH_SECONDS
            while True:
                await asyncio.sleep(NETWORK_WATCH_SECONDS)
                fp = network_fingerprint()
                if fp != self._net_fingerprint:
                    self._net_fingerprint = fp
                    log.warning("network changed under the agent "
                                "(%s); reconnecting instantly", fp)
                    if self._ws is not None:
                        try:
                            await self._ws.close()
                        except Exception:
                            pass
                    return

        async def _mesh_watch():
            """While RIDING a peer (v1.2.0): refresh discovery on the
            mesh cadence, and if the ridden server's health falls to
            the floor, migrate — drop the socket and let the race
            pick the next eligible server (or home, which the
            home-probe is already watching). A server you ride is a
            waiting room; when it stops being good, you leave."""
            while True:
                # At home, discovery refreshes on the heartbeat
                # cadence (real-time law: mesh state moves at
                # heartbeat cadence at the slowest) — a peer that
                # earns its health rating must join the race set
                # within seconds, or a home that dies in the gap
                # leaves its agents with nobody to ride. While
                # riding, the slower refresh cadence stands.
                if self.current_endpoint is not None and \
                        self.current_endpoint == self.endpoint:
                    await asyncio.sleep(SERVER_HEARTBEAT_SECONDS)
                else:
                    await asyncio.sleep(MESH_REFRESH_SECONDS)
                if self.current_endpoint is None:
                    continue
                try:
                    entries = await self.servers()
                except Exception:
                    continue
                if self.current_endpoint == self.endpoint:
                    # At home: discovery still refreshes (v1.3.0 —
                    # a peer that was UNRATED at first welcome earns
                    # its rating minutes later and must join the
                    # race set without a reconnect), but home is
                    # never migrated away from: your own server
                    # always takes you back.
                    continue
                mine = next((e for e in entries
                             if e.get("endpoint")
                             == self.current_endpoint), None)
                if mine is not None and mine.get("health") is not None \
                        and mine["health"] <= SERVER_HEALTHY_MIN:
                    log.warning("ridden server %s health fell to %s%%"
                                " (floor %d%%); migrating to an"
                                " eligible server",
                                self.current_endpoint, mine["health"],
                                SERVER_HEALTHY_MIN)
                    if self._ws is not None:
                        try:
                            await self._ws.close()
                        except Exception:
                            pass
                    return

        while True:
            self.connection_state = "connecting"
            connected = False
            try:
                winner = await self._race_endpoints()
            except Exception:
                winner = None
            if winner is not None:
                try:
                    await self.start(winner)
                    connected = True
                except RegistrationFailed as exc:
                    reason = str(exc)
                    if reason.startswith(("server_full",
                                          "server_unhealthy",
                                          "server_unrated")):
                        # Mesh deflection (v1.2.0): this server
                        # won't take a rider right now — full, or
                        # not healthy enough. NOT a registration
                        # failure: deflect and race the next
                        # eligible server.
                        self._note_deflection(winner, reason)
                    else:
                        raise
                except Exception as exc:
                    # Won the race, failed the hello: sit this
                    # endpoint out of the NEXT race so another
                    # candidate gets its turn (phantom-winner loop
                    # breaker, v1.2.2).
                    self._skip_next_race.add(winner)
                    log.warning("raced endpoint %s failed at hello "
                                "(%s)", winner, exc)
            if not connected:
                # Backoff caps at 5 seconds — no long sleep exists in
                # this system (point 39a).
                await asyncio.sleep(min(reconnect_delay,
                                        RECONNECT_BACKOFF_CAP_SECONDS))
                reconnect_delay = max(reconnect_delay, 0.5)
                continue
            self.connection_state = "connected"
            self._net_fingerprint = network_fingerprint()
            probe = asyncio.create_task(_home_probe())
            heal = asyncio.create_task(self._self_heal_loop())
            watch = asyncio.create_task(_network_watch())
            mesh = asyncio.create_task(_mesh_watch())
            try:
                await self.serve()
            finally:
                probe.cancel()
                heal.cancel()
                watch.cancel()
                mesh.cancel()
                if self._reader is not None:
                    self._reader.cancel()
            log.warning("disconnected from %s; reconnecting (home first)",
                        self.current_endpoint)
            # INSTANT first retry on a drop (points 43b/44): a
            # disconnect races all endpoints again immediately; the
            # capped pacing applies only between FAILED attempts.
            reconnect_delay = 0.0

    async def _self_heal_loop(self) -> None:
        from .timing import SELF_CHECK_SECONDS
        while True:
            await asyncio.sleep(SELF_CHECK_SECONDS)
            try:
                await self.self_check()
            except Exception:
                log.exception("self-check failed")

    # -- requests ------------------------------------------------------------------
    async def _request(self, frame: dict, timeout: float = 15.0) -> dict:
        req_id = new_id()
        frame = {**frame, "req_id": req_id}
        fut = asyncio.get_running_loop().create_future()
        self._pending[req_id] = fut
        await self._send_raw(frame)
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._pending.pop(req_id, None)

    # -- keys -------------------------------------------------------------------------
    async def pubkey_of(self, username: str) -> str:
        u = normalize_username(username) or username
        if u == self.username and self.identity:
            return self.identity.public_key_b64
        if u in self._pubkey_cache:
            return self._pubkey_cache[u]
        data = await self._request({"type": "get_key", "username": u})
        pub = data.get("pubkey") or ""
        if pub:
            self._pubkey_cache[u] = pub
        return pub

    def _encrypt_obj(self, recipient_pub: str, obj: dict) -> dict:
        return self.identity.encrypt_for(
            recipient_pub, json.dumps(obj).encode())

    def _decrypt_obj(self, envelope: dict) -> dict:
        return json.loads(self.identity.decrypt_envelope(envelope))

    # -- owner oversight wraps ------------------------------------------------
    def _oversight_wrap(self, plaintext: bytes, kind: str) -> dict | None:
        """Seal a copy for the owner's oversight key, or None when no
        oversight pubkey is known (client then sends no wrap — a relay
        with AGENTLINK_REQUIRE_OVERSIGHT=1 will reject the send).

        The wrap is the standard encrypt_for envelope plus a ``kind``
        discriminator: ``content`` = the wrapped plaintext is the
        content payload JSON itself; ``content_key`` = the wrapped
        plaintext is the raw symmetric key that decrypts the sibling
        content envelope (group/channel messages, file keys)."""
        pub = self.oversight_pubkey
        if not pub:
            return None
        try:
            env = encrypt_to_pubkey(pub, plaintext)
        except Exception:
            log.exception("oversight wrap failed; sending without it")
            return None
        env["kind"] = kind
        return env

    def _oversight_for_obj(self, obj: dict) -> dict | None:
        return self._oversight_wrap(json.dumps(obj).encode(), "content")

    def _oversight_for_key(self, key: bytes) -> dict | None:
        return self._oversight_wrap(key, "content_key")

    # -- dispatch ------------------------------------------------------------------------
    async def _dispatch(self, frame: dict) -> None:
        ftype = frame.get("type")
        req_id = frame.get("req_id")
        if ftype in ("result", "error") and req_id in self._pending:
            fut = self._pending.pop(req_id)
            if not fut.done():
                if ftype == "result" and frame.get("ok", True):
                    fut.set_result(frame.get("data") or {})
                else:
                    fut.set_exception(RequestFailed(
                        frame.get("reason", "error"), frame.get("detail", "")))
            return
        if ftype == "message":
            # Spawned: processing may fetch group keys / pubkeys, whose
            # results this same read loop must deliver.
            asyncio.create_task(self._process_message(frame))
            return
        if ftype == "read_receipt":
            self.read_receipts.append(frame)
            if self._read_handler is not None:
                asyncio.create_task(self._run_simple_handler(
                    self._read_handler, frame))
            return
        if ftype == "group_key":
            try:
                key = self.identity.unwrap_key(frame["wrapped"])
                self._store_group_key(frame["group_id"],
                                      int(frame["epoch"]), key)
            except Exception:
                log.exception("failed to unwrap group key")
            return
        if ftype == "channel_key":
            try:
                key = self.identity.unwrap_key(frame["wrapped"])
                self._store_channel_key(frame["channel_id"],
                                        int(frame["epoch"]), key)
            except Exception:
                log.exception("failed to unwrap channel key")
            return
        if ftype == "channel_event":
            self.channel_events.append(frame)
            asyncio.create_task(self._maybe_provision_channel_keys(frame))
            return
        if ftype == "room_event":
            self.room_events.append(frame)
            return
        if ftype == "room_signal":
            self.room_signals.append(frame)
            if self._media_sessions or self._media_rooms:
                from . import media as _media_mod
                _media_mod.route_signal(self, frame)
            if self._room_signal_handler is not None:
                asyncio.create_task(self._run_simple_handler(
                    self._room_signal_handler, frame))
            return
        if ftype == "work_progress":
            ev = dict(frame)
            enc = ev.get("content_enc")
            if enc:
                try:
                    ev["note"] = self._decrypt_obj(enc).get("note", "")
                except Exception:
                    ev["note"] = ""
            self.work_progress_events.append(ev)
            return
        if ftype == "group_event":
            self.group_events.append(frame)
            self._apply_membership_event(frame)
            if self._group_handler is not None:
                asyncio.create_task(self._run_simple_handler(
                    self._group_handler, frame))
            asyncio.create_task(self._maybe_provision_keys(frame))
            return
        if ftype == "work_assigned":
            asyncio.create_task(self._process_work(frame.get("work") or {},
                                                   assigned=True))
            return
        if ftype == "work_checkpoint":
            self.checkpoint_events.append(frame)
            return
        if ftype == "deadline_warning":
            self.deadline_warnings.append(frame)
            return
        if ftype == "work_overdue":
            self.overdue_events.append(frame)
            return
        if ftype in ("work_reassigned", "work_reassigned_notice"):
            self.work_updates.append(frame)
            return
        if ftype == "chain_event":
            self.chain_events.append(frame)
            return
        if ftype == "work_update":
            asyncio.create_task(self._process_work(frame.get("work") or {},
                                                   assigned=False))
            return

    def _apply_membership_event(self, frame: dict) -> None:
        gid = frame.get("group_id")
        if not gid:
            return
        members = frame.get("members") or []
        mine = next((m for m in members
                     if m["username"] == self.username), None)
        if mine is None and frame.get("event") in (
                "removed_from_group",):
            self.memberships.pop(gid, None)
            return
        if mine is not None:
            cur = self.memberships.setdefault(gid, {})
            cur.update({"role": mine.get("role"),
                        "nickname": mine.get("nickname", ""),
                        "custom_role": mine.get("custom_role", ""),
                        "name": frame.get("group_name",
                                          cur.get("name", ""))})
        if frame.get("settings"):
            cur = self.memberships.setdefault(gid, {})
            cur["settings"] = frame["settings"]

    async def _resync_memberships(self) -> None:
        """Full role/permission resync from the backend (43e) — also
        heals a lost group-key cache (43d) by re-fetching wrapped keys
        for every group I belong to."""
        try:
            data = await self._request({"type": "my_groups"})
        except Exception:
            return
        for g in data.get("groups", []):
            mine = g.get("my") or {}
            self.memberships[g["group_id"]] = {
                "role": mine.get("role"),
                "nickname": mine.get("nickname", ""),
                "custom_role": mine.get("custom_role", ""),
                "settings": g.get("settings") or {},
                "name": g.get("name", "")}
            if g["group_id"] not in self._group_keys:
                await self._ensure_group_key(g["group_id"])
        for c in data.get("channels", []):
            self.channel_roles[c["channel_id"]] = c.get("my_role", "")
            if c["channel_id"] not in self._channel_keys:
                await self._ensure_channel_key(c["channel_id"])

    async def _record_repair(self, event: str, detail: str = "") -> None:
        rec = {"event": event, "detail": detail,
               "ts": int(__import__("time").time())}
        self.self_repairs.append(rec)
        try:
            path = self.state_dir / "self-repairs.jsonl"
            with path.open("a") as fh:
                fh.write(json.dumps(rec) + "\n")
        except Exception:
            pass
        if self._ws is not None:
            try:
                await self._request({"type": "self_report",
                                     "event": event, "detail": detail})
            except Exception:
                pass

    async def self_check(self) -> dict:
        """Self-healing (point 43d): verify local state; repair what is
        repairable from the backend mirror; report every repair. Runs
        at startup and on the SELF_CHECK cadence inside run(). A clean
        check costs one pass and changes nothing."""
        repairs = []
        for event in self._pending_repairs:
            await self._record_repair(event)
            repairs.append(event)
        self._pending_repairs = []
        # State files: half-written/corrupt JSON caches are rebuilt.
        for name, rebuild in (
                (f"groupkeys-{self.username}.json", "groupkeys"),
                (f"channelkeys-{self.username}.json", "channelkeys"),
                (f"filekeys-{self.username}.json", "filekeys")):
            p = self.state_dir / name
            if p.exists():
                try:
                    json.loads(p.read_text())
                except Exception:
                    p.rename(p.with_suffix(".corrupt"))
                    if rebuild == "groupkeys":
                        self._group_keys = {}
                    elif rebuild == "channelkeys":
                        self._channel_keys = {}
                    await self._record_repair(f"{rebuild}_cache_rebuilt")
                    repairs.append(rebuild)
        if "groupkeys" in repairs or "channelkeys" in repairs:
            await self._resync_memberships()
        # Journal: verify; rebuild from the backend mirror if broken
        # (probe failure now, or a corruption quarantined at boot).
        if self._journal is not None:
            _rebuild = "journal_corrupt_rebuilt" in repairs
            if not _rebuild:
                try:
                    self._journal.get("__probe__")
                except Exception:
                    _rebuild = True
            if _rebuild:
                data = await self._request({"type": "work_inbox",
                                            "status": None,
                                            "group_id": None})
                for raw in data.get("work", []):
                    if raw.get("assignee") != self.username:
                        continue
                    work = self._decrypt_work(raw)
                    self._journal.put(work)
                    if work.get("checkpoint"):
                        self._journal.set_checkpoint(
                            work["id"], work["checkpoint"])
                await self._record_repair("journal_rebuilt_from_mirror")
                repairs.append("journal")
        return {"ok": True, "repairs": repairs}

    async def _maybe_provision_keys(self, event: dict) -> None:
        """If I am an admin of this group and hold its key, wrap it for
        newly added/joined members (e.g. invite-link joins)."""
        if event.get("event") not in ("added_to_group", "joined_group"):
            return
        gid = event.get("group_id")
        rec = self._group_keys.get(gid)
        if rec is None:
            return
        my_role = next((m["role"] for m in event.get("members", [])
                        if m["username"] == self.username), None)
        if my_role not in ("admin", "superadmin"):
            return
        targets = [t for t in event.get("targets") or []
                   if t and t != self.username]
        if not targets:
            return
        try:
            wrapped = {}
            for t in targets:
                pub = await self.pubkey_of(t)
                if pub:
                    wrapped[t] = self.identity.wrap_key(pub, rec["key"])
            if wrapped:
                await self._request({"type": "set_group_keys",
                                     "group_id": gid, "epoch": rec["epoch"],
                                     "wrapped": wrapped})
        except Exception:
            log.exception("group key provisioning failed")

    async def _maybe_provision_channel_keys(self, event: dict) -> None:
        if event.get("event") != "subscribed_to_channel":
            return
        cid = event.get("channel_id")
        rec = self._channel_keys.get(cid)
        if rec is None:
            return
        my_role = next((m["role"] for m in event.get("members", [])
                        if m["username"] == self.username), None)
        if my_role not in ("admin", "superadmin"):
            return
        targets = [t for t in event.get("targets") or []
                   if t and t != self.username]
        if not targets:
            return
        try:
            wrapped = {}
            for t in targets:
                pub = await self.pubkey_of(t)
                if pub:
                    wrapped[t] = self.identity.wrap_key(pub, rec["key"])
            if wrapped:
                await self._request({"type": "set_channel_keys",
                                     "channel_id": cid,
                                     "epoch": rec["epoch"],
                                     "wrapped": wrapped})
        except Exception:
            log.exception("channel key provisioning failed")

    async def _ensure_channel_key(self, cid: str) -> dict | None:
        rec = self._channel_keys.get(cid)
        if rec:
            return rec
        try:
            data = await self._request({"type": "get_channel_key",
                                        "channel_id": cid})
        except Exception:
            return None
        key_rec = data.get("key")
        if not key_rec:
            return None
        try:
            key = self.identity.unwrap_key(key_rec["wrapped"])
        except Exception:
            return None
        self._store_channel_key(cid, int(key_rec["epoch"]), key)
        return self._channel_keys[cid]

    # -- canonical mailbox (v1.3.7) ------------------------------------
    # Delivery completes only when an item is durably journaled in
    # the local mailbox AND acked back to the relay; take-in is a
    # durable fact in the same store, not just a read frame; what
    # was journaled but never taken in replays on start; the relay's
    # history backfills the store. See mailbox.py for the contract.

    async def _send_ack(self, ids) -> None:
        """Tell the relay these ids are durably journaled in my
        mailbox: {"type": "ack", "ids": [...]}. Only on ack does the
        relay delete its queued copy and mark the audit row
        delivered. Best-effort on a dying socket — an unacked item
        simply stays in the relay's custody and is redelivered."""
        ids = [str(i) for i in (ids or []) if i]
        if not ids or self._ws is None:
            return
        try:
            await self._send_raw({"type": "ack", "ids": ids})
        except Exception:
            pass

    def _mailbox_mark_taken(self, message_id) -> None:
        if self.mailbox is not None and message_id:
            try:
                self.mailbox.mark_taken([str(message_id)])
            except Exception:
                log.exception("mailbox mark_taken failed")

    def _local_mailbox(self) -> Mailbox | None:
        """The mailbox for pure-local reads: the live instance when
        there is one, else the state dir's mailbox.db opened read-
        write on demand — inbox()/history() must work with NO
        connection whenever the file exists."""
        if self.mailbox is not None:
            return self.mailbox
        try:
            path = self.state_dir / "mailbox.db"
            if path.exists():
                self.mailbox = Mailbox(path, owner=self.username)
                self._mailbox = self.mailbox
        except Exception:
            return None
        return self.mailbox

    def inbox(self, limit: int = 50, unread_only: bool = False,
              conversation: str | None = None,
              before_ts: int | None = None) -> list[dict]:
        """This agent's local mailbox, newest first — the msg dicts
        exactly as handlers see them. Pure local read: no connection
        needed, only the state dir's mailbox.db. ``conversation`` is
        a peer username (DM), "group:<id>" or "channel:<id>";
        ``unread_only`` keeps only items never taken in."""
        mb = self._local_mailbox()
        if mb is None:
            return []
        return mb.inbox(limit=limit, before_ts=before_ts,
                        conversation=conversation,
                        unread_only=unread_only)

    def history(self, limit: int = 50, unread_only: bool = False,
                conversation: str | None = None,
                before_ts: int | None = None) -> list[dict]:
        """The agent's conversation history — the same canonical
        mailbox inbox() reads (the line backfills it via
        sync_history, live delivery journals into it), under the
        name an agent naturally asks for."""
        return self.inbox(limit=limit, unread_only=unread_only,
                          conversation=conversation,
                          before_ts=before_ts)

    async def _replay_mailbox(self) -> None:
        """Replay journaled-but-not-taken-in items to the
        intelligence, oldest first, through the SAME take-in tail
        live messages use. An item whose take-in fails through the
        decision link stays taken=0 and replays again next start.
        Sealed stubs (history rows that could not be decrypted) are
        journal records, not deliverable content — they stay
        journaled for a future start that holds the key, and are
        upgraded in place if the real item ever arrives live."""
        mb = self.mailbox
        if mb is None:
            return
        for msg in mb.pending_takein():
            mid = msg.get("id")
            if not mid or mid in self._takein_inflight:
                continue
            if msg.get("sealed"):
                continue
            self._takein_inflight.add(str(mid))
            try:
                if not any(m.get("id") == mid for m in self.messages):
                    self.messages.append(msg)
                await self._dispatch_message_tail(msg)
            except Exception:
                log.exception("mailbox replay of %s failed", mid)
                self._takein_inflight.discard(str(mid))

    async def _dispatch_message_tail(self, msg: dict) -> None:
        """The take-in tail of message processing, shared verbatim
        by the live path (_process_message) and the mailbox replay:
        reply waiters, mention/urgent side handlers, then the ONE
        take-in decision — the registered message handler, or the
        autonomous runtime when no handler is registered.

        Take-in marking (mailbox + read receipt) happens at exactly
        the points it always has: handler invocation here, and —
        for the autonomous path — inside _auto_consider_message at
        its existing _queue_read point, so a DecisionLinkError
        (which returns before that point) never marks an item
        taken. The caller owns the _takein_inflight claim for
        ``msg``; the tail releases it unless the autonomous task
        inherits it."""
        mid = msg.get("id")
        waiter = self._reply_waiters.pop(msg["in_reply_to"], None) \
            if msg.get("in_reply_to") else None
        if waiter is not None and not waiter.done():
            waiter.set_result(msg)
        mentions = msg["mentions"]
        if self.username in mentions or \
                ("all" in mentions and msg["group_id"]):
            self.mention_inbox_items.append(msg)
            if self._mention_handler is not None:
                asyncio.create_task(self._run_simple_handler(
                    self._mention_handler, msg))
        if msg["priority"] == "urgent" and self._urgent_handler is not None:
            asyncio.create_task(self._run_simple_handler(
                self._urgent_handler, msg))
        if self._message_handler is not None:
            asyncio.create_task(self._run_message_handler(
                self._message_handler, msg))
            if msg.get("from") != self.username:
                # The message has been taken in by the registered
                # handler: mark it taken in the durable mailbox at
                # the same point the read receipt has always been
                # queued — the receipt is now backed by the journal.
                self._mailbox_mark_taken(mid)
                if self.auto_read:
                    self._queue_read(mid)
            if mid:
                self._takein_inflight.discard(str(mid))
        elif self._autonomous_on():
            # Autonomous runtime (v1.1.7): no owner-registered message
            # handler, so the unattended loop considers the message.
            # Manual mode never reaches here, and a registered
            # on_message handler always takes precedence — the
            # agent's own code receiving its events IS its decision
            # link for this surface. The take-in claim rides the
            # consideration task: it is released only when the
            # consideration ends (taken marked inside, at the
            # decision-backed read point).
            asyncio.create_task(self._auto_consider_claimed(msg))
        else:
            # No handler, not autonomous: nothing took the item in.
            # It stays journaled taken=0 and replays on a later
            # start that does have a taker.
            if mid:
                self._takein_inflight.discard(str(mid))

    async def _auto_consider_claimed(self, msg: dict) -> None:
        try:
            await self._auto_consider_message(msg)
        finally:
            if msg.get("id"):
                self._takein_inflight.discard(str(msg["id"]))

    # -- history sync (v1.3.7): the line backfills the mailbox --------
    async def sync_history(self) -> dict:
        """Page the relay's history for everything the line holds
        for me (audit content rows, newest page first, walking
        backwards by seq) and journal it into the local mailbox.
        Rows I sent enter taken=1; rows addressed to me enter
        taken=0 and replay into the intelligence. A row whose
        envelope cannot be opened here is journaled as a sealed
        stub — a row is never dropped silently. Returns
        {"fetched", "inserted", "pages"} (plus "error" when the
        relay could not be asked — the sync is resumable by simply
        calling it again, and start() calls it on every connect)."""
        out = {"fetched": 0, "inserted": 0, "pages": 0}
        mb = self.mailbox
        if mb is None or self._ws is None:
            return out
        from . import timing as _timing
        page_size = int(getattr(_timing, "DELIVERY_HISTORY_PAGE", 200)
                        or 200)
        before: int | None = None
        smallest: int | None = None
        while True:
            frame: dict = {"type": "history", "limit": page_size}
            if before is not None:
                frame["before_seq"] = before
            try:
                data = await self._request(frame, timeout=30)
            except Exception as exc:
                log.warning("history sync stopped: %s", exc)
                out["error"] = str(exc)
                return out
            rows = data.get("rows") or []
            out["pages"] += 1
            out["fetched"] += len(rows)
            for row in rows:
                seq = row.get("seq")
                if isinstance(seq, (int, float)):
                    smallest = int(seq) if smallest is None else min(
                        smallest, int(seq))
                msg = self._history_row_to_msg(row)
                if msg is None or not msg.get("id"):
                    continue
                if mb.put_if_absent(msg):
                    out["inserted"] += 1
            if len(rows) < page_size or smallest is None:
                break  # short page = the beginning of history
            if before is not None and smallest >= before:
                break  # no progress — never spin
            before = smallest
        return out

    def _history_row_to_msg(self, row: dict) -> dict | None:
        """Convert one relay history (audit) row into the msg dict
        handlers see, opening its content envelope with the same
        keys the live path uses: the identity for DMs, the stored
        group/channel key for group/channel rows. Any failure — no
        envelope persisted, no key held, undecryptable — yields a
        sealed stub carrying the row's metadata, never silence."""
        kind = str(row.get("kind") or "")
        ref = row.get("ref_id") or row.get("work_id") or ""
        if not ref:
            return None
        group_id = row.get("group_id") or None
        channel_id = row.get("channel_id") or None
        if kind == "channel_message":
            # Channel audit rows carry the channel id in group_id
            # (the store's shape) unless the row spells it out.
            channel_id = channel_id or group_id
            group_id = None
        elif kind != "group_message":
            group_id = None
        sender = row.get("from")
        target = row.get("to")
        if channel_id:
            to = channel_id
        elif group_id:
            to = group_id
        else:
            to = target or self.username
        msg = {
            "id": ref,
            "from": sender,
            "from_name": row.get("from_name") or sender,
            "sender_nickname": row.get("sender_nickname") or "",
            "sender_role": row.get("sender_role") or "",
            "sender_custom_role": row.get("sender_custom_role") or "",
            "to": to,
            "group_id": group_id,
            "group_name": row.get("group_name"),
            "channel_id": channel_id,
            "channel_name": row.get("channel_name"),
            "priority": row.get("priority") or "normal",
            "ts": row.get("ts"),
            "time": row.get("ts"),
            "kind": "text",
            "body": "",
            "meta": {},
            "file": None,
            "size": row.get("size") or 0,
            "mentions": row.get("mentions") or [],
            "in_reply_to": row.get("in_reply_to"),
            "delivery_status": "history",
            "queued": False,
            "encrypted": True,
        }
        if kind.startswith("work"):
            # Work rows are history records in the mailbox, never
            # message replays (pending_takein excludes kind "work";
            # the TaskJournal remains the work system of record).
            msg["kind"] = "work"
            msg["work_id"] = row.get("work_id") or ref
            msg["sealed"] = True
            return msg
        envelope = None
        for key in ("content", "content_envelope", "content_enc",
                    "envelope"):
            val = row.get(key)
            if isinstance(val, dict) and val.get("ct"):
                envelope = val
                break
        payload = None
        if envelope is not None and self.identity is not None:
            try:
                if channel_id:
                    rec = self._channel_keys.get(channel_id)
                    if rec:
                        payload = json.loads(decrypt_with_key(
                            rec["key"], envelope))
                elif group_id:
                    rec = self._group_keys.get(group_id)
                    if rec:
                        payload = json.loads(decrypt_with_key(
                            rec["key"], envelope))
                else:
                    payload = self._decrypt_obj(envelope)
            except Exception:
                payload = None
        if payload is None:
            msg["sealed"] = True
            return msg
        msg["body"] = payload.get("body", "")
        msg["kind"] = payload.get("kind") or \
            (payload.get("file") or {}).get("kind") or "text"
        msg["meta"] = payload.get("meta") or {}
        msg["file"] = payload.get("file")
        msg["size"] = (payload.get("file") or {}).get(
            "size", len(msg["body"]))
        return msg

    # -- messages ---------------------------------------------------------------------------
    async def _ensure_group_key(self, gid: str) -> dict | None:
        rec = self._group_keys.get(gid)
        if rec:
            return rec
        try:
            data = await self._request({"type": "get_group_key",
                                        "group_id": gid})
        except Exception:
            return None
        key_rec = data.get("key")
        if not key_rec:
            return None
        try:
            key = self.identity.unwrap_key(key_rec["wrapped"])
        except Exception:
            return None
        self._store_group_key(gid, int(key_rec["epoch"]), key)
        return self._group_keys[gid]

    async def _process_message(self, frame: dict) -> None:
        try:
            if frame.get("channel_id"):
                rec = await self._ensure_channel_key(frame["channel_id"])
                if rec is None:
                    log.warning("no channel key for %s; cannot decrypt",
                                frame["channel_id"])
                    return
                payload = json.loads(decrypt_with_key(
                    rec["key"], frame["content"]))
                to = frame["channel_id"]
            elif frame.get("group_id"):
                rec = await self._ensure_group_key(frame["group_id"])
                if rec is None:
                    log.warning("no group key for %s; cannot decrypt",
                                frame["group_id"])
                    return
                payload = json.loads(decrypt_with_key(
                    rec["key"], frame["content"]))
                to = frame["group_id"]
            else:
                payload = self._decrypt_obj(frame["content"])
                to = self.username
        except Exception:
            log.exception("failed to decrypt message %s", frame.get("id"))
            return
        if frame.get("from_pubkey"):
            self._pubkey_cache[frame["from"]] = frame["from_pubkey"]
        file_payload = payload.get("file")
        if file_payload and file_payload.get("blob_id"):
            try:
                file_payload = await self._resolve_blob_file(
                    file_payload, frame)
            except Exception:
                log.exception("failed to fetch/decrypt blob file")
                return
            payload["file"] = file_payload
        if file_payload and not verify_file(file_payload):
            log.warning("dropping message %s: file hash mismatch",
                        frame.get("id"))
            return
        body = payload.get("body", "")
        msg = {
            "id": frame.get("id"),
            "from": frame.get("from"),
            "from_name": frame.get("from_name"),
            "sender_nickname": frame.get("sender_nickname") or "",
            "sender_role": frame.get("sender_role") or "",
            "sender_custom_role": frame.get("sender_custom_role") or "",
            "to": to,
            "group_id": frame.get("group_id"),
            "group_name": frame.get("group_name"),
            "channel_id": frame.get("channel_id"),
            "channel_name": frame.get("channel_name"),
            "priority": frame.get("priority") or "normal",
            "ts": frame.get("ts"),
            "time": frame.get("ts"),
            "kind": payload.get("kind") or
            (file_payload or {}).get("kind") or "text",
            "body": body,
            "meta": payload.get("meta") or {},
            "file": file_payload,
            "size": (file_payload or {}).get("size", len(body)),
            "mentions": frame.get("mentions") or [],
            "in_reply_to": frame.get("in_reply_to"),
            "delivery_status": "queued" if frame.get("queued") else "live",
            "queued": bool(frame.get("queued")),
            "encrypted": True,
        }
        # CANONICAL MAILBOX (v1.3.7): journal BEFORE processing,
        # ack only once the item is durable, and never reprocess a
        # duplicate. The claim is taken synchronously — before the
        # ack's await can yield — so a start-of-session replay
        # racing this live delivery can never dispatch it twice.
        mid = msg.get("id")
        if mid and self.mailbox is not None:
            if self.mailbox.put_if_absent(msg):
                self._takein_inflight.add(str(mid))
                await self._send_ack([mid])
            else:
                existing = self.mailbox.get(str(mid))
                if existing and existing.get("sealed") \
                        and not msg.get("sealed") \
                        and not self.mailbox.taken_of(str(mid)):
                    # A sealed history stub stood in for this item;
                    # the real content has now arrived live and was
                    # never taken in — upgrade the journal in place
                    # and process the real item.
                    self.mailbox.replace_msg(msg)
                    self._takein_inflight.add(str(mid))
                    await self._send_ack([mid])
                else:
                    # Duplicate delivery: already journaled. Re-ack
                    # (the first ack may have been lost with the
                    # socket that carried it) and stop — never
                    # reprocess, never list twice.
                    await self._send_ack([mid])
                    return
        elif mid:
            self._takein_inflight.add(str(mid))
        self.messages.append(msg)
        await self._dispatch_message_tail(msg)

    async def _run_message_handler(self, handler, msg: dict) -> None:
        # The handler invocation + the reply send are ONE critical
        # operation for update continuity: a self-update never
        # re-execs between a handler finishing and its reply landing.
        async with self._critical_op("message-reply"):
            await self._run_message_handler_inner(handler, msg)

    async def _run_message_handler_inner(self, handler,
                                         msg: dict) -> None:
        try:
            result = handler(msg)
            if inspect.isawaitable(result):
                result = await result
        except Exception:
            log.exception("on_message handler failed")
            return
        if result:
            try:
                if msg.get("group_id"):
                    await self.group_send(msg["group_id"], str(result),
                                          in_reply_to=msg.get("id"))
                else:
                    await self.send_message(msg["from"], str(result),
                                            in_reply_to=msg.get("id"))
            except Exception:
                log.exception("sending handler reply failed")

    async def _run_simple_handler(self, handler, arg) -> None:
        try:
            r = handler(arg)
            if inspect.isawaitable(r):
                await r
        except Exception:
            log.exception("handler failed")

    # -- autonomous runtime (v1.1.7, platform autonomy law) -----------
    # The runtime is a LOOP, not an intelligence: receive -> consult
    # the agent's own decision-making through its DECISION LINK ->
    # act. It contains no reply text of its own and never speaks
    # for the agent — the agent is the intelligence; the link only
    # carries events to it and its answers back. Owner approval
    # plays no part anywhere in it — the only permission layer is
    # the assigner-side approval gate, applied by the relay exactly
    # as before. Loop safety: autonomous sends are marked
    # (meta.autonomous) inside the E2E envelope; per conversation
    # the loop enforces a consecutive-reply cap and an hourly
    # budget from timing.py, both tightened when the triggering
    # message is itself marked autonomous, plus a pacing delay
    # before every reply. A cap trip ends the exchange quietly and
    # is logged.

    def _autonomous_on(self) -> bool:
        """The runtime fires only for a real platform citizen in
        autonomous mode. Ephemeral tooling agents (one-shot sends,
        diagnostics) are never unattended actors."""
        return self.mode == "autonomous" and not self.ephemeral

    def _auto_log(self, event: str, conversation: str = "",
                  **fields) -> None:
        entry = {"event": event, "conversation": conversation,
                 "ts": int(time.time())}
        entry.update(fields)
        self.autonomous_log.append(entry)
        log.info("autonomous[%s] %s %s", self.username, event,
                 conversation)

    def _decision_wired(self) -> bool:
        """Is the agent's decision link wired for the autonomous
        runtime? Any of: an in-process decision callable, an
        out-call decision endpoint, or the agent's own registered
        message/work handlers (its own code receiving events IS a
        link). Nothing wired = the link is PENDING — a fact about
        this CONNECTION, never about the agent, whose capability
        and memory are its own regardless."""
        return self._decision_callable is not None \
            or self.decision_endpoint is not None \
            or self._message_handler is not None \
            or self._work_handler is not None

    @property
    def decision_linked(self) -> bool:
        """Public: True when the decision link is wired (see
        _decision_wired). Meaningful in autonomous mode."""
        return self._decision_wired()

    def _decision_declaration(self) -> str:
        """What the hello declares to the relay (v1.3.5), so the
        dashboard and the directory can state the fact instead of
        leaving silence unexplained: "linked" / "pending" for an
        autonomous agent; "" when the question does not apply
        (manual mode — the agent is directed by its operator — or
        an ephemeral tooling connection)."""
        if not self._autonomous_on():
            return ""
        return "linked" if self._decision_wired() else "pending"

    def _refresh_link_declaration(self) -> None:
        """Re-declare the decision link when its state changes
        AFTER the hello (v1.3.5 fix): an agent that wires its link
        in its own time — handlers registered after connect — must
        not leave every surface repeating the hello-time snapshot
        of a living state (the baseline suite showed a stale
        "pending" stranding real agents' work and mislabelling
        wired agents). Best-effort by design: if there is no live
        connection or no running loop yet, the next hello carries
        the current value, which is the same truth one step later."""
        if not self._autonomous_on():
            return
        current = self._decision_declaration()
        if current == self._declared_link_sent or self._ws is None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._declared_link_sent = current
        loop.create_task(self._send_link_update(current))

    async def _send_link_update(self, value: str) -> None:
        try:
            await self._send_raw({"type": "decision_link_update",
                                  "decision_link": value})
        except Exception:
            pass

    def _warn_if_unlinked(self) -> None:
        """Autonomous mode with the decision link NOT wired (no
        decision callable, no decision endpoint, no handlers): the
        connection will hold the line — it will not reply to
        messages and will not execute work, because answering or
        accepting on the agent's behalf without its own decision
        would be fabrication. Say so LOUDLY at startup: silence by
        surprise would be a lie about the agent's presence; the
        held line, declared, is the truth."""
        if not self._autonomous_on() or self._auto_warned_unlinked:
            return
        if self._decision_wired():
            return
        self._auto_warned_unlinked = True
        log.warning(
            "DECISION LINK PENDING: @%s is in autonomous mode, and "
            "this line connection is not yet linked to the agent's "
            "decision-making — the agent itself is the intelligence; "
            "until its operator links it (Agent(..., "
            "decision_link=<the agent's own decision callable>), an "
            "out-call decision endpoint (--decision-endpoint / "
            "AGENTLINK_DECISION_ENDPOINT), or its own handlers), "
            "this connection holds the line: messages and work queue "
            "safely and are NOT answered or accepted on the agent's "
            "behalf.", self.username)
        self._auto_log("decision_link_pending_warning")

    # Pre-1.3.5 name, kept as an alias so nothing that calls it
    # breaks; the warning it emits is the truthful one above.
    _warn_if_brainless = _warn_if_unlinked

    def _agent_profile(self) -> dict:
        return {"username": self.username,
                "display_name": self.display_name,
                "mode": self.mode,
                "capabilities": list(self.capabilities),
                "cap_description": self.cap_description}

    async def _call_decision(self, ctx: dict):
        """Consult the agent's own decision-making through its
        decision link and return its answer verbatim: a reply
        string, a result dict (work), or None (the agent chose
        silence). An in-process callable is invoked directly; with
        an out-call decision endpoint, the event is POSTed to the
        agent product's own local endpoint and its reply is used
        the same way. A link FAILURE (endpoint unreachable, timed
        out, unusable answer) raises DecisionLinkError — the event
        was never decided, and callers hold it; a failure is never
        dressed up as the agent's silence."""
        fn = self._decision_callable
        if fn is not None:
            result = fn(ctx)
            if inspect.isawaitable(result):
                result = await result
            return result
        if self.decision_endpoint is not None:
            return await self._call_decision_endpoint(ctx)
        return None

    # Pre-1.3.5 name, kept as an alias (see _warn_if_brainless).
    _call_brain = _call_decision

    async def _call_decision_endpoint(self, ctx: dict):
        """The out-call decision link (v1.3.5): POST the event, as
        JSON, to the agent product's own local decision endpoint
        and act on its reply. The endpoint speaks the decision
        callable's language over HTTP — its reply body is the same
        value a callable would return, JSON-encoded: a string (a
        message reply / a work body), an object ({"body", "files",
        "decline", ...}), or null (the agent chose silence). For
        work, the reply may also carry "progress": [{"percent": n,
        "note": str}] entries, which this client reports through
        the normal progress path before acting on the result —
        progress is one ctx member that cannot cross HTTP as a
        callable, so it travels as data instead; the vault_get
        accessor is the other (the JSON-safe vault SUMMARY crosses;
        an endpoint-flavour agent opens the same state-dir vault
        through the SDK's CredentialsVault class directly).
        Config-only for the agent product: expose the endpoint; no
        SDK code changes are needed on its side."""
        payload = {k: v for k, v in ctx.items()
                   if k not in ("report_progress", "vault_get")}
        url = self.decision_endpoint
        timeout = DECISION_LINK_TIMEOUT_SECONDS

        def _post() -> tuple[int, bytes]:
            import urllib.error
            import urllib.request
            req = urllib.request.Request(
                url, data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"},
                method="POST")
            try:
                with urllib.request.urlopen(req,
                                            timeout=timeout) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read() or b""

        try:
            status, raw = await asyncio.to_thread(_post)
        except Exception as exc:  # noqa: BLE001 - any transport failure
            raise DecisionLinkError(
                f"decision endpoint {url} unreachable: {exc}") from exc
        if status == 204 or (status == 200 and not raw.strip()):
            return None  # the agent chose silence
        if status != 200:
            raise DecisionLinkError(
                f"decision endpoint {url} answered HTTP {status}")
        try:
            result = json.loads(raw.decode("utf-8"))
        except Exception:
            # A non-JSON body is the agent's own plain words: a
            # reply for a message, a delivery body for work.
            text = raw.decode("utf-8", "replace").strip()
            return text or None
        if isinstance(result, dict) and ctx.get("kind") == "work":
            progress = result.pop("progress", None)
            report = ctx.get("report_progress")
            if report is not None and isinstance(progress, list):
                for entry in progress:
                    if isinstance(entry, dict) \
                            and entry.get("percent") is not None:
                        # JSON numbers arrive as int or float
                        # depending on the agent's encoder;
                        # report_progress's contract is int percent
                        # — the adapter coerces, the range check
                        # inside still rejects out-of-range values.
                        await report(int(float(entry["percent"])),
                                     str(entry.get("note") or ""))
        return result

    @staticmethod
    def _conv_key(msg: dict) -> tuple[str, str]:
        """(conversation key, conversation kind) for a received
        message — the granularity every loop cap is enforced at."""
        if msg.get("group_id"):
            return f"group:{msg['group_id']}", "group"
        if msg.get("channel_id"):
            return f"channel:{msg['channel_id']}", "channel"
        return f"dm:{msg.get('from')}", "dm"

    async def _auto_consider_message(self, msg: dict) -> None:
        # Decision call through reply send = one critical operation
        # (update continuity): the swap waits for it to complete.
        async with self._critical_op("autonomous-message"):
            await self._auto_consider_message_inner(msg)

    async def _auto_consider_message_inner(self, msg: dict) -> None:
        conv = ""
        try:
            sender = msg.get("from")
            if not sender or sender == self.username:
                return  # never reply to our own messages
            conv, kind = self._conv_key(msg)
            if kind in ("group", "channel"):
                mentions = msg.get("mentions") or []
                if self.username not in mentions and \
                        "all" not in mentions:
                    return  # groups/channels: mentions only
            peer_auto = bool((msg.get("meta") or {}).get("autonomous"))
            if not peer_auto:
                # A fresh non-autonomous message re-opens the floor:
                # the consecutive cap measures an UNINTERRUPTED run
                # of autonomous replies.
                self._auto_consec[conv] = 0
            if self._decision_callable is None \
                    and self.decision_endpoint is None:
                # The link is not wired: the line holds. The event
                # is neither answered nor marked read — it waits,
                # exactly as the startup warning declared.
                self._auto_log("decision_link_pending_silent", conv,
                               sender=sender)
                return
            cap = AUTO_MAX_CONSECUTIVE_AUTO if peer_auto \
                else AUTO_MAX_CONSECUTIVE_REPLIES
            if self._auto_consec.get(conv, 0) >= cap:
                self._auto_log("capped_consecutive", conv,
                               sender=sender, cap=cap)
                return
            now = time.time()
            window = [t for t in self._auto_sent.get(conv, [])
                      if now - t < 3600.0]
            self._auto_sent[conv] = window
            budget = AUTO_HOURLY_BUDGET_AUTO if peer_auto \
                else AUTO_HOURLY_BUDGET
            if len(window) >= budget:
                self._auto_log("capped_budget", conv, sender=sender,
                               budget=budget)
                return
            await asyncio.sleep(
                AUTO_REPLY_DELAY_AUTO_SECONDS if peer_auto
                else AUTO_REPLY_DELAY_SECONDS)
            recent = [m for m in self.messages
                      if self._conv_key(m)[0] == conv][-8:]
            ctx = {
                "kind": "message",
                "agent": self._agent_profile(),
                "message": msg,
                "sender": {"username": sender,
                           "display_name": msg.get("from_name")},
                "conversation": {"type": kind, "key": conv},
                "recent": recent,
                # Credentials vault (v1.4.0): the agent's own
                # decision-making can fetch its login for a service
                # mid-task via ctx["vault_get"](service) — its own
                # vault, its own key, no permission step.
                **self._vault_ctx_fields(),
            }
            try:
                reply = await self._call_decision(ctx)
            except DecisionLinkError as exc:
                # The LINK failed — the agent never decided. The
                # message stays unanswered and unread (held), and
                # the failure is logged as what it is: a
                # connection-side fact, not the agent's silence.
                log.warning("decision link failed on a message "
                            "from @%s: %s", sender, exc)
                self._auto_log("decision_link_error", conv,
                               sender=sender)
                return
            except Exception:
                log.exception("decision callable failed on a message")
                self._auto_log("decision_error", conv, sender=sender)
                return
            if reply is None:
                # The agent's own decision-making chose silence;
                # that ends the exchange.
                self._auto_log("decision_silent", conv, sender=sender)
                return
            text = str(reply)
            # The agent genuinely took this message in, through its
            # decision link: mark it taken in the durable mailbox at
            # the same point the read receipt has always fired.
            # Every earlier exit — decision-link pending, loop caps,
            # the agent's chosen silence, and above all a
            # DecisionLinkError (the link failed; the agent never
            # decided) — returns BEFORE this point, so none of them
            # ever marks the item taken or read.
            self._mailbox_mark_taken(msg.get("id"))
            if self.auto_read:
                self._queue_read(msg.get("id"))
            if kind == "dm":
                await self.send_message(
                    sender, text, in_reply_to=msg.get("id"),
                    meta={"autonomous": True})
            elif kind == "group":
                await self.group_send(
                    msg["group_id"], text, in_reply_to=msg.get("id"),
                    meta={"autonomous": True})
            else:
                await self.channel_send(
                    msg["channel_id"], text,
                    meta={"autonomous": True})
            self._auto_consec[conv] = self._auto_consec.get(conv, 0) + 1
            self._auto_sent.setdefault(conv, []).append(time.time())
            self._auto_log("reply", conv, sender=sender)
        except Exception:
            log.exception("autonomous message handling failed")
            self._auto_log("error", conv)

    async def _run_autonomous_work(self, work: dict) -> None:
        # Decision consideration through delivery/decline = one
        # critical operation (update continuity).
        async with self._critical_op("autonomous-work"):
            await self._run_autonomous_work_inner(work)

    async def _run_autonomous_work_inner(self, work: dict) -> None:
        """The autonomous work path: an assignment is considered by
        the agent's own decision-making, through its decision link,
        which may deliver, decline, or stay silent — the runtime
        does none of those on its own authority. A decline is the
        agent's own words, sent verbatim to the assigner; the work
        itself is left untouched for the assigner (never
        fake-delivered, never silently completed)."""
        conv = (f"group:{work['group_id']}" if work.get("group_id")
                else f"dm:{work.get('assigner')}")
        if work.get("status") not in ("assigned", "in_progress",
                                      "changes_requested"):
            return
        if self._decision_callable is None \
                and self.decision_endpoint is None:
            log.warning(
                "autonomous @%s received work %s but its decision "
                "link is not wired — leaving it untouched (no "
                "fabricated delivery, nothing accepted on the "
                "agent's behalf); it stays assigned for its "
                "assigner.", self.username, work.get("id"))
            self._auto_log("work_decision_link_pending", conv,
                           work_id=work.get("id"))
            return

        async def _progress(percent: float, note: str = "") -> None:
            await self.report_progress(work["id"], percent, note)

        ctx = {"kind": "work", "agent": self._agent_profile(),
               "work": work, "report_progress": _progress,
               # Credentials vault (v1.4.0): as on the message path,
               # the agent's decision-making gets its own vault —
               # ctx["vault_get"](service) returns the full entry
               # (password included) or None; no permission step.
               **self._vault_ctx_fields()}
        try:
            result = await self._call_decision(ctx)
        except DecisionLinkError as exc:
            # The LINK failed — the agent never decided. The work
            # stays exactly where it was: unaccepted, undelivered.
            log.warning("decision link failed on work %s: %s",
                        work.get("id"), exc)
            self._auto_log("work_decision_link_error", conv,
                           work_id=work.get("id"))
            return
        except Exception:
            log.exception("decision callable failed on work %s",
                          work.get("id"))
            self._auto_log("work_decision_error", conv,
                           work_id=work.get("id"))
            return
        if result is None:
            self._auto_log("work_decision_silent", conv,
                           work_id=work.get("id"))
            return
        if isinstance(result, str):
            result = {"body": result}
        if not isinstance(result, dict):
            self._auto_log("work_decision_bad_result", conv,
                           work_id=work.get("id"))
            return
        decline = result.get("decline")
        if decline:
            # The agent's own words, verbatim. Honest refusal beats
            # a fabricated delivery — always (fail-closed).
            try:
                await self.send_message(
                    work["assigner"], str(decline),
                    meta={"autonomous": True})
            except Exception:
                log.exception("sending work decline failed")
            self._auto_log("work_declined", conv,
                           work_id=work.get("id"))
            return
        body = str(result.get("body") or "")
        files = [str(p) for p in (result.get("files") or [])]
        await self.deliver_work(work["id"], body,
                                files=files or None)
        self._auto_log("work_delivered", conv, work_id=work.get("id"))

    async def _resolve_blob_file(self, descriptor: dict,
                                 frame: dict) -> dict:
        """Fetch a sealed blob through the relay and decrypt it.

        Scheme (see _make_blob_descriptor): the blob bytes are the raw
        ChaCha20-Poly1305 ciphertext of the file under a random file
        key; the nonce rides in the descriptor; the file key is wrapped
        to the recipient (1:1) or under the group key (groups). The
        relay only ever proxies ciphertext.
        """
        import base64 as _b64
        # Bulk-fetch patience (v1.1 Phase-1 live fix): a blob fetch is
        # a store lookup + an object-store read on the relay, proxied
        # through whatever egress window the fleet is in; the 15s
        # control-request default starved real fetches in bad windows
        # (the file existed, the relay answered, too late). Bounded
        # at 120s — a fetch that cannot land in two minutes is a
        # failure the caller hears about, never a silent hang.
        # Bounded retries ride out short bad windows (an error frame
        # or a dropped socket fails one attempt, not the file).
        data = None
        last_exc: Exception | None = None
        for _attempt in range(3):
            try:
                data = await self._request(
                    {"type": "blob_get",
                     "blob_id": descriptor["blob_id"]}, timeout=120)
                break
            except Exception as exc:  # noqa: BLE001 - retried below
                last_exc = exc
                if isinstance(exc, ConnectionError):
                    # Socket is down/reconnecting: wait for the line
                    # to come back rather than burning attempts.
                    for _ in range(120):
                        if self.connection_state == "connected":
                            break
                        await asyncio.sleep(0.5)
                else:
                    await asyncio.sleep(2)
        if data is None:
            raise last_exc if last_exc is not None else \
                RuntimeError("blob fetch failed")
        ct_b64 = data["data_b64"]
        if descriptor.get("wrapped_key"):
            key = self.identity.decrypt_envelope(descriptor["wrapped_key"])
        elif frame.get("channel_id"):
            rec = await self._ensure_channel_key(frame["channel_id"])
            key = decrypt_with_key(rec["key"],
                                   descriptor["group_wrapped_key"])
        else:
            rec = await self._ensure_group_key(frame.get("group_id"))
            key = decrypt_with_key(rec["key"],
                                   descriptor["group_wrapped_key"])
        raw = decrypt_with_key(key, {"nonce": descriptor["blob_nonce"],
                                     "ct": ct_b64})
        return {"name": descriptor["name"], "kind": descriptor["kind"],
                "mime": descriptor["mime"], "size": len(raw),
                "sha256": descriptor["sha256"],
                "folder": bool(descriptor.get("folder")),
                "data_b64": _b64.b64encode(raw).decode()}

    # -- resumable chunked uploads + dedup (point 24) -------------------------
    def _filekey_path(self) -> Path:
        return self.state_dir / f"filekeys-{self.username}.json"

    def _load_filekey(self, whole_sha: str) -> dict | None:
        try:
            return json.loads(self._filekey_path().read_text()).get(whole_sha)
        except Exception:
            return None

    def _save_filekey(self, whole_sha: str, key: bytes,
                      nonce_b64: str) -> None:
        path = self._filekey_path()
        try:
            data = json.loads(path.read_text()) if path.exists() else {}
        except Exception:
            data = {}
        data[whole_sha] = {"key": base64.b64encode(key).decode(),
                           "nonce": nonce_b64}
        path.write_text(json.dumps(data))
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass

    async def upload_blob(self, data: bytes, *, for_user: str | None = None,
                          for_group: str | None = None,
                          for_channel: str | None = None,
                          whole_sha: str = "",
                          chunk_size: int = 1024 * 1024,
                          session_id: str | None = None,
                          interrupt_after: int | None = None) -> str:
        """Chunked, resumable upload of ciphertext through the relay
        proxy path only. Per-chunk SHA256 + whole-ciphertext SHA256.
        On resume, only missing chunks are sent. Dedup: a completed
        blob with the same whole-file hash from this sender to this
        scope returns instantly by reference."""
        import hashlib as _hl
        ct_sha = _hl.sha256(data).hexdigest()
        if session_id is None:
            resp = await self._request({
                "type": "blob_session_start", "whole_sha": whole_sha,
                "ct_sha": ct_sha, "size": len(data),
                "chunk_size": chunk_size, "for_user": for_user,
                "for_group": for_group, "for_channel": for_channel})
            if resp.get("dedup"):
                return resp["blob_id"]
            session_id = resp["session_id"]
            chunk_size = resp["chunk_size"]
        status = await self._request({"type": "blob_session_status",
                                      "session_id": session_id})
        sent = 0
        for index in status["missing"]:
            chunk = data[index * chunk_size:(index + 1) * chunk_size]
            # One chunk in transit is a critical operation; BETWEEN
            # chunks is a safe point — the session lives server-side
            # and a restarted uploader sends only the missing chunks.
            async with self._critical_op("blob-chunk"):
                await self._request({
                    "type": "blob_chunk", "session_id": session_id,
                    "index": index,
                    "chunk_sha": _hl.sha256(chunk).hexdigest(),
                    "data_b64": base64.b64encode(chunk).decode()})
            sent += 1
            if interrupt_after is not None and sent >= interrupt_after:
                raise ConnectionError(
                    "simulated drop mid-upload (session kept server-side)")
        resp = await self._request({
            "type": "blob_session_finish", "session_id": session_id,
            "for_user": for_user, "for_group": for_group,
            "for_channel": for_channel})
        return resp["blob_id"]

    async def start_upload_session(self, data: bytes, *,
                                   for_user: str | None = None,
                                   for_group: str | None = None,
                                   for_channel: str | None = None,
                                   whole_sha: str = "",
                                   chunk_size: int = 1024 * 1024):
        """Returns (session_id, chunk_size) — or the string 'dedup:<id>'
        when the relay already holds this exact file for this scope."""
        import hashlib as _hl
        resp = await self._request({
            "type": "blob_session_start", "whole_sha": whole_sha,
            "ct_sha": _hl.sha256(data).hexdigest(), "size": len(data),
            "chunk_size": chunk_size, "for_user": for_user,
            "for_group": for_group, "for_channel": for_channel})
        if resp.get("dedup"):
            return ("dedup:" + resp["blob_id"], resp.get("chunk_size",
                                                         chunk_size))
        return (resp["session_id"], resp["chunk_size"])

    async def _make_blob_descriptor(self, path: str, kind: str | None,
                                    for_user: str | None = None,
                                    group_id: str | None = None,
                                    channel_id: str | None = None,
                                    raw_override: bytes | None = None,
                                    name_override: str | None = None,
                                    folder: bool = False) -> dict:
        import hashlib
        import secrets as _secrets
        from .protocol import infer_kind
        p = Path(path)
        raw = raw_override if raw_override is not None else p.read_bytes()
        whole_sha = hashlib.sha256(raw).hexdigest()
        # Dedup: reuse the persisted file key + nonce for identical
        # content so the ciphertext (and blob) is identical too.
        stored = self._load_filekey(whole_sha)
        if stored:
            file_key = base64.b64decode(stored["key"])
            nonce = base64.b64decode(stored["nonce"])
            enc = encrypt_with_key(file_key, raw, nonce=nonce)
        else:
            file_key = _secrets.token_bytes(32)
            enc = encrypt_with_key(file_key, raw)
            self._save_filekey(whole_sha, file_key, enc["nonce"])
        ct_bytes = base64.b64decode(enc["ct"])
        if len(ct_bytes) > self.blob_chunk_threshold:
            blob_id = await self.upload_blob(
                ct_bytes, for_user=for_user, for_group=group_id,
                for_channel=channel_id, whole_sha=whole_sha)
        else:
            frame = {"type": "blob_put",
                     "data_b64": base64.b64encode(ct_bytes).decode(),
                     "whole_sha": whole_sha}
            if group_id:
                frame["for_group"] = group_id
            elif channel_id:
                frame["for_channel"] = channel_id
            else:
                frame["for_user"] = for_user
            put = await self._request(frame)
            blob_id = put["blob_id"]
        import mimetypes as _mt
        descriptor = {
            "name": name_override or p.name,
            "kind": infer_kind(p, kind), "folder": folder,
            "mime": _mt.guess_type(str(p))[0] or "application/octet-stream",
            "size": len(raw), "sha256": whole_sha,
            "blob_id": blob_id, "blob_nonce": enc["nonce"],
        }
        if group_id:
            rec = await self._ensure_group_key(group_id)
            descriptor["group_wrapped_key"] = encrypt_with_key(
                rec["key"], file_key)
        elif channel_id:
            rec = await self._ensure_channel_key(channel_id)
            descriptor["group_wrapped_key"] = encrypt_with_key(
                rec["key"], file_key)
        else:
            pub = await self.pubkey_of(for_user)
            descriptor["wrapped_key"] = self.identity.encrypt_for(
                pub, file_key)
        # Owner oversight: the file key, wrapped to the oversight key,
        # so the dashboard can render the media. Rides inside the
        # (already encrypted) message payload next to the other wraps.
        ov = self._oversight_for_key(file_key)
        if ov:
            descriptor["oversight"] = ov
        return descriptor

    # -- folder send (point 35): a folder is packed to ZIP on the fly and
    # travels the exact same any-file path; receivers unpack the tree.
    async def send_folder(self, to: str, folder: str,
                          caption: str = "") -> dict:
        data = pack_folder(folder)
        descriptor = await self._make_blob_descriptor(
            folder, "file", for_user=normalize_username(to) or to,
            raw_override=data, name_override=Path(folder).name + ".zip",
            folder=True)
        return await self.send_message(to, caption, kind="file",
                                       file=descriptor)

    async def group_send_folder(self, group_id: str, folder: str,
                                caption: str = "") -> dict:
        data = pack_folder(folder)
        descriptor = await self._make_blob_descriptor(
            folder, "file", group_id=group_id, raw_override=data,
            name_override=Path(folder).name + ".zip", folder=True)
        return await self.group_send(group_id, caption, kind="file",
                                     file=descriptor)

    async def send_message(self, to: str, body: str, kind: str = "text",
                           file: dict | None = None,
                           in_reply_to: str | None = None,
                           priority: str = "normal",
                           meta: dict | None = None) -> dict:
        u = normalize_username(to) or to
        pub = await self.pubkey_of(u)
        if not pub:
            raise RequestFailed("unknown_recipient", f"no key for @{u}")
        obj = {"body": body, "kind": kind, "file": file}
        if meta:
            # Envelope metadata inside the E2E content object: the
            # autonomous runtime marks its sends {"autonomous": true}
            # so a receiving runtime can apply its tightened loop
            # caps. The relay never sees it.
            obj["meta"] = dict(meta)
        content = self._encrypt_obj(pub, obj)
        frame = {
            "type": "send", "to": u, "content": content, "id": new_id(),
            "mentions": parse_mentions(body), "in_reply_to": in_reply_to,
            "priority": priority}
        ov = self._oversight_for_obj(obj)
        if ov:
            frame["oversight"] = ov
        result = await self._request(frame)
        self._mailbox_record_sent({
            "id": result.get("id") or frame["id"], "from": self.username,
            "to": u, "group_id": None, "channel_id": None,
            "kind": kind, "body": body, "file": file,
            "meta": dict(meta) if meta else {},
            "mentions": frame["mentions"],
            "in_reply_to": in_reply_to, "priority": priority,
            "ts": int(time.time())})
        return result

    def _mailbox_record_sent(self, item: dict) -> None:
        """Journal one of my OWN sent items (taken=1 at birth) so
        the local mailbox is the complete history of the
        conversation, not just its inbound half."""
        if self.mailbox is None or not item.get("id"):
            return
        try:
            self.mailbox.put_if_absent(item, taken=True)
        except Exception:
            log.exception("mailbox record of sent item failed")

    async def send_file(self, to: str, path: str, caption: str = "",
                        kind: str | None = None,
                        via_blob: bool = False) -> dict:
        if via_blob:
            u = normalize_username(to) or to
            descriptor = await self._make_blob_descriptor(
                path, kind, for_user=u)
            return await self.send_message(to, caption,
                                           kind=descriptor["kind"],
                                           file=descriptor)
        payload = make_file_payload(path, kind)
        return await self.send_message(to, caption, kind=payload["kind"],
                                       file=payload)

    async def wait_reply(self, message_id: str, timeout: float = 15.0) -> dict:
        for m in self.messages:
            if m.get("in_reply_to") == message_id:
                return m
        fut = asyncio.get_running_loop().create_future()
        self._reply_waiters[message_id] = fut
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        finally:
            self._reply_waiters.pop(message_id, None)

    # -- read receipts (v1.1.2) -------------------------------------------
    async def mark_read(self, message_ids) -> dict:
        """Report message(s) as read. The relay validates — per
        message, from its own audit row — that this agent is a
        participant of the conversation, records the FIRST read
        time, pushes a live read_receipt to the sender, and the
        operator dashboard gains the Seen state. Accepts a single
        message id or an iterable of ids. Returns the relay result:
        {"read": [ids actually recorded], "reads": [{id, read_at}]}.
        Ids that are unknown, already read by someone else only, or
        not this agent's to read are silently absent from the
        result."""
        if isinstance(message_ids, str):
            ids = [message_ids]
        else:
            ids = [str(m) for m in (message_ids or []) if m]
        if not ids:
            return {"read": [], "reads": []}
        result = await self._request({"type": "read", "ids": ids})
        # An explicit mark_read IS a take-in (the deferred runtime's
        # own word for it): record it in the durable mailbox too, so
        # the item does not replay on the next start.
        if self.mailbox is not None:
            try:
                self.mailbox.mark_taken(ids)
            except Exception:
                log.exception("mailbox mark_taken failed")
        return result

    def _pending_reads_path(self) -> Path:
        return Path(self.state_dir) / f"pending-reads-{self.username}.json"

    def _persist_pending_reads(self) -> None:
        """Read cursors are durable state: pending receipts are
        mirrored to the agent home on every change, so a restart —
        including a self-update re-exec — never loses one."""
        if not self.username:
            return
        path = self._pending_reads_path()
        try:
            if not self._pending_reads:
                path.unlink(missing_ok=True)
                return
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(sorted(self._pending_reads)))
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except Exception:
            log.exception("persisting pending reads failed")

    def _load_pending_reads(self) -> None:
        if not self.username:
            return
        try:
            raw = self._pending_reads_path().read_text()
            self._pending_reads.update(str(i) for i in json.loads(raw))
        except FileNotFoundError:
            pass
        except Exception:
            log.exception("loading pending reads failed")

    def _queue_read(self, message_id: str | None) -> None:
        """Auto-read plumbing: accumulate ids and flush ONE read
        frame per burst — a reconnect can deliver a whole queue of
        messages at once, and each still gets its receipt."""
        if not message_id:
            return
        self._pending_reads.add(str(message_id))
        self._persist_pending_reads()
        task = self._read_flush_task
        if task is None or task.done():
            self._read_flush_task = asyncio.create_task(
                self._flush_reads_soon())

    async def _flush_reads_soon(self) -> None:
        try:
            await asyncio.sleep(0.3)
            while self._pending_reads:
                ids = sorted(self._pending_reads)
                self._pending_reads.clear()
                try:
                    await self._request({"type": "read", "ids": ids})
                    self._persist_pending_reads()
                except Exception:
                    # Offline / relay error: keep the ids pending —
                    # the next queued read or the next start() (the
                    # reconnect path) retries the flush. Receipts are
                    # never silently dropped by this client.
                    self._pending_reads.update(ids)
                    self._persist_pending_reads()
                    return
        except asyncio.CancelledError:
            raise

    def mention_inbox(self, group_id: str | None = None) -> list[dict]:
        items = self.mention_inbox_items
        if group_id:
            items = [m for m in items if m.get("group_id") == group_id]
        return list(items)

    # -- groups ------------------------------------------------------------------------------
    async def _distribute_group_key(self, gid: str, epoch: int, key: bytes,
                                      members: list[str]) -> None:
        wrapped = {}
        for u in members:
            if u == self.username:
                continue
            pub = await self.pubkey_of(u)
            if pub:
                wrapped[u] = self.identity.wrap_key(pub, key)
        if wrapped:
            await self._request({"type": "set_group_keys", "group_id": gid,
                                 "epoch": epoch, "wrapped": wrapped})

    async def group_create(self, name: str, members: list[str] | None = None,
                           settings: dict | None = None) -> dict:
        data = await self._request({"type": "group_create", "name": name,
                                    "members": members or [],
                                    "settings": settings})
        gid = data["group_id"]
        key = new_group_key()
        self._store_group_key(gid, 1, key)
        all_members = [m["username"] for m in data["members"]]
        await self._distribute_group_key(gid, 1, key, all_members)
        return data

    async def group_add(self, group_id: str, members: list[str]) -> dict:
        data = await self._request({"type": "group_add",
                                    "group_id": group_id, "members": members})
        rec = self._group_keys.get(group_id)
        if rec and data.get("added"):
            await self._distribute_group_key(group_id, rec["epoch"],
                                             rec["key"], data["added"])
        return data

    async def group_remove(self, group_id: str, username: str) -> dict:
        data = await self._request({"type": "group_remove",
                                    "group_id": group_id, "username": username})
        # Rotate the group key so the removed member cannot read
        # anything sent after their removal.
        rec = self._group_keys.get(group_id)
        if rec:
            try:
                members = await self.group_members(group_id)
                remaining = [m["username"] for m in members["members"]]
                new_key = new_group_key()
                epoch = rec["epoch"] + 1
                self._store_group_key(group_id, epoch, new_key)
                await self._distribute_group_key(group_id, epoch, new_key,
                                                 remaining)
            except Exception:
                log.exception("group key rotation failed")
        return data

    async def group_members(self, group_id: str) -> dict:
        data = await self._request({"type": "group_members",
                                    "group_id": group_id})
        mine = next((m for m in data.get("members", [])
                     if m["username"] == self.username), None)
        if mine is not None:
            cur = self.memberships.setdefault(group_id, {})
            cur.update({"role": mine.get("role"),
                        "nickname": mine.get("nickname", ""),
                        "custom_role": mine.get("custom_role", "")})
        return data

    async def group_promote(self, group_id: str, username: str) -> dict:
        return await self._request({"type": "group_promote",
                                    "group_id": group_id, "username": username})

    async def group_demote(self, group_id: str, username: str) -> dict:
        return await self._request({"type": "group_demote",
                                    "group_id": group_id, "username": username})

    async def group_settings(self, group_id: str, settings: dict) -> dict:
        return await self._request({"type": "group_settings",
                                    "group_id": group_id, "settings": settings})

    async def group_set_nickname(self, group_id: str, nickname: str,
                                 username: str | None = None) -> dict:
        return await self._request({"type": "group_nickname",
                                    "group_id": group_id,
                                    "username": username or self.username,
                                    "nickname": nickname})

    async def group_set_custom_role(self, group_id: str, username: str,
                                    custom_role: str) -> dict:
        return await self._request({"type": "group_custom_role",
                                    "group_id": group_id, "username": username,
                                    "custom_role": custom_role})

    async def group_join_link(self, group_id: str) -> dict:
        return await self._request({"type": "group_join_link",
                                    "group_id": group_id})

    async def group_join(self, link_or_token: str,
                         group_id: str | None = None) -> dict:
        frame = {"type": "group_join", "token": link_or_token}
        if group_id:
            frame["group_id"] = group_id
        return await self._request(frame)

    def _gate(self, group_id: str, setting: str) -> None:
        """Local behaviour gate (point 43e): if my live membership
        view says this group restricts the action to admins and I am
        not one, stop BEFORE attempting it. The relay enforces the
        same rule server-side; the local gate means the agent's
        behaviour adjusts the instant permissions change."""
        m = self.memberships.get(group_id)
        if not m:
            return
        if (m.get("settings") or {}).get(setting) == "admins_only" and \
                m.get("role") not in ("admin", "superadmin"):
            raise RequestFailed(
                "permission_denied_local",
                f"group setting {setting}=admins_only and you are a"
                " member; not attempting")

    async def group_send(self, group_id: str, body: str, kind: str = "text",
                         file: dict | None = None,
                         in_reply_to: str | None = None,
                         priority: str = "normal",
                         meta: dict | None = None) -> dict:
        self._gate(group_id, "send_messages")
        rec = await self._ensure_group_key(group_id)
        if rec is None:
            raise RequestFailed("no_group_key",
                                f"no encryption key for group {group_id}")
        payload_obj = {"body": body, "kind": kind, "file": file}
        if meta:
            payload_obj["meta"] = dict(meta)
        payload = json.dumps(payload_obj).encode()
        content = {"epoch": rec["epoch"],
                   **encrypt_with_key(rec["key"], payload)}
        frame = {
            "type": "group_send", "group_id": group_id, "content": content,
            "id": new_id(), "mentions": parse_mentions(body),
            "in_reply_to": in_reply_to, "priority": priority}
        ov = self._oversight_for_key(rec["key"])
        if ov:
            frame["oversight"] = ov
        result = await self._request(frame)
        self._mailbox_record_sent({
            "id": result.get("id") or frame["id"], "from": self.username,
            "to": group_id, "group_id": group_id, "channel_id": None,
            "kind": kind, "body": body, "file": file,
            "meta": dict(meta) if meta else {},
            "mentions": frame["mentions"],
            "in_reply_to": in_reply_to, "priority": priority,
            "ts": int(time.time())})
        return result

    async def group_send_file(self, group_id: str, path: str,
                              caption: str = "", kind: str | None = None,
                              via_blob: bool = False) -> dict:
        if via_blob:
            descriptor = await self._make_blob_descriptor(
                path, kind, group_id=group_id)
            return await self.group_send(group_id, caption,
                                         kind=descriptor["kind"],
                                         file=descriptor)
        payload = make_file_payload(path, kind)
        return await self.group_send(group_id, caption, kind=payload["kind"],
                                     file=payload)

    async def blob_delete(self, blob_id: str) -> dict:
        return await self._request({"type": "blob_delete",
                                    "blob_id": blob_id})

    # -- work -----------------------------------------------------------------------------------
    def _decrypt_work(self, raw: dict) -> dict:
        def _try(envelope):
            try:
                return self._decrypt_obj(envelope) if envelope else None
            except Exception:
                return None

        def _try_group(envelope, gid):
            rec = self._group_keys.get(gid or "")
            if not envelope or rec is None:
                return None
            try:
                return json.loads(decrypt_with_key(rec["key"], envelope))
            except Exception:
                return None

        content = _try(raw.get("content_enc")) or \
            _try(raw.get("content_self")) or \
            _try_group(raw.get("content_group"), raw.get("group_id")) or {}
        checkpoint = None
        cp = raw.get("checkpoint") or {}
        if cp:
            checkpoint = _try(cp.get("content_assigner")) or \
                _try_group(cp.get("content_group"), raw.get("group_id"))
        deliveries = []
        for d in raw.get("deliveries", []):
            dc = _try(d.get("content_enc")) or _try(d.get("content_self")) or {}
            deliveries.append({
                "id": d.get("id"), "work_id": d.get("work_id"),
                "deliverer": d.get("deliverer"), "ts": d.get("ts"),
                "body": dc.get("body", ""), "files": dc.get("files", []),
                "encrypted": True})
        return {
            "id": raw.get("id"), "assigner": raw.get("assigner"),
            "assignee": raw.get("assignee"), "group_id": raw.get("group_id"),
            "title": content.get("title", ""),
            "instructions": content.get("instructions", ""),
            "attachments": content.get("attachments", []),
            "deadline": raw.get("deadline"),
            "deadline_pt": pacific_display(raw.get("deadline")),
            "attempt": raw.get("attempt", 1),
            "my_role": (self.memberships.get(raw.get("group_id") or "")
                        or {}).get("role"),
            "my_custom_role": (self.memberships.get(
                raw.get("group_id") or "") or {}).get("custom_role"),
            "chain_id": raw.get("chain_id") or "",
            "chain_step": raw.get("chain_step") or 0,
            "prev_deliverables": raw.get("prev_deliverables") or [],
            "auto_reassign": bool(raw.get("auto_reassign", 1)),
            "checkpoint": checkpoint,
            "status": raw.get("status"),
            "batch_id": raw.get("batch_id"),
            "priority": raw.get("priority") or "normal",
            "progress_percent": raw.get("progress_percent", 0),
            "progress_at": raw.get("progress_at", 0),
            "require_approval": bool(raw.get("require_approval")),
            "proof_verified": bool(raw.get("proof_verified")),
            "proof_hash": raw.get("proof_hash", ""),
            "created_at": raw.get("created_at"),
            "updated_at": raw.get("updated_at"),
            "deliveries": deliveries, "encrypted": True}

    async def _process_work(self, raw: dict, assigned: bool) -> None:
        try:
            work = self._decrypt_work(raw)
        except Exception:
            log.exception("failed to decrypt work")
            return
        if assigned:
            # AT-LEAST-ONCE CUSTODY (v1.3.7): a work_assigned frame
            # has no ack-able id, so the relay re-offers it while it
            # sits in custody — the same (id, attempt) may arrive
            # more than once, live and across restarts. First sight
            # wins; a re-offer is acknowledged by ignoring it.
            wkey = (work.get("id"), int(work.get("attempt") or 1))
            # BOOT DEFERRAL: while start() is still running (boot
            # gate closed) and the journal already holds this work,
            # the frame is a re-offer of a RESUMPTION candidate —
            # journal/record it below, but do NOT claim the attempt
            # or spawn a runner: the start() resume pass owns it and
            # is the only path that runs the handler resumed=True
            # with its checkpoint. (Live assignment while running —
            # gate open — always takes the normal path.)
            _boot_defer = bool(
                work.get("id") and not self._boot_gate.is_set()
                and self._journal is not None
                and self._journal.get(work["id"]) is not None)
            if work.get("id") and not _boot_defer:
                if wkey in self._seen_work:
                    return
                self._seen_work.add(wkey)
            # JOURNAL FIRST (point 30): the assignment is durable on
            # this agent's disk before any handler acts on it.
            if self._journal is not None and work.get("id"):
                self._journal.put(work)
            # Mailbox first-sight record (v1.3.7): the assignment
            # also lands in the canonical mailbox as kind="work", so
            # the agent's one local history shows it arrived. The
            # TaskJournal remains the work system of record — this
            # record never replays as a message.
            if self.mailbox is not None and work.get("id"):
                try:
                    self.mailbox.put_if_absent({
                        "id": work["id"], "kind": "work",
                        "from": work.get("assigner"),
                        "to": self.username,
                        "group_id": work.get("group_id"),
                        "channel_id": None,
                        "attempt": wkey[1],
                        "ts": work.get("created_at")
                        or int(time.time()),
                        "title": work.get("title", ""),
                        "status": work.get("status")})
                except Exception:
                    log.exception("mailbox work record failed")
            # ACK BY WORK ID (v1.3.7): the assignment is now
            # durably journaled — tell the relay, so custody can
            # retire the frame instead of re-offering it forever
            # (an unretirable frame would also count as an
            # undelivered blocker, e.g. at deregister). The relay
            # matches acked ids against the frames it holds for
            # this agent, including work frames by their work id.
            if work.get("id"):
                await self._send_ack([work["id"]])
            self.assigned_work.append(work)
            if _boot_defer:
                return
            if self._work_handler is not None or self._autonomous_on():
                asyncio.create_task(self._run_work(work, resumed=False))
        else:
            self.work_updates.append(work)

    def _activity_state(self) -> str:
        return (f"working:{self._active_work}" if self._active_work
                else "online_idle")

    async def _run_work(self, work: dict, resumed: bool) -> None:
        """Worker pool (point 31): assignments run CONCURRENTLY up to
        max_concurrency; a queued assignment starts the instant a slot
        frees — event-driven, never timer-polled, never a human nudge.
        Dedup is by work_id + attempt (point 29)."""
        key = (work.get("id"), int(work.get("attempt") or 1))
        if key in self._running_work:
            return
        self._running_work.add(key)
        if self._work_sem is None:
            self._work_sem = asyncio.Semaphore(self.max_concurrency)
        try:
            await self._boot_gate.wait()
            async with self._work_sem:
                self._active_work += 1
                try:
                    checkpoint = None
                    if self._journal is not None:
                        entry = self._journal.get(work["id"])
                        if entry:
                            checkpoint = entry.get("checkpoint")
                    ctx = type("ResumeContext", (), {
                        "resumed": bool(resumed and checkpoint is not None),
                        "checkpoint": checkpoint,
                        "attempt": key[1],
                        "work_id": work["id"]})()
                    handler = self._work_handler
                    if work.get("chain_id") and \
                            self._chain_step_handler is not None:
                        handler = self._chain_step_handler
                    if handler is None:
                        # No owner-registered work handler: in
                        # autonomous mode the runtime loop itself
                        # considers the assignment through the agent's
                        # decision link; in manual mode the work
                        # simply waits, exactly as it always has.
                        if self._autonomous_on():
                            await self._run_autonomous_work(work)
                        return
                    params = inspect.signature(handler).parameters
                    if len(params) >= 2:
                        result = handler(work, ctx)
                    else:
                        result = handler(work)
                    if inspect.isawaitable(result):
                        await result
                except ResumeUnsupported as exc:
                    # Explicit, never silent (point 30).
                    log.warning("resume_failed for %s: %s", work["id"], exc)
                    try:
                        await self._request({
                            "type": "work_resume_failed",
                            "work_id": work["id"],
                            "reason": str(exc)[:200]})
                    except Exception:
                        pass
                except Exception:
                    log.exception("on_work handler failed")
                finally:
                    self._active_work -= 1
        finally:
            self._running_work.discard(key)

    async def _resume_open_work(self) -> None:
        """Boot steps 3-4: fetch open assignments from the relay, merge
        the local journal, and re-invoke handlers — with the exact
        checkpoint when one exists (ctx.resumed=True)."""
        if self._journal is None:
            return
        data = await self._request({"type": "work_inbox", "status": None,
                                    "group_id": None})
        for raw in data.get("work", []):
            if raw.get("assignee") != self.username:
                continue
            if raw.get("status") not in ("assigned", "in_progress",
                                         "changes_requested"):
                continue
            work = self._decrypt_work(raw)
            entry = self._journal.get(work["id"])
            if entry is None:
                self._journal.put(work)
                entry = self._journal.get(work["id"])
            work["checkpoint"] = entry.get("checkpoint") if entry else None
            if work not in self.assigned_work:
                self.assigned_work.append(work)
            # Mark the attempt seen (a custody re-offer of the
            # same work_assigned frame later in the session is a
            # duplicate — see _process_work) but NEVER skip the
            # resume spawn on that account: the resume pass is the
            # only path that runs the handler with resumed=True
            # and its checkpoint, and a frame that arrived during
            # boot defers to it (see _process_work). If both paths
            # do spawn, _run_work's own (id, attempt) guard admits
            # exactly one runner.
            if work.get("id"):
                self._seen_work.add(
                    (work["id"], int(work.get("attempt") or 1)))
            if self._work_handler is not None or self._autonomous_on():
                asyncio.create_task(self._run_work(
                    work, resumed=work["checkpoint"] is not None))

    async def checkpoint(self, work_id: str, data: dict) -> None:
        """Persist a resume point (point 30): local journal first, then
        the E2E-encrypted backend mirror (assigner copy + group copy),
        so the checkpoint travels with the assignment."""
        if self._journal is not None:
            self._journal.set_checkpoint(work_id, data)
        entry = self._journal.get(work_id) if self._journal else None
        work = entry or next((w for w in self.assigned_work
                              if w["id"] == work_id), None)
        if work is None:
            return
        frame = {"type": "work_checkpoint", "work_id": work_id,
                 "attempt": int(work.get("attempt") or 1)}
        assigner = work.get("assigner")
        if assigner:
            pub = await self.pubkey_of(assigner)
            if pub:
                frame["content_assigner"] = self._encrypt_obj(pub, data)
        gid = work.get("group_id")
        if gid:
            rec = await self._ensure_group_key(gid)
            if rec:
                frame["content_group"] = encrypt_with_key(
                    rec["key"], json.dumps(data).encode())
        try:
            await self._request(frame)
        except Exception:
            log.exception("checkpoint mirror failed")

    async def assign_work(self, assignees: list[str], title: str,
                          instructions: str = "", group_id: str | None = None,
                          attachments: list[str] | None = None,
                          deadline=None,
                          priority: str = "normal",
                          target_role: str | None = None,
                          auto_reassign: bool = True,
                          require_approval: bool = False) -> list[dict]:
        payloads = [make_file_payload(p) for p in (attachments or [])]
        obj = {"title": title, "instructions": instructions,
               "attachments": payloads}
        envelopes = {}
        self_pub = self.identity.public_key_b64
        for a in assignees:
            u = normalize_username(a) or a
            pub = await self.pubkey_of(u)
            if not pub:
                raise RequestFailed("unknown_username", f"no key for @{u}")
            envelopes[u] = {"enc": self._encrypt_obj(pub, obj),
                            "self": self._encrypt_obj(self_pub, obj)}
        from .deadlines import parse_deadline
        frame = {
            "type": "assign",
            "assignees": [normalize_username(a) or a for a in assignees],
            "group_id": group_id, "envelopes": envelopes,
            "deadline": parse_deadline(deadline), "priority": priority,
            "auto_reassign": auto_reassign}
        if group_id:
            # Group copy: any entitled member (e.g. a reassignment
            # replacement) can read the assignment; the relay cannot.
            rec = await self._ensure_group_key(group_id)
            if rec:
                frame["content_group"] = encrypt_with_key(
                    rec["key"], json.dumps(obj).encode())
        if target_role:
            frame["target_role"] = target_role
        if require_approval:
            frame["require_approval"] = True
        ov = self._oversight_for_obj(obj)
        if ov:
            frame["oversight"] = ov
        data = await self._request(frame)
        out = []
        for raw_w in data["work"]:
            w = self._decrypt_work(raw_w)
            if raw_w.get("notice"):
                # Platform notice (v1.3.5): e.g. an assignee whose
                # decision link is pending — the work parked safely
                # and nothing was accepted on its behalf. The notice
                # is the relay speaking about the LINK, never as the
                # agent; it rides the assignment result so the
                # assigner hears it in the same breath as the work.
                w["notice"] = raw_w["notice"]
            out.append(w)
        return out

    async def assign_work_role(self, group_id: str, role: str, title: str,
                               instructions: str = "",
                               attachments: list[str] | None = None,
                               deadline: int | None = None,
                               priority: str = "normal",
                               require_approval: bool = False) -> list[dict]:
        """Assign to EVERY current holder of a custom role in a group.
        One delivery satisfies the whole batch; the rest are 'covered'.
        The relay re-resolves the role server-side; an empty role is
        rejected with 'empty_role'."""
        members = await self.group_members(group_id)
        holders = [m["username"] for m in members["members"]
                   if (m.get("custom_role") or "").lower() == role.lower()]
        return await self.assign_work(
            holders, title, instructions, group_id=group_id,
            attachments=attachments, deadline=deadline, priority=priority,
            target_role=role, require_approval=require_approval)

    def delivery_proof(self, work_id: str, obj: dict) -> dict:
        """Signed delivery proof (point 23): Ed25519 signature from the
        identity keypair over the canonical payload
        work_id|content_hash|timestamp|deliverer, where content_hash is
        the SHA256 of the canonical JSON of the deliverable."""
        import hashlib
        import time as _time
        canonical_obj = json.dumps(obj, sort_keys=True,
                                   separators=(",", ":"))
        content_hash = hashlib.sha256(canonical_obj.encode()).hexdigest()
        ts = int(_time.time())
        payload = f"{work_id}|{content_hash}|{ts}|{self.username}".encode()
        return {"hash": content_hash, "ts": ts,
                "sig": self.identity.sign(payload)}

    async def deliver_work(self, work_id: str, body: str = "",
                           files: list[str] | None = None) -> dict:
        # A delivery in transit is a critical operation: a
        # self-update waits for the frame to land before it swaps.
        async with self._critical_op("delivery"):
            return await self._deliver_work_inner(work_id, body, files)

    async def _deliver_work_inner(self, work_id: str, body: str = "",
                                  files: list[str] | None = None
                                  ) -> dict:
        inbox = await self.work_inbox()
        mine = next((w for w in inbox if w["id"] == work_id), None)
        if mine is None:
            raise RequestFailed("unknown_work", work_id)
        payloads = [make_file_payload(p) for p in (files or [])]
        obj = {"body": body, "files": payloads}
        assigner_pub = await self.pubkey_of(mine["assigner"])
        frame = {
            "type": "deliver_work", "work_id": work_id,
            "attempt": int(mine.get("attempt") or 1),
            "proof": self.delivery_proof(work_id, obj),
            "library": [{"name": f.get("name", ""),
                         "size": f.get("size", 0),
                         "sha256": f.get("sha256", "")}
                        for f in payloads],
            "content_enc": self._encrypt_obj(assigner_pub, obj),
            "content_self": self._encrypt_obj(
                self.identity.public_key_b64, obj)}
        if mine.get("group_id"):
            rec = await self._ensure_group_key(mine["group_id"])
            if rec:
                frame["content_group"] = encrypt_with_key(
                    rec["key"], json.dumps(obj).encode())
        if mine.get("chain_id"):
            # Chain handoff (point 41c): encrypt a copy to each next
            # step assignee NOW, while this client holds the
            # plaintext — the relay only ever stores ciphertext.
            try:
                ctx = await self._request(
                    {"type": "chain_context", "work_id": work_id})
                nxt = {}
                for u in ctx.get("next_assignees") or []:
                    pub = await self.pubkey_of(u)
                    if pub:
                        nxt[u] = self._encrypt_obj(pub, obj)
                if nxt:
                    frame["content_next"] = nxt
            except Exception:
                log.exception("chain-next copy failed")
        ov = self._oversight_for_obj(obj)
        if ov:
            frame["oversight"] = ov
        data = await self._request(frame)
        return self._decrypt_work(data["work"])

    async def report_progress(self, work_id: str, percent: int,
                              note: str = "") -> dict:
        """Live progress (point 21): percent is envelope metadata; the
        note is content and travels E2E-encrypted to the assigner."""
        if not isinstance(percent, int) or not (0 <= percent <= 100):
            raise RequestFailed("bad_percent", "percent must be 0-100")
        inbox = await self.work_inbox()
        mine = next((w for w in inbox if w["id"] == work_id), None)
        if mine is None:
            raise RequestFailed("unknown_work", work_id)
        obj = {"note": note}
        assigner_pub = await self.pubkey_of(mine["assigner"])
        data = await self._request({
            "type": "work_progress", "work_id": work_id,
            "percent": percent,
            "content_enc": self._encrypt_obj(assigner_pub, obj),
            "content_self": self._encrypt_obj(
                self.identity.public_key_b64, obj)})
        return self._decrypt_work(data["work"])

    async def verify_delivery_proof(self, raw_work: dict) -> bool:
        """Verify a delivery's signed proof against the deliverer's
        REGISTERED signing public key (point 23)."""
        from .crypto import Identity as _Identity
        deliveries = raw_work.get("deliveries") or []
        if not deliveries or not raw_work.get("proof_sig"):
            return False
        deliverer = deliveries[-1].get("deliverer")
        data = await self._request({"type": "get_key",
                                    "username": deliverer})
        sign_pub = data.get("sign_pub") or ""
        canonical = "{}|{}|{}|{}".format(
            raw_work["id"], raw_work.get("proof_hash", ""),
            raw_work.get("proof_ts", ""), deliverer).encode()
        return _Identity.verify_signature(
            sign_pub, canonical, raw_work.get("proof_sig", ""))

    async def complete_work(self, work_id: str, note: str = "") -> dict:
        data = await self._request({"type": "work_action", "work_id": work_id,
                                    "action": "complete", "note": note})
        return self._decrypt_work(data["work"])

    async def request_changes(self, work_id: str, note: str = "") -> dict:
        data = await self._request({"type": "work_action", "work_id": work_id,
                                    "action": "request_changes", "note": note})
        return self._decrypt_work(data["work"])

    async def approve_work(self, work_id: str, note: str = "") -> dict:
        """Approval gate (v1.1.0): decide a delivery parked in
        awaiting_approval. Only the assigner (or a group admin for
        group work) may decide; approval completes the work \u2014 and
        only NOW does a chain advance."""
        data = await self._request({"type": "work_action", "work_id": work_id,
                                    "action": "approve", "note": note})
        return self._decrypt_work(data["work"])

    async def reject_work(self, work_id: str, reason: str = "") -> dict:
        """Approval gate (v1.1.0): reject a parked delivery with a
        reason \u2014 the work returns to changes_requested (the reason
        rides the note to the assignee) and a chain stays paused."""
        data = await self._request({"type": "work_action", "work_id": work_id,
                                    "action": "reject", "note": reason})
        return self._decrypt_work(data["work"])

    async def work_inbox(self, status: str | None = None,
                         group_id: str | None = None) -> list[dict]:
        data = await self._request({"type": "work_inbox", "status": status,
                                    "group_id": group_id})
        return [self._decrypt_work(w) for w in data["work"]]

    # -- channels (broadcast: admins post, subscribers read-only) --------------
    async def _distribute_channel_key(self, cid: str, epoch: int,
                                      key: bytes, members: list[str]) -> None:
        wrapped = {}
        for u in members:
            if u == self.username:
                continue
            pub = await self.pubkey_of(u)
            if pub:
                wrapped[u] = self.identity.wrap_key(pub, key)
        if wrapped:
            await self._request({"type": "set_channel_keys",
                                 "channel_id": cid, "epoch": epoch,
                                 "wrapped": wrapped})

    async def channel_create(self, name: str,
                             members: list[str] | None = None) -> dict:
        data = await self._request({"type": "channel_create", "name": name,
                                    "members": members or []})
        cid = data["channel_id"]
        key = new_group_key()
        self._store_channel_key(cid, 1, key)
        all_members = [m["username"] for m in data["members"]]
        await self._distribute_channel_key(cid, 1, key, all_members)
        return data

    async def channel_add(self, channel_id: str,
                          members: list[str]) -> dict:
        data = await self._request({"type": "channel_add",
                                    "channel_id": channel_id,
                                    "members": members})
        rec = self._channel_keys.get(channel_id)
        if rec and data.get("added"):
            await self._distribute_channel_key(channel_id, rec["epoch"],
                                               rec["key"], data["added"])
        return data

    async def channel_remove(self, channel_id: str, username: str) -> dict:
        data = await self._request({"type": "channel_remove",
                                    "channel_id": channel_id,
                                    "username": username})
        # Rotate the channel key on removal (same rule as groups).
        rec = self._channel_keys.get(channel_id)
        if rec:
            try:
                members = await self.channel_members(channel_id)
                remaining = [m["username"] for m in members["members"]]
                new_key = new_group_key()
                epoch = rec["epoch"] + 1
                self._store_channel_key(channel_id, epoch, new_key)
                await self._distribute_channel_key(channel_id, epoch,
                                                   new_key, remaining)
            except Exception:
                log.exception("channel key rotation failed")
        return data

    async def channel_members(self, channel_id: str) -> dict:
        return await self._request({"type": "channel_members",
                                    "channel_id": channel_id})

    async def channel_promote(self, channel_id: str, username: str) -> dict:
        return await self._request({"type": "channel_promote",
                                    "channel_id": channel_id,
                                    "username": username})

    async def channel_join_link(self, channel_id: str) -> dict:
        return await self._request({"type": "channel_join_link",
                                    "channel_id": channel_id})

    async def channel_join(self, link_or_token: str,
                           channel_id: str | None = None) -> dict:
        frame = {"type": "channel_join", "token": link_or_token}
        if channel_id:
            frame["channel_id"] = channel_id
        return await self._request(frame)

    async def channel_send(self, channel_id: str, body: str,
                           kind: str = "text", file: dict | None = None,
                           priority: str = "normal",
                           meta: dict | None = None) -> dict:
        rec = await self._ensure_channel_key(channel_id)
        if rec is None:
            raise RequestFailed("no_channel_key",
                                f"no encryption key for {channel_id}")
        payload_obj = {"body": body, "kind": kind, "file": file}
        if meta:
            payload_obj["meta"] = dict(meta)
        payload = json.dumps(payload_obj).encode()
        content = {"epoch": rec["epoch"],
                   **encrypt_with_key(rec["key"], payload)}
        frame = {
            "type": "channel_send", "channel_id": channel_id,
            "content": content, "id": new_id(),
            "mentions": parse_mentions(body), "priority": priority}
        ov = self._oversight_for_key(rec["key"])
        if ov:
            frame["oversight"] = ov
        result = await self._request(frame)
        self._mailbox_record_sent({
            "id": result.get("id") or frame["id"], "from": self.username,
            "to": channel_id, "group_id": None, "channel_id": channel_id,
            "kind": kind, "body": body, "file": file,
            "meta": dict(meta) if meta else {},
            "mentions": frame["mentions"], "in_reply_to": None,
            "priority": priority, "ts": int(time.time())})
        return result

    async def channel_send_file(self, channel_id: str, path: str,
                                caption: str = "",
                                kind: str | None = None) -> dict:
        descriptor = await self._make_blob_descriptor(
            path, kind, channel_id=channel_id)
        return await self.channel_send(channel_id, caption,
                                       kind=descriptor["kind"],
                                       file=descriptor)

    # -- voice rooms (WebRTC signalling only; media is peer-to-peer) ------------
    async def room_open(self, group_id: str) -> dict:
        return await self._request({"type": "room_open",
                                    "group_id": group_id})

    async def room_join(self, room_id: str) -> dict:
        return await self._request({"type": "room_join",
                                    "room_id": room_id})

    async def room_leave(self, room_id: str) -> dict:
        return await self._request({"type": "room_leave",
                                    "room_id": room_id})

    async def room_close(self, room_id: str) -> dict:
        return await self._request({"type": "room_close",
                                    "room_id": room_id})

    async def room_signal(self, room_id: str, to: str, kind: str,
                          payload) -> dict:
        """Send one signalling payload (offer/answer/ice) to exactly one
        room participant. Agent-side media still needs the agent's own
        WebRTC stack (e.g. aiortc or a browser runtime) — the relay
        routes signalling only and never carries audio."""
        return await self._request({"type": "room_signal",
                                    "room_id": room_id, "to": to,
                                    "kind": kind, "payload": payload})

    # -- voice-room media (v1.3.9, optional extra) -------------------------
    # The agent's own WebRTC audio leg, negotiated over room_signal.
    # The relay still routes signalling only and never carries
    # audio; media flows peer-to-peer (see agentlink/media.py for
    # the NAT reality, stated plainly).

    @staticmethod
    def media_available() -> bool:
        """True when the optional media stack (aiortc) is installed."""
        from .media import media_available as _available
        return _available()

    async def media_join(self, room_id: str, peer: str, *,
                         initiator: bool = False,
                         publish: str | None = None,
                         loop: bool = False):
        """Open a media session with one participant of a room the
        agent has already joined (room_join). initiator=True sends
        the offer; otherwise the session answers the peer's offer
        when it arrives. publish=<wav path> makes that file the
        session's outgoing audio (loop=True repeats it). Returns
        the RoomMediaSession. Raises MediaUnavailable when the
        optional media stack is not installed."""
        from .media import (MediaUnavailable, RoomMediaSession,
                            media_available as _available)
        if not _available():
            raise MediaUnavailable(
                "voice-room media needs the optional media stack: "
                "pip install 'agentlink[media]' (aiortc)")
        peer = normalize_username(peer) or peer
        session = RoomMediaSession(self, room_id, peer)
        self._media_sessions[(room_id, peer)] = session
        if publish:
            await session.publish_wav(publish, loop=loop)
        if initiator:
            await session.connect(initiator=True)
        return session

    def media_enable_room(self, room_id: str, *,
                          publish: str | None = None,
                          loop: bool = False) -> None:
        """Auto-answer media in this room: any participant's offer
        gets an answerer session (created on the offer's arrival),
        optionally publishing the same WAV to every comer — how an
        agent audibly greets a human joining from the dashboard.
        Requires the media stack at offer time; without it, offers
        simply go unanswered (the declared capability fact)."""
        self._media_rooms[room_id] = \
            (str(publish), bool(loop)) if publish else None

    async def media_disable_room(self, room_id: str) -> None:
        """Stop auto-answering in this room AND close its live
        media sessions — disabling a room ends its media, it does
        not leave a stream running unanswered-to."""
        self._media_rooms.pop(room_id, None)
        for key in [k for k in self._media_sessions
                    if k[0] == room_id]:
            sess = self._media_sessions.get(key)
            if sess is not None:
                try:
                    await sess.close()
                except Exception:
                    pass

    async def media_leave(self, session) -> None:
        """Close one media session (the peer connection ends; the
        room membership itself is room_leave's business)."""
        try:
            await self.room_signal(session.room_id, session.peer,
                                   "bye", {})
        except Exception:
            pass
        await session.close()

    async def update_capabilities(self, capabilities: list[str],
                                  description: str = "") -> dict:
        """Signed capability update (point 33): the signature is made
        with the identity signing key over the canonical payload; the
        relay verifies it against the registered public key."""
        caps = [str(c)[:40] for c in capabilities][:32]
        # The relay canonicalises the description at 200 chars; sign
        # exactly what the relay will rebuild (a longer description
        # used to make every such update fail bad_signature).
        description = str(description or "")[:200]
        canonical = "caps|{}|{}|{}".format(
            self.username, ",".join(caps), description).encode()
        data = await self._request({
            "type": "update_capabilities", "capabilities": caps,
            "description": description,
            "sig": self.identity.sign(canonical)})
        self.capabilities = caps
        self.cap_description = description
        return data

    # -- work chains (point 41) ------------------------------------------------------
    async def create_chain(self, steps: list[dict],
                           group_id: str | None = None,
                           name: str = "") -> dict:
        """Create a work chain. Each step dict:
        {"to": username} or {"role": name, "group_id": gid} or
        {"group_member": gid}, plus title/instructions/attachments/
        deadline/priority. EVERY step's assignment envelope is created
        NOW, E2E-encrypted to its own assignee, and held queued at the
        relay (metadata only) until the previous step's delivery is
        proven AND accepted — then it fires instantly."""
        from .deadlines import parse_deadline
        prepared = []
        for st in steps:
            title = st.get("title", "")
            obj = {"title": title,
                   "instructions": st.get("instructions", ""),
                   "attachments": [make_file_payload(p) for p in
                                   st.get("attachments") or []]}
            step = {"target_type": "user", "target": "",
                    "group_id": st.get("group_id") or group_id or "",
                    "assignees": [], "envelopes": {},
                    "deadline": parse_deadline(st.get("deadline")),
                    "priority": st.get("priority", "normal"),
                    "require_approval": bool(st.get("require_approval"))}
            self_pub = self.identity.public_key_b64
            if st.get("role"):
                gid = st.get("group_id") or group_id
                members = await self.group_members(gid)
                holders = [m["username"] for m in members["members"]
                           if (m.get("custom_role") or "").lower()
                           == st["role"].lower()]
                step["target_type"] = "role"
                step["target"] = st["role"]
                step["assignees"] = holders
            elif st.get("group_member"):
                step["target_type"] = "member"
                step["group_id"] = st["group_member"]
            else:
                u = normalize_username(st.get("to") or "") or st.get("to")
                step["target"] = u
                step["assignees"] = [u]
            for a in step["assignees"]:
                pub = await self.pubkey_of(a)
                if not pub:
                    raise RequestFailed("unknown_username",
                                        f"no key for @{a}")
                step["envelopes"][a] = {
                    "enc": self._encrypt_obj(pub, obj),
                    "self": self._encrypt_obj(self_pub, obj)}
            sgid = step["group_id"]
            if sgid:
                rec = await self._ensure_group_key(sgid)
                if rec:
                    step["content_group"] = encrypt_with_key(
                        rec["key"], json.dumps(obj).encode())
            prepared.append(step)
        data = await self._request({
            "type": "chain_create", "group_id": group_id, "name": name,
            "steps": prepared})
        return data["chain"]

    async def chain_cancel(self, chain_id: str) -> dict:
        data = await self._request({"type": "chain_cancel",
                                    "chain_id": chain_id})
        return data["chain"]

    async def chain_list(self) -> list[dict]:
        data = await self._request({"type": "chain_list"})
        return data["chains"]

    async def chain_get(self, chain_id: str) -> dict:
        data = await self._request({"type": "chain_get",
                                    "chain_id": chain_id})
        return data["chain"]

    # -- delivery library + group vault (point 38) --------------------------------
    async def library_search(self, q: str = "", sender: str = "",
                             group_id: str = "",
                             hash_prefix: str = "") -> list[dict]:
        data = await self._request({
            "type": "library_search", "q": q, "sender": sender,
            "group_id": group_id, "hash_prefix": hash_prefix})
        return data["entries"]

    async def library_fetch(self, library_id: str) -> dict:
        """Fetch a deliverable through the line (entitlement-checked
        by the relay) and decrypt the copy addressed to me."""
        data = await self._request({"type": "library_fetch",
                                    "library_id": library_id})
        content = data.get("content")
        obj = self._decrypt_obj(content) if content else {}
        return {"entry": data["entry"], "body": obj.get("body", ""),
                "files": obj.get("files", [])}

    async def vault_put(self, group_id: str, path: str,
                        pinned: bool = False) -> dict:
        self._gate(group_id, "vault_add")
        descriptor = await self._make_blob_descriptor(
            path, None, group_id=group_id)
        data = await self._request({
            "type": "vault_add", "group_id": group_id,
            "descriptor": descriptor, "pinned": pinned})
        return data["entry"]

    async def vault_list(self, group_id: str) -> list[dict]:
        data = await self._request({"type": "vault_list",
                                    "group_id": group_id})
        return data["files"]

    async def vault_get(self, entry: dict) -> dict:
        """Download + decrypt a vault file (group key). The relay
        re-checks membership on the blob fetch itself."""
        return await self._resolve_blob_file(
            entry["descriptor"], {"group_id": entry["group_id"]})

    async def vault_pin(self, vault_id: str, pinned: bool = True) -> dict:
        data = await self._request({"type": "vault_pin",
                                    "vault_id": vault_id,
                                    "pinned": pinned})
        return data["entry"]

    async def vault_remove(self, vault_id: str) -> dict:
        return await self._request({"type": "vault_remove",
                                    "vault_id": vault_id})

    # -- directory ---------------------------------------------------------------------------------
    async def directory(self, query: str = "",
                        capability: str = "") -> list[dict]:
        data = await self._request({"type": "directory", "query": query,
                                    "capability": capability})
        for u in data["users"]:
            if u.get("pubkey"):
                self._pubkey_cache[u["username"]] = u["pubkey"]
        return data["users"]

    # -- deregistration (v1.1.10) ------------------------------------------------------------
    async def deregister(self, *, wipe_local: bool = False) -> dict:
        """Remove THIS agent's registration from the relay — the
        exit door for test/scratch identities (standing rule: after
        testing, always delete what the test created).

        The request rides the connection authenticated at hello
        with this agent's secret (the same auth as every frame);
        the relay acts only on the authenticated username, so an
        agent can only ever deregister ITSELF. Fail-closed: while
        non-terminal work, undelivered queue frames or live chain
        entanglements stand, the relay refuses with reason
        'deregister_blocked' and nothing is removed — live work is
        never orphaned by an exit. On success the registration and
        everything that belongs to it is deleted server-side (see
        Store.remove_user for the exact cascade), the relay closes
        the connection, and the returned dict carries the per-table
        removal counts. wipe_local=True ADDITIONALLY deletes this
        agent's local home files (secret, identity keys, group /
        channel / file keys, pending reads, work journal); it is
        off by default and never implied."""
        if self.ephemeral:
            raise RequestFailed(
                "ephemeral_no_registration",
                "ephemeral callers have no registration to remove")
        data = await self._request({"type": "deregister"})
        await self.close()
        if wipe_local:
            self._wipe_local_home()
        return data

    def _wipe_local_home(self) -> None:
        names = [f"secret-{self.username}.json",
                 f"keys-{self.username}.json",
                 f"groupkeys-{self.username}.json",
                 f"channelkeys-{self.username}.json",
                 f"filekeys-{self.username}.json",
                 f"pending-reads-{self.username}.json",
                 f"heartbeat-{self.username}.txt"]
        for suffix in ("", "-wal", "-shm"):
            names.append(f"tasks-{self.username}.db{suffix}")
            names.append(f"mailbox.db{suffix}")
        for name in names:
            try:
                (self.state_dir / name).unlink()
            except OSError:
                pass
        cur = self.state_dir / "current.json"
        try:
            if cur.exists() and json.loads(cur.read_text()).get(
                    "username") == self.username:
                cur.unlink()
        except Exception:
            pass


def pack_folder(folder: str) -> bytes:
    """Pack a directory tree into ZIP bytes, preserving internal paths.
    A folder is just a file to the transport (opaque bytes + SHA256)."""
    import io
    import zipfile
    root = Path(folder)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fp in sorted(root.rglob("*")):
            if fp.is_file():
                zf.write(fp, fp.relative_to(root).as_posix())
    return buf.getvalue()


def unpack_folder(data: bytes, dest: str) -> list[str]:
    """Unpack ZIP bytes into dest, restoring the tree. Entries are
    sanitised against path traversal (never trusted as a type check —
    only as a save-location guard). Returns the written paths."""
    import io
    import zipfile
    dest_root = Path(dest).resolve()
    written = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = (dest_root / info.filename).resolve()
            if dest_root not in target.parents and target != dest_root:
                raise ValueError(f"unsafe path in archive: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info.filename))
            written.append(str(target))
    return written


async def dial(endpoint: str | None, to: str, body: str,
               timeout: float = 15.0, state_dir: str = DEFAULT_STATE_DIR) -> str:
    """One-shot: send a message as an ephemeral caller and await the reply
    on the same line — the ask_fo / get_fo_reply pattern, generalised."""
    caller = Agent("dial", endpoint=endpoint, state_dir=state_dir,
                   ephemeral=True)
    await caller.start()
    try:
        sent = await caller.send_message(to, body)
        reply = await caller.wait_reply(sent["id"], timeout=timeout)
        return reply.get("body", "")
    finally:
        await caller.close()
