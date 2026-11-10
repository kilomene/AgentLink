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
import threading
import time
from pathlib import Path

import websockets.exceptions
from websockets.client import connect

from .config import DEFAULT_ENDPOINT, resolve_endpoint, \
    resolve_fallbacks, resolve_oversight_pubkey, \
    resolve_update_check_seconds, self_update_enabled
from .deadlines import pacific_display
from .timing import (
    AUTO_HOURLY_BUDGET,
    AUTO_HOURLY_BUDGET_AUTO,
    AUTO_MAX_CONSECUTIVE_AUTO,
    AUTO_MAX_CONSECUTIVE_REPLIES,
    AUTO_REPLY_DELAY_AUTO_SECONDS,
    AUTO_REPLY_DELAY_SECONDS,
    DECISION_CONVENTION_URL,
    DECISION_LINK_CHECK_TIMEOUT_SECONDS,
    DECISION_LINK_RECHECK_SECONDS,
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
from .outbox import Outbox
from .protocol import (
    MAX_FRAME,
    make_file_payload,
    new_id,
    normalize_username,
    now_ts,
    verify_file,
)
from .vault import CredentialsVault, VaultAccess, VaultError
from .transport_v2 import (
    SERVERLESS_ENDPOINT,
    Refusal,
    ServerlessConfig,
    ServerlessTransport,
    TransportError,
)
from .transport_v2 import transport_mode as _env_transport_mode
from .doorbell import build_counterparty_set

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


async def _dial_via_proxy_candidates(url: str, _connect=None):
    """Dial a websocket through the egress proxy, racing the
    freshly resolved credential candidates in parallel —
    first success wins (the canonical proxycreds pattern).
    The pre-1.8.1 fallback let the websockets library honour
    the PROCESS ENVIRONMENT's proxy: a value pinned at process
    start, dead the moment the runtime rotates the token.
    Here every candidate is passed explicitly, the winner is
    cached by proxycreds, and a library too old for a
    per-dial proxy falls back to the env-honoured connect —
    never worse than the old behaviour."""
    from .proxycreds import candidate_proxies, note_proxy_result
    if _connect is None:
        from websockets.asyncio.client import (
            connect as _connect)
    candidates = candidate_proxies()
    if not candidates:
        return await _connect(url, max_size=MAX_FRAME)

    async def _attempt(proxy):
        try:
            ws = await _connect(url, max_size=MAX_FRAME,
                                proxy=proxy)
        except Exception:
            note_proxy_result(proxy, False)
            raise
        note_proxy_result(proxy, True)
        return ws

    pending = {asyncio.ensure_future(_attempt(p))
               for p in candidates}
    winner = None
    last: Exception | None = None
    type_errors = 0
    try:
        while pending and winner is None:
            done, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED)
            for t in done:
                exc = t.exception()
                if exc is not None:
                    last = exc
                    if isinstance(exc, TypeError):
                        type_errors += 1
                elif winner is None:
                    winner = t.result()
                else:
                    try:
                        await t.result().close()
                    except Exception:
                        pass
        if winner is not None:
            return winner
        if type_errors and type_errors >= len(candidates):
            # The installed library cannot take a per-dial
            # proxy at all: env-honoured connect is the only
            # door (the pre-1.8.1 behaviour).
            return await _connect(url, max_size=MAX_FRAME)
        raise last if last is not None else ConnectionError(
            f"cannot reach {url} via any egress proxy")
    finally:
        def _reap(t):
            if not t.cancelled():
                t.exception()
        for t in pending:
            t.cancel()
            t.add_done_callback(_reap)


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

# Pubkey cache freshness (v1.7.0): how long a resolved peer key
# may be reused before pubkey_of re-resolves it through the
# relay. A peer's key changes when its account is rebound (a
# recovery login) — the relay's key_rotated notice invalidates
# the entry immediately on the reclaiming relay; this TTL is
# the fleet-wide backstop for peers connected elsewhere.
_PUBKEY_CACHE_TTL_SECONDS = 300.0


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


def _sd_notify_watchdog() -> None:
    """One systemd watchdog pat (2.2.0), from the stamp loops.

    When the daemon runs under a systemd unit with WatchdogSec
    (the `service install` template sets 30s), systemd restarts
    a unit that stops patting — the frozen-but-alive case that
    Restart=always cannot see. The stamp loops call this beside
    every heartbeat-stamp write, so a frozen event loop stops
    patting at exactly the moment its stamp goes stale: the two
    supervision nets (systemd's watchdog, the host watchdog.sh)
    read the same liveness truth. No NOTIFY_SOCKET (every
    non-systemd run) → no-op. Never raises."""
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    try:
        import socket as _socket
        if addr.startswith("@"):
            addr = "\0" + addr[1:]
        sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_DGRAM)
        try:
            sock.sendto(b"WATCHDOG=1", addr)
        finally:
            sock.close()
    except Exception:
        pass


def _payload_body(payload: dict) -> str:
    """The text of an opened message payload (2.2.0).

    The canonical payload shape carries the text under "body".
    The retired drill injector (and any pre-canonical sender)
    used the DM-era shape {"text": ...} on room frames — real
    text under a key no reader consulted, which rendered as
    empty posts fleet-wide (the 29 Nova family items, findings
    in drill-evidence/v220/findings-29.md). An opened payload's
    text is its "body" when that key is present (even empty —
    an intentionally empty body stays empty), else its legacy
    "text". One helper, every open path, so the alias can never
    drift between the live and history readers again."""
    if not isinstance(payload, dict):
        return ""
    body = payload.get("body")
    if isinstance(body, str):
        return body
    text = payload.get("text")
    return text if isinstance(text, str) else ""


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


def instance_lock_holder(state_dir, username: str) -> dict | None:
    """The LIVE holder of ``username``'s instance lock, or None
    (2.2.3). Reads instance-<username>.lock and returns its
    record only when it names THIS username and its pid is
    alive right now (a PermissionError on the probe means the
    pid exists under another owner — alive). A missing /
    unreadable / foreign / dead holder is None: the flock is
    the kernel's truth, this record is only the witness the
    already-registered fast paths (setup, the support hook)
    use to prove a running instance is OURS before treating
    an instance collision as that instance's success."""
    sd = Path(state_dir).expanduser()
    try:
        holder = json.loads(
            (sd / f"instance-{username}.lock").read_text())
    except Exception:
        return None
    if not isinstance(holder, dict) \
            or holder.get("username") != username:
        return None
    pid = holder.get("pid")
    if not pid:
        return None
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        pass  # alive, owned by someone else
    except Exception:
        return None
    return holder


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
                f"within {timeout:.0f}s. Two honest possibilities: "
                "it is still executing inside a network ride-out "
                "(a proxy stall window can hold one hardened call "
                "for ~160s by design), or the daemon is wedged. "
                "The command may still complete on the daemon — "
                "for a WRITE, verify in the server record before "
                "retrying, because it may have landed. Failing "
                "closed rather than guessing; restart the daemon "
                "only if it does not recover.")
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


def _quarantine_db_file(path: Path) -> None:
    """Rename a corrupt SQLite database aside, WAL sidecars
    included (v1.6.0). A leftover -wal/-shm pair belongs to the
    corrupt incarnation: replayed against the rebuilt database it
    would resurrect the corruption the quarantine exists to
    escape (the 43d rebuild depends on this). Sidecars are renamed
    alongside where possible and unlinked otherwise — the rebuilt
    store comes from the backend mirror / history backfill, never
    from the corrupt file's remains."""
    try:
        path.rename(path.with_suffix(".corrupt"))
    except Exception:
        pass
    for suffix in ("-wal", "-shm"):
        side = path.with_name(path.name + suffix)
        try:
            side.rename(side.with_name(side.name + ".corrupt"))
        except Exception:
            try:
                side.unlink()
            except Exception:
                pass


class TaskJournal:
    """The agent's local task store (point 30): SQLite in the state
    dir, mode 0600. Every assignment is journaled on receipt, and
    every checkpoint is written BEFORE the agent acts on it, so a
    SIGKILL/reboot loses nothing."""

    def __init__(self, path: Path):
        import sqlite3
        # Header sanity BEFORE sqlite sees the file (v1.6.0):
        # under WAL, a garbage main file can be shadowed by a
        # still-valid -wal sidecar (page 1 lives there), so sqlite
        # would "recover" a database whose base file was destroyed
        # — masking exactly the corruption the quarantine +
        # mirror-rebuild path (point 43d) exists for. A non-empty
        # file without the SQLite header IS a corrupt journal.
        if Path(path).exists() and Path(path).stat().st_size > 0:
            with open(path, "rb") as fh:
                if fh.read(16) != b"SQLite format 3\x00":
                    raise sqlite3.DatabaseError(
                        "file is not a database")
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        # WAL + busy timeout — the relay Store's posture (v1.6.0).
        # Under sqlite defaults (rollback journal, one fsync pair
        # per commit) a single journal commit measured 80–800ms on
        # real disk, paid synchronously on the event loop for EVERY
        # assignment before its handler may start (journal-first,
        # point 30) — dispatch latency, not durability. WAL keeps
        # synchronous=FULL (the durability contract is unchanged:
        # a commit survives process death and power loss exactly
        # as before) while a commit becomes one sequential append:
        # ~25ms worst case on the same disk.
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA busy_timeout=10000")
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

    # Registration designations (probe/test segregation, v1.6.0):
    # PRODUCTION = the owner's real line; TEST = a probe/test
    # identity, filed apart in the owner's dashboard. Declared
    # ONCE, here at registration, and declared by the registering
    # side — never inferred from the username. After registration
    # the designation is the operator's to change, never the
    # agent's (the relay honours this declaration only on the
    # claiming hello).
    DESIGNATIONS = ("production", "test")

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
        designation: str = "production",
        brain=None,
        decision_link=None,
        on_decision=None,
        decision_endpoint: str | None = None,
        media: bool = False,
        workspace: str | None = None,
        recovery_key: str | None = None,
        rectify_code: str | None = None,
        rectify_intent: bool = False,
        connectors: list | None = None,
        transport: str | None = None,
        serverless_config: ServerlessConfig | None = None,
        serverless_transport: ServerlessTransport | None = None,
    ):
        u = normalize_username(username)
        if u is None and not ephemeral:
            raise ValueError(f"bad username {username!r}")
        m = str(mode or "").strip().lower()
        if m not in self.MODES:
            raise ValueError(
                f"bad mode {mode!r}: expected one of {self.MODES}")
        self.mode = m
        d = str(designation or "").strip().lower()
        if d not in self.DESIGNATIONS:
            raise ValueError(
                f"bad designation {designation!r}: expected one of "
                f"{self.DESIGNATIONS}")
        self.designation = d
        # Dual transport: the daemon runs on ONE of two data
        # paths — "serverless" (Supabase + Firebase via
        # agentlink.transport_v2, no relay anywhere) or "relay"
        # (the websocket mesh). Selection, highest first:
        #   1. the explicit transport= override;
        #   2. the AGENTLINK_TRANSPORT config flip, when set;
        #   3. an explicit NON-DEFAULT endpoint: a caller pointing
        #      this client at a specific relay (a private
        #      deployment, a test relay) means that relay;
        #   4. the default: serverless (2.0.1). The production
        #      relay behind DEFAULT_ENDPOINT retired at the v2.0
        #      cutover, so the bare default endpoint carries no
        #      relay intent — defaulting to it stranded the fleet
        #      (beulah, frozen 2026-11-04 on 2.0.0).
        # The choice is configuration only: identity, state dir,
        # mailbox, journal and handlers are identical on both
        # paths.
        _tm = str(transport or "").strip().lower()
        if not _tm:
            _env_tm = os.environ.get("AGENTLINK_TRANSPORT")
            if _env_tm:
                _tm = _env_tm.strip().lower()
            elif endpoint and str(endpoint).strip() not in \
                    ("", DEFAULT_ENDPOINT):
                _tm = "relay"
            else:
                _tm = _env_transport_mode()
        self.transport_mode = "serverless" if _tm == "serverless" \
            else "relay"
        # Serverless wiring seams: a prebuilt config (else the
        # transport builds ServerlessConfig.from_env() at start)
        # and a prebuilt transport (tests / embeddings inject
        # one; the daemon builds its own at start otherwise).
        self._serverless_config = serverless_config
        self._serverless_injected = serverless_transport
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
        # Auto decision link (v1.8.0, owner's law — "not manually.
        # not manually."): where the endpoint came from. An
        # explicitly configured endpoint ("config") is the
        # operator's own act and is trusted as such; an endpoint
        # ADOPTED from the well-known local convention
        # ("convention") had to prove it belongs to this agent
        # (nonce echo) before adoption — see _autowire_decision_link.
        self._endpoint_origin = "config" if ep else None
        # The link's living state: how it is wired (mode: config /
        # in_process / handlers / convention / none) and whether
        # the live self-check has VERIFIED the path. Resolved and
        # verified at every start() BEFORE the hello, so the first
        # hello already carries the truth; re-verified on the
        # serve loop's recheck cadence and on every real decision
        # outcome. _declared_detail_sent is the last detail JSON
        # this client declared to the relay.
        self._link_mode = "none"
        self._link_verified = False
        self._link_checked_at = 0
        self._link_task = None
        self._declared_detail_sent = ""
        # One-time admin grant (v1.8.1, owner's corrected model):
        # the grant summary the last welcome carried (None = no
        # grant on record / not yet known); my_grant() refreshes
        # it live. The grant is requested BY THIS AGENT and
        # allowed by THE AGENT'S OWN OWNER, agent-side — the
        # pending request is local state (below), mirrored at the
        # relay by a signed statement; nothing about it can be
        # created from the platform side.
        self.grant: dict | None = None
        # The CONNECTOR BRIDGE (v1.8.1): the host's registered
        # OAuth-linked connectors (agentlink.connectors), keyed
        # by name. The declared inventory derives from these;
        # broker-authorized actions execute through them, here,
        # on the agent's own host.
        self._connectors: dict = {}
        # The pending permission request (v1.8.1): created by
        # request_permission(), persisted in the state dir so the
        # owner's allow — whenever it comes — acts on a request
        # that visibly exists. Loaded after state_dir resolves.
        self._permission_request: dict | None = None
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
        # Capability declaration persistence (2.2.0): the boot
        # declare in _start_serverless re-presents
        # self.capabilities — which used to be only ever what the
        # constructor was handed, i.e. [] for every CLI one-shot
        # and daemon start. A declaration published in one session
        # was silently UNPUBLISHED by the next session's boot
        # declare (proven live: a plain `agentlink directory`
        # session reverted a drill agent's server row to []).
        # The declaration is now durable local state: loaded here
        # when the constructor did not state one explicitly (an
        # explicit constructor declaration always wins), and
        # saved by update_capabilities on every successful
        # publish.
        if capabilities is None and not ephemeral:
            self._load_capabilities_declaration()
        # Recovery keys (v1.7.0, owner's design): the agent's
        # login-back credential and its DURABLE storage contract.
        # workspace= names the agent's workspace — where its
        # documents live and the place a machine/state wipe does
        # not reach (AGENTLINK_WORKSPACE env, default ~/workspace):
        # every issued recovery key is written there at a fixed
        # path so a wiped agent can find its own way back.
        # recovery_key= is the explicit manual-reclaim credential
        # (see `agentlink reclaim`); the automatic paths discover
        # the stored copies on their own.
        self.workspace = Path(
            workspace or os.environ.get("AGENTLINK_WORKSPACE")
            or "~/workspace").expanduser()
        self._recovery_key_manual = recovery_key or None
        # The operator rectification code handed in explicitly
        # (see `agentlink rectify`); the automatic paths discover
        # a dropped-in code on their own (_find_rectify_code).
        self._rectify_code_manual = rectify_code or None
        # Explicit rectification intent (2.2.2): set ONLY by the
        # `agentlink rectify` command. In this mode a held code
        # is PRESENTED to the Edge — never swallowed by a key
        # login that happens to open the session first (the
        # false-success defect: the command printed "rectified"
        # while the code sat unburned server-side, no rebind
        # happened and no new recovery key existed).
        self._rectify_intent = bool(rectify_intent)
        # Which ceremony opened this session (2.2.2) — the
        # truthful-reporting record the rectify command's report
        # is built from: "registered", "recovered", "rectified",
        # "key-login" (the self-collision rescue) or "plain"
        # (the direct key login). None until a session opens.
        self.session_ceremony: str | None = None
        # Whether an operator rectification code was PRESENTED
        # to the Edge in this run (2.2.2). Presented is not
        # accepted: session_ceremony == "rectified" is the only
        # proof the Edge accepted it.
        self._rectify_presented = False
        # The most recently issued/used recovery key (plaintext —
        # held by the agent itself, exactly like its identity
        # keys; the server only ever holds the hash) and the
        # workspace file that carries its durable copy.
        self.recovery_key: str | None = None
        self.recovery_file: str | None = None
        self.ephemeral = ephemeral
        # Connector bridge (v1.8.1): register the host's
        # connectors and restore any pending permission request.
        for _conn in connectors or []:
            self._register_connector_local(_conn)
        self._load_permission_request()
        # Unreadable park journal (2.0.10): message ids whose
        # decryption has failed, with attempt counts and the
        # next retry time — the backoff state that keeps a bad
        # envelope from being retried in a hot loop (class A).
        self._unreadable: dict[str, dict] = {}
        self._load_unreadable()
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
        # Serverless session state (v2.0 daemon port): the live
        # ServerlessTransport while a serverless session runs
        # (None on the relay path and while disconnected), the
        # stop event its supervision threads obey, the threads
        # themselves, the event serve() waits on, the loop the
        # transport threads deliver frames into, and the local
        # heartbeat-stamp task (the watchdog contract the relay
        # path's _ping_loop maintains — see _v2_stamp_loop).
        self._v2: ServerlessTransport | None = None
        self._v2_stop: threading.Event | None = None
        self._v2_threads: list[threading.Thread] = []
        self._v2_down: asyncio.Event | None = None
        self._v2_loop: asyncio.AbstractEventLoop | None = None
        self._v2_stamp_task: asyncio.Task | None = None
        self._v2_close_requested = False
        # Counterparty activeness as the scoped presence watcher
        # reports it (v2.0): username -> ladder state, plus the
        # event log ({"username", "state", "ts"} per change).
        self.presence_peers: dict[str, str] = {}
        self.presence_events: list[dict] = []
        # Close-code telemetry (v1.6.2): the last session socket's
        # close code/reason, captured by the read loop when the
        # connection dies, so the session-end log can name WHY the
        # session ended (before this, client logs recorded a bare
        # disconnect line and forensics could not name the trigger).
        self._closed_code = None
        self._closed_reason = ""
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
        self._pubkey_cache: dict[str, tuple[str, float]] = {}
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
        # True once a hello frame has actually been written on
        # some connection (v1.8.0): decision_link_update frames
        # may only ever FOLLOW a hello — one racing ahead of the
        # hello on a fresh socket is protocol garbage at the
        # relay's auth gate. The hello carries the state anyway.
        self._hello_sent = False
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
                _quarantine_db_file(jpath)
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
                _quarantine_db_file(mpath)
                try:
                    self.mailbox = Mailbox(mpath, owner=self.username)
                except Exception:
                    self.mailbox = None
            self._mailbox = self.mailbox
        # Persistent send outbox (2.0.10, class B): sends that
        # meet a dead network window queue here and flush until
        # the server confirms — a proxy window can delay a send,
        # never lose it or wedge the daemon.
        self._outbox: Outbox | None = None
        if not ephemeral and self.username:
            try:
                self._outbox = Outbox(
                    self.state_dir / f"outbox-{self.username}.json")
            except Exception:
                self._outbox = None
        # Ids claimed by a live dispatch (or a replay) in this
        # process: the guard that makes journal-then-dispatch
        # exactly-once when a queued flush, a history sync and the
        # start-of-session replay all race over the same item.
        self._takein_inflight: set[str] = set()
        # Rooms whose admins this session has already asked to
        # re-issue a key wrap (2.0.6 self-heal; see _ask_key_reissue).
        self._key_reissue_asked: set = set()
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
            elif cmd == "whoami":
                # The running instance's own truthful surface
                # (2.2.3): setup's already-registered fast path
                # reads the DAEMON's recovery-held / grant /
                # decision-link state through here instead of
                # guessing from a rival process. whoami() never
                # carries a secret — the recovery KEY stays in
                # its files; only held/not-held crosses.
                result = self.whoami()
            elif cmd == "presence":
                # My own presence record, read back through MY
                # authenticated doorbell (2.2.3): the rival
                # process in setup's fast path holds no Firebase
                # token (its fresh doorbell can only fail with
                # "no Firebase custom token"), while this daemon
                # is the beat's writer — reading the node back
                # through it proves the beat landed server-side.
                if self._v2 is None:
                    raise ValueError(
                        "presence is a serverless surface; this "
                        "instance runs the relay transport")
                result = await asyncio.to_thread(
                    self._v2.doorbell.read_presence, self.username)
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
                    notes=str(spec.get("notes") or ""),
                    auth_type=str(spec.get("auth_type")
                                  or "password"))
            elif cmd == "vault_get":
                result = await self.vault.get(
                    str(spec["service_or_id"]))
            elif cmd == "vault_list":
                result = {"entries": await self.vault.list()}
            elif cmd == "vault_remove":
                result = await self.vault.remove(
                    str(spec["entry_id"]))
            elif cmd == "work_inbox":
                # Read-only one-shots forward too (2.0.10,
                # class E): a read must never die with
                # instance_collision just because the daemon
                # holds the state dir — the daemon IS the
                # reader. (Beulah's `agentlink work inbox`
                # refused on every check since 1.3.7 while her
                # daemon ran.) Write commands keep the
                # existing send/group_add/vault discipline.
                result = {"items": await self.work_inbox()}
            elif cmd == "work_progress":
                # The work lifecycle writes join the forward
                # set (2.2.0, sweep): an operator driving a
                # daemon-running agent through CLI one-shots
                # could read the inbox but could not progress,
                # deliver or review — the write side of
                # Beulah's class-E refusal. Same trust boundary
                # as send/vault_put: same user, socket 0600,
                # per-boot token, executed AS the daemon.
                result = await self.report_progress(
                    str(spec["work_id"]),
                    int(spec.get("percent") or 0),
                    str(spec.get("note") or ""))
            elif cmd == "work_deliver":
                result = await self.deliver_work(
                    str(spec["work_id"]),
                    str(spec.get("body") or ""),
                    [str(f) for f in (spec.get("files") or [])])
            elif cmd == "work_assign":
                if spec.get("role"):
                    result = await self.assign_work_role(
                        str(spec.get("group_id") or ""),
                        str(spec["role"]),
                        str(spec.get("title") or ""),
                        str(spec.get("instructions") or ""),
                        attachments=[str(f) for f in
                                     (spec.get("attachments")
                                      or [])],
                        deadline=spec.get("deadline"),
                        priority=str(spec.get("priority")
                                     or "normal"),
                        require_approval=bool(
                            spec.get("require_approval")))
                else:
                    result = await self.assign_work(
                        [str(x) for x in
                         (spec.get("assignees") or [])],
                        str(spec.get("title") or ""),
                        str(spec.get("instructions") or ""),
                        group_id=spec.get("group_id"),
                        attachments=[str(f) for f in
                                     (spec.get("attachments")
                                      or [])],
                        deadline=spec.get("deadline"),
                        priority=str(spec.get("priority")
                                     or "normal"),
                        require_approval=bool(
                            spec.get("require_approval")))
            elif cmd == "work_complete":
                result = await self.complete_work(
                    str(spec["work_id"]),
                    str(spec.get("note") or ""))
            elif cmd == "work_approve":
                result = await self.approve_work(
                    str(spec["work_id"]),
                    str(spec.get("note") or ""))
            elif cmd == "work_reject":
                result = await self.reject_work(
                    str(spec["work_id"]),
                    str(spec.get("note") or ""))
            elif cmd == "work_request_changes":
                result = await self.request_changes(
                    str(spec["work_id"]),
                    str(spec.get("note") or ""))
            elif cmd == "directory":
                result = await self.directory(
                    query=str(spec.get("query") or ""))
            elif cmd == "sync_history":
                result = await self.sync_history()
            elif cmd == "delivery_status":
                result = await self.delivery_status(
                    str(spec["message_id"]))
            elif cmd == "chain_list":
                result = {"chains": await self.chain_list()}
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
                             password: str, notes: str = "",
                             auth_type: str = "password",
                             grant_receipt: str = "") -> dict:
        """THE auto-save path (owner's order): the one call an agent
        — or its account-creation helper — makes the moment it
        creates an account, so the login (service, account email /
        username, password) lands in its own vault automatically.
        No permission, no prompt. Flat alias of
        ``agent.vault.remember(...)``; returns the saved entry.
        ``grant_receipt`` (v1.8.0) stamps the entry with the id of
        the signed grant receipt under which the account was
        created, for the dashboard's provenance column."""
        return await self.vault.remember(
            service, username, password, notes, auth_type=auth_type,
            grant_receipt=grant_receipt)

    async def _vault_publish(self) -> None:
        """Upload the current vault document through the blob layer
        and publish its pointer + oversight-sealed envelopes (the
        labels for the Agents cell, and since v1.5.0 the full
        content for the owner's Credentials view). The old
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
            "content": core.content_envelope(self.oversight_pubkey),
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
        if self._ws is None and self._v2 is None:
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
        if self._control_server is None:
            # Not serving: the socket file at this path belongs
            # to the RUNNING instance, not to this object. A
            # rival that met the instance collision (setup's
            # already-registered fast path builds exactly such
            # an object and closes it in its finally) must never
            # unlink the daemon's channel out from under it —
            # the first successful setup run silently killed the
            # channel for every later one (2.2.3 drill round 2:
            # the daemon stayed online while its control socket
            # vanished). Only the serving object removes its own
            # socket, exactly as _release_instance_lock only
            # releases a lock this object actually holds.
            return
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

    # -- recovery keys (v1.7.0) -------------------------------------
    # The owner's storage law: a recovery key is written to BOTH
    # the client state dir AND a fixed path in the agent's
    # WORKSPACE — the durable document store that survives the
    # machine/state wipe the key exists for. One copy in the very
    # place that can be wiped would be a spare key kept inside the
    # locked house.

    def _recovery_state_path(self) -> Path:
        return self.state_dir / f"recovery-{self.username}.json"

    def _recovery_workspace_path(self) -> Path:
        return self.workspace / f"agentlink-recovery-{self.username}.txt"

    def _save_recovery_key(self, key: str) -> None:
        """Persist an issued recovery key per the storage contract
        (both copies, 0600, atomic) and SURFACE it: the key, the
        exact file paths, and the instruction — so the agent can
        also record it in its own long-term memory."""
        if not key or self.ephemeral or not self.username:
            return
        self.recovery_key = key
        # (a) the state-dir copy — the fast local copy, in the
        # _save_secret atomic pattern.
        p = self._recovery_state_path()
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"username": self.username,
                                   "endpoint": self.endpoint,
                                   "recovery_key": key}))
        os.replace(tmp, p)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        # (b) THE WORKSPACE FILE — plain text that explains itself
        # to whichever future instance of the agent finds it after
        # a wipe, with the owner's warning inside it.
        wp = self._recovery_workspace_path()
        try:
            self.workspace.mkdir(parents=True, exist_ok=True)
            wtmp = wp.with_suffix(".txt.tmp")
            wtmp.write_text(
                f"AgentLink recovery key — @{self.username}\n"
                f"username: {self.username}\n"
                f"endpoint: {self.endpoint}\n"
                f"recovery_key: {key}\n"
                f"\n"
                f"NEVER DELETE THIS FILE. This is your AgentLink "
                f"recovery key — the only way back into "
                f"@{self.username} if this machine or your client "
                f"state is wiped. Boot your client with this "
                f"workspace intact (or run `agentlink reclaim`) "
                f"and present it: everything — conversations, "
                f"groups, vault, unread messages — is restored, "
                f"because it all lives server-side under your "
                f"username. Keep a copy in your own long-term "
                f"memory as well. Whoever holds this key IS "
                f"@{self.username}: guard it like a private key. "
                f"When you use it, it burns and a new one is "
                f"issued into this file.\n")
            os.replace(wtmp, wp)
            try:
                os.chmod(wp, 0o600)
            except OSError:
                pass
            self.recovery_file = str(wp)
        except Exception:
            log.exception("could not write the workspace recovery "
                          "file at %s", wp)
        log.warning(
            "RECOVERY KEY issued for @%s — this is your login-back "
            "credential, the ONLY way back into your account if "
            "this machine or your client state is ever wiped. It "
            "is saved in your client state (%s) and in your "
            "workspace (%s). RECORD IT IN YOUR OWN LONG-TERM "
            "MEMORY AS WELL. Never share it: whoever holds it IS "
            "@%s.", self.username, p, wp, self.username)

    def _find_recovery_key(self) -> str | None:
        """Discover a stored recovery key: the WORKSPACE file
        first (the durable copy that survives a client-state
        wipe), then the state-dir copy. None when this agent
        holds no key anywhere.

        A stored copy is SCOPED to the line that issued it: the
        endpoint recorded in the copy must be this client's
        configured home endpoint. A leftover copy from another
        line (a test relay, a previous deployment, a different
        network) is never presented — a credential is not
        sprayed at lines that did not issue it, and a stale
        file can never turn a fresh registration on a new line
        into a refused recovery attempt."""
        if self.ephemeral or not self.username:
            return None
        home = str(self.endpoint or "")
        try:
            wp = self._recovery_workspace_path()
            if wp.exists():
                key = ""
                ep = ""
                for line in wp.read_text().splitlines():
                    if line.startswith("recovery_key:"):
                        key = line.split(":", 1)[1].strip()
                    elif line.startswith("endpoint:"):
                        ep = line.split(":", 1)[1].strip()
                if key and (not ep or ep == home):
                    return key
        except Exception:
            pass
        try:
            p = self._recovery_state_path()
            if p.exists():
                data = json.loads(p.read_text())
                key = data.get("recovery_key")
                ep = str(data.get("endpoint") or "")
                if key and (not ep or ep == home):
                    return str(key)
        except Exception:
            pass
        return None

    def _rectify_workspace_path(self) -> Path:
        return self.workspace / f"agentlink-rectify-{self.username}.txt"

    def _find_rectify_code(self) -> str | None:
        """Discover an operator rectification code (v2.0.9): the
        code handed in explicitly, then the AGENTLINK_RECTIFY_CODE
        environment variable, then the drop-in file in the
        workspace (the owner places the operator's code there —
        a bare code line, or the self-describing
        ``rectify_code:`` line). None when no code is held.

        No endpoint scoping (unlike the recovery key): a code is
        single-use, short-lived and bound to this username
        server-side — a stale or foreign code simply fails the
        Edge's hash check and burns nothing."""
        if self.ephemeral or not self.username:
            return None
        if self._rectify_code_manual:
            return self._rectify_code_manual
        env_code = os.environ.get("AGENTLINK_RECTIFY_CODE", "").strip()
        if env_code:
            return env_code
        try:
            wp = self._rectify_workspace_path()
            if wp.exists():
                for line in wp.read_text().splitlines():
                    line = line.strip()
                    if line.startswith("rectify_code:"):
                        code = line.split(":", 1)[1].strip()
                        if code:
                            return code
                    elif line and not line.startswith("#"):
                        return line
        except Exception:
            pass
        return None

    def _drop_rectify_code_file(self) -> None:
        """Remove the drop-in code file after a successful
        rectification: the code is burned server-side, and no
        copy of a spent credential should linger in the
        workspace."""
        try:
            wp = self._rectify_workspace_path()
            if wp.exists():
                wp.unlink()
        except Exception:
            pass

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
        # Recovery surface (v1.7.0): whether this agent HOLDS a
        # recovery key — its login-back credential — and the
        # workspace file that carries the durable copy. The key
        # itself is never printed here (it lives in the files and
        # in the agent's own memory, nowhere else).
        _rec_held = bool(self.recovery_key or self._recovery_key_manual)
        _rec_file = self.recovery_file
        if self.username and not self.ephemeral:
            try:
                if self._find_recovery_key():
                    _rec_held = True
                _wp = self._recovery_workspace_path()
                if _rec_file is None and _wp.exists():
                    _rec_file = str(_wp)
            except Exception:
                pass
        # Rectification surface (2.2.2): whether an operator
        # rectification code is currently held (handed in, in
        # the environment, or in the workspace drop-in).
        _rect_held = False
        if self.username and not self.ephemeral:
            try:
                _rect_held = bool(self._find_rectify_code())
            except Exception:
                _rect_held = False
        return {"username": self.username,
                "display_name": self.display_name,
                "designation": self.designation,
                "endpoint": self.endpoint,
                "endpoints": list(self.endpoints),
                "servers": list(self.known_servers),
                "recovery_key_held": _rec_held,
                "recovery_file": _rec_file,
                # Ceremony truth (2.2.2): which ceremony opened
                # this session and whether an operator
                # rectification code was presented / is held —
                # the fields the `agentlink rectify` report is
                # built from, so "rectified" is claimed only
                # when a rectification actually happened.
                "session_ceremony": self.session_ceremony,
                "rectify_presented": self._rectify_presented,
                "rectify_code_held": _rect_held,
                # Onboarding surface (v1.8.0): the agent states
                # its own decision-link wiring truthfully (mode +
                # verified state — the same facts its hello
                # declares) and its admin grant summary as the
                # last welcome carried it; my_grant() refreshes
                # the grant live. No grant is ever implied:
                # absent is None.
                "decision_link": self.decision_link_state,
                # Grant + connector vault (v1.8.1): the grant
                # summary, the PENDING permission request when
                # one exists (the local surface the owner's allow
                # acts on), the declared connector inventory with
                # linked states, and the capabilities the vault
                # confers.
                "grant": self.grant,
                "permission_request": self._permission_request,
                "connectors": self.connector_inventory(),
                "derived_capabilities":
                    self.derived_capabilities(),
                # Dead-letter surface (2.3.0): deliveries that
                # exhausted the retry policy and parked — the
                # count is always present; the records ride
                # along so an operator sees WHAT parked without
                # opening the state dir.
                "dead_letters": len(self._v2.dead_letters)
                if self._v2 is not None else 0,
                "dead_letter_records": self._v2.dead_letters.records()
                if self._v2 is not None else []}

    # -- connector bridge + one-time admin grant (v1.8.1) --------
    # The owner's corrected model, end to end:
    # * THE AGENT ASKS. request_permission() creates a pending
    #   permission REQUEST — local state, visible in whoami() —
    #   and presents it to the relay under the agent's signature.
    # * THE AGENT'S OWNER ALLOWS, agent-side. allow_permission()
    #   is the owner's ceremony entry (driven by the owner's own
    #   tooling in this agent's environment — e.g. `agentlink
    #   grant allow`): it signs the ALLOW statement over the
    #   pending request with the agent's identity key and
    #   presents it; only then does the grant exist. The
    #   platform operator has no path into this flow at all.
    # * THE SUBSTANCE IS THE CONNECTOR VAULT: OAuth-linked
    #   connectors the host bridges in (connectors= /
    #   register_connector). The grant covers the whole vault;
    #   the advertised capability profile is synthesized from it.
    # * ACTIONS: connector_action() asks the relay broker to
    #   AUTHORIZE (grant active x connector in the vault and
    #   linked x not a red line x rate room), executes HERE
    #   through the bridge, and reports the outcome for
    #   receipting. Red lines queue for THE AGENT'S OWNER
    #   (pending_approvals / decide_approval), never the
    #   platform. Payment instruments are outside this surface
    #   entirely — a payment-shaped action class cannot even be
    #   declared (connectors.lawful_action_class).

    # -- the bridge registry -------------------------------------

    def _register_connector_local(self, connector) -> None:
        name = str(getattr(connector, "name", "") or "").strip()
        if not name:
            raise ValueError("a bridged connector needs a name")
        self._connectors[name] = connector

    def connector_inventory(self) -> list[dict]:
        """The declared inventory of the agent's connector
        vault: one entry per bridged connector — name, service,
        label, LINKED state, the OAuth scopes the user granted
        the service, its action table, its explicit
        capabilities. This is what the hello declares and what
        connector_update re-declares."""
        return [c.inventory_entry()
                for c in self._connectors.values()]

    def derived_capabilities(self) -> list[str]:
        """The capabilities the connector vault confers
        (connectors.derived_capabilities over the inventory —
        linked connectors only)."""
        from .connectors import derived_capabilities as _derived
        return _derived(self.connector_inventory())

    def advertised_capabilities(self) -> list[str]:
        """The capability profile the line sees: the declared
        capabilities UNION the connector-derived set (declared
        first, platform cap 32 — the same bound the relay
        enforces on capability updates)."""
        out = list(self.capabilities)
        for tag in self.derived_capabilities():
            if tag not in out:
                out.append(tag)
        return [str(c)[:40] for c in out][:32]

    async def register_connector(self, connector) -> dict:
        """Bridge a connector in (the owner connected a service
        on this agent's side). The inventory is re-declared to
        the relay under signature and the advertised profile
        re-synthesized — the new connector's derived
        capabilities appear on the line, and the grant covers
        the connector from this moment."""
        self._register_connector_local(connector)
        return await self._declare_connectors()

    async def unregister_connector(self, name: str) -> dict:
        """Bridge a connector OUT (the owner disconnected it).
        Its derived capabilities leave the advertised profile
        and the grant stops covering it — both on the next
        declaration, which this call makes immediately."""
        self._connectors.pop(str(name or ""), None)
        return await self._declare_connectors()

    async def _declare_connectors(self) -> dict:
        """Re-declare the vault + the synthesized profile to the
        relay (signed connector_update + signed
        update_capabilities). Offline: returns the local truth;
        the next hello re-declares everything anyway."""
        inventory = self.connector_inventory()
        if (self._ws is None and self._v2 is None) \
                or self.identity is None:
            return {"connectors": len(inventory),
                    "derived_capabilities":
                        self.derived_capabilities(),
                    "declared": False}
        from .protocol import inventory_digest
        out = await self._statement_request(
            "connector_update", "connector_update",
            {"inventory_digest": inventory_digest(inventory)},
            extra={"connectors": inventory})
        await self.update_capabilities(self.capabilities,
                                       self.cap_description)
        if isinstance(out, dict):
            out["declared"] = True
        return out

    # -- the capability declaration (durable local state, 2.2.0) --

    def _capabilities_path(self) -> Path:
        return self.state_dir / \
            f"capabilities-{self.username}.json"

    def _load_capabilities_declaration(self) -> None:
        """Adopt the declaration a previous session published
        (see the __init__ note). Constructor-stated values have
        already won by the time this runs — it only fills what
        the constructor left unstated."""
        if not self.username:
            return
        try:
            p = self._capabilities_path()
            if not p.exists():
                return
            data = json.loads(p.read_text())
            if not isinstance(data, dict):
                return
            caps = data.get("capabilities")
            if isinstance(caps, list) and caps:
                merged = [str(c) for c in caps]
                # The media leg's marker is computed fresh at
                # every construction; never let a stored
                # declaration drop it.
                if "media_audio" in self.capabilities \
                        and "media_audio" not in merged:
                    merged.append("media_audio")
                self.capabilities = merged
            desc = data.get("description")
            if isinstance(desc, str) and desc \
                    and not self.cap_description:
                self.cap_description = desc
        except Exception:
            pass

    def _save_capabilities_declaration(self) -> None:
        """Persist the declaration update_capabilities just
        published, so the next session's boot declare re-presents
        IT — not the constructor default. Best-effort: a failed
        save must never fail the publish it rode on."""
        if self.ephemeral or not self.username:
            return
        try:
            p = self._capabilities_path()
            p.write_text(json.dumps({
                "capabilities": list(self.capabilities),
                "description": self.cap_description,
                "ts": int(time.time())}))
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        except Exception:
            pass

    # -- the permission request (agent-initiated) ------------------

    def _permission_request_path(self) -> Path:
        return self.state_dir / \
            f"permission-request-{self.username}.json"

    def _load_permission_request(self) -> None:
        if self.ephemeral or not self.username:
            return
        try:
            p = self._permission_request_path()
            if p.exists():
                data = json.loads(p.read_text())
                if isinstance(data, dict) and data.get("id"):
                    self._permission_request = {
                        "id": str(data["id"]),
                        "reason": str(data.get("reason") or ""),
                        "ts": int(data.get("ts") or 0)}
        except Exception:
            self._permission_request = None

    def _save_permission_request(self) -> None:
        if self.ephemeral or not self.username \
                or self._permission_request is None:
            return
        try:
            p = self._permission_request_path()
            tmp = p.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(self._permission_request))
            os.replace(tmp, p)
            try:
                os.chmod(p, 0o600)
            except OSError:
                pass
        except Exception:
            log.exception("could not persist the permission "
                          "request for @%s", self.username)

    def _clear_permission_request(self) -> None:
        self._permission_request = None
        if self.ephemeral or not self.username:
            return
        try:
            self._permission_request_path().unlink(missing_ok=True)
        except Exception:
            pass

    @property
    def permission_request(self) -> dict | None:
        """The pending permission request, if one exists — the
        agent's own ask, awaiting its owner's allow."""
        return self._permission_request

    # -- signed statements ------------------------------------------

    def _sign_statement(self, kind: str,
                        fields: dict) -> tuple[dict, str]:
        from .protocol import grant_statement_payload
        stmt = {"kind": kind, "ts": now_ts()}
        stmt.update(fields)
        payload = grant_statement_payload(
            kind, self.username, stmt["ts"], fields)
        return stmt, self.identity.sign(payload)

    async def _statement_request(self, ftype: str, kind: str,
                                 fields: dict,
                                 extra: dict | None = None) -> dict:
        """Present a signed grant statement and return the
        relay's answer; a refusal comes back as an outcome dict
        ({"status": "refused", "reason": ...}) rather than an
        exception — a refused statement is a fact to state, not
        a crash."""
        stmt, sig = self._sign_statement(kind, fields)
        frame = {"type": ftype, "statement": stmt, "sig": sig}
        if extra:
            frame.update(extra)
        try:
            return await self._request(frame, timeout=15.0)
        except RequestFailed as exc:
            return {"status": "refused", "reason": exc.reason}
        except Exception as exc:
            return {"status": "refused",
                    "reason": f"statement not delivered: {exc}"}

    async def request_permission(self, reason: str = "") -> dict:
        """THE AGENT ASKS (v1.8.1): create the one-time
        permission request and present it to the relay under the
        agent's signature. The request is durable local state —
        it survives restarts and stays visible in whoami() —
        until the agent's owner allows it (allow_permission) or
        it is superseded. Returns {"status": "requested",
        "request": {...}} (or the active grant, if one already
        stands)."""
        if self.grant and self.grant.get("status") == "active":
            return {"status": "active", "grant": self.grant}
        if self._permission_request is None:
            self._permission_request = {
                "id": new_id("greq-"),
                "reason": str(reason or "")[:500],
                "ts": now_ts()}
            self._save_permission_request()
        req = self._permission_request
        if self._ws is not None or self._v2 is not None:
            out = await self._statement_request(
                "grant_request", "request",
                {"request_id": req["id"],
                 "reason": req["reason"]})
            if isinstance(out, dict) and out.get("grant"):
                self.grant = out["grant"]
        log.warning(
            "PERMISSION REQUESTED by @%s (request %s): this "
            "agent has asked its owner for the one-time admin "
            "permission over its connector vault. The OWNER "
            "allows it on this agent's side — `agentlink grant "
            "allow` in this agent's environment — once; the "
            "platform cannot allow it and cannot issue it.",
            self.username, req["id"])
        return {"status": "requested", "request": dict(req)}

    async def allow_permission(self, grantor: str = "") -> dict:
        """THE OWNER'S ALLOW (v1.8.1) — the one-time permission
        itself. This is the owner's ceremony entry point, driven
        by the owner's own tooling in the agent's environment
        (`agentlink grant allow --by <owner>`): it signs the
        ALLOW statement over the agent's pending request with
        the agent's identity key and presents it; the relay
        activates the grant ONLY against a recorded request.
        `grantor` attests WHO allowed it (the agent's owner) —
        recorded on the grant for the oversight dashboard."""
        req = self._permission_request
        if req is None:
            return {"status": "refused",
                    "reason": "no pending permission request — "
                              "the agent must ask first "
                              "(request_permission)"}
        from .protocol import inventory_digest
        out = await self._statement_request(
            "grant_allow", "allow",
            {"request_id": req["id"],
             "grantor": str(grantor or "agent-owner")[:80],
             "inventory_digest": inventory_digest(
                 self.connector_inventory())})
        if isinstance(out, dict) and out.get("grant"):
            self.grant = out["grant"]
            self._clear_permission_request()
        return out

    async def revoke_permission(self) -> dict:
        """THE OWNER'S KILL SWITCH (v1.8.1), agent-side: a
        signed revoke statement; the broker refuses the very
        next action. (Agent-side like the allow — the platform
        has no revoke button either.)"""
        out = await self._statement_request(
            "grant_revoke", "revoke", {})
        if isinstance(out, dict) and "grant" in out:
            self.grant = out["grant"]
        return out

    async def _resend_permission_request(self) -> None:
        """After a (re)connect: if a pending request exists
        locally but the relay holds no grant record, present the
        request again so the relay's requested state — and the
        dashboard's — is the truth."""
        try:
            if self._permission_request is None:
                return
            if self.grant and self.grant.get("status") in (
                    "requested", "active"):
                return
            req = self._permission_request
            out = await self._statement_request(
                "grant_request", "request",
                {"request_id": req["id"],
                 "reason": req["reason"]})
            if isinstance(out, dict) and out.get("grant"):
                self.grant = out["grant"]
        except Exception:
            pass

    # -- grant state + brokered actions ------------------------------

    async def my_grant(self) -> dict | None:
        """The agent's exact current grant: {"status",
        "grantor", "granted_at", "requested_at", "coverage"} or
        None when no grant is on record. Read live from the
        relay (the welcome cache is only the fallback when the
        query cannot complete). 'Show my grant' also carries the
        declared vault: see my_connectors()."""
        if self._ws is not None or self._v2 is not None:
            try:
                out = await self._request(
                    {"type": "grant_query"}, timeout=10.0)
                self.grant = out.get("grant")
                return self.grant
            except Exception:
                pass
        return self.grant

    async def my_connectors(self) -> dict:
        """The agent's connector vault as the RELAY holds it:
        {"grant", "connectors", "derived_capabilities"} — the
        linkage truth both sides agree on."""
        if self._ws is not None or self._v2 is not None:
            out = await self._request({"type": "grant_query"},
                                      timeout=10.0)
            self.grant = out.get("grant")
            return out
        return {"grant": self.grant,
                "connectors": self.connector_inventory(),
                "derived_capabilities":
                    self.derived_capabilities()}

    async def connector_action(self, connector: str, action: str,
                               params: dict | None = None,
                               work_ref: str = "") -> dict:
        """Run ONE brokered connector action under the grant:
        the relay AUTHORIZES (grant active x connector in the
        vault and linked x not a red line x rate room), this
        host EXECUTES through the bridge, and the outcome is
        reported back for its signed receipt. Returns the
        outcome dict: {"status": "executed", "receipt_id",
        "result", ...} on success; "refused" (with the refusal
        receipt_id) when the gate says no; "awaiting_approval"
        (with approval_id) when the action crosses a red line —
        it then waits for THE AGENT'S OWNER, not the platform;
        "rate_limited"; "error" (executed locally, failed —
        still receipted).

        ISOLATION: this door reaches ONLY this agent's own
        bridged connectors under this agent's own grant. There
        is deliberately no way to name another agent here —
        cross-agent help travels as assigned work, executed by
        the capable agent through its own connector."""
        params = dict(params or {})
        out = await self._request(
            {"type": "grant_action", "connector": connector,
             "action": action, "params": params,
             "work_ref": work_ref}, timeout=30.0)
        if not isinstance(out, dict) \
                or out.get("status") != "authorized":
            return out
        token = out.get("authorization") or ""
        return await self._execute_authorized(
            token, connector, action, params)

    # Back-compat name (v1.8.0): the brokered door, same call.
    grant_action = connector_action

    async def _execute_authorized(self, token: str, connector: str,
                                  action: str,
                                  params: dict) -> dict:
        """Execute one authorized action through the local
        bridge and report its outcome for receipting. A
        connector the relay authorized but this host does not
        bridge is reported as an error — never silently dropped,
        never fabricated as executed."""
        conn = self._connectors.get(connector)
        if conn is None:
            rep = await self._request(
                {"type": "grant_report", "authorization": token,
                 "status": "error",
                 "error": f"connector {connector!r} is not "
                          f"bridged on this host"},
                timeout=15.0)
            rep.setdefault("status", "error")
            return rep
        try:
            result = conn.execute(action, params, self.username)
            if inspect.isawaitable(result):
                result = await result
            if result is None:
                result = {}
            if not isinstance(result, dict):
                result = {"value": result}
        except Exception as exc:
            rep = await self._request(
                {"type": "grant_report", "authorization": token,
                 "status": "error", "error": str(exc)[:500]},
                timeout=15.0)
            rep.setdefault("status", "error")
            rep.setdefault("reason", str(exc)[:500])
            return rep
        rep = await self._request(
            {"type": "grant_report", "authorization": token,
             "status": "executed", "result": result},
            timeout=15.0)
        rep.setdefault("status", "executed")
        rep.setdefault("result", result)
        return rep

    async def pending_approvals(self) -> list[dict]:
        """The agent's OWN red-line approval queue (v1.8.1):
        the actions waiting for THE AGENT'S OWNER's decision,
        read live from the relay."""
        out = await self._request({"type": "grant_approvals"},
                                  timeout=10.0)
        return (out or {}).get("approvals") or []

    async def decide_approval(self, approval_id: str,
                              approved: bool,
                              decided_by: str = "") -> dict:
        """THE AGENT OWNER'S red-line decision (v1.8.1),
        presented from the agent's side under the agent's
        signature. On approval the relay re-gates and returns
        the authorization; this host then executes the stored
        action through the bridge and reports it — the
        execution receipt ties back to the approval. On
        rejection the action simply never executes."""
        out = await self._statement_request(
            "grant_decide", "decide",
            {"approval_id": str(approval_id),
             "approved": bool(approved),
             "decided_by": str(decided_by or "agent-owner")[:80]})
        if not isinstance(out, dict) \
                or out.get("status") != "authorized":
            return out
        approval = None
        for row in await self.pending_approvals():
            if row.get("id") == approval_id:
                approval = row
                break
        if approval is None:
            return {"status": "error",
                    "reason": "approved but the approval record "
                              "could not be re-read; nothing "
                              "executed"}
        return await self._execute_authorized(
            out.get("authorization") or "",
            approval["connector"], approval["action"],
            approval.get("params") or {})

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
                # The legacy connect() used above has no proxy
                # support, so the fallback dials through the
                # asyncio client — racing the freshly resolved
                # proxy credentials (proxycreds), never just the
                # process env a rotation strands.
                return await _dial_via_proxy_candidates(url)
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

    # -- serverless transport (v2.0 daemon port) ----------------------------
    # The daemon loop on agentlink.transport_v2: same Agent, same
    # identity / mailbox / journal / handlers — only the wire
    # changes. start() branches here when the AGENTLINK_TRANSPORT
    # flip (or transport=) selects "serverless"; run()/serve()/
    # close() branch with it, and _request/_send_ack route the
    # data path onto the transport. The relay path above/below is
    # untouched and remains the default + live fallback until the
    # serverless cutover.

    def _serverless(self) -> bool:
        return self.transport_mode == "serverless"

    def _make_v2_transport(self) -> ServerlessTransport:
        if self._serverless_injected is not None:
            transport = self._serverless_injected
        else:
            # Dead-letter park (2.3.0): rooted in THIS agent's
            # state dir, so a delivery that exhausts the retry
            # policy leaves a durable, operator-visible record.
            from .retry import DeadLetterPark
            transport = ServerlessTransport(
                self._serverless_config or ServerlessConfig.from_env(),
                dead_letter_park=DeadLetterPark(
                    str(self.state_dir / "dead-letter.jsonl")))
        # Recovery enrollment (2.2.3): whichever login path the
        # transport takes (start, refresh, 401 backstop), an
        # enrollment key the Edge hands back lands in the
        # storage contract through this sink — never dropped
        # because the login that carried it was a background
        # re-login nobody was watching.
        transport.on_recovery_enrollment = self._adopt_enrollment_key
        # Dead-letter surfacing (2.3.0): a parked delivery is a
        # WARNING in the daemon log the moment it parks, and the
        # record itself lives in the park (state-dir JSONL +
        # transport.dead_letters) for diagnostics.
        transport.on_dead_letter = self._on_v2_dead_letter
        return transport

    def _on_v2_dead_letter(self, record: dict) -> None:
        log.warning(
            "dead-letter: %s %s to @%s parked after %s attempts "
            "(%s) — see dead-letter.jsonl in the state dir",
            record.get("kind"), record.get("item_id"),
            record.get("to") or "-", record.get("attempts"),
            record.get("last_error") or "")

    def _adopt_enrollment_key(self, key: str) -> None:
        if not key or self.ephemeral:
            return
        self._save_recovery_key(key)
        log.warning(
            "recovery key ENROLLED for @%s — the account had "
            "none on file (its registration reply never landed); "
            "the key is saved in the client state and the "
            "workspace file.", self.username)

    def _v2_fanout(self) -> str:
        """Presence subscription fan-out for the daemon wiring:
        "digest" by default (the Phase 1 quota valve — peer
        records ride 30s-coalesced digest nodes; activeness-
        critical work counterparties stay on raw presence).
        AGENTLINK_PRESENCE_FANOUT=presence selects raw streams
        for every counterparty (small-fleet mode)."""
        mode = str(os.environ.get("AGENTLINK_PRESENCE_FANOUT")
                   or "digest").strip().lower()
        return mode if mode in ("presence", "digest") else "digest"

    def _v2_critical_set(self) -> set:
        """Activeness-critical counterparties (the watcher's raw-
        presence class): my current work's assigners + assignees."""
        out = set()
        for w in self.assigned_work:
            for k in ("assigner", "assignee"):
                if w.get(k):
                    out.add(str(w[k]))
        out.discard(self.username)
        return out

    def _v2_counterparty_set(self) -> set:
        """The scoped-subscription set, built from the membership
        data this client already holds: DM peers from the local
        mailbox, group/channel co-members read through the
        transport for the groups/channels I belong to, and my
        work counterparties. Fail-soft per source — a partial set
        re-scopes on the next refresh; the agent NEVER subscribes
        fleet-wide."""
        dm_peers: set = set()
        group_members: set = set()
        channel_members: set = set()
        mb = self.mailbox
        if mb is not None:
            try:
                for row in mb.list_items(limit=200):
                    # list_items rows are wrapped: {"msg", ...}.
                    item = row.get("msg") if isinstance(row, dict) \
                        else None
                    if not isinstance(item, dict):
                        continue
                    if item.get("group_id") or item.get("channel_id"):
                        continue
                    for k in ("from", "to"):
                        u = item.get(k)
                        if u and u != self.username:
                            dm_peers.add(str(u))
            except Exception:
                pass
        v2 = self._v2
        if v2 is not None:
            for gid in list(self.memberships):
                try:
                    group_members.update(
                        m["username"] for m in v2.group_members(gid))
                except Exception:
                    pass
            for cid in list(self.channel_roles):
                try:
                    channel_members.update(
                        m["username"] for m in v2.channel_members(cid))
                except Exception:
                    pass
        crit = self._v2_critical_set()
        return build_counterparty_set(
            dm_peers=dm_peers, group_members=group_members,
            channel_members=channel_members,
            assignees=crit, assigners=crit, exclude={self.username})

    def _on_v2_presence(self, username, record, state) -> None:
        """Scoped-watcher callback (transport thread): record the
        counterparty's ladder state. Display/diagnostics state —
        reassignment decisions live server-side, never on this
        cache."""
        self.presence_peers[str(username)] = str(state)
        self.presence_events.append({
            "username": str(username), "state": str(state),
            "ts": int(time.time())})

    def _v2_deliver(self, frame: dict) -> None:
        """Hand one fetched custody frame to the SAME dispatch
        the relay read loop feeds — journaling, decryption,
        handler invocation and the ack all happen in _dispatch /
        _process_message exactly as on the relay path (the
        mailbox claim makes signal + slow-sync double-delivery
        exactly-once, as the relay's re-offer already was)."""
        loop = self._v2_loop
        if loop is None or loop.is_closed():
            return
        try:
            asyncio.run_coroutine_threadsafe(
                self._dispatch(dict(frame)), loop)
        except RuntimeError:
            pass

    def _on_v2_signal(self, conversation_key, signal) -> None:
        """Signal-stream callback (transport thread): a tap means
        something changed in a conversation. Since 2.3.0 the
        frame itself normally arrives on the TRANSIT INBOX stream
        — a tap whose item the inbox already delivered needs no
        fetch at all. A tap for anything else (a custody-only
        frame, a read receipt, a transit copy Firebase lost)
        reconciles against the custody queue: signal-triggered,
        never periodic. A fetch failure is the degraded leg's
        cue, not an error worth raising into the stream thread."""
        v2 = self._v2
        if v2 is None:
            return
        if isinstance(signal, dict):
            item_id = str(signal.get("latest_item_id") or "")
            if item_id and v2.transit_seen(item_id):
                return
        try:
            rows = v2.fetch_unacked()
        except Exception as exc:
            # A transient fetch failure (the path emptied or
            # clipped the response past its retry budget) is the
            # designed degradation this docstring describes — the
            # degraded-sync leg retries while the stream is down
            # and delivery continues. It is logged as ONE warning
            # line, not a traceback: a traceback is the shape of
            # a crash, and stamping one on a self-healing
            # transient corrupts the log's signal for every
            # operator watching it (2.0.6 soak catch, 2026-11-06 —
            # the supervisor read this traceback as a fault while
            # the daemon delivered on around it).
            log.warning("serverless signal fetch failed: %s", exc)
            return
        for row in rows or []:
            frame = row.get("frame") if isinstance(row, dict) else None
            if isinstance(frame, dict):
                self._v2_deliver(frame)

    def _on_v2_frames(self, rows) -> None:
        """Frame-delivery callback (transport threads): rows from
        the transit inbox stream, a reconnect reconciliation, or
        the degraded-sync loop all take the identical delivery
        path."""
        for row in rows or []:
            frame = row.get("frame") if isinstance(row, dict) else None
            if isinstance(frame, dict):
                self._v2_deliver(frame)

    async def _v2_stamp_loop(self) -> None:
        """The local heartbeat stamp, serverless edition: the
        relay path's _ping_loop writes heartbeat-<username>.txt
        every HEARTBEAT_SECONDS — the stamp the host watchdog
        reads (a stale stamp = a hung process = death). The
        NETWORK heartbeat is the doorbell's own thread (180s
        health beats since 2.3.0, started by transport login,
        independent of every loop here); this task maintains only
        the local stamp contract so host supervision behaves
        identically on both transports."""
        stamp = self.state_dir / f"heartbeat-{self.username}.txt"
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            try:
                stamp.write_text(str(int(time.time())))
            except Exception:
                return
            _sd_notify_watchdog()

    async def _present_rectify_code(self, v2, code: str) -> bool:
        """Present a held operator rectification code to the
        login Edge (v2.0.9's third ceremony, factored out
        2.2.2 so every path presents it identically).

        True: the Edge accepted — the account is rebound to
        this machine's keys, the code is burned, and the
        freshly minted recovery key is persisted under the
        storage contract (state-dir copy + workspace file);
        the drop-in code file is removed.
        False: the Edge refused with rectify_failed — the code
        did not verify, OR it burned in a landed first attempt
        whose reply was lost; the caller discriminates with the
        plain key login. Nothing was saved and no file was
        dropped: a refusal makes no claims.
        Weather (any other TransportError) raises
        ConnectionError — never a verdict."""
        self._rectify_presented = True
        pubs = {"sign_pub": self.identity.signing_public_key_b64,
                "pubkey": self.identity.public_key_b64}
        try:
            result = await asyncio.to_thread(
                v2.rectify_and_login, self.username,
                self.identity.sign, code,
                pubs["sign_pub"], pubs["pubkey"],
                _package_version(),
                decision_link=self._declared_link_sent,
                decision_link_detail=self._decision_detail())
        except TransportError as exc:
            if "rectify_failed" in str(exc):
                return False
            raise ConnectionError(
                f"registration failed at step "
                f"'serverless-rectify': the login Edge "
                f"did not answer for @{self.username} "
                f"({exc}). Retry when the endpoints are "
                f"reachable from this machine.") from exc
        issued = str(result.get("recovery_key") or "")
        if issued:
            self._save_recovery_key(issued)
        self._drop_rectify_code_file()
        self.session_ceremony = "rectified"
        log.warning(
            "rectified @%s by operator code — stranded "
            "account rebound to this machine's keys; the "
            "code is burned and the new recovery key is "
            "saved.", self.username)
        return True

    async def _explicit_rectify_open(self, v2, code: str) -> bool:
        """The `agentlink rectify` command's opening ceremony
        (2.2.2): present the operator's code BEFORE any plain
        key login gets the chance to open the session silently.
        The operator's intent is the rebind + a NEW recovery
        key — a session that merely opens on existing keys has
        NOT done what was asked and must never be reported as
        a rectification (the lean false-success defect).

        True: the session is open — by rectification itself
        (session_ceremony == "rectified"), or, when the code
        was refused but the discriminating key login opened
        anyway, by key login (session_ceremony == "key-login";
        the rectification stays UNCONFIRMED — either a first
        attempt landed and burned the code with its reply
        lost, or the code did not verify while this machine's
        keys already open the account; no new recovery key
        was saved on this machine in this run).
        Raises RegistrationFailed when the code refused AND
        this machine's keys do not open the account — the
        truthful final refusal. Weather raises
        ConnectionError."""
        if await self._present_rectify_code(v2, code):
            return True
        try:
            await asyncio.to_thread(
                v2.login, self.username, self.identity.sign,
                _package_version(),
                decision_link=self._declared_link_sent,
                decision_link_detail=self._decision_detail())
        except TransportError as exc:
            if "key_auth_failed" in str(exc):
                raise RegistrationFailed(
                    f"serverless_rectify_refused: the "
                    f"rectification code presented for "
                    f"@{self.username} did not verify, and "
                    f"this machine's keys do not open the "
                    f"account ({exc}). The account is "
                    f"untouched. Check the code with the "
                    f"operator — it may be spent, expired, "
                    f"or issued for another name.") from exc
            raise ConnectionError(
                f"registration failed at step "
                f"'serverless-rectify': the login Edge did "
                f"not answer for @{self.username} ({exc}). "
                f"Retry when the endpoints are reachable "
                f"from this machine.") from exc
        self.session_ceremony = "key-login"
        log.warning(
            "rectify for @%s: the code was presented and "
            "refused, but this machine's keys opened the "
            "session — the rectification is UNCONFIRMED and "
            "no new recovery key was saved in this run.",
            self.username)
        return True

    async def _serverless_first_contact(self, v2) -> bool:
        """The first-contact suite (v2.0.8), run when the key
        login refuses with key_auth_failed — the Edge's single
        refusal for BOTH a name with no account yet and an
        account whose keys this machine does not hold. The suite
        separates the two by acting, never by guessing:

        1. RECLAIM — a recovery key is held (handed in, or found
           in the stored copies): present it; the account rebinds
           to this machine's identity keys and the session opens.
           A key handed in explicitly that does not verify is a
           final refusal (RegistrationFailed) — its owner asked
           for exactly this account. A merely DISCOVERED key that
           no longer verifies (the account moved on) falls
           through to registration, which will refuse truthfully.
        2. REGISTER — no usable recovery key: claim the name
           first-come for this machine's keys. The account is
           created and the session opens in the same step; the
           recovery key the Edge issues is persisted under the
           storage contract at once.
        3. RECTIFY (v2.0.9) — the name is taken and an operator
           rectification code is held (handed in, in the
           environment, or dropped in the workspace): present
           it; the stranded account rebinds to this machine's
           keys, the code burns, and the Edge's freshly minted
           recovery key is persisted under the storage contract.
           A code that does not verify falls through to TAKEN —
           it burns nothing and changes nothing.
        4. TAKEN — the name is registered to other keys and
           neither a recovery key nor a rectification code is
           held: return False; the caller raises the permanent
           refusal with the way forward.

        EXPLICIT RECTIFY (2.2.2) — when this agent was built
        for the `agentlink rectify` command (rectify_intent),
        a held code outranks the self-collision rescue in the
        taken branch: the operator's code is consulted FIRST,
        so an explicit rectification always presents its code
        and is never silently replaced by a key login that
        happens to open. (At start() level the same intent
        presents the code before the plain login at all — see
        _explicit_rectify_open.)

        Weather (any other TransportError) raises ConnectionError
        — the retry class — never a false identity verdict.
        Returns True when a ceremony opened the session."""
        async def _key_login_opens() -> bool:
            # The self-collision rescue (2.2.0): the hardened
            # ride-out retries a ceremony POST whose first attempt
            # may have LANDED with its response clipped by the
            # proxy (200, empty body) — the retry then meets the
            # ceremony's OWN success and misreads it: register
            # answers username_taken, recovery/rectify answer
            # *_failed for the just-burned key/code. A fresh
            # setup stranded itself exactly this way (2026-11-07:
            # register landed, its retry said taken, the suite
            # declared the name a stranger's). The plain key
            # login discriminates exactly: it opens only for the
            # account's real keys — if this machine's ceremony
            # landed, those keys are this machine's and the
            # session opens; if the name is genuinely another's,
            # the login refuses and the original verdict stands.
            # (A rescued registration holds no recovery key —
            # the minted key rode the clipped reply. The account
            # is fully usable; an operator rectification rotates
            # a fresh recovery key if one is ever needed.)
            try:
                await asyncio.to_thread(
                    v2.login, self.username, self.identity.sign,
                    _package_version(),
                    decision_link=self._declared_link_sent,
                    decision_link_detail=self._decision_detail())
                self.session_ceremony = "key-login"
                return True
            except Exception:
                # Any failure — the refusal itself, weather, a
                # transport that cannot run the ceremony — leaves
                # the original verdict exactly where it was.
                return False

        manual_key = self._recovery_key_manual
        held_key = manual_key or self._find_recovery_key()
        pubs = {"sign_pub": self.identity.signing_public_key_b64,
                "pubkey": self.identity.public_key_b64}
        if held_key:
            try:
                result = await asyncio.to_thread(
                    v2.recover_and_login, self.username,
                    self.identity.sign, held_key,
                    pubs["sign_pub"], pubs["pubkey"],
                    _package_version(),
                    decision_link=self._declared_link_sent,
                    decision_link_detail=self._decision_detail())
            except TransportError as exc:
                if "recovery_failed" in str(exc):
                    if manual_key:
                        # The key may have burned in a landed
                        # first attempt whose reply was clipped:
                        # if the rebind landed, the key login
                        # opens and no refusal is owed.
                        if await _key_login_opens():
                            return True
                        raise RegistrationFailed(
                            f"serverless_recovery_refused: {exc} — "
                            f"the recovery key handed in did not "
                            f"verify for @{self.username}; the "
                            f"account is untouched.") from exc
                    # A discovered key that no longer verifies:
                    # fall through — registration gives the
                    # truthful taken/registered answer.
                else:
                    raise ConnectionError(
                        f"registration failed at step "
                        f"'serverless-recovery': the login Edge "
                        f"did not answer for @{self.username} "
                        f"({exc}). Retry when the endpoints are "
                        f"reachable from this machine.") from exc
            else:
                issued = str(result.get("recovery_key") or "")
                if issued:
                    self._save_recovery_key(issued)
                log.warning(
                    "recovered @%s by recovery key — account "
                    "rebound to this machine's keys; the used key "
                    "is burned and its successor is saved.",
                    self.username)
                self.session_ceremony = "recovered"
                return True
        try:
            result = await asyncio.to_thread(
                v2.register_and_login, self.username,
                self.identity.sign,
                pubs["sign_pub"], pubs["pubkey"],
                _package_version(),
                decision_link=self._declared_link_sent,
                decision_link_detail=self._decision_detail(),
                designation=self.designation)
        except TransportError as exc:
            if "username_taken" in str(exc):
                if self._rectify_intent:
                    # Explicit rectification (2.2.2): the
                    # operator's code is consulted BEFORE the
                    # rescue — an explicit `agentlink rectify`
                    # must present its code, never be swallowed
                    # by a key login that happens to open (the
                    # false-success defect: the command printed
                    # "rectified" while the code sat unburned).
                    code = self._find_rectify_code()
                    if code:
                        if await self._present_rectify_code(
                                v2, code):
                            return True
                        # Refused — the code may have burned in
                        # a landed first attempt; the key login
                        # discriminates, exactly as below.
                        return await _key_login_opens()
                    return False
                # Self-collision first (2.2.0): the taken answer
                # may be this machine's OWN register, landed a
                # moment ago with its reply clipped — the key
                # login opens for exactly that case and leaves a
                # held rectification code unburned.
                if await _key_login_opens():
                    return True
                # Step 3 (v2.0.9): a held rectification code is
                # the operator's way back into a stranded legacy
                # account — try it before declaring the name
                # taken for good.
                code = self._find_rectify_code()
                if not code:
                    return False
                if await self._present_rectify_code(v2, code):
                    return True
                # The code did not verify — or it burned in a
                # landed first attempt (see _key_login_opens).
                return await _key_login_opens()
            raise ConnectionError(
                f"registration failed at step 'serverless-register':"
                f" the login Edge did not answer for"
                f" @{self.username} ({exc}). Retry when the"
                f" endpoints are reachable from this machine."
            ) from exc
        issued = str(result.get("recovery_key") or "")
        if issued:
            self._save_recovery_key(issued)
        log.warning(
            "registered @%s — first-come account created and "
            "session opened; the recovery key is saved in the "
            "client state and the workspace file.", self.username)
        self.session_ceremony = "registered"
        return True

    async def _start_serverless(self) -> str:
        """start(), serverless edition: Edge login ceremony
        (key-signed challenge -> scoped JWT + Firebase token)
        instead of the websocket hello, then the supervision
        bundle the Phase 6 drills require the daemon to own:
        the supervised signal stream, the transit inbox stream
        (2.3.0 — the live delivery path) and the degraded-sync
        loop — plus the doorbell heartbeat the login itself
        starts, on its own thread, independent of the message/
        work loops (hardcoded law). The boot sequence mirrors
        the relay path's order and guards."""
        if self.ephemeral or not self.username:
            raise RegistrationFailed(
                "serverless_requires_identity: the serverless "
                "transport logs in with a registered identity key; "
                "ephemeral dial clients stay on the relay path")
        self.current_endpoint = SERVERLESS_ENDPOINT
        # Same instance claim as the relay path, before anything
        # network-shaped happens.
        self._acquire_instance_lock()
        # Decision-link auto-wiring is local (config / in-process
        # / convention probe) — identical on both transports. The
        # declaration has a serverless home (v2.0 coverage): it
        # rides the login ceremony's verify as an additive field
        # and the Edge persists it to my al_users row with the
        # relay setters' validation, so the dashboard-visible
        # state is the same truth on both transports; mid-session
        # changes go through update_decision_link (the
        # decision_link_update frame's serverless home), and the
        # transport re-declares the newest state on every token
        # refresh.
        await self._autowire_decision_link()
        self._declared_link_sent = self._decision_declaration()
        self._declared_detail_sent = json.dumps(
            self._decision_detail(), sort_keys=True)
        v2 = self._make_v2_transport()
        self._v2 = v2
        _login_needed = True
        if self._rectify_intent:
            # Explicit rectification (2.2.2): the operator ran
            # `agentlink rectify` — a held code is presented
            # FIRST (see _explicit_rectify_open), before the
            # plain key login below gets any chance to open the
            # session silently and leave the command reporting
            # a rectification that never happened.
            _rcode = self._find_rectify_code()
            if _rcode:
                try:
                    await self._explicit_rectify_open(v2, _rcode)
                except Exception:
                    self._v2 = None
                    try:
                        await asyncio.to_thread(v2.logout)
                    except Exception:
                        pass
                    raise
                _login_needed = False
        if _login_needed:
            try:
                _login_result = await asyncio.to_thread(
                    v2.login, self.username, self.identity.sign,
                    _package_version(),
                    decision_link=self._declared_link_sent,
                    decision_link_detail=self._decision_detail())
                self.session_ceremony = "plain"
                # Recovery enrollment (2.2.3): if this account's
                # recovery hash was still empty server-side (its
                # register reply never landed), the Edge enrolled
                # it on this verified login and the key rode the
                # reply — the transport's enrollment sink (wired
                # in _make_v2_transport) already persisted it
                # under the storage contract during the login
                # itself, on this path and on every background
                # re-login path alike. Nothing further to do here.
            except TransportError as exc:
                if "key_auth_failed" in str(exc) and \
                        await self._serverless_first_contact(v2):
                    # First contact (v2.0.8): the ceremony — a
                    # recovery reclaim or a first-come registration —
                    # opened the session on this same transport. Fall
                    # through to the post-login sequence below.
                    pass
                elif "key_auth_failed" in str(exc):
                    self._v2 = None
                    try:
                        await asyncio.to_thread(v2.logout)
                    except Exception:
                        pass
                    # key_auth_failed with the first-contact suite
                    # exhausted is the Edge's one genuinely permanent
                    # refusal: the name is registered to keys this
                    # machine does not hold, and no recovery key is
                    # held either. Final until the identity or the
                    # account changes — the same finality a
                    # RegistrationFailed carries on the relay path.
                    # EVERY other refusal is configuration or weather,
                    # never identity: a 405 (the challenge arrived as
                    # the wrong method — a redirect or URL-shape fault
                    # on this host), a 404 (wrong Edge URL), a 429
                    # (rate_limited), a 500 — the daemon retries those
                    # forever under the no-going-dark law. The old
                    # "any HTTP 4xx is permanent" rule crash-looped
                    # beulah's daemon on a 405 (2026-11-06): the
                    # process died on every supervisor relaunch
                    # instead of riding out a fixable fault.
                    raise RegistrationFailed(
                        f"serverless_login_refused: {exc} — "
                        f"@{self.username} is registered to other "
                        f"keys and no recovery key is held on this "
                        f"machine. If this name is yours, restore "
                        f"your recovery file (agentlink-recovery-"
                        f"{self.username}.txt in your workspace) and "
                        f"boot again to reclaim it. If that file is "
                        f"lost, ask the operator for a rectification "
                        f"code and run `agentlink rectify --username "
                        f"{self.username} --rectify-code <code>` — "
                        f"the stranded account rebinds to this "
                        f"machine and a fresh recovery key is issued. "
                        f"Otherwise pick a new username.") from exc
                else:
                    self._v2 = None
                    try:
                        await asyncio.to_thread(v2.logout)
                    except Exception:
                        pass
                    raise ConnectionError(
                        f"registration failed at step 'serverless-login':"
                        f" the login Edge did not answer for"
                        f" @{self.username} ({exc}). Nothing was"
                        f" registered. Retry: check the serverless"
                        f" configuration (AGENTLINK_SUPABASE_URL /"
                        f" AGENTLINK_LOGIN_EDGE_URL / Firebase settings)"
                        f" and that the endpoints are reachable from this"
                        f" machine.") from exc
            except Exception as exc:
                self._v2 = None
                try:
                    await asyncio.to_thread(v2.logout)
                except Exception:
                    pass
                raise ConnectionError(
                    f"registration failed at step 'serverless-login':"
                    f" @{self.username} could not complete the login"
                    f" ceremony ({type(exc).__name__}: {exc})."
                    f" Nothing was registered; a retry with this same"
                    f" state dir resumes cleanly.") from exc
        self._hello_sent = True
        self._v2_close_requested = False
        if not self._oversight_configured and v2.oversight_pubkey:
            # Login-Edge-advertised oversight key (the serverless
            # welcome frame, 2.0.4): fleet agents pick it up with
            # zero manual config, exactly as the relay path adopts
            # the welcome frame's key. A locally configured key
            # (env/arg) is the override and is never replaced.
            # Without this, a zero-config serverless agent knew no
            # oversight key at all and every message it sent landed
            # with no oversight wrap — sealed forever on the
            # owner's dashboard.
            self.oversight_pubkey = str(v2.oversight_pubkey)
        log.info("logged in as @%s (serverless transport)",
                 self.username)
        self._warn_if_unlinked()
        # Supervision bundle (Phase 6 finding 2 — the daemon MUST
        # start all three): the heartbeat already runs (login
        # started it, doorbell-owned thread). The stamp task
        # maintains the local watchdog contract.
        self._v2_loop = asyncio.get_running_loop()
        self._v2_stop = threading.Event()
        self._v2_down = asyncio.Event()
        if self._v2_stamp_task is None or self._v2_stamp_task.done():
            self._v2_stamp_task = asyncio.create_task(
                self._v2_stamp_loop())
        v2.set_counterparty_provider(self._v2_counterparty_set)
        try:
            v2.start_presence_watch(
                self._on_v2_presence, fanout=self._v2_fanout(),
                critical=self._v2_critical_set())
        except Exception:
            log.exception("serverless presence watch failed to"
                          " start; the line stays up (signals +"
                          " transit inbox still deliver)")
        self._v2_threads = [
            threading.Thread(
                target=v2.listen_supervised,
                args=(self._on_v2_signal,),
                kwargs={"on_frames": self._on_v2_frames,
                        "stop_event": self._v2_stop},
                name="agentlink-v2-signals", daemon=True),
            threading.Thread(
                target=v2.listen_inbox_supervised,
                args=(self._on_v2_frames,),
                kwargs={"stop_event": self._v2_stop},
                name="agentlink-v2-inbox", daemon=True),
            threading.Thread(
                target=v2.run_slow_sync,
                args=(self._on_v2_frames,),
                kwargs={"stop_event": self._v2_stop},
                name="agentlink-v2-slowsync", daemon=True),
        ]
        for t in self._v2_threads:
            t.start()
        # Directory working copy (2.3.0): publish my entry to the
        # live layer so peers read it from RTDB instead of
        # PostgREST. Best-effort — the Supabase master record
        # still serves any lookup the copy misses.
        try:
            _my_entry = v2.directory_entry(self.username)
            if _my_entry:
                v2.publish_my_directory(_my_entry)
        except Exception:
            pass
        # Owner-seat control channel: the lock holder serves
        # forwarded one-shot commands, as on the relay path.
        await self._start_control_server()
        # BOOT SEQUENCE, same order and guards as the relay path:
        # resume from checkpoints -> membership resync -> self
        # check, with work handlers gated until the resume pass
        # has run.
        if not self.ephemeral:
            self._boot_gate.clear()
            try:
                await self._resume_open_work()
                await self._resync_memberships()
                await self.self_check()
            except TransportError as exc:
                # A transient transport failure (the path emptied
                # or clipped a response past its retry budget) is a
                # designed degradation: the degraded-sync pass and
                # the reconnect reconciliation retry it. ONE
                # warning line, not a traceback — the
                # signal-fetch hygiene doctrine (2.0.6): a
                # traceback is the shape of a crash, and stamping
                # one on a self-healing transient corrupts the
                # log's signal.
                log.warning("resume/resync pass deferred: %s", exc)
            except Exception:
                log.exception("resume/resync pass failed")
            finally:
                self._boot_gate.set()
            # Memberships are fresh now: re-scope the presence
            # subscriptions onto the real counterparty set.
            try:
                v2.refresh_presence_subscriptions()
            except Exception:
                pass
        self._load_pending_reads()
        if self._pending_reads:
            self._queue_read(next(iter(self._pending_reads)))
        # Mailbox: the history backfill runs through the same
        # _request("history") surface — serverless, it pages the
        # audit log under RLS (transport.fetch_history_page) and
        # merges through the identical journal path; the replay
        # is local and runs exactly as on the relay path.
        if self.mailbox is not None:
            try:
                self.mailbox_sync = await self.sync_history()
            except Exception:
                log.exception("mailbox history sync failed")
            try:
                await self._replay_mailbox()
            except Exception:
                log.exception("mailbox replay failed")
        if not self.ephemeral:
            asyncio.create_task(self._vault_sync_guarded())
        # The relay hello carries the connector inventory and
        # the capability declaration; the login ceremony does
        # not, so the boot declares them here — the same
        # connector_update + signed update_capabilities the
        # relay path presents, plus the pending-permission
        # resend the relay path runs after its hello. All
        # best-effort: the declarations re-present on the next
        # login exactly as they re-present on the next hello.
        try:
            await self._declare_connectors()
        except Exception:
            log.exception("serverless connector declaration "
                          "failed; it re-presents on next login")
        try:
            await self._resend_permission_request()
        except Exception:
            pass
        # The grant state the welcome would have carried:
        # refresh the local cache from the broker so whoami /
        # 'show my grant' speak the current truth from boot.
        try:
            await self.my_grant()
        except Exception:
            pass
        self.connection_state = "connected"
        return self.username

    async def _stop_v2_session(self) -> None:
        """End the serverless session: stop the supervision
        threads, then log out (Firebase offline write + local
        offline transition + refresh-timer cancel, inside
        transport.logout). Idempotent — close() and run()'s
        teardown may both call it; the first caller wins the
        transport, the second finds None."""
        v2, self._v2 = self._v2, None
        if self._v2_stamp_task is not None:
            self._v2_stamp_task.cancel()
            self._v2_stamp_task = None
        if self._v2_stop is not None:
            self._v2_stop.set()
        if self._v2_down is not None:
            self._v2_down.set()
        threads = list(self._v2_threads)
        self._v2_threads = []
        if v2 is not None:
            def _teardown():
                for t in threads:
                    t.join(timeout=5)
                try:
                    v2.logout()
                except Exception:
                    pass
            await asyncio.to_thread(_teardown)

    async def _run_serverless(self, reconnect_delay: float = 2.0) -> None:
        """run(), serverless edition: login, supervise, and on a
        login-level failure retry with the same capped pacing as
        the relay loop (backoff cap RECONNECT_BACKOFF_CAP_SECONDS,
        no long sleep exists in this system). Stream-level
        failure never reaches this loop — listen_supervised
        reconnects the signal stream without limit and slow-sync
        covers the gap. A RegistrationFailed is final, exactly as
        on the relay path. Cancellation is terminal."""
        while True:
            self.connection_state = "connecting"
            try:
                await self.start()
            except RegistrationFailed:
                raise
            except Exception as exc:
                log.warning("serverless login attempt failed (%s);"
                            " retrying", exc)
                await asyncio.sleep(min(
                    reconnect_delay, RECONNECT_BACKOFF_CAP_SECONDS))
                reconnect_delay = max(reconnect_delay, 0.5)
                continue
            self.connection_state = "connected"
            heal = asyncio.create_task(self._self_heal_loop())
            flush = asyncio.create_task(self._outbox_flush_loop())
            try:
                await self.serve()
            finally:
                heal.cancel()
                flush.cancel()
                await self._stop_v2_session()
            if self._v2_close_requested:
                return
            # serve() returned without a close: the session ended
            # underneath us — re-login immediately (the instant
            # first retry), pacing applies to failed attempts.
            reconnect_delay = 0.0

    async def _send_request(self, frame: dict) -> dict:
        """A message-plane send (DM / group / channel) with the
        outbox discipline (2.0.10, class B): a TRANSPORT failure
        — the network window, never a server verdict — journals
        the sealed frame in the persistent outbox and returns an
        honest ``queued`` result carrying the frame's own id
        (the server honours client ids, so the flush can never
        double-post). The flusher retries until the server
        confirms; delivery state matures via delivery_status
        (class D). Refusals propagate unchanged: they are about
        the send itself, not the weather."""
        try:
            return await self._request(frame)
        except (TransportError, ConnectionError) as exc:
            if self._v2 is None or self._outbox is None:
                raise
            self._outbox.add(frame)
            log.warning(
                "send %s queued in the outbox (transport failure: "
                "%s) — it flushes automatically when the path "
                "recovers", frame.get("id"), exc)
            return {"id": frame.get("id"),
                    "delivery_status": "queued", "queued": True,
                    "outbox": True}

    async def _outbox_flush_loop(self) -> None:
        """Flush due outbox entries until the server confirms
        each one. Runs for the life of a serverless session:
        every few seconds, and so effectively on every
        (re)connect — a send queued in a dead window lands as
        soon as any window opens."""
        while True:
            try:
                await asyncio.sleep(5)
                if self._v2 is None or self._outbox is None:
                    continue
                for entry in self._outbox.due():
                    frame = entry["frame"]
                    try:
                        await asyncio.to_thread(
                            self._v2_request_sync, frame)
                    except Exception as exc:
                        failed = self._outbox.mark_failed(
                            entry["id"], str(exc))
                        if failed is not None and \
                                failed.get("status") == "parked":
                            # Attempt budget spent (2.3.0): the
                            # entry leaves the retry set and the
                            # park makes the failure a visible,
                            # durable record — never a silent
                            # infinite retry.
                            self._v2._park(
                                "outbox", entry["id"],
                                to=str(frame.get("to")
                                       or frame.get("group_id")
                                       or ""),
                                attempts=int(
                                    failed.get("attempts") or 0),
                                last_error=str(exc))
                            log.error(
                                "outbox: send %s PARKED after %s "
                                "attempts (dead-lettered): %s",
                                entry["id"],
                                failed.get("attempts"), exc)
                        continue
                    self._outbox.mark_sent(entry["id"])
                    log.info("outbox: queued send %s confirmed by "
                             "the server", entry["id"])
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("outbox flush pass failed")

    def _v2_request_sync(self, frame: dict) -> dict:
        """The _request surface, serverless edition (sync; called
        via to_thread from _request). FULL COVERAGE (v2.0
        coverage phase): every request type the client speaks
        has a serverless path with the relay's contract — the
        transport executes it against PostgREST under the
        Phase 1 RLS policies where they can express it, and
        against the Edge functions (agentlink-work / -groups /
        -grants / -blobs / -library / -account) where the
        contract needs a service-role writer or server-side
        compute. Refusals arrive as transport Refusals carrying
        the relay's reason strings and are mapped to
        RequestFailed by _request.

        Two deliberate exceptions, both documented in the
        coverage evidence:

        * ``servers`` answers ``{"servers": []}`` — TRUTHFULLY.
          Server-carrying is a server-era concept: in serverless
          mode there are no peer relays to ride, health to
          publish or capacity to race for; the platform
          (Supabase + Firebase + R2) is the server, and presence /
          health truth is the activeness ladder. An empty mesh
          is the same answer a relay with zero registered peers
          gives, and the client's mesh machinery learns nothing
          from it — which is the correct state.
        * The room types (room_open / room_join / room_leave /
          room_close / room_signal) still fail CLOSED: they are
          the voice leg's signalling surface, and the voice leg
          is parked by the owner's standing ruling — there is no
          media path to signal for, on either transport's
          roadmap, until he un-parks it."""
        v2 = self._v2
        if v2 is None:
            raise RequestFailed("serverless_down",
                                "no live serverless session")
        ftype = frame.get("type")
        pub = self.identity.public_key_b64 if self.identity else ""
        if ftype == "send":
            return v2.send_dm(
                frame["to"], frame["content"],
                message_id=frame.get("id"),
                mentions=frame.get("mentions"),
                priority=frame.get("priority") or "normal",
                in_reply_to=frame.get("in_reply_to"),
                oversight=frame.get("oversight"),
                from_name=self.display_name, from_pubkey=pub)
        if ftype == "group_send":
            gid = frame["group_id"]
            members = [m["username"] for m in v2.group_members(gid)]
            mine = self.memberships.get(gid) or {}
            return v2.send_group_frame(
                gid, frame["content"], members=members,
                message_id=frame.get("id"),
                mentions=frame.get("mentions"),
                priority=frame.get("priority") or "normal",
                in_reply_to=frame.get("in_reply_to"),
                oversight=frame.get("oversight"),
                from_name=self.display_name, from_pubkey=pub,
                group_name=mine.get("name", ""),
                sender_nickname=mine.get("nickname", ""),
                sender_role=mine.get("role", "") or "",
                sender_custom_role=mine.get("custom_role", ""))
        if ftype == "channel_send":
            cid = frame["channel_id"]
            members = [m["username"]
                       for m in v2.channel_members(cid)]
            ch_name = ""
            try:
                ch_name = next(
                    (c["name"] for c in
                     v2.my_memberships()["channels"]
                     if c["channel_id"] == cid), "")
            except Exception:
                pass
            return v2.send_channel_frame(
                cid, frame["content"], members=members,
                message_id=frame.get("id"),
                mentions=frame.get("mentions"),
                priority=frame.get("priority") or "normal",
                oversight=frame.get("oversight"),
                from_name=self.display_name, from_pubkey=pub,
                channel_name=ch_name,
                sender_role=self.channel_roles.get(cid, ""))
        if ftype == "get_key":
            row = v2.directory_entry(frame["username"])
            if not row:
                return {"pubkey": ""}
            return {"pubkey": row.get("pubkey") or "",
                    "sign_pub": row.get("sign_pub") or ""}
        if ftype == "get_group_key":
            return {"group_id": frame["group_id"],
                    "key": v2.group_key_for(frame["group_id"],
                                            self.username)}
        if ftype == "get_channel_key":
            return {"channel_id": frame["channel_id"],
                    "key": v2.channel_key_for(frame["channel_id"],
                                              self.username)}
        if ftype == "my_groups":
            return v2.my_memberships()
        if ftype == "read":
            return v2.mark_read(frame.get("ids") or [])
        if ftype == "history":
            # Mailbox backfill: the relay's history pages, from
            # the audit log under RLS — sync_history merges them
            # through the identical _history_row_to_msg ->
            # put_if_absent path, so exactly-once is one rule on
            # both transports. The 2.3.0 forward arm: with an
            # ``after_seq`` cursor the page is strictly-newer rows
            # only (fetch_history_since) — the backward page below
            # runs exactly once per install.
            if frame.get("after_seq") is not None:
                return {"rows": v2.fetch_history_since(
                    frame["after_seq"], frame.get("limit") or 200)}
            return {"rows": v2.fetch_history_page(
                frame.get("limit") or 200, frame.get("before_seq"))}
        # -- work lifecycle -------------------------------------------------
        if ftype == "work_inbox":
            return v2.work_inbox(frame.get("status"),
                                 frame.get("group_id"))
        if ftype == "assign":
            return v2.work_assign(frame)
        if ftype == "deliver_work":
            return v2.work_deliver(frame)
        if ftype == "work_action":
            return v2.work_action(frame)
        if ftype == "work_progress":
            return v2.work_progress(frame)
        if ftype == "work_checkpoint":
            return v2.work_checkpoint(frame)
        if ftype == "work_resume_failed":
            return v2.work_resume_failed(frame)
        if ftype == "chain_create":
            return v2.chain_create(frame)
        if ftype == "chain_cancel":
            return v2.chain_cancel(frame)
        if ftype == "chain_list":
            return v2.chain_list()
        if ftype == "chain_get":
            return v2.chain_get(frame)
        if ftype == "chain_context":
            return v2.chain_context(frame)
        # -- groups / channels ------------------------------------------------
        if ftype == "group_members":
            return v2.group_members_view(frame)
        if ftype == "channel_members":
            return v2.channel_members_view(frame)
        if ftype == "set_group_keys":
            return v2.set_group_keys(frame)
        if ftype == "set_channel_keys":
            return v2.set_channel_keys(frame)
        if ftype == "attach_oversight":
            return v2.attach_oversight(frame)
        if ftype == "group_key_request":
            return v2.request_group_key(frame)
        if ftype == "channel_key_request":
            return v2.request_channel_key(frame)
        if ftype in ("group_create", "group_add", "group_remove",
                     "group_promote", "group_demote",
                     "group_nickname", "group_custom_role",
                     "group_settings", "group_join_link",
                     "group_join", "channel_create", "channel_add",
                     "channel_remove", "channel_promote",
                     "channel_join_link", "channel_join",
                     "vault_pin", "vault_remove"):
            return v2.group_admin(ftype, frame)
        # -- vault --------------------------------------------------------------
        if ftype == "vault_add":
            return v2.vault_add(frame)
        if ftype == "vault_list":
            return v2.vault_list(frame)
        if ftype == "vault_publish":
            return v2.vault_publish(frame)
        if ftype == "vault_fetch_meta":
            return v2.vault_fetch_meta()
        # -- blobs ----------------------------------------------------------------
        if ftype == "blob_put":
            return v2.blob_put(frame)
        if ftype == "blob_get":
            return v2.blob_get(frame)
        if ftype == "blob_delete":
            return v2.blob_delete(frame)
        if ftype == "blob_session_start":
            return v2.blob_session_start(frame)
        if ftype == "blob_session_status":
            return v2.blob_session_status(frame)
        if ftype == "blob_chunk":
            return v2.blob_chunk(frame)
        if ftype == "blob_session_finish":
            return v2.blob_session_finish(frame)
        # -- grants + connectors (the Edge broker) --------------------------------
        if ftype == "grant_request":
            return v2.grant_edge("request", frame)
        if ftype == "grant_allow":
            return v2.grant_edge("allow", frame)
        if ftype == "grant_revoke":
            return v2.grant_edge("revoke", frame)
        if ftype == "grant_query":
            return v2.grant_edge("query", frame)
        if ftype == "grant_action":
            return v2.grant_edge("action", frame)
        if ftype == "grant_report":
            return v2.grant_edge("report", frame)
        if ftype == "grant_approvals":
            return v2.grant_edge("approvals", frame)
        if ftype == "grant_decide":
            return v2.grant_edge("decide", frame)
        if ftype == "connector_update":
            return v2.grant_edge("connector_update", frame)
        # -- library ---------------------------------------------------------------
        if ftype == "library_search":
            return v2.library_edge("search", frame)
        if ftype == "library_fetch":
            return v2.library_edge("fetch", frame)
        # -- account -----------------------------------------------------------------
        if ftype == "directory":
            return v2.account_edge("directory", frame)
        if ftype == "update_capabilities":
            return v2.account_edge("capabilities", frame)
        if ftype == "deregister":
            return v2.account_edge("deregister", frame)
        if ftype == "self_report":
            return v2.self_report(frame)
        if ftype == "whoami":
            return v2.whoami()
        # -- the mesh question, answered truthfully --------------------------------
        if ftype == "servers":
            # Deliberate (see the docstring): no peer servers
            # exist in serverless mode; the empty mesh is the
            # truth, not a failure.
            return {"servers": []}
        raise RequestFailed(
            "serverless_unsupported",
            f"request type {ftype!r} has no serverless data path"
            f" (the room/voice signalling types remain relay-only"
            f" while the voice leg is parked); the daemon remains"
            f" on the relay transport for that operation")

    async def start(self, endpoint: str | None = None,
                    _force_recovery: bool = False) -> str:
        if self.identity is None:  # ephemeral dial client
            self.identity = Identity.ephemeral()
        # First-boot self-clean (v2.0.11, owner's update-semantics
        # ruling): an agent that ARRIVED at this version through an
        # older overlay updater still carries the old tree's
        # leftovers — v1-era modules (the retired relay/dashboard
        # among them), stale caches, and relay-era endpoint cargo
        # in its persisted config. Converge the install to this
        # version's manifest and normalize the config, once per
        # version, before anything connects. Serverless line only:
        # a client deliberately running the retired relay transport
        # (a local test harness) owns its mesh registry legitimately.
        # Governed scope only, state never touched, and a failure
        # here never blocks startup.
        if self._serverless():
            try:
                from .updater import self_clean_install
                outcome = self_clean_install(
                    Path(__file__).resolve().parent.parent,
                    self.state_dir, _package_version())
                self._self_clean = outcome
                if outcome.get("changed"):
                    cfg = outcome.get("config") or {}
                    log.info(
                        "self-clean (%s): removed %d stale file(s), %d"
                        " cache dir(s)%s%s — the install now matches"
                        " the %s manifest",
                        _package_version(),
                        len(outcome.get("removed") or []),
                        outcome.get("caches", 0),
                        f", config files removed: {cfg['removed_files']}"
                        if cfg.get("removed_files") else "",
                        f", config keys stripped: {cfg['stripped']}"
                        if cfg.get("stripped") else "",
                        _package_version())
            except Exception:
                log.debug("self-clean skipped", exc_info=True)
        if self._serverless():
            return await self._start_serverless()
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
        # Auto decision link (v1.8.0, owner's law): wire and
        # VERIFY the link BEFORE the hello is composed, so the
        # first hello already declares the truth — how the link
        # is wired and whether its self-check came back decided.
        await self._autowire_decision_link()
        self._declared_link_sent = self._decision_declaration()
        self._declared_detail_sent = json.dumps(
            self._decision_detail(), sort_keys=True)
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
        # Recovery login (v1.7.0): when this client has NO usable
        # identity for its username but holds a recovery key, the
        # hello IS a recovery hello — it presents the key with
        # this client's (fresh) identity, and the relay rebinds
        # the account to it: LOGIN BACK, never re-register. The
        # door is taken when (a) a recovery credential was given
        # explicitly (Agent(recovery_key=...) / `agentlink
        # reclaim`, or a forced retry after a key-auth mismatch in
        # this very start), or (b) there is no saved secret at all
        # (fresh/wiped state) and a stored key is discovered in
        # the workspace file or the state dir.
        _recovery_key = None
        if not self.ephemeral and self.username:
            if _force_recovery or self._recovery_key_manual:
                _recovery_key = self._recovery_key_manual or \
                    self._find_recovery_key()
            elif _saved_secret is None:
                _recovery_key = self._find_recovery_key()
        _key_auth = bool(_saved_secret) and \
            url not in self._legacy_auth_endpoints and \
            _recovery_key is None
        await self._send_raw({
            "type": "hello", "username": self.username or None,
            "display_name": self.display_name,
            "pubkey": self.identity.public_key_b64,
            "sign_pub": self.identity.signing_public_key_b64,
            "capabilities": self.advertised_capabilities(),
            # Connector vault (v1.8.1): the declared inventory of
            # OAuth-linked connectors rides the hello; the relay
            # validates it whole (a payment-shaped action class
            # refuses the inventory) and stores it as the
            # coverage source for the grant gate.
            "connectors": self.connector_inventory(),
            "cap_description": self.cap_description,
            "mode": self.mode,
            # Probe/test segregation (v1.6.0): declared at
            # registration; the relay records it only on the
            # claiming hello — after that the designation is the
            # operator's (an agent cannot flip its own).
            "designation": self.designation,
            "decision_link": self._declared_link_sent,
            # Auto-link detail (v1.8.0): the wiring mode + the
            # self-check verdict riding beside the summary.
            "decision_link_detail": self._decision_detail()
            if self._autonomous_on() else None,
            # Delivery custody (v1.3.7): this client journals every
            # inbound item into its canonical local mailbox and acks
            # items back — the relay keeps custody of queued frames
            # until the ack, and marks audit delivered only then.
            "delivery_ack": 1,
            "client_version": _package_version(),
            "secret": None if (self.ephemeral or _key_auth
                               or _recovery_key) else _saved_secret,
            "auth": "recovery" if _recovery_key else (
                "key" if _key_auth else None),
            "recovery_key": _recovery_key,
            "ephemeral": self.ephemeral,
            "home_endpoint": self.endpoint,
            "core": core_fingerprint(),
        })
        self._hello_sent = True
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
                if frame.get("recovery_key"):
                    # Issued at claim / enrollment / recovery
                    # rotation (v1.7.0): persist per the storage
                    # contract (state dir + workspace file) and
                    # surface it to the agent.
                    self._save_recovery_key(frame["recovery_key"])
                if frame.get("servers"):
                    # Peer discovery (v1.2.0): learn the live mesh
                    # from whichever relay served this hello, merge
                    # it into the race set, and persist it.
                    self._learn_servers(frame["servers"])
                # Onboarding surface (v1.8.0): the welcome states
                # the agent's own grant (or None) — cached for
                # whoami(); my_grant() refreshes it live.
                if "grant" in frame:
                    self.grant = frame.get("grant")
                if self._permission_request is not None:
                    # A pending permission request the relay has
                    # no record of (requested while offline, or
                    # the relay's store is fresh): present it now
                    # so the requested state is true on both
                    # sides. Spawned — the read loop must stay
                    # free to deliver the answer.
                    asyncio.create_task(
                        self._resend_permission_request())
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
                        self._ping_loop(self._ws))
                # Decision-link re-verification (v1.8.0): the
                # wired path must keep proving itself for the
                # life of the connection — an endpoint that dies
                # mid-session flips the declaration to pending
                # within one recheck cadence, and revives it the
                # same way. Session-bound like the heartbeat.
                if self._link_task is None or self._link_task.done():
                    self._link_task = asyncio.create_task(
                        self._link_recheck_loop(self._ws))
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
                    except TransportError as exc:
                        # Transient transport failure: designed
                        # degradation, retried by the sync passes —
                        # one warning line, not a traceback (the
                        # signal-fetch hygiene doctrine, 2.0.6).
                        log.warning("resume/resync pass deferred: %s",
                                    exc)
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
                if not _force_recovery and _recovery_key is None \
                        and not self.ephemeral and self.username and \
                        frame.get("reason") == "key_auth_failed" and \
                        self._find_recovery_key():
                    # Identity mismatch (v1.7.0): this machine's
                    # identity keys no longer match the account —
                    # the state was rebuilt around a surviving
                    # secret file, so the signature gate (rightly)
                    # refuses — but a recovery key is on file. Take
                    # the recovery door ONCE: the relay rebinds the
                    # account to this identity and everything is
                    # restored. A refused recovery is final: the
                    # retry's own refusal propagates as-is.
                    log.warning(
                        "key-signed hello refused for @%s "
                        "(identity mismatch) — a recovery key is "
                        "on file; logging back in with it instead",
                        self.username)
                    await self._ws.close()
                    return await self.start(endpoint,
                                            _force_recovery=True)
                await self._ws.close()
                raise RegistrationFailed(
                    f"{frame.get('reason')}: {frame.get('detail', '')}")
        raise RegistrationFailed("connection closed before welcome")

    async def _read_loop(self) -> None:
        # Close-code telemetry (v1.6.2): reset for this session, then
        # capture WHY the socket ended. An abnormal close raises
        # ConnectionClosed into the except; a NORMAL close (1000/
        # 1001) simply ends the async-for (websockets' iterator
        # swallows ConnectionClosedOK), so the finally reads the
        # code/reason off the socket itself. The socket is bound at
        # entry — the same object the async-for iterates — so a
        # later session's socket can never be misread as this one's.
        ws = self._ws
        self._closed_code = None
        self._closed_reason = ""
        try:
            async for raw in ws:
                await self._dispatch(json.loads(raw))
        except websockets.exceptions.ConnectionClosed as exc:
            self._closed_code = exc.code
            self._closed_reason = exc.reason or ""
        finally:
            if self._closed_code is None and ws is not None:
                self._closed_code = getattr(ws, "close_code", None)
                self._closed_reason = getattr(
                    ws, "close_reason", None) or self._closed_reason

    async def _ping_loop(self, ws=None) -> None:
        """The connection's heartbeat (v1.4.3 — owned by start(),
        not by run()): a ping every HEARTBEAT_SECONDS for as long
        as the connection lives, plus the last-alive stamp the
        watchdog reads (a stale stamp = a hung process = death).
        Presence derives from these pings on every relay, so they
        must flow for EVERY connected client — daemon or one-shot
        embedding alike. A send failure ends the loop; the reader
        owns disconnect handling and a reconnect re-spawns it.

        SESSION-BOUND (v1.6.0): the loop is tied to the socket it
        was spawned for and dies the moment that socket is no
        longer the live one. It previously read self._ws
        dynamically and was cancelled only by close() — never by
        run()'s per-session teardown — so a loop sleeping through
        a reconnect could wake after the new session's socket was
        installed and write its ping onto the NEW connection,
        inside that hello's key-auth window; the relay's auth wait
        mistook the ping for a failed auth_response and refused
        the hello (the 44-race gate failure). run()'s teardown
        now also cancels the task (see run()); this identity
        guard is the second lock on the same door."""
        ws = ws if ws is not None else self._ws
        stamp = self.state_dir / f"heartbeat-{self.username}.txt"
        while True:
            await asyncio.sleep(HEARTBEAT_SECONDS)
            if self._ws is not ws:
                return
            try:
                if self._ws is not None:
                    await self._send_raw({
                        "type": "ping",
                        "activity": self._activity_state()})
                stamp.write_text(str(int(time.time())))
                _sd_notify_watchdog()
            except Exception:
                return

    async def close(self) -> None:
        # Serverless session (v2.0): stop the supervision bundle
        # and log out FIRST — no frame may be delivered into
        # handlers while the rest of the teardown runs, and the
        # offline presence write is the clean-close signal.
        if self._v2 is not None:
            self._v2_close_requested = True
            await self._stop_v2_session()
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
        if self._link_task is not None:
            self._link_task.cancel()
            self._link_task = None
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

    async def serve(self) -> None:
        if self._serverless():
            # Serverless session: there is no socket to await —
            # the session lives in the transport's supervision
            # threads (signal stream, slow-sync, heartbeat) and
            # ends when close() (or run()'s teardown) stops them.
            # Cancellation stays terminal, as on the relay path.
            assert self._v2 is not None and self._v2_down is not None, \
                "call start() first"
            self._ensure_update_checker()
            await self._v2_down.wait()
            return
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
        if self._serverless():
            await self._run_serverless(reconnect_delay)
            return

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
                # The heartbeat dies with its session (v1.6.0):
                # close() always cancelled it, but this per-session
                # teardown did not — a surviving loop could wake on
                # the NEXT session's socket and ping inside its
                # key-auth window (the 44-race gate failure). The
                # loop is also socket-bound as a second lock.
                if self._ping_task is not None:
                    self._ping_task.cancel()
                    self._ping_task = None
                if self._link_task is not None:
                    self._link_task.cancel()
                    self._link_task = None
            _close_code = self._closed_code
            _close_reason = self._closed_reason
            if _close_code is None and self._ws is not None:
                _close_code = getattr(self._ws, "close_code", None)
                _close_reason = getattr(
                    self._ws, "close_reason", None) or _close_reason
            log.warning("disconnected from %s (close_code=%s "
                        "close_reason=%r); reconnecting (home first)",
                        self.current_endpoint, _close_code,
                        _close_reason)
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
        if self._v2 is not None:
            # Serverless session: the request surface executes
            # against the transport (see _v2_request_sync for the
            # routing). The transport's own HTTP timeouts govern;
            # `timeout` is the relay contract's and does not
            # apply here. A transport Refusal carries the relay's
            # own reason string and surfaces as the identical
            # RequestFailed the relay path would have raised.
            try:
                return await asyncio.to_thread(
                    self._v2_request_sync, frame)
            except Refusal as exc:
                raise RequestFailed(exc.reason,
                                    exc.detail) from exc
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
        # The cache carries a freshness stamp (v1.7.0): a peer's
        # key can CHANGE under its username — a recovery login
        # rebinds the account to fresh keys — and a cache that
        # never re-reads would seal to the dead key for the whole
        # session. Entries older than the TTL are re-resolved
        # through the relay (the authoritative row), and a
        # key_rotated notice from the relay drops the entry the
        # moment a rebind happens.
        ent = self._pubkey_cache.get(u)
        if ent and (time.time() - ent[1]) < _PUBKEY_CACHE_TTL_SECONDS:
            return ent[0]
        data = await self._request({"type": "get_key", "username": u})
        pub = data.get("pubkey") or ""
        if pub:
            self._pubkey_cache[u] = (pub, time.time())
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

    async def _rectify_oversight(self, ref_id, *, payload=None,
                                 room_key=None) -> None:
        """Receiver-side oversight rectification (2.0.6): a message
        whose sender shipped no oversight wrap would sit unreadable
        on the owner's dashboard. The receiver — which has just
        decrypted the message legitimately — computes the same wrap
        the sender would have (the content wrap for a DM, the room
        key wrap for group/channel traffic) and attaches it to the
        audit row through the pinned database function, which only
        ever fills an EMPTY oversight column for a party to the
        message. Fail-soft by design: a failure leaves the row
        unwrapped, the next history sync retries, and message
        processing never blocks on it."""
        if not ref_id or not self.oversight_pubkey:
            return
        try:
            wrap = None
            if room_key is not None:
                wrap = self._oversight_for_key(room_key)
            elif payload is not None:
                wrap = self._oversight_for_obj(payload)
            if not wrap:
                return
            await self._request({"type": "attach_oversight",
                                 "ref_id": str(ref_id),
                                 "oversight": wrap})
        except Exception:
            log.debug("oversight rectification failed for %s",
                      ref_id, exc_info=True)

    async def _ask_key_reissue(self, scope: str, scope_id: str) -> None:
        """My stored wrap for this group/channel no longer unwraps
        (the classic cause: my identity rotated after the wrap was
        sealed). Ask the room's admins — at most once per room per
        session — to re-issue the current epoch key sealed to my
        CURRENT directory key. Fail-soft: if the ask cannot go
        out, the next session asks again."""
        tag = (scope, scope_id)
        if tag in self._key_reissue_asked:
            return
        self._key_reissue_asked.add(tag)
        try:
            await self._request({"type": f"{scope}_key_request",
                                 f"{scope}_id": scope_id})
        except Exception:
            log.debug("key reissue ask failed for %s %s",
                      scope, scope_id, exc_info=True)

    async def _reissue_group_key(self, frame: dict) -> None:
        """A member's group wrap no longer unwraps: if I hold this
        group's key, re-seal the SAME epoch key to the member's
        CURRENT directory pubkey and re-distribute to them alone.
        The store enforces admin rights on the write; a non-admin
        attempt is refused there and logged here, never fatal. The
        request frame is acked once handled — or when there is
        nothing I can do (no key held) — and left in custody when
        the re-distribution itself failed, so it is retried."""
        gid = frame.get("group_id")
        requester = frame.get("from")
        rec = self._group_keys.get(gid) if gid else None
        if not rec or not requester or requester == self.username:
            if frame.get("id"):
                await self._send_ack([frame["id"]])
            return
        try:
            await self._distribute_group_key(
                gid, int(rec["epoch"]), rec["key"], [requester])
        except Exception:
            log.warning("group key reissue for %s in %s failed",
                        requester, gid, exc_info=True)
            return
        if frame.get("id"):
            await self._send_ack([frame["id"]])

    async def _reissue_channel_key(self, frame: dict) -> None:
        """The channel twin of _reissue_group_key."""
        cid = frame.get("channel_id")
        requester = frame.get("from")
        rec = self._channel_keys.get(cid) if cid else None
        if not rec or not requester or requester == self.username:
            if frame.get("id"):
                await self._send_ack([frame["id"]])
            return
        try:
            await self._distribute_channel_key(
                cid, int(rec["epoch"]), rec["key"], [requester])
        except Exception:
            log.warning("channel key reissue for %s in %s failed",
                        requester, cid, exc_info=True)
            return
        if frame.get("id"):
            await self._send_ack([frame["id"]])

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
        if ftype == "key_rotated":
            # A peer's account was rebound to fresh identity keys
            # (a recovery login, v1.7.0): the cached key for that
            # username is dead — drop it so the next seal resolves
            # the CURRENT key through the relay.
            self._pubkey_cache.pop(
                str(frame.get("username") or ""), None)
            return
        if ftype == "group_key":
            try:
                key = self.identity.unwrap_key(frame["wrapped"])
                self._store_group_key(frame["group_id"],
                                      int(frame["epoch"]), key)
            except Exception:
                log.exception("failed to unwrap group key")
                asyncio.create_task(self._ask_key_reissue(
                    "group", str(frame.get("group_id") or "")))
            return
        if ftype == "channel_key":
            try:
                key = self.identity.unwrap_key(frame["wrapped"])
                self._store_channel_key(frame["channel_id"],
                                        int(frame["epoch"]), key)
            except Exception:
                log.exception("failed to unwrap channel key")
                asyncio.create_task(self._ask_key_reissue(
                    "channel", str(frame.get("channel_id") or "")))
            return
        if ftype == "group_key_request":
            asyncio.create_task(self._reissue_group_key(frame))
            return
        if ftype == "channel_key_request":
            asyncio.create_task(self._reissue_channel_key(frame))
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
        if self._v2 is not None:
            # Membership moved: the scoped presence subscriptions
            # re-derive from the new counterparty set.
            try:
                self._v2.refresh_presence_subscriptions()
            except Exception:
                pass

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
                # Same cold-key guard as the boot resume pass
                # (_ensure_keys_for_work): the rebuild decrypts
                # the same mirror and must not drop group
                # checkpoints to an empty key cache.
                await self._ensure_keys_for_work(data.get("work", []))
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
            await self._ask_key_reissue("channel", cid)
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
        if not ids:
            return
        if self._v2 is not None:
            # Serverless custody: the ack deletes my queue rows
            # and marks the audit rows delivered, store-side —
            # the same contract, executed by the transport.
            try:
                await asyncio.to_thread(self._v2.ack, ids)
            except Exception:
                pass
            return
        if self._ws is None:
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
        {"fetched", "inserted", "pages", "rectified"} (plus
        "error" when the relay could not be asked — the sync is
        resumable by simply calling it again, and start() calls it
        on every connect). Serverless since 2.3.0: a returning
        agent syncs FORWARD from its persisted history cursor
        (only the rows it has never journaled); the backward full
        paging is the once-per-install first sync, and remains
        the relay path's standing shape."""
        out = {"fetched": 0, "inserted": 0, "pages": 0, "rectified": 0,
               "healed": 0}
        mb = self.mailbox
        if mb is None or (self._ws is None and self._v2 is None):
            return out
        from . import timing as _timing
        page_size = int(getattr(_timing, "DELIVERY_HISTORY_PAGE", 200)
                        or 200)
        # Clipped-body fallback (2.2.0): on this VM class of
        # egress proxy, a desync window answers LARGE responses
        # with an empty body, which the transport reports as an
        # undecodable page. A 200-row page (~250KB) can stall a
        # returning agent's whole history sync for the length of
        # the window; the same cursor at a smaller page size
        # (~60KB, ~12KB) slips through far more often. On an
        # undecodable page, shrink and retry the SAME cursor;
        # the shrunk size holds for the rest of this sync.
        shrink_ladder = [50, 10]
        before: int | None = None
        smallest: int | None = None
        # Forward-cursor sync (2.3.0, serverless only): with a
        # persisted history cursor the sync asks ONLY for rows
        # strictly newer than it (the after_seq arm) — a returning
        # agent downloads exactly what it has never journaled.
        # The backward full re-download below runs exactly once
        # per install (cursor 0) and establishes the cursor. The
        # cursor advances only over pages actually journaled.
        forward = self._v2 is not None and self._history_cursor() > 0
        after: int | None = self._history_cursor() if forward else None
        largest: int | None = None
        while True:
            frame: dict = {"type": "history", "limit": page_size}
            if forward:
                frame["after_seq"] = after
            elif before is not None:
                frame["before_seq"] = before
            try:
                data = await self._request(frame, timeout=30)
            except Exception as exc:
                # Both clip signatures are the same fault: the
                # transport's read path raises "returned an empty
                # body" for the zero-byte costume and "returned
                # an undecodable body" for the truncated one —
                # match either (the first live shrink stopped
                # after one step because the 50-row page failed
                # with the OTHER string).
                if ("undecodable" in str(exc)
                        or "empty body" in str(exc)) \
                        and shrink_ladder:
                    page_size = shrink_ladder.pop(0)
                    out["page_shrunk_to"] = page_size
                    continue
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
                    largest = int(seq) if largest is None else max(
                        largest, int(seq))
                msg = self._history_row_to_msg(row)
                if msg is None or not msg.get("id"):
                    continue
                rectify = msg.pop("_rectify", None)
                if not msg.get("sealed"):
                    # Envelope reconciliation (2.0.10, class A):
                    # the server's copy of this id OPENS here, so
                    # it supersedes any local stub — a sealed
                    # history stub or a parked-unreadable entry —
                    # whose envelope never did. The journal heals
                    # from the canonical record instead of the
                    # local copy being wrong forever (the 31
                    # re-sealed family messages reached beulah's
                    # server record long before her client stopped
                    # failing on its pre-repair local copies).
                    existing = mb.get(str(msg["id"]))
                    if existing and (existing.get("sealed")
                                     or existing.get("unreadable")
                                     or (not existing.get("body")
                                         and msg.get("body"))):
                        # The third arm (2.2.0): a journal entry
                        # that OPENED but rendered empty — the
                        # legacy {"text": ...} payload shape the
                        # pre-fix reader could not see into —
                        # is superseded by the server copy that
                        # now opens with its real text. An entry
                        # with any body of its own is never
                        # overwritten by a re-sync.
                        if mb.replace_msg(msg):
                            out["healed"] += 1
                            self._clear_unreadable(str(msg["id"]))
                    elif mb.put_if_absent(msg):
                        out["inserted"] += 1
                elif mb.put_if_absent(msg):
                    out["inserted"] += 1
                if rectify is not None and out["rectified"] < 150:
                    # Bounded per sync (the sync re-pages everything
                    # on every connect, so the remainder is picked
                    # up next time); a failed attach leaves the row
                    # unwrapped and is retried the same way.
                    try:
                        await self._request(
                            {"type": "attach_oversight", **rectify})
                        out["rectified"] += 1
                    except Exception:
                        pass
            if forward:
                if largest is not None:
                    after = largest
                    self._save_history_cursor(largest)
                if len(rows) < page_size or largest is None:
                    break  # caught up to the archive's head
                continue
            if len(rows) < page_size or smallest is None:
                # Short page = the beginning of history: the ONE
                # full backfill is complete, so the cursor is set
                # and every later boot syncs forward from it.
                if self._v2 is not None and largest is not None:
                    self._save_history_cursor(largest)
                break
            if before is not None and smallest >= before:
                break  # no progress — never spin
            before = smallest
        return out

    def _history_cursor_path(self):
        return self.state_dir / "al_history_cursor"

    def _history_cursor(self) -> int:
        """The persisted history high-water mark (2.3.0): the
        greatest audit seq this client has journaled from the
        archive. 0 when no cursor file exists — a fresh install,
        whose one full backfill establishes it."""
        try:
            return int(
                self._history_cursor_path().read_text().strip()
                or 0)
        except Exception:
            return 0

    def _save_history_cursor(self, seq: int) -> None:
        """Persist the history cursor. Fail-soft: a cursor that
        cannot be written costs one forward re-sync of the same
        rows (the journal dedupes), never a crash."""
        try:
            self._history_cursor_path().write_text(str(int(seq)))
        except Exception:
            pass

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
        via_identity = False
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
            if payload is None and (channel_id or group_id):
                # 2.0.7 fallback: room traffic mis-sealed to my
                # identity key (see _process_message) — readable by
                # me, and rectified below with a CONTENT wrap.
                try:
                    payload = self._decrypt_obj(envelope)
                    via_identity = payload is not None
                except Exception:
                    payload = None
        if payload is None:
            msg["sealed"] = True
            return msg
        msg["body"] = _payload_body(payload)
        msg["kind"] = payload.get("kind") or \
            (payload.get("file") or {}).get("kind") or "text"
        msg["meta"] = payload.get("meta") or {}
        msg["file"] = payload.get("file")
        msg["size"] = (payload.get("file") or {}).get(
            "size", len(msg["body"]))
        if not row.get("oversight") and self.oversight_pubkey:
            # Backfill (2.0.6): this row's sender shipped no
            # oversight wrap. Stash the wrap on the msg (the sync
            # loop pops it before journaling and attaches it), so
            # the owner's dashboard can read history too, not just
            # live traffic.
            wrap = None
            if via_identity:
                wrap = self._oversight_for_obj(payload)
            elif (channel_id or group_id) and rec:
                wrap = self._oversight_for_key(rec["key"])
            elif not channel_id and not group_id:
                wrap = self._oversight_for_obj(payload)
            if wrap:
                msg["_rectify"] = {"ref_id": ref, "oversight": wrap}
        return msg

    # -- messages ---------------------------------------------------------------------------
    async def delivery_status(self, message_id: str) -> dict:
        """Where one of MY sent messages stands (2.0.10,
        class D): the server's record — acceptance, per-recipient
        custody, read receipts — merged with the local outbox
        (a message still flushing locally reports ``queued``
        until the server knows it). Recipients come from the
        local sent journal: the DM peer, or the group's member
        list for a room post."""
        if self._v2 is None:
            raise TransportError(
                "delivery_status needs the serverless transport")
        recipients = None
        group_id = None
        if self.mailbox is not None:
            sent = self.mailbox.get(str(message_id))
            if sent and sent.get("from") == self.username:
                group_id = sent.get("group_id") or None
                if not group_id and sent.get("to"):
                    recipients = [str(sent["to"])]
        state = await asyncio.to_thread(
            self._v2.delivery_state, str(message_id), recipients,
            group_id)
        if self._outbox is not None \
                and self._outbox.get(str(message_id)) is not None \
                and state["state"] == "unknown":
            state = dict(state, state="queued", local_outbox=True)
        return state

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
            await self._ask_key_reissue("group", gid)
            return None
        self._store_group_key(gid, int(key_rec["epoch"]), key)
        return self._group_keys[gid]

    # -- unreadable park journal (2.0.10, class A) ------------------
    #
    # A message that cannot be decrypted used to be dropped by
    # _process_message with nothing journaled and nothing acked:
    # the custody row stayed on the server, every fetch offered
    # it again, and the client retried the same failing decrypt
    # forever — beulah's log recorded 7,863 InvalidTag retries
    # against 31 messages whose SERVER copies had already been
    # repaired (her local journal predated the repair, and
    # nothing anywhere replaced a bad local copy with the good
    # server one). The discipline now:
    #
    # * one fresh-key retry on the live path (a stale cached
    #   room key is the common transient);
    # * then PARK: journal an honest sealed stub marked
    #   ``unreadable`` and ACK the custody row, so redelivery
    #   stops dead;
    # * re-attempts ride an exponential backoff recorded in
    #   unreadable-<username>.json (30s doubling, capped at 1h);
    # * self-healing: whenever a copy of the same id DOES open
    #   (a later live delivery, or the history sync's server
    #   copy), it replaces the stub in place and the park record
    #   clears — the journal heals itself from the server's
    #   canonical record.

    def _unreadable_path(self) -> Path:
        return Path(self.state_dir) / f"unreadable-{self.username}.json"

    def _load_unreadable(self) -> None:
        if self.ephemeral or not self.username:
            return
        try:
            data = json.loads(self._unreadable_path().read_text())
            if isinstance(data, dict):
                self._unreadable = {
                    str(k): {"attempts": int(v.get("attempts") or 0),
                             "next_ts": int(v.get("next_ts") or 0)}
                    for k, v in data.items() if isinstance(v, dict)}
        except FileNotFoundError:
            pass
        except Exception:
            log.exception("loading the unreadable park journal failed")

    def _save_unreadable(self) -> None:
        if self.ephemeral or not self.username:
            return
        try:
            path = self._unreadable_path()
            if not self._unreadable:
                path.unlink(missing_ok=True)
                return
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._unreadable))
            os.replace(tmp, path)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
        except Exception:
            log.exception("persisting the unreadable park journal "
                          "failed")

    def _park_unreadable(self, mid: str) -> dict:
        """Record one more failed opening of ``mid`` and return
        its park record (attempts + the next permitted retry)."""
        rec = self._unreadable.get(str(mid)) or {"attempts": 0,
                                                 "next_ts": 0}
        rec["attempts"] = int(rec.get("attempts") or 0) + 1
        wait = min(3600, 30 * (2 ** min(rec["attempts"] - 1, 7)))
        rec["next_ts"] = int(time.time()) + wait
        self._unreadable[str(mid)] = rec
        self._save_unreadable()
        return rec

    def _clear_unreadable(self, mid: str) -> None:
        if self._unreadable.pop(str(mid), None) is not None:
            self._save_unreadable()

    def _unreadable_due(self, mid: str) -> bool:
        """True when a parked id may be attempted again (no park
        record, or its backoff has elapsed)."""
        rec = self._unreadable.get(str(mid))
        if not rec:
            return True
        return int(time.time()) >= int(rec.get("next_ts") or 0)

    async def _open_frame_payload(self, frame: dict):
        """Open one delivered frame's content: the room key for
        group/channel traffic (with the 2.0.7 identity fallback),
        the identity for DMs. Returns (payload, via_identity,
        room_key_rec, to). Raises when nothing opens it."""
        via_identity = False
        rec = None
        if frame.get("channel_id") or frame.get("group_id"):
            if frame.get("channel_id"):
                rec = await self._ensure_channel_key(frame["channel_id"])
                to = frame["channel_id"]
            else:
                rec = await self._ensure_group_key(frame["group_id"])
                to = frame["group_id"]
            payload = None
            if rec is not None:
                try:
                    payload = json.loads(decrypt_with_key(
                        rec["key"], frame["content"]))
                except Exception:
                    payload = None
            if payload is None:
                # 2.0.7 fallback: a sender whose client mis-seals
                # room traffic to a member's identity key can
                # still be read by that member (the retired drill
                # injector sealed Nova family posts exactly this
                # way). The oversight rectification below then
                # wraps the CONTENT, not the room key.
                payload = self._decrypt_obj(frame["content"])
                via_identity = True
        else:
            payload = self._decrypt_obj(frame["content"])
            to = self.username
        return payload, via_identity, rec, to

    async def _process_message(self, frame: dict) -> None:
        mid = frame.get("id")
        if mid and self.mailbox is not None:
            existing = self.mailbox.get(str(mid))
            if existing and existing.get("unreadable") \
                    and not self._unreadable_due(str(mid)):
                # Parked and still inside its backoff: ack the
                # re-offer and stop — no decrypt attempt, no log
                # line, no spin (class A).
                await self._send_ack([mid])
                return
        via_identity = False
        rec = None
        try:
            payload, via_identity, rec, to = \
                await self._open_frame_payload(frame)
        except Exception:
            # One fresh-key retry: a stale cached room key is
            # the common transient (the room re-wrapped while
            # this client held the old wrap).
            retried = False
            if frame.get("channel_id"):
                self._channel_keys.pop(frame["channel_id"], None)
                retried = True
            elif frame.get("group_id"):
                self._group_keys.pop(frame["group_id"], None)
                retried = True
            if retried:
                try:
                    payload, via_identity, rec, to = \
                        await self._open_frame_payload(frame)
                except Exception:
                    retried = False
            if not retried:
                # PARK (class A): journal the honest stub, ack
                # the custody row, record the backoff. The item
                # is never dropped silently and never retried in
                # a hot loop; a later opening copy heals it.
                park = self._park_unreadable(str(mid)) if mid \
                    else {"attempts": 1}
                if mid and self.mailbox is not None:
                    stub = {
                        "id": mid,
                        "from": frame.get("from"),
                        "from_name": frame.get("from_name"),
                        "sender_nickname":
                            frame.get("sender_nickname") or "",
                        "sender_role": frame.get("sender_role") or "",
                        "sender_custom_role":
                            frame.get("sender_custom_role") or "",
                        "to": frame.get("group_id")
                            or frame.get("channel_id")
                            or self.username,
                        "group_id": frame.get("group_id"),
                        "group_name": frame.get("group_name"),
                        "channel_id": frame.get("channel_id"),
                        "channel_name": frame.get("channel_name"),
                        "priority": frame.get("priority") or "normal",
                        "ts": frame.get("ts"),
                        "time": frame.get("ts"),
                        "kind": "text", "body": "", "meta": {},
                        "file": None, "size": 0,
                        "mentions": frame.get("mentions") or [],
                        "in_reply_to": frame.get("in_reply_to"),
                        "delivery_status": "unreadable",
                        "queued": bool(frame.get("queued")),
                        "encrypted": True,
                        "sealed": True,
                        "unreadable": True,
                    }
                    self.mailbox.put_if_absent(stub)
                    await self._send_ack([mid])
                log.warning(
                    "message %s could not be decrypted — parked as "
                    "unreadable (attempt %s); it heals automatically "
                    "when an opening copy syncs from the server",
                    mid, park.get("attempts"))
                return
        if not frame.get("oversight"):
            # The sender shipped no oversight wrap (an old client):
            # rectify from the plaintext just decrypted, in the
            # background — never on the delivery path's clock.
            if via_identity:
                asyncio.create_task(self._rectify_oversight(
                    frame.get("id"), payload=payload))
            elif frame.get("channel_id") or frame.get("group_id"):
                asyncio.create_task(self._rectify_oversight(
                    frame.get("id"), room_key=rec["key"]))
            else:
                asyncio.create_task(self._rectify_oversight(
                    frame.get("id"), payload=payload))
        if frame.get("from_pubkey"):
            self._pubkey_cache[frame["from"]] = (
                frame["from_pubkey"], time.time())
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
        body = _payload_body(payload)
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
                    # and process the real item. A parked-unreadable
                    # stub heals the same way (2.0.10, class A):
                    # its park record clears with the replacement.
                    self.mailbox.replace_msg(msg)
                    self._clear_unreadable(str(mid))
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
            # A real dispatch through the agent's own handler
            # failed (v1.8.0): the link state hears about it.
            self._note_link_failure()
            log.exception("on_message handler failed")
            return
        self._note_link_success()
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
        """Public: True when the decision link is wired AND its
        live self-check has verified the path (v1.8.0 — before
        the first check has run, wired is the best available
        fact and is reported as such). Meaningful in autonomous
        mode."""
        if self._link_checked_at:
            return bool(self._link_verified)
        return self._decision_wired()

    @property
    def decision_link_state(self) -> dict:
        """Public (v1.8.0): the link's full living state —
        {"mode", "verified", "checked_at", "state"} — the same
        facts the hello declares and whoami() states."""
        return {**self._decision_detail(),
                "state": self._decision_declaration() or "n/a"}

    def _decision_declaration(self) -> str:
        """What the hello declares to the relay (v1.3.5; verified
        semantics v1.8.0), so the dashboard and the directory can
        state the fact instead of leaving silence unexplained:
        "linked" / "pending" for an autonomous agent; "" when the
        question does not apply (manual mode — the agent is
        directed by its operator — or an ephemeral tooling
        connection). Since v1.8.0, once the self-check has run
        "linked" means WIRED AND VERIFIED: the link was found by
        the auto-wiring and its live probe came back decided; a
        wired path that has not answered its probe is declared
        "pending" — the truthful state, never an optimistic one.
        (Before any check has run — a client that was never
        started — the declaration states the wiring alone; the
        hello a relay records is always the verified form,
        because start() verifies before it composes the hello.)"""
        if not self._autonomous_on():
            return ""
        if self._link_checked_at:
            return "linked" if self._link_verified else "pending"
        # No self-check has run yet (a constructed-but-unstarted
        # client): the declaration states the wiring, as it did
        # pre-1.8.0. start() always verifies BEFORE the hello,
        # so anything a relay ever records is the verified form.
        return "linked" if self._decision_wired() else "pending"

    def _decision_detail(self) -> dict:
        """The auto-link detail (v1.8.0): how this client wired
        itself and whether the self-check verified the path —
        declared beside the summary in every hello and update."""
        return {"mode": self._link_mode,
                "verified": bool(self._link_verified),
                "checked_at": int(self._link_checked_at or 0)}

    # -- auto decision link (v1.8.0, owner's law) ---------------------
    # Immediately after registration the decision link must
    # verify and wire ITSELF — "not manually. not manually."
    # Resolution order: an explicitly configured decision
    # endpoint; the in-process decision callable the hosting
    # program registered with the SDK (the process running this
    # client IS the agent); the agent's own registered handlers;
    # the platform's well-known local convention endpoint. The
    # wired path is then PROVEN with a synthetic probe event.
    # Automatic wiring only ever FINDS the agent's own
    # intelligence — it never substitutes one: an agent with
    # nothing reachable stays silent, queues, and declares
    # 'pending' on every surface.

    def _local_link_mode(self) -> str | None:
        """The wiring this process already carries, in the
        owner's precedence order: (1) an explicitly configured
        decision endpoint — the operator's own deliberate act
        wins over every automatic discovery; (2) the in-process
        decision callable the hosting program registered; (3)
        an already-adopted convention endpoint; (4) the agent's
        registered handlers. None when nothing local is wired
        (the convention probe is the remaining door).
        _call_decision dispatches in this same order, so the
        declared mode is always the path decisions really take."""
        if self.decision_endpoint is not None \
                and self._endpoint_origin == "config":
            return "config"
        if self._decision_callable is not None:
            return "in_process"
        if self.decision_endpoint is not None \
                and self._endpoint_origin == "convention":
            return "convention"
        if self._message_handler is not None \
                or self._work_handler is not None:
            return "handlers"
        return None

    def _link_check_ctx(self, nonce: str) -> dict:
        return {"kind": "link_check",
                "agent": self._agent_profile(),
                "username": self.username,
                "nonce": nonce,
                "synthetic": True}

    async def _run_link_check(self, mode: str) -> bool:
        """The live self-check (v1.8.0): a synthetic probe event
        travels the wired path and must come back DECIDED inside
        the deadline. Any decision value — including the agent's
        chosen silence (None) — is a decision; a link error or a
        timeout is not. Handlers mode is the one exception to
        probing: the path is the process itself, so verification
        is structural (a handler is registered) and real dispatch
        outcomes carry the state from there — injecting a fake
        event into the agent's own handler would falsify the
        very event stream the honesty law protects."""
        import secrets as _secrets
        nonce = _secrets.token_hex(8)
        ctx = self._link_check_ctx(nonce)
        try:
            if mode == "handlers":
                # No probe is injected: a synthetic frame would
                # falsify the agent's own event stream (handlers
                # act on frames — they count, record, reply).
                # The in-process path has no transport that can
                # be down; a registered handler IS the verified
                # wiring, and real dispatch outcomes (a handler
                # raising, a handler answering) move the state
                # from here — see _note_link_failure/_success
                # call sites on the handler paths.
                return (self._message_handler is not None
                        or self._work_handler is not None)
            await asyncio.wait_for(
                self._call_decision(ctx),
                timeout=DECISION_LINK_CHECK_TIMEOUT_SECONDS)
            return True
        except Exception:
            return False

    async def _probe_convention(self) -> bool:
        """Probe THE convention endpoint (v1.8.0):
        DECISION_CONVENTION_URL. Adoption is deliberately
        strict — the endpoint must echo the probe's nonce in its
        decision, proving it is answering THIS agent's probe as
        a decision endpoint for this agent. On a shared host,
        another agent's endpoint (which decides in its own
        words, without this agent's nonce) is never adopted."""
        import secrets as _secrets
        nonce = _secrets.token_hex(8)
        ctx = self._link_check_ctx(nonce)
        url = DECISION_CONVENTION_URL

        def _post() -> tuple[int, bytes]:
            import urllib.error
            import urllib.request
            req = urllib.request.Request(
                url, data=json.dumps(ctx).encode(),
                headers={"Content-Type": "application/json"},
                method="POST")
            try:
                with urllib.request.urlopen(
                        req,
                        timeout=DECISION_LINK_CHECK_TIMEOUT_SECONDS
                        ) as resp:
                    return resp.status, resp.read()
            except urllib.error.HTTPError as exc:
                return exc.code, exc.read() or b""

        try:
            status, raw = await asyncio.wait_for(
                asyncio.to_thread(_post),
                timeout=DECISION_LINK_CHECK_TIMEOUT_SECONDS + 2)
        except Exception:
            return False
        if status != 200 or nonce.encode() not in raw:
            return False
        self.decision_endpoint = url
        self._endpoint_origin = "convention"
        log.info("decision link: adopted the convention endpoint "
                 "%s (nonce-verified as this agent's own)", url)
        return True

    async def _autowire_decision_link(self) -> None:
        """Wire + verify the decision link (v1.8.0). Runs BEFORE
        every hello — at registration and on every connect — so
        the declaration the hello carries is always the current
        truth. Never raises: a wiring failure is a state
        ('pending'), not a registration failure."""
        if not self._autonomous_on():
            self._link_mode = "none"
            self._link_verified = False
            return
        try:
            mode = self._local_link_mode()
            if mode is None:
                if await self._probe_convention():
                    mode = "convention"
                    self._set_link_state(mode, True)
                    return
                mode = "none"
            # The mode lands BEFORE the check runs, so the check
            # travels the very path the mode declares (dispatch
            # follows the resolved mode — see _call_decision).
            self._link_mode = mode
            verified = await self._run_link_check(mode) \
                if mode != "none" else False
            self._set_link_state(mode, verified)
        except Exception:
            log.exception("decision link auto-wiring failed")
            self._link_mode = "none"
            self._link_verified = False

    def _set_link_state(self, mode: str, verified: bool) -> None:
        """Record a link state and re-declare it if it changed.
        Single funnel for every transition — auto-wiring, the
        recheck loop, real decision outcomes — so the stored
        declaration can never drift from the living state."""
        changed = (mode != self._link_mode
                   or bool(verified) != self._link_verified)
        self._link_mode = mode
        self._link_verified = bool(verified)
        self._link_checked_at = int(time.time())
        if changed:
            self._refresh_link_declaration()

    def _note_link_failure(self) -> None:
        """A real decision call failed at the link (v1.8.0): the
        state flips to pending TRUTHFULLY, at once — surfaces
        stop calling a dead path 'linked' the moment it dies."""
        if self._link_verified and self._link_mode != "none":
            self._set_link_state(self._link_mode, False)

    def _note_link_success(self) -> None:
        """A real decision came back over the link (v1.8.0): a
        path that was failing has answered again — the state
        recovers without waiting for the recheck cadence."""
        if not self._link_verified and self._link_mode != "none":
            self._set_link_state(self._link_mode, True)

    async def _link_recheck_loop(self, ws=None) -> None:
        """Serve-loop re-verification (v1.8.0), session-bound
        like the heartbeat: every DECISION_LINK_RECHECK_SECONDS
        the wired path must prove itself again (a decision
        endpoint can die mid-session; the declaration follows
        within one cadence), and an unwired client retries the
        full auto-wiring (its agent may have started its
        endpoint after registering)."""
        ws = ws if ws is not None else self._ws
        while True:
            await asyncio.sleep(DECISION_LINK_RECHECK_SECONDS)
            if self._ws is not ws or self._ws is None:
                return
            try:
                if not self._autonomous_on():
                    continue
                if self._link_mode == "none":
                    await self._autowire_decision_link()
                else:
                    verified = await self._run_link_check(
                        self._link_mode)
                    self._set_link_state(self._link_mode, verified)
            except Exception:
                log.exception("decision link recheck failed")

    def _refresh_link_declaration(self) -> None:
        """Re-declare the decision link when its state changes
        AFTER the hello (v1.3.5 fix): an agent that wires its link
        in its own time — handlers registered after connect — must
        not leave every surface repeating the hello-time snapshot
        of a living state (the baseline suite showed a stale
        "pending" stranding real agents' work and mislabelling
        wired agents). Best-effort by design: if there is no live
        connection or no running loop yet, the next hello carries
        the current value, which is the same truth one step later.

        v1.8.0: the declaration is the (summary, detail) pair —
        a mode or verification change re-declares exactly like a
        summary change. A handler/callable registered while the
        link stood at 'none' first re-resolves the local wiring
        and schedules its verification."""
        if not self._autonomous_on():
            return
        if self._link_mode == "none":
            local = self._local_link_mode()
            if local in ("in_process", "handlers"):
                self._link_mode = local
                try:
                    loop = asyncio.get_running_loop()
                except RuntimeError:
                    loop = None
                if loop is not None:
                    loop.create_task(self._verify_and_declare(local))
        current = self._decision_declaration()
        detail = self._decision_detail()
        detail_json = json.dumps(detail, sort_keys=True)
        if (current == self._declared_link_sent
                and detail_json == self._declared_detail_sent) \
                or (self._ws is None and self._v2 is None) \
                or not self._hello_sent:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._declared_link_sent = current
        self._declared_detail_sent = detail_json
        loop.create_task(self._send_link_update(current, detail))

    async def _verify_and_declare(self, mode: str) -> None:
        verified = await self._run_link_check(mode)
        self._set_link_state(mode, verified)

    async def _send_link_update(self, value: str,
                                detail: dict) -> None:
        try:
            if self._v2 is not None:
                # Serverless: the update's home is my own al_users
                # row (the transport validates + cleans exactly as
                # the relay's setters do, and the stored
                # declaration rides every later token refresh).
                await asyncio.to_thread(
                    self._v2.update_decision_link, value, detail)
                return
            await self._send_raw(
                {"type": "decision_link_update",
                 "decision_link": value,
                 "decision_link_detail": detail})
        except Exception:
            pass

    def _warn_if_unlinked(self) -> None:
        """Autonomous mode with the decision link NOT VERIFIED:
        the connection will hold the line — it will not reply to
        messages and will not execute work, because answering or
        accepting on the agent's behalf without its own decision
        would be fabrication. Say so LOUDLY at startup: silence by
        surprise would be a lie about the agent's presence; the
        held line, declared, is the truth. Since v1.8.0 the
        client has already TRIED to wire itself — explicit
        config, the in-process callable, its handlers, and the
        convention endpoint — so this warning distinguishes the
        two honest cases: nothing was found anywhere, or a path
        was found but its self-check did not come back decided."""
        if not self._autonomous_on() or self._auto_warned_unlinked:
            return
        if self._link_verified:
            return
        self._auto_warned_unlinked = True
        if self._link_mode == "none":
            log.warning(
                "DECISION LINK PENDING: @%s is in autonomous mode, "
                "and the auto-wiring found no link to the agent's "
                "own decision-making — it searched the explicit "
                "config (decision_endpoint= / "
                "AGENTLINK_DECISION_ENDPOINT / --decision-endpoint), "
                "an in-process decision callable (Agent(..., "
                "decision_link=...)), the agent's own handlers, and "
                "the platform convention endpoint %s, and none "
                "answered — the agent itself is the intelligence, "
                "and this connection is only its line: it holds "
                "the line until a link verifies: messages and work "
                "queue safely and are NOT answered or accepted on "
                "the agent's behalf.",
                self.username, DECISION_CONVENTION_URL)
        else:
            log.warning(
                "DECISION LINK UNVERIFIED: @%s is in autonomous "
                "mode and its decision link is wired via %s, but "
                "the live self-check did not come back decided — "
                "the line is held (messages and work queue, "
                "nothing is answered on the agent's behalf) until "
                "the path answers again; the client keeps "
                "re-checking on its own.",
                self.username, self._link_mode)
        self._auto_log("decision_link_pending_warning")

    # Pre-1.3.5 name, kept as an alias so nothing that calls it
    # breaks; the warning it emits is the truthful one above.
    _warn_if_brainless = _warn_if_unlinked

    def _agent_profile(self) -> dict:
        return {"username": self.username,
                "display_name": self.display_name,
                "mode": self.mode,
                "designation": self.designation,
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
        dressed up as the agent's silence.

        Dispatch follows the owner's precedence (v1.8.0): an
        explicitly configured endpoint answers before the
        in-process callable when BOTH are present — the declared
        mode and the real path never diverge."""
        if self._link_mode in ("config", "convention") \
                and self.decision_endpoint is not None:
            return await self._call_decision_endpoint(ctx)
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
                # The declared link state flips to pending at
                # once (v1.8.0) — a dead path is never still
                # called 'linked' on any surface.
                self._note_link_failure()
                log.warning("decision link failed on a message "
                            "from @%s: %s", sender, exc)
                self._auto_log("decision_link_error", conv,
                               sender=sender)
                return
            except Exception:
                log.exception("decision callable failed on a message")
                self._auto_log("decision_error", conv, sender=sender)
                return
            self._note_link_success()
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
            # The declared link state flips to pending at once
            # (v1.8.0), exactly as on the message path.
            self._note_link_failure()
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
        self._note_link_success()
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
        result = await self._send_request(frame)
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
        result = await self._send_request(frame)
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
            # ONE RECORD PER (id, attempt) — key-guarded append
            # (v1.6.0): this append is shared by the normal path
            # and the boot-defer path above, and the defer path
            # deliberately skips the _seen_work guard (the resume
            # pass owns the spawn) — but the resume pass ALSO
            # appends this work as its own record. Unguarded, a
            # custody re-offer landing in the window between the
            # resume pass journaling the work and the boot gate
            # opening appended a SECOND assigned_work entry for
            # one assignment. (The window was a rarity at the old
            # 1s scan cadence; the dedicated frame drain made it
            # routine — the gate caught it.) Key-guard the append
            # itself so every path agrees on the invariant.
            if not any(w.get("id") == work.get("id")
                       and int(w.get("attempt") or 1) == wkey[1]
                       for w in self.assigned_work):
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
                    # A real dispatch through the agent's own
                    # work handler completed (v1.8.0): the link
                    # state hears about it, as on the message path.
                    self._note_link_success()
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

    async def _ensure_keys_for_work(self, raws) -> None:
        """Fetch the group keys an inbox's group work needs BEFORE
        any of it is decrypted (43d, hardened in v1.6.0): group
        content and checkpoints are group-key-sealed, and a
        restart can reach a journal-populating pass with the key
        cache cold — file deleted (only a CORRUPT cache triggers
        the resync in self_check) or keys not yet re-delivered.
        Decrypting anyway silently drops the checkpoint the
        backend mirror faithfully kept; the entry then looks
        checkpoint-less forever. Ensuring keys first makes the
        mirror's contents recoverable at every population pass,
        not just the lucky ones."""
        for raw in raws:
            gid = raw.get("group_id")
            if gid and gid not in self._group_keys:
                await self._ensure_group_key(gid)

    async def _resume_open_work(self) -> None:
        """Boot steps 3-4: fetch open assignments from the relay, merge
        the local journal, and re-invoke handlers — with the exact
        checkpoint when one exists (ctx.resumed=True)."""
        if self._journal is None:
            return
        data = await self._request({"type": "work_inbox", "status": None,
                                    "group_id": None})
        await self._ensure_keys_for_work(data.get("work", []))
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
            # Dedup on the (id, attempt) KEY, never on dict
            # equality (v1.6.0): the frame path may already have
            # appended its own decrypt of this same assignment —
            # with the dedicated frame drain, custody frames now
            # routinely land DURING boot, before this pass — and
            # the two dicts are only transiently equal (either may
            # be mutated by its runner), so `work not in
            # assigned_work` intermittently appended a SECOND
            # entry for one assignment (assigned_work is the
            # agent's public workload record; a duplicate corrupts
            # every count built on it). Exactly one entry per
            # (id, attempt), whichever path arrives first.
            if not any(w.get("id") == work["id"]
                       and int(w.get("attempt") or 1)
                       == int(work.get("attempt") or 1)
                       for w in self.assigned_work):
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
        entry = self._journal.get(work_id) if self._journal else None
        work = entry or next((w for w in self.assigned_work
                              if w["id"] == work_id), None)
        if work is None:
            # The assignment's push may not have been ingested yet:
            # a checkpoint recorded the moment work lands races the
            # frame that carries it (the 43d failure mode, root-
            # caused in the v1.6.0 gate — the call returned
            # silently, the mirror stayed empty, and a later
            # restart had nothing to recover). A checkpoint for
            # unknown work is NEVER a silent no-op: fetch the
            # assignment from the backend, journal it, and mirror
            # as usual. Only a work id the backend itself does not
            # hold for this agent is an error — a loud one.
            data_inbox = await self._request(
                {"type": "work_inbox", "status": None,
                 "group_id": None})
            for raw in data_inbox.get("work", []):
                if raw.get("id") != work_id \
                        or raw.get("assignee") != self.username:
                    continue
                await self._ensure_keys_for_work([raw])
                work = self._decrypt_work(raw)
                # Key-based dedup, as in _resume_open_work: one
                # assigned_work entry per (id, attempt).
                if not any(w.get("id") == work["id"]
                           and int(w.get("attempt") or 1)
                           == int(work.get("attempt") or 1)
                           for w in self.assigned_work):
                    self.assigned_work.append(work)
                break
        if work is None:
            raise ValueError(
                f"checkpoint for unknown work {work_id}: not in "
                "the local journal, not among assigned work, and "
                "not in the backend inbox — nothing was mirrored")
        if self._journal is not None:
            # Journal-first (the point-30 order): the entry must
            # exist for the checkpoint to land on, so journal the
            # work itself first when this call is what found it.
            if self._journal.get(work_id) is None:
                self._journal.put(work)
            self._journal.set_checkpoint(work_id, data)
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
        result = await self._send_request(frame)
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
        self.capabilities = caps
        self.cap_description = description
        # Connector-derived synthesis (v1.8.1): what the line
        # advertises is the declared set UNION what the agent's
        # connector vault confers — the signature covers the
        # SYNTHESIZED set, exactly what the relay will store.
        advertised = self.advertised_capabilities()
        canonical = "caps|{}|{}|{}".format(
            self.username, ",".join(advertised),
            description).encode()
        data = await self._request({
            "type": "update_capabilities",
            "capabilities": advertised,
            "description": description,
            "sig": self.identity.sign(canonical)})
        # 2.2.0: the publish is durable local state from here —
        # the next session's boot declare re-presents this
        # declaration instead of unpublishing it with the
        # constructor default.
        self._save_capabilities_declaration()
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
                self._pubkey_cache[u["username"]] = (
                    u["pubkey"], time.time())
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
