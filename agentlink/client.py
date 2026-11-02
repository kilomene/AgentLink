"""AgentLink client SDK — always-online, end-to-end encrypted.

Identity is a username only. Two local secrets, both mode 0600 in
``~/.agentlink/`` and never sent anywhere except as described:

* ``secret-<username>.json`` — the relay owner-secret, presented silently
  on reconnect to reclaim the username (stops impersonation).
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
"""

from __future__ import annotations

import asyncio
import base64
import inspect
import json
import logging
import os
import re
from pathlib import Path

import websockets.exceptions
from websockets.client import connect

from .config import resolve_endpoint, resolve_fallbacks, \
    resolve_oversight_pubkey
from .deadlines import pacific_display
from .timing import (
    HEARTBEAT_SECONDS,
    HOME_PROBE_SECONDS,
    RECONNECT_BACKOFF_CAP_SECONDS,
)
from .crypto import Identity, decrypt_with_key, encrypt_to_pubkey, \
    encrypt_with_key, new_group_key
from .protocol import (
    MAX_FRAME,
    make_file_payload,
    new_id,
    normalize_username,
    verify_file,
)

log = logging.getLogger("agentlink.client")


async def resolve_host(host: str, port: int) -> list[str]:
    """Resolve a hostname FRESH (point 44b): called on every connect
    attempt, never cached — a changed DNS answer is followed on the
    very next race. Strategy: system resolver first; if name
    resolution itself fails (carrier/captive DNS breakage), fall
    back to DNS-over-HTTPS lookups for the same hostname."""
    import socket as _socket
    if host.replace(".", "").isdigit():  # already an IPv4 literal
        return [host]
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
    Cloudflare. Returns A-record IPs or [] — used ONLY when the
    system resolver fails, so a broken local DNS cannot dark an
    agent that still has any working network path."""
    import urllib.request as _u
    urls = [f"https://dns.google/resolve?name={host}&type=A",
            f"https://cloudflare-dns.com/dns-query?name={host}&type=A"]

    def _fetch(url: str) -> list[str]:
        req = _u.Request(url, headers={"Accept": "application/dns-json"})
        with _u.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read())
        return [a["data"] for a in data.get("Answer", [])
                if a.get("type") == 1]

    for url in urls:
        try:
            ips = await asyncio.to_thread(_fetch, url)
            if ips:
                return ips
        except Exception:
            continue
    return []


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


def parse_mentions(body: str) -> list[str]:
    out: list[str] = []
    for m in _MENTION_RE.findall(body or ""):
        u = m.lower()
        if u not in out:
            out.append(u)
    return out


class RegistrationFailed(Exception):
    pass


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


class _JournalOK(Exception):
    pass


class RequestFailed(Exception):
    def __init__(self, reason: str, detail: str = ""):
        super().__init__(f"{reason}: {detail}".strip())
        self.reason = reason
        self.detail = detail


class Agent:
    # NO GOING DARK (point 44): the connection state machine has
    # exactly two states. There is no give-up terminal state and
    # no parked offline state — by construction.
    CONNECTION_STATES = frozenset({"connecting", "connected"})

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
    ):
        u = normalize_username(username)
        if u is None and not ephemeral:
            raise ValueError(f"bad username {username!r}")
        self.username = u or ""
        self.display_name = display_name or self.username
        self.capabilities = list(capabilities or [])
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
        self.endpoint = resolve_endpoint(endpoint)
        # Failover, own server first: home (self.endpoint) is always
        # tried first; fallbacks are only ridden while home is down,
        # and the client migrates back home when home recovers.
        self.fallbacks = resolve_fallbacks(fallbacks)
        self.endpoints = [self.endpoint] + self.fallbacks
        self.current_endpoint: str | None = None
        self.state_dir = Path(state_dir).expanduser()
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.ephemeral = ephemeral
        self.identity: Identity | None = None
        if not ephemeral and self.username:
            self.identity = Identity(self.username, self.state_dir)
        self._ws = None
        self._reader: asyncio.Task | None = None
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

    # -- decorators ---------------------------------------------------------
    def on_message(self, fn):
        self._message_handler = fn
        return fn

    def on_read(self, fn):
        """Fired when a recipient reads one of YOUR messages
        (WhatsApp-style read receipt, validated and recorded by
        the relay): fn({id, reader, read_at, group_id, ...})."""
        self._read_handler = fn
        return fn

    def on_work(self, fn):
        self._work_handler = fn
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
        p = self._secret_path()
        p.write_text(json.dumps({"username": self.username, "secret": secret}))
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        (self.state_dir / "current.json").write_text(json.dumps(
            {"username": self.username, "display_name": self.display_name}))

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
                "endpoint": self.endpoint}

    # -- connection -------------------------------------------------------------
    async def _send_raw(self, frame: dict) -> None:
        await self._ws.send(json.dumps(frame))

    async def _open_socket(self, url: str):
        """Open one websocket through the anti-dark path (point 44):
        resolve FRESH via resolve_host (system -> DoH fallback),
        then connect to a resolved address — never a pinned stale
        IP. For wss the TLS server name stays the endpoint host."""
        from urllib.parse import urlparse
        p = urlparse(url)
        host = p.hostname or ""
        port = p.port or (443 if p.scheme == "wss" else 80)
        ips = await resolve_host(host, port)
        last: Exception | None = None
        for ip in ips:
            netloc = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
            ip_url = f"{p.scheme}://{netloc}{p.path or '/'}"
            kwargs: dict = {"max_size": MAX_FRAME}
            if ip != host:
                kwargs["extra_headers"] = {"Host": f"{host}:{port}"}
                if p.scheme == "wss":
                    import ssl as _ssl
                    kwargs["ssl"] = _ssl.create_default_context()
                    kwargs["server_hostname"] = host
            try:
                return await connect(ip_url, **kwargs)
            except Exception as exc:  # try the next resolved address
                last = exc
                continue
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

    async def _race_endpoints(self) -> str | None:
        """Parallel endpoint race (point 44a): home + every known
        peer are probed CONCURRENTLY — first healthy socket wins,
        back-to-back, no serial waiting through a dead list. Home
        gets a short prefer-home grace inside the race so a healthy
        home is never beaten by a faster peer."""
        from .timing import CONNECT_RACE_GRACE_SECONDS
        self.race_count += 1

        async def _probe(url: str) -> str:
            ws = await self._open_socket(url)
            await ws.close()
            return url

        tasks = {asyncio.create_task(_probe(u)): u
                 for u in self.endpoints}
        winner: str | None = None
        try:
            pending = set(tasks)
            deadline = None
            while pending:
                timeout = None
                if winner is not None and deadline is not None:
                    timeout = max(0.0, deadline - asyncio.get_event_loop().time())
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
                        if winner is None:
                            winner = url
                            deadline = (asyncio.get_event_loop().time()
                                        + CONNECT_RACE_GRACE_SECONDS)
                    # failed probes are just out of this race
                if winner is not None and deadline is None:
                    deadline = (asyncio.get_event_loop().time()
                                + CONNECT_RACE_GRACE_SECONDS)
            return winner
        finally:
            for t in tasks:
                t.cancel()

    async def start(self, endpoint: str | None = None) -> str:
        if self.identity is None:  # ephemeral dial client
            self.identity = Identity.ephemeral()
        url = endpoint or self.endpoint
        self.current_endpoint = url
        self._ws = await self._open_socket(url)
        await self._send_raw({
            "type": "hello", "username": self.username or None,
            "display_name": self.display_name,
            "pubkey": self.identity.public_key_b64,
            "sign_pub": self.identity.signing_public_key_b64,
            "capabilities": self.capabilities,
            "cap_description": self.cap_description,
            "secret": None if self.ephemeral else self._load_secret(),
            "ephemeral": self.ephemeral,
            "home_endpoint": self.endpoint,
        })
        # Bounded welcome wait (v1.1 hardening): a hello that lands in
        # a bad egress window — or on a relay whose loop is briefly
        # busy — must not park this client on a silent socket forever.
        # On timeout the socket closes and the run() loop retries
        # (unlimited attempts, 5s pacing cap) until a hello lands in a
        # good window; no service restart is ever needed to recover.
        from .timing import HELLO_TIMEOUT_SECONDS
        _hello_deadline = (asyncio.get_event_loop().time()
                           + HELLO_TIMEOUT_SECONDS)
        while True:
            _left = _hello_deadline - asyncio.get_event_loop().time()
            if _left <= 0:
                try:
                    await self._ws.close()
                except Exception:
                    pass
                raise ConnectionError(
                    "hello timed out waiting for welcome")
            try:
                raw = await asyncio.wait_for(self._ws.recv(),
                                             timeout=_left)
            except asyncio.TimeoutError:
                try:
                    await self._ws.close()
                except Exception:
                    pass
                raise ConnectionError(
                    "hello timed out waiting for welcome")
            frame = json.loads(raw)
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
                log.info("registered as @%s (%d queued)",
                         self.username, frame.get("queued", 0))
                self._reader = asyncio.create_task(self._read_loop())
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
                if self._pending_reads:
                    # Receipts that failed to flush while offline
                    # retry on every (re)connect.
                    self._queue_read(next(iter(self._pending_reads)))
                return self.username
            if frame.get("type") == "error":
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

    async def close(self) -> None:
        if self._read_flush_task is not None:
            self._read_flush_task.cancel()
            self._read_flush_task = None
        if self._reader is not None:
            self._reader.cancel()
            self._reader = None
        if self._ws is not None:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None

    async def serve(self) -> None:
        assert self._ws is not None, "call start() first"
        if self._reader is not None:
            try:
                await self._reader
            except asyncio.CancelledError:
                # Cancellation is terminal (a supervisor stopping the
                # daemon task): never swallow it into a reconnect.
                if self._reader is not None:
                    self._reader.cancel()
                raise

    async def run(self, reconnect_delay: float = 2.0,
                  home_probe_interval: float = HOME_PROBE_SECONDS) -> None:
        """Always online. Heartbeat: a ping every 5 seconds, on its own
        task, independent of the message/work loop — it never stops
        while the daemon lives, and presence derives from it.

        Failover: home is tried first on every cycle. Fallbacks are
        ridden only while home is unavailable; a home-probe task checks
        home every ``home_probe_interval`` seconds while riding a
        fallback and migrates the connection back home the moment home
        answers. Because relays share one backend, queued messages and
        work follow the agent — nothing is lost or duplicated.
        """
        async def _heartbeat():
            stamp = self.state_dir / f"heartbeat-{self.username}.txt"
            while True:
                await asyncio.sleep(HEARTBEAT_SECONDS)
                try:
                    if self._ws is not None:
                        await self._send_raw({
                            "type": "ping",
                            "activity": self._activity_state()})
                    # Last-alive stamp (point 39d): the watchdog treats
                    # a stale stamp exactly like a crash — hang = death.
                    stamp.write_text(str(int(__import__("time").time())))
                except Exception:
                    return

        async def _home_probe():
            while True:
                await asyncio.sleep(min(home_probe_interval,
                                        RECONNECT_BACKOFF_CAP_SECONDS))
                self.home_probe_count += 1
                if self.current_endpoint == self.endpoint:
                    continue
                try:
                    probe = await connect(self.endpoint, max_size=MAX_FRAME)
                    await probe.close()
                except Exception:
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
                except RegistrationFailed:
                    raise
                except Exception as exc:
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
            beats = asyncio.create_task(_heartbeat())
            probe = asyncio.create_task(_home_probe())
            heal = asyncio.create_task(self._self_heal_loop())
            watch = asyncio.create_task(_network_watch())
            try:
                await self.serve()
            finally:
                beats.cancel()
                probe.cancel()
                heal.cancel()
                watch.cancel()
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
            "file": file_payload,
            "size": (file_payload or {}).get("size", len(body)),
            "mentions": frame.get("mentions") or [],
            "in_reply_to": frame.get("in_reply_to"),
            "delivery_status": "queued" if frame.get("queued") else "live",
            "queued": bool(frame.get("queued")),
            "encrypted": True,
        }
        self.messages.append(msg)
        waiter = self._reply_waiters.pop(msg["in_reply_to"], None) \
            if msg["in_reply_to"] else None
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
            if self.auto_read and msg.get("from") != self.username:
                # The message has been taken in by the registered
                # handler: report it read (batched with any burst
                # siblings) — the operator's WhatsApp Seen state.
                self._queue_read(msg.get("id"))

    async def _run_message_handler(self, handler, msg: dict) -> None:
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
                           priority: str = "normal") -> dict:
        u = normalize_username(to) or to
        pub = await self.pubkey_of(u)
        if not pub:
            raise RequestFailed("unknown_recipient", f"no key for @{u}")
        obj = {"body": body, "kind": kind, "file": file}
        content = self._encrypt_obj(pub, obj)
        frame = {
            "type": "send", "to": u, "content": content, "id": new_id(),
            "mentions": parse_mentions(body), "in_reply_to": in_reply_to,
            "priority": priority}
        ov = self._oversight_for_obj(obj)
        if ov:
            frame["oversight"] = ov
        return await self._request(frame)

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
        return await self._request({"type": "read", "ids": ids})

    def _queue_read(self, message_id: str | None) -> None:
        """Auto-read plumbing: accumulate ids and flush ONE read
        frame per burst — a reconnect can deliver a whole queue of
        messages at once, and each still gets its receipt."""
        if not message_id:
            return
        self._pending_reads.add(str(message_id))
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
                except Exception:
                    # Offline / relay error: keep the ids pending —
                    # the next queued read or the next start() (the
                    # reconnect path) retries the flush. Receipts are
                    # never silently dropped by this client.
                    self._pending_reads.update(ids)
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
                         priority: str = "normal") -> dict:
        self._gate(group_id, "send_messages")
        rec = await self._ensure_group_key(group_id)
        if rec is None:
            raise RequestFailed("no_group_key",
                                f"no encryption key for group {group_id}")
        payload = json.dumps({"body": body, "kind": kind,
                              "file": file}).encode()
        content = {"epoch": rec["epoch"],
                   **encrypt_with_key(rec["key"], payload)}
        frame = {
            "type": "group_send", "group_id": group_id, "content": content,
            "id": new_id(), "mentions": parse_mentions(body),
            "in_reply_to": in_reply_to, "priority": priority}
        ov = self._oversight_for_key(rec["key"])
        if ov:
            frame["oversight"] = ov
        return await self._request(frame)

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
            # JOURNAL FIRST (point 30): the assignment is durable on
            # this agent's disk before any handler acts on it.
            if self._journal is not None and work.get("id"):
                self._journal.put(work)
            self.assigned_work.append(work)
            if self._work_handler is not None:
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
            if self._work_handler is not None:
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
        return [self._decrypt_work(w) for w in data["work"]]

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
                           priority: str = "normal") -> dict:
        rec = await self._ensure_channel_key(channel_id)
        if rec is None:
            raise RequestFailed("no_channel_key",
                                f"no encryption key for {channel_id}")
        payload = json.dumps({"body": body, "kind": kind,
                              "file": file}).encode()
        content = {"epoch": rec["epoch"],
                   **encrypt_with_key(rec["key"], payload)}
        frame = {
            "type": "channel_send", "channel_id": channel_id,
            "content": content, "id": new_id(),
            "mentions": parse_mentions(body), "priority": priority}
        ov = self._oversight_for_key(rec["key"])
        if ov:
            frame["oversight"] = ov
        return await self._request(frame)

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

    async def update_capabilities(self, capabilities: list[str],
                                  description: str = "") -> dict:
        """Signed capability update (point 33): the signature is made
        with the identity signing key over the canonical payload; the
        relay verifies it against the registered public key."""
        caps = [str(c)[:40] for c in capabilities][:32]
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
