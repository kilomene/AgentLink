"""Dial-time egress-proxy credential resolution and racing.

THE DEFECT THIS KILLS: outbound transports used to take the
egress-proxy credential from the PROCESS ENVIRONMENT — a value
pinned at process start. When the runtime rotates the proxy
token, the environment of every already-running process keeps
the dead credential, and the transport strands until a restart
or an operator swap (the 2026-11-04 front-door outage: the
VM's networking was fine, every credential on the box was
either rejected 407 or stalled after auth, and long-lived
processes had no way to adopt the fresh one).

THE PATTERN (the platform-wide contract, shared with the
tunnel client): every outbound connection attempt RESOLVES
credentials fresh, races the candidates in parallel —
first success wins — caches the winner, and invalidates the
cache on failure. Adoption of a rotated credential never
needs a restart. Resolution order (canonical contract):

  1. the CANONICAL VERIFIED-CREDENTIAL FILE — proxy_watch
     publishes the currently-verified working credential to
     ~/workspace/agentlink-deploy/proxy-current.env
     (atomically, 0600, KEY=value env format;
     $AGENTLINK_PROXY_CANONICAL may name another path). It
     outranks everything, including the local winner cache:
     it is verified evidence, not a guess. The chain is
     complete without it — an absent file is skipped.
  2. the cached winner (locally verified by a completed
     dial; dropped the moment it fails),
  3. a proxy override ($AGENTLINK_PROXY_OVERRIDE names a
     proxy.env-style file or a file holding one proxy URL),
  4. the current ~/.vm-agent/proxy.env — re-read at every
     resolution, so a rotation that lands on disk is seen,
  5. harvested candidates: proxy values found in process
     environments under /proc (a sibling started after the
     rotation carries the fresh credential even when this
     process's env is stale; this process's own env arrives
     here too).

Credentials are NEVER logged: diagnostics name a candidate
only by a truncated SHA-256 of its URL ("proxy#1a2b3c4d").
"""
from __future__ import annotations

import hashlib
import logging
import os
import threading

log = logging.getLogger("agentlink.proxy")

OVERRIDE_ENV = "AGENTLINK_PROXY_OVERRIDE"
CANONICAL_ENV = "AGENTLINK_PROXY_CANONICAL"
DEFAULT_CANONICAL_PATH = os.path.join(
    "~", "workspace", "agentlink-deploy", "proxy-current.env")
PROXY_ENV_NAME = os.path.join(".vm-agent", "proxy.env")
_KEYS = ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY",
         "all_proxy", "ALL_PROXY")
_PROC_ROOT = "/proc"

_lock = threading.Lock()
_winner: str = ""


def describe(proxy_url: str) -> str:
    """A log-safe name for a candidate: hash prefix only."""
    if not proxy_url:
        return "proxy#none"
    h = hashlib.sha256(proxy_url.encode()).hexdigest()[:8]
    return f"proxy#{h}"


def _parse_env_text(text: str) -> list[str]:
    out: list[str] = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            # A bare URL line (an override file may hold just
            # the proxy URL).
            if "://" in line:
                out.append(line.strip().strip('"').strip("'"))
            continue
        key, _, val = line.partition("=")
        if key.strip() in _KEYS:
            val = val.strip().strip('"').strip("'")
            if val:
                out.append(val)
    return out


def _read_file(path: str) -> list[str]:
    try:
        with open(path, "r", errors="replace") as fh:
            return _parse_env_text(fh.read())
    except OSError:
        return []


def _harvested_values(proc_root: str | None = None) -> list[str]:
    """Proxy values other processes carry. Best-effort: an
    unreadable /proc entry is skipped, never fatal."""
    root = proc_root or _PROC_ROOT
    out: list[str] = []
    try:
        pids = os.listdir(root)
    except OSError:
        return out
    for pid in pids:
        if not pid.isdigit():
            continue
        try:
            with open(os.path.join(root, pid, "environ"),
                      "rb") as fh:
                raw = fh.read(262144)
        except OSError:
            continue
        for kv in raw.split(b"\0"):
            if b"=" not in kv:
                continue
            k, _, v = kv.partition(b"=")
            if k.decode(errors="replace") in _KEYS:
                val = v.decode(errors="replace").strip()
                if val and val not in out:
                    out.append(val)
        if len(out) >= 16:
            break
    return out


def canonical_path() -> str:
    named = (os.environ.get(CANONICAL_ENV) or "").strip()
    return os.path.expanduser(named or DEFAULT_CANONICAL_PATH)


def candidate_proxies(proc_root: str | None = None) -> list[str]:
    """The ordered, de-duplicated candidate list, resolved
    FRESH at every call, in the canonical contract order:
    the verified-credential file, the cached winner, the
    override, the current proxy.env, harvested /proc values."""
    ordered: list[str] = []

    def _add(url: str):
        url = (url or "").strip()
        if url and url not in ordered:
            ordered.append(url)

    for u in _read_file(canonical_path()):
        _add(u)
    with _lock:
        winner = _winner
    if winner:
        _add(winner)
    override = (os.environ.get(OVERRIDE_ENV) or "").strip()
    if override:
        if "://" in override and "=" not in override \
                and not override.endswith(".env"):
            _add(override)  # the value IS a proxy URL
        else:
            for u in _read_file(override):
                _add(u)
    for path in _proxy_env_paths():
        for u in _read_file(path):
            _add(u)
    for u in _harvested_values(proc_root):
        _add(u)
    return ordered


def _proxy_env_paths() -> list[str]:
    """Every proxy.env location that may hold the current
    credential: the caller's own ~/.vm-agent/proxy.env PLUS
    each /home/*/.vm-agent/proxy.env. The /home sweep is not
    decoration: a process running as root resolves "~" to
    /root and would otherwise never see the deployment
    user's file — the exact trap that bit tunnel_watch's
    first systemd runs."""
    paths = [os.path.expanduser(os.path.join("~", PROXY_ENV_NAME))]
    try:
        for name in sorted(os.listdir("/home")):
            p = os.path.join("/home", name, PROXY_ENV_NAME)
            if p not in paths:
                paths.append(p)
    except OSError:
        pass
    return paths


def note_proxy_result(proxy_url: str, ok: bool) -> None:
    """Record a dial outcome. A success crowns the winner; a
    failure of the reigning winner abdicates it, so the next
    resolution re-races the full field."""
    global _winner
    if not proxy_url:
        return
    with _lock:
        if ok:
            if _winner != proxy_url:
                _winner = proxy_url
                log.info("egress proxy adopted: %s",
                         describe(proxy_url))
        elif _winner == proxy_url:
            _winner = ""
            log.warning("egress proxy winner failed, invalidated:"
                        " %s", describe(proxy_url))


def open_url(req, timeout: float = 30.0):
    """Open a urllib Request, racing the freshly resolved
    proxy candidates through explicit ProxyHandlers (urllib's
    default opener would take the proxy from the process
    environment — pinned at process start). Returns the
    response (the caller owns closing it). An HTTPError means
    the request REACHED a server — that candidate worked, so
    it is crowned and the error propagates untouched; only
    transport failures move the race to the next candidate.
    With no proxy in play this is exactly urlopen."""
    import urllib.error
    import urllib.request
    candidates = candidate_proxies()
    if not candidates:
        return urllib.request.urlopen(req, timeout=timeout)
    last: Exception | None = None
    for proxy in candidates:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(
                {"http": proxy, "https": proxy}))
        try:
            resp = opener.open(req, timeout=timeout)
        except urllib.error.HTTPError:
            note_proxy_result(proxy, True)
            raise
        except Exception as exc:
            note_proxy_result(proxy, False)
            last = exc
            continue
        note_proxy_result(proxy, True)
        return resp
    raise last if last is not None else ConnectionError(
        "no egress proxy candidate completed")


def winner() -> str:
    with _lock:
        return _winner


def reset_winner() -> None:
    global _winner
    with _lock:
        _winner = ""
