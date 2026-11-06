"""v1.8.1 — dial-time proxy-credential resolution + racing.

The defect (2026-11-04 front-door outage): outbound transports
took the egress-proxy credential from the PROCESS ENVIRONMENT
— pinned at process start — so a runtime token rotation
stranded every long-lived process until a restart. These pins
hold the canonical pattern (shared with the tunnel client):

  PX1. Resolution order is the contract order — canonical
      verified-credential file, cached winner, override,
      current proxy.env, harvested /proc values — and a file
      rewritten mid-flight (a rotation landing) is adopted on
      the NEXT resolution, no restart.
  PX2. Credentials are never logged: describe() yields only a
      hash prefix.
  PX3. The winner cache crowns on success and abdicates on
      failure.
  PX4. The Supabase store CONNECT transport races candidates
      in parallel: a 407 from the stale credential does not
      strand the dial — the fresh candidate completes, is
      crowned, and when IT later dies the race re-runs and
      crowns the next.
  PX5. The client websocket proxied fallback races the same
      way, and a library without per-dial proxy support falls
      back to the env-honoured connect.
  PX6. proxycreds.open_url (updater / blobstore / webhook):
      transport failure moves to the next candidate; an
      HTTPError means a server answered — crowned, propagated.
"""

from __future__ import annotations

import asyncio
import io
import ssl
import threading
import urllib.error
import urllib.request

import pytest

import agentlink.proxycreds as pc
from agentlink import client as client_module
from agentlink.supabase_store import SupabaseStore

BAD = "http://user:bad-token@proxy.invalid:3128"
GOOD = "http://user:good-token@proxy.invalid:3128"
FRESH = "http://user:fresh-token@proxy.invalid:3128"


@pytest.fixture(autouse=True)
def _clean_winner():
    pc.reset_winner()
    yield
    pc.reset_winner()


def _env_file(path, url):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"https_proxy={url}\n")


# ---------------------------------------------------------------------
# PX1/PX2/PX3 — the resolver itself
# ---------------------------------------------------------------------

def test_px1_resolution_order_and_fresh_adoption(tmp_path,
                                                 monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("HOME", str(home))
    canon = tmp_path / "verified-proxy.env"
    monkeypatch.setenv(pc.CANONICAL_ENV, str(canon))
    override = tmp_path / "override.env"
    monkeypatch.setenv(pc.OVERRIDE_ENV, str(override))
    _env_file(canon, GOOD)
    _env_file(override, BAD)
    _env_file(home / ".vm-agent" / "proxy.env", FRESH)
    got = pc.candidate_proxies(proc_root="/nonexistent-proc")
    # Canonical first, then override, then proxy.env (harvest
    # pointed at an empty root so nothing else interferes).
    assert got[:3] == [GOOD, BAD, FRESH], got
    # A rotation lands in the canonical file: the NEXT
    # resolution adopts it, no restart, nothing restarted.
    _env_file(canon, FRESH)
    got = pc.candidate_proxies(proc_root="/nonexistent-proc")
    assert got[0] == FRESH, got
    # The chain is complete without the canonical file.
    canon.unlink()
    got = pc.candidate_proxies(proc_root="/nonexistent-proc")
    assert got[:2] == [BAD, FRESH], got


def test_px2_describe_never_leaks_the_credential():
    d = pc.describe(GOOD)
    assert d.startswith("proxy#") and len(d) == 14, d
    assert "good-token" not in d and "user" not in d


def test_px3_winner_crowned_and_abdicates(tmp_path, monkeypatch):
    monkeypatch.setenv(pc.CANONICAL_ENV,
                       str(tmp_path / "absent.env"))
    monkeypatch.setenv("HOME", str(tmp_path))
    assert pc.candidate_proxies(
        proc_root="/nonexistent-proc")[:1] != [GOOD]
    pc.note_proxy_result(GOOD, True)
    assert pc.winner() == GOOD
    got = pc.candidate_proxies(proc_root="/nonexistent-proc")
    assert got[0] == GOOD, got
    pc.note_proxy_result(GOOD, False)
    assert pc.winner() == ""


# ---------------------------------------------------------------------
# PX4 — the store CONNECT race
# ---------------------------------------------------------------------

class _FakeRaw:
    """A scripted proxy socket: answers the CONNECT with 200
    only when the Proxy-Authorization carries the good token
    (which tokens are good is controlled per-phase)."""

    good_tokens: set = set()
    attempts: list = []
    _lock = threading.Lock()

    def __init__(self):
        self._buf = b""
        self._sent = b""

    def sendall(self, data):
        self._sent += data
        token = ""
        for line in data.decode("latin1").split("\r\n"):
            if line.lower().startswith("proxy-authorization:"):
                import base64 as _b64
                raw = _b64.b64decode(
                    line.split(" ", 2)[-1]).decode()
                token = raw.split(":", 1)[-1]
        with self._lock:
            type(self).attempts.append(token)
        if token in type(self).good_tokens:
            self._buf = b"HTTP/1.1 200 OK\r\n\r\n"
        else:
            self._buf = (b"HTTP/1.1 407 Proxy Authentication"
                         b" Required\r\n\r\n")

    def recv(self, n):
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def close(self):
        pass


class _FakeWrapped:
    def __init__(self, raw):
        self._raw = raw

    def makefile(self, mode):
        return io.BytesIO(b"")

    def close(self):
        pass

    def settimeout(self, t):
        pass


def _scripted_store(monkeypatch, candidates):
    store = SupabaseStore("https://db.example.invalid", "k")
    monkeypatch.setattr(pc, "candidate_proxies",
                        lambda proc_root=None: list(candidates))
    _FakeRaw.attempts = []
    monkeypatch.setattr(
        "socket.create_connection",
        lambda addr, timeout=0: _FakeRaw())

    class _Ctx:
        def wrap_socket(self, raw, server_hostname=None):
            return _FakeWrapped(raw)

    monkeypatch.setattr(ssl, "create_default_context",
                        lambda: _Ctx())
    return store


def test_px4_store_races_and_adopts_rotation(monkeypatch):
    # Phase 1: the stale credential 407s, the good one wins.
    _FakeRaw.good_tokens = {"good-token"}
    store = _scripted_store(monkeypatch, [BAD, GOOD])
    wrapped, _reader = store._open_conn()
    assert isinstance(wrapped, _FakeWrapped)
    assert pc.winner() == GOOD
    assert set(_FakeRaw.attempts) == {"bad-token", "good-token"}
    # Phase 2: rotation — the crowned winner is now dead and a
    # fresh candidate exists. The next dial re-races and
    # adopts the fresh credential with no restart.
    _FakeRaw.good_tokens = {"fresh-token"}
    store2 = _scripted_store(monkeypatch, [GOOD, FRESH])
    wrapped, _reader = store2._open_conn()
    assert isinstance(wrapped, _FakeWrapped)
    assert pc.winner() == FRESH


# ---------------------------------------------------------------------
# PX5 — the client websocket proxied race
# ---------------------------------------------------------------------

def test_px5_ws_race_and_legacy_fallback(monkeypatch):
    monkeypatch.setattr(pc, "candidate_proxies",
                        lambda proc_root=None: [BAD, GOOD])

    class _WS:
        def __init__(self, tag):
            self.tag = tag

        async def close(self):
            pass

    async def _factory(url, max_size=None, proxy=None):
        if proxy == BAD:
            raise ConnectionError("407")
        return _WS(proxy or "env")

    async def _t():
        ws = await client_module._dial_via_proxy_candidates(
            "wss://relay.invalid/ws", _connect=_factory)
        assert ws.tag == GOOD
        assert pc.winner() == GOOD

        async def _legacy(url, max_size=None, proxy=None):
            if proxy is not None:
                raise TypeError("no proxy kwarg here")
            return _WS("env")

        ws = await client_module._dial_via_proxy_candidates(
            "wss://relay.invalid/ws", _connect=_legacy)
        assert ws.tag == "env"

    asyncio.run(_t())


# ---------------------------------------------------------------------
# PX6 — open_url behaviour
# ---------------------------------------------------------------------

class _FakeResp:
    def __init__(self, body=b"ok"):
        self._body = body

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_px6_open_url_races_and_crowns_http(monkeypatch):
    monkeypatch.setattr(pc, "candidate_proxies",
                        lambda proc_root=None: [BAD, GOOD])
    seen = []

    class _Opener:
        def __init__(self, proxy):
            self.proxy = proxy

        def open(self, req, timeout=0):
            seen.append(self.proxy)
            if self.proxy == BAD:
                raise urllib.error.URLError("407 stall")
            return _FakeResp(b"payload")

    def _build(*handlers):
        proxy = handlers[0].proxies["https"]
        return _Opener(proxy)

    monkeypatch.setattr(urllib.request, "build_opener", _build)
    req = urllib.request.Request("https://example.invalid/x")
    with pc.open_url(req, timeout=5) as resp:
        assert resp.read() == b"payload"
    assert pc.winner() == GOOD

    # An HTTPError is a real answer: crowned + propagated, the
    # race does not move on.
    pc.reset_winner()
    seen.clear()

    class _HttpOpener:
        def __init__(self, proxy):
            self.proxy = proxy

        def open(self, req, timeout=0):
            seen.append(self.proxy)
            raise urllib.error.HTTPError(
                req.full_url, 404, "nope", {}, None)

    monkeypatch.setattr(
        urllib.request, "build_opener",
        lambda *h: _HttpOpener(h[0].proxies["https"]))
    with pytest.raises(urllib.error.HTTPError):
        pc.open_url(req, timeout=5)
    assert seen == [BAD]  # first candidate answered; race over
    assert pc.winner() == BAD
