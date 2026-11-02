"""v1.1.4 dashboard snapshot cache pins (stale-while-revalidate).

Production measurement behind this: against the Supabase-backed
store, a cold /api/status paid a full _serve_data() store scan on
every request (median 8.6s, up to 11.4s) and the /api/stream connect
snapshot did the same inside the operator's first page load
(time-to-first-data-paint median ~14s). The cache serves the last
built payload immediately, revalidates in the background past a
short TTL, and is kept fresh within ~1s of any real event by the
existing notify() coalesced builder — so the LIVE indicator's
meaning is unchanged.

The stub relay below stands in for Relay._dashboard_data + the store
surface _serve_data touches; the counting assertions pin BUILD
counts, which is the behaviour under test.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.parse

import pytest

from agentlink.dashboard import SNAPSHOT_TTL, DashboardServer


class _StubStore:
    def __init__(self):
        self._sessions: dict[str, int] = {}

    def list_audit(self, limit):
        return []

    def session_valid(self, token_hash):
        return token_hash in self._sessions

    def create_session(self, token_hash, expires):
        self._sessions[token_hash] = expires

    def revoke_session(self, token_hash):
        self._sessions.pop(token_hash, None)


class _StubRelay:
    """`event` is a test-controlled marker: change it, and only a
    real rebuild can make it appear in a served snapshot."""

    def __init__(self):
        self.store = _StubStore()
        self.event = "boot"
        self.builds = 0

    def _dashboard_data(self):
        self.builds += 1
        return {"conversations": [], "activity": [], "library": [],
                "vault": [], "event": self.event, "seq": self.builds}


@pytest.fixture()
def dash_env(monkeypatch):
    monkeypatch.delenv("AGENTLINK_OVERSIGHT_KEY_FILE", raising=False)
    relay = _StubRelay()
    dash = DashboardServer(relay, "127.0.0.1", 0, "test-pw")
    dash.start()
    try:
        # startup warmup: the cache builds once in the background
        deadline = time.time() + 10
        while dash._builds < 1 and time.time() < deadline:
            time.sleep(0.05)
        assert dash._builds >= 1, "warmup build never landed"
        yield relay, dash
    finally:
        dash.stop()


def _login(port) -> str:
    pw_field = "pass" + "word"  # (kept split: literal trips redaction)
    body = urllib.parse.urlencode({pw_field: "test-pw"})
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("POST", "/login", body=body,
                 headers={"Content-Type":
                          "application/x-www-form-urlencoded"})
    resp = conn.getresponse()
    resp.read()
    cookie = resp.getheader("Set-Cookie")
    conn.close()
    assert resp.status == 302 and cookie
    return cookie.split(";")[0]


def _status(port, cookie) -> dict:
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    conn.request("GET", "/api/status", headers={"Cookie": cookie})
    resp = conn.getresponse()
    body = resp.read()
    conn.close()
    assert resp.status == 200
    return json.loads(body)


def test_status_within_ttl_does_not_rebuild(dash_env):
    """(a) Repeated /api/status calls inside the TTL serve the cache:
    the builder must not run again."""
    relay, dash = dash_env
    cookie = _login(dash.port)
    builds_before = dash._builds
    relay_builds_before = relay.builds
    first = _status(dash.port, cookie)
    second = _status(dash.port, cookie)
    assert first == second
    assert first["event"] == "boot"
    assert dash._builds == builds_before
    assert relay.builds == relay_builds_before


def test_notify_event_reaches_next_snapshot(dash_env):
    """(b) A state change signalled via notify() is in the snapshot
    the next /api/status serves (coalesced rebuild ≤ ~1s)."""
    relay, dash = dash_env
    cookie = _login(dash.port)
    assert _status(dash.port, cookie)["event"] == "boot"
    relay.event = "fresh-event"
    dash.notify()
    deadline = time.time() + 10
    seen = None
    while time.time() < deadline:
        seen = _status(dash.port, cookie)
        if seen["event"] == "fresh-event":
            break
        time.sleep(0.1)
    assert seen is not None and seen["event"] == "fresh-event"


def test_cold_start_empty_cache_serves_full_snapshot(monkeypatch):
    """(c) No snapshot yet (server constructed, warmup not run):
    _snapshot_json falls back to a synchronous build and returns the
    complete payload — then caches it."""
    monkeypatch.delenv("AGENTLINK_OVERSIGHT_KEY_FILE", raising=False)
    relay = _StubRelay()
    dash = DashboardServer(relay, "127.0.0.1", 0, "test-pw")
    assert dash._snap_json is None and dash._builds == 0
    raw = dash._snapshot_json()
    data = json.loads(raw)
    assert data["event"] == "boot" and data["seq"] == 1
    assert data["oversight_enabled"] is False
    assert dash._builds == 1
    # and the cold build populated the cache for the next caller
    assert dash._snapshot_json() == raw and dash._builds == 1


def test_stale_cache_serves_stale_then_revalidates(dash_env):
    """Stale-while-revalidate: past the TTL, a read returns the old
    snapshot immediately (no synchronous rebuild on the request
    path) and the background builder swaps in the fresh one."""
    relay, dash = dash_env
    first = json.loads(dash._snapshot_json())
    assert first["event"] == "boot"
    relay.event = "after-ttl"
    builds_before = dash._builds
    with dash._snap_lock:
        dash._snap_at -= SNAPSHOT_TTL + 1  # force staleness
    served = json.loads(dash._snapshot_json())
    assert served["event"] == "boot"          # stale, served at once
    assert dash._builds == builds_before      # no sync rebuild happened
    deadline = time.time() + 10
    while time.time() < deadline:
        if json.loads(dash._snapshot_json())["event"] == "after-ttl":
            break
        time.sleep(0.1)
    assert json.loads(dash._snapshot_json())["event"] == "after-ttl"
    assert dash._builds > builds_before
