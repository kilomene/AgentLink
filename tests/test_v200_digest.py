"""Digest fan-out valve pins (v2.0 integration — Phase 1 quota proof
made implementation mandatory at circle-10 scale).

The valve: every client ALSO maintains /digest/<user>, refreshed
on the beat cadence; peers may subscribe to digests (a fraction
of the download) while activeness-critical counterparties stay
on raw presence. 2.3.0: the beat stretched to 180s and the
digest now refreshes EVERY beat (DIGEST_EVERY_N_BEATS == 1,
DIGEST_INTERVAL_S == 180) — at a 3-minute beat a 6-beat
coalescing would leave digests 18 minutes stale. These pins
hold the writer cadence, the reader scoping, and the rules
coverage.
"""
import json
import time
from pathlib import Path

from agentlink.doorbell import (
    BEAT_INTERVAL_S, DIGEST_EVERY_N_BEATS, DIGEST_INTERVAL_S,
    DoorbellClient, ScopedPresenceWatcher)

ROOT = Path(__file__).resolve().parent.parent


def _recorder_client():
    c = DoorbellClient("https://fake.firebaseio.com")
    calls = []
    c._rest = lambda m, p, body=None: calls.append((m, p, body))
    return c, calls


def test_digest_cadence_constants():
    assert DIGEST_INTERVAL_S == 180
    assert DIGEST_EVERY_N_BEATS == 1
    assert DIGEST_EVERY_N_BEATS * BEAT_INTERVAL_S == DIGEST_INTERVAL_S


def test_beat_digest_writes_own_digest_node():
    c, calls = _recorder_client()
    c.beat_digest("alice")
    assert len(calls) == 1
    method, path, body = calls[0]
    assert method == "PATCH" and path == "digest/alice"
    assert body["state"] == "online" and "ts" in body
    # digest never touches the raw presence node
    assert all("presence/" not in p for _m, p, _b in calls)


def test_heartbeat_loop_refreshes_digest_every_beat():
    c, calls = _recorder_client()
    c.start_heartbeat("alice", interval_s=0.01)
    try:
        deadline = time.monotonic() + 3.0
        while time.monotonic() < deadline:
            beats = [1 for m, p, _b in calls
                     if m == "PATCH" and p == "presence/alice"]
            if len(beats) >= 13:
                break
            time.sleep(0.02)
    finally:
        c.stop_heartbeat(fire_offline=False)
    beats = [1 for m, p, _b in calls
             if m == "PATCH" and p == "presence/alice"]
    digests = [1 for m, p, _b in calls
               if m == "PATCH" and p == "digest/alice"]
    assert len(beats) >= 12
    # 2.3.0: one digest per beat, modulo the beat in flight when
    # the loop was stopped.
    assert len(beats) - 1 <= len(digests) <= len(beats)


class _FakeListenClient:
    def __init__(self):
        self.opened = []

    def listen_presence(self, username, cb, stop_event=None):
        self.opened.append(f"presence/{username}")
        stop_event.wait(5)

    def listen_digest(self, username, cb, stop_event=None):
        self.opened.append(f"digest/{username}")
        stop_event.wait(5)


def test_watcher_digest_mode_scopes_and_critical_stays_raw():
    fake = _FakeListenClient()
    events = []
    watcher = ScopedPresenceWatcher(
        fake, lambda: {"alice", "bob"},
        lambda u, r, s: events.append((u, s)),
        fanout="digest", critical={"bob"})
    try:
        live = watcher.refresh()
        assert live == {"alice", "bob"}
        assert watcher.subscribed_paths() == \
            {"digest/alice", "presence/bob"}
        time.sleep(0.1)
        assert set(fake.opened) == {"digest/alice", "presence/bob"}
    finally:
        watcher.close()


def test_watcher_default_mode_stays_raw_presence():
    fake = _FakeListenClient()
    watcher = ScopedPresenceWatcher(
        fake, lambda: {"alice"}, lambda u, r, s: None,
        fanout="digest")
    try:
        watcher.refresh()
        assert watcher.subscribed_paths() == {"digest/alice"}
    finally:
        watcher.close()
    watcher2 = ScopedPresenceWatcher(
        fake, lambda: {"alice"}, lambda u, r, s: None)
    try:
        watcher2.refresh()
        assert watcher2.subscribed_paths() == {"presence/alice"}
    finally:
        watcher2.close()


def test_rules_cover_digest_own_write_auth_read():
    rules = json.loads((ROOT / "firebase" / "database.rules.json")
                       .read_text())
    node = rules["rules"]["digest"]["$user"]
    assert node[".write"] == "auth != null && auth.uid === $user"
    assert node[".read"] == "auth != null"
