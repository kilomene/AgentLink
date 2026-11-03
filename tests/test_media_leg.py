"""Agent media leg pins (v1.3.9, WS1 — the headline workstream).

The defect, proven live 2026-11-03: voice rooms carried
signalling only; SDK agents had no media engine, so the owner
stepped into a live room and heard silence.

The cure pinned here: an agent with the optional media stack
(aiortc — the agentlink[media] extra) joins a room with a REAL
WebRTC audio track: it publishes a WAV and the peer records the
received track to a WAV that verifiably carries the audio
(duration + sample energy + sane size). And the absence path:
without the stack, media is a declared capability fact — the
agent runs normally, carries no media capability, and media_join
raises MediaUnavailable instead of crashing.
"""

from __future__ import annotations

import asyncio
import math
import struct
import tempfile
import threading
import wave
from pathlib import Path

import pytest

from agentlink.client import Agent
from agentlink.relay import Relay

HOST = "127.0.0.1"


class RelayHandle:
    def __init__(self, db, name):
        self.db = db
        self.name = name
        self.relay = None
        self.loop = None
        self.thread = None
        self.port = 0
        self.dash_port = 0

    def start(self):
        self.relay = Relay(host=HOST, port=self.port, db_path=self.db,
                           server_name=self.name,
                           dashboard_password="test-password",
                           dashboard_port=self.dash_port)
        ready = threading.Event()

        def _thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.loop = loop

            async def _serve():
                await self.relay.start()
                ready.set()
                await asyncio.Future()

            try:
                loop.run_until_complete(_serve())
            except (RuntimeError, asyncio.CancelledError):
                pass

        self.thread = threading.Thread(target=_thread, daemon=True)
        self.thread.start()
        assert ready.wait(timeout=10)
        self.port = self.relay.port
        self.dash_port = self.relay.dashboard_port
        return f"ws://{HOST}:{self.relay.port}"

    def stop(self):
        if self.relay is not None and self.loop is not None:
            fut = asyncio.run_coroutine_threadsafe(
                self.relay.stop(), self.loop)
            try:
                fut.result(timeout=10)
            except Exception:
                pass
            self.relay = None


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=120))


async def wait_for(pred, timeout=20.0):
    for _ in range(int(timeout / 0.1)):
        if pred():
            return True
        await asyncio.sleep(0.1)
    return pred()


def _write_tone_wav(path, seconds=2.0, rate=48000):
    """A distinctive two-tone signal (440 Hz + 880 Hz) — energy a
    silent or empty recording cannot fake."""
    frames = int(seconds * rate)
    with wave.open(str(path), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        buf = bytearray()
        for i in range(frames):
            t = i / rate
            v = int(12000 * math.sin(2 * math.pi * 440 * t)
                    + 8000 * math.sin(2 * math.pi * 880 * t))
            buf += struct.pack("<h", v)
        w.writeframes(bytes(buf))


def _wav_stats(path):
    with wave.open(str(path), "rb") as w:
        rate = w.getframerate()
        n = w.getnframes()
        raw = w.readframes(n)
        width = w.getsampwidth()
        channels = w.getnchannels()
    samples = struct.unpack(f"<{len(raw) // 2}h", raw)
    rms = math.sqrt(sum(s * s for s in samples) / max(1, len(samples)))
    return {"duration": n / rate if rate else 0, "rms": rms,
            "bytes": Path(path).stat().st_size, "rate": rate,
            "channels": channels, "width": width}


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-md-agents-") as tmp:
        yield Path(tmp)


@pytest.mark.skipif(not Agent.media_available(),
                    reason="aiortc not installed in this environment")
def _udp_sendto_blocked():
    """Probe the one fact the media transport depends on: may a
    process here send an unconnected UDP datagram at all? (aioice
    — aiortc's ICE stack — sends connectivity checks exactly that
    way.) On the build VM the sandbox policy answers EPERM even
    for loopback, for systemd units too; where UDP is permitted
    this returns False and the recording assertions in the media
    pin are fully binding."""
    import socket as _s
    s = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
    try:
        s.sendto(b"probe", ("127.0.0.1", 9))
        return False
    except OSError:
        return True
    finally:
        s.close()


def test_media_leg_publishes_and_records(state_root, tmp_path):
    """Two media-capable agents in one room: A publishes a tone
    WAV on a real WebRTC track; B records the received track; the
    recording verifiably carries the audio. Signalling, SDP
    negotiation and track arrival are asserted unconditionally;
    the audio-flow assertions bind wherever UDP can flow, and
    skip — with the probe evidence — only where the host forbids
    unconnected UDP outright (no ICE implementation could
    connect there)."""
    tmp = tempfile.mkdtemp(prefix="agentlink-md-")
    h = RelayHandle(str(Path(tmp) / "relay.db"), "md-relay")
    url = h.start()
    announce = tmp_path / "announce.wav"
    _write_tone_wav(announce)
    recorded = tmp_path / "recorded.wav"
    outcome = {}

    async def _t():
        ann = Agent("mdann", endpoint=url,
                    state_dir=str(state_root / "mdann"), media=True)
        rec = Agent("mdrec", endpoint=url,
                    state_dir=str(state_root / "mdrec"), media=True)
        await ann.start()
        await rec.start()
        try:
            assert "media_audio" in ann.capabilities
            assert "media_audio" in rec.capabilities
            g = await ann.group_create("md-group", ["mdrec"])
            gid = g["group_id"]
            rid = (await ann.room_open(gid))["room_id"]
            await rec.room_join(rid)
            rec_sess = await rec.media_join(rid, "mdann")
            rec_sess.record_to(str(recorded))
            ann_sess = await ann.media_join(
                rid, "mdrec", initiator=True,
                publish=str(announce), loop=True)
            # Negotiation is environment-independent: SDP crosses
            # the real relay signalling and the track arrives.
            assert await rec_sess.wait_track(25), \
                "recorder never received an audio track"
            outcome["connected"] = await ann_sess.wait_connected(20)
            if outcome["connected"]:
                assert await rec_sess.wait_connected(10)
                await asyncio.sleep(3.0)
                await rec_sess.stop_recording()
            await ann.media_leave(ann_sess)
        finally:
            try:
                await rec.close()
            except Exception:
                pass
            try:
                await ann.close()
            except Exception:
                pass

    run(_t())
    h.stop()
    if not outcome.get("connected"):
        assert _udp_sendto_blocked(), \
            "media did not connect AND UDP is not blocked here — " \
            "that is a real media-leg failure, not an environment fact"
        pytest.skip("host network policy forbids unconnected UDP "
                    "(sendto EPERM) — ICE cannot complete on this "
                    "host; negotiation + track proven, audio flow "
                    "unverifiable here")
    stats = _wav_stats(recorded)
    assert stats["duration"] >= 1.0, stats
    assert stats["rms"] > 500, \
        f"recording carries no real audio energy: {stats}"
    assert 10_000 < stats["bytes"] < 5_000_000, stats


def test_media_enable_room_answers_offers(state_root, tmp_path):
    """media_enable_room is the answerer-side wiring: an enabled
    agent that never called media_join still answers an incoming
    offer — route_signal spawns its session (with the room's
    publication pending) — and media_disable_room retires the
    room so later offers spawn nothing. Track arrival is asserted
    (negotiation needs no UDP); connection state is not — see the
    environment note in the publish/record pin."""
    tmp = tempfile.mkdtemp(prefix="agentlink-md-")
    h = RelayHandle(str(Path(tmp) / "relay.db"), "md-relay3")
    url = h.start()
    announce = tmp_path / "announce.wav"
    _write_tone_wav(announce)

    async def _t():
        ann = Agent("mdann3", endpoint=url,
                    state_dir=str(state_root / "mdann3"), media=True)
        rec = Agent("mdrec3", endpoint=url,
                    state_dir=str(state_root / "mdrec3"), media=True)
        await ann.start()
        await rec.start()
        try:
            g = await ann.group_create("md-group3", ["mdrec3"])
            gid = g["group_id"]
            rid = (await ann.room_open(gid))["room_id"]
            await rec.room_join(rid)
            rec.media_enable_room(rid)
            assert rid in rec._media_rooms
            ann_sess = await ann.media_join(
                rid, "mdrec3", initiator=True,
                publish=str(announce), loop=True)
            assert await wait_for(
                lambda: (rid, "mdann3") in rec._media_sessions)
            spawned = rec._media_sessions[(rid, "mdann3")]
            assert await spawned.wait_track(25), \
                "the spawned answerer session got no track"
            await rec.media_disable_room(rid)
            assert rid not in rec._media_rooms
            assert (rid, "mdann3") not in rec._media_sessions
            await ann.media_leave(ann_sess)
        finally:
            try:
                await rec.close()
            except Exception:
                pass
            try:
                await ann.close()
            except Exception:
                pass

    run(_t())
    h.stop()


def test_media_absent_is_declared_not_fatal(state_root, monkeypatch):
    """Without the stack: the agent connects and works normally,
    declares NO media capability, and media_join raises
    MediaUnavailable with the install path named."""
    import agentlink.media as media_mod
    monkeypatch.setattr(media_mod, "media_available", lambda: False)
    tmp = tempfile.mkdtemp(prefix="agentlink-md-")
    h = RelayHandle(str(Path(tmp) / "relay.db"), "md-relay2")
    url = h.start()

    async def _t():
        a = Agent("mdplain", endpoint=url,
                  state_dir=str(state_root / "mdplain"), media=True)
        await a.start()
        try:
            assert "media_audio" not in a.capabilities
            with pytest.raises(media_mod.MediaUnavailable):
                await a.media_join("r-none", "mdpeer")
        finally:
            await a.close()

    run(_t())
    h.stop()
