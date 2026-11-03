"""Agent-side voice-room media (v1.3.9, OPTIONAL extra: ``media``).

Voice rooms carry WebRTC signalling over the line; the MEDIA itself
has always been peer-to-peer by the owner's design law — the relay
routes offer/answer/ICE and never sees a byte of audio. Until
v1.3.9 an SDK agent had no media engine of its own, so a room full
of agents was a room full of signalling and silence: the owner
joined his own dashboard's room and heard nothing. This module is
the agent-side media leg.

An agent whose operator enables it (``Agent(..., media=True)``)
gains a real WebRTC audio stack (aiortc):

- ``await agent.media_join(room_id, peer)`` — a media session with
  one room participant: a full RTCPeerConnection negotiated over
  the EXISTING room_signal channel (offer/answer kinds carry
  ``{"type", "sdp"}`` payloads, ice kinds carry RTCIceCandidateInit
  payloads — the exact shapes the dashboard browser client speaks,
  so an SDK agent and a browser meet in a room as equals).
- ``session.publish_wav(path, loop=False)`` — send audio: any WAV
  (a TTS announcement, an alert tone, a composed message) becomes
  the session's outgoing track.
- ``session.record_to(path)`` — receive audio: the participant's
  track is recorded to a WAV file the agent can inspect, archive
  or transcribe with its own tools.
- ``agent.media_enable_room(room_id, publish=..., loop=...)`` —
  auto-answer: any participant who offers media in that room gets
  an answerer session, optionally publishing the same audio (how
  an agent greets a human who joins from the dashboard).

aiortc is an OPTIONAL dependency (``pip install agentlink[media]``).
The SDK imports and runs fully without it: media is opt-in per
agent, requesting media without the extra installed is a loud
startup warning and a capability fact (``media_audio`` is simply
not declared), never a crash.

NAT REALITY, stated plainly: media is peer-to-peer. Two agents on
one host or one LAN connect on host candidates directly. A remote
agent behind NAT needs its side of the path to exist — a public
address, a port mapping, or a TURN server on ITS side. This
release ships no TURN and relays no media (the owner's law); a
pair that cannot find a direct path fails ICE honestly
(``wait_connected`` times out / the session reports ``failed``)
instead of pretending to be heard.
"""

from __future__ import annotations

import asyncio
import inspect
import logging

log = logging.getLogger("agentlink.media")

#: ICE servers offered to the peer connection — the same public
#: STUN the dashboard browser client uses. STUN only helps a side
#: discover its own server-reflexive address; it is not a relay.
ICE_SERVERS = ("stun:stun.l.google.com:19302",)


def media_available() -> bool:
    """True when the optional media stack (aiortc) is importable."""
    try:
        import aiortc  # noqa: F401
        return True
    except Exception:
        return False


class MediaUnavailable(Exception):
    """Media was requested but the optional aiortc stack is not
    installed. Raised by media entry points — never at import or
    Agent construction time."""


def _rtc():
    """Import the aiortc pieces lazily (the SDK must import and run
    without the media extra)."""
    try:
        from aiortc import (RTCConfiguration, RTCIceServer,
                            RTCPeerConnection, RTCSessionDescription)
        from aiortc.contrib.media import MediaPlayer, MediaRecorder
        from aiortc.sdp import candidate_from_sdp, candidate_to_sdp
    except Exception as exc:
        raise MediaUnavailable(
            "voice-room media needs the optional media stack: "
            "pip install 'agentlink[media]' (aiortc). The agent "
            "itself runs fine without it — it just cannot send or "
            "receive room audio.") from exc
    return (RTCConfiguration, RTCIceServer, RTCPeerConnection,
            RTCSessionDescription, MediaPlayer, MediaRecorder,
            candidate_from_sdp, candidate_to_sdp)


class RoomMediaSession:
    """One WebRTC audio session between this agent and ONE other
    participant of one room. Created via Agent.media_join (explicit
    pair) or by the room auto-answer; not constructed directly."""

    def __init__(self, agent, room_id: str, peer: str):
        self.agent = agent
        self.room_id = room_id
        self.peer = peer
        self.pc = None
        self._sender = None
        self._player = None
        self._pending_publish: tuple[str, bool] | None = None
        self._remote_track = None
        self._track_event = asyncio.Event()
        self._connected_event = asyncio.Event()
        self.state = "new"  # new|connecting|connected|failed|closed
        self._recorder = None
        self._record_path: str | None = None
        self._closed = False

    # -- lifecycle ----------------------------------------------------

    async def connect(self, initiator: bool = False) -> None:
        """Build the peer connection. The initiator creates the
        audio transceiver and sends the offer; the answerer's
        negotiation is driven by the incoming offer signal."""
        (RTCConfiguration, RTCIceServer, RTCPeerConnection,
         _SD, _MP, _MR, _cf, _ct) = _rtc()
        config = RTCConfiguration(iceServers=[
            RTCIceServer(urls=u) for u in ICE_SERVERS])
        pc = RTCPeerConnection(configuration=config)
        self.pc = pc
        self.state = "connecting"

        @pc.on("icecandidate")
        async def _on_ice(candidate):
            if candidate is None:
                return
            try:
                await self.agent.room_signal(
                    self.room_id, self.peer, "ice",
                    {"candidate": _ct(candidate),
                     "sdpMid": candidate.sdpMid,
                     "sdpMLineIndex": candidate.sdpMLineIndex})
            except Exception:
                pass  # a lost candidate is one path fewer, not a crash

        @pc.on("track")
        def _on_track(track):
            if track.kind != "audio":
                return
            self._remote_track = track
            self._track_event.set()
            if self._record_path:
                self._start_recorder(track)

        @pc.on("iceconnectionstatechange")
        async def _on_ice_state():
            state = pc.iceConnectionState
            if state in ("connected", "completed"):
                self.state = "connected"
                self._connected_event.set()
            elif state in ("failed", "closed"):
                self.state = "failed" if state == "failed" else "closed"
                self._connected_event.set()

        if initiator:
            transceiver = pc.addTransceiver("audio",
                                            direction="sendrecv")
            self._sender = transceiver.sender
            if self._pending_publish:
                path, loop = self._pending_publish
                self._pending_publish = None
                await self.publish_wav(path, loop=loop)
            offer = await pc.createOffer()
            await pc.setLocalDescription(offer)
            await self.agent.room_signal(
                self.room_id, self.peer, "offer",
                {"type": pc.localDescription.type,
                 "sdp": pc.localDescription.sdp})

    async def wait_connected(self, timeout: float = 30.0) -> bool:
        """True when ICE reached connected/completed; False on
        timeout or failure — the honest NAT answer."""
        try:
            await asyncio.wait_for(self._connected_event.wait(),
                                   timeout=timeout)
        except asyncio.TimeoutError:
            return False
        return self.state == "connected"

    async def wait_track(self, timeout: float = 30.0) -> bool:
        """True when the participant's audio track has arrived."""
        try:
            await asyncio.wait_for(self._track_event.wait(),
                                   timeout=timeout)
        except asyncio.TimeoutError:
            return False
        return self._remote_track is not None

    # -- publishing -----------------------------------------------------

    async def publish_wav(self, path: str, loop: bool = False) -> None:
        """Make a WAV file this session's outgoing audio (a TTS
        announcement, a tone, any composed sound). With loop=True
        the file repeats for as long as the session lives — how an
        agent holds an audible presence in a room."""
        (_RC, _RI, _RPC, _SD, MediaPlayer, _MR, _cf, _ct) = _rtc()
        if self.pc is None or self._sender is None:
            # No negotiated audio sender yet (publication requested
            # before connect(), or by an answerer before the offer
            # landed): applied the moment a sender exists — by
            # connect() for an initiator, by the offer handler for
            # an answerer — via replaceTrack on the negotiated
            # sender, so the publication never forces a second
            # m-line or a renegotiation.
            self._pending_publish = (str(path), bool(loop))
            return
        player = MediaPlayer(str(path), loop=bool(loop))
        if player.audio is None:
            raise MediaUnavailable(
                f"{path}: no audio stream could be decoded")
        self._player = player
        # aiortc's replaceTrack is a plain method in current
        # releases and a coroutine in older ones — accept both.
        _res = self._sender.replaceTrack(player.audio)
        if inspect.isawaitable(_res):
            await _res

    # -- recording ----------------------------------------------------

    def record_to(self, path: str) -> None:
        """Record the participant's incoming audio to a WAV file.
        Starts immediately when the track is already here, else
        the moment it arrives."""
        self._record_path = str(path)
        if self._remote_track is not None:
            self._start_recorder(self._remote_track)

    def _start_recorder(self, track) -> None:
        if self._recorder is not None or self._record_path is None:
            return
        (_RC, _RI, _RPC, _SD, _MP, MediaRecorder, _cf, _ct) = _rtc()
        recorder = MediaRecorder(self._record_path, format="wav")
        recorder.addTrack(track)
        self._recorder = recorder
        asyncio.ensure_future(recorder.start())

    async def stop_recording(self) -> None:
        if self._recorder is not None:
            try:
                await self._recorder.stop()
            except Exception:
                pass
            self._recorder = None

    # -- signalling -----------------------------------------------------

    async def _handle_signal(self, frame: dict) -> None:
        """Feed one room_signal frame (addressed to us, from our
        peer) into the peer connection. Unknown/duplicate signals
        are WebRTC weather — ignored, never fatal."""
        if self._closed:
            return
        kind = frame.get("kind")
        payload = frame.get("payload") or {}
        try:
            if kind == "offer":
                if self.pc is None:
                    await self.connect(initiator=False)
                (_RC, _RI, _RPC, RTCSessionDescription,
                 _MP, _MR, _cf, _ct) = _rtc()
                sdp = payload.get("sdp")
                if not sdp:
                    return
                await self.pc.setRemoteDescription(
                    RTCSessionDescription(
                        sdp=sdp, type=payload.get("type") or "offer"))
                # Our audio transceiver exists now (created by the
                # offer): remember its sender, and apply a pending
                # publication by REPLACING the (silent) track so no
                # renegotiation is needed after the answer.
                for t in self.pc.getTransceivers():
                    if t.kind == "audio":
                        self._sender = t.sender
                        break
                if self._pending_publish:
                    path, loop = self._pending_publish
                    self._pending_publish = None
                    await self.publish_wav(path, loop=loop)
                answer = await self.pc.createAnswer()
                await self.pc.setLocalDescription(answer)
                await self.agent.room_signal(
                    self.room_id, self.peer, "answer",
                    {"type": self.pc.localDescription.type,
                     "sdp": self.pc.localDescription.sdp})
            elif kind == "answer":
                if self.pc is None:
                    return
                (_RC, _RI, _RPC, RTCSessionDescription,
                 _MP, _MR, _cf, _ct) = _rtc()
                sdp = payload.get("sdp")
                if not sdp:
                    return
                await self.pc.setRemoteDescription(
                    RTCSessionDescription(
                        sdp=sdp, type=payload.get("type") or "answer"))
            elif kind == "ice":
                if self.pc is None:
                    return
                cand_sdp = payload.get("candidate")
                if not cand_sdp:
                    return  # end-of-candidates marker
                (_RC, _RI, _RPC, _SD, _MP, _MR,
                 candidate_from_sdp, _ct) = _rtc()
                candidate = candidate_from_sdp(cand_sdp)
                candidate.sdpMid = payload.get("sdpMid")
                candidate.sdpMLineIndex = payload.get("sdpMLineIndex")
                await self.pc.addIceCandidate(candidate)
            elif kind == "bye":
                await self.close()
        except Exception:
            log.exception("media signal handling failed (room %s, "
                          "peer %s, kind %s)", self.room_id,
                          self.peer, kind)

    async def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.state = "closed"
        await self.stop_recording()
        if self.pc is not None:
            try:
                await self.pc.close()
            except Exception:
                pass
            self.pc = None
        sessions = getattr(self.agent, "_media_sessions", None)
        if sessions is not None:
            sessions.pop((self.room_id, self.peer), None)


def route_signal(agent, frame: dict) -> None:
    """Client frame-dispatch hook: hand a room_signal frame to the
    media session it belongs to. An offer from a peer we hold no
    session for, in a room the agent enabled media on
    (media_enable_room), spawns the answerer session — that is how
    a dashboard browser's call gets answered."""
    room_id = frame.get("room_id") or ""
    sender = frame.get("from") or ""
    sessions = getattr(agent, "_media_sessions", None)
    if sessions is None:
        return
    session = sessions.get((room_id, sender))
    if session is not None:
        asyncio.ensure_future(session._handle_signal(frame))
        return
    if frame.get("kind") != "offer":
        return
    rooms = getattr(agent, "_media_rooms", None) or {}
    if room_id not in rooms:
        return
    publication = rooms[room_id]
    session = RoomMediaSession(agent, room_id, sender)
    sessions[(room_id, sender)] = session
    if publication is not None:
        path, loop = publication
        session._pending_publish = (path, loop)
    asyncio.ensure_future(session._handle_signal(frame))
