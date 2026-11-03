"""In-conversation file viewing + download (v1.3.8, owner's ruling
2026-11-03): a file inside a conversation is clickable, viewable
and downloadable right there in the thread — no separate Media
section. This suite replaces that cancelled section's reason to
exist.

Contract pinned here (dashboard payload + routes, real clients ->
relay -> store -> dashboard HTTP throughout):
- An opened file item gains item["file"] — metadata only, never
  bytes: {name, kind, mime, size (PLAINTEXT bytes), sha256, form,
  verified} plus "url" ONLY when verified (fail-closed).
- Inline form (protocol file payload with data_b64): verified is
  protocol.verify_file (size + sha256); the url is
  /api/file/<item id>, served statelessly from the audit row,
  byte-exact, with X-Content-SHA256. A tampered payload earns NO
  url and the route answers 404 — unverified bytes never serve.
- Blob form (descriptor with blob_id): verified needs the
  descriptor's oversight wrap (blob_url registered) AND the blob
  object present in the store; deleting the object flips the
  rebuilt payload to verified False with no url.
- Non-file items carry NO "file" key (payloads unchanged).
- A DM file is NOT a Library entry (library stays
  work-deliverables-only) and is never deduped: the same file sent
  twice is two conversation items.

Tamper construction: the doctored payload travels the REAL send
path — Agent.send_message accepts the file dict, so a payload whose
data_b64 was corrupted after its sha256/size were computed is
sealed, oversight-wrapped and audit-logged by production code
exactly like an honest file; only the dashboard's verify gate can
tell the difference, which is the gate under test.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from agentlink.blobstore import LocalBlobStore
from agentlink.client import Agent
from agentlink.crypto import OversightKey
from agentlink.relay import Relay

HOST = "127.0.0.1"
PASSWORD = "test-dash-pass"

# A real 1x1 transparent PNG.
PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
    "Xw8AAwMCAO+ip1sAAAAASUVORK5CYII=")
ZIP_BYTES = b"PK\x03\x04" + b"agentlink-zip-payload\x00\xff" * 8
VIDEO_BYTES = b"\x00\x00\x00\x18ftypmp42" + b"video-frame-bytes" * 16


def _start_relay(relay):
    ready = threading.Event()
    box: dict = {}

    def _thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        box["loop"] = loop

        async def _serve():
            await relay.start()
            ready.set()
            await asyncio.Future()

        try:
            loop.run_until_complete(_serve())
        except (RuntimeError, asyncio.CancelledError):
            pass

    t = threading.Thread(target=_thread, daemon=True)
    t.start()
    assert ready.wait(timeout=10)
    return box


@pytest.fixture()
def env_factory(monkeypatch):
    """Relay advertising an oversight pubkey (clients wrap for
    real) + its dashboard holding the matching private key file —
    the test_owner_downloads harness shape."""
    started = []

    def make(blob_store=None):
        tmp = tempfile.mkdtemp(prefix="agentlink-cf-")
        okey = OversightKey.generate()
        key_path = okey.save(str(Path(tmp) / "oversight-key.json"))
        monkeypatch.setenv("AGENTLINK_OVERSIGHT_KEY_FILE",
                           str(key_path))
        db = str(Path(tmp) / "relay.db")
        kw = {}
        if blob_store is not None:
            kw["blob_store"] = blob_store
        relay = Relay(host=HOST, port=0, db_path=db,
                      dashboard_password=PASSWORD, dashboard_port=0,
                      oversight_pubkey=okey.public_key_b64, **kw)
        box = _start_relay(relay)
        env = {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
               "db": db, "dash_port": relay.dashboard_port,
               "relay": relay, "okey": okey, "tmp": Path(tmp),
               "loop": box["loop"]}
        started.append(env)
        return env

    yield make
    for env in started:
        fut = asyncio.run_coroutine_threadsafe(
            env["relay"].stop(), env["loop"])
        try:
            fut.result(timeout=10)
        except Exception:
            pass


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-cf-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


async def make(env, state_root, username, **kw):
    a = Agent(username, endpoint=env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=8.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


def _opener(env, login=True):
    base = f"http://{HOST}:{env['dash_port']}"
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor())
    if login:
        req = urllib.request.Request(
            base + "/login", data=f"password={PASSWORD}".encode(),
            headers={"Content-Type": "application/x-www-form-urlencoded"})
        try:
            opener.open(req, timeout=5)
        except urllib.error.HTTPError:
            pass
    return base, opener


def dash_data(env):
    base, opener = _opener(env)
    return json.loads(opener.open(base + "/api/status", timeout=10).read())


def dash_data_wait(env, pred, timeout=12.0):
    """Poll the real /api/status payload until pred holds (the
    snapshot cache waits for post-notify builds, so this converges
    as soon as the relay has logged the send)."""
    data = None
    deadline = time.time() + timeout
    while time.time() < deadline:
        data = dash_data(env)
        if pred(data):
            return data
        time.sleep(0.25)
    return data


def dash_fetch(env, path, login=True):
    base, opener = _opener(env, login=login)
    try:
        resp = opener.open(base + path, timeout=10)
        return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def conv_items(data):
    return [i for c in data.get("conversations", [])
            for i in c.get("items", [])]


def file_item(data, name):
    for i in conv_items(data):
        f = i.get("file")
        if isinstance(f, dict) and f.get("name") == name:
            return i
    return None


async def _pair(env, state_root):
    a = await make(env, state_root, "alice")
    b = await make(env, state_root, "bob")
    return a, b


# -- inline image -------------------------------------------------------------

def test_inline_image_view_and_download(env_factory, state_root, tmp_path):
    env = env_factory()
    f = tmp_path / "pixel.png"
    f.write_bytes(PNG)

    async def scenario():
        a, b = await _pair(env, state_root)
        try:
            await a.send_file("bob", str(f))
            assert await wait_for(lambda: len(b.messages) == 1)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    data = dash_data_wait(env, lambda d: file_item(d, "pixel.png"))
    item = file_item(data, "pixel.png")
    assert item is not None, data["conversations"]
    info = item["file"]
    assert info["form"] == "inline"
    assert info["verified"] is True
    assert info["size"] == len(PNG)  # plaintext size, not ciphertext
    assert info["sha256"] == hashlib.sha256(PNG).hexdigest()
    assert info["mime"] == "image/png"
    assert info["kind"] == "image"
    assert info["url"] == f"/api/file/{item['id']}"
    # No file bytes ride the status payload.
    assert base64.b64encode(PNG).decode() not in json.dumps(data)
    status, headers, got = dash_fetch(env, info["url"])
    assert status == 200
    assert got == PNG  # byte-exact
    assert headers.get("X-Content-SHA256") == \
        hashlib.sha256(PNG).hexdigest()
    assert headers.get_content_type() == "image/png"
    assert "inline" in (headers.get("Content-Disposition") or "")
    # The route is behind the operator session, like every /api route.
    status, _, _ = dash_fetch(env, info["url"], login=False)
    assert status == 401


# -- inline arbitrary file (zip) ----------------------------------------------

def test_inline_zip_downloads_as_attachment(env_factory, state_root,
                                            tmp_path):
    env = env_factory()
    f = tmp_path / "bundle.zip"
    f.write_bytes(ZIP_BYTES)

    async def scenario():
        a, b = await _pair(env, state_root)
        try:
            await a.send_file("bob", str(f))
            assert await wait_for(lambda: len(b.messages) == 1)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    data = dash_data_wait(env, lambda d: file_item(d, "bundle.zip"))
    item = file_item(data, "bundle.zip")
    assert item is not None
    info = item["file"]
    assert info["form"] == "inline" and info["verified"] is True
    assert info["size"] == len(ZIP_BYTES)
    assert info["sha256"] == hashlib.sha256(ZIP_BYTES).hexdigest()
    status, headers, got = dash_fetch(env, info["url"])
    assert status == 200
    assert got == ZIP_BYTES
    disp = headers.get("Content-Disposition") or ""
    assert "attachment" in disp and "bundle.zip" in disp, disp


# -- inline video ---------------------------------------------------------------

def test_inline_video_serves_inline(env_factory, state_root, tmp_path):
    env = env_factory()
    f = tmp_path / "clip.mp4"
    f.write_bytes(VIDEO_BYTES)

    async def scenario():
        a, b = await _pair(env, state_root)
        try:
            await a.send_file("bob", str(f))
            assert await wait_for(lambda: len(b.messages) == 1)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    data = dash_data_wait(env, lambda d: file_item(d, "clip.mp4"))
    item = file_item(data, "clip.mp4")
    assert item is not None
    info = item["file"]
    assert info["form"] == "inline" and info["verified"] is True
    assert info["kind"] == "video"
    status, headers, got = dash_fetch(env, info["url"])
    assert status == 200
    assert got == VIDEO_BYTES
    assert headers.get_content_type() == "video/mp4"
    assert "inline" in (headers.get("Content-Disposition") or "")


# -- tampered inline payload: fail-closed ---------------------------------------

def test_tampered_inline_fails_closed(env_factory, state_root):
    env = env_factory()
    raw = b"tamper-target-bytes" * 4
    payload = {
        "name": "evil.png", "kind": "image", "mime": "image/png",
        "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
        # Bytes corrupted AFTER the header was computed: same length,
        # wrong sha256 — verify_file must refuse.
        "data_b64": base64.b64encode(b"X" + raw[1:]).decode(),
    }

    async def scenario():
        a, b = await _pair(env, state_root)
        try:
            # The real send path: the doctored payload is sealed,
            # oversight-wrapped and audit-logged by production code.
            await a.send_message("bob", "", kind="image", file=payload)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    data = dash_data_wait(env, lambda d: file_item(d, "evil.png"))
    item = file_item(data, "evil.png")
    assert item is not None, data["conversations"]
    info = item["file"]
    assert info["form"] == "inline"
    assert info["verified"] is False
    assert "url" not in info  # fail-closed: no URL is ever issued
    status, _, body = dash_fetch(env, f"/api/file/{item['id']}")
    assert status == 404
    assert json.loads(body)["error"] == "file unavailable"


# -- blob form --------------------------------------------------------------------

def test_blob_form_verified_then_missing(env_factory, state_root, tmp_path):
    blobs = LocalBlobStore(str(tmp_path / "blob-root"))
    env = env_factory(blob_store=blobs)
    f = tmp_path / "blobpic.png"
    f.write_bytes(PNG)

    async def scenario():
        a, b = await _pair(env, state_root)
        try:
            await a.send_file("bob", str(f), via_blob=True)
            assert await wait_for(lambda: len(b.messages) == 1)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    data = dash_data_wait(env, lambda d: file_item(d, "blobpic.png"))
    item = file_item(data, "blobpic.png")
    assert item is not None, data["conversations"]
    info = item["file"]
    assert info["form"] == "blob"
    assert info["verified"] is True
    assert info["size"] == len(PNG)
    assert info["sha256"] == hashlib.sha256(PNG).hexdigest()
    assert info["url"] == item["blob_url"]
    status, headers, got = dash_fetch(env, item["blob_url"])
    assert status == 200
    assert got == PNG  # decrypted plaintext, byte-exact
    # Delete the object: the rebuilt payload must say so honestly.
    blobs.delete(item["blob_id"])
    env["relay"].dashboard.notify()
    data = dash_data_wait(
        env, lambda d: (file_item(d, "blobpic.png") or {})
        .get("file", {}).get("verified") is False)
    item = file_item(data, "blobpic.png")
    assert item is not None
    assert item["file"]["verified"] is False
    assert "url" not in item["file"]
    status, _, _ = dash_fetch(env, "/api/blob/" + item["blob_id"])
    assert status == 404


# -- non-file items unchanged ------------------------------------------------------

def test_text_message_has_no_file_key(env_factory, state_root):
    env = env_factory()

    async def scenario():
        a, b = await _pair(env, state_root)
        try:
            await a.send_message("bob", "just words, no file")
            assert await wait_for(lambda: len(b.messages) == 1)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    data = dash_data_wait(
        env, lambda d: any(i.get("text") == "just words, no file"
                           for i in conv_items(d)))
    texts = [i for i in conv_items(data) if i.get("kind") == "message"]
    assert len(texts) == 1
    assert "file" not in texts[0]


# -- separation: not library, never deduped -----------------------------------------

def test_dm_file_not_in_library_and_never_deduped(env_factory, state_root,
                                                  tmp_path):
    env = env_factory()
    f = tmp_path / "pixel.png"
    f.write_bytes(PNG)

    async def scenario():
        a, b = await _pair(env, state_root)
        try:
            await a.send_file("bob", str(f))
            await a.send_file("bob", str(f))  # same file, second send
            assert await wait_for(lambda: len(b.messages) == 2)
        finally:
            await a.close()
            await b.close()

    run(scenario())
    data = dash_data_wait(
        env, lambda d: len([i for i in conv_items(d)
                            if (i.get("file") or {}).get("name")
                            == "pixel.png"]) == 2)
    # The Library stays work-deliverables-only: the DM file is absent.
    assert all(e.get("filename") != "pixel.png"
               for e in data.get("library", []))
    hits = [i for i in conv_items(data)
            if (i.get("file") or {}).get("name") == "pixel.png"]
    assert len(hits) == 2  # exactly the two sends — no dedupe, no extra
    assert hits[0]["id"] != hits[1]["id"]
    assert all(i["file"]["verified"] is True for i in hits)


# -- served page carries the in-thread file UI ---------------------------------------

def test_dashboard_html_has_file_ui(env_factory):
    env = env_factory()
    base, opener = _opener(env)
    html = opener.open(base + "/", timeout=5).read().decode()
    assert "humanSize" in html
    assert "filechip unavailable" in html
    assert "bytes could not be verified" in html
    assert "<audio controls" in html
    assert 'class="chatvid"' in html and 'class="chatimg"' in html
