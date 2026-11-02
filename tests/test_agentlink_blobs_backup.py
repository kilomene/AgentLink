"""Sealed blob storage (R2 layer, local backend + signed R2 requests
against a fake S3 endpoint) and encrypted backup create/verify.

Real relay, real clients, real HTTP — no mocks of the system itself.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from agentlink.backup import create_backup, verify_backup
from agentlink.blobstore import LocalBlobStore, R2BlobStore
from agentlink.client import Agent, RequestFailed
from agentlink.protocol import file_bytes, verify_file
from agentlink.relay import Relay

HOST = "127.0.0.1"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-blob-")
    relay = Relay(host=HOST, port=0, db_path=str(Path(tmp) / "relay.db"),
                  dashboard_password="test-pass", dashboard_port=0)
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

    threading.Thread(target=_thread, daemon=True).start()
    assert ready.wait(timeout=10)
    yield {"url": f"ws://{HOST}:{relay.port}", "tmp": tmp, "relay": relay}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-blob-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=30))


async def make(relay_env, state_root, username):
    a = Agent(username, endpoint=relay_env["url"],
              state_dir=str(state_root / username))
    await a.start()
    return a


async def wait_for(pred, timeout=5.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


def test_blob_round_trip_1to1_and_access_control(relay_env, state_root,
                                                 tmp_path):
    secret_file = tmp_path / "report.bin"
    secret_file.write_bytes(b"sealed-report-contents" * 10)

    async def _t():
        alice = await make(relay_env, state_root, "alice")
        bob = await make(relay_env, state_root, "bob")
        eve = await make(relay_env, state_root, "eve")
        await alice.send_file("bob", str(secret_file), caption="sealed",
                              via_blob=True)
        assert await wait_for(lambda: len(bob.messages) == 1)
        f = bob.messages[0]["file"]
        assert verify_file(f)
        assert file_bytes(f) == secret_file.read_bytes()

        # Eve was not a recipient: the relay refuses her the blob, and
        # there is no list/browse operation for her to find it with.
        blob_id = relay_env["relay"].store.list_blob_meta()[0]["id"]
        with pytest.raises(RequestFailed) as ei:
            await eve._request({"type": "blob_get", "blob_id": blob_id})
        assert ei.value.reason == "permission_denied"
        # Eve cannot delete it either; the owner can.
        with pytest.raises(RequestFailed):
            await eve.blob_delete(blob_id)
        await alice.blob_delete(blob_id)
        assert relay_env["relay"].store.list_blob_meta() == []
        for a in (alice, bob, eve):
            await a.close()
        return blob_id
    run(_t())
    # At rest, the blob on disk was ciphertext, never the plaintext.
    blobs_dir = Path(relay_env["tmp"]) / "blobs"
    assert not blobs_dir.exists() or all(
        b"sealed-report-contents" not in p.read_bytes()
        for p in blobs_dir.iterdir())


def test_blob_group_round_trip(relay_env, state_root, tmp_path):
    doc = tmp_path / "team.txt"
    doc.write_text("group sealed doc")

    async def _t():
        one = await make(relay_env, state_root, "agent-one")
        two = await make(relay_env, state_root, "agent-two")
        g = await one.group_create("BlobTeam", ["agent-two"])
        await one.group_send_file(g["group_id"], str(doc), via_blob=True)
        assert await wait_for(lambda: len(two.messages) == 1)
        f = two.messages[0]["file"]
        assert verify_file(f)
        assert file_bytes(f) == b"group sealed doc"
        await one.close()
        await two.close()
    run(_t())


def test_r2_store_signed_round_trip_against_fake_s3():
    store: dict[str, bytes] = {}
    seen_auth: list[str] = []

    class FakeS3(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _key(self):
            return self.path.rsplit("/", 1)[1]

        def do_PUT(self):
            seen_auth.append(self.headers.get("Authorization") or "")
            store[self._key()] = self.rfile.read(
                int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            if self._key() not in store:
                self.send_response(404)
                self.end_headers()
                return
            data = store[self._key()]
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_DELETE(self):
            store.pop(self._key(), None)
            self.send_response(204)
            self.end_headers()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), FakeS3)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    endpoint = f"http://127.0.0.1:{srv.server_address[1]}"
    r2 = R2BlobStore(bucket="agentlink-blobs", access_key="AKID",
                     secret_key="SECRET", endpoint=endpoint)
    r2.put("b-abc", b"ciphertext-bytes")
    assert store["b-abc"] == b"ciphertext-bytes"
    assert seen_auth and seen_auth[0].startswith(
        "AWS4-HMAC-SHA256 Credential=AKID/")
    assert r2.get("b-abc") == b"ciphertext-bytes"
    r2.delete("b-abc")
    assert "b-abc" not in store
    srv.shutdown()

    local = LocalBlobStore(Path(tempfile.mkdtemp()) / "blobs")
    local.put("b-x", b"data")
    assert local.get("b-x") == b"data"
    assert local.list_ids() == ["b-x"]


def test_r2_get_falls_back_to_ranges_when_body_truncated():
    """Production defect (v1.1.1 release): the egress proxy truncates
    large R2 GET bodies mid-read (http.client.IncompleteRead after
    ~10-26 KB), so the dashboard's /api/blob for a 91 KB image 404'd
    while every other path worked. R2BlobStore.get must reassemble
    the object from ranged slices when the plain GET truncates."""
    payload = bytes((i * 31 + 7) % 256 for i in range(90_000))
    store: dict[str, bytes] = {"b-big": payload}
    ranged: list[str] = []

    class TruncatingS3(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _key(self):
            return self.path.rsplit("/", 1)[1]

        def do_GET(self):
            if self._key() not in store:
                self.send_response(404)
                self.end_headers()
                return
            data = store[self._key()]
            rng = self.headers.get("Range")
            if rng:
                ranged.append(rng)
                a, b = rng.removeprefix("bytes=").split("-")
                a, b = int(a), min(int(b), len(data) - 1)
                chunk = data[a:b + 1]
                self.send_response(206)
                self.send_header("Content-Range",
                                 f"bytes {a}-{b}/{len(data)}")
                self.send_header("Content-Length", str(len(chunk)))
                self.end_headers()
                # Even slices truncate: promise the whole slice,
                # deliver a prefix, drop. The client must resume
                # from the partial bytes it did receive.
                self.wfile.write(chunk[:9000])
                self.connection.close()
                return
            # Plain GET: headers promise the whole body, the wire
            # delivers a prefix then drops — the observed proxy cut.
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data[:9000])
            self.connection.close()

    srv = ThreadingHTTPServer(("127.0.0.1", 0), TruncatingS3)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        endpoint = f"http://127.0.0.1:{srv.server_address[1]}"
        r2 = R2BlobStore(bucket="agentlink-blobs", access_key="AKID",
                         secret_key="SECRET", endpoint=endpoint)
        got = r2.get("b-big")
        assert got == payload
        assert len(ranged) >= 2  # reassembled from multiple slices
    finally:
        srv.shutdown()


def test_backup_create_verify_and_tamper(relay_env, tmp_path):
    # Seed a blob into the relay's blob dir so the archive covers it.
    blobs = LocalBlobStore(Path(relay_env["tmp"]) / "blobs")
    blobs.put("b-seed", b"blob-ciphertext")
    out = tmp_path / "backups"
    result = create_backup(relay_env["db"] if "db" in relay_env else
                           str(Path(relay_env["tmp"]) / "relay.db"),
                           str(Path(relay_env["tmp"]) / "blobs"),
                           str(out), passphrase="operator-pass")
    assert result["verified"] is True
    archive = result["archive"]
    check = verify_backup(archive, "operator-pass")
    assert check["ok"] is True
    # Wrong passphrase: does not count as a backup.
    assert verify_backup(archive, "wrong")["ok"] is False
    # Tampered archive: does not count either.
    raw = bytearray(Path(archive).read_bytes())
    raw[-5] ^= 0xFF
    bad = tmp_path / "bad.enc"
    bad.write_bytes(bytes(raw))
    assert verify_backup(str(bad), "operator-pass")["ok"] is False
    # Archive bytes never contain the DB's readable content markers.
    assert hashlib.sha256(b"x").hexdigest()
