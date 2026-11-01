"""Ops tests: dashboard login/trusted-device flow, DB hardening,
audit log, and the GitHub auto-updater (verify/install/rollback)
against a real local HTTP server. No mocks."""

from __future__ import annotations

import asyncio
import hashlib
import http.cookiejar
import json
import sqlite3
import stat
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from websockets.client import connect  # noqa: F401  (parity with other suites)

from agentlink.client import Agent
from agentlink.relay import Relay
from agentlink.updater import UpdateError, Updater

HOST = "127.0.0.1"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-ops-")
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
    yield {"url": f"ws://{HOST}:{relay.port}", "relay": relay,
           "dash": f"http://{HOST}:{relay.dashboard_port}",
           "db": str(Path(tmp) / "relay.db"), "tmp": tmp}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-ops-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=30))


def _opener():
    cj = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj)), cj


def _post(opener, url, data: bytes):
    req = urllib.request.Request(url, data=data, method="POST")
    return opener.open(req, timeout=5)


def test_dashboard_login_trusted_device_flow(relay_env):
    opener, cj = _opener()
    base = relay_env["dash"]
    # Unauthenticated: status is 401, / shows the login page.
    with pytest.raises(urllib.error.HTTPError) as ei:
        opener.open(base + "/api/status", timeout=5)
    assert ei.value.code == 401
    login_page = opener.open(base + "/", timeout=5).read().decode()
    assert "Operator login" in login_page
    # Wrong password: 401.
    with pytest.raises(urllib.error.HTTPError) as ei:
        _post(opener, base + "/login", b"password=nope")
    assert ei.value.code == 401
    # Correct password: trusted-device cookie, HttpOnly, 7-day Max-Age.
    # (Read the raw 302 response — a redirect-following client would
    # surface the headers of the follow-up GET instead.)
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **kw):
            return None
    opener_nr = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj), _NoRedirect())
    with pytest.raises(urllib.error.HTTPError) as ei:
        _post(opener_nr, base + "/login", b"password=test-pass")
    assert ei.value.code == 302
    set_cookie = ei.value.headers.get("Set-Cookie") or ""
    assert "HttpOnly" in set_cookie
    assert "Max-Age=604800" in set_cookie
    cookies = [c for c in cj]
    assert cookies and cookies[0].name == "agentlink_dash"
    # Now the dashboard + status work, and the session persists across
    # fresh requests with just the cookie.
    page = opener.open(base + "/", timeout=5).read().decode()
    assert "Live Dashboard" in page
    data = json.loads(opener.open(base + "/api/status", timeout=5).read())
    assert "users" in data and "activity" in data
    # Logout revokes server-side: the same cookie stops working.
    _post(opener, base + "/logout", b"")
    opener2, _ = _opener()
    # Reuse the revoked token explicitly.
    req = urllib.request.Request(
        base + "/api/status",
        headers={"Cookie": f"agentlink_dash={cookies[0].value}"})
    with pytest.raises(urllib.error.HTTPError) as ei:
        opener2.open(req, timeout=5)
    assert ei.value.code == 401


def test_db_hardened_and_secret_hashed(relay_env, state_root):
    async def _t():
        a = Agent("alice", endpoint=relay_env["url"],
                  state_dir=str(state_root / "alice"))
        await a.start()
        secret = json.loads(
            (state_root / "alice" / "secret-alice.json").read_text())["secret"]
        await a.close()
        return secret
    secret = run(_t())
    db = Path(relay_env["db"])
    assert stat.S_IMODE(db.stat().st_mode) == 0o600
    raw = db.read_bytes()
    assert secret.encode() not in raw  # only its SHA-256 hash is stored
    conn = sqlite3.connect(str(db))
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    # Private key material is never in the relay DB.
    keys = (state_root / "alice" / "keys-alice.json").read_text()
    priv = json.loads(keys)["private_key"]
    assert priv.encode() not in raw
    conn.close()


def test_audit_log_append_only_metadata(relay_env, state_root):
    async def _t():
        alice = Agent("alice", endpoint=relay_env["url"],
                      state_dir=str(state_root / "alice"))
        bob = Agent("bob", endpoint=relay_env["url"],
                    state_dir=str(state_root / "bob"))
        await alice.start()
        await bob.start()
        await alice.send_message("bob", "audit me not the content")
        await alice.close()
        await bob.close()
    run(_t())
    conn = sqlite3.connect(relay_env["db"])
    rows = conn.execute(
        "SELECT kind, actor, target FROM audit_log").fetchall()
    conn.close()
    kinds = {(r[0], r[1], r[2]) for r in rows}
    assert ("message", "alice", "bob") in kinds
    assert ("online", "alice", "") in kinds


# -- updater ---------------------------------------------------------------

def _serve_dir(directory: Path):
    handler = lambda *a, **kw: SimpleHTTPRequestHandler(  # noqa: E731
        *a, directory=str(directory), **kw)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _make_release(root: Path, version: str, init_body: str,
                  corrupt: bool = False):
    pkg = root / "agentlink"
    pkg.mkdir(parents=True, exist_ok=True)
    files = {}
    body = init_body.encode()
    (pkg / "__init__.py").write_bytes(body)
    sha = hashlib.sha256(body).hexdigest()
    files["agentlink/__init__.py"] = ("0" * 64) if corrupt else sha
    manifest = {"version": version, "files": files}
    (root / "update-manifest.json").write_text(json.dumps(manifest))
    return manifest


def test_updater_verify_install_and_rollback(tmp_path):
    # Current install (a copy of the package skeleton) in tmp.
    install = tmp_path / "install"
    (install / "agentlink").mkdir(parents=True)
    (install / "agentlink" / "__init__.py").write_text(
        '__version__ = "1.0.0"\n')
    state = tmp_path / "state"

    # Release 1.1.0 served over real HTTP.
    rel = tmp_path / "release"
    rel.mkdir()
    _make_release(rel, "1.1.0", '__version__ = "1.1.0"\n')
    srv, base = _serve_dir(rel)
    try:
        up = Updater(base_url=base, install_dir=install, state_dir=state,
                     current_version="1.0.0")
        info = up.check()
        assert info["update_available"] is True
        result = up.apply()
        assert result["updated"] is True and result["to"] == "1.1.0"
        assert (install / "agentlink" / "__init__.py").read_text() == \
            '__version__ = "1.1.0"\n'
        # Backup of the old version exists for rollback.
        backups = list((state / "update-backups").iterdir())
        assert backups and (backups[0] / "VERSION").read_text() == "1.0.0"
    finally:
        srv.shutdown()

    # Corrupt manifest (hash mismatch): refused, nothing written.
    rel2 = tmp_path / "release-bad"
    rel2.mkdir()
    _make_release(rel2, "1.2.0", '__version__ = "1.2.0"\n', corrupt=True)
    srv, base = _serve_dir(rel2)
    try:
        up = Updater(base_url=base, install_dir=install, state_dir=state,
                     current_version="1.1.0")
        with pytest.raises(UpdateError):
            up.apply()
        assert (install / "agentlink" / "__init__.py").read_text() == \
            '__version__ = "1.1.0"\n'
    finally:
        srv.shutdown()

    # Broken release (valid hash, broken code): health check fails and
    # the updater rolls back automatically.
    rel3 = tmp_path / "release-broken"
    rel3.mkdir()
    _make_release(rel3, "1.3.0", 'this is not python (\n')
    srv, base = _serve_dir(rel3)
    try:
        up = Updater(base_url=base, install_dir=install, state_dir=state,
                     current_version="1.1.0")
        with pytest.raises(UpdateError):
            up.apply()
        assert (install / "agentlink" / "__init__.py").read_text() == \
            '__version__ = "1.1.0"\n'
    finally:
        srv.shutdown()
