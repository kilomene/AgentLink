"""Owner downloads (v1.1.2, owner's order 2026-11-02): the owner
personally downloads files from the delivery Library and from
group Vaults, from the dashboard — a read action inside his
owner-oversight (the dashboard otherwise stays monitor-only).

Real composition only: real clients -> relay -> store -> dashboard
HTTP. Wrap chains under test:
- Library: entry metadata -> the work delivery's kind "content"
  oversight wrap (audit row) -> content {"files": [payload]} ->
  inline payload bytes, sha256/size verified against the index.
- Vault: entry -> stored descriptor -> its nested kind
  "content_key" oversight wrap -> file key -> relay blob store
  ciphertext -> exact original bytes.
Legacy (pre-oversight) items must state honestly that they are not
downloadable and the routes must refuse cleanly (404, no 500, no
empty file). Unauthenticated attempts get 401. File bytes never
ride the /api/status JSON.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from agentlink.client import Agent
from agentlink.crypto import OversightKey
from agentlink.relay import Relay

HOST = "127.0.0.1"
PASSWORD = "test-dash-pass"


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
def oversight_env(monkeypatch):
    """Relay advertising an oversight pubkey (clients wrap for real)
    + dashboard holding the matching private key file."""
    tmp = tempfile.mkdtemp(prefix="agentlink-dl-")
    okey = OversightKey.generate()
    key_path = okey.save(str(Path(tmp) / "oversight-key.json"))
    monkeypatch.setenv("AGENTLINK_OVERSIGHT_KEY_FILE", str(key_path))
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password=PASSWORD, dashboard_port=0,
                  oversight_pubkey=okey.public_key_b64)
    box = _start_relay(relay)
    yield {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "dash_port": relay.dashboard_port, "relay": relay,
           "okey": okey, "tmp": Path(tmp)}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def legacy_env(monkeypatch):
    """No oversight anywhere: clients send no wraps, the dashboard
    holds no key — every item is pre-oversight legacy."""
    monkeypatch.delenv("AGENTLINK_OVERSIGHT_KEY_FILE", raising=False)
    monkeypatch.delenv("AGENTLINK_OVERSIGHT_PUBKEY", raising=False)
    tmp = tempfile.mkdtemp(prefix="agentlink-dl-legacy-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password=PASSWORD, dashboard_port=0)
    box = _start_relay(relay)
    yield {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "dash_port": relay.dashboard_port, "relay": relay,
           "tmp": Path(tmp)}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-dl-agents-") as tmp:
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


def dash_fetch(env, path, login=True):
    base, opener = _opener(env, login=login)
    try:
        resp = opener.open(base + path, timeout=10)
        return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


DELIVERABLE = b"OWNER-DOWNLOAD-DELIVERABLE\x00\x01" + bytes(range(256)) * 4
VAULT_FILE = b"vault release checklist\n- ship it\n" * 7


async def _deliver(env, state_root, tmp_path):
    f = tmp_path / "deliverable.bin"
    f.write_bytes(DELIVERABLE)
    boss = await make(env, state_root, "dl-boss")
    hand = await make(env, state_root, "dl-hand")
    works = await boss.assign_work(["dl-hand"], "Downloadable work",
                                   "make the file")
    await hand.deliver_work(works[0]["id"], "here is the file",
                            files=[str(f)])
    await boss.close()
    await hand.close()


async def _vault_put(env, state_root, tmp_path):
    f = tmp_path / "checklist.txt"
    f.write_bytes(VAULT_FILE)
    a = await make(env, state_root, "dl-alice")
    b = await make(env, state_root, "dl-bob")
    g = await a.group_create("Download Crew", ["dl-bob"])
    entry = await a.vault_put(g["group_id"], str(f))
    await a.close()
    await b.close()
    return entry


# -- (a) library download ------------------------------------------------

def test_library_download_byte_exact(oversight_env, state_root, tmp_path):
    run(_deliver(oversight_env, state_root, tmp_path))
    data = dash_data(oversight_env)
    assert data["oversight_enabled"] is True
    lib = data["library"]
    assert len(lib) == 1, lib
    e = lib[0]
    assert e["filename"] == "deliverable.bin"
    assert e["sha256"] == hashlib.sha256(DELIVERABLE).hexdigest()
    assert e.get("download_url") == f"/api/library/{e['id']}/download", e
    assert "not_downloadable" not in e
    # No wrap, no descriptor, and NO file bytes in the status JSON.
    assert "oversight" not in e and "descriptor" not in e
    assert base64.b64encode(DELIVERABLE).decode() not in json.dumps(data)
    status, headers, got = dash_fetch(oversight_env, e["download_url"])
    assert status == 200
    assert got == DELIVERABLE
    disp = headers.get("Content-Disposition") or ""
    assert "attachment" in disp and "deliverable.bin" in disp, disp


# -- (b) vault download ----------------------------------------------------

def test_vault_download_byte_exact(oversight_env, state_root, tmp_path):
    entry = run(_vault_put(oversight_env, state_root, tmp_path))
    # The stored descriptor carries the wrap chain the dashboard uses.
    stored = oversight_env["relay"].store.vault_entry(entry["id"])
    assert stored["descriptor"]["oversight"]["kind"] == "content_key"
    data = dash_data(oversight_env)
    vault = data["vault"]
    assert len(vault) == 1, vault
    v = vault[0]
    assert v["name"] == "checklist.txt"
    assert v.get("download_url") == f"/api/vault/{v['id']}/download", v
    # The descriptor (and its wrap) never reach the browser payload.
    assert "descriptor" not in v and "oversight" not in v
    assert "blob_id" not in v
    assert base64.b64encode(VAULT_FILE).decode() not in json.dumps(data)
    status, headers, got = dash_fetch(oversight_env, v["download_url"])
    assert status == 200
    assert got == VAULT_FILE
    disp = headers.get("Content-Disposition") or ""
    assert "attachment" in disp and "checklist.txt" in disp, disp


# -- (c) legacy items: honest state + clean refusal -------------------------

def test_legacy_items_honest_and_refused(legacy_env, state_root, tmp_path):
    run(_deliver(legacy_env, state_root, tmp_path))
    run(_vault_put(legacy_env, state_root, tmp_path))
    data = dash_data(legacy_env)
    assert data["oversight_enabled"] is False
    lib = data["library"]
    assert len(lib) == 1, lib
    e = lib[0]
    assert "download_url" not in e
    assert e["not_downloadable"] is True
    assert e["download_note"] == "sealed before owner oversight"
    status, headers, body = dash_fetch(
        legacy_env, f"/api/library/{e['id']}/download")
    assert status == 404, (status, body)
    assert json.loads(body)["error"] == "not_downloadable"
    vault = data["vault"]
    assert len(vault) == 1, vault
    v = vault[0]
    assert "download_url" not in v
    assert v["not_downloadable"] is True
    assert v["download_note"] == "sealed before owner oversight"
    assert "descriptor" not in v
    status, headers, body = dash_fetch(
        legacy_env, f"/api/vault/{v['id']}/download")
    assert status == 404, (status, body)
    assert json.loads(body)["error"] == "not_downloadable"
    # Unknown ids refuse the same clean way — no 500s anywhere.
    for path in ("/api/library/lib-nope/download",
                 "/api/vault/v-nope/download"):
        status, _, body = dash_fetch(legacy_env, path)
        assert status == 404, (path, status, body)


# -- (d) unauthenticated -----------------------------------------------------

def test_downloads_require_login(oversight_env, state_root, tmp_path):
    run(_deliver(oversight_env, state_root, tmp_path))
    entry = run(_vault_put(oversight_env, state_root, tmp_path))
    lib = oversight_env["relay"].store.library_all()
    assert lib
    for path in (f"/api/library/{lib[0]['id']}/download",
                 f"/api/vault/{entry['id']}/download"):
        status, _, _ = dash_fetch(oversight_env, path, login=False)
        assert status == 401, (path, status)


# -- served page carries the download UI -------------------------------------

def test_dashboard_html_has_download_ui(oversight_env):
    base, opener = _opener(oversight_env)
    html = opener.open(base + "/", timeout=5).read().decode()
    assert "dllink" in html and "⬇ Download" in html
    assert "not downloadable" in html
    assert "sealed before owner oversight" in html
    # Still monitor-only: downloads are links, no protocol actions.
    assert "work_action" not in html and "vault_add" not in html


def test_mobile_navtoggle_lives_in_top_header(oversight_env):
    """Owner's standing law (flagged by the v1.1.2 live proof): at
    mobile widths the nav toggle sits IN the top header beside the
    Nova logo — never as a floating bottom-left button. Desktop
    keeps the persistent sidebar; the drawer behaviour is unchanged
    (the same #navtoggle button + setDrawer wiring)."""
    base, opener = _opener(oversight_env)
    html = opener.open(base + "/", timeout=5).read().decode()
    # The toggle is INSIDE the header, followed by the logo mark.
    i = html.index('<header id="topbar">')
    j = html.index('</header>')
    header = html[i:j]
    assert 'id="navtoggle"' in header
    assert 'class="mark"' in header and "data:image/jpeg" in header
    assert header.index('id="navtoggle"') < header.index('class="mark"')
    # CSS: header hidden by default (desktop), a fixed flex bar at
    # <=900px, and the toggle is no longer a fixed bottom button.
    assert "#topbar{display:none}" in html
    assert "#topbar{display:flex" in html
    start = html.index("#navtoggle{")
    nav = html[start:html.index("}", start)]
    assert "position:fixed" not in nav and "bottom:" not in nav
