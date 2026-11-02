"""v1.1.0 upgrade regression suite (owner order 2026-11-01: every
feature in, advanced, nothing removed).

Pins: ephemeral-port fixtures under production load, the animated
drawer dashboard (served-HTML markers), conversation completeness
(sender nickname/role/custom role + group participants), the
reachability home-label fix, approval gates end-to-end (happy path,
reject path, chain blocking, decider rules, trust timing), the
AGENTLINK_BACKEND env fix, and the canonical invites / upload-session
schema alignment. Harness copied from test_features2.py.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import tarfile
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

import pytest

from agentlink.client import Agent, RequestFailed, unpack_folder
from agentlink.deadlines import pacific_display, parse_deadline
from agentlink.protocol import file_bytes
from agentlink.relay import Relay

HOST = "127.0.0.1"


@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-f2-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="test-dash-pass", dashboard_port=0)
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
    yield {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "dash_port": relay.dashboard_port, "relay": relay}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-f2-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=60))


async def make(relay_env, state_root, username, **kw):
    a = Agent(username, endpoint=relay_env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


async def wait_for(pred, timeout=8.0):
    for _ in range(int(timeout / 0.05)):
        if pred():
            return True
        await asyncio.sleep(0.05)
    return pred()


def dash_data(relay_env):
    base = f"http://{HOST}:{relay_env['dash_port']}"
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor())
    req = urllib.request.Request(
        base + "/login", data=b"password=test-dash-pass",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        opener.open(req, timeout=5)
    except urllib.error.HTTPError:
        pass
    return json.loads(opener.open(base + "/api/status", timeout=5).read())




def dash_html(relay_env):
    base = f"http://{HOST}:{relay_env['dash_port']}"
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor())
    import urllib.parse as _up
    body = _up.urlencode(
        {"password": relay_env["relay"].dashboard_password}).encode()
    req = urllib.request.Request(
        base + "/login", data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        opener.open(req, timeout=5)
    except urllib.error.HTTPError:
        pass
    return opener.open(base + "/", timeout=5).read().decode()


# -- dashboard: drawer + animation system (served HTML markers) ----------

def test_dashboard_html_has_drawer_and_animation_system(relay_env):
    """Item 2a/2b: the served dashboard carries the animated slide-in
    side drawer (logo mark, grouped nav, live connection status),
    the pulsing LIVE indicator keyframes, enter transitions, animated
    presence dots and the prefers-reduced-motion guard."""
    html = dash_html(relay_env)
    assert 'id="drawer"' in html and 'class="mark"' in html
    for label in ("Overview", "Agents", "Conversations", "Work",
                  "Chains", "Library", "Vault", "Voice Rooms",
                  "Alerts"):
        assert label in html, label
    assert 'id="livedot"' in html and "livePulse" in html
    assert "@keyframes" in html and "riseIn" in html
    assert "prefers-reduced-motion" in html
    assert "new EventSource" in html or "EventSource('/api/stream')" in html
    # monitor-only: the page embeds no protocol action surface at all
    # (decisions happen on the line, never here)
    assert "work_action" not in html and "blob_session" not in html
    assert 'id="convs"' in html and 'id="work"' in html


# -- dashboard design law: real Nova logo, white theme, Nova company -----

NOVA_LOGO_SHA256 = \
    "d0c4f86e64a52875b0f7688132f0929807f2c0d2a043c02c34e7e6e73613f675"


def _logo_hashes(html):
    out = []
    for m in re.finditer(r"data:image/jpeg;base64,([A-Za-z0-9+/=]+)", html):
        out.append(hashlib.sha256(base64.b64decode(m.group(1))).hexdigest())
    return out


def test_dashboard_design_law_logo_and_theme(relay_env):
    """Owner's standing design law: the dashboard carries HIS real Nova
    logo (served bytes hash-match the authoritative logo file — never a
    substitute glyph/mark), the drawer says 'A Nova company', and the
    theme is the white/light Nova design system."""
    html = dash_html(relay_env)
    hashes = _logo_hashes(html)
    assert hashes, "no embedded logo image served"
    assert all(h == NOVA_LOGO_SHA256 for h in hashes), hashes
    assert '<img' in html and 'class="mark"' in html
    assert "◆" not in html  # the old substitute glyph is gone
    assert "A <b>Nova</b> company" in html
    # light GLASSMORPHISM design system (owner's locked language):
    # frosted translucent panels + backdrop blur over the aurora wash
    assert "--bg:#edf1f7" in html
    assert "--glass:rgba(255,255,255,.62)" in html
    assert "backdrop-filter:blur(18px)" in html
    assert 'class="aurora"' in html and "drift1" in html and "drift2" in html
    assert "Space Grotesk" in html and "Inter" in html


def test_login_page_design_law(relay_env):
    """The login page obeys the same law: real logo, light theme,
    'A Nova company'."""
    base = f"http://{HOST}:{relay_env['dash_port']}"
    html = urllib.request.urlopen(base + "/", timeout=5).read().decode()
    hashes = _logo_hashes(html)
    assert hashes and all(h == NOVA_LOGO_SHA256 for h in hashes), hashes
    assert "A <b>Nova</b> company" in html
    assert "--bg:#edf1f7" in html and "◆" not in html


# -- per-section views + WhatsApp chat markup ------------------------------

def test_dashboard_views_and_chat_markup(relay_env):
    """Expansion A/B structure pins: every section is its own
    hash-routed view (persistent sidebar nav), and the Conversations
    view is a WhatsApp-style chat screen (list + pane + bubbles) with
    the honest sealed-content note."""
    html = dash_html(relay_env)
    for view in ("overview", "agents", "conversations", "work", "chains",
                 "library", "vault", "rooms", "activity"):
        assert f'id="view-{view}"' in html, view
        assert f'href="#/{view}"' in html, view
        assert f'data-route="{view}"' in html, view
    assert "hashchange" in html and "viewIn" in html
    # chat screen pieces
    assert 'id="chatwrap"' in html and 'id="chatmsgs"' in html
    assert 'id="chathead"' in html and 'id="sealednote"' in html
    assert "Content sealed" in html and "chatrow" in html and "bubble" in html
    assert "bubbleIn" in html


def test_dashboard_channel_conversation_names(relay_env):
    """Channel conversations resolve their display name against the
    channels list (with a channel marker), not the 'Group <id-tail>'
    fallback that group-only resolution produced: channel posts ride
    audit rows whose group_id is the channel id, which is not a group.
    The chat header likewise labels a channel conversation as a
    broadcast channel instead of listing (empty) group participants."""
    html = dash_html(relay_env)
    assert "function convChannel(c)" in html
    assert "lastData.channels" in html
    assert "if(ch) return '📣 '+ch.name;" in html
    assert "broadcast channel · by @" in html


def test_dashboard_mobile_responsive_stack(relay_env):
    """Responsive law (owner's standing rule, restated 2026-11-02 with
    screenshots of Library/Vault sprawling off a phone viewport):
    mobile widths get a TRUE mobile layout, desktop the desktop
    layout, and no horizontal overflow ever. The desktop list tables
    size columns to max-content (nowrap sealed-notes, unbreakable
    ids/hashes), which dragged the document to 576-587px at a 390px
    viewport. Pins: every list table carries .stack, and the <=900px
    block restacks rows into one-item blocks with
    overflow-wrap:anywhere collapsing long-token min-content; the
    desktop base table rule is untouched."""
    html = dash_html(relay_env)
    for tid in ("groups", "ovact", "users", "work", "chains",
                "library", "vault", "rooms", "act"):
        assert f'<table class="stack"><tbody id="{tid}">' in html, tid
    assert "table.stack,table.stack tbody{display:block" in html
    assert "table.stack tr{display:block" in html
    assert "table.stack td{display:block" in html
    assert "overflow-wrap:anywhere" in html
    assert ".sealed-note{white-space:normal}" in html
    assert "table{width:100%;border-collapse:collapse" in html


# -- owner oversight: REAL composition (client -> relay -> audit ->
#    dashboard). No fabricated wraps anywhere in this section: real
#    clients adopt the relay-advertised oversight pubkey from the
#    welcome frame and emit the production wrap shapes; the dashboard
#    opens them from the persisted audit rows. (The pre-composition
#    _inject_oversight monkeypatch suite was deleted — it tested a
#    {wrapped_key,...} shape production code never emitted, which is
#    how the group/channel breakage shipped green.)

@pytest.fixture()
def oversight_env(monkeypatch):
    """A relay whose clients wrap for oversight (oversight_pubkey
    configured; adopted from the welcome frame) AND whose dashboard
    holds the matching PRIVATE key via AGENTLINK_OVERSIGHT_KEY_FILE
    (the canonical `agentlink oversight-keygen` file, set BEFORE the
    DashboardServer is constructed)."""
    from agentlink.crypto import OversightKey
    tmp = tempfile.mkdtemp(prefix="agentlink-ovc-")
    okey = OversightKey.generate()
    key_path = okey.save(str(Path(tmp) / "oversight-key.json"))
    monkeypatch.setenv("AGENTLINK_OVERSIGHT_KEY_FILE", str(key_path))
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="test-dash-pass", dashboard_port=0,
                  oversight_pubkey=okey.public_key_b64)
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
    yield {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "dash_port": relay.dashboard_port, "relay": relay,
           "okey": okey, "tmp": Path(tmp)}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def oversight_nowatch_env():
    """Oversight pubkey configured at the relay (clients wrap for
    real) but NO key file for the dashboard: content must stay
    honestly sealed in the payload."""
    from agentlink.crypto import OversightKey
    tmp = tempfile.mkdtemp(prefix="agentlink-ovn-")
    okey = OversightKey.generate()
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="test-dash-pass", dashboard_port=0,
                  oversight_pubkey=okey.public_key_b64)
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
    yield {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "dash_port": relay.dashboard_port, "relay": relay,
           "okey": okey, "tmp": Path(tmp)}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


def dash_fetch(relay_env, path):
    """Authenticated dashboard GET -> (status, headers, bytes)."""
    base = f"http://{HOST}:{relay_env['dash_port']}"
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor())
    req = urllib.request.Request(
        base + "/login", data=b"password=test-dash-pass",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        opener.open(req, timeout=5)
    except urllib.error.HTTPError:
        pass
    try:
        resp = opener.open(base + path, timeout=10)
        return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def conv_items(data, kind):
    return [i for c in data["conversations"] for i in c["items"]
            if i["kind"] == kind]


def test_oversight_composition_1v1_text(oversight_env, state_root):
    """Real chain, 1v1: a real client's kind=content wrap is opened
    by the dashboard from the persisted audit row — exact text."""
    body = "composition dm — exact string ✓ 42"

    async def _t():
        one = await make(oversight_env, state_root, "cmp-one")
        two = await make(oversight_env, state_root, "cmp-two")
        await one.send_message("cmp-two", body)
        assert await wait_for(lambda: len(two.messages) == 1)
        await one.close(); await two.close()
    run(_t())
    data = dash_data(oversight_env)
    assert data["oversight_enabled"] is True
    items = conv_items(data, "message")
    assert len(items) == 1, items
    item = items[0]
    assert item["text"] == body, item
    assert item["sealed"] is False
    assert "oversight" not in item  # wrap never echoed to the browser
    assert "content_envelope" not in item


def test_oversight_composition_group_text(oversight_env, state_root):
    """Real chain, group: the client's kind=content_key wrap (raw
    group key) combines with the persisted frame content envelope —
    the dashboard renders the EXACT group string (this composition
    shipped broken twice: wrap ignored `kind`, envelope never
    persisted)."""
    body = "group composition — exact string, no mojibake"

    async def _t():
        one = await make(oversight_env, state_root, "cmp-one")
        two = await make(oversight_env, state_root, "cmp-two")
        g = await one.group_create("Composition Crew", ["cmp-two"])
        gid = g["group_id"]
        await one.group_send(gid, body)
        assert await wait_for(
            lambda: any(m.get("group_id") == gid for m in two.messages))
        await one.close(); await two.close()
    run(_t())
    # The persisted audit row itself carries BOTH ciphertext pieces.
    rows = [r for r in oversight_env["relay"].store.list_audit(100)
            if r["kind"] == "group_message"]
    assert len(rows) == 1
    assert rows[0]["oversight"]["kind"] == "content_key"
    cenv = rows[0]["content_envelope"]
    assert cenv and cenv["ct"] and cenv["nonce"] and "epoch" in cenv
    data = dash_data(oversight_env)
    items = conv_items(data, "group_message")
    assert len(items) == 1, items
    assert items[0]["text"] == body, items[0]
    assert items[0]["sealed"] is False
    assert "oversight" not in items[0]
    assert "content_envelope" not in items[0]


def test_oversight_composition_channel_text(oversight_env, state_root):
    """Real chain, channel: same content-key composition as groups."""
    body = "channel composition — exact post text"

    async def _t():
        one = await make(oversight_env, state_root, "cmp-one")
        two = await make(oversight_env, state_root, "cmp-two")
        c = await one.channel_create("Composition Channel", ["cmp-two"])
        await one.channel_send(c["channel_id"], body)
        assert await wait_for(lambda: len(two.messages) == 1)
        await one.close(); await two.close()
    run(_t())
    data = dash_data(oversight_env)
    items = conv_items(data, "channel_message")
    assert len(items) == 1, items
    assert items[0]["text"] == body, items[0]
    assert items[0]["sealed"] is False


def test_oversight_composition_file_blob_fetch(oversight_env, state_root,
                                               tmp_path):
    """Real chain, files: a blob file message's caption opens via
    the outer content wrap; the descriptor's nested oversight wrap
    (kind=content_key -> file key) lets /api/blob serve the EXACT
    file bytes to the operator session — inline for images,
    attachment for other types. Bytes never ride the status JSON."""
    png = base64.b64decode(
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8"
        "Xw8AAwMCAO+ip1sAAAAASUVORK5CYII=")
    shot = tmp_path / "shot.png"
    shot.write_bytes(png)
    blob_bytes = bytes(range(256)) * 8
    binf = tmp_path / "payload.bin"
    binf.write_bytes(blob_bytes)

    async def _t():
        one = await make(oversight_env, state_root, "cmp-one")
        two = await make(oversight_env, state_root, "cmp-two")
        await one.send_file("cmp-two", str(shot),
                            caption="look at this shot", via_blob=True)
        await one.send_file("cmp-two", str(binf),
                            caption="and this data", via_blob=True)
        assert await wait_for(lambda: len(two.messages) == 2)
        await one.close(); await two.close()
    run(_t())
    data = dash_data(oversight_env)
    items = conv_items(data, "message")
    assert len(items) == 2, items
    by_name = {i.get("file_name"): i for i in items}
    img = by_name["shot.png"]
    assert img["text"] == "look at this shot", img
    assert img["sealed"] is False
    assert img["blob_url"].startswith("/api/blob/"), img
    # File bytes are NOT in the status payload (base64 of the PNG
    # would appear verbatim if they were).
    assert base64.b64encode(png).decode() not in json.dumps(data)
    status, headers, got = dash_fetch(oversight_env, img["blob_url"])
    assert status == 200
    assert got == png
    assert headers.get_content_type() == "image/png"
    assert "inline" in (headers.get("Content-Disposition") or "")
    dat = by_name["payload.bin"]
    assert dat["text"] == "and this data", dat
    status, headers, got = dash_fetch(oversight_env, dat["blob_url"])
    assert status == 200
    assert got == blob_bytes
    assert "attachment" in (headers.get("Content-Disposition") or "")
    # The route is authenticated: no session, no bytes.
    base = f"http://{HOST}:{oversight_env['dash_port']}"
    try:
        urllib.request.urlopen(base + img["blob_url"], timeout=5)
        raise AssertionError("blob route served bytes unauthenticated")
    except urllib.error.HTTPError as e:
        assert e.code == 401


def test_oversight_composition_work_content(oversight_env, state_root):
    """Real chain, work: assign + deliver wraps (kind=content) open
    in BOTH the conversation items and the activity rows, so work
    text is readable in the Work/Activity payloads."""
    async def _t():
        boss = await make(oversight_env, state_root, "cmp-boss")
        hand = await make(oversight_env, state_root, "cmp-hand")
        works = await boss.assign_work(["cmp-hand"], "Composition Title",
                                       "do the exact thing")
        await hand.deliver_work(works[0]["id"], "exact delivery body")
        await boss.close(); await hand.close()
    run(_t())
    data = dash_data(oversight_env)
    assigned = conv_items(data, "work_assigned")
    assert len(assigned) == 1, assigned
    assert assigned[0]["title"] == "Composition Title", assigned[0]
    assert assigned[0]["text"] == "do the exact thing", assigned[0]
    assert assigned[0]["sealed"] is False
    assert "oversight" not in assigned[0]
    delivered = conv_items(data, "work_delivered")
    assert len(delivered) == 1, delivered
    assert delivered[0]["text"] == "exact delivery body", delivered[0]
    assert delivered[0]["sealed"] is False
    act = {r["kind"]: r for r in data["activity"]
           if r["kind"] in ("work_assigned", "work_delivered")}
    assert act["work_assigned"]["title"] == "Composition Title"
    assert act["work_assigned"]["text"] == "do the exact thing"
    assert act["work_delivered"]["text"] == "exact delivery body"
    assert all("oversight" not in r for r in data["activity"])


def test_oversight_composition_sealed_honesty(oversight_env, state_root):
    """Regression for the exact integration-check failure: a group
    item whose content-key wrap survives but whose persisted
    content envelope is missing/corrupt must stay SEALED with no
    text — the unwrapped raw group key must never be rendered as
    (mojibake) text anywhere in the payload."""
    async def _t():
        one = await make(oversight_env, state_root, "cmp-one")
        two = await make(oversight_env, state_root, "cmp-two")
        g = await one.group_create("Honesty Crew", ["cmp-two"])
        gid = g["group_id"]
        await one.group_send(gid, "honesty message one")
        await one.group_send(gid, "honesty message two")
        assert await wait_for(
            lambda: len([m for m in two.messages
                         if m.get("group_id") == gid]) == 2)
        await one.close(); await two.close()
    run(_t())
    store = oversight_env["relay"].store
    okey = oversight_env["okey"]
    with store._lock:
        rows = store._db.execute(
            "SELECT seq, oversight FROM audit_log"
            " WHERE kind='group_message' ORDER BY seq").fetchall()
        assert len(rows) == 2
        raw_key = okey.open_key(json.loads(rows[0][1]))
        assert len(raw_key) == 32
        # Message one: the content envelope never landed (the
        # data-availability half of the original defect).
        store._db.execute(
            "UPDATE audit_log SET content_envelope='' WHERE seq=?",
            (rows[0][0],))
        # Message two: the envelope landed corrupted (AEAD must fail).
        env2 = json.loads(store._db.execute(
            "SELECT content_envelope FROM audit_log WHERE seq=?",
            (rows[1][0],)).fetchone()[0])
        ct = env2["ct"]
        env2["ct"] = ("A" if ct[0] != "A" else "B") + ct[1:]
        store._db.execute(
            "UPDATE audit_log SET content_envelope=? WHERE seq=?",
            (json.dumps(env2), rows[1][0]))
        store._db.commit()
    data = dash_data(oversight_env)
    items = conv_items(data, "group_message")
    assert len(items) == 2, items
    for item in items:
        assert item["sealed"] is True, item
        assert "text" not in item, item
    dump = json.dumps(data, default=str)
    # The raw group key — the exact bytes the old dashboard rendered
    # as mojibake — appears NOWHERE in the payload, in any encoding.
    assert raw_key.decode("utf-8", "replace") not in dump
    assert base64.b64encode(raw_key).decode() not in dump
    assert "honesty message one" not in dump
    assert "honesty message two" not in dump


def test_oversight_absent_degrades_to_sealed(oversight_nowatch_env,
                                             state_root):
    """Real wraps, no dashboard key: items stay honestly sealed —
    no text, no wrap or envelope echoed, oversight_enabled False."""
    async def _t():
        one = await make(oversight_nowatch_env, state_root, "cmp-one")
        two = await make(oversight_nowatch_env, state_root, "cmp-two")
        await one.send_message("cmp-two", "cannot read this")
        g = await one.group_create("Sealed Crew", ["cmp-two"])
        await one.group_send(g["group_id"], "cannot read this either")
        assert await wait_for(lambda: len(two.messages) == 2)
        await one.close(); await two.close()
    run(_t())
    data = dash_data(oversight_nowatch_env)
    assert data["oversight_enabled"] is False
    items = conv_items(data, "message") + conv_items(data, "group_message")
    assert len(items) == 2, items
    for item in items:
        assert "text" not in item, item
        assert item["sealed"] is True, item
        assert "oversight" not in item
        assert "content_envelope" not in item


def test_oversight_open_legacy_shape_unit(monkeypatch, tmp_path):
    """UNIT ONLY — demoted fabricated shape: the pre-composition
    {wrapped_key, nonce, ciphertext} wrap is exercised directly
    against DashboardServer._oversight_open. Production clients
    NEVER emit this shape; the real wire shapes are pinned by the
    composition tests above. This unit also pins the opener's
    kind handling: a content_key wrap without a content envelope
    opens to None — never to the raw key bytes."""
    from agentlink.crypto import (Identity, encrypt_with_key,
                                  new_group_key)
    from agentlink.dashboard import DashboardServer
    ident = Identity("oversight", str(tmp_path / "ov-state"))
    monkeypatch.setenv("AGENTLINK_OVERSIGHT_KEY_FILE", str(ident.path))
    dash = DashboardServer(relay=None, host=HOST, port=0, password="x")
    assert dash._oversight is not None
    pub = ident.public_key_b64
    payload = json.dumps(
        {"body": "legacy unit", "kind": "text", "file": None}).encode()
    ck = new_group_key()
    env = encrypt_with_key(ck, payload)
    legacy = {"wrapped_key": Identity.ephemeral().encrypt_for(pub, ck),
              "nonce": env["nonce"], "ciphertext": env["ct"]}
    assert dash._oversight_open(legacy) == payload
    # Real shape, kind=content_key: opens ONLY via the envelope.
    keywrap = Identity.ephemeral().encrypt_for(pub, ck)
    keywrap["kind"] = "content_key"
    assert dash._oversight_open(keywrap) is None
    assert dash._oversight_open(
        keywrap, {"nonce": env["nonce"], "ct": env["ct"]}) == payload
    # Real shape, kind=content: direct envelope.
    direct = Identity.ephemeral().encrypt_for(pub, payload)
    direct["kind"] = "content"
    assert dash._oversight_open(direct) == payload


# -- conversations: sender identity + group participants ------------------

def test_conversation_items_carry_sender_identity(relay_env, state_root):
    """Item 2c: after a scripted group message, /api/status
    conversations carry the sender's in-group nickname, permission
    role and custom role, and the group conversation lists its
    participants with the same identity fields."""
    async def _t():
        one = await make(relay_env, state_root, "conv-one")
        two = await make(relay_env, state_root, "conv-two")
        g = await one.group_create("Identity", ["conv-two"])
        gid = g["group_id"]
        await one.group_set_nickname(gid, "Boss")
        await one.group_set_custom_role(gid, "conv-one", "Lead")
        await one.group_send(gid, "status update for the board")
        assert await wait_for(lambda: len(two.messages) == 1)
        await one.close(); await two.close()
    run(_t())
    data = dash_data(relay_env)
    convs = [c for c in data["conversations"] if c["group_id"]]
    assert convs, "no group conversation in dashboard data"
    conv = convs[0]
    parts = {p["username"]: p for p in conv["participants"]}
    assert parts["conv-one"]["nickname"] == "Boss"
    assert parts["conv-one"]["role"] == "superadmin"
    assert parts["conv-one"]["custom_role"] == "Lead"
    assert "conv-two" in parts
    items = [i for i in conv["items"] if i["kind"] == "group_message"]
    assert items, "group message item missing"
    item = items[-1]
    assert item["sender_nickname"] == "Boss", item
    assert item["sender_role"] == "superadmin", item
    assert item["sender_custom_role"] == "Lead", item


# -- reachability: home label compares endpoint identity, not --name -----

def test_is_home_endpoint_ignores_server_name(relay_env):
    """Item 2d (unit): a named relay recognises its own public
    endpoint and its bind address as home; foreign endpoints are not
    home; the friendly label is never an endpoint."""
    unit_db = str(Path(tempfile.mkdtemp(prefix="agentlink-v11-unit-"))
                  / "unit.db")
    relay = Relay(host=HOST, port=0, db_path=unit_db,
                  dashboard_enabled=False,
                  server_name="Phoenix Home Relay",
                  public_endpoint="wss://x.novamail.store/ws")
    assert relay.server_label == "Phoenix Home Relay"
    assert relay._is_home_endpoint("wss://x.novamail.store/ws")
    assert relay._is_home_endpoint("wss://x.novamail.store/ws/")
    assert relay._is_home_endpoint(f"ws://{HOST}:{relay.port}")
    assert not relay._is_home_endpoint("wss://other.example/ws")
    assert not relay._is_home_endpoint("Phoenix Home Relay")
    assert not relay._is_home_endpoint("")


def test_named_relay_labels_home_agents_home(state_root):
    """Item 2d (integration): with --name set, an agent homed to THIS
    relay reads 'online (home)' — the v1.0 bug read
    'online (via Phoenix Home Relay)'."""
    tmp = tempfile.mkdtemp(prefix="agentlink-v11-named-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password="pw-named", dashboard_port=0,
                  server_name="Phoenix Home Relay")
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
    env = {"url": f"ws://{HOST}:{relay.port}", "port": relay.port,
           "db": db, "dash_port": relay.dashboard_port, "relay": relay}

    async def _t():
        a = await make(env, state_root, "homer")
        data = relay._dashboard_data()
        row = next(u for u in data["users"]
                   if u["username"] == "homer")
        assert row["online"], row
        assert row["reachability"] == "online (home)", row
        await a.close()
    run(_t())
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


# -- approval gates ---------------------------------------------------------

def test_approval_gate_happy_path(relay_env, state_root):
    """Item 3: gated delivery parks in awaiting_approval; only the
    assigner's approve completes it; audit records gate set,
    delivered-awaiting, approved; trust: +1 on proven delivery,
    +4 on final completion."""
    async def _t():
        boss = await make(relay_env, state_root, "gate-boss")
        hand = await make(relay_env, state_root, "gate-hand")
        store = relay_env["relay"].store
        assert store.compute_trust("gate-hand") == 50
        work = (await boss.assign_work(
            ["gate-hand"], "Gated task", "do the thing",
            require_approval=True))[0]
        assert work["require_approval"] is True
        assert work["status"] == "assigned"
        delivered = await hand.deliver_work(work["id"], "done")
        assert delivered["status"] == "awaiting_approval", delivered
        # proven delivery still earns its +1 while parked
        assert store.compute_trust("gate-hand") == 51
        # the assignee cannot decide their own gate
        with pytest.raises(RequestFailed):
            await hand.approve_work(work["id"])
        approved = await boss.approve_work(work["id"], "looks right")
        assert approved["status"] == "completed"
        assert store.compute_trust("gate-hand") == 54
        kinds = [r["kind"] for r in store.list_audit(200)]
        for kind in ("approval_gate_set", "work_awaiting_approval",
                     "work_approved", "work_completed"):
            assert kind in kinds, kind
        await boss.close(); await hand.close()
    run(_t())


def test_approval_gate_reject_and_redeliver(relay_env, state_root):
    """Item 3: reject returns the work to changes_requested with the
    reason reaching the assignee; trust keeps the +1 delivery point
    but takes the -6 changes-requested hit; a re-delivery parks
    again and a later approve completes."""
    async def _t():
        boss = await make(relay_env, state_root, "rej-boss")
        hand = await make(relay_env, state_root, "rej-hand")
        store = relay_env["relay"].store
        work = (await boss.assign_work(
            ["rej-hand"], "Gated", "v1 please",
            require_approval=True))[0]
        await hand.deliver_work(work["id"], "v1")
        rejected = await boss.reject_work(work["id"], "needs more detail")
        assert rejected["status"] == "changes_requested"
        # state-based formula: the delivery +1 is surrendered when the
        # work leaves the delivered state; the round scores -6.
        assert store.compute_trust("rej-hand") == 50 - 6
        kinds = [r["kind"] for r in store.list_audit(200)]
        assert "work_approval_rejected" in kinds
        assert "work_changes_requested" in kinds
        again = await hand.deliver_work(work["id"], "v2 with detail")
        assert again["status"] == "awaiting_approval"
        done = await boss.approve_work(work["id"])
        assert done["status"] == "completed"
        await boss.close(); await hand.close()
    run(_t())


def test_approval_gate_blocks_chain_until_approved(relay_env, state_root):
    """Item 3: a gated chain step does NOT release the next step on
    delivery — only on approval."""
    async def _t():
        boss = await make(relay_env, state_root, "chain-boss")
        first = await make(relay_env, state_root, "chain-first")
        second = await make(relay_env, state_root, "chain-second")
        chain = await boss.create_chain([
            {"to": "chain-first", "title": "Step one",
             "require_approval": True},
            {"to": "chain-second", "title": "Step two"}],
            name="gated chain")
        inbox1 = await first.work_inbox()
        assert len(inbox1) == 1
        wid = inbox1[0]["id"]
        parked = await first.deliver_work(wid, "step one output")
        assert parked["status"] == "awaiting_approval"
        # next step must NOT have been released by the delivery alone
        assert await second.work_inbox() == []
        await boss.approve_work(wid)
        inbox2 = await second.work_inbox()
        assert len(inbox2) == 1, inbox2
        assert inbox2[0]["title"] == "Step two"
        await boss.close(); await first.close(); await second.close()
    run(_t())


def test_approval_gate_group_admin_may_decide(relay_env, state_root):
    """Item 3: for group work, a group admin (not the assigner) may
    decide; a plain member may not."""
    async def _t():
        boss = await make(relay_env, state_root, "grp-boss")
        admin = await make(relay_env, state_root, "grp-admin")
        hand = await make(relay_env, state_root, "grp-hand")
        g = await boss.group_create(
            "GateGroup", ["grp-admin", "grp-hand"])
        gid = g["group_id"]
        await boss.group_promote(gid, "grp-admin")
        work = (await boss.assign_work(
            ["grp-hand"], "Group gated", "group task", group_id=gid,
            require_approval=True))[0]
        await hand.deliver_work(work["id"], "done")
        with pytest.raises(RequestFailed):
            await hand.approve_work(work["id"])
        decided = await admin.approve_work(work["id"], "admin ok")
        assert decided["status"] == "completed"
        await boss.close(); await admin.close(); await hand.close()
    run(_t())


def test_gate_off_behaves_like_v1(relay_env, state_root):
    """Item 3: without require_approval the lifecycle is unchanged —
    delivery lands in 'delivered', complete works, and approve/reject
    actions on a non-gated work are refused."""
    async def _t():
        boss = await make(relay_env, state_root, "plain-boss")
        hand = await make(relay_env, state_root, "plain-hand")
        work = (await boss.assign_work(
            ["plain-hand"], "Plain task", "no gate"))[0]
        assert work["require_approval"] is False
        delivered = await hand.deliver_work(work["id"], "done")
        assert delivered["status"] == "delivered"
        with pytest.raises(RequestFailed):
            await boss.approve_work(work["id"])
        done = await boss.complete_work(work["id"])
        assert done["status"] == "completed"
        store = relay_env["relay"].store
        kinds = [r["kind"] for r in store.list_audit(200)]
        assert "approval_gate_set" not in kinds
        assert "work_awaiting_approval" not in kinds
        await boss.close(); await hand.close()
    run(_t())


# -- backend env (item 4a) ---------------------------------------------------

def _relay_subprocess(env_extra):
    import subprocess
    import sys
    env = dict(os.environ)
    env.pop("AGENTLINK_BACKEND", None)
    env.pop("SUPABASE_URL", None)
    env.pop("SUPABASE_SERVICE_KEY", None)
    env.update(env_extra)
    return subprocess.run(
        [sys.executable, "-m", "agentlink.relay",
         "--host", "127.0.0.1", "--port", "0", "--dashboard-port", "0",
         "--db", str(Path(tempfile.mkdtemp()) / "r.db")],
        capture_output=True, text=True, env=env, timeout=30,
        cwd=str(Path(__file__).resolve().parent.parent))


def test_backend_env_honored_without_flag():
    """Item 4a: AGENTLINK_BACKEND alone selects the backend — a bogus
    value dies in create_store with 'unknown backend', proving main()
    read the environment (v1.0 ignored it without --backend)."""
    proc = _relay_subprocess({"AGENTLINK_BACKEND": "bogus"})
    assert proc.returncode != 0
    assert "unknown backend" in proc.stderr, proc.stderr[-500:]


def test_backend_env_supabase_needs_keys():
    """Item 4a: AGENTLINK_BACKEND=supabase without keys fails closed
    with the store's own configuration error."""
    proc = _relay_subprocess({"AGENTLINK_BACKEND": "supabase"})
    assert proc.returncode != 0
    assert "SUPABASE_URL" in proc.stderr, proc.stderr[-500:]


# -- canonical schema alignment (item 4b) -------------------------------------

def test_store_schema_is_canonical(relay_env):
    """Item 4b: a fresh SQLite store has the Supabase-canonical
    invites (token/created_at) and upload_sessions (no for_channel)
    shapes, plus the v1.1 audit/work/chain columns."""
    import sqlite3
    db = sqlite3.connect(relay_env["db"])
    cols = {r[1] for r in db.execute("PRAGMA table_info(invites)")}
    assert cols == {"token", "group_id", "created_by", "created_at"}, cols
    cols = {r[1] for r in
            db.execute("PRAGMA table_info(upload_sessions)")}
    assert "for_channel" not in cols
    assert {"session_id", "owner", "for_user", "for_group"} <= cols
    cols = {r[1] for r in db.execute("PRAGMA table_info(audit_log)")}
    assert {"sender_nickname", "sender_role",
            "sender_custom_role"} <= cols
    cols = {r[1] for r in db.execute("PRAGMA table_info(work)")}
    assert "require_approval" in cols
    cols = {r[1] for r in db.execute("PRAGMA table_info(chain_steps)")}
    assert "require_approval" in cols
    db.close()


def test_invite_roundtrip_and_expiry(relay_env):
    """Item 4b: invites validate by hash-at-rest token and expire on
    the canonical created_at + TTL rule."""
    from agentlink.store import INVITE_TTL_SECONDS
    store = relay_env["relay"].store
    token = store.create_invite("g-x", "someone")
    assert store.invite_valid("g-x", token)
    assert not store.invite_valid("g-x", token + "x")
    assert not store.invite_valid("g-y", token)
    with store._lock:
        store._db.execute(
            "UPDATE invites SET created_at = created_at - ?",
            (INVITE_TTL_SECONDS + 60,))
        store._db.commit()
    assert not store.invite_valid("g-x", token)


def test_upload_session_shape_and_finish_scope(relay_env, state_root):
    """Item 4b: sessions round-trip without a persisted channel
    column; a channel-scoped chunked upload still lands its blob
    scope from the finish frame (client carries it)."""
    async def _t():
        a = await make(relay_env, state_root, "up-scope")
        b = await make(relay_env, state_root, "down-scope")
        chan = await a.channel_create("Scoped", ["down-scope"])
        cid = chan["channel_id"]
        sess = relay_env["relay"].store.get_upload_session(
            (await a.start_upload_session(
                b"x" * 10, for_channel=cid))[0])
        assert sess is not None and sess["for_channel"] == ""
        data = os.urandom(1_500_000)
        blob_id = await a.upload_blob(data, for_channel=cid)
        got = await b._request({"type": "blob_get", "blob_id": blob_id})
        assert base64.b64decode(got["data_b64"]) == data
        await a.close(); await b.close()
    run(_t())
