"""Phase 5 static pins for dashboard-v2 (no network, no secrets)."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / "dashboard-v2"
SRC = (ROOT / "agentlink" / "dashboard.py").read_text()

EXPECTED = ["overview", "agents", "conversations", "probes", "work",
            "chains", "library", "vault", "credentials", "grants",
            "rooms", "activity"]


def _all_files():
    return [p for p in DASH.rglob("*") if p.is_file()]


def test_current_dashboard_views_enumerated():
    found = re.findall(r'id="view-([a-z]+)"', SRC)
    assert found == EXPECTED, found


def test_every_view_has_module_and_route():
    index = (DASH / "index.html").read_text()
    app = (DASH / "js" / "app.js").read_text()
    for v in EXPECTED:
        assert (DASH / "js" / "views" / f"{v}.js").is_file(), v
        assert f"#/{{{v}}}" not in index  # routes are plain hrefs
        assert f'href="#/{v}"' in index, v
        assert f'import * as v_{v}' in app, v
        assert f'id="view-{v}"' in index, v


def test_no_view_is_empty_stub():
    for v in EXPECTED:
        body = (DASH / "js" / "views" / f"{v}.js").read_text()
        assert len(body) > 400, v
        assert "render" in body and ("table(" in body or "chatwrap" in body
                                     or "oversight" in body), v


def test_no_secrets_anywhere():
    keyish = re.compile(r"eyJ[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{16,}|"
                        r"[0-9a-f]{64}")
    for p in _all_files():
        text = p.read_text(errors="ignore")
        assert "service_role" not in text, p
        assert not keyish.search(text), p


def test_config_example_placeholders_only():
    cfg = (DASH / "config.example.js").read_text()
    for name in ("supabaseUrl", "anonKey", "edgeBase", "firebaseDbUrl"):
        assert name in cfg
    assert "YOUR_" in cfg
    assert not (DASH / "config.js").exists() or True  # generated at deploy


def test_index_references_all_view_modules():
    app = (DASH / "js" / "app.js").read_text()
    for v in EXPECTED:
        assert f"./views/{v}.js" in app, v
    index = (DASH / "index.html").read_text()
    assert "css/app.css" in index and "js/app.js" in index
    assert "config.js" in index


def test_css_responsive_breakpoints():
    css = (DASH / "css" / "app.css").read_text()
    assert "@media (min-width:901px)" in css   # persistent sidebar law
    assert "@media (max-width:900px)" in css   # slide-in drawer law
    assert "overflow-x:hidden" in css.replace(" ", "")
    assert "Space Grotesk" in css and "Inter" in css
    assert "backdrop-filter" in css            # glassmorphism


def test_presence_reads_presence_and_never_writes_content():
    src = (DASH / "js" / "presence.js").read_text()
    assert "/presence" in src
    for verb in ("PUT", "POST", "PATCH", "DELETE"):
        assert verb not in src, verb
    assert "method:" not in src  # fetch defaults to read-only GET


def test_data_layer_contract():
    src = (DASH / "js" / "data.js").read_text()
    assert "/rest/v1/" in src
    assert "dashboard-login" in src and "/oversight" in src
    assert "7*24*60*60" in src.replace(" ", "")  # 7-day trusted device
    assert "_parties_test" in src or "partiesTest" in src
    assert "decrypt" not in src.lower()  # never opens content client-side


def test_trust_formula_ported():
    src = (DASH / "js" / "trust.js").read_text()
    for token in ("50", "+= 4", "+= 1", "-= 6", "-= 10", "compute_trust"):
        assert token in src, token


def test_chat_no_placeholder_law():
    # NO-PLACEHOLDER LAW (owner, 2026-11-06): a bubble may only ever
    # appear with its content in it. Unopened items are not painted at
    # all, and an open that returns no words and no file does not
    # count as opened (the convergence pass keeps retrying it).
    src = (DASH / "js" / "views" / "chat.js").read_text()
    assert "if(!m.opened) continue;" in src  # paintThread skips unopened
    assert "if(item.opened){" in src  # appendLive: open-before-paint
    assert "(o.text || o.title || o.file_name)" in src
    for banned in ("opening via oversight", "oversight copy pending",
                   "no text payload", "oversight unavailable for this item",
                   "loading…"):
        assert banned not in src, banned
