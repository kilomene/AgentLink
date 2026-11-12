"""Phase 5b static pins: dashboard activeness staleness ladder.

Owner ruling 2026-11-05 set the original hyper-sensitive law
(beats every 5s, online 10, suspect 15). 2.3.0 SUPERSEDES it
(owner-ratified 2026-11-09): presence is connection-based and
the beat is only the unclean-death detector, so the ladder
stretches to beats every 180s, ONLINE_MAX_AGE_S = 240,
SUSPECT_MAX_AGE_S = 420, and onDisconnect => offline instantly.
Dashboard ladder must equal the client ladder
(agentlink/doorbell.py: same numbers, same names).

Stdlib only. The ladder logic is pinned structurally (thresholds
extracted and the three branches asserted with their comparisons)
and, when node is available, behaviourally by executing the real
js/activeness.js at the 240/241/420/421 boundaries.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / "dashboard-v2"
ACT = DASH / "js" / "activeness.js"
PRESENCE = DASH / "js" / "presence.js"


def _const(src, name):
    m = re.search(rf"export const {name} = (\d+);", src)
    assert m, f"{name} not exported as an integer constant"
    return int(m.group(1))


@pytest.fixture(scope="module")
def act():
    return ACT.read_text()


# --- 1. ladder constants: 180 / 240 / 420 ------------------------------

def test_ladder_constants_connection_based(act):
    assert _const(act, "BEAT_INTERVAL_S") == 180
    assert _const(act, "ONLINE_MAX_AGE_S") == 240
    assert _const(act, "SUSPECT_MAX_AGE_S") == 420


def test_ladder_constants_are_ordered_with_grace(act):
    beat = _const(act, "BEAT_INTERVAL_S")
    online = _const(act, "ONLINE_MAX_AGE_S")
    suspect = _const(act, "SUSPECT_MAX_AGE_S")
    # 2.3.0: one beat of grace past the interval reads online;
    # a second missed beat lands suspect; beyond that, offline.
    assert beat < online < suspect
    assert online - beat == 60
    assert suspect - online == beat


def test_activeness_mirrors_doorbell_comment(act):
    assert "agentlink/doorbell.py" in act
    flat = re.sub(r"\s+", " ", act)
    assert "same numbers, same names" in flat
    assert "mirror agentlink/doorbell.py exactly" in flat
    for name in ("BEAT_INTERVAL_S", "ONLINE_MAX_AGE_S",
                 "SUSPECT_MAX_AGE_S"):
        assert name in act


# --- 2. branch structure + boundaries ---------------------------------

def test_three_branches_with_correct_comparisons(act):
    flat = re.sub(r"\s+", " ", act)
    assert 'if(age <= ONLINE_MAX_AGE_S) return "online";' in flat
    assert 'if(age <= SUSPECT_MAX_AGE_S) return "suspect";' in flat
    assert 'return "offline";' in flat
    # online branch is evaluated before the suspect branch
    assert flat.index("ONLINE_MAX_AGE_S) return") < \
        flat.index("SUSPECT_MAX_AGE_S) return")


def test_missing_and_disconnect_are_offline_before_age(act):
    flat = re.sub(r"\s+", " ", act)
    assert 'if(!presenceNode' in flat and 'return "offline"' in flat
    for token in ("disconnected", '"offline"', '"disconnected"'):
        assert token in act, token
    # disconnect handling precedes the age comparisons (instant) —
    # scoped to the activenessState function body, not the header
    body = flat[flat.index("export function activenessState"):]
    assert body.index("DISCONNECT_STATES.has") < \
        body.index("age <= ONLINE_MAX_AGE_S")


def _ladder(age, beat, online_max, suspect_max):
    if age <= online_max:
        return "online"
    if age <= suspect_max:
        return "suspect"
    return "offline"


def test_boundaries_from_extracted_thresholds(act):
    beat = _const(act, "BEAT_INTERVAL_S")
    online = _const(act, "ONLINE_MAX_AGE_S")
    suspect = _const(act, "SUSPECT_MAX_AGE_S")
    expected = {0: "online", 100: "online", 240: "online",
                241: "suspect", 420: "suspect",
                421: "offline", 900: "offline"}
    for age, want in expected.items():
        got = _ladder(age, beat, online, suspect)
        assert got == want, f"age {age}: {got} != {want}"


def test_activeness_js_executed_at_boundaries(act):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for behavioural check")
    script = (
        "import {activenessState} from "
        f"{json.dumps(str(ACT))};"
        "const now=1000000;"
        "const byAge=a=>({beat_at:(now-a)*1000, state:'online'});"
        "const out={};"
        "for(const a of [0,240,241,420,421,900]) out[a]=activenessState(byAge(a),now);"
        "out.missing=activenessState(null,now);"
        "out.empty=activenessState({},now);"
        "out.disconnect=activenessState({beat_at:now*1000,state:'offline'},now);"
        "out.discflag=activenessState({beat_at:now*1000,state:'online',"
        "disconnected:true},now);"
        "console.log(JSON.stringify(out));"
    )
    proc = subprocess.run([node, "--input-type=module", "-e", script],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    out = json.loads(proc.stdout.strip().splitlines()[-1])
    assert out == {"0": "online", "240": "online", "241": "suspect",
                   "420": "suspect", "421": "offline", "900": "offline",
                   "missing": "offline", "empty": "offline",
                   "disconnect": "offline", "discflag": "offline"}


def test_activeness_label_names_suspect_staleness(act):
    assert "suspect — no heartbeat for" in act
    assert "activenessLabel" in act and "activenessState" in act


# --- 3. presence.js rewiring ------------------------------------------

@pytest.fixture(scope="module")
def presence():
    return PRESENCE.read_text()


def test_presence_delegates_to_activeness(presence):
    assert 'from "./activeness.js"' in presence
    assert "activenessState(" in presence and "beatAgeSeconds(" in presence
    # per-user ladder state + beat age are exposed, not just a boolean
    assert "u.activeness" in presence and "u.beat_age_s" in presence
    assert 'u.online = u.activeness === "online"' in presence
    for name in ("online", "suspect", "offline"):
        assert f'u.activeness==="{name}"' in presence or \
            f'data.{name}' in presence, name
    # the old binary 15s check is gone
    assert "now-(p.ts||0)" not in presence.replace(" ", "")


def _tick_body(presence):
    start = presence.index("export function startActivenessTick")
    return presence[start:]


def test_ui_tick_recomputes_without_network(presence):
    assert _const_tick(presence) == 5000
    body = _tick_body(presence)
    assert "setInterval" in body and "applyPresence" in body
    # the tick creates NO new network traffic of any kind
    for forbidden in ("fetch", "EventSource", "fetchPresence",
                      "streamPresence", "XMLHttpRequest"):
        assert forbidden not in body, forbidden
    flat = re.sub(r"\s+", " ", presence)
    assert "tick only recomputes" in flat
    assert "NO new network traffic" in flat


def _const_tick(presence):
    m = re.search(r"export const UI_TICK_MS = (\d+);", presence)
    assert m, "UI_TICK_MS not exported"
    return int(m.group(1))


def test_app_wires_the_ui_tick():
    app = (DASH / "js" / "app.js").read_text()
    assert "startActivenessTick" in app
    assert "data-activeness-user" in app or "paintActiveness" in app


# --- 4. views + css -----------------------------------------------------

def _view(name):
    return (DASH / "js" / "views" / f"{name}.js").read_text()


def test_agents_view_three_states_and_beat_age():
    src = _view("agents")
    for state in ("online", "suspect", "offline"):
        assert f'"{state}"' in src or f"{state}:" in src or \
            f"activeness-{state}" in src, state
    assert "activeness-" in src            # per-state badge classes
    assert "Beat age" in src               # beat-age column shown
    assert "beat_age_s" in src and "data-beat-age-user" in src
    # 2.5.0 SUPERSEDES the activenessLabel pin (owner's Life
    # Signs brief, item 6): the roster's liveness surface is the
    # computed GRADE + last proof, judged by the agent's own
    # declared nature — the bare online light is gone from the
    # primary column (the beat-age column above remains).
    assert "lifeSignCell" in src
    assert 'data-label="Life sign"' in src
    for grade in ("BEATING", "RESTING", "SUSPECT", "DARK"):
        assert grade in src, grade
    assert "last_proof_tier" in src        # proof tier shown
    assert "judged by nature v" in src     # judged-by stated
    assert "unproven" in src               # no grade = unproven
    assert "activenessLabel" not in src    # dead code swept


def test_overview_view_three_states():
    src = _view("overview")
    for state in ("online", "suspect", "offline"):
        assert state in src, state
    assert "activeness-" in src
    assert "suspect" in src and "counts" in src


def test_css_defines_three_distinct_state_classes():
    css = (DASH / "css" / "app.css").read_text()
    blocks = {}
    for state in ("online", "suspect", "offline"):
        m = re.search(rf"\.activeness-{state}\{{([^}}]*)\}}", css)
        assert m, f".activeness-{state} missing"
        blocks[state] = m.group(1)
    # visually distinct: the three rule bodies are not identical
    assert len(set(blocks.values())) == 3, blocks
    assert ".activeness{" in css.replace(" ", "") or ".activeness {" in css
    assert "overflow-x:hidden" in css.replace(" ", "")  # no h-overflow


def test_readme_records_permanent_pages_home():
    readme = (DASH / "README.md").read_text()
    assert "x.novamail.store" in readme
    assert "PERMANENT" in readme
    assert "stands down" in readme  # VM-served dashboard cutover


# --- 5. no privileged key anywhere (re-pin) ----------------------------

def test_no_service_role_anywhere():
    for p in DASH.rglob("*"):
        if p.is_file():
            assert "service_role" not in \
                p.read_text(errors="ignore"), p
