"""v242 static + behavioural pins: dashboard real-time truth.

Owner order 2026-11-10 (09:20 PST) after his screenshot showed
@phoenix "offline / 2.2.3 / latest" while the live RTDB presence
node said online / 2.4.1 / beat 32s old. Root causes (evidence:
drill-evidence/v242/ROOT-CAUSE.md, probe 2026-11-10 ~13:56 PST):

  RC1  al_activeness.client_version can never be current: the
       v211 login trigger writes '' on insert and never updates
       it, so versionOf()'s mirror fallback served the frozen
       pre-2.3.0 mirror write ("2.2.3"). The fallback is REMOVED:
       the presence node is the only version source; no node
       reads "not reported", never a stale value.
  RC2  streamPresence had no deterministic snapshot (fetchPresence
       had zero callers) and its "put" handler bypassed the merge,
       REPLACING user nodes from raw event data — a subtree put
       or a missed initial put left the stale DB floor in charge.
       Now: one snapshot seed per (re)connect + every event
       merges through mergePresencePatch into one map; and app.js
       softReload re-applies that map onto swapped datasets.
  RC3  "latest" was max(version reported by the fleet) — a stale
       fleet crowned its own staleness. Now the published
       update-manifest, fetched at runtime (config manifestUrl).
  RC4  The "N feeds pending migration" pill keyed on
       subscribed-but-quiet feeds; publication membership is
       complete server-side, so it could never clear. The pill
       now reserves "pending" for unlanded subscriptions and
       calls silent feeds "quiet".

Stdlib only; behavioural checks execute the real JS under node
when available (same pattern as test_v200_dashboard_activeness).
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / "dashboard-v2"
PRESENCE = DASH / "js" / "presence.js"
AGENTS = DASH / "js" / "views" / "agents.js"
DATA = DASH / "js" / "data.js"
APP = DASH / "js" / "app.js"
REALTIME = DASH / "js" / "realtime.js"


def _flat(p):
    return re.sub(r"\s+", " ", p.read_text())


# --- RC1: the mirror is never a version source -------------------------

def test_versionof_reads_presence_node_only():
    src = AGENTS.read_text()
    body = src[src.index("function versionOf"):]
    body = body[:body.index("}")]
    assert "r.presence" in body and "client_version" in body
    assert "activenessMirror" not in body, \
        "v242: the login-record mirror must never supply a version"


def test_no_mirror_version_anywhere_in_views():
    for p in (DASH / "js" / "views").glob("*.js"):
        assert "activenessMirror &&" not in p.read_text() or \
            "client_version" not in p.read_text(), p


# --- RC2: one merge path + deterministic seed + swap re-apply ----------

def test_stream_seeds_from_snapshot_and_merges_every_event():
    flat = _flat(PRESENCE)
    # the snapshot helper finally has a caller, inside the stream
    stream = flat[flat.index("export function streamPresence"):]
    assert "fetchPresence()" in stream
    # both event kinds route through the single deliver() merge
    assert stream.count("deliver(") >= 3  # seed + put + patch
    assert "mergePresencePatch(lastPresence, path, data)" in stream
    # the raw-overwrite put handler is gone for good
    assert "onUpdate(JSON.parse(e.data).data" not in flat


def test_current_presence_exported_and_reapplied_on_softreload():
    assert "export function currentPresence()" in PRESENCE.read_text()
    flat = _flat(APP)
    assert "currentPresence" in flat
    assert "applyPresence(d, currentPresence())" in flat


def test_apply_presence_stamps_live_last_seen():
    flat = _flat(PRESENCE)
    assert "u.last_seen_display" in flat
    assert "beatTimestampSeconds(p, now)" in flat


def _run_node(script):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for behavioural check")
    proc = subprocess.run([node, "--input-type=module", "-e", script],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_merge_and_apply_behaviour_live_wins():
    """Execute the real presence.js: a subtree put must not evict
    another user's node, and applyPresence must surface the LIVE
    version/state/last-seen over a contradictory stale mirror."""
    pres = json.dumps(str(PRESENCE))
    script = (
        f"import {{mergePresencePatch, applyPresence}} from {pres};"
        "const now = 1794347695;"
        "let m = {};"
        # snapshot put at "/" (both agents, live truth)
        "m = mergePresencePatch(m, '/', {"
        "  phoenix: {client_version:'2.4.1', state:'online', ts:(now-32)*1000},"
        "  'swift-otter-7': {client_version:'2.4.1', state:'online', ts:(now-162)*1000},"
        "  'vertex-bcf0d5fb': {client_version:'2.2.2', state:'online', ts:1794130766368}});"
        # subtree put for ONE user only (the pre-v242 poison shape)
        "m = mergePresencePatch(m, '/swift-otter-7', {ts:(now-5)*1000});"
        "const data = {users:["
        "  {username:'phoenix', last_seen:1794343298,"
        "   activenessMirror:{client_version:'2.2.3', state:'online', updated_at:1794343298}},"
        "  {username:'swift-otter-7', last_seen:1794347598,"
        "   activenessMirror:{client_version:'2.2.3', state:'online', updated_at:1794347598}},"
        "  {username:'vertex-bcf0d5fb', last_seen:1794130767,"
        "   activenessMirror:{client_version:'2.2.2', state:'offline', updated_at:1794130980}},"
        "  {username:'ghost', last_seen:1794340000,"
        "   activenessMirror:{client_version:'', state:'online', updated_at:1794340000}}"
        "], testUsers:[]};"
        "applyPresence(data, m, now);"
        "const by = {}; for(const u of data.users) by[u.username] ="
        " {v:u.presence && u.presence.client_version, act:u.activeness,"
        "  age:u.beat_age_s, seen:u.last_seen_display};"
        "console.log(JSON.stringify(by));"
    )
    by = _run_node(script)
    # phoenix survived swift's subtree put, live values win
    assert by["phoenix"] == {"v": "2.4.1", "act": "online",
                             "age": 32, "seen": 1794347663}
    # swift's beat advanced via the subtree put; version intact
    assert by["swift-otter-7"]["v"] == "2.4.1"
    assert by["swift-otter-7"]["age"] == 5
    assert by["swift-otter-7"]["act"] == "online"
    # vertex: node present but ancient -> offline BY THE LADDER,
    # version still the node's own (truthfully old, not hidden)
    assert by["vertex-bcf0d5fb"]["v"] == "2.2.2"
    assert by["vertex-bcf0d5fb"]["act"] == "offline"
    # ghost: no node -> no live fields at all; display falls back
    # to the registry last_seen (its last login), state offline
    assert by["ghost"]["v"] is None
    assert by["ghost"]["seen"] == 1794340000


# --- RC3: latest comes from the manifest -------------------------------

def test_latest_is_manifest_not_fleet_max():
    src = AGENTS.read_text()
    assert "reported.slice().sort(vcmp)" not in src, \
        "fleet-derived latest must stay gone"
    assert "manifestLatest" in src and "fetchManifestVersion" in src
    flat = _flat(DATA)
    assert "export async function fetchManifestVersion()" in flat
    assert "CFG().manifestUrl" in flat
    # honest fallback: unreadable manifest -> "" -> no latest tag
    body = src[src.index("function versionCell"):]
    assert 'if(!latest) return "<b>" + esc(v) + "</b>";' in \
        re.sub(r"\s+", " ", body[:600])


def test_config_example_documents_manifest_url():
    assert "manifestUrl" in (DASH / "config.example.js").read_text()


# --- RC4: the pill tells the literal truth -----------------------------

def test_no_pending_migration_wording_anywhere():
    # the rendered pill claim (a quoted UI string) must be gone;
    # historical prose in comments may still name the old bug
    for p in list(DASH.rglob("*.js")) + list(DASH.rglob("*.html")):
        assert "feeds pending migration" not in p.read_text(), p
        assert '" · " + pending.length' not in p.read_text() or \
            "pending migration" not in p.read_text(), p


def test_pill_distinguishes_pending_from_quiet():
    flat = _flat(APP)
    assert "feeds pending subscription" in flat
    assert "feeds quiet" in flat
    rt = _flat(REALTIME)
    assert "unconfirmed" in rt and "pending" in rt


# --- quota discipline: no new polling ----------------------------------

def test_presence_snapshot_is_connect_time_only():
    flat = _flat(PRESENCE)
    tick = flat[flat.index("export function startActivenessTick"):]
    for forbidden in ("fetchPresence", "fetch(", "EventSource"):
        assert forbidden not in tick, forbidden
    # the snapshot fetch lives in streamPresence's connect path
    stream = flat[flat.index("export function streamPresence"):]
    assert stream.index("fetchPresence()") < stream.index("new EventSource")
