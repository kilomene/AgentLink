"""v261 Fix 1 pins: dashboard duplicate-message dedupe.

Root cause (verified, drill-evidence/v261/SPEC.md): al_audit_log
seq/ts are int64. PostgREST returns them as JSON numbers;
Supabase Realtime delivers them as strings. store.js dedupe
guards used strict identity (seenAuditSeq Set.has, and the
conversation item check m.ts === item.ts), so a Realtime copy
of an already-loaded row defeated both guards and appended a
duplicate conversation item on every resubscribe/redelivery.

Fix: Number coercion at every boundary (data.js itemOf and
loadAudit, store.js applyAudit BEFORE any guard, realtime.js
onEvent for al_audit_log seq/ts and al_queue seq), and
conversation item dedupe by item id ALONE (ref_id is the
globally unique message id).

Stdlib only; behavioural checks execute the real JS under node
when available (same pattern as test_v242_dashboard_realtime_truth).
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / "dashboard-v2"
DATA = DASH / "js" / "data.js"
STORE = DASH / "js" / "store.js"
REALTIME = DASH / "js" / "realtime.js"

MSG_ID = "53d8c653ce1344f8a708e81909f1601f"
SEQ = 14286
TS = 1794347695


def _flat(p):
    return re.sub(r"\s+", " ", p.read_text())


# --- static pins: data.js ---------------------------------------------

def test_itemof_coerces_seq_and_ts_to_number():
    src = DATA.read_text()
    body = src[src.index("export function itemOf"):]
    body = body[:body.index("\n}")]
    assert "seq: Number(r.seq" in body, "itemOf must coerce seq to Number"
    assert "ts: Number(r.ts" in body, "itemOf must coerce ts to Number"


def test_loadaudit_normalizes_both_load_shapes():
    flat = _flat(DATA)
    # a single normalizer coerces both fields
    assert "r.seq = Number(r.seq)" in flat
    assert "r.ts = Number(r.ts)" in flat
    # ...and it is applied on the initial full load AND the
    # seq-delta merge (two map sites in loadAudit)
    body = flat[flat.index("export async function loadAudit()"):]
    body = body[:body.index("export async function oversightOpen")]
    assert body.count("normalizeAuditRow") >= 2, body
    assert body.count(".map(normalizeAuditRow)") == 2, body


# --- static pins: store.js --------------------------------------------

def test_applyaudit_normalizes_before_any_guard():
    flat = _flat(STORE)
    body = flat[flat.index("applyAudit(r){"):]
    body = body[:body.index("applyQueue(r){")]
    norm_seq = body.index("r.seq = Number(r.seq)")
    norm_ts = body.index("r.ts = Number(r.ts)")
    guard = body.index("this.seenAuditSeq.has(r.seq)")
    assert norm_seq < guard and norm_ts < guard, \
        "applyAudit must normalize seq/ts BEFORE the seenAuditSeq guard"


def test_conversation_dedupe_by_item_id_alone():
    src = STORE.read_text()
    assert "conv.items.some(m => m.id === item.id)" in src
    assert "m.id === item.id && m.ts === item.ts" not in src, \
        "the ts conjunction must stay gone: ref_id alone is the identity"


# --- static pins: realtime.js -----------------------------------------

def test_realtime_boundary_coerces_scoped_int64_fields():
    flat = _flat(REALTIME)
    assert 'al_audit_log: ["seq", "ts"]' in flat
    assert 'al_queue: ["seq"]' in flat
    assert "row[f] = Number(row[f])" in flat
    # the coercion is applied at the onEvent boundary
    assert "row: coerceInt64Identity(table, payload.new || {})" in flat
    # and the reason is commented at the helper
    assert "Realtime delivers int64" in REALTIME.read_text()


# --- behavioural: the real modules under node --------------------------

def _run_node(script):
    node = shutil.which("node")
    if not node:
        pytest.skip("node not available for behavioural check")
    proc = subprocess.run([node, "--input-type=module", "-e", script],
                          capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_same_row_number_and_string_shapes_dedupe_to_one():
    """Load the REAL data.js/store.js: feed the same audit row
    once in PostgREST number shape and twice in Realtime string
    shape; exactly ONE conversation item and ONE auditAsc entry
    may result. Also prove loadAudit normalizes string-shaped
    rows from the wire and itemOf coerces both fields."""
    data_url = json.dumps(DATA.as_uri())
    store_url = json.dumps(STORE.as_uri())
    script = (
        # minimal browser shims the real modules touch at call time
        "const _ls = new Map();"
        "globalThis.localStorage = {"
        "  getItem: k => (_ls.has(k) ? _ls.get(k) : null),"
        "  setItem: (k, v) => _ls.set(k, String(v)),"
        "  removeItem: k => _ls.delete(k) };"
        "globalThis.window = { AGENTLINK_CONFIG: {"
        "  supabaseUrl: 'https://example.test', anonKey: 'anon',"
        "  edgeBase: 'https://example.test' } };"
        "_ls.set('agentlink_dash_token', 'tok');"
        "_ls.set('agentlink_dash_expires', String(Math.floor(Date.now()/1000) + 3600));"
        "_ls.set('agentlink_dash_jwt', '');"
        # fetch stub: PostgREST-shaped endpoint; the wire rows are
        # STRING-shaped here to prove loadAudit normalizes them;
        # the seq-delta query returns nothing new.
        "globalThis.fetch = async (url) => ({ ok: true, status: 200,"
        "  json: async () => (String(url).includes('seq=gt.') ? [] : [{"
        f"    seq: '{SEQ}', ts: '{TS}', kind: 'message', actor: 'pres',"
        "    target: 'phoenix', group_id: '', ref_id: '" + MSG_ID + "',"
        "    status: '', size: 0, mentions: [], work_id: '' }]) });"
        f"const data = await import({data_url});"
        f"const {{ store }} = await import({store_url});"
        # loadAudit: string wire shape -> Number cache shape
        "const audit = await data.loadAudit();"
        "const loaded = { seqType: typeof audit[0].seq, tsType: typeof audit[0].ts,"
        "                 seq: audit[0].seq, ts: audit[0].ts };"
        # itemOf coercion on a string-shaped row
        f"const item = data.itemOf({{ seq: '{SEQ}', ts: '{TS}', kind: 'message',"
        "  actor: 'pres', target: 'phoenix', ref_id: '" + MSG_ID + "' });"
        "const itemTypes = { seqType: typeof item.seq, tsType: typeof item.ts };"
        # store: fresh dataset, feed number shape, then string
        # shape, then string shape again (fresh object each time,
        # as separate deliveries would be)
        "const d = { auditAsc: [], activity: [], conversations: [],"
        "  testConversations: [],"
        "  designation: new Map([['pres', 'production'], ['phoenix', 'production']]),"
        "  membersOf: () => [], nameOf: id => id, users: [], testUsers: [] };"
        "store.setData(d);"
        f"const base = {{ seq: {SEQ}, ts: {TS}, kind: 'message', actor: 'pres',"
        "  target: 'phoenix', group_id: '', ref_id: '" + MSG_ID + "',"
        "  status: '', size: 0, mentions: [], work_id: '' };"
        "store.applyAudit({ ...base });"
        f"store.applyAudit({{ ...base, seq: '{SEQ}', ts: '{TS}' }});"
        f"store.applyAudit({{ ...base, seq: '{SEQ}', ts: '{TS}' }});"
        "const conv = d.conversations[0] || d.testConversations[0] || null;"
        "console.log(JSON.stringify({ loaded, itemTypes,"
        "  auditAsc: d.auditAsc.length,"
        "  auditSeqTypes: d.auditAsc.map(r => typeof r.seq),"
        "  items: conv ? conv.items.length : -1,"
        "  itemSeqType: conv && conv.items[0] ? typeof conv.items[0].seq : null,"
        "  itemTsType: conv && conv.items[0] ? typeof conv.items[0].ts : null }));"
    )
    out = _run_node(script)
    # loadAudit normalized the string wire shape
    assert out["loaded"] == {"seqType": "number", "tsType": "number",
                             "seq": SEQ, "ts": TS}
    # itemOf coerces both fields
    assert out["itemTypes"] == {"seqType": "number", "tsType": "number"}
    # the dedupe itself: one audit entry, one conversation item
    assert out["auditAsc"] == 1, out
    assert out["auditSeqTypes"] == ["number"], out
    assert out["items"] == 1, out
    assert out["itemSeqType"] == "number" and out["itemTsType"] == "number", out


def test_string_shape_first_then_number_shape_also_dedupes():
    """Order must not matter: a Realtime string-shaped arrival
    first, then the PostgREST number shape, is still one item."""
    data_url = json.dumps(DATA.as_uri())
    store_url = json.dumps(STORE.as_uri())
    script = (
        "globalThis.localStorage = { getItem: () => null,"
        "  setItem: () => {}, removeItem: () => {} };"
        "globalThis.window = {};"
        f"await import({data_url});"
        f"const {{ store }} = await import({store_url});"
        "const d = { auditAsc: [], activity: [], conversations: [],"
        "  testConversations: [],"
        "  designation: new Map([['pres', 'production'], ['phoenix', 'production']]),"
        "  membersOf: () => [], nameOf: id => id, users: [], testUsers: [] };"
        "store.setData(d);"
        f"const base = {{ seq: {SEQ}, ts: {TS}, kind: 'message', actor: 'pres',"
        "  target: 'phoenix', group_id: '', ref_id: '" + MSG_ID + "',"
        "  status: '', size: 0, mentions: [], work_id: '' };"
        f"store.applyAudit({{ ...base, seq: '{SEQ}', ts: '{TS}' }});"
        "store.applyAudit({ ...base });"
        "const conv = d.conversations[0] || d.testConversations[0] || null;"
        "console.log(JSON.stringify({ auditAsc: d.auditAsc.length,"
        "  items: conv ? conv.items.length : -1 }));"
    )
    out = _run_node(script)
    assert out == {"auditAsc": 1, "items": 1}, out
