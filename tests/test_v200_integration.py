"""v2.0 integration pins — the seams BETWEEN the phase deliverables.

Each pin guards a cross-phase contract that no single phase's test
suite could see (the login field-name mismatch these pins were born
from would have failed every first contact closed). Static/source
pins, stdlib only, same style as the other v200 suites.
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SHARED_TS = (ROOT / "supabase/functions/_shared/v200.ts").read_text()
LOGIN_TS = (ROOT / "supabase/functions/agentlink-login/index.ts").read_text()
TRANSPORT = (ROOT / "agentlink/transport_v2.py").read_text()
DOORBELL = (ROOT / "agentlink/doorbell.py").read_text()


def test_firebase_uid_is_sanitized_username():
    # doorbell.py is the source of truth for the uid form; the Edge
    # minter must mint uid = sanitize_key(username) so RTDB rules
    # (auth.uid == path segment) line up for dotted usernames too.
    assert "uid: sanitizeKey(username)" in SHARED_TS
    assert "uid = sanitize_key" in DOORBELL


def test_login_challenge_expiry_field_alignment():
    # Edge returns the expiry under BOTH names; client accepts either.
    assert "expires: exp" in LOGIN_TS
    assert 'challenge.get("expires") or challenge.get("exp")' in TRANSPORT


def test_login_verify_expiry_field_alignment():
    # Client sends both names; Edge accepts either.
    assert '"exp": expires, "expires": expires' in TRANSPORT
    assert "body.exp ?? body.expires" in LOGIN_TS


def test_activeness_mirror_carries_beat_clock_and_transport():
    # Phase 1's al_activeness contract: beat_at is the beat clock at
    # the transition and transport names the leg; the client writes
    # both on transition mirrors (never per beat).
    assert '"beat_at": now_ts()' in TRANSPORT
    assert '"transport": ("slow-sync" if self.slow_sync_active' in TRANSPORT


def test_oversight_accepts_operator_jwt_and_dashboard_contracts():
    # Phase 7 flag, closed at integration: dashboard-v2 presents the
    # operator JWT as Bearer and posts batch {items} / {credentials_
    # for} bodies; the oversight function must honour all of it, not
    # only the original single-envelope session-token contract.
    ts = (ROOT / "supabase/functions/agentlink-oversight/index.ts").read_text()
    assert "operatorAuthorized" in ts
    assert "verifyAgentJwt" in ts
    assert 'claims.operator === true || claims.app_role === "operator"' in ts
    assert "Array.isArray(body.items)" in ts
    assert 'typeof body.credentials_for === "string"' in ts
    # _content_fields mirror: body -> instructions -> note precedence
    assert 'obj.body || obj.instructions || obj.note' in ts


def test_ladder_constants_agree_across_client_and_dashboard():
    # One ladder, three homes: doorbell.py, dashboard activeness.js.
    js = (ROOT / "dashboard-v2/js/activeness.js").read_text()
    for name, val in (("BEAT_INTERVAL_S", 5), ("ONLINE_MAX_AGE_S", 10),
                      ("SUSPECT_MAX_AGE_S", 15)):
        assert f"{name} = {val}" in DOORBELL, name
        assert f"{name} = {val}" in js, name


def test_file_route_response_carries_cors():
    # 2026-11-06, owner's phone: every file in the dashboard thread
    # rendered "unavailable" while the batch route proved the same
    # files verified — serveFilePayload's raw Response carried no
    # CORS headers, so real browsers refused to expose its body to
    # the page (Node fetch, used by every earlier proof, does not
    # enforce CORS and could not see the failure). The byte route
    # must carry the same CORS contract as the JSON routes.
    ts = (ROOT / "supabase/functions/agentlink-oversight/index.ts").read_text()
    assert "CORS_HEADERS," in ts  # imported from _shared/v200.ts
    start = ts.index("async function serveFilePayload")
    end = ts.index("function matchDeliveryFile")
    body = ts[start:end]
    assert "...CORS_HEADERS" in body
    assert "access-control-expose-headers" in body


def test_activeness_mirror_carries_client_version():
    # 2.0.1 (owner's order): the dashboard's Agents list states the
    # client version each agent actually runs. The Postgres
    # activeness mirror is one of its two truth sources — before
    # this fix the mirror write omitted client_version entirely,
    # so the column stayed '' for every agent forever.
    assert '"client_version": self.client_version' in TRANSPORT


def test_dashboard_agents_roster_shows_version():
    js = (ROOT / "dashboard-v2/js/views/agents.js").read_text()
    assert 'data-label="Version"' in js
    assert "<th>Version</th>" in js
    assert "activenessMirror" in js  # mirror is a version source
    assert "not reported" in js      # honest state for silent agents
