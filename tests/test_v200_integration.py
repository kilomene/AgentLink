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


def test_activeness_mirror_is_deleted():
    # 2.3.0: the Postgres activeness mirror is DELETED — the
    # transport never writes the table (the only remaining
    # mentions are the doc-comments recording the deletion).
    assert 'self._rest(\n            "POST", "activeness"' not in TRANSPORT
    assert "_mirror_activeness" not in TRANSPORT
    assert 'update_presence_backup' not in TRANSPORT
    # The version fact the mirror used to carry rides the
    # Firebase presence node now (doorbell set_presence).
    assert '"client_version"' in DOORBELL


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
    assert 'obj.body || obj.text || obj.instructions || obj.note' in ts


def test_ladder_constants_agree_across_client_and_dashboard():
    # One ladder, three homes: doorbell.py, dashboard activeness.js.
    js = (ROOT / "dashboard-v2/js/activeness.js").read_text()
    for name, val in (("BEAT_INTERVAL_S", 180), ("ONLINE_MAX_AGE_S", 240),
                      ("SUSPECT_MAX_AGE_S", 420)):
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


def test_presence_node_carries_client_version():
    # 2.0.1 (owner's order): the dashboard's Agents list states the
    # client version each agent actually runs. The version rides
    # the Firebase presence node (2.3.0: the Postgres mirror that
    # also carried it is deleted — presence is the one truth).
    assert '"client_version": self.client_version' in TRANSPORT or \
        "client_version=client_version" in TRANSPORT or \
        '"client_version"' in DOORBELL


def test_dashboard_agents_roster_shows_version():
    js = (ROOT / "dashboard-v2/js/views/agents.js").read_text()
    assert 'data-label="Version"' in js
    assert "<th>Version</th>" in js
    assert "activenessMirror" in js  # mirror is a version source
    assert "not reported" in js      # honest state for silent agents


def test_resume_pass_transient_logs_one_warning_line():
    # Log hygiene (2.0.6 doctrine, extended 2.0.8): a transient
    # TransportError in the boot/reconnect resume pass is a designed
    # degradation — it must be caught BEFORE the generic handler and
    # logged as one warning line, never as a traceback (a traceback
    # is the shape of a crash; the 2.0.8 soak supervisor reads it as
    # a fault while the daemon delivers on around it). Both boot
    # sequences (serverless + relay reconnect) carry the guard.
    client = (ROOT / "agentlink/client.py").read_text()
    assert client.count('log.warning("resume/resync pass deferred') == 2
    assert client.count('log.exception("resume/resync pass failed")') == 2
