"""2.1.0 hotfix pins — the support form's browser contract.

2026-11-07, the owner's own phone (iPhone Safari): he filled the
support form, attached a proof PNG, hit submit, and got the bare
"Load failed". The lodge itself had landed (his ticket was in the
table); the flow died at the proof upload — the form PUTs the file
straight from the browser to a presigned R2 URL, and the
agentlink-files bucket had NO CORS configuration, so Safari's
preflight to r2.cloudflarestorage.com was unanswered and the fetch
rejected before a byte moved. Two drill blind spots let it ship:
the 2.1.0 exercise drove lodge/attach through the CLI client
(server-side HTTP does not enforce CORS and could not see it), and
the dashboard-clause verification rendered the form without ever
submitting it.

These pins guard what CAN be guarded in source:
  * the support Edge answers every response — preflight included —
    through the shared CORS-carrying helpers, never a raw Response;
  * the form shows the lodged ticket's id + claim secret BEFORE it
    attempts any upload, and an upload failure can no longer throw
    that key away (the page must say the ticket is lodged and safe).
The bucket half of the contract is infrastructure, not source: the
live browser-simulation probe (lodge -> attach -> R2 preflight ->
PUT -> confirm, with real Origin headers) is kept in evidence at
drill-evidence/v210/hotfix_flow.py and was run green after the
bucket CORS rule was set (origin https://x.novamail.store, methods
PUT/GET/HEAD, headers *, expose ETag).
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUPPORT_TS = (ROOT / "supabase/functions/agentlink-support/index.ts").read_text()
SHARED_TS = (ROOT / "supabase/functions/_shared/v200.ts").read_text()
FORM = (ROOT / "dashboard-v2/support.html").read_text()


def test_support_edge_no_raw_responses():
    # Every response the support Edge returns must come from the
    # shared helpers (jsonResponse / errorResponse / methodGuard),
    # which are the ones that carry CORS_HEADERS. A single raw
    # `new Response(` would re-open the browser failure class.
    assert "new Response(" not in SUPPORT_TS
    for helper in ("methodGuard", "jsonResponse", "errorResponse"):
        assert helper in SUPPORT_TS


def test_support_edge_guards_method_before_routing():
    # methodGuard is what answers the OPTIONS preflight (204 +
    # CORS_HEADERS in _shared/v200.ts); it must run at the top of
    # the handler, before any route logic.
    handler = SUPPORT_TS.index("Deno.serve")
    guard = SUPPORT_TS.index("methodGuard(req)", handler)
    lodge = SUPPORT_TS.index('"/lodge"', handler)
    assert handler < guard < lodge


def test_shared_helpers_carry_the_cors_contract():
    # The shared half of the pin: the preflight answer and every
    # JSON response carry Access-Control-Allow-Origin.
    assert '"access-control-allow-origin"' in SHARED_TS
    preflight = SHARED_TS.index('req.method === "OPTIONS"')
    assert "CORS_HEADERS" in SHARED_TS[preflight:preflight + 200]
    assert "...CORS_HEADERS" in SHARED_TS


def test_form_shows_ticket_before_attempting_uploads():
    # The ticket block (id + claim secret) must render as soon as
    # the lodge returns — BEFORE the proof-upload loop — and the
    # upload failure path must keep it visible.
    lodge_at = FORM.index('post("/lodge"')
    shown_at = FORM.index("Ticket lodged.", lodge_at)
    upload_at = FORM.index('post("/attach"', lodge_at)
    assert lodge_at < shown_at < upload_at
    assert "Your ticket is lodged and safe" in FORM
