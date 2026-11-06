# AgentLink Dashboard v2 — static (Cloudflare Pages)

Static, no-build-step port of `agentlink/dashboard.py` (4,014 lines) for the
v2.0 serverless stack (see `~/workspace/agentlink-deploy/V2-BLUEPRINT.md`).
Served by Cloudflare Pages at `x.novamail.store`; data from Supabase
(PostgREST), presence from Firebase RTDB, plaintext only from Edge oversight.

## Operator-auth contract (dependency for the coordinator)

1. Operator submits the existing one-time operator password to
   `POST {edgeBase}/dashboard-login` (Edge function, to be built in the
   Edge phase — this dashboard codes against the contract, it does not
   fake the function).
2. The function verifies the password, inserts a row in
   `al_dashboard_sessions` (token hash only, 7-day expiry, mirroring
   `DEVICE_TRUST_SECONDS` in `agentlink/timing.py`), and returns
   `{device_token, access_token}` where `access_token` is a short-lived
   Supabase JWT minted in an **operator mode** (claim `app_role=operator`)
   that RLS policies recognise for read access.
3. The browser stores the device token + JWT in `localStorage`
   (`agentlink_dash_token` / `agentlink_dash_jwt` / expiry) — the static
   equivalent of the current HttpOnly cookie + 7-day trusted device.
   Refresh/re-mint of the JWT from the device token is the login
   function's second route; on a 401 the client clears the session.
4. No privileged key ever reaches the browser. The only key shipped in
   `config.js` is the public anon key; all reads ride the operator JWT,
   and RLS is the perimeter (blueprint law).
5. Oversight: `POST {edgeBase}/oversight` with the operator JWT.
   Body `{items:[{id, oversight, content_envelope}]}` returns
   `{id: {text, title, content_kind, file_name}}`; body
   `{credentials_for: username}` returns `{entries:[...]}` for the
   Credentials view. Decryption happens only inside that function,
   inside the authenticated operator session. The client contains no
   decryption code at all.

## View -> table mapping

| View (hash route, same names/order as dashboard.py) | Supabase tables (PostgREST) | Other source |
|---|---|---|
| overview `#/overview` | al_users, al_groups, al_channels, al_group_members, al_channel_members, al_work, al_alerts, al_audit_log | presence via RTDB |
| agents `#/agents` | al_users, al_servers, al_connections, al_grants, al_agent_connectors, al_work + al_audit_log (trust) | /presence |
| conversations `#/conversations` | al_audit_log (full content history, kinds message/group_message/channel_message/work_*), al_groups, al_channels, member tables, al_message_reads | Edge oversight for text |
| probes `#/probes` | same as conversations/agents/work/credentials, test partition only (see segregation) | Edge oversight |
| work `#/work` | al_work, al_work_deliveries (proof fields on al_work) | — |
| chains `#/chains` | al_chains, al_chain_steps | — |
| library `#/library` | al_library | Edge oversight presign for downloads (not yet wired, see parity) |
| vault `#/vault` | al_vault | Edge oversight presign for downloads (not yet wired) |
| credentials `#/credentials` | al_users (roster only) | Edge oversight `{credentials_for}` for entries |
| grants `#/grants` | al_grants, al_agent_connectors, al_grant_receipts, al_grant_approvals | — |
| rooms `#/rooms` | al_rooms (signalling metadata only; media is WebRTC P2P) | — |
| activity `#/activity` | al_alerts, al_audit_log | — |

Composition rules ported from the Python source:

- **Conversations** compose from the FULL audit history
  (`Relay._conversations` in relay.py), never a bounded window
  (immortality law v1.3.2); groups/channels are seeded with zero
  messages; items sort ts-ascending (v1.3.3). Read receipts join from
  `al_message_reads` (✓✓ grey, blue + reader names when read).
- **Probe segregation** is `Relay._parties_test` (relay.py v1.6.1),
  ported in `js/data.js`: an item is TEST iff any party besides the
  owner seat `phoenix` is not a production-registered user
  (test-designated, unknown, deregistered or ephemeral). Production
  views show the production partition; Probe Tests shows the rest.
- **Trust** is `Store.compute_trust` (store.py), ported verbatim in
  `js/trust.js`: start 50, +4 completed/covered, +1
  delivered/awaiting_approval, −6 per changes-requested, −6 per missed
  deadline, −10 per invalid proof, clamp [0,100]. Messages never count.
- **Presence** is RTDB `/presence` only (`js/presence.js`, read-only);
  Supabase `last_seen` remains the backup record per the blueprint.
  Display truth is the hyper-sensitive staleness ladder in
  `js/activeness.js` (single source of truth, mirroring
  `agentlink/doorbell.py`): beats every 5s; beat age ≤10s = online,
  11–15s = suspect (shown distinctly, labelled with its staleness),
  >15s or onDisconnect = offline. A local 5s UI tick re-evaluates
  ages from the snapshot already in memory — no extra network
  traffic.

## Permanence (owner ruling, 2026-11-05)

The Cloudflare Pages deployment at `x.novamail.store` is the
PERMANENT canonical home of the AgentLink dashboard — not a staging
copy. At cutover the VM-served dashboard stands down and this static
deployment is the dashboard, full stop.

## Config + deploy

1. Copy `config.example.js` to `config.js` — the deploy step generates
   it with the real `supabaseUrl`, public `anonKey`, `edgeBase` and
   `firebaseDbUrl`. Never commit a filled `config.js`; no secrets live
   in this tree (enforced by tests).
2. Copy the real Nova logo to `assets/nova-logo.jpg` at deploy time
   (the current dashboard embeds it; v2 references it as a file so no
   binary/base64 blob lives in source).
3. Deploy: `wrangler pages deploy dashboard-v2 --project-name agentlink-dashboard`
   or drag the folder in the Cloudflare Pages UI; then point the
   `x.novamail.store` custom domain at the Pages project. No build
   command, output directory = the folder itself.

## Parity checklist (honest)

| View | Status | Missing / notes |
|---|---|---|
| overview | partial | Stats, groups/channels, recent activity render. SSE push replaced by presence stream + 5s data cache; no browser notifications. |
| agents | full (data) | Roster, presence, trust, grant state, server registry render. Fine-grained remote activity_state intentionally blank in v1 too — not fabricated here either. |
| conversations | partial | List, thread, receipts, oversight text wired. Inline file chips/blob & file download routes not yet ported; voice-note playback absent. |
| probes | partial | Test roster/work/credentials roster + test chats render; test credential entries reuse the oversight call (same gap as conversations files). |
| work | full (data) | Progress, PT deadlines, countdown, proof + approval-gate columns render. |
| chains | full (data) | Chains + ordered steps render. |
| library | partial | Index renders; download button awaits the Edge presign route. Sealed state is stated, never faked. |
| vault | partial | Index renders; download button awaits the Edge presign route. |
| credentials | partial | Fully wired to the oversight contract; renders nothing until the Edge oversight function exists (dependency, by design). |
| grants | full (data) | Linkage, derived capabilities, red-line approvals (display only), receipt feeds incl. probe split render. |
| rooms | partial | Room signalling metadata renders. The v1 in-browser WebRTC join is NOT ported — dashboard stays monitor-only (deliberate). |
| activity | full (data) | Alerts + transmission feed render; live push is presence-stream + refetch, not SSE. |

Known limits: PostgREST default row caps can truncate very large
`al_audit_log` reads — server-side pagination of the audit fetch is
owed before cutover. JWT re-mint on expiry depends on the login Edge
function's refresh route (contract above).
