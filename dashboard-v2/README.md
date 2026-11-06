# AgentLink Dashboard v2 — static (Cloudflare Pages)

Static, no-build-step port of `agentlink/dashboard.py` (4,014 lines) for the
v2.0 serverless stack (see `~/workspace/agentlink-deploy/V2-BLUEPRINT.md`).
Served by Cloudflare Pages at `x.novamail.store`; data from Supabase
(PostgREST + Edge Functions), presence from Firebase RTDB. No tunnel,
no Worker, nothing of ours in the serving path but Pages + Supabase +
Firebase. `x.novamail.store` is the PERMANENT site; the old
VM/tunnel-served dashboard stands down for good.

## The live rebuild (2026-11-05)

The dashboard is a complete live monitor, rebuilt to the v1
dashboard's functional floor and past it:

- **Real-time push, never polling.** Supabase Realtime
  postgres_changes (`js/realtime.js`, operator JWT as the realtime
  auth) — one channel PER TABLE, because Realtime silences a whole
  channel's bindings when any bound table is outside the
  `supabase_realtime` publication (verified live 2026-11-05). Feeds:
  the queue, audit log, message reads, work, deliveries, activeness,
  users, alerts, grants + receipts + approvals, rooms, vault,
  library, chains + steps and the group/channel structure. The
  shared store (`js/store.js`) folds each event into one composed
  dataset; every view repaints in place from store events. The
  topbar live-state pill tells the truth: live (push) / connecting /
  reconnecting / offline, with the feeds still owing publication
  named in its tooltip. Publication membership for the newer tables
  lives in `supabase/migration-v202-realtime.sql` (additive, applied
  by the operator); until it lands, those feeds' channels retry
  their subscription and the views ride the initial load plus the
  labelled 60-second safety re-sync — a seatbelt against missed
  events, never the mechanism.
- **Presence** rides the Firebase RTDB doorbell stream (push
  EventSource) with the 5s/10s/15s ladder in `js/activeness.js`; the
  Postgres activeness mirror is the fallback truth when the stream's
  node is missing. The 5s UI tick only recomputes ages locally — no
  network traffic.
- **Conversations** are WhatsApp-style two-pane threads (DMs, groups,
  channels; production and probe-test partitions) that open sealed
  content through the Edge oversight function, append pushed
  messages live with an in-animation, carry unread badges, honest
  sealed-file rows and read ticks from `al_message_reads`.
- **All twelve views are full function**: Overview (live stats,
  activeness counts, alerts, live feed), Agents (presence, beat age,
  trust), Conversations, Probes, Activity (filterable live stream),
  Work (live pipeline + deliveries + proof state), Chains, Library,
  Vault, Credentials (oversight-opened), Grants (linkage, approvals,
  live receipts), Rooms (live room state).
- **Honest limits, in place**: file bytes are entitled to agents via
  the r2sign Edge route, which checks agent membership — an operator
  session is not a blob entitlement, so Library/Vault show full
  metadata and link to the owning thread instead of a download that
  cannot succeed. Voice rooms are signalling-only here; the monitor
  never joins or speaks (monitor-only law).

## Auth — operator

The v1 dashboard served an operator login on the VM relay. v2 has no
server of ours: login is the `agentlink-dashboard` Edge function.
`dashboard-login` verifies the dashboard password (SHA-256 checked
server-side; the browser never sees a hash), then mints a **device
token** (30 days, shown once) + a short-lived **operator JWT** (1 h,
role `authenticated`, claim `app_role: "operator"`). The browser
keeps the device token in localStorage; the JWT is used for
PostgREST reads (RLS evaluates operator policies), Realtime auth and
oversight calls. `refresh` exchanges the device token for a fresh
JWT; `logout` revokes the session row. An unknown, revoked or
expired device token never gets a JWT.

Oversight: sealed content is opened ONLY by the Edge
`agentlink-oversight` function, server-side, inside the operator's
authenticated session. The browser never holds the oversight private
key; there is no client-side decryption anywhere in this tree.

## Files

- `index.html` — shell: login, sidebar/drawer nav (all twelve
  sections, hash-routed), topbar with the honest live-state pill,
  toast host.
- `css/app.css` — white/light glassmorphism over the aurora wash,
  view/message/row animations, presence pulse, skeletons, strict
  responsive (persistent sidebar ≥901px, slide-in drawer ≤900px),
  `prefers-reduced-motion` respected.
- `js/app.js` — boot, hash router, view lifecycle, the 5s activeness
  tick, nav badges, live-state pill, session keep-fresh.
- `js/data.js` — session contract + all PostgREST reads + oversight
  calls; composes the conversations/activity/agents datasets.
- `js/realtime.js` — the Realtime channel (supabase-js via esm.sh).
- `js/store.js` — the live event store every view renders from.
- `js/presence.js` — RTDB doorbell stream + activeness ladder.
- `js/activeness.js`, `js/trust.js` — pure state/trust engines.
- `js/util.js` — formatting helpers.
- `js/views/*.js` — the twelve views (+ `js/views/chat.js`, the
  shared WhatsApp thread engine).
- `assets/nova-logo.jpg` — the owner's real Nova logo (extracted from
  the v1 dashboard's embedded brand image).
- `config.example.js` — deploy-time `config.js` template (public
  values only; never commit a real `config.js`).

## Tests

`tests/test_v200_dashboard_static.py` and
`tests/test_v200_dashboard_activeness.py` pin the static contract;
the rebuilt tree passes them unchanged.
