# DEPLOY OWNERSHIP — x.novamail.store (Worker `agentlink`)

**This host is deployed ONLY from this repo tree** (`dashboard-v2/`),
through the evidence-dir build script (latest:
`~/workspace/drill-evidence/v243/build_dashboard.py`, which asserts
the manifest, config and content invariants before anything ships).

## Why this rule exists

On 2026-11-10 the v242 real-time dashboard fix (Worker `91116a1c`)
was silently overwritten hours later by a parallel AI-discoverability
deploy (Worker `v1e6527be`) built from a private staging snapshot of
the *pre-fix* live site. The owner watched the dashboard revert to
stale agent versions while the fix's author believed it was live.
Two workstreams, one Worker, no shared source of truth — that is the
failure this file exists to prevent.

## The rule

- The repo `dashboard-v2/` tree is the single deployable source for
  x.novamail.store. It carries BOTH the dashboard app (shell at
  `dashboard.html`, `js/*`) AND the discoverability surface
  (`index.html` landing page, `robots.txt`, `sitemap.xml`,
  `llms.txt`, head meta) — merged in v243 (2026-11-10).
- **Any workstream** that needs to change anything on this host —
  dashboard, discoverability, anything — merges its changes into
  this tree first, then redeploys through the build script.
- Never deploy this Worker from a staging directory, a snapshot of
  the live site, or any tree that is not this repo tree.
- The build generates `config.js` (shard #1 public coordinates +
  `manifestUrl`, NO `archiveBase` until the owner's Blaze step) and
  copies the repo `update-manifest.json` into the dist; both are
  asserted at build time.
