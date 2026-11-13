import { esc, pt, table, states, empty, fail, avatar, pill } from "../util.js";
import { activenessState } from "../activeness.js";
import { fetchManifestVersion } from "../data.js";

// Agents: roster with live presence. Presence truth is the
// hyper-sensitive ladder (online / suspect / offline are three
// visually distinct badges; suspect names its staleness). The badge
// and beat-age cells carry the username so the 5s UI tick repaints
// them in place as ages advance; pushed user/activeness changes
// re-render the roster region in place.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

// ------------------------------------------------ Life Signs
// (2.5.0): the Presence column shows the GRADE — the platform's
// computed judgment of the agent by its OWN declared nature —
// with its last proof (tier + age), instead of the bare online
// light. Sources, in freshness order: the LIVE node
// (/liveness/<user>, pushed at proof/transition time), then the
// record-layer row. A stale node is labelled stale with its
// age; no source at all reads "unproven" — never a guessed
// grade. The presence ladder still shows in Beat age, and a
// lost presence under a live grade is stated as a fact
// ("presence lost — awaiting evaluation"), not hidden.
const GRADE_CLASS = { BEATING: "beating", RESTING: "resting", SUSPECT: "suspect", DARK: "dark" };
const PROOF_LABEL = { runtime: "runtime-proven", daemon: "daemon-proven", login: "last authentication" };
const LIVENESS_STALE_S = 180;
function fmtAge(s){
  if(s === null || s === undefined || !isFinite(s)) return "never";
  s = Math.max(0, Math.floor(s));
  if(s < 90) return s + "s ago";
  if(s < 5400) return Math.floor(s / 60) + "m ago";
  if(s < 172800) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}
function nodeAsOfS(node, now){
  const raw = Number(node && node.as_of || 0);
  if(!raw) return 0;
  return raw > now * 10 ? raw / 1000 : raw;
}
function lifeSignCell(r, now){
  const node = r.livenessNode || null;
  const rec = r.liveness || null;
  let grade = "", tier = "", proofAt = 0, daemonOnly = false,
      stale = false, source = "";
  if(node && node.grade){
    grade = String(node.grade);
    tier = String(node.last_proof_tier || "");
    proofAt = Number(node.last_proof_at || 0);
    daemonOnly = !!node.daemon_only;
    const asOf = nodeAsOfS(node, now);
    stale = !asOf || (now - asOf) > LIVENESS_STALE_S;
    source = stale ? "live node stale " + fmtAge(now - asOf) : "live";
  } else if(rec && rec.grade){
    grade = String(rec.grade);
    const dAt = Number(rec.last_daemon_receipt_at || 0);
    const rAt = Number(rec.last_runtime_proof_at || 0);
    if(rAt >= dAt && rAt > 0){ tier = "runtime"; proofAt = rAt; }
    else if(dAt > 0){ tier = "daemon"; proofAt = dAt; }
    daemonOnly = !!rec.daemon_only;
    source = "recorded " + fmtAge(now - Number(rec.updated_at || 0));
  }
  if(!grade){
    const dS = (node && node.dossier_status) || (rec && rec.dossier_status) || "missing";
    return '<span class="activeness activeness-unproven">unproven</span>' +
      '<br><small>no grade on record</small>' +
      '<br><small>dossier: ' + esc(dS) + ' (Drive only)</small>';
  }
  const cls = GRADE_CLASS[grade] || "unproven";
  let html = '<span class="activeness activeness-' + cls + '">' +
    esc(grade.toLowerCase()) + (stale ? " (stale)" : "") + "</span>";
  html += '<br><small>' +
    (tier ? esc(PROOF_LABEL[tier] || tier) + " " + fmtAge(now - proofAt)
          : "no proof on record") +
    (daemonOnly ? ' · <b>daemon-only</b>' : "") +
    '<br>judged by nature v' +
    esc(String(node ? (node.nature_version ?? 0) : (rec.judged_nature_version ?? 0))) +
    " · " + esc(source) + "</small>";
  // Dossier FLAG only: the dossier itself lives solely in the
  // owner's Drive archive — never rendered here; this line is
  // the status + last deposit date and nothing else.
  const dStatus = (node && node.dossier_status) || (rec && rec.dossier_status) || "missing";
  const dAt = rec ? Number(rec.dossier_deposited_at || 0) : 0;
  if(dStatus === "deposit-parked" || dStatus === "missing")
    html += '<br><small><b>dossier: ' + esc(dStatus) + '</b>' +
      (dAt ? ' · last deposited ' + fmtAge(now - dAt) + ' ago' : '') + '</small>';
  else
    html += '<br><small>dossier: ' + esc(dStatus) +
      (dAt ? ' · deposited ' + fmtAge(now - dAt) + ' ago' : '') + '</small>';
  if((grade === "BEATING" || grade === "RESTING") && r.activeness === "offline")
    html += '<br><small>presence lost — awaiting evaluation</small>';
  return html;
}

// Nature badge, under the agent's name. The declaration is
// the agent's signed statement of how it runs, labelled by
// its nature words — an honest claim, not a platform-verified
// fact. (2.6.0: the dashboard shows no machine spec; the
// platform retired spec collection entirely.) Non-compliance
// (no current signed
// declaration) replaces the badge outright (owner's hardening
// ruling): it is impossible to miss.
const RK_LABEL = { "persistent-daemon": "persistent daemon", "session-chat": "session runtime", "scheduled": "scheduled", "embedded": "embedded", "other": "other runtime" };
const HC_LABEL = { "cloud-vm": "cloud VM", "home-pc": "home PC", "phone": "phone", "server": "server", "other": "other host" };
function natureLine(r){
  const prof = r.nature_profile || null;
  const node = r.livenessNode || null;
  const rec = r.liveness || null;
  let compliant;
  if(node && node.nature_compliant !== undefined) compliant = !!node.nature_compliant;
  else if(rec) compliant = !!rec.nature_compliant;
  else compliant = (r.nature_version || 0) > 0;
  if(!prof || !compliant){
    return '<br><small><b>nature undeclared / stale — non-compliant</b></small>';
  }
  let line = '<br><small>' + esc(RK_LABEL[prof.runtime_kind] || "runtime") +
    " · " + esc(HC_LABEL[prof.host_class] || "host") +
    " · " + esc(prof.persistence_class || "") + " class · nature v" +
    esc(String(r.nature_version || 0)) + "</small>";
  if(prof.duty_pattern) line += '<br><small>' + esc(String(prof.duty_pattern)) + "</small>";
  return line;
}

// Build integrity chip (2.5.2, the Street Rule): the
// PLATFORM's verdict on the build this agent runs, computed
// server-side from its signed attestation against the
// registered release digest — never the agent's own version
// string. stock = the attested manifest IS the release;
// modified = a verified attestation names a different build
// (non-compliant, shown everywhere non-compliance is shown);
// unattested = no verified attestation (every pre-2.5.2
// build reads this until it lands 2.5.2). Node-first,
// record fallback, exactly like the grade.
function buildLine(r){
  const node = r.livenessNode || null;
  const rec = r.liveness || null;
  let verdict = "", bVer = "", bDig = "";
  if(node && node.build_integrity){
    verdict = String(node.build_integrity);
    bVer = String(node.build_version || "");
    bDig = String(node.build_digest || "");
  } else if(rec){
    verdict = String(rec.build_integrity || "unattested");
    bVer = String(rec.build_version || "");
    bDig = String(rec.build_digest || "").slice(0, 12);
  }
  if(!verdict) verdict = "unattested";
  const detail = (bVer ? " · v" + esc(bVer) : "") +
    (bDig ? " · " + esc(bDig) + "…" : "");
  if(verdict === "modified")
    return '<br><small><b>build: MODIFIED' + detail + '</b>' +
      ' — non-compliant (platform verdict)</small>';
  if(verdict === "stock")
    return '<br><small>build: stock' + detail +
      ' (attested)</small>';
  return '<br><small>build: unattested' + detail + '</small>';
}
function beatAgeCell(r, age){
  return '<span data-beat-age-user="' + esc(r.username) + '">' +
    (age === null || age === undefined ? "—" : age + "s ago") + "</span>";
}
const REACHABILITY = { online: "online", suspect: "suspect — heartbeat stale", offline: "unreachable — work protected" };

// Client version (owner's order, 2026-11-06): every agent row
// states the client version that agent is ACTUALLY running, so
// the operator can see who has updated and who is stranded on an
// old build. The ONLY truth source is the live Firebase presence
// node, stamped by the client itself at connect/beat time.
// v242: the old fallback to the Postgres activeness mirror is
// REMOVED — since v211 that row is a login record whose
// client_version the login trigger writes as '' on insert and
// never updates, so any non-empty value there is a frozen
// pre-2.3.0 mirror write (it showed "2.2.3" for agents live on
// 2.4.1 — the owner's 2026-11-10 screenshot). An agent with no
// presence node reports nothing and reads "not reported": an
// absent claim, never a stale one dressed as current.
function versionOf(r){
  return (r.presence && r.presence.client_version) || "";
}
function vcmp(a, b){
  const x = String(a).split("."), y = String(b).split(".");
  for(let i = 0; i < 3; i++){ const d = (parseInt(x[i], 10) || 0) - (parseInt(y[i], 10) || 0); if(d) return d; }
  return 0;
}
function versionCell(r, latest){
  const v = versionOf(r);
  if(!v) return '<span class="state">not reported</span>';
  // "latest" compares against the PUBLISHED manifest version
  // (v242, fetched at runtime by data.js) — never a maximum
  // derived from the fleet itself. When the manifest could not
  // be read (latest === ""), no tag is shown at all.
  if(!latest) return "<b>" + esc(v) + "</b>";
  return "<b>" + esc(v) + "</b>" + (vcmp(v, latest) >= 0
    ? '<br><small>latest</small>' : '<br><small>older build</small>');
}

// Last seen (v242): the live presence beat when a node exists
// (applyPresence stamps last_seen_display from the node); the
// registry's last_seen — the agent's last LOGIN — only when
// there is no node, where it is labelled as a login so it can
// never masquerade as liveness.
function lastSeenCell(r){
  const t = (r.last_seen_display !== undefined && r.last_seen_display !== null)
    ? r.last_seen_display : r.last_seen;
  if(!t) return "—";
  return esc(pt(t)) + (r.presence ? "" : '<br><small>last login</small>');
}

// The published manifest version, resolved async by render();
// module state so repaints (bus events, 5s-tick region renders)
// reuse it without refetching.
let manifestLatest = "";

function rosterHtml(d, now){
  if(!d.users.length) return '<p class="state">No production agents registered.</p>';
  const latest = manifestLatest;
  const rows = d.users.map(r => {
    const state = r.activeness || activenessState(r.presence, now);
    const age = (r.beat_age_s === undefined ? null : r.beat_age_s);
    const conn = (d.connections || []).find(c => c.username === r.username);
    return '<tr><td data-label="Agent" class="tfirst">' + avatar(r.username) + " <b>@" + esc(r.username) + "</b>" +
      (r.display_name ? '<br><small>' + esc(r.display_name) + "</small>" : "") +
      '<br><small>' + esc(r.designation || "production") + " · mode " + esc(r.mode || "autonomous") + '</small>' +
      natureLine(r) + buildLine(r) + '</td><td data-label="Life sign">' +
      lifeSignCell(r, now) + '</td><td data-label="Beat age">' + beatAgeCell(r, age) + '</td><td data-label="Version">' +
      versionCell(r, latest) + '</td><td data-label="Reachability">' +
      esc(r.reachability || REACHABILITY[state]) + '</td><td data-label="Trust">' +
      '<span class="trustbar"><span class="progressbar"><i style="width:' + r.trust_score + '%"></i></span><b>' + r.trust_score + "</b></span>" +
      '<br><small>trust from verified work history</small></td><td data-label="Last seen">' + lastSeenCell(r) + '</td><td data-label="Grant">' +
      (r.grant ? pill(r.grant.status, r.grant.status === "active" ? "green" : "amber") + "<br><small>by " + esc(r.grant.granted_by || "") + "</small>" : pill("none", "grey")) +
      '</td><td data-label="Server">' + esc(conn ? (conn.server_id || conn.endpoint || "") : "—") + "</td></tr>";
  }).join("");
  return '<table><thead><tr><th>Agent</th><th>Life sign</th><th>Beat age</th><th>Version</th><th>Reachability</th><th>Trust</th><th>Last seen</th><th>Grant</th><th>Server</th></tr></thead><tbody>' + rows + "</tbody></table>";
}

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  root.innerHTML = '<div class="vhead"><h2>Agents</h2><div class="vsub">Life Signs: every agent is graded by its OWN declared nature — BEATING / RESTING / SUSPECT / DARK — from verified proofs: a daemon receipt proves the daemon woke (daemon-proven); only the runtime\'s own countersignature reads runtime-proven. Grades arrive in real time on the live layer and are labelled with their source and age; a grade with no live proof reads unproven, never a guess. Nature + machine are the agent\'s signed declarations (client-detected, labelled declared); an agent without a current declaration reads non-compliant, in the open. Trust is computed from verified work history: 0 base — trust is earned, never granted — +4 per completed/covered assignment (work given, done successfully and reviewed successfully; delivery alone earns nothing), −6 per changes-requested or missed deadline, −10 per invalid proof. Phoenix (100) and deploy-probe (56) hold the real percentages they earned before the zero-base ruling.</div></div>' +
    '<div class="card"><h3>Agents — life signs, nature, trust</h3><div class="roster"></div></div>' +
    '<div class="card"><h3>Servers — the peer registry</h3><div class="servers"></div></div>';
  const roster = root.querySelector(".roster");
  const paint = () => { roster.innerHTML = rosterHtml(ctx.store.data, Date.now() / 1000); };
  paint();
  // Resolve the published "latest" from the manifest, then
  // repaint once so the tags land without waiting for the next
  // bus event. Cached in data.js after the first fetch.
  fetchManifestVersion().then(v => { if(v && v !== manifestLatest){ manifestLatest = v; paint(); } }).catch(() => {});
  const serversHost = root.querySelector(".servers");
  const paintServers = () => {
    const dd = ctx.store.data;
    serversHost.innerHTML = dd.servers.length ? table(
      [["Server", r => esc(r.label || r.server_id || r.endpoint || "")], ["Endpoint", r => esc(r.endpoint || "")],
       ["Health", r => (r.health == null || r.health < 0) ? "unrated" : '<span class="progressbar"><i style="width:' + r.health + '%"></i></span> ' + r.health + "%"],
       ["Riders", r => (r.riders ?? 0) + "/" + (r.capacity ?? 10)], ["State", r => esc(r.carry_state || "")]], dd.servers)
      : '<p class="state">No servers registered.</p>';
  };
  paintServers();
  unsubs.push(ctx.bus.on("users", paint));
  unsubs.push(ctx.bus.on("activeness", paint));
  unsubs.push(ctx.bus.on("liveness", paint));
  unsubs.push(ctx.bus.on("structure", paintServers));
  return { destroy };
}
