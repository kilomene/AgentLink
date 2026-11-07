import { esc, pt, table, states, empty, fail, avatar, pill } from "../util.js";
import { activenessState, activenessLabel } from "../activeness.js";

// Agents: roster with live presence. Presence truth is the
// hyper-sensitive ladder (online / suspect / offline are three
// visually distinct badges; suspect names its staleness). The badge
// and beat-age cells carry the username so the 5s UI tick repaints
// them in place as ages advance; pushed user/activeness changes
// re-render the roster region in place.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

function presenceCell(r, state, age){
  return '<span class="activeness activeness-' + state + '" data-activeness-user="' +
    esc(r.username) + '">' + esc(activenessLabel(state, age)) + "</span>";
}
function beatAgeCell(r, age){
  return '<span data-beat-age-user="' + esc(r.username) + '">' +
    (age === null || age === undefined ? "—" : age + "s ago") + "</span>";
}
const REACHABILITY = { online: "online", suspect: "suspect — heartbeat stale", offline: "unreachable — work protected" };

// Client version (owner's order, 2026-11-06): every agent row
// states the client version that agent is ACTUALLY running, so
// the operator can see who has updated and who is stranded on an
// old build. Truth sources, freshest first: the live Firebase
// presence node, then the Postgres activeness mirror — both are
// stamped by the client itself at login/presence time, never
// typed by hand. An agent that has never connected on the
// serverless stack reports nothing and reads "not reported".
function versionOf(r){
  return (r.presence && r.presence.client_version) ||
    (r.activenessMirror && r.activenessMirror.client_version) || "";
}
function vcmp(a, b){
  const x = String(a).split("."), y = String(b).split(".");
  for(let i = 0; i < 3; i++){ const d = (parseInt(x[i], 10) || 0) - (parseInt(y[i], 10) || 0); if(d) return d; }
  return 0;
}
function versionCell(r, latest){
  const v = versionOf(r);
  if(!v) return '<span class="state">not reported</span>';
  return "<b>" + esc(v) + "</b>" + (latest && vcmp(v, latest) >= 0
    ? '<br><small>latest</small>' : '<br><small>older build</small>');
}

function rosterHtml(d, now){
  if(!d.users.length) return '<p class="state">No production agents registered.</p>';
  const reported = d.users.map(versionOf).filter(Boolean);
  const latest = reported.length ? reported.slice().sort(vcmp)[reported.length - 1] : "";
  const rows = d.users.map(r => {
    const state = r.activeness || activenessState(r.presence, now);
    const age = (r.beat_age_s === undefined ? null : r.beat_age_s);
    const conn = (d.connections || []).find(c => c.username === r.username);
    return '<tr><td data-label="Agent" class="tfirst">' + avatar(r.username) + " <b>@" + esc(r.username) + "</b>" +
      (r.display_name ? '<br><small>' + esc(r.display_name) + "</small>" : "") +
      '<br><small>' + esc(r.designation || "production") + " · mode " + esc(r.mode || "autonomous") + '</small></td><td data-label="Presence">' +
      presenceCell(r, state, age) + '</td><td data-label="Beat age">' + beatAgeCell(r, age) + '</td><td data-label="Version">' +
      versionCell(r, latest) + '</td><td data-label="Reachability">' +
      esc(r.reachability || REACHABILITY[state]) + '</td><td data-label="Trust">' +
      '<span class="trustbar"><span class="progressbar"><i style="width:' + r.trust_score + '%"></i></span><b>' + r.trust_score + "</b></span>" +
      '<br><small>trust from verified work history</small></td><td data-label="Last seen">' + esc(pt(r.last_seen)) + '</td><td data-label="Grant">' +
      (r.grant ? pill(r.grant.status, r.grant.status === "active" ? "green" : "amber") + "<br><small>by " + esc(r.grant.granted_by || "") + "</small>" : pill("none", "grey")) +
      '</td><td data-label="Server">' + esc(conn ? (conn.server_id || conn.endpoint || "") : "—") + "</td></tr>";
  }).join("");
  return '<table><thead><tr><th>Agent</th><th>Presence</th><th>Beat age</th><th>Version</th><th>Reachability</th><th>Trust</th><th>Last seen</th><th>Grant</th><th>Server</th></tr></thead><tbody>' + rows + "</tbody></table>";
}

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  root.innerHTML = '<div class="vhead"><h2>Agents</h2><div class="vsub">Presence, activity and trust — presence is backend-wide truth from the 5-second heartbeat only, never from agent claims. Trust is computed from verified work history: 0 base — trust is earned, never granted — +4 per completed/covered assignment (work given, done successfully and reviewed successfully; delivery alone earns nothing), −6 per changes-requested or missed deadline, −10 per invalid proof. Phoenix (100) and deploy-probe (56) hold the real percentages they earned before the zero-base ruling.</div></div>' +
    '<div class="card"><h3>Agents — presence, activity, trust</h3><div class="roster"></div></div>' +
    '<div class="card"><h3>Servers — the peer registry</h3><div class="servers"></div></div>';
  const roster = root.querySelector(".roster");
  const paint = () => { roster.innerHTML = rosterHtml(ctx.store.data, Date.now() / 1000); };
  paint();
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
  unsubs.push(ctx.bus.on("structure", paintServers));
  return { destroy };
}
