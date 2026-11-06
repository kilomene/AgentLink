import { esc, pt, table, states, empty, fail, avatar } from "../util.js";
import { activenessState, activenessLabel } from "../activeness.js";

// Presence cell: one badge per ladder state — "online", "suspect"
// (labelled with its staleness) and "offline" are three visually
// distinct classes (css: .activeness-online / .activeness-suspect /
// .activeness-offline). The badge and the beat-age cell carry the
// username so the 5s UI tick can repaint them in place.
function presenceCell(r, state, age){
  return '<span class="activeness activeness-' + state + '" data-activeness-user="' +
    esc(r.username) + '">' + esc(activenessLabel(state, age)) + "</span>";
}
function beatAgeCell(r, age){
  return '<span data-beat-age-user="' + esc(r.username) + '">' +
    (age === null || age === undefined ? "—" : age + "s ago") + "</span>";
}
const REACHABILITY = { online: "online", suspect: "suspect — heartbeat stale", offline: "unreachable — work protected" };

export async function render(root, ctx){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  if(!d.users.length) return empty(root, "No production agents registered.");
  const now = Date.now()/1000;
  const rows = d.users.map(r=>{
    const state = r.activeness || activenessState(r.presence, now);
    const age = (r.beat_age_s === undefined ? null : r.beat_age_s);
    return "<tr><td>" + esc("@"+r.username) + "</td><td>" + presenceCell(r, state, age) + "</td><td>" +
      beatAgeCell(r, age) + "</td><td>" + esc(r.reachability || REACHABILITY[state]) + "</td><td>" +
      esc(r.mode || "autonomous") + "</td><td>" + esc(String(r.trust_score)) + "</td><td>" +
      esc(pt(r.last_seen)) + "</td><td>" + esc(r.grant ? r.grant.status : "none") + "</td></tr>";
  }).join("");
  root.innerHTML = "<h3>Agents — presence, activity, trust</h3>"
    + '<table><thead><tr><th>Agent</th><th>Presence</th><th>Beat age</th><th>Reachability</th><th>Mode</th><th>Trust</th><th>Last seen</th><th>Grant</th></tr></thead><tbody>'
    + rows + "</tbody></table>"
    + "<h3>Servers — the peer registry</h3>" + table([["Server",r=>r.label||r.server_id||r.endpoint],["Endpoint",r=>r.endpoint],["Health",r=>r.health==null?"unrated":r.health+"%"],["Riders",r=>(r.riders??0)+"/"+(r.capacity??10)],["State",r=>r.carry_state||""]], d.servers);
}
