import { esc, pt, table, states, empty, fail, avatar } from "../util.js";
import { activenessState } from "../activeness.js";

// Activeness summary: the three ladder states are counted and shown
// as three distinct badges — "online", "suspect" and "offline"
// (css: .activeness-online / .activeness-suspect /
// .activeness-offline) — never collapsed into one online number.
export async function render(root, ctx){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  const now = Date.now()/1000;
  const statesOf = (d.users||[]).map(u=>u.activeness || activenessState(u.presence, now));
  const counts = { online: statesOf.filter(s=>s==="online").length,
                   suspect: statesOf.filter(s=>s==="suspect").length,
                   offline: statesOf.filter(s=>s==="offline").length };
  const stats = [["Agents", d.users.length],["Online", counts.online],["Groups", d.groups.length],["Channels", d.channels.length],["Open work", d.work.filter(w=>w.status!=="completed").length],["Alerts", d.alerts.filter(a=>a.status!=="resolved").length]];
  const badges = ["online","suspect","offline"].map(s=>'<span class="stat activeness activeness-'+s+'" data-activeness-count="'+s+'"><b>'+counts[s]+"</b> "+s+"</span>").join("");
  root.innerHTML = '<div class="stats">'+stats.map(s=>'<span class="stat"><b>'+s[1]+"</b> "+esc(s[0])+"</span>").join("")+badges+"</div>"
    + "<h3>Groups &amp; Channels</h3>" + table([["Name",r=>r.name],["Kind",r=>d.channels.includes(r)?"channel":"group"],["Creator",r=>r.creator],["Members",r=>d.membersOf(r.id, d.channels.includes(r)).length]], [...d.groups, ...d.channels])
    + "<h3>Recent activity</h3>" + table([["When",r=>pt(r.ts)],["Kind",r=>r.kind],["From",r=>r.actor],["To",r=>r.target||r.group_id||""],["Evidence",r=>r.evidence||"verified"]], d.activity.slice(0,25));
}
