import { esc, pt, table, states, fail, pill, parseJson } from "../util.js";

// Connector Grants - OVERSIGHT ONLY. The grant is asked by the
// agent, given ONCE by that agent's own owner, agent-side; it then
// covers the agent's connector vault. This page shows linkage:
// grant state, grantor, linked connectors, the capabilities those
// connectors confer, red-line approvals (display only - the
// decision happens with the agent's owner) and the signed receipt
// feed, which is pushed live. Payment instruments are never in
// scope: no connector, grant or code path touches credit/ATM cards.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

function derived(conns){
  const caps = new Set();
  for(const c of conns || []){
    if(typeof c === "string"){ caps.add(c); continue; }
    for(const cap of (c.capabilities || c.actions || [])) caps.add(typeof cap === "string" ? cap : (cap.action || cap.name || ""));
    if(c.name && !(c.capabilities || c.actions)) caps.add(c.name);
  }
  return [...caps].filter(Boolean);
}
function connNames(conns){
  return (conns || []).map(c => typeof c === "string" ? c : (c.name || c.connector || "")).filter(Boolean);
}

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  root.innerHTML = '<div class="vhead"><h2>Connector Grants</h2><div class="vsub">The one-time admin permission — <b>oversight only</b>. The agent asks its own user, agent-side; the user allows it once, there. Nothing on this page can issue, revoke or approve. <b>Payment instruments are never in scope.</b></div></div>' +
    '<div class="card"><h3>Agent Grants &amp; Connector Linkage</h3><div class="linkage"></div></div>' +
    '<div class="card"><h3>Red-Line Approvals — decided by each agent\'s owner (display only)</h3><div class="approvals"></div></div>' +
    '<div class="card"><h3><span class="live-dot"></span> Grant Activity — signed receipts, live</h3><div class="receipts"></div></div>' +
    '<div class="card"><h3>Grant Activity — Probe Tests</h3><div class="testreceipts"></div></div>';
  const paint = () => {
    const dd = ctx.store.data;
    root.querySelector(".linkage").innerHTML = table(
      [["Agent", r => "<b>@" + esc(r.username) + "</b>"], ["Permission", r => r.grant ? pill(r.grant.status, r.grant.status === "active" ? "green" : "amber") : pill("none", "grey")],
       ["Grantor", r => esc(r.grant ? (r.grant.granted_by || "") : "")], ["Granted", r => r.grant ? pt(r.grant.granted_at) : ""],
       ["Connector vault", r => connNames(r.connectors).map(esc).join(", ") || "—"],
       ["Derived capabilities", r => derived(r.connectors).map(c => pill(c, "blue")).join(" ") || "—"],
       ["Scopes", r => (parseJson(r.grant?.scopes, []) || []).map(esc).join(", ")]], dd.users);
    root.querySelector(".approvals").innerHTML = table(
      [["When", r => pt(r.ts)], ["Agent", r => "@" + esc(r.username)], ["Connector", r => esc(r.connector)], ["Action", r => esc(r.action)], ["Target", r => esc(r.target || "")],
       ["Status", r => pill(r.status, r.status === "approved" ? "green" : r.status === "rejected" ? "red" : "amber")], ["Decided by", r => esc(r.decided_by || "")]], dd.grantApprovals);
    const recCols = [["When", r => pt(r.ts)], ["Agent", r => "@" + esc(r.username)], ["Connector", r => esc(r.connector)], ["Action", r => esc(r.action)], ["Target", r => esc(r.target || "")],
      ["Status", r => pill(r.status, r.status === "ok" || r.status === "success" ? "green" : "grey")], ["Signed", r => r.sig ? pill("signed ✓", "verified") : pill("unsigned", "claimed")]];
    root.querySelector(".receipts").innerHTML = table(recCols, dd.grantActivity.slice(0, 80));
    root.querySelector(".testreceipts").innerHTML = table(recCols, dd.testGrantActivity.slice(0, 40));
  };
  paint();
  unsubs.push(ctx.bus.on("grants", paint));
  unsubs.push(ctx.bus.on("users", paint));
  return { destroy };
}
