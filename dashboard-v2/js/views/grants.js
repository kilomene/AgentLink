import { esc, pt, table, states, empty, fail, avatar } from "../util.js";

export async function render(root, ctx){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  root.innerHTML = "<p>OVERSIGHT ONLY — grants are asked by the agent, given by that agent's own owner, agent-side. Nothing here can issue, revoke or approve. Payment instruments are never in scope.</p>"
    + "<h3>Agent Grants &amp; Connector Linkage</h3>" + table([["Agent",r=>"@"+r.username],["Permission",r=>r.grant?r.grant.status:"none"],["Grantor",r=>r.grant?(r.grant.granted_by||""):""],["Connector vault",r=>(r.connectors||[]).map(c=>typeof c==="string"?c:(c.name||c.connector||"")).join(", ")],["Derived capabilities",r=>derived(r.connectors)]], d.users)
    + "<h3>Red-Line Approvals — decided by each agent's owner (display only)</h3>" + table([["When",r=>pt(r.ts)],["Agent",r=>r.username],["Connector",r=>r.connector],["Action",r=>r.action],["Status",r=>r.status]], d.grantApprovals)
    + "<h3>Grant Activity — signed receipts, live</h3>" + table([["When",r=>pt(r.ts)],["Agent",r=>r.username],["Connector",r=>r.connector],["Action",r=>r.action],["Target",r=>r.target],["Status",r=>r.status]], d.grantActivity)
    + "<h3>Grant Activity — Probe Tests</h3>" + table([["When",r=>pt(r.ts)],["Agent",r=>r.username],["Action",r=>r.action],["Status",r=>r.status]], d.testGrantActivity);
}
function derived(conns){ const caps=new Set(); for(const c of conns||[]){ for(const cap of (c.capabilities||c.actions||[])) caps.add(typeof cap==="string"?cap:cap.action||""); } return [...caps].filter(Boolean).join(", ")||"—"; }
