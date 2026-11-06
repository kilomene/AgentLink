import { esc, pt, table, states, empty, fail, avatar } from "../util.js";

export async function render(root, ctx){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  root.innerHTML = "<h3>Alerts</h3>" + table([["Kind",r=>r.kind],["Subject",r=>r.subject],["Detail",r=>r.detail],["Status",r=>r.status],["When",r=>pt(r.created_at)]], d.alerts)
    + "<h3>Activity — who is transmitting to whom</h3>" + table([["When",r=>pt(r.ts)],["Kind",r=>r.kind],["From",r=>r.actor],["To",r=>r.target||r.group_id||""],["Status",r=>r.status||""],["Evidence",r=>r.evidence||"verified"]], d.activity.slice(0,200));
}
