import { esc, pt, table, states, empty, fail, avatar } from "../util.js";

export async function render(root, ctx){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  if(!d.chains.length) return empty(root, "No chains yet.");
  root.innerHTML = d.chains.map(c=>"<h3>"+esc(c.name||c.id)+"</h3><p><small>creator "+esc(c.creator)+" · status "+esc(c.status)+"</small></p>"
    + table([["Step",r=>String(r.position)],["Target",r=>r.target_type+" "+(r.target||"")],["Assignees",r=>(r.assignees||[]).join(", ")],["Status",r=>r.status||""],["Deadline",r=>pt(r.deadline)]], c.steps)).join("");
}
