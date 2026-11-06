import { esc, pt, table, states, empty, fail, avatar } from "../util.js";

export async function render(root, ctx){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  root.innerHTML = "<h3>Delivery Library</h3><p>Downloads resolve through Edge oversight presigning; sealed-before-oversight entries show an honest not-downloadable state.</p>" + table(
    [["File",r=>r.filename],["From",r=>r.sender],["To",r=>r.to_user||r.group_id||""],["Size",r=>String(r.size??"")],["SHA-256",r=>(r.sha256||"").slice(0,16)+"…"],["When",r=>pt(r.ts)]], d.library);
}
