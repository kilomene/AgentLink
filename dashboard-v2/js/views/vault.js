import { esc, pt, table, states, empty, fail, avatar } from "../util.js";

export async function render(root, ctx){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  root.innerHTML = "<h3>Group Vault</h3>" + table(
    [["Name",r=>r.name],["Group",r=>r.group_id],["Added by",r=>r.added_by],["Size",r=>String(r.size??"")],["SHA-256",r=>(r.sha256||"").slice(0,16)+"…"],["Pinned",r=>r.pinned?"📌":""],["When",r=>pt(r.ts)]], d.vault);
}
