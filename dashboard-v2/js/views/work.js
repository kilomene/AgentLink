import { esc, pt, table, states, empty, fail, avatar } from "../util.js";

export async function render(root, ctx){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  root.innerHTML = "<h3>Work — progress, deadlines (PT), proofs</h3>" + table(
    [["Work",r=>r.id],["Assigner",r=>r.assigner],["Assignee",r=>r.assignee],["Status",r=>r.status],["Progress",r=>(r.progress_percent??0)+"%"],["Deadline",r=>pt(r.deadline)],["Countdown",r=>countdown(r)],["Proof",r=>r.proof_verified?"verified":(r.proof_hash?"pending":"—")],["Approval",r=>r.require_approval?"🔒 gate":"—"]], d.work);
}
function countdown(w){ if(!w.deadline) return ""; if(w.status==="completed") return "done"; const left=w.deadline-Math.floor(Date.now()/1000); return left<0 ? "overdue "+Math.floor(-left/60)+"m" : Math.floor(left/60)+"m left"; }
