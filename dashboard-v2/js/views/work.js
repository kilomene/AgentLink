import { esc, pt, table, states, fail, pill, countdown } from "../util.js";

// Work: the live pipeline. Assignments move across the board as
// their status changes are pushed (assigned → in flight → delivered
// → awaiting approval → completed), with progress, Pacific
// deadlines with live countdowns, signed-proof state and approval
// gates. Below the board, the full table and the delivery records.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

const COLS = [["assigned", "Assigned"], ["in_progress", "In progress"], ["delivered", "Delivered"], ["awaiting_approval", "Awaiting approval"], ["completed", "Completed"]];
function colOf(w){
  if(w.status === "completed" || w.status === "covered") return "completed";
  if(w.status === "awaiting_approval") return "awaiting_approval";
  if(w.status === "delivered") return "delivered";
  if(w.status === "assigned" || w.status === "awaiting_agent") return "assigned";
  return "in_progress";
}
function proofPill(w){
  if(w.proof_verified) return pill("proof verified ✓", "verified");
  if(w.proof_hash) return pill("proof pending", "amber");
  return pill("no proof yet", "grey");
}
function cardHtml(w){
  return '<div class="wcard" data-work="' + esc(w.id) + '"><div class="wid">' + esc(w.id) + "</div>" +
    '<div class="wroute">' + esc(w.assigner) + " → " + esc(w.assignee) + (w.group_id ? " · " + esc(w.group_id) : "") + "</div>" +
    '<div class="progressbar"><i style="width:' + (w.progress_percent ?? 0) + '%"></i></div>' +
    '<div class="wmeta">' + pill((w.progress_percent ?? 0) + "%", "grey") +
    (w.deadline ? '<span class="pill ' + (w.deadline < Date.now() / 1000 && w.status !== "completed" ? "red" : "grey") + '" data-countdown="' + esc(w.id) + '">' + countdown(w) + "</span>" : "") +
    proofPill(w) + (w.require_approval ? pill("🔒 approval gate", "gate") : "") +
    (w.priority && w.priority !== "normal" ? pill(w.priority, "pink") : "") + "</div></div>";
}

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  root.innerHTML = '<div class="vhead"><h2>Work</h2><div class="vsub">Assignments across the line — live progress, Pacific deadlines, signed delivery proofs, approval gates. Cards move between columns the moment a status change is pushed; nothing here can assign, deliver or approve (monitor only).</div></div>' +
    '<div class="pipeline"></div>' +
    '<div class="card"><h3>All work</h3><div class="allwork"></div></div>' +
    '<div class="card"><h3>Deliveries — signed proof records</h3><div class="deliveries"></div></div>';
  const pipe = root.querySelector(".pipeline");
  const allHost = root.querySelector(".allwork");
  const delHost = root.querySelector(".deliveries");
  const paint = () => {
    const dd = ctx.store.data;
    pipe.innerHTML = COLS.map(([key, label]) => {
      const items = dd.work.filter(w => colOf(w) === key);
      return '<div class="pipe-col"><h4>' + label + '<span class="n">' + items.length + "</span></h4>" +
        (items.map(cardHtml).join("") || '<p class="state">—</p>') + "</div>";
    }).join("");
    allHost.innerHTML = dd.work.length ? table(
      [["Work", w => '<span class="mono">' + esc(w.id) + "</span>"], ["Assigner", w => esc(w.assigner)], ["Assignee", w => esc(w.assignee)],
       ["Status", w => pill(w.status, w.status === "completed" ? "green" : w.status === "awaiting_approval" ? "amber" : "blue")],
       ["Progress", w => '<span class="progressbar"><i style="width:' + (w.progress_percent ?? 0) + '%"></i></span> ' + (w.progress_percent ?? 0) + "%"],
       ["Deadline (PT)", w => pt(w.deadline)], ["Countdown", w => countdown(w)], ["Proof", w => proofPill(w)],
       ["Approval", w => w.require_approval ? pill("🔒 gate", "gate") : "—"]], dd.work)
      : '<p class="state">No work yet.</p>';
    const byWork = {}; dd.work.forEach(w => { byWork[w.id] = w; });
    delHost.innerHTML = dd.deliveries.length ? table(
      [["Delivery", x => '<span class="mono">' + esc(x.id) + "</span>"], ["Work", x => '<span class="mono">' + esc(x.work_id) + "</span>"],
       ["Deliverer", x => esc(x.deliverer)], ["When", x => pt(x.ts)],
       ["Work status", x => byWork[x.work_id] ? pill(byWork[x.work_id].status, "grey") : "—"],
       ["Proof", x => byWork[x.work_id] ? proofPill(byWork[x.work_id]) : "—"]], dd.deliveries.slice(0, 60))
      : '<p class="state">No deliveries recorded yet.</p>';
  };
  paint();
  unsubs.push(ctx.bus.on("work", paint));
  return { destroy };
}
