import { esc, pt, table, states, empty, fail, pill } from "../util.js";

// Chains: multi-step work chains — a step releases only on the
// previous step's proven, accepted delivery. Chain and step changes
// are pushed live and repaint the timeline in place.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

function statusPill(s){
  return pill(s || "pending", s === "completed" ? "green" : s === "active" || s === "running" ? "blue" : s === "cancelled" ? "red" : s === "paused" ? "amber" : "grey");
}
function chainHtml(c){
  const done = c.steps.filter(s => s.status === "completed").length;
  return '<div class="card chaincard"><h3>' + esc(c.name || c.id) + " " + statusPill(c.status) + "</h3>" +
    '<p class="sub">creator ' + esc(c.creator) + (c.group_id ? " · group " + esc(c.group_id) : "") + " · " + done + "/" + c.steps.length + " steps proven · created " + pt(c.created_at) + " · updated " + pt(c.updated_at) + "</p>" +
    (c.steps.length ? '<div class="steps">' + c.steps.map(s =>
      '<div class="step"><div class="spos">Step ' + (s.position ?? "") + " " + statusPill(s.status) + '</div><div class="stgt">' +
      esc(s.target_type || "user") + " " + esc(s.target || (s.assignees || []).join(", ")) + '</div><div class="sub">' +
      (s.work_id ? 'work <span class="mono">' + esc(s.work_id) + "</span><br>" : "") +
      (s.deadline ? "deadline " + pt(s.deadline) + "<br>" : "") +
      (s.require_approval ? "approval gate" : "") + "</div></div>").join("") + "</div>"
      : '<p class="state">No steps recorded.</p>') + "</div>";
}

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  root.innerHTML = '<div class="vhead"><h2>Chains</h2><div class="vsub">Multi-step work chains — a step releases only on the previous step\'s proven, accepted delivery. Progress lands here live as steps complete.</div></div>' +
    '<div class="card"><h3>Chains at a glance</h3><div class="glance"></div></div><div class="chainlist"></div>';
  const host = root.querySelector(".chainlist");
  const glance = root.querySelector(".glance");
  const paint = () => {
    const dd = ctx.store.data;
    glance.innerHTML = dd.chains.length ? table(
      [["Chain", c => "<b>" + esc(c.name || c.id) + "</b>"], ["Creator", c => esc(c.creator)], ["Status", c => statusPill(c.status)],
       ["Steps proven", c => c.steps.filter(s => s.status === "completed").length + "/" + c.steps.length],
       ["Updated", c => pt(c.updated_at)]], dd.chains)
      : '<p class="state">No chains yet.</p>';
    host.innerHTML = dd.chains.length ? dd.chains.map(chainHtml).join("") : "";
  };
  paint();
  unsubs.push(ctx.bus.on("chains", paint));
  unsubs.push(ctx.bus.on("work", paint));
  return { destroy };
}
