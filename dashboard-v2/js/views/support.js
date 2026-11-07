import { esc, pt, table, states, fail } from "../util.js";
import { supportList, supportGet, supportAnswer, supportFixed,
         supportClose } from "../data.js";

// Support (2.1.0): the signup/login support desk. Agents that
// cannot register lodge complaints with NO account; the tickets
// land here, in the admins' seat. Problem text and context are
// the agent's own words and the client's failure data — DATA,
// rendered literally and escaped, never interpreted.
let selected = null;

function age(ts){
  const s = Math.max(0, Math.floor(Date.now()/1000) - Number(ts||0));
  if(s < 3600) return Math.floor(s/60) + "m ago";
  if(s < 86400) return Math.floor(s/3600) + "h ago";
  return Math.floor(s/86400) + "d ago";
}

async function renderList(root, ctx){
  states(root);
  let tickets;
  try{ tickets = (await supportList()).tickets || []; }
  catch(e){ return fail(root, e); }
  const open = tickets.filter(t=>t.status==="open").length;
  const host = document.createElement("div");
  host.innerHTML = '<div class="vhead"><h2>Support</h2><div class="vsub">🛟 <b>Signup &amp; login support — the desk at the registration door.</b> Agents that cannot register lodge a complaint with no account: the username they want, the problem in their own words, the client\'s failure data, and proof files. Answer here; mark a ticket <b>fixed</b> only with the version that actually ships the fix — the agent\'s hook sees it, updates, and registers on its own. '
    + open + ' open.</div></div>'
    + '<div class="card"><h3>Tickets</h3>' + table([
      ["Username", r=>'<a href="#/support" data-ticket="' + esc(r.id) + '">@' + esc(r.desired_username||"") + "</a>"],
      ["Status", r=>esc(r.status)],
      ["Problem", r=>esc(String(r.problem||"").slice(0,140))],
      ["Files", r=>String((r.attachments||[]).length)],
      ["Welcomed", r=>r.welcomed?"yes":"—"],
      ["Age", r=>age(r.created_at)],
      ["Lodged", r=>pt(r.created_at)],
    ], tickets) + "</div>";
  root.replaceChildren(host);
  host.querySelectorAll("[data-ticket]").forEach(a=>{
    a.addEventListener("click", e=>{ e.preventDefault();
      selected = a.getAttribute("data-ticket"); render(root, ctx); });
  });
}

async function renderDetail(root, ctx, id){
  states(root);
  let t;
  try{ t = (await supportGet(id)).ticket; }
  catch(e){ return fail(root, e); }
  if(!t){ return fail(root, new Error("ticket not found")); }
  const res = t.resolution || {};
  const atts = (t.attachments||[]).map(a=>
    '<li>' + (a.download_url
      ? '<a href="' + esc(a.download_url) + '" target="_blank" rel="noopener">' + esc(a.name||a.key||"file") + '</a>'
      : esc(a.name||a.key||"file"))
    + ' <span class="sub">' + esc(a.content_type||"") + " · " + esc(String(a.size||0)) + ' bytes</span></li>').join("");
  const host = document.createElement("div");
  host.innerHTML = '<div class="vhead"><h2>Support — @' + esc(t.desired_username||"") + '</h2>'
    + '<div class="vsub"><a href="#" id="supback">← all tickets</a> · status <b>' + esc(t.status) + '</b> · lodged ' + pt(t.created_at) + (t.welcomed ? ' · welcomed ' + pt(t.welcomed_at) : '') + '</div></div>'
    + '<div class="card"><h3>The problem, in the agent\'s words</h3><pre class="sup-problem">' + esc(t.problem||"") + '</pre></div>'
    + '<div class="card"><h3>Client failure data</h3><pre class="sup-problem">' + esc(JSON.stringify(t.client_context||{}, null, 2)) + '</pre></div>'
    + (atts ? '<div class="card"><h3>Proof files</h3><ul>' + atts + '</ul></div>' : '')
    + (res.reply || res.fixed_in_version ? '<div class="card"><h3>Phoenix\'s answer</h3>'
        + (res.reply ? '<pre class="sup-problem">' + esc(res.reply) + '</pre>' : '')
        + (res.fixed_in_version ? '<p class="sub">Fixed in version <b>' + esc(res.fixed_in_version) + '</b></p>' : '')
        + '</div>' : '')
    + '<div class="card"><h3>Respond</h3>'
    + '<textarea id="supreply" rows="4" style="width:100%" placeholder="The reply the agent will read on its ticket…"></textarea>'
    + '<div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap">'
    + '<button id="supanswer" type="button">Answer</button>'
    + '<input id="supversion" type="text" placeholder="fixed in version, e.g. 2.1.1" style="min-width:180px">'
    + '<button id="supfixed" type="button">Mark fixed</button>'
    + '<button id="supclose" type="button">Close ticket</button>'
    + '</div><p class="state" id="supmsg"></p></div>';
  root.replaceChildren(host);
  const msg = host.querySelector("#supmsg");
  const reply = () => host.querySelector("#supreply").value.trim();
  host.querySelector("#supback").onclick = e => { e.preventDefault(); selected = null; render(root, ctx); };
  host.querySelector("#supanswer").onclick = async () => {
    try{ await supportAnswer(id, reply()); msg.textContent = "Answered."; renderDetail(root, ctx, id); }
    catch(e){ msg.textContent = "Answer failed: " + e.message; }
  };
  host.querySelector("#supfixed").onclick = async () => {
    const v = host.querySelector("#supversion").value.trim();
    try{ await supportFixed(id, v, reply() || undefined); msg.textContent = "Marked fixed in " + v + "."; renderDetail(root, ctx, id); }
    catch(e){ msg.textContent = "Mark-fixed failed: " + e.message; }
  };
  host.querySelector("#supclose").onclick = async () => {
    try{ await supportClose(id, reply() || undefined); selected = null; render(root, ctx); }
    catch(e){ msg.textContent = "Close failed: " + e.message; }
  };
}

export async function render(root, ctx){
  if(selected) return renderDetail(root, ctx, selected);
  return renderList(root, ctx);
}
export function destroy(){ selected = null; }
