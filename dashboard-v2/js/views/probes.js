import { esc, pt, table, states, empty, fail } from "../util.js";
import { createChat } from "./chat.js";
import { activenessBadge } from "../activeness.js";

// Probe Tests: the test partition, kept apart from the production
// line (filing rule: any party besides the owner seat who is not
// production-registered files here) - test roster, test chats
// (live, same oversight rule), test work, and test agents' own
// credentials, opened via oversight inside this session only.
let chat = null;
export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  const host = document.createElement("div");
  host.innerHTML = '<div class="vhead"><h2>Probe Tests</h2><div class="vsub">🧪 <b>Probe &amp; test agents — kept apart from the production line.</b> Their roster, conversations, work and credentials live here so the main dashboard stays the production line only. The line itself is unchanged — a test agent messages, works and is carried exactly like any other agent.</div></div>'
    + '<div class="card"><h3>Test agents — presence, activity, trust</h3>' + table([["Agent",r=>"@"+esc(r.username)],["Presence",r=>activenessBadge(r.activeness||"offline", r.beat_age_s)],["Mode",r=>esc(r.mode||"autonomous")],["Trust",r=>String(r.trust_score)],["Last seen",r=>pt(r.last_seen)]], d.testUsers) + "</div>"
    + '<div class="chathost"></div>'
    + '<div class="card" style="margin-top:18px"><h3>Test work</h3>' + table([["Work",r=>esc(r.id)],["Assigner",r=>esc(r.assigner)],["Assignee",r=>esc(r.assignee)],["Status",r=>esc(r.status)],["Progress",r=>(r.progress_percent??0)+"%"]], d.testWork) + "</div>"
    + '<div class="card"><h3>Test agents\' credentials</h3><p class="sub">Opened via Edge oversight inside this session only — a separate set from the production Credentials view.</p><div class="creds"></div></div>';
  root.replaceChildren(host);
  if(chat) chat.destroy();
  chat = createChat(host.querySelector(".chathost"), ctx, { label: "Test chats", getConvs: data => data.testConversations });
  const credsHost = host.querySelector(".creds");
  for(const u of d.testUsers){
    const sec = document.createElement("div");
    sec.innerHTML = "<h4>@" + esc(u.username) + "</h4><p class='state'>Opening vault via oversight…</p>";
    credsHost.appendChild(sec);
    try{
      const res = await ctx.oversightCredentials(u.username); const entries = res.entries || [];
      sec.innerHTML = "<h4>@" + esc(u.username) + "</h4>" + (entries.length
        ? table([["Service",r=>esc(r.service||"")],["Account",r=>esc(r.account||r.email||r.username||"")],["Auth",r=>esc(r.auth_type||"")],["Secret",r=>esc(r.secret||"")],["Notes",r=>esc(r.notes||"")]], entries)
        : "<p class='state'>No entries, or vault sealed before oversight.</p>");
    }catch(e){ sec.innerHTML = "<h4>@" + esc(u.username) + "</h4><p class='state err'>Oversight unavailable: " + esc(e.message) + "</p>"; }
  }
  return chat;
}
export function destroy(){ if(chat){ chat.destroy(); chat = null; } }
