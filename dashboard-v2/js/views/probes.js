import { esc, pt, table, states, empty, fail, avatar } from "../util.js";

async function renderChat(root, ctx, convs, label){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  if(!convs(d).length) return empty(root, "No conversations yet.");
  const list = convs(d);
  root.innerHTML = '<div class="chatwrap"><div class="chatlist"><div class="chatlisthead">'+label+'</div>'
    + list.map((c,i)=>'<div class="chatrow" data-i="'+i+'">'+avatar(c.group_id?(c.group_id):(c.participants[0]?.username||c.participants[0]||"?"), !!c.group_id)+'<div class="cmain"><div class="cname">'+esc(c.group_id?c.key.replace("group:",""):c.participants.map(p=>typeof p==="string"?p:p.username).join(" ↔ "))+'</div><div class="cprev">'+c.items.length+' items</div></div></div>').join("")
    + '</div><div class="chatpane" id="chatpane"><div class="chatempty">Select a conversation to watch it live.</div></div></div>';
  root.querySelectorAll(".chatrow").forEach(row=>row.onclick=async()=>{
    const c = list[Number(row.dataset.i)]; const pane = root.querySelector("#chatpane");
    pane.innerHTML = '<div class="chatmsgs">'+c.items.map(m=>'<div class="msgrow"><div class="bubble"><div class="sender">'+esc(m.from||"")+'</div><div class="btext sealed" data-id="'+esc(m.id)+'">🔒 sealed — opening via oversight…</div><div class="bmeta">'+pt(m.ts)+" · "+esc(m.kind)+readTicks(ctx, c, m)+"</div></div></div>").join("")+"</div>";
    // Plaintext arrives only from the Edge oversight function.
    try{ const opened = await ctx.oversight(c.items.filter(m=>m.oversight)); for(const m of c.items){ const o = opened[m.id]; const el = pane.querySelector('[data-id="'+CSS.escape(m.id)+'"]'); if(el && o){ el.textContent = o.text||""; el.classList.remove("sealed"); m.sealed=false; } else if(el){ el.textContent = "🔒 sealed"; } } }catch(e){ pane.querySelectorAll(".btext").forEach(el=>el.textContent="🔒 sealed (oversight unavailable)"); }
  });
}
function readTicks(ctx, c, m){
  const reads = (ctx.cache?.reads||[]).filter(r=>r.message_id===m.id);
  if(!reads.length) return ' <span class="ticks">✓✓</span>';
  return ' <span class="ticks read">✓✓</span> <span class="readby">read by '+reads.map(r=>esc(r.reader)).join(", ")+"</span>";
}

export async function render(root, ctx){
  const host = document.createElement("div"); root.replaceChildren(host);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  host.innerHTML = "<p>🧪 Probe &amp; test agents — kept apart from the production line (filing rule: any party besides the owner seat who is not production-registered files here).</p>"
    + "<h3>Test agents — presence, activity, trust</h3>" + table([["Agent",r=>"@"+r.username],["Presence",r=>r.online?"online":"offline"],["Trust",r=>String(r.trust_score)]], d.testUsers)
    + "<h3>Test work</h3>" + table([["Work",r=>r.id],["Assigner",r=>r.assigner],["Assignee",r=>r.assignee],["Status",r=>r.status]], d.testWork)
    + "<h3>Test agents' credentials</h3><p>Opened via Edge oversight inside this session only — see Credentials view logic scoped to test agents.</p>"
    + table([["Agent",r=>"@"+r.username],["Vault entries",r=>String((r.vault_count??r.connectors?.length)||0)]], d.testUsers);
  const chatHost = document.createElement("div"); root.appendChild(chatHost);
  return renderChat(chatHost, ctx, dd=>dd.testConversations, "Test chats");
}
