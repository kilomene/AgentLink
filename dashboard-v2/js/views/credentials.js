import { esc, pt, table, states, empty, fail, avatar } from "../util.js";

async function renderCreds(root, ctx, users, label){
  states(root); 
  root.innerHTML = "<h3>"+label+"</h3><p>Plaintext exists only inside this authenticated session, returned by the Edge oversight function. Nothing is opened client-side.</p>";
  for(const u of users){
    const sec = document.createElement("div"); sec.innerHTML = "<h4>@"+esc(u.username)+"</h4><p class='state'>Opening vault via oversight…</p>"; root.appendChild(sec);
    try{ const res = await ctx.oversightCredentials(u.username); const entries = res.entries||[];
      sec.innerHTML = "<h4>@"+esc(u.username)+"</h4>" + (entries.length ? table([["Service",r=>r.service||""],["Account",r=>r.account||r.email||r.username||""],["Auth",r=>r.auth_type||""],["Secret",r=>r.secret||""],["Notes",r=>r.notes||""]], entries) : "<p class='state'>No entries, or vault sealed before oversight.</p>");
    }catch(e){ sec.innerHTML = "<h4>@"+esc(u.username)+"</h4><p class='state err'>Oversight unavailable: "+esc(e.message)+"</p>"; }
  }
}

export async function render(root, ctx){ let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); } return renderCreds(root, ctx, d.users, "Agent Credentials"); }
