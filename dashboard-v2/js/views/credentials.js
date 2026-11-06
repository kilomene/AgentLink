import { esc, states, fail, table, pill } from "../util.js";

// Credentials: each agent's own credentials vault - the accounts
// it created and the auth it saved - shown in full (service,
// account, secret, auth type) inside this authenticated operator
// session only. Entries arrive exclusively from the Edge oversight
// function; the browser holds no key material and opens nothing
// locally. A "Re-open" control per agent re-fetches that agent's
// entries through oversight on demand.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

async function renderCreds(root, ctx, users, label){
  root.innerHTML = '<div class="vhead"><h2>' + esc(label) + '</h2><div class="vsub">Each agent\'s own credentials vault, shown in full — service, account, secret and auth type. Plaintext exists only here, inside your authenticated session: entries are sealed to the owner-oversight key end to end, stores hold ciphertext only, and no agent can open this dashboard. This is NOT the group Vault — that is shared group files.</div></div>';
  const host = document.createElement("div");
  root.appendChild(host);
  if(!users.length){ host.innerHTML = '<p class="state">No agents in this partition.</p>'; return; }
  for(const u of users){
    const sec = document.createElement("div");
    sec.className = "card";
    sec.innerHTML = "<h3>@" + esc(u.username) + ' <button type="button" class="reopen" style="float:right">Re-open via oversight</button></h3><div class="entries"><p class="state">Opening vault via oversight…</p></div>';
    host.appendChild(sec);
    const entriesHost = sec.querySelector(".entries");
    const load = async () => {
      entriesHost.innerHTML = '<div class="skel skelrow"></div><div class="skel skelrow" style="width:84%"></div>';
      try{
        const res = await ctx.oversightCredentials(u.username); const entries = res.entries || [];
        entriesHost.innerHTML = entries.length
          ? table([["Service", r => "<b>" + esc(r.service || "") + "</b>"], ["Account", r => esc(r.account || r.email || r.username || "")], ["Auth", r => pill(r.auth_type || "password", "blue")], ["Secret", r => '<span class="mono">' + esc(r.secret || "") + "</span>"], ["Notes", r => esc(r.notes || "")]], entries)
          : "<p class='state'>No entries, or this agent's vault was sealed before oversight existed.</p>";
      }catch(e){ entriesHost.innerHTML = "<p class='state err'>Oversight unavailable: " + esc(e.message) + "</p>"; }
    };
    sec.querySelector(".reopen").onclick = load;
    load();
  }
}

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  await renderCreds(root, ctx, d.users, "Credentials");
  return { destroy };
}
