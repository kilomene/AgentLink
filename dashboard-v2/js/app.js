
import * as v_overview from "./views/overview.js";
import * as v_agents from "./views/agents.js";
import * as v_conversations from "./views/conversations.js";
import * as v_probes from "./views/probes.js";
import * as v_activity from "./views/activity.js";
import * as v_work from "./views/work.js";
import * as v_chains from "./views/chains.js";
import * as v_library from "./views/library.js";
import * as v_vault from "./views/vault.js";
import * as v_credentials from "./views/credentials.js";
import * as v_grants from "./views/grants.js";
import * as v_rooms from "./views/rooms.js";
import { session, login, clearSession, loadAll, oversightOpen, oversightCredentials } from "./data.js";
import { streamPresence, applyPresence, startActivenessTick } from "./presence.js";
import { activenessLabel } from "./activeness.js";
const VIEWS = { overview: v_overview,agents: v_agents,conversations: v_conversations,probes: v_probes,activity: v_activity,work: v_work,chains: v_chains,library: v_library,vault: v_vault,credentials: v_credentials,grants: v_grants,rooms: v_rooms };
const ORDER = ["overview","agents","conversations","probes","activity","work","chains","library","vault","credentials","grants","rooms"];
let cache = null, cacheAt = 0, inflight = null;
const ctx = { cache:null, getData: async()=>{ if(cache && Date.now()-cacheAt<5000) return cache; if(!inflight) inflight = loadAll().then(d=>{cache=d; ctx.cache=d; cacheAt=Date.now(); inflight=null; return d;}).catch(e=>{inflight=null; throw e;}); return inflight; }, oversight: oversightOpen, oversightCredentials, data:null };
ctx.data = ctx; // views access membersOf via ctx.data
function route(){ const name = (location.hash.replace("#/","").split("/")[0]) || "overview"; return ORDER.includes(name)?name:"overview"; }
async function applyRoute(){ const name = route();
  document.querySelectorAll(".view").forEach(s=>s.classList.toggle("active", s.id==="view-"+name));
  document.querySelectorAll(".navitem").forEach(a=>a.classList.toggle("active", a.dataset.route===name));
  if(window.innerWidth<=900) document.getElementById("drawer").classList.add("closed");
  const body = document.querySelector("#view-"+name+" .viewbody");
  try{ await VIEWS[name].render(body, ctx); }catch(e){ body.innerHTML='<p class="state err">'+e.message+"</p>"; }
}
window.addEventListener("hashchange", applyRoute);
// Repaint activeness badges / beat ages / counts in place from the
// cached roster — used by the local 5s UI tick; no data is refetched.
function paintActiveness(){
  if(!cache) return;
  const byUser = {}; [...(cache.users||[]), ...(cache.testUsers||[])].forEach(u=>{ byUser[u.username]=u; });
  document.querySelectorAll("[data-activeness-user]").forEach(el=>{ const u = byUser[el.dataset.activenessUser]; if(!u) return;
    el.className = "activeness activeness-" + u.activeness; el.textContent = activenessLabel(u.activeness, u.beat_age_s); });
  document.querySelectorAll("[data-beat-age-user]").forEach(el=>{ const u = byUser[el.dataset.beatAgeUser]; if(!u) return;
    el.textContent = (u.beat_age_s === null || u.beat_age_s === undefined) ? "—" : u.beat_age_s + "s ago"; });
  document.querySelectorAll("[data-activeness-count]").forEach(el=>{ const s = el.dataset.activenessCount;
    const n = (cache.users||[]).filter(u=>u.activeness===s).length; const b = el.querySelector("b"); if(b) b.textContent = n; });
}
let tickStarted = false;
function showShell(){ document.getElementById("login").hidden=true; document.getElementById("shell").hidden=false; applyRoute();
  streamPresence(async p=>{ if(cache){ applyPresence(cache,p); paintActiveness(); } }, ()=>{});
  if(!tickStarted){ tickStarted = true; startActivenessTick(()=>paintActiveness()); } }
document.getElementById("loginform").addEventListener("submit", async e=>{ e.preventDefault();
  try{ await login(document.getElementById("pw").value); showShell(); }catch(err){ document.getElementById("loginerr").textContent = err.message; } });
document.getElementById("logout").onclick = ()=>{ clearSession(); location.reload(); };
document.getElementById("navtoggle").onclick = ()=>document.getElementById("drawer").classList.toggle("closed");
if(session()) showShell();
