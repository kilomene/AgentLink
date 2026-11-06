
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
import { session, login, clearSession, loadAll, oversightOpen, oversightCredentials, oversightFile, oversightVaultFile, oversightLibraryFile, ensureFreshJwt } from "./data.js";
import { streamPresence, applyPresence, startActivenessTick } from "./presence.js";
import { startRealtime, onRtState, rtState, setRealtimeJwt, stopRealtime } from "./realtime.js";
import { store, on as busOn } from "./store.js";
import { activenessLabel } from "./activeness.js";
import { toast } from "./util.js";
const VIEWS = { overview: v_overview,agents: v_agents,conversations: v_conversations,probes: v_probes,activity: v_activity,work: v_work,chains: v_chains,library: v_library,vault: v_vault,credentials: v_credentials,grants: v_grants,rooms: v_rooms };
const ORDER = ["overview","agents","conversations","probes","activity","work","chains","library","vault","credentials","grants","rooms"];
let cache = null, inflight = null, currentView = null, booted = false;
const ctx = { store, bus: { on: busOn },
  getData: async () => { if(store.data) return store.data; if(!inflight) inflight = loadAll().then(d => { store.setData(d); cache = d; inflight = null; return d; }).catch(e => { inflight = null; throw e; }); return inflight; },
  oversight: oversightOpen, oversightCredentials, oversightFile, oversightVaultFile, oversightLibraryFile, data: null };
ctx.data = ctx; // legacy accessor: views reach store.data via ctx.getData()

function route(){ const name = (location.hash.replace("#/","").split("/")[0]) || "overview"; return ORDER.includes(name)?name:"overview"; }
async function applyRoute(){
  const name = route();
  if(currentView && VIEWS[currentView]?.destroy) { try{ VIEWS[currentView].destroy(); }catch(_){} }
  currentView = name;
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

function paintBadges(){
  if(!store.data) return;
  const set = (name, n) => { const el = document.querySelector('[data-navbadge="'+name+'"]'); if(!el) return;
    el.textContent = n > 99 ? "99+" : String(n); el.classList.toggle("hidden", !n); };
  set("conversations", store.unreadTotal());
  set("activity", (store.data.alerts||[]).filter(a=>a.status!=="resolved").length);
  set("work", (store.data.work||[]).filter(w=>w.status!=="completed" && w.status!=="cancelled").length);
}

const LIVE_TEXT = { live: "live — real-time push", connecting: "connecting…", reconnecting: "reconnecting…", offline: "offline — stream down" };
function paintLiveState(s){
  const rt = rtState();
  const pending = rt.pending || [];
  document.querySelectorAll("[data-livestate]").forEach(el=>{
    el.className = s;
    const t = el.querySelector(".ltxt");
    if(t) t.textContent = (LIVE_TEXT[s] || s) + (s === "live" && pending.length ? " · " + pending.length + " feeds pending migration" : "");
    el.title = pending.length ? "Feeds awaiting supabase_realtime publication: " + pending.join(", ")
      : (rt.unconfirmed && rt.unconfirmed.length ? "Core feeds live. Not yet confirmed by traffic: " + rt.unconfirmed.join(", ") : "All feeds subscribed and confirmed by traffic");
  });
}

async function softReload(){
  if(inflight) return;
  const oldUnread = new Map(store.unread), oldMark = new Map(store.readMark);
  try{
    const d = await loadAll();
    store.setData(d); cache = d;
    // Preserve unread badges the operator has not yet cleared.
    oldUnread.forEach((n, key) => { if(n > 0){ const c = store.findConv(key); if(c && (c.lastTs||0) > (oldMark.get(key)||0)) store.unread.set(key, n); } });
    paintBadges();
    const name = route();
    if(VIEWS[name]?.render){ const body = document.querySelector("#view-"+name+" .viewbody"); await VIEWS[name].render(body, ctx); }
  }catch(_){ /* stream state already reports connectivity honestly */ }
}

let tickStarted = false, jwtTimer = null;
async function showShell(){
  document.getElementById("boot").hidden = true;
  document.getElementById("login").hidden = true;
  document.getElementById("shell").hidden = false;
  // Route FIRST: the view the operator was on (hash route) paints
  // immediately — skeletons while data loads — instead of sitting
  // on the drawer/menu until the full data load lands. On mobile
  // the drawer starts closed (its HTML default), so a reload
  // returns to the exact view, never to an open side menu.
  applyRoute();
  await ensureFreshJwt();
  try{ const d = await ctx.getData(); cache = d; }catch(e){ /* views surface the error */ }
  paintBadges();
  if(booted) return; booted = true;
  streamPresence(p => { if(store.data){ applyPresence(store.data, p); cache = store.data; paintActiveness(); } },
    () => { /* RTDB stream hiccup: it reconnects itself; the mirror + ladder stay truthful */ });
  if(!tickStarted){ tickStarted = true; startActivenessTick(() => paintActiveness()); }
  onRtState(paintLiveState);
  startRealtime({
    onEvent: ev => {
      store.applyEvent(ev);
      if(ev.table === "al_queue" && ev.row){
        const pl = ev.row.payload || {};
        const from = pl.from || pl.sender || "";
        if(from && store.openConvKey == null) toast("New message", from + " → " + (ev.row.to_username || ""), () => { location.hash = "#/conversations"; });
      }
    },
    onResync: () => softReload()
  });
  busOn("badges", paintBadges);
  busOn("unread", paintBadges);
  if(!jwtTimer) jwtTimer = setInterval(async () => { const s = await ensureFreshJwt(); if(s && s.jwt) setRealtimeJwt(s.jwt); }, 240000);
}
document.getElementById("loginform").addEventListener("submit", async e=>{ e.preventDefault();
  const btn = e.target.querySelector("button"); btn.disabled = true; btn.textContent = "Logging in…";
  try{ await login(document.getElementById("pw").value); await showShell(); }
  catch(err){ document.getElementById("loginerr").textContent = err.message; btn.disabled = false; btn.textContent = "Log in"; } });
document.getElementById("logout").onclick = async ()=>{
  const s = session();
  if(s){ try{ await fetch((window.AGENTLINK_CONFIG||{}).edgeBase + "/dashboard-login", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({action:"logout", session_token: s.token})}); }catch(_){} }
  await stopRealtime(); clearSession(); location.reload();
};
document.getElementById("navtoggle").onclick = ()=>document.getElementById("drawer").classList.toggle("closed");
// Boot: the splash (#boot) is the only thing painted until the
// session state is known — the login form NEVER flashes on a
// reload with a trusted device, and with no session the splash
// hands straight over to the login form.
if(session()) showShell();
else { document.getElementById("boot").hidden = true; document.getElementById("login").hidden = false; }
