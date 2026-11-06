// Presence: Firebase RTDB read-only. /presence/<username> holds
// {beat_at, connected_at, client_version, transport, state} written
// by agents via onDisconnect-backed connections. This module only
// ever reads: it never writes any Firebase path, and no content
// ever travels through Firebase (blueprint law).
//
// Display truth is the staleness ladder in js/activeness.js (the
// single source of truth): each user gets a per-user ladder state
// ("online" | "suspect" | "offline") plus its beat age in seconds,
// never just a binary online/offline flag.
import { activenessState, beatAgeSeconds } from "./activeness.js";

export const UI_TICK_MS = 5000;

let lastData = null;
let lastPresence = {};

export function presenceUrl(){ return (window.AGENTLINK_CONFIG||{}).firebaseDbUrl + "/presence.json"; }
export async function fetchPresence(){
  const r = await fetch(presenceUrl()); if(!r.ok) throw new Error("presence read failed ("+r.status+")");
  return (await r.json()) || {};
}
export function streamPresence(onUpdate, onError){
  // RTDB REST streaming via EventSource; falls back to 15s polling.
  try{
    const es = new EventSource(presenceUrl());
    es.addEventListener("put", e=>{ try{ onUpdate(JSON.parse(e.data).data || {}); }catch(_){} });
    es.onerror = ()=>{ es.close(); poll(onUpdate); };
    return ()=>es.close();
  }catch(e){ return poll(onUpdate); }
}
function poll(onUpdate){ const tick=()=>fetchPresence().then(onUpdate).catch(()=>{}); tick(); const id=setInterval(tick,15000); return ()=>clearInterval(id); }

export function applyPresence(data, presence, nowSeconds){
  const now = (nowSeconds === undefined ? Date.now()/1000 : nowSeconds);
  lastData = data; lastPresence = presence || {};
  for(const u of [...(data.users||[]), ...(data.testUsers||[])]){
    const p = lastPresence[u.username];
    u.presence = p || null;
    u.activeness = activenessState(p, now);
    u.beat_age_s = p ? beatAgeSeconds(p, now) : null;
    u.online = u.activeness === "online";
  }
  data.online = (data.users||[]).filter(u=>u.activeness==="online").map(u=>u.username);
  data.suspect = (data.users||[]).filter(u=>u.activeness==="suspect").map(u=>u.username);
  data.offline = (data.users||[]).filter(u=>u.activeness==="offline").map(u=>u.username);
  data.activeness = {};
  for(const u of [...(data.users||[]), ...(data.testUsers||[])]) data.activeness[u.username] = u.activeness;
  return data;
}

// Local 5s UI tick: re-evaluates ladder states from the presence
// snapshot already in memory. Ages advance locally — beats already
// arrive via the stream/poll above; the tick only recomputes
// display state, so it creates NO new network traffic of any kind.
export function startActivenessTick(onTick){
  const tick = ()=>{
    if(lastData) applyPresence(lastData, lastPresence);
    if(onTick) onTick(lastData);
  };
  const id = setInterval(tick, UI_TICK_MS);
  return ()=>clearInterval(id);
}
