// Presence: Firebase RTDB read-only. /presence/<username> holds
// {beat_at, connected_at, client_version, transport, state} written
// by agents via onDisconnect-backed connections. This module only
// ever reads: it never writes any Firebase path, and no content
// ever travels through Firebase (blueprint law).
//
// The stream below is a server-push subscription (RTDB REST
// streaming): beats arrive the moment agents write them. There is
// NO polling fallback - if the stream drops it reconnects with
// backoff, and the Postgres activeness mirror (al_activeness,
// pushed over Supabase Realtime) keeps a transition-level truth on
// screen in the meantime.
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
  let stopped = false, es = null, backoff = 2000, retry = null;
  const connect = () => {
    if(stopped) return;
    try{
      es = new EventSource(presenceUrl());
      es.addEventListener("put", e => { backoff = 2000; try{ onUpdate(JSON.parse(e.data).data || {}); }catch(_){} });
      es.addEventListener("patch", e => { try{ const d = JSON.parse(e.data); if(d && d.data) onUpdate({ ...lastPresence, ...d.data }); }catch(_){} });
      es.onerror = () => {
        if(es){ es.close(); es = null; }
        if(onError) onError(new Error("presence stream interrupted"));
        if(!stopped){ retry = setTimeout(connect, backoff); backoff = Math.min(backoff * 2, 30000); }
      };
    }catch(err){
      if(onError) onError(err);
      if(!stopped){ retry = setTimeout(connect, backoff); backoff = Math.min(backoff * 2, 30000); }
    }
  };
  connect();
  return () => { stopped = true; if(retry) clearTimeout(retry); if(es) es.close(); };
}

export function applyPresence(data, presence, nowSeconds){
  const now = (nowSeconds === undefined ? Date.now()/1000 : nowSeconds);
  lastData = data; lastPresence = presence || {};
  for(const u of [...(data.users||[]), ...(data.testUsers||[])]){
    const p = lastPresence[u.username];
    u.presence = p || null;
    u.activeness = activenessState(p, now);
    u.beat_age_s = p ? beatAgeSeconds(p, now) : null;
    u.online = u.activeness === "online";
    // Postgres transition mirror as the floor: if the RTDB node is
    // missing entirely but the mirror says the agent transitioned
    // to online moments ago, do not show a false offline.
    if(!p && u.activenessMirror && u.activenessMirror.state === "online" && u.activeness === "offline"){
      u.activeness = "suspect";
    }
  }
  data.online = (data.users||[]).filter(u=>u.activeness==="online").map(u=>u.username);
  data.suspect = (data.users||[]).filter(u=>u.activeness==="suspect").map(u=>u.username);
  data.offline = (data.users||[]).filter(u=>u.activeness==="offline").map(u=>u.username);
  data.activeness = {};
  for(const u of [...(data.users||[]), ...(data.testUsers||[])]) data.activeness[u.username] = u.activeness;
  return data;
}

// Local 5s UI tick: re-evaluates ladder states from the presence
// snapshot already in memory. Ages advance locally - beats already
// arrive via the stream above; the tick only recomputes
// display state, so it creates NO new network traffic of any kind.
export function startActivenessTick(onTick){
  const tick = ()=>{
    if(lastData) applyPresence(lastData, lastPresence);
    if(onTick) onTick(lastData);
  };
  const id = setInterval(tick, UI_TICK_MS);
  return ()=>clearInterval(id);
}
