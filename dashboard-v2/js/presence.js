// Presence: Firebase RTDB read-only. /presence/<username> holds
// {beat_at, connected_at, client_version, transport, state} written
// by agents via onDisconnect-backed connections. This module only
// ever reads: it never writes any Firebase path, and no content
// ever travels through Firebase (blueprint law).
//
// The stream below is a server-push subscription (RTDB REST
// streaming): beats arrive the moment agents write them. There is
// NO polling fallback - if the stream drops it reconnects with
// backoff, and the Postgres activeness rows (al_activeness, pushed
// over Supabase Realtime) keep a transition-level truth on screen
// in the meantime. Since 2.3.0 those rows are LOGIN records
// (migration v211): the login Edge's last_seen stamp maintains
// them, so they prove "authenticated, at this time" - never
// liveness. The floor below is freshness-gated for exactly that
// reason.
//
// Display truth is the staleness ladder in js/activeness.js (the
// single source of truth): each user gets a per-user ladder state
// ("online" | "suspect" | "offline") plus its beat age in seconds,
// never just a binary online/offline flag.
import { activenessState, beatAgeSeconds, ONLINE_MAX_AGE_S } from "./activeness.js";

export const UI_TICK_MS = 5000;

let lastData = null;
let lastPresence = {};

// Merge one RTDB REST-streaming "patch" event into the presence
// map. A patch carries a PATH and only the changed subtree at
// that path: a beat arrives as path "/<user>" with data
// {ts: ...} — NOT as a top-level map. The pre-2.0.4 handler
// spread that data over the top level, so every beat after the
// initial snapshot was discarded, the displayed beat age grew
// from the page-load value forever, and the ladder decayed every
// live agent to "offline" 15 seconds after page load (owner
// catch, 2026-11-06). This merge applies the change where the
// path says it belongs:
//   "/"            -> partial top-level map, merged per user
//   "/<user>"      -> partial node, merged into that user
//   "/<user>/<f>"  -> one leaf field set (or deleted when null)
export function mergePresencePatch(presence, path, data){
  const base = { ...(presence || {}) };
  const segs = String(path || "/").split("/").filter(Boolean);
  if(segs.length === 0){
    if(data && typeof data === "object"){
      for(const k of Object.keys(data)) base[k] = data[k];
    }
    return base;
  }
  const head = segs[0];
  if(segs.length === 1){
    if(data === null){ delete base[head]; return base; }
    if(data && typeof data === "object"){
      base[head] = { ...(base[head] || {}), ...data };
    } else {
      base[head] = data;
    }
    return base;
  }
  const node = { ...(base[head] || {}) };
  let cursor = node;
  for(let i = 1; i < segs.length - 1; i++){
    cursor[segs[i]] = { ...(cursor[segs[i]] || {}) };
    cursor = cursor[segs[i]];
  }
  const leaf = segs[segs.length - 1];
  if(data === null) delete cursor[leaf]; else cursor[leaf] = data;
  base[head] = node;
  return base;
}

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
      es.addEventListener("patch", e => { try{ const d = JSON.parse(e.data); if(d && d.data !== undefined) onUpdate(mergePresencePatch(lastPresence, d.path, d.data)); }catch(_){} });
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
    // Postgres login record as the floor: if the RTDB node is
    // missing entirely but the agent authenticated moments ago,
    // do not show a false offline. Freshness-gated (v211): the
    // record's updated_at is the last login stamp, and only a
    // record inside ONLINE_MAX_AGE_S may lift the display - a
    // stale 'online' login record proves nothing about now.
    if(!p && u.activenessMirror && u.activenessMirror.state === "online" && u.activeness === "offline"
       && Number.isFinite(Number(u.activenessMirror.updated_at))
       && now - Number(u.activenessMirror.updated_at) <= ONLINE_MAX_AGE_S){
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
