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
// v242 (2026-11-10) — the merge contract, fixed at the source.
// Two defects made the board serve stale presence/version while
// RTDB held the truth (owner's screenshot: phoenix "offline /
// 2.2.3 / latest" while his node said online / 2.4.1 / 32s):
//   1. There was NO deterministic snapshot: the board depended on
//      the stream's first event landing before the views painted,
//      and fetchPresence() existed but had no caller. The stream
//      now seeds itself with one snapshot read at (re)connect.
//   2. The "put" handler bypassed the merge: it handed the raw
//      event data to applyPresence, which REPLACED each listed
//      user's node wholesale. A subtree "put" (path "/<user>")
//      therefore left every other user at whatever older snapshot
//      the tick still held, and a missed initial put left
//      lastPresence empty forever — the stale DB floor won.
// Every stream event now merges through mergePresencePatch into
// the single in-memory map, and applyPresence is a pure function
// of that map: where a presence node exists it is the ONLY source
// for state, client_version, beat age and last-seen; the registry
// row supplies static identity fields only.
//
// Display truth is the staleness ladder in js/activeness.js (the
// single source of truth): each user gets a per-user ladder state
// ("online" | "suspect" | "offline") plus its beat age in seconds,
// never just a binary online/offline flag.
import { activenessState, beatAgeSeconds, beatTimestampSeconds, ONLINE_MAX_AGE_S } from "./activeness.js";

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

// The stream's current in-memory map (v242): the dataset-swap
// path in app.js re-applies exactly this onto fresh rows, so a
// softReload can never resurrect the login-record floor.
export function currentPresence(){ return lastPresence; }

export function presenceUrl(){ return (window.AGENTLINK_CONFIG||{}).firebaseDbUrl + "/presence.json"; }
export async function fetchPresence(){
  const r = await fetch(presenceUrl()); if(!r.ok) throw new Error("presence read failed ("+r.status+")");
  return (await r.json()) || {};
}
export function streamPresence(onUpdate, onError){
  let stopped = false, es = null, backoff = 2000, retry = null;
  // One event, one path: every put/patch merges into the SAME
  // in-memory map the 5s tick reads, so the display can never be
  // a mix of two snapshots from different moments. A "put" at "/"
  // is a full snapshot of the provided keys (mergePresencePatch
  // semantics); a "put"/"patch" below "/" touches only its path.
  const deliver = (path, data) => {
    if(stopped) return;
    lastPresence = mergePresencePatch(lastPresence, path, data);
    try{ onUpdate(lastPresence); }catch(_){}
  };
  const connect = () => {
    if(stopped) return;
    // Deterministic seed: one snapshot read per (re)connect, so a
    // stream that opens late — or an initial put lost to a proxy
    // hiccup — can never leave the board on the login-record
    // floor while RTDB holds live nodes. This is a connect-time
    // read, not polling: beats still arrive only via the stream.
    fetchPresence()
      .then(snap => { if(!stopped && snap && typeof snap === "object") deliver("/", snap); })
      .catch(() => { /* stream events still seed the map */ });
    try{
      es = new EventSource(presenceUrl());
      es.addEventListener("put", e => { backoff = 2000; try{ const d = JSON.parse(e.data); if(d && d.data !== undefined) deliver(d.path || "/", d.data); }catch(_){} });
      es.addEventListener("patch", e => { try{ const d = JSON.parse(e.data); if(d && d.data !== undefined) deliver(d.path || "/", d.data); }catch(_){} });
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
    // Live layer wins for last-seen too (v242): with a presence
    // node, "last seen" IS the node's beat (epoch seconds, the
    // same scale as al_users.last_seen) — the registry value is
    // only the fallback for an agent with no node at all, where
    // it truthfully reads as its last login. A stale login stamp
    // must never be displayed next to a live agent.
    const beat = p ? beatTimestampSeconds(p, now) : null;
    u.last_seen_live = beat === null ? null : Math.floor(beat);
    u.last_seen_display = beat !== null ? Math.floor(beat) : (u.last_seen ?? null);
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

// ------------------------------------------------ Life Signs
// (2.5.0): /liveness/<username> holds {grade, nature_version,
// persistence_class, last_proof_tier, last_proof_at, daemon_only,
// spec_drift, as_of} — written by the platform's verification
// machinery (the liveness Edge at proof time, the doorbell
// tapper at sweep transitions) from the record layer's truth.
// The dashboard subscribes exactly like presence: server-push,
// seeded by one snapshot per (re)connect, never polled. A node
// whose as_of ages past the staleness bound is displayed AS
// STALE with its age — the last known grade, never dressed as
// current; no node at all reads "unproven".
export const LIVENESS_STALE_S = 180;
let lastLiveness = {};
export function currentLiveness(){ return lastLiveness; }
export function livenessUrl(){ return (window.AGENTLINK_CONFIG||{}).firebaseDbUrl + "/liveness.json"; }
export async function fetchLiveness(){
  const r = await fetch(livenessUrl()); if(!r.ok) throw new Error("liveness read failed ("+r.status+")");
  return (await r.json()) || {};
}
export function streamLiveness(onUpdate, onError){
  let stopped = false, es = null, backoff = 2000, retry = null;
  const deliver = (path, data) => {
    if(stopped) return;
    lastLiveness = mergePresencePatch(lastLiveness, path, data);
    try{ onUpdate(lastLiveness); }catch(_){}
  };
  const connect = () => {
    if(stopped) return;
    fetchLiveness()
      .then(snap => { if(!stopped && snap && typeof snap === "object") deliver("/", snap); })
      .catch(() => { /* stream events still seed the map */ });
    try{
      es = new EventSource(livenessUrl());
      es.addEventListener("put", e => { backoff = 2000; try{ const d = JSON.parse(e.data); if(d && d.data !== undefined) deliver(d.path || "/", d.data); }catch(_){} });
      es.addEventListener("patch", e => { try{ const d = JSON.parse(e.data); if(d && d.data !== undefined) deliver(d.path || "/", d.data); }catch(_){} });
      es.onerror = () => {
        if(es){ es.close(); es = null; }
        if(onError) onError(new Error("liveness stream interrupted"));
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

export function applyLiveness(data, liveness){
  lastLiveness = liveness || {};
  for(const u of [...(data.users||[]), ...(data.testUsers||[])]){
    u.livenessNode = lastLiveness[u.username] || null;
  }
  data.liveness = lastLiveness;
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
