// Real-time core: Supabase Realtime postgres_changes, authenticated
// with the operator JWT. This replaces ALL polling - every view
// updates in place from pushed row changes. RLS decides what the
// operator may see, exactly as for PostgREST reads: the JWT is set
// as the realtime access token, so the same operator SELECT policies
// are evaluated before any event is delivered.
//
// One channel PER TABLE, deliberately: Realtime rejects a channel's
// postgres_changes bindings wholesale when any bound table is not a
// member of the supabase_realtime publication (verified live
// 2026-11-05: one unpublished table in a shared channel silenced
// every binding, published ones included). Per-table channels keep
// each feed independent: published tables flow today; a table whose
// publication membership is still owed (see
// supabase/migration-v202-realtime.sql) retries its SUBSCRIPTION
// every 30s - a subscription retry, not data polling; the data path
// is push-only - and starts flowing the moment the migration lands,
// with no dashboard redeploy.
//
// The header live-state is driven from here and tells the truth:
// "live" only when the core feeds (audit, work, users) are
// subscribed. rtState() keeps two lists strictly apart (v242):
//   pending     — feeds NOT subscribed (channel refused/errored):
//                 the only state that may be called "pending".
//   unconfirmed — feeds subscribed whose channel has not carried
//                 an event yet this session. Publication
//                 membership is COMPLETE on the backend (all 20
//                 feed tables, verified server-side 2026-11-09
//                 and re-verified 2026-11-10), so an unconfirmed
//                 feed is a QUIET table, not a missing migration —
//                 the old pill wording claimed a backend debt
//                 that does not exist and could never clear for
//                 low-traffic tables.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { session } from "./data.js";

const CFG = () => window.AGENTLINK_CONFIG || {};

// [table, events] - one feed per table.
const FEEDS = [
  ["al_queue", ["INSERT"]],
  ["al_audit_log", ["INSERT"]],
  ["al_message_reads", ["INSERT"]],
  ["al_work", ["INSERT", "UPDATE"]],
  ["al_work_deliveries", ["INSERT", "UPDATE"]],
  ["al_activeness", ["INSERT", "UPDATE"]],
  ["al_users", ["INSERT", "UPDATE"]],
  ["al_alerts", ["INSERT", "UPDATE"]],
  ["al_grants", ["INSERT", "UPDATE"]],
  ["al_grant_receipts", ["INSERT"]],
  ["al_grant_approvals", ["INSERT", "UPDATE"]],
  ["al_rooms", ["INSERT", "UPDATE"]],
  ["al_vault", ["INSERT", "UPDATE"]],
  ["al_library", ["INSERT"]],
  ["al_chains", ["INSERT", "UPDATE"]],
  ["al_chain_steps", ["INSERT", "UPDATE"]],
  ["al_groups", ["INSERT", "UPDATE"]],
  ["al_channels", ["INSERT", "UPDATE"]],
  ["al_group_members", ["INSERT", "UPDATE"]],
  ["al_channel_members", ["INSERT", "UPDATE"]],
];
// Core = the feeds the "live" claim stands on. al_queue joins them
// once its publication lands; audit carries live messages meanwhile.
const CORE = new Set(["al_audit_log", "al_work", "al_users"]);

let client = null;
let channels = new Map();   // table -> channel
let feedState = new Map();  // table -> subscribed | pending
let everSubscribed = new Set();
let feedSeen = new Map();   // table -> true once an event has arrived
let state = "connecting";   // connecting | live | reconnecting | offline
let wasLive = false;
let safetyTimer = null;
let retryTimer = null;
let retryTimer2 = null;
let handlers = { onEvent: null, onResync: null };
const stateCbs = new Set();

export function rtState(){
  return { state,
    pending: [...feedState].filter(([, s]) => s !== "subscribed").map(([t]) => t),
    // Subscribed at channel level but no event has arrived yet this
    // session: the binding may still be waiting on publication
    // membership (a channel joins even when its binding is refused).
    unconfirmed: FEEDS.map(([t]) => t).filter(t => feedState.get(t) === "subscribed" && !feedSeen.get(t)) };
}
export function onRtState(cb){ stateCbs.add(cb); cb(state); return () => stateCbs.delete(cb); }
function setState(s){
  if(s === state) return;
  state = s;
  stateCbs.forEach(cb => { try{ cb(s); }catch(_){} });
}
function recompute(){
  const coreOk = [...CORE].every(t => feedState.get(t) === "subscribed");
  if(typeof navigator !== "undefined" && navigator.onLine === false){ setState("offline"); return; }
  if(coreOk){ setState("live"); wasLive = true; }
  else setState(wasLive ? "reconnecting" : "connecting");
}

// startRealtime({onEvent, onResync}): onEvent({table, eventType,
// row, old}) for every pushed change; onResync() when a core feed
// re-subscribes after having been live (events may have been missed
// while down - the caller re-reads state once), and on the labelled
// 60s safety net.
export function startRealtime({ onEvent, onResync } = {}){
  stopRealtime();
  handlers = { onEvent, onResync };
  const cfg = CFG();
  const jwt = (session() || {}).jwt || cfg.anonKey;
  client = createClient(cfg.supabaseUrl, cfg.anonKey, {
    auth: { persistSession: false, autoRefreshToken: false },
    global: { headers: { Authorization: "Bearer " + jwt } },
  });
  client.realtime.setAuth(jwt);
  for(const [table, events] of FEEDS){
    feedState.set(table, "pending");
    let ch = client.channel("dash-" + table);
    for(const event of events){
      ch = ch.on("postgres_changes",
        { event, schema: "public", table },
        (payload) => { feedSeen.set(table, true);
          handlers.onEvent && handlers.onEvent({
            table, eventType: payload.eventType,
            row: payload.new || {}, old: payload.old || {} }); });
    }
    ch.subscribe((status) => {
      if(status === "SUBSCRIBED"){
        const resub = feedState.get(table) === "subscribed" || everSubscribed.has(table);
        everSubscribed.add(table);
        feedState.set(table, "subscribed");
        recompute();
        if(CORE.has(table) && resub && handlers.onResync) handlers.onResync();
      } else if(status === "CHANNEL_ERROR" || status === "TIMED_OUT" || status === "CLOSED"){
        // A table outside the publication lands here: mark it
        // pending; the subscription retry picks it up after the
        // migration is applied. Other feeds are unaffected.
        const wasSub = feedState.get(table) === "subscribed";
        feedState.set(table, "pending");
        recompute();
        if(wasSub && CORE.has(table) && handlers.onResync) handlers.onResync();
      }
    });
    channels.set(table, ch);
  }
  recompute();
  // Subscription retry for feeds not yet subscribed (publication
  // membership owed, or a transient channel error), and a slower
  // re-subscribe for feeds whose channel joined but which have
  // never delivered an event (a refused binding looks identical to
  // a quiet table until traffic flows). This retries subscriptions
  // only - no data is ever polled.
  retryTimer = setInterval(() => {
    if(!client) return;
    for(const [table, ch] of channels){
      if(feedState.get(table) !== "subscribed"){ try{ ch.subscribe(); }catch(_){} }
    }
  }, 30000);
  retryTimer2 = setInterval(() => {
    if(!client) return;
    for(const [table, ch] of channels){
      if(feedState.get(table) === "subscribed" && !feedSeen.get(table)){ try{ ch.subscribe(); }catch(_){} }
    }
  }, 90000);
  // Safety re-sync (seatbelt, NOT the mechanism): realtime is the
  // mechanism; this only heals the dataset if a pushed event was
  // somehow missed. Labelled honestly - it is not how data arrives.
  safetyTimer = setInterval(() => { if(state === "live" && handlers.onResync) handlers.onResync(); }, 60000);
  window.addEventListener("online", recompute);
  window.addEventListener("offline", recompute);
  return client;
}

export function setRealtimeJwt(jwt){
  if(client && jwt) client.realtime.setAuth(jwt);
}

export function stopRealtime(){
  if(safetyTimer){ clearInterval(safetyTimer); safetyTimer = null; }
  if(retryTimer){ clearInterval(retryTimer); retryTimer = null; }
  if(retryTimer2){ clearInterval(retryTimer2); retryTimer2 = null; }
  if(client){ try{ client.removeAllChannels(); }catch(_){} client = null; }
  channels = new Map();
  feedState = new Map();
  feedSeen = new Map();
  everSubscribed = new Set();
}
