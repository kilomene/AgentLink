// Activeness: the single source of truth for how the dashboard reads
// Firebase presence. Presence nodes /presence/<username> carry
// {beat_at (server ts), connected_at, client_version, transport,
// state}; agents beat every BEAT_INTERVAL_S seconds and register an
// onDisconnect write, so a disconnect flips the node to offline at
// once and a crashed agent simply stops beating.
//
// Staleness ladder (owner ruling 2026-11-05, hyper-sensitive —
// AgentLink's ORIGINAL timing law transplanted onto Firebase):
//   beat age <= ONLINE_MAX_AGE_S   -> "online"   (<= 2 missed beats)
//   beat age <= SUSPECT_MAX_AGE_S  -> "suspect"  (3rd beat missed)
//   beat age >  SUSPECT_MAX_AGE_S  -> "offline"
//   missing node / disconnect state -> "offline" (instantly)
//
// These thresholds mirror agentlink/doorbell.py exactly
// (same numbers, same names): BEAT_INTERVAL_S, ONLINE_MAX_AGE_S,
// SUSPECT_MAX_AGE_S — so the dashboard ladder and the client
// ladder can never drift apart: change the numbers in one place
// only after changing them in the other.
export const BEAT_INTERVAL_S = 5;
export const ONLINE_MAX_AGE_S = 10;
export const SUSPECT_MAX_AGE_S = 15;
export const ACTIVENESS_STATES = ["online", "suspect", "offline"];

const DISCONNECT_STATES = new Set(["offline", "disconnected", "disconnect"]);

// beat_at is an RTDB server timestamp (milliseconds). Plain-second
// values are also accepted so tests and fixtures can use seconds:
// a value far larger than "now" in seconds can only be milliseconds.
export function beatTimestampSeconds(presenceNode, nowSeconds){
  if(!presenceNode || typeof presenceNode !== "object") return null;
  const raw = Number(presenceNode.beat_at ?? presenceNode.ts ?? 0);
  if(!Number.isFinite(raw) || raw <= 0) return null;
  const now = Number(nowSeconds ?? Date.now()/1000);
  return raw > now*10 ? raw/1000 : raw;
}

export function beatAgeSeconds(presenceNode, nowSeconds){
  const now = Number(nowSeconds ?? Date.now()/1000);
  const beat = beatTimestampSeconds(presenceNode, now);
  if(beat === null) return null;
  return Math.max(0, Math.floor(now - beat));
}

// Pure ladder: (presence node, now in seconds) -> display state.
export function activenessState(presenceNode, nowSeconds){
  if(!presenceNode || typeof presenceNode !== "object") return "offline";
  if(presenceNode.disconnected === true) return "offline";
  if(DISCONNECT_STATES.has(String(presenceNode.state || ""))) return "offline";
  const age = beatAgeSeconds(presenceNode, nowSeconds);
  if(age === null) return "offline";
  if(age <= ONLINE_MAX_AGE_S) return "online";
  if(age <= SUSPECT_MAX_AGE_S) return "suspect";
  return "offline";
}

// Human label for a state; suspect always names how stale it is.
export function activenessLabel(state, ageSeconds){
  if(state === "online") return "online";
  if(state === "suspect") return "suspect — no heartbeat for " + (ageSeconds ?? "?") + "s";
  return "offline";
}

// Badge HTML for a state (label text is generated here from a state
// name + a number only, so it needs no further escaping).
export function activenessBadge(state, ageSeconds){
  return '<span class="activeness activeness-' + state + '">' +
    activenessLabel(state, ageSeconds) + "</span>";
}
