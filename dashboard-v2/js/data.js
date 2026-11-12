// Data layer: PostgREST reads + Edge oversight + session handling.
// Contract (see README): login Edge function verifies the one-time
// operator password, creates an al_dashboard_sessions row, and mints
// a short-lived dashboard JWT in operator mode. That JWT - never any
// privileged key - authorises PostgREST reads. Plaintext content is
// NEVER opened client-side: conversation text and credential entries
// arrive only from the Edge oversight function inside the session.
import { OWNER_SEAT, parseJson } from "./util.js";
import { computeTrust } from "./trust.js";
const CFG = () => window.AGENTLINK_CONFIG || {};
const TOKEN_KEY = "agentlink_dash_token";       // 7-day trusted device token
const JWT_KEY = "agentlink_dash_jwt";
const EXP_KEY = "agentlink_dash_expires";
export const SESSION_TTL_SECONDS = 7*24*60*60;  // mirrors DEVICE_TRUST_SECONDS in agentlink/timing.py
export function session(){ const t = localStorage.getItem(TOKEN_KEY); const exp = Number(localStorage.getItem(EXP_KEY)||0);
  if(!t || Date.now()/1000 > exp) return null; return { token:t, jwt: localStorage.getItem(JWT_KEY)||"" }; }
export function saveSession(token, jwt){ localStorage.setItem(TOKEN_KEY, token); if(jwt) localStorage.setItem(JWT_KEY, jwt);
  localStorage.setItem(EXP_KEY, String(Math.floor(Date.now()/1000)+SESSION_TTL_SECONDS)); }
export function clearSession(){ [TOKEN_KEY,JWT_KEY,EXP_KEY].forEach(k=>localStorage.removeItem(k)); }
export function jwtExpiry(jwt){ try{ const p = JSON.parse(atob(String(jwt||"").split(".")[1].replace(/-/g,"+").replace(/_/g,"/"))); return Number(p.exp||0); }catch(_){ return 0; } }
export async function login(password){
  const r = await fetch(CFG().edgeBase + "/dashboard-login", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({password})});
  if(!r.ok) throw new Error("login failed ("+r.status+")");
  const j = await r.json(); saveSession(j.device_token, j.access_token); return j;
}
export async function refreshSession(){
  const s = session(); if(!s) throw new Error("login required");
  let r;
  try{
    r = await fetch(CFG().edgeBase + "/dashboard-login", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({action:"refresh", device_token: s.token})});
  }catch(_){
    // A network failure says NOTHING about the device trust and
    // must never destroy it: the 7-day trusted device survives a
    // dropped connection. (Owner hit the old behaviour
    // 2026-11-06: one flaky refresh and the phone demanded the
    // password again.) Only a definitive 401 from the login
    // service — it no longer knows this device token — may end
    // the session.
    const e = new Error("session refresh unreachable - connection problem, device still trusted");
    e.code = "REFRESH_UNREACHABLE";
    throw e;
  }
  if(r.status === 401){
    const e = new Error("session expired - log in again");
    e.code = "SESSION_DEAD";
    throw e;
  }
  if(!r.ok) throw new Error("session refresh failed ("+r.status+")");
  const j = await r.json(); saveSession(j.device_token || s.token, j.access_token); return j;
}
export async function ensureFreshJwt(){
  const s = session(); if(!s) return null;
  if(jwtExpiry(s.jwt) - Date.now()/1000 < 300){ try{ await refreshSession(); }catch(_){ /* reads will surface a real 401 */ } }
  return session();
}
async function pgRaw(table, query){
  const s = session(); const url = CFG().supabaseUrl + "/rest/v1/" + table + "?" + (query||"select=*");
  const r = await fetch(url, {headers:{apikey: CFG().anonKey, Authorization: "Bearer " + (s?.jwt || CFG().anonKey)}});
  if(r.status===401){
    // The operator JWT lives 1h inside a 7-day trusted device: one
    // refresh + retry before the session is treated as dead. The
    // stored device trust is cleared ONLY when the login service
    // definitively rejects the device token (SESSION_DEAD); a
    // transient refresh failure keeps the trust and surfaces a
    // connectivity error instead of a forced password prompt.
    try{ await refreshSession(); }catch(e){
      if(e && e.code === "SESSION_DEAD"){ clearSession(); throw new Error("session expired - log in again"); }
      throw new Error("connection problem while refreshing the session - device still trusted, retry");
    }
    const s2 = session();
    const r2 = await fetch(url, {headers:{apikey: CFG().anonKey, Authorization: "Bearer " + (s2?.jwt || CFG().anonKey)}});
    if(!r2.ok) throw new Error(table+" read failed ("+r2.status+")");
    return r2.json();
  }
  if(!r.ok) throw new Error(table+" read failed ("+r.status+")");
  return r.json();
}
export async function pg(table, query){ return pgRaw(table, query); }
// Full-table read in 1000-row pages (PostgREST caps each response):
// the audit history is composed in FULL (immortality law), so a
// single capped response would silently drop the newest history.
export async function pgAll(table, query){
  const out = []; const page = 1000;
  for(let off = 0; ; off += page){
    const rows = await pgRaw(table, (query||"select=*") + "&limit=" + page + "&offset=" + off);
    out.push(...rows);
    if(rows.length < page) return out;
  }
}
// EGRESS DISCIPLINE (2.4.0): the audit read is FIELD-MINIMAL —
// exactly the columns the conversation/activity composition
// consumes (the same set the client transport selects), never
// select=*. And the audit history is fetched ONCE in full
// (immortality law), then refreshed by SEQ DELTA only: a resync
// asks for rows strictly newer than the highest seq already
// held, so a 60s safety resync costs the delta, not the archive.
export const AUDIT_SELECT = "select=seq,ts,kind,actor,target,group_id,work_id,status,priority,size,mentions,ref_id,sender_nickname,sender_role,sender_custom_role,oversight,content_envelope";
let _auditCache = null, _auditMaxSeq = 0;
export async function loadAudit(){
  if(!_auditCache){
    _auditCache = await pgAll("al_audit_log", AUDIT_SELECT + "&order=seq.asc");
    _auditMaxSeq = _auditCache.reduce((m, r) => Math.max(m, Number(r.seq || 0)), 0);
    return _auditCache;
  }
  const fresh = await pgAll("al_audit_log", AUDIT_SELECT + "&seq=gt." + _auditMaxSeq + "&order=seq.asc");
  if(fresh.length){
    _auditCache.push(...fresh);
    _auditMaxSeq = fresh.reduce((m, r) => Math.max(m, Number(r.seq || 0)), _auditMaxSeq);
  }
  return _auditCache;
}
export async function oversightOpen(items){
  // items: [{id, oversight, content_envelope}] -> {id: {text,title,content_kind,file_name}}
  const s = session(); if(!s) throw new Error("login required");
  // Hard timeout: a hung request must reject, never wedge the
  // caller's open pass — the chat view retries until every item
  // reaches its text.
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), 25000);
  try{
    const r = await fetch(CFG().edgeBase + "/oversight", {method:"POST", headers:{"Content-Type":"application/json", Authorization:"Bearer "+s.jwt}, body: JSON.stringify({items}), signal: ctl.signal});
    if(!r.ok) throw new Error("oversight failed ("+r.status+")");
    return await r.json();
  }finally{ clearTimeout(timer); }
}
export async function oversightCredentials(username){
  const s = session(); if(!s) throw new Error("login required");
  const r = await fetch(CFG().edgeBase + "/oversight", {method:"POST", headers:{"Content-Type":"application/json", Authorization:"Bearer "+s.jwt}, body: JSON.stringify({credentials_for: username})});
  if(!r.ok) throw new Error("oversight failed ("+r.status+")");
  return r.json();
}
// File bytes (owner's v1 in-chat media ruling, carried into v2):
// the oversight function serves a file's VERIFIED plaintext bytes
// inside the operator session — media renders/plays in the thread,
// every other file downloads in place, and Library/Vault entries
// download the same way. A refusal (404) means the bytes could not
// be verified under oversight; callers show the honest state.
async function oversightFileBlob(body){
  const s = session(); if(!s) throw new Error("login required");
  const r = await fetch(CFG().edgeBase + "/oversight", {method:"POST", headers:{"Content-Type":"application/json", Authorization:"Bearer "+s.jwt}, body: JSON.stringify(body)});
  if(!r.ok) throw new Error("file unavailable ("+r.status+")");
  return r.blob();
}
export async function oversightFile(item){
  return oversightFileBlob({file_item: {oversight: item.oversight, content_envelope: item.content_envelope}});
}
export async function oversightVaultFile(descriptor){
  return oversightFileBlob({vault_file: {descriptor}});
}
export async function oversightLibraryFile(entry){
  return oversightFileBlob({library_file: {work_id: entry.work_id, sha256: entry.sha256, filename: entry.filename, size: entry.size}});
}
// DASHBOARD NEVER ERASES (Disappearing Mode v2, 2.4.0):
// disappearing conversations are NOT in the audit history at
// all — they render from the OWNER ARCHIVE, read through the
// archive service (Firebase archiveRead; Drive is the store).
// The sealed entries are opened on the server, inside the
// operator session, and only the opened items come back —
// this layer never opens content itself. The delivery stores
// erase on the per-side clocks; this path has no erase.
// Returns dashboard-shaped items (already opened), or [] when
// the archive service is not configured / holds nothing for
// the conversation. A conversation is filed under EVERY
// participant, so reading any one participant's folder is
// reading the conversation.
export async function archiveConversation(conv){
  const base = CFG().archiveBase;
  if(!base || !conv) return [];
  const s = session(); if(!s) return [];
  const people = (conv.participants || []).map(p => typeof p === "string" ? p : p.username).filter(Boolean);
  let convId = "", agent = people[0] || "";
  if(conv.group_id){ convId = (conv.isChannel ? "channel:" : "group:") + conv.group_id; }
  else{
    const pair = [...people].sort();
    if(pair.length < 2) return [];
    convId = "dm:" + pair.join(":");
    agent = pair[0];
  }
  if(!agent || !convId) return [];
  const r = await fetch(base + "/archiveRead?agent=" + encodeURIComponent(agent) + "&conversation=" + encodeURIComponent(convId),
    {headers:{"X-Operator-Session": s.token}});
  if(!r.ok) return [];
  const j = await r.json();
  return (j.entries || []).filter(e => e.kind === "content").map(e => ({
    id: e.message_id, seq: 0, ts: e.ts, from: e.sender, target: "", group_id: conv.group_id || "",
    kind: "message", status: "", size: 0, mentions: [], work_id: "",
    sender_nickname: "", sender_role: "", oversight: null, content_envelope: null,
    sealed: false, disappearing: true,
    opened: { text: (e.payload && e.payload.body) || "", title: "", content_kind: (e.payload && e.payload.kind) || "text", file_name: "" }
  }));
}
// Probe segregation: port of Relay._parties_test (relay.py, v1.6.1).
// TEST iff any party besides the owner seat is not a production-
// registered user (test-designated, unknown, deregistered, ephemeral).
export function partiesTest(names, designation){
  const others = (names||[]).filter(n=>n && n !== OWNER_SEAT);
  return others.some(n => designation.get(n) !== "production");
}
export const CONTENT_KINDS = new Set(["message","group_message","channel_message","work_assigned","work_delivered","work_completed","work_changes_requested","work_progress","work_awaiting_approval","work_approved","work_approval_rejected"]);
export function convKeyOf(r){
  if(r.group_id) return "group:"+r.group_id;
  const pair = [r.actor, r.target].filter(Boolean).sort();
  return "dm:"+pair.join("|");
}
export function itemOf(r){
  return { id: r.ref_id || String(r.seq), seq: r.seq || 0, ts: r.ts, from: r.actor, target: r.target||"", group_id: r.group_id||"",
    kind: r.kind, status: r.status||"", size: r.size||0, mentions: r.mentions||[], work_id: r.work_id||"",
    sender_nickname: r.sender_nickname||"", sender_role: r.sender_role||"",
    oversight: r.oversight || null, content_envelope: r.content_envelope || null, sealed: true, opened: null };
}
export async function loadAll(){
  const [users, groups, gm, channels, cm, work, deliveries, chains, steps, library, vault, alerts, audit, reads, servers, conns, rooms, grants, connectors, receipts, approvals, activenessRows, blobs, queue, livenessRows] = await Promise.all([
    pg("al_users"), pg("al_groups"), pg("al_group_members","select=*"), pg("al_channels"), pg("al_channel_members","select=*"),
    pg("al_work","select=*&order=created_at.desc"), pg("al_work_deliveries","select=*&order=ts.desc&limit=300"), pg("al_chains","select=*&order=created_at.desc"), pg("al_chain_steps","select=*&order=position.asc"),
    pg("al_library","select=*&order=ts.desc"), pg("al_vault","select=*&order=ts.desc"), pg("al_alerts","select=*&order=created_at.desc&limit=100"),
    loadAudit(), pg("al_message_reads","select=*"), pg("al_servers","select=*"), pg("al_connections","select=*"),
    pg("al_rooms","select=*"), pg("al_grants","select=*"), pg("al_agent_connectors","select=*"),
    pg("al_grant_receipts","select=*&order=ts.desc&limit=200"), pg("al_grant_approvals","select=*&order=ts.desc&limit=100"),
    pg("al_activeness","select=*"), pg("al_blobs","select=*&order=created_at.desc&limit=200"), pg("al_queue","select=*&order=seq.desc&limit=120"),
    pg("al_liveness","select=*").catch(() => [])
  ]);
  const designation = new Map(users.map(u=>[u.username, u.designation==="test" ? "test" : "production"]));
  const membersOf = (id, isCh) => (isCh?cm:gm).filter(m=>(isCh?m.channel_id:m.group_id)===id).map(m=>m.username);
  const chanIds = new Set(channels.map(c=>c.id));
  const isTestGroup = id => partiesTest(membersOf(id, chanIds.has(id)), designation);
  const stepsByChain = {}; steps.forEach(s=>{(stepsByChain[s.chain_id] ||= []).push(s);});
  const chainsFull = chains.map(c=>({...c, steps: stepsByChain[c.id]||[]}));
  const chainTest = c => partiesTest([c.creator, ...c.steps.flatMap(s=>[...(s.assignees||[]), s.assignee, s.target].filter(Boolean)), ...(c.group_id?membersOf(c.group_id):[])], designation);
  const partyNames = (item, keys) => [...keys.map(k=>item[k]).filter(Boolean), ...(item.group_id?membersOf(item.group_id, chanIds.has(item.group_id)):[])];
  const nameOf = id => { const g = groups.find(x=>x.id===id); if(g) return g.name||g.id; const c = channels.find(x=>x.id===id); return c ? (c.name||c.id) : id; };
  // Conversations compose from FULL audit history (immortality law,
  // relay.py Relay._conversations): never a bounded activity window;
  // groups/channels are seeded even with zero messages; items ts-asc.
  const convMap = new Map();
  const partFor = gid => (chanIds.has(gid)?cm:gm).filter(m=>(chanIds.has(gid)?m.channel_id:m.group_id)===gid).map(m=>({username:m.username, nickname:m.nickname||"", role:m.role||""}));
  for(const g of [...groups, ...channels]) convMap.set("group:"+g.id, {key:"group:"+g.id, group_id:g.id, isChannel: chanIds.has(g.id), title: nameOf(g.id), participants:partFor(g.id), items:[]});
  for(const r of audit.filter(a=>CONTENT_KINDS.has(a.kind))){
    const key = convKeyOf(r);
    if(!convMap.has(key)){
      const pair = [r.actor, r.target].filter(Boolean).sort();
      convMap.set(key, {key, group_id: r.group_id||null, isChannel:false, title: pair.join(" ↔ "), participants: pair, items:[]});
    }
    convMap.get(key).items.push(itemOf(r));
  }
  convMap.forEach(c=>{ c.items.sort((a,b)=>a.ts-b.ts || (a.seq||0)-(b.seq||0)); c.lastTs = c.items.length ? c.items[c.items.length-1].ts : 0; });
  const convTest = c => c.group_id ? isTestGroup(c.group_id) : partiesTest((c.participants||[]).map(p=>typeof p==="string"?p:p.username), designation);
  const now = Math.floor(Date.now()/1000);
  const actMap = {}; activenessRows.forEach(a=>{ actMap[a.username]=a; });
  // Life Signs (2.5.0): the record-layer grade rows join the
  // roster (the LIVE nodes layer on top via presence.js
  // applyLiveness; where they disagree the node is fresher and
  // the view says which source it is showing).
  const livMap = {}; (livenessRows||[]).forEach(a=>{ livMap[a.username]=a; });
  const usersFull = users.map(u=>({...u, trust_score: computeTrust(u.username, work, audit, now), online:false, activenessMirror: actMap[u.username]||null, liveness: livMap[u.username]||null,
    connectors: parseJson((connectors.find(x=>x.username===u.username)||{}).inventory, []), grant: grants.find(g=>g.username===u.username)||null}));
  const split = (arr, fn) => ({prod: arr.filter(x=>!fn(x)), test: arr.filter(fn)});
  const U = split(usersFull, u=>designation.get(u.username)==="test");
  const convsSorted = [...convMap.values()].sort((a,b)=>(b.lastTs||0)-(a.lastTs||0));
  const C = split(convsSorted, convTest);
  const W = split(work, w=>partiesTest(partyNames(w,["assigner","assignee"]), designation));
  const CH = split(chainsFull, chainTest);
  const L = split(library, e=>partiesTest(partyNames(e,["sender","to_user"]), designation));
  const V = split(vault, e=>partiesTest(partyNames(e,["added_by"]), designation));
  const G = split(groups, g=>isTestGroup(g.id)); const CN = split(channels, c=>isTestGroup(c.id));
  return { users:U.prod, testUsers:U.test, groups:G.prod, testGroups:G.test, channels:CN.prod, testChannels:CN.test,
    work:W.prod, testWork:W.test, chains:CH.prod, testChains:CH.test, library:L.prod, testLibrary:L.test,
    vault:V.prod, testVault:V.test, conversations:C.prod, testConversations:C.test,
    alerts, activity:[...audit].reverse(), auditAsc: audit, reads, servers, connections:conns, rooms, deliveries, blobs, queue,
    activeness: actMap,
    liveness: livMap,
    grantActivity: receipts.filter(r=>designation.get(r.username)!=="test"), testGrantActivity: receipts.filter(r=>designation.get(r.username)==="test"),
    grantApprovals: approvals.filter(a=>designation.get(a.username)!=="test"), testGrantApprovals: approvals.filter(a=>designation.get(a.username)==="test"),
    designation, membersOf, nameOf };
}

// Published "latest" (v242): the version clients themselves
// update to is the update-manifest served next to the dashboard
// (config.js: manifestUrl, generated at deploy from the repo's
// update-manifest.json — the same artifact `agentlink update`
// reads). The Agents view's "latest" tag compares against THIS,
// fetched at runtime, never against a fleet-derived maximum and
// never a baked constant: a fleet whose newest reporter is stale
// must not crown its own staleness "latest" (owner's screenshot,
// 2026-11-10: 2.2.3 tagged latest while 2.4.0 was published).
// Fetched once per page load and cached in memory — one small
// read per session, no polling. On any failure it resolves to ""
// and the view shows versions WITHOUT a latest tag: an absent
// claim, never a wrong one.
let _manifestVersion = null;
export async function fetchManifestVersion(){
  if(_manifestVersion !== null) return _manifestVersion;
  const url = CFG().manifestUrl;
  if(!url){ _manifestVersion = ""; return ""; }
  try{
    const r = await fetch(url, { cache: "no-store" });
    if(!r.ok) throw new Error("manifest read failed (" + r.status + ")");
    const j = await r.json();
    _manifestVersion = String((j && j.version) || "");
  }catch(_){ _manifestVersion = ""; }
  return _manifestVersion;
}

// Support desk (2.1.0): operator routes on the agentlink-support
// Edge, authorised by the trusted device token — the
// agentlink-api contract (sha256(token) in al_dashboard_sessions).
async function supportApi(route, body){
  const s = session(); if(!s) throw new Error("login required");
  const r = await fetch(CFG().edgeBase + "/agentlink-support" + route,
    {method:"POST", headers:{"Content-Type":"application/json",
     Authorization:"Bearer " + s.token}, body: JSON.stringify(body||{})});
  const j = await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(j.detail || j.error || ("support " + route + " failed (" + r.status + ")"));
  return j;
}
export function supportList(status){ return supportApi("/operator/list", status ? {status} : {}); }
export function supportGet(ticket_id){ return supportApi("/operator/get", {ticket_id}); }
export function supportAnswer(ticket_id, reply){ return supportApi("/operator/answer", {ticket_id, reply}); }
export function supportFixed(ticket_id, fixed_in_version, reply){ return supportApi("/operator/fixed", {ticket_id, fixed_in_version, reply}); }
export function supportClose(ticket_id, reply){ return supportApi("/operator/close", {ticket_id, reply}); }
