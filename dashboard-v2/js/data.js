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
export async function oversightOpen(items){
  // items: [{id, oversight, content_envelope}] -> {id: {text,title,content_kind,file_name}}
  const s = session(); if(!s) throw new Error("login required");
  const r = await fetch(CFG().edgeBase + "/oversight", {method:"POST", headers:{"Content-Type":"application/json", Authorization:"Bearer "+s.jwt}, body: JSON.stringify({items})});
  if(!r.ok) throw new Error("oversight failed ("+r.status+")");
  return r.json();
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
  const [users, groups, gm, channels, cm, work, deliveries, chains, steps, library, vault, alerts, audit, reads, servers, conns, rooms, grants, connectors, receipts, approvals, activenessRows, blobs, queue] = await Promise.all([
    pg("al_users"), pg("al_groups"), pg("al_group_members","select=*"), pg("al_channels"), pg("al_channel_members","select=*"),
    pg("al_work","select=*&order=created_at.desc"), pg("al_work_deliveries","select=*&order=ts.desc&limit=300"), pg("al_chains","select=*&order=created_at.desc"), pg("al_chain_steps","select=*&order=position.asc"),
    pg("al_library","select=*&order=ts.desc"), pg("al_vault","select=*&order=ts.desc"), pg("al_alerts","select=*&order=created_at.desc&limit=100"),
    pgAll("al_audit_log","select=*&order=seq.asc"), pg("al_message_reads","select=*"), pg("al_servers","select=*"), pg("al_connections","select=*"),
    pg("al_rooms","select=*"), pg("al_grants","select=*"), pg("al_agent_connectors","select=*"),
    pg("al_grant_receipts","select=*&order=ts.desc&limit=200"), pg("al_grant_approvals","select=*&order=ts.desc&limit=100"),
    pg("al_activeness","select=*"), pg("al_blobs","select=*&order=created_at.desc&limit=200"), pg("al_queue","select=*&order=seq.desc&limit=120")
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
  const usersFull = users.map(u=>({...u, trust_score: computeTrust(u.username, work, audit, now), online:false, activenessMirror: actMap[u.username]||null,
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
    grantActivity: receipts.filter(r=>designation.get(r.username)!=="test"), testGrantActivity: receipts.filter(r=>designation.get(r.username)==="test"),
    grantApprovals: approvals.filter(a=>designation.get(a.username)!=="test"), testGrantApprovals: approvals.filter(a=>designation.get(a.username)==="test"),
    designation, membersOf, nameOf };
}
