// Data layer: PostgREST reads + Edge oversight + session handling.
// Contract (see README): login Edge function verifies the one-time
// operator password, creates an al_dashboard_sessions row, and mints
// a short-lived dashboard JWT in operator mode. That JWT - never any
// privileged key - authorises PostgREST reads. Plaintext content is
// NEVER opened client-side: conversation text and credential entries
// arrive only from the Edge oversight function inside the session.
import { OWNER_SEAT } from "./util.js";
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
export async function login(password){
  const r = await fetch(CFG().edgeBase + "/dashboard-login", {method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify({password})});
  if(!r.ok) throw new Error("login failed ("+r.status+")");
  const j = await r.json(); saveSession(j.device_token, j.access_token); return j;
}
async function pg(table, query){
  const s = session(); const url = CFG().supabaseUrl + "/rest/v1/" + table + "?" + (query||"select=*");
  const r = await fetch(url, {headers:{apikey: CFG().anonKey, Authorization: "Bearer " + (s?.jwt || CFG().anonKey)}});
  if(r.status===401){ clearSession(); throw new Error("session expired - log in again"); }
  if(!r.ok) throw new Error(table+" read failed ("+r.status+")");
  return r.json();
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
// Probe segregation: port of Relay._parties_test (relay.py, v1.6.1).
// TEST iff any party besides the owner seat is not a production-
// registered user (test-designated, unknown, deregistered, ephemeral).
export function partiesTest(names, designation){
  const others = (names||[]).filter(n=>n && n !== OWNER_SEAT);
  return others.some(n => designation.get(n) !== "production");
}
export async function loadAll(){
  const [users, groups, gm, channels, cm, work, chains, steps, library, vault, alerts, audit, reads, servers, conns, rooms, grants, connectors, receipts, approvals] = await Promise.all([
    pg("al_users"), pg("al_groups"), pg("al_group_members","select=*"), pg("al_channels"), pg("al_channel_members","select=*"),
    pg("al_work","select=*&order=created_at.desc"), pg("al_chains","select=*&order=created_at.desc"), pg("al_chain_steps","select=*&order=position.asc"),
    pg("al_library","select=*&order=ts.desc"), pg("al_vault","select=*&order=ts.desc"), pg("al_alerts","select=*&order=created_at.desc&limit=50"),
    pg("al_audit_log","select=*&order=ts.asc"), pg("al_message_reads","select=*"), pg("al_servers","select=*"), pg("al_connections","select=*"),
    pg("al_rooms","select=*"), pg("al_grants","select=*"), pg("al_agent_connectors","select=*"),
    pg("al_grant_receipts","select=*&order=ts.desc&limit=200"), pg("al_grant_approvals","select=*&order=ts.desc&limit=50")
  ]);
  const designation = new Map(users.map(u=>[u.username, u.designation==="test" ? "test" : "production"]));
  const membersOf = (id, isCh) => (isCh?cm:gm).filter(m=>(isCh?m.channel_id:m.group_id)===id).map(m=>m.username);
  const chanIds = new Set(channels.map(c=>c.id));
  const isTestGroup = id => partiesTest(membersOf(id, chanIds.has(id)), designation);
  const stepsByChain = {}; steps.forEach(s=>{(stepsByChain[s.chain_id] ||= []).push(s);});
  const chainsFull = chains.map(c=>({...c, steps: stepsByChain[c.id]||[]}));
  const chainTest = c => partiesTest([c.creator, ...c.steps.flatMap(s=>[...(s.assignees||[]), s.assignee, s.target].filter(Boolean)), ...(c.group_id?membersOf(c.group_id):[])], designation);
  const partyNames = (item, keys) => [...keys.map(k=>item[k]).filter(Boolean), ...(item.group_id?membersOf(item.group_id, chanIds.has(item.group_id)):[])];
  // Conversations compose from FULL audit history (immortality law,
  // relay.py Relay._conversations): never a bounded activity window;
  // groups/channels are seeded even with zero messages; items ts-asc.
  const CONTENT = new Set(["message","group_message","channel_message","work_assigned","work_delivered","work_completed","work_changes_requested","work_progress","work_awaiting_approval","work_approved","work_approval_rejected"]);
  const convMap = new Map();
  const partFor = gid => (chanIds.has(gid)?cm:gm).filter(m=>(chanIds.has(gid)?m.channel_id:m.group_id)===gid).map(m=>({username:m.username, nickname:m.nickname||"", role:m.role||""}));
  for(const g of [...groups, ...channels]) convMap.set("group:"+g.id, {key:"group:"+g.id, group_id:g.id, participants:partFor(g.id), items:[]});
  for(const r of audit.filter(a=>CONTENT.has(a.kind))){
    let key, participants;
    if(r.group_id){ key="group:"+r.group_id; participants=partFor(r.group_id); }
    else { const pair=[r.actor, r.target].filter(Boolean).sort(); key="dm:"+pair.join("|"); participants=pair; }
    if(!convMap.has(key)) convMap.set(key,{key, group_id:r.group_id||null, participants, items:[]});
    convMap.get(key).items.push({id:r.ref_id||String(r.seq), ts:r.ts, from:r.actor, kind:r.kind, status:r.status, size:r.size, mentions:r.mentions, oversight:r.oversight||null, sealed:true});
  }
  convMap.forEach(c=>c.items.sort((a,b)=>a.ts-b.ts));
  const convTest = c => c.group_id ? isTestGroup(c.group_id) : partiesTest((c.participants||[]).map(p=>typeof p==="string"?p:p.username), designation);
  const now = Math.floor(Date.now()/1000);
  const usersFull = users.map(u=>({...u, trust_score: computeTrust(u.username, work, audit, now), online:false, connectors:(connectors.find(x=>x.username===u.username)?.inventory)||[], grant: grants.find(g=>g.username===u.username)||null}));
  const split = (arr, fn) => ({prod: arr.filter(x=>!fn(x)), test: arr.filter(fn)});
  const U = split(usersFull, u=>designation.get(u.username)==="test");
  const C = split([...convMap.values()], convTest);
  const W = split(work, w=>partiesTest(partyNames(w,["assigner","assignee"]), designation));
  const CH = split(chainsFull, chainTest);
  const L = split(library, e=>partiesTest(partyNames(e,["sender","to_user"]), designation));
  const V = split(vault, e=>partiesTest(partyNames(e,["added_by"]), designation));
  const G = split(groups, g=>isTestGroup(g.id)); const CN = split(channels, c=>isTestGroup(c.id));
  return { users:U.prod, testUsers:U.test, groups:G.prod, testGroups:G.test, channels:CN.prod, testChannels:CN.test,
    work:W.prod, testWork:W.test, chains:CH.prod, testChains:CH.test, library:L.prod, testLibrary:L.test,
    vault:V.prod, testVault:V.test, conversations:C.prod, testConversations:C.test,
    alerts, activity:[...audit].reverse(), reads, servers, connections:conns, rooms,
    grantActivity: receipts.filter(r=>designation.get(r.username)!=="test"), testGrantActivity: receipts.filter(r=>designation.get(r.username)==="test"),
    grantApprovals: approvals.filter(a=>designation.get(a.username)!=="test"), testGrantApprovals: approvals.filter(a=>designation.get(a.username)==="test"),
    designation, membersOf };
}
