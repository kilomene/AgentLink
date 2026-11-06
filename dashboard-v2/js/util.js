export const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const ptFmt = new Intl.DateTimeFormat("en-US",{timeZone:"America/Los_Angeles",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hour12:false});
const ptTimeFmt = new Intl.DateTimeFormat("en-US",{timeZone:"America/Los_Angeles",hour:"2-digit",minute:"2-digit",hour12:false});
const ptDayFmt = new Intl.DateTimeFormat("en-US",{timeZone:"America/Los_Angeles",weekday:"short",month:"short",day:"numeric",year:"numeric"});
export const pt = ts => ts ? ptFmt.format(new Date(ts*1000)) + " PT" : "";
export const ptime = ts => ts ? ptTimeFmt.format(new Date(ts*1000)) : "";
export const pday = ts => ts ? ptDayFmt.format(new Date(ts*1000)) : "";
export const dayKey = ts => { const d = new Date(ts*1000); return d.getFullYear()+"-"+d.getMonth()+"-"+d.getDate(); };
export const OWNER_SEAT = "phoenix";
export function states(root){ root.innerHTML = '<div class="skel skelcard"></div><div class="skel skelrow"></div><div class="skel skelrow"></div><div class="skel skelrow" style="width:82%"></div>'; }
export function empty(root,msg){ root.innerHTML = '<p class="state">'+esc(msg)+"</p>"; }
export function fail(root,e){ root.innerHTML = '<p class="state err">Could not load: '+esc(e.message||e)+"</p>"; }
export function table(cols, rows){
  if(!rows.length) return '<p class="state">No rows yet.</p>';
  // Every cell carries its column title as data-label and the
  // first column is the card head: on phones the stylesheet turns
  // each row into a designed card of label/value lines, so the
  // mobile view is a mobile view — never a squeezed desktop table.
  return "<table><thead><tr>"+cols.map(c=>"<th>"+esc(c[0])+"</th>").join("")+"</tr></thead><tbody>"+
    rows.map(r=>"<tr>"+cols.map((c,i)=>'<td data-label="'+esc(c[0])+'"'+(i===0?' class="tfirst"':"")+">"+c[1](r)+"</td>").join("")+"</tr>").join("")+"</tbody></table>";
}
const HUES = [[ "#3f6212","#84cc16"],["#075e8f","#0a7dc2"],["#a3005e","#f4008c"],["#7c2d12","#ea580c"],["#4c1d95","#8b5cf6"],["#134e4a","#14b8a6"],["#713f12","#eab308"],["#7f1d1d","#ef4444"]];
export function avatar(name, grp, chan){ const i=(name||"?").replace(/^g-|^dm:/,"").slice(0,2).toUpperCase(); let cls="avatar"+(grp?" grp":chan?" chan":"");
  if(!grp && !chan){ let h=0; const s=String(name||""); for(let k=0;k<s.length;k++) h=(h*31+s.charCodeAt(k))>>>0; const g=HUES[h%HUES.length]; return '<span class="'+cls+'" style="background:linear-gradient(135deg,'+g[0]+","+g[1]+')">'+esc(i)+"</span>"; }
  return '<span class="'+cls+'">'+esc(i)+"</span>"; }
export function senderColor(name){ let h=0; const s=String(name||""); for(let k=0;k<s.length;k++) h=(h*31+s.charCodeAt(k))>>>0; return ["#3f6212","#075e8f","#a3005e","#9a3412","#5b21b6","#0f766e","#a16207","#b91c1c"][h%8]; }
export function fmtBytes(n){ n = Number(n||0); if(!n) return "0 B"; const u=["B","KB","MB","GB"]; let i=0; while(n>=1024 && i<3){ n/=1024; i++; } return (i?n.toFixed(1):Math.round(n))+" "+u[i]; }
export function relAge(ts, nowS){ if(!ts) return "—"; const s = Math.max(0, Math.floor((nowS||Date.now()/1000) - ts)); if(s<5) return "just now"; if(s<60) return s+"s ago"; if(s<3600) return Math.floor(s/60)+"m ago"; if(s<86400) return Math.floor(s/3600)+"h ago"; return Math.floor(s/86400)+"d ago"; }
export function countdown(w, nowS){ if(!w.deadline) return ""; if(w.status==="completed") return "done"; const left=w.deadline-(nowS||Math.floor(Date.now()/1000)); if(left<0) return '<span class="overdue">overdue '+Math.floor(-left/60)+'m</span>'; if(left<3600) return Math.floor(left/60)+"m left"; if(left<86400) return Math.floor(left/3600)+"h "+Math.floor((left%3600)/60)+"m left"; return Math.floor(left/86400)+"d left"; }
export function pill(text, cls){ return '<span class="pill '+(cls||"grey")+'">'+esc(text)+"</span>"; }
export function parseJson(v, dflt){ if(v==null) return dflt; if(typeof v !== "string") return v; try{ return JSON.parse(v); }catch(_){ return dflt; } }
export function downloadBlob(blob, name){
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name || "download";
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 4000);
}
export function toast(title, sub, onclick){
  const host = document.getElementById("toasts"); if(!host) return;
  const t = document.createElement("div"); t.className = "toast";
  t.innerHTML = "<b>"+esc(title)+'</b>'+(sub?'<div class="tsub">'+esc(sub)+"</div>":"");
  t.onclick = ()=>{ t.remove(); if(onclick) onclick(); };
  host.appendChild(t); setTimeout(()=>{ t.style.opacity="0"; t.style.transition="opacity .4s"; setTimeout(()=>t.remove(),420); }, 6000);
}
