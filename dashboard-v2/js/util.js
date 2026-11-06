export const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const ptFmt = new Intl.DateTimeFormat("en-US",{timeZone:"America/Los_Angeles",year:"numeric",month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",hour12:false});
export const pt = ts => ts ? ptFmt.format(new Date(ts*1000)) + " PT" : "";
export const OWNER_SEAT = "phoenix";
export function states(root){ root.innerHTML = '<p class="state">Loading…</p>'; }
export function empty(root,msg){ root.innerHTML = '<p class="state">'+esc(msg)+"</p>"; }
export function fail(root,e){ root.innerHTML = '<p class="state err">Could not load: '+esc(e.message||e)+"</p>"; }
export function table(cols, rows){
  if(!rows.length) return '<p class="state">No rows yet.</p>';
  return "<table><thead><tr>"+cols.map(c=>"<th>"+esc(c[0])+"</th>").join("")+"</tr></thead><tbody>"+
    rows.map(r=>"<tr>"+cols.map(c=>"<td>"+esc(c[1](r))+"</td>").join("")+"</tr>").join("")+"</tbody></table>";
}
export function avatar(name, grp){ const i=(name||"?").slice(0,2).toUpperCase(); return '<span class="avatar'+(grp?" grp":"")+'">'+esc(i)+"</span>"; }
