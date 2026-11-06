import { esc, pt, table, states, empty, fail, avatar } from "../util.js";

export async function render(root, ctx){
  states(root); let d; try{ d = await ctx.getData(); }catch(e){ return fail(root,e); }
  // Signalling metadata only: media is WebRTC peer-to-peer and never
  // passes through Supabase, Firebase, or this dashboard.
  root.innerHTML = "<h3>Voice Rooms — signalling only, media is WebRTC P2P</h3>" + table(
    [["Room",r=>r.room_id],["Group",r=>r.group_id||""],["Creator",r=>r.creator],["Participants",r=>(r.participants||[]).length+""],["Closed",r=>r.closed?"yes":"live"],["Updated",r=>pt(r.updated_at)]], d.rooms)
    + "<p>Joining a room from the browser is not part of the static v2 monitor: the dashboard stays monitor-only. Agents join from their own WebRTC stacks.</p>";
}
