import { esc, pt, table, states, fail, pill } from "../util.js";

// Voice Rooms: live room state - who opened which room, who is in
// it, whether it is live or closed - pushed as room rows change.
// Signalling metadata only: media is WebRTC peer-to-peer and never
// passes through Supabase, Firebase or this dashboard. Joining a
// room from the browser is deliberately NOT part of the v2 monitor:
// the dashboard can never send, speak or participate (monitor-only
// law); agents join from their own WebRTC stacks.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  root.innerHTML = '<div class="vhead"><h2>Voice Rooms</h2><div class="vsub">Live voice rooms — the backend carries signalling only; media is WebRTC peer-to-peer. Room state on this page is pushed live as rooms open, fill and close. This monitor never joins or speaks in a room.</div></div><div class="roomlist"></div>';
  const host = root.querySelector(".roomlist");
  const paint = () => {
    const dd = ctx.store.data;
    const rooms = [...dd.rooms].sort((a, b) => (a.closed || 0) - (b.closed || 0) || (b.updated_at || 0) - (a.updated_at || 0));
    const live = rooms.filter(r => !r.closed);
    host.innerHTML =
      '<div class="card roomcard' + (live.length ? " live" : "") + '"><span class="pulse"></span><div><b>' + live.length + " room" + (live.length === 1 ? "" : "s") + ' live now</b><div class="sub">' + rooms.length + " room(s) on record — state updates stream in as rooms open, fill and close.</div></div></div>" +
      (rooms.length ? table(
        [["Room", r => "<b>" + esc(r.room_id) + "</b>"], ["State", r => r.closed ? pill("closed", "grey") : pill("live", "green")],
         ["Group", r => esc(dd.nameOf ? dd.nameOf(r.group_id) : (r.group_id || ""))], ["Opened by", r => esc(r.creator || "")],
         ["Participants", r => { const parts = Array.isArray(r.participants) ? r.participants : []; return parts.length ? parts.map(p => pill("@" + p, "blue")).join(" ") : "—"; }],
         ["Opened", r => pt(r.opened_at)], ["Updated", r => pt(r.updated_at)]], rooms)
        : '<p class="state">No voice rooms yet.</p>');
  };
  paint();
  unsubs.push(ctx.bus.on("rooms", paint));
  return { destroy };
}
