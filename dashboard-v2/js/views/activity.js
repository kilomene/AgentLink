import { esc, pt, ptime, table, states, fail, pill } from "../util.js";

// Alerts & Activity: fleet alerts (pushed live) and the full
// transmission feed — who is sending what to whom, as it happens.
// Filters are client-side over the in-memory feed; new audit rows
// stream in at the top without a refresh.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

const CATS = [["all", "All"], ["message", "Messages"], ["work", "Work"], ["grant", "Grants"], ["room", "Rooms"], ["other", "Other"]];
function catOf(kind){
  if(kind.includes("message")) return "message";
  if(kind.startsWith("work") || kind.startsWith("delivery")) return "work";
  if(kind.includes("grant")) return "grant";
  if(kind.includes("room")) return "room";
  return "other";
}

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  let cat = "all", query = "", shown = 120, alertFilter = "open";
  root.innerHTML = '<div class="vhead"><h2>Alerts &amp; Activity</h2><div class="vsub">Fleet alerts and the full transmission feed — who is sending what to whom, as it happens. Everything on this page is pushed live; the newest event lands at the top the moment it commits.</div></div>' +
    '<div class="card"><h3>Alerts</h3><div class="filters"><button class="chipbtn" data-af="open">Open</button><button class="chipbtn" data-af="resolved">Resolved</button><button class="chipbtn" data-af="all">All</button></div><div class="alerts"></div></div>' +
    '<div class="card"><h3>Feed summary — loaded events by category</h3><div class="summary"></div></div>' +
    '<div class="card"><h3><span class="live-dot"></span> Activity — who is transmitting to whom</h3>' +
    '<div class="filters">' + CATS.map(c => '<button class="chipbtn" data-cat="' + c[0] + '">' + c[1] + "</button>").join("") +
    '<input type="search" placeholder="Filter by agent, kind, group…" aria-label="Filter activity"></div>' +
    '<div class="feed"></div><div style="margin-top:12px"><button class="morebtn" type="button">Show more</button> <span class="state feedcount"></span></div></div>';
  const alertsHost = root.querySelector(".alerts");
  const feed = root.querySelector(".feed");
  const chips = root.querySelectorAll("[data-cat]");
  const afChips = root.querySelectorAll("[data-af]");
  const search = root.querySelector("input[type=search]");
  const moreBtn = root.querySelector(".morebtn");
  const count = root.querySelector(".feedcount");
  const syncChips = () => { chips.forEach(b => b.classList.toggle("on", b.dataset.cat === cat)); afChips.forEach(b => b.classList.toggle("on", b.dataset.af === alertFilter)); };
  const paintAlerts = () => {
    const list = ctx.store.data.alerts.filter(a => alertFilter === "all" ? true : alertFilter === "open" ? a.status !== "resolved" : a.status === "resolved");
    alertsHost.innerHTML = list.length ? list.slice(0, 40).map(a =>
      '<div class="alertrow' + (a.status === "resolved" ? " resolved" : "") + '"><span>' + (a.status === "resolved" ? "✅" : "⚠️") + '</span><div style="flex:1"><b>' + esc(a.kind) + "</b> — " + esc(a.subject || "") +
      '<div class="sub">' + esc(a.detail || "") + " · " + pt(a.created_at) + (a.reminders ? " · " + a.reminders + " reminder(s)" : "") + "</div></div>" +
      pill(a.status || "open", a.status === "resolved" ? "grey" : "amber") + "</div>").join("")
      : '<p class="state">No ' + alertFilter + " alerts.</p>";
  };
  const rowHtml = r => '<div class="feedrow"><span class="fic">' + (catOf(r.kind) === "work" ? "🛠" : catOf(r.kind) === "message" ? "💬" : catOf(r.kind) === "grant" ? "🔑" : catOf(r.kind) === "room" ? "🎙" : "•") + '</span><div class="fmain"><b>' +
    esc(r.actor || "system") + "</b> " + esc(r.kind.replace(/_/g, " ")) + (r.target ? " → <b>" + esc(r.target) + "</b>" : "") +
    (r.group_id ? " in <b>" + esc(r.group_id) + "</b>" : "") + (r.work_id ? ' <span class="mono">' + esc(r.work_id) + "</span>" : "") +
    (r.status ? ' <span class="pill grey">' + esc(r.status) + "</span>" : "") +
    ' <span class="pill ' + (r.evidence ? "verified" : "claimed") + '">' + esc(r.evidence || "claimed") + '</span></div><span class="ftime">' + pt(r.ts) + "</span></div>";
  const summary = root.querySelector(".summary");
  const paintSummary = () => {
    const act = ctx.store.data.activity;
    summary.innerHTML = table([["Category", c => c[0]], ["Events loaded", c => String(c[1])]],
      CATS.slice(1).map(([k, label]) => [label, act.filter(r => catOf(r.kind) === k).length]).concat([["Total", act.length]]));
  };
  const paintFeed = () => {
    paintSummary();
    const all = ctx.store.data.activity.filter(r =>
      (cat === "all" || catOf(r.kind) === cat) &&
      (!query || (r.actor + " " + r.target + " " + r.kind + " " + r.group_id).toLowerCase().includes(query)));
    feed.innerHTML = all.slice(0, shown).map(rowHtml).join("") || '<p class="state">Nothing matches.</p>';
    count.textContent = "showing " + Math.min(shown, all.length) + " of " + all.length + " loaded events";
    moreBtn.style.display = all.length > shown ? "" : "none";
  };
  chips.forEach(b => b.onclick = () => { cat = b.dataset.cat; shown = 120; syncChips(); paintFeed(); });
  afChips.forEach(b => b.onclick = () => { alertFilter = b.dataset.af; syncChips(); paintAlerts(); });
  search.addEventListener("input", () => { query = search.value.trim().toLowerCase(); shown = 120; paintFeed(); });
  moreBtn.onclick = () => { shown += 200; paintFeed(); };
  syncChips(); paintAlerts(); paintFeed();
  unsubs.push(ctx.bus.on("activity", () => paintFeed()));
  unsubs.push(ctx.bus.on("alerts", () => paintAlerts()));
  return { destroy };
}
