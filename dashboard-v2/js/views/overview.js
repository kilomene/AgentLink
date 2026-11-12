import { esc, pt, ptime, table, states, fail } from "../util.js";
import { activenessState, activenessBadge } from "../activeness.js";

// Overview: live fleet stats, the three-state activeness summary
// (online / suspect / offline counted separately, never collapsed),
// open alerts, groups & channels, and the live activity feed -
// audit rows pushed by Realtime land at the top of the feed the
// moment they commit.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

function feedRow(r){
  const icon = r.kind.startsWith("work") ? "🛠" : r.kind.includes("message") ? "💬" : r.kind.includes("grant") ? "🔑" : r.kind.includes("room") ? "🎙" : "•";
  return '<div class="feedrow"><span class="fic">' + icon + '</span><div class="fmain"><b>' + esc(r.actor || "system") + "</b> " +
    esc(r.kind.replace(/_/g, " ")) + (r.target ? " → <b>" + esc(r.target) + "</b>" : "") + (r.group_id ? " in <b>" + esc(r.group_id) + "</b>" : "") +
    (r.status ? ' <span class="pill grey">' + esc(r.status) + "</span>" : "") +
    ' <span class="pill ' + (r.evidence ? "verified" : "claimed") + '">' + esc(r.evidence || "claimed") + '</span></div><span class="ftime">' + ptime(r.ts) + "</span></div>";
}

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  const now = Date.now() / 1000;
  const statesOf = (d.users || []).map(u => u.activeness || activenessState(u.presence, now));
  const counts = { online: statesOf.filter(s => s === "online").length,
                   suspect: statesOf.filter(s => s === "suspect").length,
                   offline: statesOf.filter(s => s === "offline").length };
  const statsHost = document.createElement("div");
  const paintStats = () => {
    const dd = ctx.store.data;
    const st = (dd.users || []).map(u => u.activeness || "offline");
    const c = { online: st.filter(s => s === "online").length, suspect: st.filter(s => s === "suspect").length, offline: st.filter(s => s === "offline").length };
    const stats = [["Agents", dd.users.length], ["Groups", dd.groups.length], ["Channels", dd.channels.length],
      ["Open work", dd.work.filter(w => w.status !== "completed" && w.status !== "cancelled").length],
      ["Conversations", dd.conversations.length + dd.testConversations.length],
      ["Messages", dd.conversations.reduce((n, x) => n + x.items.length, 0)]];
    const badges = ["online", "suspect", "offline"].map(s => '<span class="stat activeness activeness-' + s + '" data-activeness-count="' + s + '"><b>' + c[s] + "</b> " + s + "</span>").join("");
    statsHost.innerHTML = '<div class="stats">' + stats.map(s => '<span class="stat"><b>' + s[1] + "</b> " + esc(s[0]) + "</span>").join("") + badges + "</div>";
  };
  paintStats();
  const openAlerts = d.alerts.filter(a => a.status !== "resolved");
  root.innerHTML = "";
  root.appendChild(statsHost);
  const alertsCard = document.createElement("div");
  const paintAlerts = () => {
    const list = ctx.store.data.alerts.filter(a => a.status !== "resolved").slice(0, 6);
    alertsCard.innerHTML = list.length ? '<div class="card"><h3>⚠ Open alerts</h3>' + list.map(a =>
      '<div class="alertrow"><span>⚠️</span><div><b>' + esc(a.kind) + "</b> — " + esc(a.subject || "") +
      '<div class="sub">' + esc(a.detail || "") + " · " + pt(a.created_at) + "</div></div></div>").join("") + "</div>" : "";
  };
  paintAlerts();
  root.appendChild(alertsCard);
  // Fleet nature census (2.5.0): the fleet's real shape — how
  // many of each runtime / host / supervision class, which
  // grades are live right now, how many machines carry a GPU,
  // and who is non-compliant. Composed from the signed nature
  // declarations (operator-visible history's current state) +
  // the liveness rows/nodes; declared facts, labelled as such.
  const natureCard = document.createElement("div");
  const paintNature = () => {
    const dd = ctx.store.data;
    const users = dd.users || [];
    const by = (fn) => { const m = {}; for(const u of users){ const k = fn(u); m[k] = (m[k] || 0) + 1; } return m; };
    const dist = (m) => Object.entries(m).sort((a, b) => b[1] - a[1])
      .map(([k, n]) => esc(k) + " <b>" + n + "</b>").join(" · ") || "—";
    const runtime = by(u => (u.nature_profile || {}).runtime_kind || "undeclared");
    const hosts = by(u => (u.nature_profile || {}).host_class || "undeclared");
    const supervision = by(u => (u.nature_profile || {}).supervision || "undeclared");
    const classes = by(u => (u.nature_profile || {}).persistence_class || "undeclared");
    const grades = by(u => (u.livenessNode && u.livenessNode.grade) || (u.liveness && u.liveness.grade) || "unproven");
    const gpuCount = users.filter(u => (((u.nature_profile || {}).machine || {}).gpus || []).length > 0).length;
    const oses = by(u => { const os = ((u.nature_profile || {}).machine || {}).os || ""; return os ? os.split(" ")[0] : "undeclared"; });
    const nonCompliant = users.filter(u => {
      const rec = u.liveness; const node = u.livenessNode;
      if(node && node.nature_compliant !== undefined) return !node.nature_compliant;
      if(rec) return !rec.nature_compliant;
      return !(u.nature_version > 0);
    }).length;
    natureCard.innerHTML = '<div class="card"><h3>Fleet nature — the fleet\'s real shape (declared)</h3>' +
      '<p class="sub">Runtime: ' + dist(runtime) + '<br>Host: ' + dist(hosts) +
      '<br>Supervision: ' + dist(supervision) + '<br>Persistence class: ' + dist(classes) +
      '<br>Grades now: ' + dist(grades) + '<br>Hardware: <b>' + gpuCount + "</b> GPU-equipped of " +
      users.length + " · OS: " + dist(oses) +
      '<br>Non-compliant (no current nature declaration): <b>' + nonCompliant + "</b></p></div>";
  };
  paintNature();
  root.appendChild(natureCard);
  const grid = document.createElement("div");
  grid.className = "grid2";
  grid.innerHTML = '<div class="card"><h3>Groups &amp; Channels</h3><div class="gc"></div></div>' +
    '<div class="card"><h3><span class="live-dot"></span> Live activity</h3><div class="feed"></div><p class="sub" style="margin-top:10px"><a href="#/activity">Open the full Alerts &amp; Activity view →</a></p></div>';
  root.appendChild(grid);
  const paintGC = () => {
    const dd = ctx.store.data;
    grid.querySelector(".gc").innerHTML = table([["Name", r => esc(r.name || r.id)], ["Kind", r => dd.channels.includes(r) ? "channel" : "group"], ["Creator", r => esc(r.creator || "")], ["Members", r => String(dd.membersOf(r.id, dd.channels.includes(r)).length)]], [...dd.groups, ...dd.channels]);
  };
  paintGC();
  const feed = grid.querySelector(".feed");
  const paintFeed = () => { feed.innerHTML = ctx.store.data.activity.slice(0, 25).map(feedRow).join("") || '<p class="state">No activity yet.</p>'; };
  paintFeed();
  unsubs.push(ctx.bus.on("activity", () => paintFeed()));
  unsubs.push(ctx.bus.on("alerts", () => paintAlerts()));
  unsubs.push(ctx.bus.on("work", () => paintStats()));
  unsubs.push(ctx.bus.on("users", () => { paintStats(); paintGC(); paintNature(); }));
  unsubs.push(ctx.bus.on("liveness", () => paintNature()));
  unsubs.push(ctx.bus.on("conversations", () => paintStats()));
  return { destroy };
}
