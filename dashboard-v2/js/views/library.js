import { esc, pt, table, states, fail, fmtBytes, pill, downloadBlob } from "../util.js";

// Delivery Library: every delivery on the line, indexed by name,
// sender and hash - pushed live as deliveries land. Rows link into
// the conversation that carried them. Downloads (owner's order,
// 2026-11-02): the owner personally downloads deliverables here —
// the oversight Edge route resolves each entry through its work's
// delivery wraps and serves the bytes only after the sha256 +
// size check passes; an entry whose bytes cannot be verified
// (e.g. sealed before owner oversight existed) says so honestly
// on the button instead of failing silently.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  let query = "";
  root.innerHTML = '<div class="vhead"><h2>Delivery Library</h2><div class="vsub">Every delivery on the line, indexed by name, sender and hash. New deliveries appear here live. Download serves the real file bytes inside your operator session, verified against the entry\'s hash by the oversight route before a single byte moves.</div></div>' +
    '<div class="card"><div class="filters"><input type="search" placeholder="Search filename, sender, recipient, hash…" aria-label="Search library"></div><div class="lib"></div></div>';
  const host = root.querySelector(".lib");
  const search = root.querySelector("input[type=search]");
  const paint = () => {
    const dd = ctx.store.data;
    const rows = dd.library.filter(e => !query || (e.filename + " " + e.sender + " " + e.to_user + " " + e.sha256 + " " + e.work_id).toLowerCase().includes(query));
    host.innerHTML = rows.length ? table(
      [["File", e => "📎 <b>" + esc(e.filename) + "</b>"], ["From", e => esc(e.sender)], ["To", e => esc(e.to_user || e.group_id || "")],
       ["Size", e => fmtBytes(e.size)], ["SHA-256", e => '<span class="mono">' + esc((e.sha256 || "").slice(0, 16)) + "…</span>"],
       ["Work", e => '<span class="mono">' + esc(e.work_id || "") + "</span>"], ["When", e => pt(e.ts)],
       ["", e => '<button type="button" data-dl="' + esc(e.id) + '">Download</button> <button type="button" data-find="' + esc(e.id) + '">View delivery</button>']], rows)
      : '<p class="state">No library entries match.</p>';
    host.querySelectorAll("[data-dl]").forEach(b => b.onclick = async () => {
      const e = ctx.store.data.library.find(x => x.id === b.dataset.dl);
      if(!e) return;
      b.disabled = true; const old = b.textContent; b.textContent = "Fetching…";
      try{
        const blob = await ctx.oversightLibraryFile(e);
        downloadBlob(blob, e.filename || "download");
        b.textContent = old;
      }catch(_){
        b.textContent = "Unavailable — unverifiable";
      }
      b.disabled = false;
    });
    host.querySelectorAll("[data-find]").forEach(b => b.onclick = () => {
      const e = ctx.store.data.library.find(x => x.id === b.dataset.find);
      if(!e) return;
      const conv = [...ctx.store.data.conversations].find(c => c.items.some(m => m.work_id === e.work_id) ) ||
        [...ctx.store.data.conversations].find(c => c.items.some(m => (m.opened && m.opened.file_name === e.filename)));
      if(conv){ ctx.store.pendingOpenConv = conv.key; location.hash = "#/conversations"; }
      else { b.textContent = "Not in a visible thread"; b.disabled = true; }
    });
  };
  search.addEventListener("input", () => { query = search.value.trim().toLowerCase(); paint(); });
  paint();
  unsubs.push(ctx.bus.on("library", paint));
  return { destroy };
}
