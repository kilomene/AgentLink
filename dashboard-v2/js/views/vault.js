import { esc, pt, table, states, fail, fmtBytes, pill, parseJson, downloadBlob } from "../util.js";

// Group Vault: shared group files, pinned first, access-controlled
// by membership. Entries appear here live as agents add them.
// Downloads (owner's order, 2026-11-02): the owner personally
// downloads vault files here — the oversight Edge route unwraps
// the entry descriptor's file key and serves the bytes only after
// the sha256 + size check passes. Entries sealed before owner
// oversight existed carry no usable wrap and show the honest
// not-downloadable state — never a dead button.
let unsubs = [];
export function destroy(){ unsubs.forEach(u => u && u()); unsubs = []; }

export async function render(root, ctx){
  states(root);
  let d; try{ d = await ctx.getData(); }catch(e){ return fail(root, e); }
  destroy();
  let query = "";
  root.innerHTML = '<div class="vhead"><h2>Group Vault</h2><div class="vsub">Shared group files, pinned and access-controlled by membership. Entries appear here live as agents add them. Download serves the real file bytes inside your operator session, verified against the entry\'s hash by the oversight route before a single byte moves.</div></div>' +
    '<div class="card"><div class="filters"><input type="search" placeholder="Search name, group, added by…" aria-label="Search vault"></div><div class="vlt"></div></div>';
  const host = root.querySelector(".vlt");
  const search = root.querySelector("input[type=search]");
  const paint = () => {
    const dd = ctx.store.data;
    const rows = [...dd.vault].sort((a, b) => (b.pinned || 0) - (a.pinned || 0) || (b.ts || 0) - (a.ts || 0))
      .filter(e => !query || (e.name + " " + e.group_id + " " + e.added_by).toLowerCase().includes(query));
    host.innerHTML = rows.length ? table(
      [["Name", e => { const desc = parseJson(e.descriptor, {}); return "🗄 <b>" + esc(e.name) + "</b>" + (desc.mime ? "<br><small>" + esc(desc.mime) + "</small>" : ""); }],
       ["Group", e => esc(dd.nameOf ? dd.nameOf(e.group_id) : e.group_id)], ["Added by", e => esc(e.added_by)],
       ["Size", e => fmtBytes(e.size)], ["SHA-256", e => '<span class="mono">' + esc((e.sha256 || "").slice(0, 16)) + "…</span>"],
       ["Pinned", e => e.pinned ? "📌 pinned" : ""], ["When", e => pt(e.ts)],
       ["", e => { const desc = parseJson(e.descriptor, {}); const ok = desc && desc.oversight && desc.blob_nonce && desc.blob_id;
         return (ok ? '<button type="button" data-dl="' + esc(e.id) + '">Download</button> ' : '<span class="fmeta">not downloadable — stored before owner oversight existed</span> ') +
           '<button type="button" data-goto="' + esc(e.group_id) + '">Open group</button>'; }]], rows)
      : '<p class="state">No vault entries match.</p>';
    host.querySelectorAll("[data-dl]").forEach(b => b.onclick = async () => {
      const e = ctx.store.data.vault.find(x => x.id === b.dataset.dl);
      if(!e) return;
      const desc = parseJson(e.descriptor, {});
      b.disabled = true; const old = b.textContent; b.textContent = "Fetching…";
      try{
        const blob = await ctx.oversightVaultFile(desc);
        downloadBlob(blob, e.name || desc.name || "download");
        b.textContent = old;
      }catch(_){
        b.textContent = "Unavailable — unverifiable";
      }
      b.disabled = false;
    });
    host.querySelectorAll("[data-goto]").forEach(b => b.onclick = () => {
      ctx.store.pendingOpenConv = "group:" + b.dataset.goto;
      location.hash = "#/conversations";
    });
  };
  search.addEventListener("input", () => { query = search.value.trim().toLowerCase(); paint(); });
  paint();
  unsubs.push(ctx.bus.on("vault", paint));
  return { destroy };
}
