// Shared WhatsApp-style chat renderer (Conversations + Probe Tests).
// Two panes: a searchable conversation list (unread badges, live
// previews) and a thread pane (bubbles, day separators, read ticks).
// Content arrives ONLY from the Edge oversight function inside the
// operator session - envelopes are opened in batches as a thread is
// shown, and each live-arriving message is opened the same way the
// moment it lands. Monitor-only: nothing here can send anything.
import { esc, pt, ptime, pday, dayKey, avatar, senderColor, fmtBytes, downloadBlob, OWNER_SEAT, states, empty, fail } from "../util.js";

const WORK_KINDS = new Set(["work_assigned","work_delivered","work_completed","work_changes_requested","work_progress","work_awaiting_approval","work_approved","work_approval_rejected"]);
const kindLabel = k => k.replace(/_/g, " ");

export function ticksHtml(reads, item){
  const rs = (reads || []).filter(r => r.message_id === item.id);
  if(!rs.length) return ' <span class="ticks">✓✓</span>';
  return ' <span class="ticks read">✓✓</span> <span class="readby">read by ' + rs.map(r => esc(r.reader)).join(", ") + "</span>";
}

function previewOf(item){
  if(!item) return "no messages yet";
  if(item.opened && item.opened.text) return item.opened.text.slice(0, 90);
  if(item.opened && item.opened.file_name) return "📎 " + item.opened.file_name;
  if(item.kind === "message") return "message";
  if(item.kind === "group_message" || item.kind === "channel_message") return kindLabel(item.kind);
  return kindLabel(item.kind) + (item.status ? " · " + item.status : "");
}

// In-conversation files (owner's v1 ruling of 2026-11-03, carried
// into v2): a verified file renders IN the thread — images shown,
// video/audio playable — and every verified file downloads in
// place. Bytes come from the oversight file route, which serves
// them only after full verification; an unverifiable file shows
// the honest unavailable state, never a dead control. The size
// shown is the file's TRUE plaintext size from its payload.
function fileHtml(item, o){
  const id = esc(item.id);
  const name = esc(o.file_name);
  const size = o.file_size ? fmtBytes(o.file_size) : "";
  if(!o.file_verified){
    return '<div class="filecard"><span class="fic">📎</span><div><div class="fname">' + name + '</div><div class="fmeta">' +
      (size ? size + " · " : "") + 'file unavailable — its bytes could not be verified under oversight</div></div></div>';
  }
  const mime = o.file_mime || "";
  const dl = '<button type="button" class="dlbtn" data-filedl="' + id + '">Download</button>';
  const meta = '<div class="fmeta2"><span>' + name + (size ? " · " + size : "") + "</span>" + dl + "</div>";
  if(mime.startsWith("image/")) return '<div class="filewrap"><img class="chatmedia" data-filemedia="' + id + '" alt="' + name + '">' + meta + "</div>";
  if(mime.startsWith("video/")) return '<div class="filewrap"><video class="chatmedia" controls preload="metadata" data-filemedia="' + id + '"></video>' + meta + "</div>";
  if(mime.startsWith("audio/")) return '<div class="filewrap"><audio controls data-filemedia="' + id + '"></audio>' + meta + "</div>";
  return '<div class="filecard"><span class="fic">📎</span><div><div class="fname">' + name + '</div><div class="fmeta">' +
    (size ? size + " · " : "") + "verified under oversight</div></div>" + dl + "</div>";
}

export function bubbleHtml(item, reads){
  const mine = item.from === OWNER_SEAT;
  const name = item.sender_nickname ? item.sender_nickname + " (@" + item.from + ")" : (item.from || "");
  const chip = item.kind !== "message" && item.kind !== "group_message" && item.kind !== "channel_message"
    ? '<span class="kindchip">' + esc(kindLabel(item.kind)) + (item.status ? " · " + esc(item.status) : "") + "</span><br>" : "";
  // NO-PLACEHOLDER LAW (owner, 2026-11-06): a bubble exists
  // only with its opened content — the operator sees the detail
  // of every message, never a loading label, never a blank.
  // Unopened items are not painted at all; the painters below
  // render opened items only, and the open pass runs before and
  // during painting until every item lands.
  if(!item.opened) return "";
  const o = item.opened;
  let body = (o.title ? "<b>" + esc(o.title) + "</b><br>" : "") +
    (o.text ? '<span class="btxt">' + esc(o.text) + "</span>" : "") +
    (o.file_name ? fileHtml(item, o) : "");
  body = '<div class="btext" data-open-for="' + esc(item.id) + '">' + body + "</div>";
  return '<div class="msgrow' + (mine ? " mine" : "") + '" data-msgrow="' + esc(item.id) + '">' +
    '<div class="bubble">' + (name ? '<div class="sender" style="color:' + senderColor(item.from) + '">' + esc(name) + "</div>" : "") +
    chip + body +
    '<div class="bmeta">' + ptime(item.ts) + '<span data-ticks="' + esc(item.id) + '">' + ticksHtml(reads, item) + "</span></div>" +
    "</div></div>";
}

export function createChat(root, ctx, opts){
  const store = ctx.store;
  let destroyed = false;
  let openKey = null;
  let query = "";
  const opening = new Set();
  const unsubs = [];

  root.innerHTML = '<div class="chatwrap"><div class="chatlist"><div class="chatsearch"><input type="search" placeholder="Search chats…" aria-label="Search chats"></div><div class="chatlisthead">' + esc(opts.label) + '</div><div class="chatrows"></div></div>' +
    '<div class="chatpane"><div class="chatempty">Select a conversation to watch it live.<br><small>New messages arrive here in real time — nothing to refresh.</small></div></div></div>';
  const wrap = root.querySelector(".chatwrap");
  const rowsHost = root.querySelector(".chatrows");
  const pane = root.querySelector(".chatpane");
  const search = root.querySelector(".chatsearch input");
  search.addEventListener("input", () => { query = search.value.trim().toLowerCase(); renderList(); });

  // File bytes for this view instance: fetched once per item from
  // the oversight file route (verified server-side), cached as
  // blobs; media elements get object URLs off the same blobs.
  const fileBlobs = new Map();
  const fileUrls = new Map();
  function fileBlobFor(item){
    if(!fileBlobs.has(item.id)){
      const p = ctx.oversightFile(item);
      p.catch(() => fileBlobs.delete(item.id));
      fileBlobs.set(item.id, p);
    }
    return fileBlobs.get(item.id);
  }
  function hydrateMedia(scope){
    if(!scope || !scope.querySelectorAll) return;
    scope.querySelectorAll("[data-filemedia]").forEach(el => {
      if(el.dataset.hydrated) return;
      el.dataset.hydrated = "1";
      const conv = openKey ? store.findConv(openKey) : null;
      const item = conv ? conv.items.find(m => m.id === el.getAttribute("data-filemedia")) : null;
      if(!item) return;
      fileBlobFor(item).then(blob => {
        if(destroyed) return;
        let url = fileUrls.get(item.id);
        if(!url){ url = URL.createObjectURL(blob); fileUrls.set(item.id, url); }
        el.src = url;
      }).catch(() => {
        const wrap = el.closest(".filewrap");
        if(wrap) wrap.outerHTML = '<div class="filecard"><span class="fic">📎</span><div><div class="fname">' + esc(item.opened ? item.opened.file_name : "file") + '</div><div class="fmeta">file unavailable — its bytes could not be verified under oversight</div></div></div>';
      });
    });
  }
  pane.addEventListener("click", async ev => {
    const btn = ev.target.closest ? ev.target.closest("[data-filedl]") : null;
    if(!btn) return;
    const conv = openKey ? store.findConv(openKey) : null;
    const item = conv ? conv.items.find(m => m.id === btn.getAttribute("data-filedl")) : null;
    if(!item) return;
    btn.disabled = true;
    const old = btn.textContent;
    btn.textContent = "Fetching…";
    try{
      const blob = await fileBlobFor(item);
      downloadBlob(blob, (item.opened && item.opened.file_name) || "download");
      btn.textContent = old;
    }catch(_){
      btn.textContent = "Unavailable";
    }
    btn.disabled = false;
  });

  const convs = () => opts.getConvs(store.data);
  const convTitle = c => c.title || c.key.replace(/^group:|^dm:/, "");
  function matches(c){
    if(!query) return true;
    const people = (c.participants || []).map(p => typeof p === "string" ? p : p.username).join(" ");
    return (convTitle(c) + " " + people + " " + previewOf(c.items[c.items.length - 1])).toLowerCase().includes(query);
  }
  function renderList(flashKey){
    const list = convs().filter(matches);
    rowsHost.innerHTML = list.length ? list.map(c => {
      const last = c.items[c.items.length - 1];
      const unread = store.unreadOf(c.key);
      return '<div class="chatrow' + (c.key === openKey ? " sel" : "") + (c.key === flashKey ? " flash" : "") + '" data-key="' + esc(c.key) + '">' +
        avatar(c.group_id || (c.participants[0]?.username || c.participants[0] || "?"), !!c.group_id && !c.isChannel, !!c.isChannel) +
        '<div class="cmain"><div class="cname">' + esc(convTitle(c)) + '</div><div class="cprev">' + esc(previewOf(last)) + "</div></div>" +
        '<div class="cside"><span class="ctime">' + (last ? ptime(last.ts) : "") + "</span>" +
        (unread ? '<span class="unread">' + unread + "</span>" : "") + "</div></div>";
    }).join("") : '<p class="state" style="padding:10px 16px">No chats match.</p>';
    rowsHost.querySelectorAll(".chatrow").forEach(row => row.onclick = () => openConv(row.dataset.key, true));
  }

  // Paint the open thread from OPENED items only, in order —
  // the open-before-paint half of the no-placeholder law. An
  // item whose content has not opened yet simply is not on
  // screen; when its open lands, the next paint carries its
  // words. There is no placeholder state to rest in.
  function paintThread(stick){
    if(destroyed || !openKey) return;
    const conv = store.findConv(openKey);
    const msgs = pane.querySelector(".chatmsgs");
    if(!conv || !msgs) return;
    const nearBottom = msgs.scrollHeight - msgs.scrollTop - msgs.clientHeight < 160;
    let html = "", lastDay = "";
    for(const m of conv.items){
      if(!m.opened) continue;
      const dk = dayKey(m.ts);
      if(dk !== lastDay){ html += '<div class="daysep">' + esc(pday(m.ts)) + "</div>"; lastDay = dk; }
      html += bubbleHtml(m, store.data.reads);
    }
    msgs.innerHTML = html || (conv.items.length ? "" : '<div class="chatempty">No messages yet — this conversation is seeded and being watched live.</div>');
    hydrateMedia(msgs);
    if(stick || nearBottom) msgs.scrollTop = msgs.scrollHeight;
  }

  async function openItems(items){
    const todo = items.filter(m => m.oversight && !m.opened && !opening.has(m.id));
    for(let i = 0; i < todo.length; i += 40){
      const chunk = todo.slice(i, i + 40);
      chunk.forEach(m => opening.add(m.id));
      try{
        const opened = await ctx.oversight(chunk.map(m => ({ id: m.id, oversight: m.oversight, content_envelope: m.content_envelope })));
        for(const m of chunk){
          opening.delete(m.id);
          const o = opened ? opened[m.id] : null;
          // An open that comes back with no words and no file is NOT
          // an open: the item stays unopened (so it is never painted)
          // and the convergence pass keeps retrying it. NO-PLACEHOLDER
          // LAW: a bubble may only ever appear with its content in it.
          if(o && (o.text || o.title || o.file_name)){ m.opened = o; m.sealed = false; }
        }
        if(!destroyed){ renderList(); paintThread(); }
      }catch(_){
        // No final failure state: the ids are released and the
        // convergence pass below retries until the text lands.
        chunk.forEach(m => opening.delete(m.id));
      }
    }
  }

  // Reload persistence: the open thread is remembered per chat
  // view (sessionStorage — survives a reload, not a tab close),
  // so refreshing the browser returns to the exact conversation
  // the operator was reading, never to a bare list or menu.
  const persistKey = "al_open_conv_" + (opts.label || "chats");
  function openConv(key, focus){
    const conv = store.findConv(key);
    if(!conv) return;
    openKey = key;
    store.openConvKey = key;
    try{ sessionStorage.setItem(persistKey, key); }catch(_){}
    store.markConvRead(key);
    wrap.classList.add("open");
    renderList();
    const people = (conv.participants || []).map(p => typeof p === "string" ? p : (p.nickname ? p.nickname + " (@" + p.username + ")" : p.username));
    const peerState = !conv.group_id && people.length ? (() => { const other = (conv.participants || []).map(p => typeof p === "string" ? p : p.username).find(n => n !== OWNER_SEAT);
      const u = [...store.data.users, ...store.data.testUsers].find(x => x.username === other); return u ? " · " + (u.activeness || "offline") : ""; })() : "";
    pane.innerHTML = '<div class="chathead"><button class="chatback" type="button" aria-label="Back to chat list">←</button>' +
      avatar(conv.group_id || (conv.participants[0]?.username || conv.participants[0] || "?"), !!conv.group_id && !conv.isChannel, !!conv.isChannel) +
      '<div><div class="ttl">' + esc(convTitle(conv)) + '</div><div class="sub2">' + esc(people.join(", ") || conv.key) + esc(peerState) + " · live</div></div></div>" +
      '<div class="chatmsgs"></div>';
    pane.querySelector(".chatback").onclick = () => { wrap.classList.remove("open"); openKey = null; store.openConvKey = null; try{ sessionStorage.removeItem(persistKey); }catch(_){} };
    paintThread(true);
    openItems(conv.items);
    // DASHBOARD NEVER ERASES (Disappearing Mode v2): merge the
    // conversation's OWNER-ARCHIVE items — disappearing messages
    // live only there once their delivery copies erase (and are
    // never in the audit history at all). Already-opened items,
    // merged by id, painted by the same open-before-paint path.
    if(ctx.archiveConversation){
      ctx.archiveConversation(conv).then(archived => {
        if(destroyed || !archived.length) return;
        const have = new Set(conv.items.map(m => m.id));
        const fresh = archived.filter(m => !have.has(m.id));
        if(!fresh.length) return;
        conv.items.push(...fresh);
        conv.items.sort((a, b) => a.ts - b.ts || (a.seq || 0) - (b.seq || 0));
        renderList(); paintThread();
      }).catch(() => {});
    }
    if(focus){ const msgs = pane.querySelector(".chatmsgs"); if(msgs) msgs.scrollTop = msgs.scrollHeight; }
  }

  function appendLive(key, item){
    if(key !== openKey) { renderList(key); return; }
    const msgs = pane.querySelector(".chatmsgs");
    if(!msgs) { renderList(key); return; }
    // Open-before-paint for live arrivals too: an item is drawn
    // only once its content is in hand — never as a placeholder.
    if(item.opened){
      paintThread();
      const row = msgs.querySelector('[data-msgrow="' + CSS.escape(item.id) + '"]');
      if(row) row.classList.add("flash");
    }else if(item.oversight){
      openItems([item]);
    }
    renderList();
  }

  unsubs.push(ctx.bus.on("conversations", ({ key, item }) => { if(!destroyed && item) appendLive(key, item); }));
  unsubs.push(ctx.bus.on("reads", r => {
    if(destroyed || !openKey) return;
    const conv = store.findConv(openKey);
    if(!conv) return;
    const item = conv.items.find(m => m.id === r.message_id);
    if(!item) return;
    const el = pane.querySelector('[data-ticks="' + CSS.escape(item.id) + '"]');
    if(el) el.innerHTML = ticksHtml(store.data.reads, item);
  }));
  unsubs.push(ctx.bus.on("unread", () => { if(!destroyed) renderList(); }));
  if(store.pendingOpenConv){ const k = store.pendingOpenConv; store.pendingOpenConv = null; if(store.findConv(k)) openConv(k, false); }
  else { let k = null; try{ k = sessionStorage.getItem(persistKey); }catch(_){} if(k && store.findConv(k)) openConv(k, false); }
  renderList();

  // Convergence: an item whose open batch hung, failed or was
  // omitted upstream must still arrive at its text. Re-run the
  // open pass for the open conversation until every wrapped item
  // is opened — a bubble never rests on a placeholder.
  const convergeTimer = setInterval(() => {
    if(destroyed || !openKey) return;
    const conv = store.findConv(openKey);
    if(conv) openItems(conv.items.filter(m => m.oversight && !m.opened));
  }, 8000);

  return {
    destroy(){ destroyed = true; clearInterval(convergeTimer); unsubs.forEach(u => u && u()); fileUrls.forEach(u => URL.revokeObjectURL(u)); fileUrls.clear(); fileBlobs.clear(); if(store.openConvKey === openKey) store.openConvKey = null; },
    refresh(){ renderList(); if(openKey && store.findConv(openKey)) openConv(openKey, false); }
  };
}
