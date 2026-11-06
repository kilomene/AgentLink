// Live store: the composed dashboard dataset (from data.js loadAll)
// plus every pushed change applied in place. Views read from here
// and subscribe to the bus for the slices they show; when a realtime
// event lands, the store mutates the data and emits, and the visible
// view updates itself - no navigation, no refetch, no manual
// refresh. Unread tracking is operator-side bookkeeping: a
// conversation is "unread" when content arrives while it is not the
// open one; opening it clears the badge. Baselines are set at load,
// so history never masquerades as new mail.
import { CONTENT_KINDS, convKeyOf, itemOf, partiesTest } from "./data.js";
import { computeTrust } from "./trust.js";
import { OWNER_SEAT } from "./util.js";

const listeners = new Map();
export function on(kind, cb){
  if(!listeners.has(kind)) listeners.set(kind, new Set());
  listeners.get(kind).add(cb);
  return () => listeners.get(kind)?.delete(cb);
}
function emit(kind, payload){
  (listeners.get(kind) || []).forEach(cb => { try{ cb(payload); }catch(_){} });
  (listeners.get("*") || []).forEach(cb => { try{ cb(kind, payload); }catch(_){} });
}

export const store = {
  data: null,
  openConvKey: null,
  unread: new Map(),       // convKey -> count of unseen items
  readMark: new Map(),     // convKey -> highest ts the operator has seen
  lastQueueSeq: 0,
  seenAuditSeq: new Set(),

  setData(d){
    this.data = d;
    this.unread.clear(); this.readMark.clear(); this.seenAuditSeq.clear();
    for(const r of d.auditAsc || []) if(r.seq) this.seenAuditSeq.add(r.seq);
    for(const c of [...d.conversations, ...d.testConversations]){
      this.readMark.set(c.key, c.lastTs || 0);
      this.unread.set(c.key, 0);
    }
    this.lastQueueSeq = (d.queue || []).reduce((m, q) => Math.max(m, q.seq || 0), 0);
  },

  convLists(){ return [this.data.conversations, this.data.testConversations]; },
  findConv(key){
    for(const list of this.convLists()){ const c = list.find(x => x.key === key); if(c) return c; }
    return null;
  },
  isTestConv(c){
    const d = this.data;
    if(c.group_id){
      const members = d.membersOf(c.group_id, c.isChannel);
      return partiesTest(members, d.designation);
    }
    return partiesTest((c.participants || []).map(p => typeof p === "string" ? p : p.username), d.designation);
  },

  markConvRead(key){
    const c = this.findConv(key);
    if(c) this.readMark.set(key, Math.max(this.readMark.get(key) || 0, c.lastTs || 0));
    if(this.unread.get(key)){ this.unread.set(key, 0); emit("unread", { key, count: 0 }); }
    emit("badges", {});
  },
  unreadOf(key){ return this.unread.get(key) || 0; },
  unreadTotal(){ let n = 0; this.unread.forEach(v => { n += v; }); return n; },

  // ---------------- pushed changes ----------------
  applyEvent({ table, eventType, row }){
    if(!this.data || !row) return;
    switch(table){
      case "al_audit_log": return this.applyAudit(row);
      case "al_queue": return this.applyQueue(row);
      case "al_message_reads": return this.applyRead(row);
      case "al_work": return this.applyWork(row, eventType);
      case "al_work_deliveries": return this.applyDelivery(row);
      case "al_users": return this.applyUser(row);
      case "al_activeness": return this.applyActiveness(row);
      case "al_alerts": return this.applyAlert(row, eventType);
      case "al_grants": return this.applyGrant(row);
      case "al_grant_receipts": return this.applyReceipt(row);
      case "al_grant_approvals": return this.applyApproval(row);
      case "al_rooms": return this.applyRoom(row, eventType);
      case "al_library": return this.applyLibrary(row);
      case "al_vault": return this.applyVault(row, eventType);
      case "al_chains": return this.applyChain(row, eventType);
      case "al_chain_steps": return this.applyStep(row);
      case "al_groups": case "al_channels":
      case "al_group_members": case "al_channel_members":
        return emit("structure", { table, row });
      default: return;
    }
  },

  applyAudit(r){
    const d = this.data;
    if(r.seq && this.seenAuditSeq.has(r.seq)) return;
    if(r.seq) this.seenAuditSeq.add(r.seq);
    d.auditAsc.push(r);
    d.activity.unshift(r);
    emit("activity", r);
    if(!CONTENT_KINDS.has(r.kind)) return;
    const key = convKeyOf(r);
    let conv = this.findConv(key);
    if(!conv){
      const test = this.isTestConv({ group_id: r.group_id || null, isChannel: false,
        participants: [r.actor, r.target].filter(Boolean) });
      conv = { key, group_id: r.group_id || null, isChannel: false,
        title: r.group_id ? (d.nameOf ? d.nameOf(r.group_id) : r.group_id) : [r.actor, r.target].filter(Boolean).sort().join(" ↔ "),
        participants: r.group_id ? [] : [r.actor, r.target].filter(Boolean).sort(), items: [] };
      (test ? d.testConversations : d.conversations).unshift(conv);
    }
    const item = itemOf(r);
    if(conv.items.some(m => m.id === item.id && m.ts === item.ts)) return;
    conv.items.push(item);
    conv.items.sort((a, b) => a.ts - b.ts || (a.seq || 0) - (b.seq || 0));
    conv.lastTs = Math.max(conv.lastTs || 0, item.ts);
    const list = this.isTestConv(conv) ? d.testConversations : d.conversations;
    const idx = list.indexOf(conv);
    if(idx > 0){ list.splice(idx, 1); list.unshift(conv); }
    if(this.openConvKey !== key && item.from !== OWNER_SEAT){
      this.unread.set(key, (this.unread.get(key) || 0) + 1);
      emit("unread", { key, count: this.unread.get(key) });
      emit("badges", {});
    }
    if(this.openConvKey === key) this.readMark.set(key, Math.max(this.readMark.get(key) || 0, item.ts));
    emit("conversations", { key, item, conv });
  },

  applyQueue(r){
    if(r.seq && r.seq <= this.lastQueueSeq) return;
    if(r.seq) this.lastQueueSeq = r.seq;
    this.data.queue.unshift(r);
    emit("queue", r);
  },

  applyRead(r){
    const d = this.data;
    if(!d.reads.some(x => x.message_id === r.message_id && x.reader === r.reader)) d.reads.push(r);
    emit("reads", r);
  },

  upsertBy(list, key, row){
    const i = list.findIndex(x => x[key] === row[key]);
    if(i >= 0){ list[i] = { ...list[i], ...row }; return list[i]; }
    list.unshift(row); return row;
  },

  applyWork(r, eventType){
    const d = this.data;
    const test = partiesTest([r.assigner, r.assignee], d.designation);
    const row = this.upsertBy(test ? d.testWork : d.work, "id", r);
    // trust moves with proven work; recompute the two parties.
    for(const name of [r.assigner, r.assignee]){
      const u = [...d.users, ...d.testUsers].find(x => x.username === name);
      if(u) u.trust_score = computeTrust(name, [...d.work, ...d.testWork], d.auditAsc, Math.floor(Date.now() / 1000));
    }
    emit("work", { row, eventType });
    emit("badges", {});
  },

  applyDelivery(r){
    this.upsertBy(this.data.deliveries, "id", r);
    emit("work", { delivery: r });
  },

  applyUser(r){
    const d = this.data;
    const list = r.designation === "test" ? d.testUsers : d.users;
    const existing = list.find(x => x.username === r.username);
    if(existing) Object.assign(existing, r);
    else list.push({ ...r, trust_score: 50, online: false, connectors: [], grant: null });
    emit("users", r);
  },

  applyActiveness(r){
    const d = this.data;
    d.activeness[r.username] = r;
    const u = [...d.users, ...d.testUsers].find(x => x.username === r.username);
    if(u) u.activenessMirror = r;
    emit("activeness", r);
  },

  applyAlert(r, eventType){
    const d = this.data;
    this.upsertBy(d.alerts, "id", r);
    d.alerts.sort((a, b) => (b.created_at || 0) - (a.created_at || 0));
    emit("alerts", { row: r, eventType });
    emit("badges", {});
  },

  applyGrant(r){
    const d = this.data;
    const u = [...d.users, ...d.testUsers].find(x => x.username === r.username);
    if(u) u.grant = r;
    emit("grants", { grant: r });
  },

  applyReceipt(r){
    const d = this.data;
    const test = d.designation.get(r.username) === "test";
    const list = test ? d.testGrantActivity : d.grantActivity;
    if(!list.some(x => x.id === r.id)) list.unshift(r);
    emit("grants", { receipt: r });
  },

  applyApproval(r){
    const d = this.data;
    const test = d.designation.get(r.username) === "test";
    this.upsertBy(test ? d.testGrantApprovals : d.grantApprovals, "id", r);
    emit("grants", { approval: r });
  },

  applyRoom(r, eventType){
    this.upsertBy(this.data.rooms, "room_id", r);
    emit("rooms", { row: r, eventType });
  },

  applyLibrary(r){
    const d = this.data;
    const test = partiesTest([r.sender, r.to_user], d.designation);
    this.upsertBy(test ? d.testLibrary : d.library, "id", r);
    emit("library", r);
  },

  applyVault(r, eventType){
    this.upsertBy(this.data.vault, "id", r);
    this.upsertBy(this.data.testVault, "id", r);
    emit("vault", { row: r, eventType });
  },

  applyChain(r, eventType){
    const d = this.data;
    for(const list of [d.chains, d.testChains]){
      const c = list.find(x => x.id === r.id);
      if(c){ Object.assign(c, r); emit("chains", { row: c, eventType }); return; }
    }
    emit("chains", { row: r, eventType });
  },

  applyStep(r){
    const d = this.data;
    for(const list of [d.chains, d.testChains]){
      const c = list.find(x => x.id === r.chain_id);
      if(c){
        const i = c.steps.findIndex(s => s.id === r.id);
        if(i >= 0) c.steps[i] = { ...c.steps[i], ...r }; else c.steps.push(r);
        c.steps.sort((a, b) => (a.position || 0) - (b.position || 0));
        emit("chains", { row: c, step: r });
        return;
      }
    }
    emit("chains", { step: r });
  }
};
