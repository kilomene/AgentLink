"use strict";
/*
 * AgentLink live-layer Cloud Functions (2.4.0, compute
 * diversification — owner, 2026-11-10): the work that MOVES to
 * Firebase. What stays on Supabase Edge, by hard boundary:
 * login/identity (Firebase is NEVER auth), registry/account,
 * support, work state, dashboard sessions, and everything whose
 * home is the Postgres data. What lives here is pure live-layer
 * work over RTDB + the owner-archive service:
 *
 *   archiveDeposit / archiveRead  the Disappearing Mode v2
 *                                 fail-closed deposit + the
 *                                 dashboard's archive read path
 *                                 (Drive-backed via driveStore;
 *                                 core logic in archiveCore.js)
 *   transitHousekeeping           RTDB-triggered cleanup when a
 *                                 transit inbox node is consumed
 *   presenceHousekeeping          scheduled stale-presence prune
 *   directoryMirror               directory working-copy
 *                                 maintenance on RTDB writes
 *   signalRelay                   pure-RTDB signal fan-out
 *
 * SAFETY CAPS (from the first deploy, so usage stays inside the
 * no-cost allotments): every function carries maxInstances <= 3,
 * short timeouts, small memory, and event retries OFF — a failed
 * housekeeping pass is retried by the next event, never by a
 * retry storm. Logging is ERROR-ONLY (the 2.4.0 log-ingestion
 * discipline; a gate test pins it).
 *
 * Configuration (function environment / .env):
 *   ARCHIVE_ROOT_FOLDER_ID  the owner's Drive archive root
 *                           folder, shared with this function's
 *                           service account (server-side only)
 *   ARCHIVE_SERVICE_TOKEN   shared secret the clients' deposit
 *                           calls present (X-Archive-Token)
 *   OPERATOR_SESSION_TOKEN  the dashboard operator-session proof
 *                           the read path requires
 *   OVERSIGHT_PRIVATE_KEY_B64  the oversight private key, held
 *                           ONLY here for the read path's
 *                           server-side decrypt (operator
 *                           session only)
 */
const { onRequest } = require("firebase-functions/v2/https");
const { onValueCreated, onValueDeleted, onValueWritten } =
  require("firebase-functions/v2/database");
const { onSchedule } = require("firebase-functions/v2/scheduler");
const admin = require("firebase-admin");

admin.initializeApp();

const core = require("./archiveCore");
const { DriveStore } = require("./driveStore");

const CAPS = { maxInstances: 3, timeoutSeconds: 30, memory: "128MiB" };
const ARCHIVE_CAPS = {
  maxInstances: 3, timeoutSeconds: 60, memory: "256MiB",
};

function _archiveStore() {
  const root = process.env.ARCHIVE_ROOT_FOLDER_ID;
  if (!root) {
    throw new core.ArchiveError(
      "ARCHIVE_ROOT_FOLDER_ID not configured — deposit service " +
      "is fail-closed until the archive root folder is shared " +
      "with this function's service account");
  }
  return new DriveStore(root);
}

function _sendJson(res, status, obj) {
  res.status(status).set("Content-Type", "application/json")
    .send(JSON.stringify(obj));
}

/* ---------------- archive deposit (fail-closed) ---------------- */

exports.archiveDeposit = onRequest(ARCHIVE_CAPS, async (req, res) => {
  try {
    if (req.method !== "POST") {
      return _sendJson(res, 405, { confirmed: false,
        error: "POST only" });
    }
    const token = process.env.ARCHIVE_SERVICE_TOKEN;
    if (!token || req.get("X-Archive-Token") !== token) {
      return _sendJson(res, 401, { confirmed: false,
        error: "unauthorized" });
    }
    const conf = await core.deposit(_archiveStore(), req.body);
    return _sendJson(res, 200, conf);
  } catch (err) {
    console.error("archiveDeposit failed:", err.message);
    return _sendJson(res, 502, { confirmed: false,
      error: String(err.message || err) });
  }
});

/* ------------- archive read (operator session only) ------------ */

exports.archiveRead = onRequest(ARCHIVE_CAPS, async (req, res) => {
  try {
    const op = process.env.OPERATOR_SESSION_TOKEN;
    if (!op || req.get("X-Operator-Session") !== op) {
      return _sendJson(res, 401, { error: "operator session required" });
    }
    const priv = process.env.OVERSIGHT_PRIVATE_KEY_B64;
    if (!priv) {
      return _sendJson(res, 500, {
        error: "oversight key not configured on the read service" });
    }
    const agent = String(req.query.agent || "");
    const conversation = String(req.query.conversation || "");
    if (!agent || !conversation) {
      return _sendJson(res, 400, {
        error: "agent and conversation are required" });
    }
    const entries = await core.readConversation(
      _archiveStore(), agent, conversation);
    return _sendJson(res, 200, {
      agent, conversation,
      entries: core.renderEntries(priv, entries),
    });
  } catch (err) {
    console.error("archiveRead failed:", err.message);
    return _sendJson(res, 502, { error: String(err.message || err) });
  }
});

/* ----------------- transit housekeeping (RTDB) ----------------- */
/*
 * When a transit inbox node is consumed (deleted), remove the
 * item's bookkeeping node alongside it. Pure RTDB work: no
 * Supabase call, no egress beyond the RTDB write itself.
 * NOTE (Disappearing Mode v2): housekeeping NEVER expires
 * unread items — it reacts to consumption only; there is no
 * time-based purge of transit anywhere in this codebase.
 */
exports.transitHousekeeping = onValueDeleted(
  { ref: "/inbox/{user}/{item}", ...CAPS, retry: false },
  async (event) => {
    const { user, item } = event.params;
    try {
      await admin.database()
        .ref(`/inbox_meta/${user}/${item}`).remove();
    } catch (err) {
      console.error("transitHousekeeping failed:", err.message);
    }
  });

/* ---------------- presence housekeeping (schedule) ------------- */
/*
 * Prune presence nodes that are stale far beyond the activeness
 * ladder (online 240s / suspect 420s): a node untouched for
 * 15 minutes belongs to a client that died without its
 * onDisconnect landing. Presence truth stays the ladder's —
 * this only collects corpses. Anomaly-only logging.
 */
const PRESENCE_CORPSE_AGE_MS = 15 * 60 * 1000;

exports.presenceHousekeeping = onSchedule(
  {
    schedule: "every 5 minutes",
    ...CAPS,
    retryCount: 1,
  },
  async () => {
    try {
      const snap = await admin.database().ref("/presence").get();
      const now = Date.now();
      const updates = {};
      snap.forEach((child) => {
        const v = child.val() || {};
        const ts = Number(v.ts || v.updated_at || 0);
        const tsMs = ts < 1e12 ? ts * 1000 : ts;
        if (tsMs && now - tsMs > PRESENCE_CORPSE_AGE_MS) {
          updates[child.key] = null;
        }
      });
      if (Object.keys(updates).length) {
        await admin.database().ref("/presence").update(updates);
      }
    } catch (err) {
      console.error("presenceHousekeeping failed:", err.message);
    }
  });

/* --------------- directory working copy (RTDB) ----------------- */
/*
 * Maintain /directory_index: the minimal live working copy of
 * the agent directory (pubkey + sign key + stamp per username)
 * that live-layer consumers read without touching Supabase. The
 * Postgres directory stays the record; this is its RTDB mirror,
 * maintained on write events only — no polling.
 */
exports.directoryMirror = onValueWritten(
  { ref: "/directory/{username}", ...CAPS, retry: false },
  async (event) => {
    const { username } = event.params;
    try {
      const after = event.data.after.val();
      const ref = admin.database()
        .ref(`/directory_index/${username}`);
      if (!after) {
        await ref.remove();
        return;
      }
      await ref.set({
        pubkey: after.pubkey || "",
        sign_pub: after.sign_pub || "",
        ts: Number(after.ts || 0),
      });
    } catch (err) {
      console.error("directoryMirror failed:", err.message);
    }
  });

/* -------------------- signal relay (RTDB) ---------------------- */
/*
 * Pure-RTDB signal fan-out: a queued signal lands under its
 * conversation's tap node (the shape clients listen on) and the
 * queue node is removed. One event in, one fan-out, no Supabase.
 */
exports.signalRelay = onValueCreated(
  { ref: "/signal_queue/{user}/{id}", ...CAPS, retry: false },
  async (event) => {
    const { user, id } = event.params;
    try {
      const val = event.data.val() || {};
      const conv = String(val.conversation_key || "");
      if (!conv) return;
      await admin.database()
        .ref(`/signals/${conv}/${id}`).set({
          from_user: user,
          item_id: String(val.item_id || id),
          ts: Number(val.ts || 0),
        });
      await event.data.ref.remove();
    } catch (err) {
      console.error("signalRelay failed:", err.message);
    }
  });
