// AgentLink v2.0 — doorbell tapper Edge Function (Phase 2, owner
// refinement 2026-11-05). The control-path tapper: it receives
// Supabase database-webhook POSTs (and direct internal POSTs) for
// LOW-VOLUME CONTROL events only, and taps the targets' Firebase
// RTDB doorbells. It is the server-side counterpart of
// agentlink/doorbell.py's client — same node shapes, same field
// allowlists, same sanitized keys — except this leg writes with a
// Google OAuth2 access token minted from the service account
// (../_shared/v200.ts mintGoogleAccessToken), because a server
// tapper holds no agent custom token and the Admin-style bypass
// belongs here, never in an agent (doorbell.py's own words).
//
// WEBHOOK SETUP (see phase2-edge.md for the full note): point ONE
// Supabase Database Webhook at this function — INSERT on
// al_doorbell_outbox (Phase 1's triggers on al_work / al_alerts
// already convert control events into outbox rows). Webhooks on
// al_work / al_alerts are also accepted for pre-extracted
// metadata-only payloads, but the outbox is the primary, intended
// path. NEVER put a webhook on al_queue or al_audit_log (the
// message tables): messages wake peers through the SENDER's own
// RTDB signal write, and the blueprint's doorbell rule forbids
// webhooks there. This function additionally refuses any other
// table outright.
//
//   POST  header x-agentlink-webhook-secret: <AGENTLINK_WEBHOOK_SECRET>
//         (also accepted: x-webhook-secret, or Authorization: Bearer)
//         Supabase webhook shape {type?, table, record, old_record?}
//         or a direct internal POST of the same shape. A direct
//         POST may add top-level conversation_id + latest_item_id
//         to also bump a conversation signal.
//     ->  {ok:true, tapped:[<usernames>], signal:<bool>,
//          outbox_marked:<bool>}
//     401 {error:"unauthorized"}        webhook secret mismatch
//     400 {error:"content_forbidden"}   record carries a content
//                                        field (see below)
//     400 {error:"unsupported_table"}   not a control table
//     502 {error:"doorbell_failed"}     RTDB write failed; the
//                                        outbox row is NOT marked,
//                                        so the tap stays visibly
//                                        pending (stale-tap sweep)
//
// CONTENT LAW: RTDB carries ids / refs / kinds / counters ONLY —
// never message content, never ciphertext, never envelopes. That
// is enforced DEFENSIVELY here: before anything is extracted, the
// record is scanned (top level and one level down) for content
// fields (body, text, plaintext, message, content, content_enc,
// content_self, content_group, content_next, ct, ciphertext,
// envelope, oversight, vault_content, file_data) and the whole
// POST is REJECTED if one is present. Consequence, stated plainly:
// a raw full-row webhook on al_work (whose rows legitimately hold
// content_enc ciphertext) will be refused — that is by design; let
// the Phase-1 triggers turn it into an outbox row, or POST a
// metadata-only record subset. What this function WRITES is built
// field-by-field from allowlists — exactly doorbell.py's
// DOORBELL_FIELDS {kind, ref, ts} and SIGNAL_FIELDS
// {latest_item_id, counter, ts} — never copied from the record.
//
// EXTRACTION:
//   al_doorbell_outbox record {id, username, ref, kind}
//     -> tap username; kind/ref pass through the allowlist.
//   al_work record {id, assignee, assigner, group_id, status}
//     -> INSERT: kind work_assigned, tap assignee.
//        UPDATE: kind work_status, tap assignee AND assigner.
//        ref = group_id when set, else the work id (the Phase-1
//        trigger's own rule).
//   al_alerts record {id, subject}
//     -> kind alert, tap `subject` (the Phase-1 trigger stores the
//        target username in al_alerts.subject), ref = alert id.
//        A subject-less alert taps nobody ({tapped:[]}).
// RTDB keys use doorbell.py's sanitize_key (v200.ts sanitizeKey):
// /doorbell/<sanitized username>, /signals/<sanitized conversation
// id>. Doorbell writes are PUT {kind, ref, ts:{".sv":"timestamp"}}
// (server timestamp, as doorbell.py writes). Signal bumps are a
// transaction-ish read-modify-write — GET the node, counter+1,
// PATCH {latest_item_id, counter, ts:{".sv":"timestamp"}} — with
// doorbell.py's own caveat: a lost increment under a race is
// harmless, because a signal can only cause a fetch.
//
// TAPPED MARKING: when the payload is an al_doorbell_outbox row
// carrying an id, the row is marked tapped=true (service role)
// AFTER the RTDB write succeeds — never before, never on failure.
//
// FAILURE MODE (by design): a missed tap is HARMLESS. The Supabase
// journal/queue re-offers unacked work on reconnect, and agents
// slow-sync Supabase directly every 60s while the doorbell leg is
// degraded (V2-BLUEPRINT fallback). This function failing can cost
// latency, never a message.
//
// Deploy: supabase functions deploy agentlink-doorbell
// Secrets (NAMES only): SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY,
// AGENTLINK_WEBHOOK_SECRET, FIREBASE_SERVICE_ACCOUNT_JSON,
// FIREBASE_DATABASE_URL.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import {
  bearerToken,
  constantTimeEqual,
  env,
  errorResponse,
  jsonResponse,
  methodGuard,
  mintGoogleAccessToken,
  patchRows,
  sanitizeKey,
  selectOne,
} from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

const ALLOWED_TABLES = new Set(["al_doorbell_outbox", "al_work", "al_alerts"]);

const CONTENT_FIELDS = new Set([
  "body",
  "text",
  "plaintext",
  "message",
  "content",
  "content_enc",
  "content_self",
  "content_group",
  "content_next",
  "ct",
  "ciphertext",
  "envelope",
  "oversight",
  "vault_content",
  "file_data",
]);

function containsContentField(value: unknown, depth: number): string | null {
  if (!value || typeof value !== "object" || depth > 1) return null;
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    if (CONTENT_FIELDS.has(k.toLowerCase())) return k;
    const nested = containsContentField(v, depth + 1);
    if (nested) return nested;
  }
  return null;
}

function webhookAuthorized(req: Request): boolean {
  const secret = env("AGENTLINK_WEBHOOK_SECRET");
  if (!secret) return false; // fail closed; the 500 below names it
  const presented = req.headers.get("x-agentlink-webhook-secret") ??
    req.headers.get("x-webhook-secret") ??
    bearerToken(req);
  return Boolean(presented) && constantTimeEqual(presented, secret);
}

interface Tap {
  username: string;
  kind: string;
  ref: string;
}

async function rtdb(
  token: string,
  method: string,
  path: string,
  body?: unknown,
): Promise<unknown> {
  const base = env("FIREBASE_DATABASE_URL").replace(/\/+$/, "");
  if (!base) {
    throw new Error("FIREBASE_DATABASE_URL is not set in this function's env");
  }
  const resp = await fetch(base + "/" + path + ".json", {
    method,
    headers: {
      authorization: "Bearer " + token,
      "content-type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!resp.ok) {
    throw new Error("RTDB " + method + " " + path + ": HTTP " + resp.status);
  }
  return resp.status === 204 ? null : await resp.json().catch(() => null);
}

Deno.serve(async (req: Request) => {
  const guard = methodGuard(req);
  if (guard) return guard;

  if (!env("AGENTLINK_WEBHOOK_SECRET")) {
    return errorResponse(
      "doorbell_not_configured",
      "AGENTLINK_WEBHOOK_SECRET is not set in this function's env",
      500,
    );
  }
  if (!webhookAuthorized(req)) {
    return errorResponse(
      "unauthorized",
      "the webhook secret header did not verify",
      401,
    );
  }

  const body = await req.json().catch(() => ({})) as Record<string, unknown>;
  const record = (body.record ?? {}) as Record<string, unknown>;
  // A direct POST of a bare outbox row (no table/record wrapper)
  // is normalized to the outbox shape; webhook POSTs always carry
  // table + record.
  const table = String(body.table ?? "al_doorbell_outbox");
  if (!ALLOWED_TABLES.has(table)) {
    return errorResponse(
      "unsupported_table",
      "doorbell taps exist only for al_doorbell_outbox, al_work " +
        "and al_alerts — never the message tables",
      400,
    );
  }

  const badField = containsContentField(record, 0);
  if (badField) {
    return errorResponse(
      "content_forbidden",
      "record carries content field '" + badField + "'; the doorbell " +
        "wire carries ids, refs, kinds and counters only",
      400,
    );
  }

  // ------------------------------------------------ extraction
  const taps: Tap[] = [];
  let outboxId = "";
  if (table === "al_doorbell_outbox") {
    const username = String(record.username ?? "");
    if (username) {
      taps.push({
        username,
        kind: String(record.kind ?? ""),
        ref: String(record.ref ?? ""),
      });
    }
    outboxId = String(record.id ?? body.outbox_id ?? "");
  } else if (table === "al_work") {
    const isUpdate = String(body.type ?? "").toUpperCase() === "UPDATE";
    const ref = String(record.group_id || record.id || "");
    const kind = isUpdate ? "work_status" : "work_assigned";
    const assignee = String(record.assignee ?? "");
    const assigner = String(record.assigner ?? "");
    if (assignee) taps.push({ username: assignee, kind, ref });
    if (isUpdate && assigner && assigner !== assignee) {
      taps.push({ username: assigner, kind, ref });
    }
  } else if (table === "al_alerts") {
    const subject = String(record.subject ?? "");
    if (subject) {
      taps.push({ username: subject, kind: "alert", ref: String(record.id ?? "") });
    }
  }

  const conversationId = String(body.conversation_id ?? body.conversation_key ?? "");
  const latestItemId = String(body.latest_item_id ?? "");

  if (!taps.length && !(conversationId && latestItemId)) {
    return jsonResponse({
      ok: true,
      tapped: [],
      signal: false,
      outbox_marked: false,
      note: "no target could be extracted; nothing tapped",
    });
  }

  // ---------------------------------------------------- RTDB leg
  try {
    const token = await mintGoogleAccessToken();
    for (const tap of taps) {
      // PUT, field-built from the DOORBELL_FIELDS allowlist only.
      await rtdb(token, "PUT", "doorbell/" + sanitizeKey(tap.username), {
        kind: tap.kind,
        ref: tap.ref,
        ts: { ".sv": "timestamp" },
      });
      // Life Signs (2.5.0): a liveness tap ALSO refreshes the
      // agent's /liveness/<user> node from the record layer —
      // the sweep enqueues these taps at challenge issue and at
      // every grade/judging transition, so the live node tracks
      // the sweep's truth in real time. The node is composed
      // from al_liveness + the registry (the same composition
      // the liveness Edge pushes at proof time; mirror of
      // liveness.py compose_liveness_node). Grades, tiers and
      // counters only — the doorbell content law holds.
      if (tap.kind === "liveness" || tap.kind === "liveness_grade") {
        const lv = await selectOne(supabase, "al_liveness", "*",
          { username: tap.username });
        const usr = await selectOne(supabase, "al_users",
          "last_seen", { username: tap.username });
        const daemonAt = Number(lv?.last_daemon_receipt_at ?? 0);
        const runtimeAt = Number(lv?.last_runtime_proof_at ?? 0);
        const loginAt = Number(usr?.last_seen ?? 0);
        let tier = "";
        let at = 0;
        for (
          const [t, v] of [["runtime", runtimeAt],
            ["daemon", daemonAt], ["login", loginAt]] as
            [string, number][]
        ) {
          if (v > at) { tier = t; at = v; }
        }
        await rtdb(token, "PATCH",
          "liveness/" + sanitizeKey(tap.username), {
            grade: String(lv?.grade ?? "") || "unproven",
            nature_version: Number(
              lv?.judged_nature_version ?? 0),
            persistence_class: String(lv?.judged_class ?? ""),
            last_proof_tier: tier,
            last_proof_at: at,
            daemon_only: Boolean(lv?.daemon_only),
            spec_drift: Boolean(String(lv?.spec_drift ?? "")),
            nature_compliant: Boolean(lv?.nature_compliant),
            dossier_status: String(lv?.dossier_status ?? "")
              || "missing",
            as_of: { ".sv": "timestamp" },
          });
      }
    }
    let signal = false;
    if (conversationId && latestItemId) {
      const key = sanitizeKey(conversationId);
      const current = await rtdb(token, "GET", "signals/" + key) as
        | Record<string, unknown>
        | null;
      const prev = Number(current?.counter ?? 0);
      await rtdb(token, "PATCH", "signals/" + key, {
        latest_item_id: latestItemId,
        counter: (Number.isFinite(prev) ? prev : 0) + 1,
        ts: { ".sv": "timestamp" },
      });
      signal = true;
    }

    // Mark the outbox row tapped ONLY after the RTDB writes land.
    let outboxMarked = false;
    if (outboxId) {
      const n = await patchRows(supabase, "al_doorbell_outbox", {
        id: outboxId,
      }, { tapped: true });
      outboxMarked = n > 0;
    }
    return jsonResponse({
      ok: true,
      tapped: taps.map((t) => t.username),
      signal,
      outbox_marked: outboxMarked,
    });
  } catch (e) {
    // Not marked, stays pending: the stale-tap sweep sees it, a
    // retry can land it, and meanwhile the journal + 60s slow-sync
    // cover the target agent. Latency, never loss.
    return errorResponse(
      "doorbell_failed",
      String(e instanceof Error ? e.message : e),
      502,
    );
  }
});
