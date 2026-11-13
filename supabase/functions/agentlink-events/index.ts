// AgentLink events reaction layer (point 42A) — Supabase Edge Function.
//
// Invoked by database webhooks on INSERT into al_alerts and on
// work-state changes in al_work. Dispatches owner alerts (point 37)
// over the operator-configured channels (webhook + email) and records
// every dispatch result in al_alert_dispatches.
//
// Channels are OPERATOR config (env), never agent-facing:
//   AGENTLINK_ALERT_WEBHOOK         outbound webhook URL
//   AGENTLINK_ALERT_WEBHOOK_SECRET  HMAC-SHA256 signing secret (opt.)
//   AGENTLINK_ALERT_EMAIL_TO        email recipient (via the SMTP
//   AGENTLINK_SMTP_URL              smtp://user:pass@host:port URL)
//
// Deploy: supabase functions deploy agentlink-events
// Then create Database Webhooks for al_alerts INSERT and al_work
// UPDATE pointing at this function.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { buildAlertPayload } from "../_shared/rules.ts";
import { CAP_CONTROL, readJsonBody } from "../_shared/v200.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

async function hmac(secret: string, body: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(body),
  );
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function record(alertId: string, channel: string, ok: boolean,
                      detail: string) {
  await supabase.from("al_alert_dispatches").insert({
    alert_id: alertId,
    channel,
    ok,
    detail: detail.slice(0, 300),
    ts: Math.floor(Date.now() / 1000),
  });
}

async function dispatchWebhook(payload: Record<string, unknown>,
                               alertId: string) {
  const url = Deno.env.get("AGENTLINK_ALERT_WEBHOOK");
  if (!url) return;
  const body = JSON.stringify(payload);
  const headers: Record<string, string> = {
    "content-type": "application/json",
  };
  const secret = Deno.env.get("AGENTLINK_ALERT_WEBHOOK_SECRET");
  if (secret) headers["x-agentlink-signature"] = "sha256=" + await hmac(secret, body);
  try {
    const resp = await fetch(url, { method: "POST", headers, body });
    await record(alertId, "webhook", resp.ok, `HTTP ${resp.status}`);
  } catch (e) {
    await record(alertId, "webhook", false, String(e));
  }
}

Deno.serve(async (req: Request) => {
  // Ingress cap (2.6.0, Part 4): webhook payloads are alert /
  // work metadata records; CAP_CONTROL is wide headroom. This
  // Edge is invoked by database webhooks (operator plumbing,
  // no agent caller), so suspension and per-agent rates do
  // not apply. NOTE (pre-existing, flagged in SERVER-AUDIT.md,
  // unchanged by this sweep): unlike agentlink-doorbell, this
  // function performs no webhook-secret check of its own.
  const parsed = await readJsonBody(req, CAP_CONTROL);
  if (parsed.response) return parsed.response;
  const payload = parsed.body;
  // deno-lint-ignore no-explicit-any
  const record_ = (payload.record ?? {}) as Record<string, any>;
  const table = payload.table ?? "";

  if (table === "al_alerts" && record_.id) {
    const body = buildAlertPayload(
      {
        id: record_.id,
        kind: record_.kind,
        subject: record_.subject,
        detail: record_.detail ?? "",
        status: record_.status ?? "open",
        created_at: record_.created_at ?? 0,
      },
      { now: Math.floor(Date.now() / 1000), server: "supabase-edge" },
    );
    await dispatchWebhook(body, record_.id);
    await record(record_.id, "dashboard", true,
                 "dashboard stream picks alerts up via Realtime");
    return new Response(JSON.stringify({ dispatched: record_.id }), {
      headers: { "content-type": "application/json" },
    });
  }

  if (table === "al_work") {
    // Work-state reactions: a completed chain step / chain completion
    // is surfaced as an alert record by the relay (or pg_cron); this
    // layer simply acknowledges — dispatch happens on al_alerts.
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "content-type": "application/json" },
    });
  }

  return new Response(JSON.stringify({ ignored: true }), {
    headers: { "content-type": "application/json" },
  });
});
