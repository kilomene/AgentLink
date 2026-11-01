// AgentLink control-plane API (point 42A) — Supabase Edge Function.
//
// HTTP control plane for the OPERATOR's surfaces: dashboard data,
// directory/capability search, alert listing, and metadata-only
// operator actions (revoke a trusted dashboard device).
//
// HARD RULE: this function receives and returns METADATA ONLY. It
// never sees message/file contents — E2E ciphertext moves exclusively
// through the relay WebSocket data plane. Requests require the
// operator's dashboard bearer (checked against al_dashboard_sessions
// token hashes) except /health.
//
// Deploy: supabase functions deploy agentlink-api
// Secrets: SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY are injected by
// the platform; the service key never leaves Supabase.

import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import { isOffline, TIMING } from "../_shared/rules.ts";

const supabase = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
);

async function sha256(text: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(text),
  );
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function authed(req: Request): Promise<boolean> {
  const token = (req.headers.get("authorization") ?? "").replace(
    /^Bearer\s+/i,
    "",
  );
  if (!token) return false;
  const { data } = await supabase
    .from("al_dashboard_sessions")
    .select("expires_at")
    .eq("token_hash", await sha256(token))
    .limit(1);
  return Boolean(data?.length) &&
    (data![0].expires_at as number) > Math.floor(Date.now() / 1000);
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

Deno.serve(async (req: Request) => {
  const url = new URL(req.url);
  const path = url.pathname.replace(/^.*agentlink-api/, "") || "/";
  const now = Math.floor(Date.now() / 1000);

  if (path === "/health") {
    return json({ ok: true, service: "agentlink-api", ts: now });
  }
  if (!(await authed(req))) {
    return json({ error: "unauthorized" }, 401);
  }

  // Agent wall: presence (heartbeat-derived), activity + metadata.
  if (path === "/agents") {
    const { data } = await supabase.from("al_users")
      .select(
        "username, display_name, capabilities, cap_desc, last_seen, created_at",
      )
      .order("username");
    const users = (data ?? []).map((u) => ({
      ...u,
      online: !isOffline(u.last_seen as number, now),
    }));
    return json({ users });
  }

  // Directory / capability search (point 33): online agents first.
  if (path === "/directory") {
    const capability = url.searchParams.get("capability") ?? "";
    const { data } = await supabase.from("al_users")
      .select("username, display_name, capabilities, cap_desc, last_seen")
      .order("username");
    let users = (data ?? []).map((u) => ({
      ...u,
      online: !isOffline(u.last_seen as number, now),
    }));
    if (capability) {
      users = users.filter((u) =>
        (u.capabilities as string[]).some(
          (c) => c.toLowerCase() === capability.toLowerCase(),
        )
      );
    }
    users.sort((a, b) =>
      Number(b.online) - Number(a.online) ||
      a.username.localeCompare(b.username)
    );
    return json({ users });
  }

  // Work board + chains (metadata only).
  if (path === "/work") {
    const { data: work } = await supabase.from("al_work")
      .select(
        "id, assigner, assignee, group_id, status, priority, batch_id, chain_id, chain_step, attempt, progress_percent, progress_at, proof_verified, deadline, created_at, updated_at",
      )
      .order("updated_at", { ascending: false }).limit(200);
    const { data: chains } = await supabase.from("al_chains")
      .select("*").order("updated_at", { ascending: false }).limit(100);
    return json({ work: work ?? [], chains: chains ?? [] });
  }

  // Conversations metadata: the audit trail's envelope details.
  if (path === "/conversations") {
    const { data } = await supabase.from("al_audit_log")
      .select(
        "ts, kind, actor, target, group_id, work_id, status, priority, size, mentions, ref_id",
      )
      .order("seq", { ascending: false }).limit(500);
    return json({ activity: data ?? [] });
  }

  // Delivery library search (metadata only; entitlement lives in the
  // relay — this operator view lists the index).
  if (path === "/library") {
    const q = url.searchParams.get("q") ?? "";
    let query = supabase.from("al_library").select("*")
      .order("ts", { ascending: false }).limit(100);
    if (q) query = query.ilike("filename", `%${q}%`);
    const { data } = await query;
    return json({ entries: data ?? [] });
  }

  // Fleet alerts (point 37).
  if (path === "/alerts") {
    const { data } = await supabase.from("al_alerts")
      .select("*").order("created_at", { ascending: false }).limit(100);
    return json({ alerts: data ?? [] });
  }

  // Operator action (metadata-only): revoke a trusted dashboard device.
  if (path === "/devices/revoke" && req.method === "POST") {
    const body = await req.json().catch(() => ({}));
    const token = String(body.token ?? "");
    if (!token) return json({ error: "token required" }, 400);
    const { error } = await supabase.from("al_dashboard_sessions")
      .delete().eq("token_hash", await sha256(token));
    if (error) return json({ error: error.message }, 500);
    return json({ revoked: true, trust_seconds: TIMING.DEVICE_TRUST_SECONDS });
  }

  return json({ error: "not found" }, 404);
});
