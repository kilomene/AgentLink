// AgentLink shared rules (point 42A) — PURE logic, no I/O.
// These evaluation rules mirror the Python relay's fleet scan and the
// one timing map (agentlink/timing.py). Keep the constants in sync:
// the repo test-suite asserts the Python and TypeScript values match.

export const TIMING = {
  HEARTBEAT_SECONDS: 5,
  OFFLINE_GRACE_SECONDS: 15, // 3 missed beats
  RECONNECT_BACKOFF_CAP_SECONDS: 5,
  REASSIGN_GRACE_SECONDS: 30,
  ALERT_OFFLINE_SECONDS: 300,
  ALERT_URGENT_SECONDS: 120,
  ALERT_REMINDER_SECONDS: 3600,
  DEVICE_TRUST_SECONDS: 7 * 24 * 3600,
} as const;

export interface AlertLike {
  id: string;
  kind: string;
  subject: string;
  detail?: string;
  status?: string;
  created_at: number;
}

/** Build the outbound alert payload (webhook/email body). Metadata only. */
export function buildAlertPayload(
  alert: AlertLike,
  opts: { reminder?: boolean; server?: string; now: number },
): Record<string, unknown> {
  return {
    alert: {
      id: alert.id,
      kind: alert.kind,
      subject: alert.subject,
      detail: alert.detail ?? "",
      status: alert.status ?? "open",
      created_at: alert.created_at,
    },
    reminder: Boolean(opts.reminder),
    server: opts.server ?? "supabase-edge",
    ts: opts.now,
  };
}

/** Staleness rule: an agent is offline for alerting when its last
 * heartbeat is older than ALERT_OFFLINE_SECONDS. Presence display
 * uses the shorter OFFLINE_GRACE_SECONDS. */
export function isAlertStale(lastSeen: number, now: number): boolean {
  return lastSeen > 0 && now - lastSeen > TIMING.ALERT_OFFLINE_SECONDS;
}

export function isOffline(lastSeen: number, now: number): boolean {
  return lastSeen === 0 || now - lastSeen > TIMING.OFFLINE_GRACE_SECONDS;
}

/** Deadline pressure evaluation (point 36): warning points at 50% of
 * the window elapsed and at 1 hour remaining (scaled to 75% elapsed
 * on windows under 2 hours); overdue escalates to urgent. Instants
 * are epoch seconds derived from Pacific wall-clock — timezones can
 * never shift them. */
export function deadlinePressure(
  createdAt: number,
  deadline: number,
  now: number,
): { warnHalf: boolean; warnLate: boolean; overdue: boolean } {
  const window = Math.max(1, deadline - createdAt);
  const warnHalfAt = createdAt + Math.floor(window / 2);
  const warnLateAt = window <= 2 * 3600
    ? createdAt + Math.floor((3 * window) / 4)
    : deadline - 3600;
  return {
    warnHalf: now >= warnHalfAt && now <= deadline,
    warnLate: now >= warnLateAt && now <= deadline,
    overdue: now > deadline,
  };
}

/** Reassignment evaluation (point 29): an assignee is dead when no
 * heartbeat has landed anywhere for REASSIGN_GRACE_SECONDS. */
export function isDead(lastSeen: number, now: number): boolean {
  return lastSeen > 0 && now - lastSeen > TIMING.REASSIGN_GRACE_SECONDS;
}
