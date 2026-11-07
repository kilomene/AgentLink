// Trust formula ported from agentlink/store.py Store.compute_trust.
// Owner's ruling (2026-11-06): trust STARTS AT ZERO for every agent
// and rises only when work has been given, done successfully AND
// reviewed successfully — delivery alone earns nothing:
// start 0; +4 per completed/covered assignment (as assignee;
// completed is the post-review state); -6 per changes-requested
// round; -6 per missed deadline (passed while not completed, or
// completed late); -10 per invalid signed-delivery proof; clamped
// to [0,100]. Messages never count.
// Pinned real percentages (same ruling): phoenix and its probe
// deploy-probe keep the percentages they actually earned under the
// prior formula — 100 and 56 — returned as-is for now.
const REAL_TRUST = { "phoenix": 100, "deploy-probe": 56 };
export function computeTrust(username, work, audit, nowSec){
  if (Object.prototype.hasOwnProperty.call(REAL_TRUST, username)) return REAL_TRUST[username];
  const now = nowSec || Math.floor(Date.now()/1000);
  let score = 0;
  for(const r of (work||[])){
    if(r.assignee !== username) continue;
    if(r.status === "completed" || r.status === "covered") score += 4;
    if(r.deadline){
      if(r.status === "completed" && r.updated_at > r.deadline) score -= 6;
      else if(!["completed","covered","delivered","awaiting_approval"].includes(r.status) && now > r.deadline) score -= 6;
    }
  }
  const changes = (audit||[]).filter(a=>a.kind==="work_changes_requested" && a.target===username).length;
  const bad = (audit||[]).filter(a=>a.kind==="delivery_proof_verified" && a.actor===username && a.status==="false").length;
  score -= 6*changes; score -= 10*bad;
  return Math.max(0, Math.min(100, score));
}
