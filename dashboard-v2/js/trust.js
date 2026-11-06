// Trust formula ported from agentlink/store.py Store.compute_trust:
// start 50; +4 per completed/covered assignment (as assignee); +1 per
// delivered/awaiting_approval; -6 per changes-requested round; -6 per
// missed deadline (passed while not completed, or completed late);
// -10 per invalid signed-delivery proof; clamped to [0,100].
// Messages never count.
export function computeTrust(username, work, audit, nowSec){
  const now = nowSec || Math.floor(Date.now()/1000);
  let score = 50;
  for(const r of (work||[])){
    if(r.assignee !== username) continue;
    if(r.status === "completed" || r.status === "covered") score += 4;
    else if(r.status === "delivered" || r.status === "awaiting_approval") score += 1;
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
