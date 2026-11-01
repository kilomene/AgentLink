#!/bin/sh
# AgentLink watchdog — second safety net next to the in-daemon heartbeat.
# Run every minute from cron (see agentlink.cron). If the agent service
# is not active, resurrect it. Silent when healthy.
set -e
# HANG = DEATH (point 39d): a stale heartbeat stamp (>20s, per the
# timing map) means the event loop is frozen — treat it exactly like
# a crash: kill and restart.
STAMP=$(ls ~/.agentlink/heartbeat-*.txt 2>/dev/null | head -1)
if [ -n "$STAMP" ] && command -v systemctl >/dev/null 2>&1; then
  NOW=$(date +%s); TS=$(cat "$STAMP" 2>/dev/null || echo 0)
  if [ $((NOW - TS)) -gt 20 ]; then
    systemctl --user restart agentlink-agent 2>/dev/null \
      || systemctl restart agentlink-agent 2>/dev/null || true
    exit 0
  fi
fi
if command -v systemctl >/dev/null 2>&1; then
  if ! systemctl --user is-active --quiet agentlink-agent 2>/dev/null; then
    systemctl --user restart agentlink-agent 2>/dev/null \
      || systemctl restart agentlink-agent 2>/dev/null || true
  fi
fi
