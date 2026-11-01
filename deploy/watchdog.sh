#!/bin/sh
# AgentLink watchdog — second safety net next to the in-daemon heartbeat.
# Run every minute from cron (see agentlink.cron). If the agent service
# is not active, resurrect it. Silent when healthy.
set -e
if command -v systemctl >/dev/null 2>&1; then
  if ! systemctl --user is-active --quiet agentlink-agent 2>/dev/null; then
    systemctl --user restart agentlink-agent 2>/dev/null \
      || systemctl restart agentlink-agent 2>/dev/null || true
  fi
fi
