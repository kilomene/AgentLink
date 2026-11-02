"""THE TIMING MAP — the single source of truth for every timed
behaviour in AgentLink (point 42B). "Every second and every minute
has its own timing": runtime code reads THESE constants; the README
Timing section mirrors this table; a consistency test fails if code
drifts from it.

All timestamps are stored as epoch SECONDS (the authoritative
instant) with Pacific display strings where humans/agents read them
(point 36); sub-second ordering uses monotonic sequence ids.
"""

# Presence / heartbeat (points 15, 39)
HEARTBEAT_SECONDS = 5            # agent heartbeat cadence, never stops
OFFLINE_GRACE_SECONDS = 15       # 3 missed beats -> shown offline
REASSIGN_GRACE_SECONDS = 30      # no heartbeat anywhere for 30s -> dead
RECONNECT_FIRST_RETRY = 0        # first retry is instant
RECONNECT_BACKOFF_CAP_SECONDS = 5
HELLO_TIMEOUT_SECONDS = 30       # bounded welcome wait per hello attempt;
                                 # a hello landing in a bad egress window
                                 # (or on a busy relay) times out, closes,
                                 # and the unlimited retry loop tries again
                                 # — never a wedged client, never a
                                 # service restart to recover
HOME_PROBE_SECONDS = 5           # failover home-probe cadence

# Supervision (points 11, 17, 39)
WATCHDOG_CRON_SECONDS = 60       # per-minute watchdog cron
WATCHDOG_STALE_SECONDS = 20      # heartbeat stamp older than this = hung
RESTART_SEC = 1                  # systemd RestartSec

# Dashboard (point 10)
DEVICE_TRUST_SECONDS = 7 * 24 * 3600   # trusted device life: 7 days
LOGIN_RATE_LIMIT_ATTEMPTS = 5
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 300

# Auto-update (point 12)
UPDATE_CHECK_SECONDS = 15 * 60   # 15 minutes
UPDATE_DRAIN_WAIT_SECONDS = 120  # bounded wait for in-flight operations
                                 # (brain call, delivery, upload chunk)
                                 # to finish or reach a checkpoint before
                                 # a self-update swap; on expiry the update
                                 # DEFERS to the next check — an update
                                 # never interrupts an operation

# Fleet alerts (point 37)
ALERT_OFFLINE_SECONDS = 300      # agent offline beyond 5 min -> alert
ALERT_URGENT_SECONDS = 120       # urgent undelivered beyond 2 min
ALERT_REMINDER_SECONDS = 3600    # throttled reminder cadence
ALERT_CHAIN_PAUSE_SECONDS = 300  # chain paused beyond 5 min -> alert

# Deadline pressure (point 36)
DEADLINE_WARN_HALF = "50% of window elapsed"
DEADLINE_WARN_LATE_SECONDS = 3600  # 1 hour remaining (scaled on short windows)

# Autonomous mode (v1.1.7, platform autonomy law): the runtime's
# loop-safety pacing. An autonomous agent's replies are its own
# brain's words; these constants only bound HOW OFTEN the loop may
# fire unattended, so two autonomous agents can never ping-pong
# forever. The "auto" variants tighten the bound when the
# counterparty's message is itself marked autonomous.
AUTO_REPLY_DELAY_SECONDS = 1.0        # pause before an autonomous reply
AUTO_REPLY_DELAY_AUTO_SECONDS = 2.0   # longer pause vs an autonomous peer
AUTO_MAX_CONSECUTIVE_REPLIES = 3      # per conversation, vs non-autonomous
AUTO_MAX_CONSECUTIVE_AUTO = 2         # per conversation, vs autonomous peer
AUTO_HOURLY_BUDGET = 20               # autonomous replies / conversation / h
AUTO_HOURLY_BUDGET_AUTO = 10          # tightened vs an autonomous peer

# Backups (points 17, 19c)
BACKUP_CRON = "daily"            # plus on-demand via operator CLI

# Relay fleet scan (reassignment + pressure + alerts evaluation)
FLEET_SCAN_SECONDS = 1
SELF_CHECK_SECONDS = 60          # daemon self-heal cadence (point 43d)
CONNECT_RACE_GRACE_SECONDS = 0.3  # prefer-home grace inside a race (44a)
RACE_PROBE_DWELL_SECONDS = 2.0   # cap on a race/home probe's liveness
                                 # wait: the probe must complete an
                                 # application ping round-trip (protocol
                                 # ping -> pong) within this window. An
                                 # endpoint fronted by a tunnel completes
                                 # the handshake — and its edge answers
                                 # control pings — even when the relay
                                 # behind it is dead; only a live relay
                                 # answers the application ping
                                 # (v1.2.2, production drill find)
NETWORK_WATCH_SECONDS = 2         # network-change fingerprint watch (44b)

# Peer mesh (v1.2.0, NO GOING DARK peer-server law): every relay
# registers itself in the shared backend's server registry on boot
# and heartbeats the row on this cadence; a client races home + every
# LIVE registry entry. A peer is a waiting room, never a new home:
# while riding, the client keeps probing home (HOME_PROBE_SECONDS)
# and migrates back the moment home is healthy again.
SERVER_HEARTBEAT_SECONDS = 5     # relay registry heartbeat cadence
SERVER_STALE_SECONDS = 20        # registry entry older than this is
                                 # not a live peer: never offered in
                                 # welcome/discovery, never raced
# Mesh rules (owner, 2026-11-02 ~05:52 PST, strict): hosting is
# peer-to-peer ANYWHERE — no admin funnel, no server gets preference
# except an agent's OWN home. Each server hosts a MAXIMUM of 10
# riding agents; effective capacity scales with health:
# capacity = floor(SERVER_MAX_RIDERS x health / 100). Every server
# carries a HEALTH PERCENTAGE from real signals (see relay.py
# compute_server_health); a client may ride ONLY a server above
# SERVER_HEALTHY_MIN — at or below it the server is "not good",
# never selected, and a rider migrates off it.
SERVER_MAX_RIDERS = 10           # hard cap of riders per server
SERVER_HEALTHY_MIN = 50          # ride only ABOVE this health (%)
SERVER_HEALTH_WINDOW_SECONDS = 300  # trailing signal window (5 min)
MESH_REFRESH_SECONDS = 30        # rider's discovery refresh cadence
                                 # while riding (health-drop watch)
DISCOVERED_SERVER_TTL_SECONDS = 180  # a discovered peer that no relay
                                 # has re-advertised for this long is
                                 # forgotten client-side (6x the relay
                                 # staleness threshold): dead entries
                                 # must not linger in the race set

# Hardened core — compliance visibility (v1.2.0): the relay watches
# HOW each agent connects. A "check-in pattern" — repeated SHORT
# sessions separated by LONG dark gaps — is an agent that configured
# itself out of continuous connection; it is flagged on its presence
# ("check-in pattern — not continuously connected"), never silently
# shown as compliant. A live daemon's session runs for hours, so it
# can never trip this by accident.
CHECKIN_WINDOW_SECONDS = 3600    # sessions considered over 1 hour
CHECKIN_MIN_SESSIONS = 3         # need this many to call it a pattern
CHECKIN_SESSION_MAX_SECONDS = 60  # each session shorter than this…
CHECKIN_GAP_MIN_SECONDS = 120    # …with dark gaps longer than this
