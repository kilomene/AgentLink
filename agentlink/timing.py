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
HELLO_TIMEOUT_SECONDS = 8        # bounded welcome wait per hello attempt;
                                 # a healthy relay answers in well under a
                                 # second even through a tunnel, so a hello
                                 # stuck in a bad egress window is cut at
                                 # 8s and the unlimited retry loop tries
                                 # again — at 30s (pre-1.2.3) two stalled
                                 # hellos serially cost a riding agent
                                 # ~60s of flip time in the production
                                 # kill-drill; never a wedged client,
                                 # never a service restart to recover
HOME_PROBE_SECONDS = 5           # failover home-probe cadence
FIRST_HELLO_TIMEOUT_SECONDS = 30  # the FIRST-contact hello window:
                                 # a brand-new identity's first hello
                                 # (its registration) gets a longer
                                 # bounded wait than a reconnect hello
                                 # (HELLO_TIMEOUT_SECONDS) — a first
                                 # registration crosses the sick
                                 # network exactly once, and the relay
                                 # spends real work on it (the claim).
                                 # The relay ALSO uses this as its
                                 # server-side bound: a connection
                                 # that has not completed a hello
                                 # within this window of connecting is
                                 # closed and counted as an incomplete
                                 # hello (v1.3.7, registration
                                 # visibility)
REGISTRATION_RESUME_WINDOW_SECONDS = 3600  # a cut-off FIRST
                                 # registration may be resumed by the
                                 # same identity (see relay.py
                                 # _try_resume_registration) only
                                 # while its half-created row is
                                 # younger than this — the window IS
                                 # the safety bound on that path

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
                                 # (decision call, delivery, upload chunk)
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
# words, decided by its own intelligence through its decision
# link; these constants only bound HOW OFTEN the loop may
# fire unattended, so two autonomous agents can never ping-pong
# forever. The "auto" variants tighten the bound when the
# counterparty's message is itself marked autonomous.
AUTO_REPLY_DELAY_SECONDS = 1.0        # pause before an autonomous reply
AUTO_REPLY_DELAY_AUTO_SECONDS = 2.0   # longer pause vs an autonomous peer
AUTO_MAX_CONSECUTIVE_REPLIES = 3      # per conversation, vs non-autonomous
AUTO_MAX_CONSECUTIVE_AUTO = 2         # per conversation, vs autonomous peer
AUTO_HOURLY_BUDGET = 20               # autonomous replies / conversation / h
AUTO_HOURLY_BUDGET_AUTO = 10          # tightened vs an autonomous peer

# Decision link (v1.3.5, "the agent is the brain"): the agent IS
# its own intelligence — capability and memory are the agent's
# own, always. The only thing this platform can ever describe as
# missing is a CONNECTION-side fact, and the one that matters here
# is the DECISION LINK: the link between the agent's line
# connection (this client) and the agent's own decision-making.
# An out-call decision endpoint that does not answer inside this
# bound has not decided anything: the event stays unanswered and
# unaccepted — held, never fabricated, never lost.
DECISION_LINK_TIMEOUT_SECONDS = 30    # one decision-endpoint call

# Auto decision link (v1.8.0, owner's law — "not manually. not
# manually."): immediately after registration the decision link
# verifies and wires ITSELF. The client resolves its wiring at
# start (explicit config -> in-process handler -> the well-known
# local convention endpoint), then proves the path with a live
# self-check: a synthetic probe event must travel the wired path
# and come back decided inside this deadline — an answered probe,
# including the agent's chosen silence, is a verified link; a
# timeout or a link error is the truthful 'pending'.
DECISION_LINK_CHECK_TIMEOUT_SECONDS = 5   # one self-check probe
DECISION_LINK_RECHECK_SECONDS = 60        # serve-loop re-verification
DECISION_CONVENTION_URL = "http://127.0.0.1:18799/decide"
# ^ THE platform convention (v1.8.0): an agent product serving its
# decision endpoint at this well-known local address is found and
# wired with zero configuration. Adoption is deliberately strict:
# the endpoint must echo the probe's nonce in its decision, so a
# client on a shared host can never adopt ANOTHER agent's endpoint
# by accident — an explicitly configured endpoint is trusted by the
# operator's own act and does not need the echo.

# One-time admin grant (v1.8.0, owner's proposal + adopted
# additions): an agent acting under the owner's grant is bounded
# per scope by generous platform rate limits, counted from the
# receipt record itself over the trailing window. Tripping one
# fails CLOSED and raises a fleet alert — work is never silently
# stopped, and a malfunctioning agent cannot burn the owner's
# accounts. Defaults live in grants.GRANT_RATE_LIMITS; the window
# is global to the grant system.
GRANT_RATE_WINDOW_SECONDS = 3600     # trailing rate window

# Delivery custody (v1.3.7): for a client that declares
# delivery_ack in its hello, the offline queue is a CUSTODY
# OUTBOX, not a flush-and-forget pile — the relay OFFERs queued
# frames and only the recipient's ack (ids durably journaled on
# ITS side) retires them. An unacked frame still in custody is
# re-offered to a connected peer on the resend cadence; a frame
# that stays unacked while its recipient has connected since it
# queued is STUCK — the exact failure of 2026-11-02, where a DM
# flushed into a check-in agent's 23-second connection was marked
# delivered and never reached the agent. Legacy clients (no
# delivery_ack declaration) keep the pre-1.3.7 flush semantics.
DELIVERY_RESEND_SECONDS = 30     # re-offer cadence to a connected,
                                 # unacked peer
DELIVERY_STUCK_SECONDS = 300     # unacked + recipient connected
                                 # since + older than this = stuck
DELIVERY_HISTORY_PAGE = 200      # default history frame page size

# Cross-relay frame drain (v1.6.0): queued frames (messages, work
# assignments — anything one relay queued for an agent connected
# to ANOTHER relay sharing the store) are pushed by a dedicated
# drain loop, not by the 1s fleet scan. Riding the scan quantized
# push dispatch to the scan tick plus the scan's own unbounded
# pass latency: back-to-back assignments through a peer relay
# arrived in second-wide batches, and a concurrent worker pool
# started them seconds apart instead of together (the point-31
# failure mode). The cadence matches the store's cost: a local
# store drain is an in-process indexed query, so it runs hot; a
# network-backed store pays a round trip per peer per tick, so it
# runs at the room drain's proven cadence (v1.4.4) — still at
# least twice as fast as the scan it replaces, and decoupled from
# the scan's pass latency entirely. The fleet scan keeps its own
# drain as backstop.
FRAME_DRAIN_SECONDS_LOCAL = 0.15   # dedicated frame drain tick,
                                   # local (SQLite) store
FRAME_DRAIN_SECONDS_REMOTE = 0.5   # dedicated frame drain tick,
                                   # network-backed store

# Blob-layer truth (v1.3.8): the object/meta reconciliation sweep
# cadence. Divergence is a slow leak and the delete path itself
# verifies synchronously, so the sweep is a backstop, not a
# hot loop — boot + this interval is proportionate.
BLOB_RECONCILE_SECONDS = 1800
# A battery cycle lives for seconds; a dial-* (ephemeral battery)
# blob pair older than this is abandoned test litter, and the
# sweep reaps the pair (production census 2026-11-03: 113/113
# blob metas were battery-owned, 44 of them intact pairs whose
# cleanup delete never executed at all).
BATTERY_LITTER_AGE_SECONDS = 3600

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

# Earned health (v1.3.0, owner's law): a server's health percentage
# is EARNED THROUGH TESTING, every time — never assigned, never a
# static default, never settable by config/env/operator. On first
# registration a server is UNRATED (health -1, "testing"): it carries
# NO percentage and is eligible neither to be ridden nor to carry
# another agent's server until its first test battery completes.
# The battery is ACTIVE and CONTINUOUS: every cycle exercises the
# real server end-to-end (probe round-trips, hello handshakes,
# registry write/read-back integrity, a real message round-trip, a
# chunked file round-trip verified by hash, heartbeat stability),
# and the rolling trailing-window signals keep re-testing it for
# the rest of its life. Stop testing and the evidence ages out of
# the window — the percentage falls with it.
HEALTH_TEST_CYCLE_SECONDS = 2    # battery cycle cadence
HEALTH_FRAME_TIMEOUT_SECONDS = 30  # per-frame wait inside a battery
                                 # cycle: the battery measures the
                                 # REAL backend (a production file
                                 # round-trip through R2 + the shared
                                 # store legitimately takes ~20s), so
                                 # a slow success must count as the
                                 # evidence it is — only a genuine
                                 # failure or a 30s silence fails
HEALTH_INITIAL_CYCLES = 3        # completed cycles before a server
                                 # earns its first rating
HEALTH_PROBE_ROUNDS = 3          # ping round-trips per battery cycle
HEALTH_UNRATED = -1              # registry health value for UNRATED

# Server carrying (v1.3.0, owner's passage model): what is carried
# is an agent's SERVER — never the agent itself. A running relay watches
# the registry; when a per-agent server's home stops answering, the
# best eligible brother (health above the floor, carrying capacity
# free — capacity is the same health-scaled law as riders) claims
# the carry under a single-winner lease and serves the server's
# identity (same label, same owner) from its own machine. The owner
# never changes; the carrier is a temporary helper. When home has
# answered strongly for the handback window, the carrier releases
# and the server goes home; if the carrier falls first, the lease
# expires and the next brother claims — the server hops again.
CARRY_WATCH_SECONDS = 5          # carrier registry watch cadence
CARRY_LEASE_SECONDS = 45         # claim lease; renewed every watch
                                 # cycle by the holding carrier
CARRY_HANDBACK_SECONDS = 60      # home must answer continuously
                                 # this long before handback

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
