"""SQLite state for the AgentLink relay.

Tables: users, offline queue, groups, group members, invite tokens,
work items and work deliveries. All access is serialised with a lock;
the relay is a single event loop, so this is cheap and race-free.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from pathlib import Path

from .protocol import new_id, new_secret, now_ts

DEFAULT_SETTINGS = {
    "send_messages": "everyone",      # everyone | admins_only
    "add_members": "everyone",        # everyone | admins_only
    "assign_work": "everyone",        # everyone | admins_only
    "vault_add": "everyone",          # everyone | admins_only
}

MAX_GROUP_MEMBERS = 50

# The audit kinds that ARE conversation content (v1.3.2): messages and
# the work-envelope lifecycle. Everything else in the audit log
# (online/offline, alerts, reads, registry churn) is a FEED — it may be
# windowed for display, but it must never decide which conversations
# exist. Conversation composition and the immortality census read
# ONLY these kinds, in full, with no row limit.
CONTENT_AUDIT_KINDS = (
    "message", "group_message", "channel_message",
    "work_assigned", "work_delivered", "work_completed",
    "work_changes_requested", "work_progress",
    "work_awaiting_approval", "work_approved",
    "work_approval_rejected")
# Voice-room lifecycle kinds (v1.3.4): room state is written to the
# audit log by whichever relay hosts the room's signalling, so the
# dashboard's Voice Rooms view can be composed from the SHARED store
# — the full lifecycle, oldest first, no window — instead of from one
# relay's local memory (which showed nothing for rooms hosted by a
# brother server).
ROOM_AUDIT_KINDS = (
    "room_opened", "room_joined", "room_left", "room_closed")
PRIORITY_WEIGHT = {"normal": 0, "high": 1, "urgent": 2}
MAX_CHANNEL_SUBSCRIBERS = 1000
CHUNK_SIZE = 1024 * 1024

# Canonical invite lifetime (v1.1.0): the Supabase al_invites shape
# stores token + created_at only, so validity is defined as
# created_at + INVITE_TTL_SECONDS >= now. create_invite shifts
# created_at so a custom ttl_seconds keeps its exact meaning.
INVITE_TTL_SECONDS = 7 * 24 * 3600  # 1 MiB resumable-upload chunk


class UsernameTaken(Exception):
    pass


class GroupFull(Exception):
    pass


class InvalidTransition(Exception):
    """Fail-closed state machine: illegal work-status jump (point 32)."""


class NotFound(Exception):
    pass


class RemovalBlocked(Exception):
    """Registration removal refused (fail-closed): the agent still
    has live entanglements — non-terminal work, undelivered queue
    frames, or live chain steps. Carries the human-readable blocker
    list; live work is never silently orphaned by a deregistration."""

    def __init__(self, username: str, blockers: list[str]):
        super().__init__(f"@{username}: " + "; ".join(blockers))
        self.username = username
        self.blockers = list(blockers)


#: Work statuses the state machine can still move FROM — a work item
#: in any of these is live, and blocks a self-deregistration.
NON_TERMINAL_WORK_STATUSES = ("assigned", "in_progress",
                              "changes_requested", "delivered",
                              "awaiting_approval", "awaiting_agent")


def _ack_id_matches(frame: dict, wanted: set) -> bool:
    """Does an ack carrying ``wanted`` ids retire this queued frame?
    Message frames match by top-level id; a work_assigned frame has
    no top-level id, so it matches by its nested work id (the client
    acks work by work id). One rule, both stores, exactly."""
    if str(frame.get("id") or "") in wanted:
        return True
    if frame.get("type") == "work_assigned":
        work = frame.get("work") or {}
        return str(work.get("id") or "") in wanted
    return False


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def carry_claim_blocked(rows: list[dict], *, claimant_id: str,
                        claimant_health: int, claimant_capacity: int,
                        claimant_riders: int = 0,
                        claimant_can_carry: bool = True,
                        claimant_carrying: int = 0,
                        now: int, stale_after: int) -> bool:
    """Single-winner carry arbitration, shared verbatim by both
    stores: True when this claimant must NOT claim — it is unrated
    or at/below the health floor, it cannot carry, its carrying
    capacity is full, or a strictly better eligible brother (higher
    health, then fewer carried servers, then fewer riders, then
    server_id for determinism) is live in the registry. Platform
    relays get NO preference: every live carrier-capable instance
    ranks by the same key, owner and stranger alike."""
    if not claimant_can_carry:
        return True
    if int(claimant_health) <= 50 or int(claimant_capacity) <= 0:
        return True
    if int(claimant_carrying) >= int(claimant_capacity):
        return True
    carrying: dict[str, int] = {}
    for r in rows:
        if r.get("owner_agent") and r.get("carry_state") == "carried" \
                and int(r.get("carry_lease_until") or 0) > now:
            cid = str(r.get("carried_by_id") or "")
            if cid:
                carrying[cid] = carrying.get(cid, 0) + 1
    my_key = (-int(claimant_health), int(claimant_carrying),
              int(claimant_riders), str(claimant_id))
    for r in rows:
        sid = str(r.get("server_id") or "")
        if not sid or sid == claimant_id:
            continue
        if not int(r.get("can_carry") if r.get("can_carry") is not None
                   else 1):
            continue
        # Is this row a LIVE carrier instance right now? A shared
        # relay lives by its registry heartbeat; a per-agent server's
        # home instance lives by its home heartbeat while at home.
        if r.get("owner_agent"):
            if r.get("carry_state") != "home":
                continue
            if now - int(r.get("home_last_seen") or 0) > stale_after:
                continue
            health = int(r.get("home_health")
                         if r.get("home_health") is not None
                         else r.get("health") or -1)
            capacity = int(r.get("home_capacity")
                           if r.get("home_capacity") is not None
                           else r.get("capacity") or 0)
            riders = int(r.get("home_riders") or 0)
        else:
            if now - int(r.get("last_seen") or 0) > stale_after:
                continue
            health = int(r.get("health")
                         if r.get("health") is not None else -1)
            capacity = int(r.get("capacity") or 0)
            riders = int(r.get("riders") or 0)
        if health <= 50 or capacity <= 0:
            continue
        load = carrying.get(sid, 0)
        if load >= capacity:
            continue
        if (-health, load, riders, sid) < my_key:
            return True
    return False


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # 'Highly classified' handling: 0700 dir, 0600 DB file, WAL,
        # integrity-checked on startup. The DB holds ciphertext and
        # metadata only — no private keys, and owner-secrets only as
        # SHA-256 hashes (see claim()).
        try:
            import os
            os.chmod(self.path.parent, 0o700)
        except OSError:
            pass
        self._lock = threading.Lock()
        self._db = sqlite3.connect(str(self.path), check_same_thread=False)
        # WAL lets readers and one writer coexist; busy_timeout makes
        # a writer WAIT for the lock instead of failing instantly —
        # several relay processes share one file in the mesh, and
        # their 5s registry heartbeats + health-battery writes must
        # queue, never error out (v1.3.0 root-cause fix).
        self._db.execute("PRAGMA busy_timeout=10000")
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA journal_mode=WAL")
        integrity = self._db.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"relay DB integrity check failed: {integrity}")
        try:
            import os
            os.chmod(self.path, 0o600)
        except OSError:
            pass
        with self._lock:
            self._db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    secret TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    pubkey TEXT NOT NULL DEFAULT '',
                    sign_pub TEXT NOT NULL DEFAULT '',
                    capabilities TEXT NOT NULL DEFAULT '[]',
                    cap_desc TEXT NOT NULL DEFAULT '',
                    mode TEXT NOT NULL DEFAULT 'autonomous',
                    designation TEXT NOT NULL DEFAULT 'production',
                    decision_link TEXT NOT NULL DEFAULT '',
                    decision_link_detail TEXT NOT NULL DEFAULT '',
                    delivery_ack INTEGER NOT NULL DEFAULT 0,
                    recovery_hash TEXT NOT NULL DEFAULT '',
                    recovery_used_at INTEGER NOT NULL DEFAULT 0,
                    vault_labels TEXT NOT NULL DEFAULT '',
                    vault_content TEXT NOT NULL DEFAULT '',
                    vault_blob TEXT NOT NULL DEFAULT '',
                    vault_version INTEGER NOT NULL DEFAULT 0,
                    vault_entries INTEGER NOT NULL DEFAULT 0,
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS queue (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    to_username TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    priority INTEGER NOT NULL DEFAULT 0,
                    ts INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_queue_to ON queue(to_username, seq);
                CREATE TABLE IF NOT EXISTS groups (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    creator TEXT NOT NULL,
                    settings TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    nickname TEXT NOT NULL DEFAULT '',
                    custom_role TEXT NOT NULL DEFAULT '',
                    added_by TEXT NOT NULL DEFAULT '',
                    joined_at INTEGER NOT NULL,
                    PRIMARY KEY (group_id, username)
                );
                CREATE TABLE IF NOT EXISTS group_keys (
                    group_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    wrapped TEXT NOT NULL,
                    PRIMARY KEY (group_id, username)
                );
                CREATE TABLE IF NOT EXISTS invites (
                    token TEXT PRIMARY KEY,
                    group_id TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS work (
                    id TEXT PRIMARY KEY,
                    assigner TEXT NOT NULL,
                    assignee TEXT NOT NULL,
                    group_id TEXT,
                    content_enc TEXT NOT NULL DEFAULT '',
                    content_self TEXT NOT NULL DEFAULT '',
                    batch_id TEXT,
                    chain_id TEXT NOT NULL DEFAULT '',
                    chain_step INTEGER NOT NULL DEFAULT 0,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    auto_reassign INTEGER NOT NULL DEFAULT 1,
                    assignee_role TEXT NOT NULL DEFAULT '',
                    require_approval INTEGER NOT NULL DEFAULT 0,
                    content_group TEXT NOT NULL DEFAULT '',
                    priority TEXT NOT NULL DEFAULT 'normal',
                    progress_percent INTEGER NOT NULL DEFAULT 0,
                    progress_at INTEGER NOT NULL DEFAULT 0,
                    proof_hash TEXT NOT NULL DEFAULT '',
                    proof_ts INTEGER NOT NULL DEFAULT 0,
                    proof_sig TEXT NOT NULL DEFAULT '',
                    proof_verified INTEGER NOT NULL DEFAULT 0,
                    deadline INTEGER,
                    status TEXT NOT NULL DEFAULT 'assigned',
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_work_assignee ON work(assignee, status);
                CREATE INDEX IF NOT EXISTS idx_work_assigner ON work(assigner, status);
                CREATE TABLE IF NOT EXISTS work_deliveries (
                    id TEXT PRIMARY KEY,
                    work_id TEXT NOT NULL,
                    deliverer TEXT NOT NULL,
                    content_enc TEXT NOT NULL DEFAULT '',
                    content_self TEXT NOT NULL DEFAULT '',
                    content_group TEXT NOT NULL DEFAULT '',
                    content_next TEXT NOT NULL DEFAULT '',
                    ts INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS blobs (
                    id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    for_user TEXT NOT NULL DEFAULT '',
                    for_group TEXT NOT NULL DEFAULT '',
                    for_channel TEXT NOT NULL DEFAULT '',
                    whole_sha TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dashboard_sessions (
                    token_hash TEXT PRIMARY KEY,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER NOT NULL,
                    kind TEXT NOT NULL,
                    actor TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    group_id TEXT NOT NULL DEFAULT '',
                    work_id TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT '',
                    priority TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    mentions TEXT NOT NULL DEFAULT '[]',
                    ref_id TEXT NOT NULL DEFAULT '',
                    sender_nickname TEXT NOT NULL DEFAULT '',
                    sender_role TEXT NOT NULL DEFAULT '',
                    sender_custom_role TEXT NOT NULL DEFAULT '',
                    oversight TEXT NOT NULL DEFAULT '',
                    content_envelope TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS message_reads (
                    message_id TEXT NOT NULL,
                    reader TEXT NOT NULL,
                    read_at INTEGER NOT NULL,
                    PRIMARY KEY (message_id, reader)
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL,
                    subject TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    reminders INTEGER NOT NULL DEFAULT 0,
                    last_reminder_at INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    resolved_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS library (
                    id TEXT PRIMARY KEY,
                    delivery_id TEXT NOT NULL DEFAULT '',
                    work_id TEXT NOT NULL DEFAULT '',
                    filename TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT '',
                    sender TEXT NOT NULL DEFAULT '',
                    to_user TEXT NOT NULL DEFAULT '',
                    group_id TEXT NOT NULL DEFAULT '',
                    chain_next TEXT NOT NULL DEFAULT '',
                    ts INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS chains (
                    id TEXT PRIMARY KEY,
                    creator TEXT NOT NULL,
                    group_id TEXT NOT NULL DEFAULT '',
                    name TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'running',
                    paused_since INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS chain_steps (
                    id TEXT PRIMARY KEY,
                    chain_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    target_type TEXT NOT NULL DEFAULT 'user',
                    target TEXT NOT NULL DEFAULT '',
                    group_id TEXT NOT NULL DEFAULT '',
                    assignees TEXT NOT NULL DEFAULT '[]',
                    envelopes TEXT NOT NULL DEFAULT '{}',
                    content_group TEXT NOT NULL DEFAULT '',
                    deadline INTEGER,
                    priority TEXT NOT NULL DEFAULT 'normal',
                    status TEXT NOT NULL DEFAULT 'pending',
                    work_id TEXT NOT NULL DEFAULT '',
                    handoff TEXT NOT NULL DEFAULT '[]',
                    require_approval INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS vault (
                    id TEXT PRIMARY KEY,
                    group_id TEXT NOT NULL,
                    name TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    sha256 TEXT NOT NULL DEFAULT '',
                    blob_id TEXT NOT NULL DEFAULT '',
                    descriptor TEXT NOT NULL DEFAULT '{}',
                    added_by TEXT NOT NULL DEFAULT '',
                    pinned INTEGER NOT NULL DEFAULT 0,
                    ts INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS work_checkpoints (
                    work_id TEXT PRIMARY KEY,
                    attempt INTEGER NOT NULL DEFAULT 1,
                    by_user TEXT NOT NULL DEFAULT '',
                    content_assigner TEXT NOT NULL DEFAULT '',
                    content_group TEXT NOT NULL DEFAULT '',
                    ts INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS channels (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    creator TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS channel_members (
                    channel_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'subscriber',
                    added_by TEXT NOT NULL DEFAULT '',
                    joined_at INTEGER NOT NULL,
                    PRIMARY KEY (channel_id, username)
                );
                CREATE TABLE IF NOT EXISTS channel_keys (
                    channel_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    wrapped TEXT NOT NULL,
                    PRIMARY KEY (channel_id, username)
                );
                CREATE TABLE IF NOT EXISTS upload_sessions (
                    session_id TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    for_user TEXT NOT NULL DEFAULT '',
                    for_group TEXT NOT NULL DEFAULT '',
                    whole_sha TEXT NOT NULL DEFAULT '',
                    ct_sha TEXT NOT NULL DEFAULT '',
                    size INTEGER NOT NULL DEFAULT 0,
                    chunk_size INTEGER NOT NULL DEFAULT 0,
                    chunks TEXT NOT NULL DEFAULT '[]',
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS servers (
                    endpoint TEXT PRIMARY KEY,
                    label TEXT NOT NULL DEFAULT '',
                    host_agent TEXT NOT NULL DEFAULT '',
                    version TEXT NOT NULL DEFAULT '',
                    health INTEGER NOT NULL DEFAULT -1,
                    riders INTEGER NOT NULL DEFAULT 0,
                    capacity INTEGER NOT NULL DEFAULT 10,
                    last_seen INTEGER NOT NULL DEFAULT 0,
                    first_seen INTEGER NOT NULL DEFAULT 0,
                    server_id TEXT NOT NULL DEFAULT '',
                    owner_agent TEXT NOT NULL DEFAULT '',
                    home_host TEXT NOT NULL DEFAULT '',
                    home_endpoint TEXT NOT NULL DEFAULT '',
                    home_last_seen INTEGER NOT NULL DEFAULT 0,
                    home_healthy_since INTEGER NOT NULL DEFAULT 0,
                    home_health INTEGER NOT NULL DEFAULT -1,
                    home_riders INTEGER NOT NULL DEFAULT 0,
                    home_capacity INTEGER NOT NULL DEFAULT 0,
                    carry_state TEXT NOT NULL DEFAULT '',
                    carried_by TEXT NOT NULL DEFAULT '',
                    carried_by_id TEXT NOT NULL DEFAULT '',
                    carry_endpoint TEXT NOT NULL DEFAULT '',
                    carry_lease_token TEXT NOT NULL DEFAULT '',
                    carry_lease_until INTEGER NOT NULL DEFAULT 0,
                    carry_claimed_at INTEGER NOT NULL DEFAULT 0,
                    can_carry INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS connections (
                    username TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL DEFAULT '',
                    endpoint TEXT NOT NULL DEFAULT '',
                    home_endpoint TEXT NOT NULL DEFAULT '',
                    updated_at INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS rooms (
                    room_id TEXT PRIMARY KEY,
                    group_id TEXT NOT NULL DEFAULT '',
                    creator TEXT NOT NULL DEFAULT '',
                    participants TEXT NOT NULL DEFAULT '[]',
                    opened_at INTEGER NOT NULL DEFAULT 0,
                    updated_at INTEGER NOT NULL DEFAULT 0,
                    closed INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS room_frames (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    to_username TEXT NOT NULL,
                    frame TEXT NOT NULL,
                    ts INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS grants (
                    username TEXT PRIMARY KEY,
                    scopes TEXT NOT NULL DEFAULT '[]',
                    granted_by TEXT NOT NULL DEFAULT '',
                    granted_at INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'active',
                    bound_sign_pub TEXT NOT NULL DEFAULT '',
                    updated_at INTEGER NOT NULL DEFAULT 0,
                    grantor TEXT NOT NULL DEFAULT '',
                    ceremony_at INTEGER NOT NULL DEFAULT 0,
                    request_id TEXT NOT NULL DEFAULT '',
                    requested_at INTEGER NOT NULL DEFAULT 0,
                    request_reason TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS grant_receipts (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    id TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    scope TEXT NOT NULL DEFAULT '',
                    connector TEXT NOT NULL DEFAULT '',
                    action TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    work_ref TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT '',
                    detail TEXT NOT NULL DEFAULT '',
                    prev_hash TEXT NOT NULL DEFAULT '',
                    sig TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS grant_approvals (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    ts INTEGER NOT NULL,
                    scope TEXT NOT NULL DEFAULT '',
                    connector TEXT NOT NULL DEFAULT '',
                    action TEXT NOT NULL DEFAULT '',
                    target TEXT NOT NULL DEFAULT '',
                    params TEXT NOT NULL DEFAULT '{}',
                    work_ref TEXT NOT NULL DEFAULT '',
                    reason TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'awaiting_approval',
                    decided_by TEXT NOT NULL DEFAULT '',
                    decided_at INTEGER NOT NULL DEFAULT 0,
                    receipt_id TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS grant_meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS agent_connectors (
                    username TEXT PRIMARY KEY,
                    inventory TEXT NOT NULL DEFAULT '[]',
                    updated_at INTEGER NOT NULL DEFAULT 0
                );
                """
            )
            self._db.commit()
            self._migrate_v11()

    def _migrate_v11(self) -> None:
        """v1.1.0 schema alignment (idempotent, runs on every open):
        invites -> canonical Supabase shape (token/created_at; the
        stored token stays the SHA-256 hash, created_at is back-derived
        as expires_at - INVITE_TTL_SECONDS so validity is preserved
        exactly for default-TTL invites); upload_sessions drops the
        for_channel column (channel scope is asserted by the relay at
        session start and carried on the finish frame); audit_log
        gains the sender identity columns; work + chain_steps gain
        require_approval."""
        db = self._db
        cols = [r[1] for r in db.execute("PRAGMA table_info(invites)")]
        if cols and "token_hash" in cols:
            db.execute(
                "CREATE TABLE invites_v11 ("
                " token TEXT PRIMARY KEY, group_id TEXT NOT NULL,"
                " created_by TEXT NOT NULL,"
                " created_at INTEGER NOT NULL)")
            db.execute(
                "INSERT INTO invites_v11 (token, group_id, created_by,"
                " created_at) SELECT token_hash, group_id, created_by,"
                " expires_at - ? FROM invites", (INVITE_TTL_SECONDS,))
            db.execute("DROP TABLE invites")
            db.execute("ALTER TABLE invites_v11 RENAME TO invites")
        cols = [r[1] for r in
                db.execute("PRAGMA table_info(upload_sessions)")]
        if "for_channel" in cols:
            db.execute(
                "CREATE TABLE upload_sessions_v11 ("
                " session_id TEXT PRIMARY KEY, owner TEXT NOT NULL,"
                " for_user TEXT NOT NULL DEFAULT '',"
                " for_group TEXT NOT NULL DEFAULT '',"
                " whole_sha TEXT NOT NULL DEFAULT '',"
                " ct_sha TEXT NOT NULL DEFAULT '',"
                " size INTEGER NOT NULL DEFAULT 0,"
                " chunk_size INTEGER NOT NULL DEFAULT 0,"
                " chunks TEXT NOT NULL DEFAULT '[]',"
                " created_at INTEGER NOT NULL)")
            db.execute(
                "INSERT INTO upload_sessions_v11 SELECT session_id,"
                " owner, for_user, for_group, whole_sha, ct_sha, size,"
                " chunk_size, chunks, created_at FROM upload_sessions")
            db.execute("DROP TABLE upload_sessions")
            db.execute("ALTER TABLE upload_sessions_v11"
                       " RENAME TO upload_sessions")

        def _add(table, column, ddl):
            existing = [r[1] for r in
                        db.execute(f"PRAGMA table_info({table})")]
            if existing and column not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        _add("audit_log", "sender_nickname",
             "sender_nickname TEXT NOT NULL DEFAULT ''")
        _add("audit_log", "sender_role",
             "sender_role TEXT NOT NULL DEFAULT ''")
        _add("audit_log", "sender_custom_role",
             "sender_custom_role TEXT NOT NULL DEFAULT ''")
        _add("audit_log", "oversight",
             "oversight TEXT NOT NULL DEFAULT ''")
        _add("audit_log", "content_envelope",
             "content_envelope TEXT NOT NULL DEFAULT ''")
        _add("work", "require_approval",
             "require_approval INTEGER NOT NULL DEFAULT 0")
        _add("chain_steps", "require_approval",
             "require_approval INTEGER NOT NULL DEFAULT 0")
        # Platform autonomy law (v1.1.7): every profile carries a
        # mode; the column default IS the law's presentation rule —
        # a profile with no explicit mode is autonomous; manual is
        # only ever an explicit opt-out recorded by the agent itself.
        _add("users", "mode",
             "mode TEXT NOT NULL DEFAULT 'autonomous'")
        # Probe/test segregation (v1.6.0, owner's ruling): every
        # registration carries a DESIGNATION — 'production' (the
        # line the owner runs) or 'test' (a probe/test identity).
        # It is DECLARED at registration, never inferred from the
        # username (deploy-probe is production permanently — it owns
        # a server and is the owner's standing fixture), and after
        # registration it changes ONLY through the operator path
        # (set_designation): an agent can never flip its own. The
        # designation steers dashboard composition ONLY — the line
        # itself (messages, work, carrying) never reads it.
        _add("users", "designation",
             "designation TEXT NOT NULL DEFAULT 'production'")
        # Decision link (v1.3.5, "the agent is the brain"): the
        # agent's own hello declares whether its line connection is
        # linked to its decision-making — 'linked' / 'pending' / ''
        # (never declared). It is a CONNECTION-side fact, the only
        # kind of "missing" this platform may ever record about an
        # agent: capability and memory are the agent's own, always,
        # and are never modelled here as parts to be supplied.
        _add("users", "decision_link",
             "decision_link TEXT NOT NULL DEFAULT ''")
        # Auto decision link (v1.8.0, owner's law): the declared
        # link's DETAIL — how the client wired itself (mode:
        # config / in_process / handlers / convention / none) and
        # whether its live self-check VERIFIED the path — as a
        # JSON object. The plain decision_link column keeps the
        # v1.3.5 summary ('linked' only when verified); this
        # column carries the rest of the truth.
        _add("users", "decision_link_detail",
             "decision_link_detail TEXT NOT NULL DEFAULT ''")
        # Delivery custody (v1.3.7): the agent's own hello declares
        # whether its client acks queued frames into its durable
        # journal (1) or still takes the legacy destructive flush
        # (0, the default for every pre-1.3.7 install). Like
        # decision_link, a CONNECTION-side fact declared by the
        # agent itself — the relay only records it.
        _add("users", "delivery_ack",
             "delivery_ack INTEGER NOT NULL DEFAULT 0")
        # Recovery keys (v1.7.0, owner's design): every registration
        # is issued a high-entropy RECOVERY KEY — the agent's
        # crypto-style private key for LOGIN-BACK. Only its SHA-256
        # hash is ever stored here (recovery_hash; '' = not
        # enrolled): nobody — not the relay, not the dashboard, not
        # a database reader — can read the key back. recovery_used_at
        # stamps the last successful recovery login (the used key is
        # burned and rotated at that moment).
        _add("users", "recovery_hash",
             "recovery_hash TEXT NOT NULL DEFAULT ''")
        _add("users", "recovery_used_at",
             "recovery_used_at INTEGER NOT NULL DEFAULT 0")
        # Key-signed hello (v1.3.9): how this agent's most recent
        # hello authenticated — 'key' (Ed25519 challenge-response,
        # nothing reusable presented), 'secret' (a legacy client
        # presenting its reusable secret), 'resume' (the v1.3.7
        # key-match resume gate), 'bootstrap' (the claiming hello
        # itself). A connection-side fact recorded from the hello,
        # exactly like delivery_ack — surfaces flag legacy methods
        # honestly instead of letting them pass as current.
        _add("users", "auth_method",
             "auth_method TEXT NOT NULL DEFAULT ''")
        # Grant, corrected model (v1.8.1): the grant row carries
        # the agent-initiated flow's record — the agent's pending
        # REQUEST (request_id / requested_at / request_reason;
        # status 'requested') and, once the agent's OWN owner
        # allows it agent-side, the grantor ATTESTATION (grantor)
        # and ceremony timestamp. The agent's connector vault is
        # stored per agent in agent_connectors (created with the
        # schema; _add covers the grant columns on older DBs).
        _add("grants", "grantor",
             "grantor TEXT NOT NULL DEFAULT ''")
        _add("grants", "ceremony_at",
             "ceremony_at INTEGER NOT NULL DEFAULT 0")
        _add("grants", "request_id",
             "request_id TEXT NOT NULL DEFAULT ''")
        _add("grants", "requested_at",
             "requested_at INTEGER NOT NULL DEFAULT 0")
        _add("grants", "request_reason",
             "request_reason TEXT NOT NULL DEFAULT ''")
        # Credentials vault (v1.4.0): the relay-side POINTER to an
        # agent's vault — never vault content. vault_labels is the
        # agent-published OVERSIGHT-SEALED label envelope (service +
        # account + timestamps; the relay stores ciphertext and
        # cannot open it — only the owner's dashboard can);
        # vault_blob names the current self-sealed vault document
        # in the blob layer; vault_version is the document revision
        # the pointer names (stale publishes are refused so a
        # zombie host can never rewind an agent's vault);
        # vault_entries is the published entry count. No column
        # here can ever hold a PLAINTEXT secret: entry secrets
        # exist in plaintext only inside the agent (identity-sealed
        # document) and, since v1.5.0, inside the oversight-sealed
        # content envelope whose plaintext lives only in the
        # owner's authenticated dashboard session.
        _add("users", "vault_labels",
             "vault_labels TEXT NOT NULL DEFAULT ''")
        # v1.5.0: vault_content is the agent-published OVERSIGHT-
        # SEALED FULL-content envelope (the owner's Credentials
        # view) — still ciphertext to this store; it holds no key
        # that can open it.
        _add("users", "vault_content",
             "vault_content TEXT NOT NULL DEFAULT ''")
        _add("users", "vault_blob",
             "vault_blob TEXT NOT NULL DEFAULT ''")
        _add("users", "vault_version",
             "vault_version INTEGER NOT NULL DEFAULT 0")
        _add("users", "vault_entries",
             "vault_entries INTEGER NOT NULL DEFAULT 0")
        # Peer mesh (v1.2.0): the server registry carries health,
        # rider load and effective capacity alongside identity.
        _add("servers", "health",
             "health INTEGER NOT NULL DEFAULT 100")
        _add("servers", "riders",
             "riders INTEGER NOT NULL DEFAULT 0")
        _add("servers", "capacity",
             "capacity INTEGER NOT NULL DEFAULT 10")
        # Server carrying + earned health (v1.3.0): a server has a
        # STABLE identity (server_id) distinct from its current
        # endpoint — while carried, the endpoint moves to the
        # carrier and the identity must not. owner_agent is the
        # PERMANENT owner of a per-agent server ('' = shared relay);
        # carried_by is only the temporary helper whose machine is
        # running it — never a transfer of ownership. Health is
        # earned by testing: -1 = UNRATED (no percentage yet).
        for _col, _ddl in (
                ("server_id", "server_id TEXT NOT NULL DEFAULT ''"),
                ("owner_agent", "owner_agent TEXT NOT NULL DEFAULT ''"),
                ("home_host", "home_host TEXT NOT NULL DEFAULT ''"),
                ("home_endpoint",
                 "home_endpoint TEXT NOT NULL DEFAULT ''"),
                ("home_last_seen",
                 "home_last_seen INTEGER NOT NULL DEFAULT 0"),
                ("home_healthy_since",
                 "home_healthy_since INTEGER NOT NULL DEFAULT 0"),
                ("home_health",
                 "home_health INTEGER NOT NULL DEFAULT -1"),
                ("home_riders",
                 "home_riders INTEGER NOT NULL DEFAULT 0"),
                ("home_capacity",
                 "home_capacity INTEGER NOT NULL DEFAULT 0"),
                ("carry_state", "carry_state TEXT NOT NULL DEFAULT ''"),
                ("carried_by", "carried_by TEXT NOT NULL DEFAULT ''"),
                ("carried_by_id",
                 "carried_by_id TEXT NOT NULL DEFAULT ''"),
                ("carry_endpoint",
                 "carry_endpoint TEXT NOT NULL DEFAULT ''"),
                ("carry_lease_token",
                 "carry_lease_token TEXT NOT NULL DEFAULT ''"),
                ("carry_lease_until",
                 "carry_lease_until INTEGER NOT NULL DEFAULT 0"),
                ("carry_claimed_at",
                 "carry_claimed_at INTEGER NOT NULL DEFAULT 0"),
                ("can_carry", "can_carry INTEGER NOT NULL DEFAULT 1")):
            _add("servers", _col, _ddl)
        db.execute(
            "UPDATE servers SET server_id = endpoint"
            " WHERE server_id = ''")
        db.execute(
            "UPDATE servers SET home_endpoint = endpoint,"
            " home_last_seen = last_seen, carry_state = 'home'"
            " WHERE owner_agent <> '' AND home_endpoint = ''")
        db.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_servers_server_id"
            " ON servers(server_id)")
        db.commit()

    # -- blob metadata (ciphertext lives in the blob store) ----------------
    def put_blob_meta(self, blob_id, owner, for_user="", for_group="",
                      size=0, for_channel="", whole_sha=""):
        with self._lock:
            self._db.execute(
                "INSERT OR REPLACE INTO blobs (id, owner, for_user,"
                " for_group, for_channel, whole_sha, size, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (blob_id, owner, for_user, for_group, for_channel,
                 whole_sha, size, now_ts()))
            self._db.commit()

    def find_blob_by_whole_sha(self, whole_sha, owner="", for_user="",
                               for_group="", for_channel=""):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM blobs WHERE whole_sha = ? AND owner = ?"
                " AND for_user = ? AND for_group = ? AND for_channel = ?"
                " ORDER BY created_at LIMIT 1",
                (whole_sha, owner, for_user, for_group, for_channel)).fetchone()
        return dict(row) if row else None

    def get_blob_meta(self, blob_id):
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM blobs WHERE id = ?", (blob_id,)).fetchone()
        return dict(row) if row else None

    def delete_blob_meta(self, blob_id):
        with self._lock:
            self._db.execute("DELETE FROM blobs WHERE id = ?", (blob_id,))
            self._db.commit()

    def list_blob_meta(self):
        with self._lock:
            rows = self._db.execute("SELECT * FROM blobs ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    # -- fleet alerts (point 37) --------------------------------------------------
    def open_alert(self, kind: str, subject: str, detail: str = "") -> dict:
        """One alert per incident: an already-open alert for the same
        kind+subject is returned, never duplicated."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM alerts WHERE kind = ? AND subject = ?"
                " AND status = 'open'", (kind, subject)).fetchone()
            if row is not None:
                return dict(row)
            aid = new_id("a-")[:14]
            self._db.execute(
                "INSERT INTO alerts (id, kind, subject, detail, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (aid, kind, subject, detail, now_ts()))
            self._db.commit()
            row = self._db.execute(
                "SELECT * FROM alerts WHERE id = ?", (aid,)).fetchone()
        return dict(row)

    def resolve_alerts(self, kind: str, subject: str) -> int:
        with self._lock:
            cur = self._db.execute(
                "UPDATE alerts SET status = 'resolved', resolved_at = ?"
                " WHERE kind = ? AND subject = ? AND status = 'open'",
                (now_ts(), kind, subject))
            self._db.commit()
        return cur.rowcount

    def bump_reminder(self, alert_id: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE alerts SET reminders = reminders + 1,"
                " last_reminder_at = ? WHERE id = ?",
                (now_ts(), alert_id))
            self._db.commit()

    def list_alerts(self, status: str | None = None,
                    limit: int = 100) -> list[dict]:
        with self._lock:
            if status:
                rows = self._db.execute(
                    "SELECT * FROM alerts WHERE status = ?"
                    " ORDER BY created_at DESC LIMIT ?",
                    (status, limit)).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM alerts ORDER BY created_at DESC"
                    " LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def oldest_urgent_queued(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT to_username, MIN(ts) AS since FROM queue"
                " WHERE priority >= 2 GROUP BY to_username").fetchall()
        return [dict(r) for r in rows]

    # -- delivery library (point 38a) ----------------------------------------------
    def add_library_entries(self, delivery_id: str, work: dict,
                            files: list[dict]) -> list[dict]:
        ids = []
        with self._lock:
            for f in files:
                lid = new_id("lib-")[:16]
                self._db.execute(
                    "INSERT INTO library (id, delivery_id, work_id,"
                    " filename, size, sha256, sender, to_user, group_id,"
                    " ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (lid, delivery_id, work["id"], f.get("name", ""),
                     int(f.get("size") or 0), f.get("sha256", ""),
                     work["assignee"], work["assigner"],
                     work["group_id"] or "", now_ts()))
                ids.append(lid)
            self._db.commit()
        if not ids:
            return []
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM library WHERE id IN (%s)"
                % ",".join("?" * len(ids)), tuple(ids)).fetchall()
        return [dict(r) for r in rows]

    def _library_visible(self, row: dict, requester: str) -> bool:
        if row["sender"] == requester or row["to_user"] == requester:
            return True
        if row.get("chain_next") and row["chain_next"] == requester:
            return True
        if row["group_id"]:
            return self.role_of(row["group_id"], requester) is not None
        return False

    def search_library(self, requester: str, q: str = "", sender: str = "",
                       group_id: str = "", hash_prefix: str = "",
                       limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM library ORDER BY ts DESC LIMIT 1000"
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            if not self._library_visible(d, requester):
                continue
            if q and q.lower() not in d["filename"].lower():
                continue
            if sender and d["sender"] != sender:
                continue
            if group_id and d["group_id"] != group_id:
                continue
            if hash_prefix and not d["sha256"].startswith(hash_prefix):
                continue
            out.append(d)
            if len(out) >= limit:
                break
        return out

    def library_entry(self, library_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM library WHERE id = ?",
                (library_id,)).fetchone()
        return dict(row) if row else None

    def library_all(self, limit: int = 200) -> list[dict]:
        """Operator (dashboard) view: all library metadata."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM library ORDER BY ts DESC LIMIT ?",
                (limit,)).fetchall()
        return [dict(r) for r in rows]

    # -- work chains (point 41) ---------------------------------------------------------
    def create_chain(self, creator: str, group_id: str, name: str,
                     steps: list[dict]) -> dict:
        cid = new_id("chain-")[:18]
        ts = now_ts()
        with self._lock:
            self._db.execute(
                "INSERT INTO chains (id, creator, group_id, name, status,"
                " created_at, updated_at) VALUES (?, ?, ?, ?, 'running',"
                " ?, ?)", (cid, creator, group_id or "", name, ts, ts))
            for i, st in enumerate(steps):
                self._db.execute(
                    "INSERT INTO chain_steps (id, chain_id, position,"
                    " target_type, target, group_id, assignees, envelopes,"
                    " content_group, deadline, priority, status,"
                    " require_approval, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                    " 'pending', ?, ?)",
                    (new_id("step-")[:16], cid, i + 1,
                     st.get("target_type", "user"), st.get("target", ""),
                     st.get("group_id", "") or group_id or "",
                     json.dumps(st.get("assignees") or []),
                     json.dumps(st.get("envelopes") or {}),
                     json.dumps(st["content_group"])
                     if st.get("content_group") else "",
                     st.get("deadline"), st.get("priority", "normal"),
                     1 if st.get("require_approval") else 0, ts))
            self._db.commit()
        return self.get_chain(cid)

    def get_chain(self, chain_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM chains WHERE id = ?", (chain_id,)).fetchone()
            if row is None:
                return None
            srows = self._db.execute(
                "SELECT * FROM chain_steps WHERE chain_id = ?"
                " ORDER BY position", (chain_id,)).fetchall()
        chain = dict(row)
        steps = []
        for r in srows:
            d = dict(r)
            d["assignees"] = json.loads(d["assignees"] or "[]")
            d["envelopes"] = json.loads(d["envelopes"] or "{}")
            try:
                d["content_group"] = json.loads(d["content_group"]
                                                or "null")
            except Exception:
                d["content_group"] = None
            d["handoff"] = json.loads(d["handoff"] or "[]")
            steps.append(d)
        chain["steps"] = steps
        return chain

    def set_chain_status(self, chain_id: str, status: str) -> dict:
        with self._lock:
            paused = now_ts() if status == "paused" else 0
            self._db.execute(
                "UPDATE chains SET status = ?,"
                " paused_since = CASE WHEN ? = 'paused' THEN ?"
                " ELSE paused_since END, updated_at = ? WHERE id = ?",
                (status, status, paused, now_ts(), chain_id))
            self._db.commit()
        return self.get_chain(chain_id)

    def set_step_status(self, step_id: str, status: str,
                        work_id: str = "") -> None:
        with self._lock:
            if work_id:
                self._db.execute(
                    "UPDATE chain_steps SET status = ?, work_id = ?"
                    " WHERE id = ?", (status, work_id, step_id))
            else:
                self._db.execute(
                    "UPDATE chain_steps SET status = ? WHERE id = ?",
                    (status, step_id))
            self._db.commit()

    def set_step_handoff(self, step_id: str, handoff: list,
                         next_assignees: list[str]) -> None:
        """Attach step N's deliverables to step N+1 and extend library
        entitlement for those deliverables to the next assignees."""
        with self._lock:
            self._db.execute(
                "UPDATE chain_steps SET handoff = ? WHERE id = ?",
                (json.dumps(handoff), step_id))
            for entry in handoff:
                for nxt in next_assignees:
                    self._db.execute(
                        "UPDATE library SET chain_next = ? WHERE id = ?",
                        (nxt, entry.get("library_id", "")))
            self._db.commit()

    def library_for_work(self, work_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM library WHERE work_id = ? ORDER BY ts",
                (work_id,)).fetchall()
        return [dict(r) for r in rows]

    def groups_for_user(self, username: str) -> list[dict]:
        """Every group the user belongs to, with their membership row
        and the group settings — the reconnect resync source (43e)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT group_id FROM group_members WHERE username = ?",
                (username,)).fetchall()
        out = []
        for r in rows:
            g = self.get_group(r["group_id"])
            if g is None:
                continue
            members = self.members(g["id"])
            mine = next((m for m in members
                         if m["username"] == username), None)
            out.append({"group_id": g["id"], "name": g["name"],
                        "settings": g["settings"], "my": mine,
                        "members": members})
        return out

    def channels_for_user(self, username: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT channel_id, role FROM channel_members"
                " WHERE username = ?", (username,)).fetchall()
        out = []
        for r in rows:
            c = self.get_channel(r["channel_id"])
            if c:
                out.append({"channel_id": c["id"], "name": c["name"],
                            "my_role": r["role"]})
        return out

    def step_by_work(self, work_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM chain_steps WHERE work_id = ?",
                (work_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["assignees"] = json.loads(d["assignees"] or "[]")
        return d

    def list_chains_meta(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM chains ORDER BY updated_at DESC LIMIT ?",
                (limit,)).fetchall()
        out = []
        for r in rows:
            chain = self.get_chain(r["id"])
            for st in chain["steps"]:
                st.pop("envelopes", None)
                st.pop("content_group", None)
                if st.get("work_id"):
                    w = self.get_work(st["work_id"])
                    if w:
                        st["work_status"] = w["status"]
                        st["progress_percent"] = w.get(
                            "progress_percent", 0)
                        st["assignee"] = w["assignee"]
            out.append(chain)
        return out

    def chains_for_user(self, username: str) -> list[dict]:
        chains = self.list_chains_meta(200)
        out = []
        for c in chains:
            involved = {c["creator"]}
            for st in c["steps"]:
                involved.update(st.get("assignees") or [])
                if st.get("assignee"):
                    involved.add(st["assignee"])
            if username in involved:
                out.append(c)
        return out

    # -- group vault (point 38b) ------------------------------------------------------
    def vault_add(self, group_id: str, descriptor: dict, added_by: str,
                  pinned: bool = False) -> dict:
        vid = new_id("v-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO vault (id, group_id, name, size, sha256,"
                " blob_id, descriptor, added_by, pinned, ts)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (vid, group_id, descriptor.get("name", ""),
                 int(descriptor.get("size") or 0),
                 descriptor.get("sha256", ""),
                 descriptor.get("blob_id", ""), json.dumps(descriptor),
                 added_by, 1 if pinned else 0, now_ts()))
            self._db.commit()
            row = self._db.execute(
                "SELECT * FROM vault WHERE id = ?", (vid,)).fetchone()
        out = dict(row)
        out["descriptor"] = json.loads(out["descriptor"] or "{}")
        out["pinned"] = bool(out["pinned"])
        return out

    def vault_list(self, group_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM vault WHERE group_id = ?"
                " ORDER BY pinned DESC, ts DESC", (group_id,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["descriptor"] = json.loads(d["descriptor"] or "{}")
            d["pinned"] = bool(d["pinned"])
            out.append(d)
        return out

    def vault_entry(self, vault_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM vault WHERE id = ?", (vault_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["descriptor"] = json.loads(d["descriptor"] or "{}")
        d["pinned"] = bool(d["pinned"])
        return d

    def vault_set_pinned(self, vault_id: str, pinned: bool) -> dict | None:
        with self._lock:
            self._db.execute(
                "UPDATE vault SET pinned = ? WHERE id = ?",
                (1 if pinned else 0, vault_id))
            self._db.commit()
        return self.vault_entry(vault_id)

    def vault_remove(self, vault_id: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM vault WHERE id = ?", (vault_id,))
            self._db.commit()
        return cur.rowcount > 0

    def vault_meta(self) -> list[dict]:
        """Operator (dashboard) view: all vault metadata PLUS the
        blob_id and parsed descriptor — the dashboard needs the
        descriptor's oversight wrap to offer the owner a download;
        it strips the descriptor before anything reaches the
        browser (see dashboard._serve_data)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, group_id, name, size, sha256, blob_id,"
                " descriptor, added_by, pinned, ts FROM vault"
                " ORDER BY pinned DESC, ts DESC LIMIT 500").fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["descriptor"] = json.loads(d.get("descriptor") or "{}")
            except Exception:
                d["descriptor"] = {}
            d["pinned"] = bool(d["pinned"])
            out.append(d)
        return out

    # -- dashboard sessions (trusted devices, 7-day) -------------------------
    def create_session(self, token_hash: str, expires_at: int) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO dashboard_sessions (token_hash, created_at,"
                " expires_at) VALUES (?, ?, ?)",
                (token_hash, now_ts(), expires_at))
            self._db.commit()

    def session_valid(self, token_hash: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT expires_at FROM dashboard_sessions"
                " WHERE token_hash = ?", (token_hash,)).fetchone()
        return bool(row) and row["expires_at"] >= now_ts()

    def revoke_session(self, token_hash: str) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM dashboard_sessions WHERE token_hash = ?",
                (token_hash,))
            self._db.commit()

    # -- append-only metadata audit log ---------------------------------------
    def audit(self, kind: str, actor: str, target: str = "",
              group_id: str = "", work_id: str = "", status: str = "",
              priority: str = "", size: int = 0, mentions=None,
              ref_id: str = "", sender_nickname: str = "",
              sender_role: str = "", sender_custom_role: str = "",
              oversight: str = "", content_envelope: str = "") -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO audit_log (ts, kind, actor, target, group_id,"
                " work_id, status, priority, size, mentions, ref_id,"
                " sender_nickname, sender_role, sender_custom_role,"
                " oversight, content_envelope)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now_ts(), kind, actor, target, group_id, work_id, status,
                 priority, int(size or 0), json.dumps(mentions or []),
                 ref_id, sender_nickname or "", sender_role or "",
                 sender_custom_role or "", oversight or "",
                 content_envelope or ""))
            self._db.commit()

    @staticmethod
    def _shape_audit_rows(rows) -> list[dict]:
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["mentions"] = json.loads(d.get("mentions") or "[]")
            except Exception:
                d["mentions"] = []
            try:
                d["oversight"] = json.loads(d.get("oversight") or "null")
            except Exception:
                d["oversight"] = None
            try:
                d["content_envelope"] = json.loads(
                    d.get("content_envelope") or "null")
            except Exception:
                d["content_envelope"] = None
            out.append(d)
        return out

    _AUDIT_COLS = ('SELECT ts, kind, actor AS "from", target AS "to",'
                   " group_id, work_id, status, priority, size, mentions,"
                   " ref_id, sender_nickname, sender_role,"
                   " sender_custom_role, oversight, content_envelope"
                   " FROM audit_log")

    def list_audit(self, limit: int = 300) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                self._AUDIT_COLS + " ORDER BY seq DESC LIMIT ?",
                (limit,)).fetchall()
            return self._shape_audit_rows(rows)

    def list_content_audit(self) -> list[dict]:
        """EVERY content row in the audit log (CONTENT_AUDIT_KINDS),
        oldest first, NO limit (v1.3.2). This — never a windowed
        list_audit — is the source for conversation composition and
        the immortality census: a conversation exists because its
        rows exist, however old they are."""
        marks = ",".join("?" * len(CONTENT_AUDIT_KINDS))
        with self._lock:
            rows = self._db.execute(
                self._AUDIT_COLS + f" WHERE kind IN ({marks})"
                " ORDER BY seq ASC", CONTENT_AUDIT_KINDS).fetchall()
            return self._shape_audit_rows(rows)

    def count_online_since(self, username: str, ts: int) -> int:
        """How many times ``username`` has come online (audit kind
        'online', actor = the user — written by the relay's hello
        path via _log_activity("online", username)) with a row ts
        STRICTLY after ``ts``. The reconnect-truth probe behind
        delivery custody (v1.3.7): a client that reconnected since
        a frame was queued is distinguishable from one that never
        came back."""
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) AS n FROM audit_log"
                " WHERE kind = 'online' AND actor = ? AND ts > ?",
                (username, int(ts))).fetchone()
        return int(row["n"])

    # list_content_audit PLUS the row seq (the cursor column the
    # per-user catch-up pages on) — same columns, same shaping.
    _AUDIT_COLS_SEQ = ('SELECT seq, ts, kind, actor AS "from",'
                       ' target AS "to", group_id, work_id, status,'
                       " priority, size, mentions, ref_id,"
                       " sender_nickname, sender_role,"
                       " sender_custom_role, oversight, content_envelope"
                       " FROM audit_log")

    def content_audit_for_user(self, username: str, limit: int = 200,
                               before_seq: int | None = None
                               ) -> list[dict]:
        """The content rows (CONTENT_AUDIT_KINDS) where ``username``
        is a party: sender ("from"), recipient ("to"), a member of
        the row's group, or a member of the row's channel (channel
        frames carry the channel id in group_id — see the relay's
        channel_message audit write — so both id sets are matched
        against it, plus a channel_id key if a row ever carries
        one). Rows carry seq plus exactly the fields
        list_content_audit returns. With before_seq, only rows with
        seq < before_seq. Returns the NEWEST ``limit`` matching
        rows, presented oldest-first (seq ASC) — a catch-up page
        that walks backwards by feeding back the oldest seq seen."""
        group_ids = {g["group_id"]
                     for g in self.groups_for_user(username)}
        channel_ids = {c["channel_id"]
                       for c in self.channels_for_user(username)}
        marks = ",".join("?" * len(CONTENT_AUDIT_KINDS))
        sql = (self._AUDIT_COLS_SEQ + f" WHERE kind IN ({marks})")
        args: list = list(CONTENT_AUDIT_KINDS)
        if before_seq is not None:
            sql += " AND seq < ?"
            args.append(int(before_seq))
        sql += " ORDER BY seq ASC"
        with self._lock:
            rows = self._db.execute(sql, args).fetchall()
            shaped = self._shape_audit_rows(rows)
        scopes = group_ids | channel_ids
        matching = []
        for r in shaped:
            if r.get("from") == username or r.get("to") == username:
                matching.append(r)
            elif r.get("group_id") and r["group_id"] in scopes:
                matching.append(r)
            elif r.get("channel_id") and r["channel_id"] in channel_ids:
                matching.append(r)
        limit = int(limit)
        if limit <= 0:
            return []
        return matching[-limit:]

    def audit_rows_for_ids(self, ids) -> list[dict]:
        """Audit rows (any kind) whose ref_id OR work_id is in
        ``ids`` — the targeted fetch behind the dashboard's oversight
        fallback and library resolution, so neither ever needs to
        scan a bounded activity window again."""
        ids = [str(i) for i in (ids or []) if i]
        if not ids:
            return []
        out: list[dict] = []
        with self._lock:
            for i in range(0, len(ids), 400):
                chunk = ids[i:i + 400]
                marks = ",".join("?" * len(chunk))
                rows = self._db.execute(
                    self._AUDIT_COLS
                    + f" WHERE ref_id IN ({marks})"
                    f" OR work_id IN ({marks}) ORDER BY seq ASC",
                    chunk + chunk).fetchall()
                out.extend(self._shape_audit_rows(rows))
        return out

    def audit_for_work(self, work_id: str) -> list[dict]:
        """Every audit row recorded against one work id."""
        if not work_id:
            return []
        with self._lock:
            rows = self._db.execute(
                self._AUDIT_COLS + " WHERE work_id = ?"
                " ORDER BY seq ASC", (work_id,)).fetchall()
            return self._shape_audit_rows(rows)

    # -- read receipts (v1.1.2: WhatsApp-style Seen state) -------------------
    def message_meta(self, message_id: str) -> dict | None:
        """The audit row for one message id (the row's ref_id): kind,
        sender (actor), recipient (target), group/channel (group_id).
        Backs read-receipt validation — the relay derives the
        conversation from this row, never from the reader's claim."""
        if not message_id:
            return None
        with self._lock:
            row = self._db.execute(
                "SELECT kind, actor, target, group_id FROM audit_log"
                " WHERE ref_id = ? AND kind IN"
                " ('message', 'group_message', 'channel_message')"
                " ORDER BY seq ASC LIMIT 1", (message_id,)).fetchone()
        return dict(row) if row else None

    def record_read(self, message_id: str, reader: str,
                    read_at: int | None = None) -> int:
        """Record that `reader` read `message_id`. First read wins
        (Seen carries the FIRST time the message was taken in).
        Returns the stored read_at (the existing one when the reader
        had already read it)."""
        ts = int(read_at or now_ts())
        with self._lock:
            self._db.execute(
                "INSERT OR IGNORE INTO message_reads"
                " (message_id, reader, read_at) VALUES (?, ?, ?)",
                (message_id, reader, ts))
            self._db.commit()
            row = self._db.execute(
                "SELECT read_at FROM message_reads"
                " WHERE message_id = ? AND reader = ?",
                (message_id, reader)).fetchone()
        return int(row[0]) if row else ts

    def reads_for(self, message_ids) -> dict:
        """{message_id: [{"username": reader, "read_at": ts}, ...]}
        for the given ids, each list ordered by read_at. Ids with no
        reads are ABSENT from the result — a message nobody read
        carries no read state anywhere (honesty rule)."""
        ids = [str(i) for i in (message_ids or []) if i]
        if not ids:
            return {}
        out: dict[str, list] = {}
        with self._lock:
            for i in range(0, len(ids), 400):
                chunk = ids[i:i + 400]
                marks = ",".join("?" * len(chunk))
                rows = self._db.execute(
                    "SELECT message_id, reader, read_at FROM message_reads"
                    f" WHERE message_id IN ({marks})"
                    " ORDER BY read_at ASC", chunk).fetchall()
                for r in rows:
                    out.setdefault(r[0], []).append(
                        {"username": r[1], "read_at": int(r[2])})
        for v in out.values():
            v.sort(key=lambda x: x["read_at"])
        return out

    def set_audit_status(self, ref_id: str, status: str) -> None:
        """Delivery-state upgrade for a message audit row — e.g. a
        message that waited in the offline queue is 'sent' until the
        recipient's hello flush hands it over, then 'delivered'."""
        if not ref_id:
            return
        with self._lock:
            self._db.execute(
                "UPDATE audit_log SET status = ? WHERE ref_id = ?"
                " AND kind IN"
                " ('message', 'group_message', 'channel_message')",
                (status, ref_id))
            self._db.commit()

    def close(self) -> None:
        with self._lock:
            self._db.close()

    # -- users -----------------------------------------------------------
    def claim(self, username: str, display_name: str, pubkey: str = "",
              sign_pub: str = "", capabilities=None,
              cap_desc: str = "", mode: str = "autonomous",
              decision_link: str = "", delivery_ack: int = 0,
              designation: str = "production",
              recovery_hash: str = "") -> str:
        secret = new_secret()
        mode = mode if mode in ("manual", "autonomous") else "autonomous"
        designation = designation if designation in (
            "production", "test") else "production"
        decision_link = decision_link if decision_link in (
            "linked", "pending") else ""
        delivery_ack = 1 if delivery_ack else 0
        with self._lock:
            try:
                self._db.execute(
                    "INSERT INTO users (username, secret, display_name, pubkey,"
                    " sign_pub, capabilities, cap_desc, mode, decision_link,"
                    " delivery_ack, designation, recovery_hash, created_at)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    # Only the SHA-256 hash is stored — the relay DB never
                    # holds a usable secret.
                    (username, _hash_token(secret), display_name, pubkey,
                     sign_pub, json.dumps(capabilities or []), cap_desc,
                     mode, decision_link, delivery_ack, designation,
                     recovery_hash or "", now_ts()),
                )
                self._db.commit()
            except sqlite3.IntegrityError:
                raise UsernameTaken(username)
        return secret

    def pubkey_of(self, username: str) -> str:
        with self._lock:
            row = self._db.execute(
                "SELECT pubkey FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row["pubkey"] if row else ""

    def set_pubkey(self, username: str, pubkey: str) -> None:
        if not pubkey:
            return
        with self._lock:
            self._db.execute(
                "UPDATE users SET pubkey = ? WHERE username = ?",
                (pubkey, username))
            self._db.commit()

    def set_secret(self, username: str, secret: str) -> None:
        """Replace a user's owner-secret (v1.3.8). Only the SHA-256
        hash is stored, exactly as claim() stores it — the relay DB
        never holds a usable secret. This is the store-level half
        of registration-resume rotation: when a cut-off FIRST
        registration is resumed by its identity keys, the relay
        rotates the secret through here and the new secret rides
        the welcome, so the client persists it and the resume
        window closes behind the identity for good."""
        if not secret:
            return
        with self._lock:
            self._db.execute(
                "UPDATE users SET secret = ? WHERE username = ?",
                (_hash_token(secret), username))
            self._db.commit()

    # -- recovery keys (v1.7.0) -------------------------------------------
    # The recovery key is the agent's login-back credential: only
    # its SHA-256 hash ever lives here (exactly like the account
    # secret) — the plaintext is issued ONCE in a welcome and kept
    # by the agent. '' hash = not enrolled (every pre-1.7.0 row
    # until its first verified post-upgrade hello enrolls it).

    def recovery_hash_of(self, username: str) -> str:
        with self._lock:
            row = self._db.execute(
                "SELECT recovery_hash FROM users WHERE username = ?",
                (username,)
            ).fetchone()
        return str(row["recovery_hash"]) if row else ""

    def set_recovery_hash(self, username: str, key_hash: str,
                          used_at: int | None = None) -> None:
        """Store a recovery key's SHA-256 hash. With used_at (a
        recovery login just succeeded), the rotation stamps the
        use; without it (issuance/enrollment) the stamp is left
        alone."""
        if not key_hash:
            return
        with self._lock:
            if used_at is None:
                self._db.execute(
                    "UPDATE users SET recovery_hash = ?"
                    " WHERE username = ?",
                    (key_hash, username))
            else:
                self._db.execute(
                    "UPDATE users SET recovery_hash = ?,"
                    " recovery_used_at = ? WHERE username = ?",
                    (key_hash, int(used_at), username))
            self._db.commit()

    def touch(self, username: str) -> None:
        """Heartbeat-derived presence, backend-wide (point 29: 'dead'
        means no heartbeat ANYWHERE, on any relay sharing the backend)."""
        with self._lock:
            self._db.execute(
                "UPDATE users SET last_seen = ? WHERE username = ?",
                (now_ts(), username))
            self._db.commit()

    def last_seen_of(self, username: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT last_seen FROM users WHERE username = ?",
                (username,)).fetchone()
        return int(row["last_seen"]) if row else 0

    # -- connection registry (v1.3.4 presence truth) ---------------------
    # Presence USED to be read off the serving relay's local peer
    # table, so an agent connected to a BROTHER server read "offline"
    # on this server's dashboard while it was online and working —
    # the dashboard stated a local guess as a backend fact. The cure
    # is recorded fact: every hello (and every heartbeat cadence
    # thereafter) notes WHERE the agent is connected in the shared
    # store, so every dashboard on every server composes the same
    # backend-wide truth: online from the shared last_seen, and the
    # current server from the freshest connection note.

    def note_connection(self, username: str, server_id: str,
                        endpoint: str, home_endpoint: str) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO connections (username, server_id,"
                " endpoint, home_endpoint, updated_at)"
                " VALUES (?, ?, ?, ?, ?)"
                " ON CONFLICT(username) DO UPDATE SET"
                " server_id = excluded.server_id,"
                " endpoint = excluded.endpoint,"
                " home_endpoint = excluded.home_endpoint,"
                " updated_at = excluded.updated_at",
                (username, server_id or "", endpoint or "",
                 home_endpoint or "", now_ts()))
            self._db.commit()

    def connections_map(self) -> dict:
        """username -> its freshest connection note (the server it
        most recently said hello / heartbeat on, anywhere in the
        backend). Callers apply the presence grace to updated_at."""
        with self._lock:
            rows = self._db.execute(
                "SELECT username, server_id, endpoint, home_endpoint,"
                " updated_at FROM connections").fetchall()
        return {r["username"]: dict(r) for r in rows}

    # -- voice-room live state (v1.3.9, shared backend) -----------------
    # Room state USED to live in each relay's own memory: a room
    # opened on one server was unjoinable from another (join refused
    # unknown_room, proven live 2026-11-03) and a room whose creator
    # died unclosed haunted the dashboard as a ghost. The v1.3.4
    # presence cure applies: the room record is a fact in the SHARED
    # store — every relay reads/writes the same rooms — and frames
    # for a participant connected to a brother relay ride a
    # store-mediated path (room_frames) that each relay drains for
    # its local peers on its scan tick, the same pattern as the
    # cross-relay queue drain. Room rows are never deleted: a closed
    # room stays as history (closed=1), only live composition reads
    # closed=0. Participants are stored as a JSON list; membership
    # changes are read-modify-write under the store lock, the same
    # discipline as the queue's claim operations.

    @staticmethod
    def _shape_room(row) -> dict | None:
        if row is None:
            return None
        r = dict(row)
        try:
            parts = json.loads(r.get("participants") or "[]")
        except Exception:
            parts = []
        return {"room_id": r["room_id"],
                "group_id": r.get("group_id") or "",
                "creator": r.get("creator") or "",
                "participants": [str(p) for p in parts],
                "opened_at": int(r.get("opened_at") or 0),
                "updated_at": int(r.get("updated_at") or 0),
                "closed": bool(r.get("closed"))}

    def room_create(self, room_id: str, group_id: str,
                    creator: str) -> dict:
        """Open a room record with the creator as first participant."""
        now = now_ts()
        with self._lock:
            self._db.execute(
                "INSERT INTO rooms (room_id, group_id, creator,"
                " participants, opened_at, updated_at, closed)"
                " VALUES (?, ?, ?, ?, ?, ?, 0)",
                (room_id, group_id or "", creator,
                 json.dumps([creator]), now, now))
            self._db.commit()
            row = self._db.execute(
                "SELECT * FROM rooms WHERE room_id = ?",
                (room_id,)).fetchone()
        return self._shape_room(row)

    def room_get(self, room_id: str) -> dict | None:
        """The LIVE room record, or None when the room does not
        exist or is closed — closed is terminal for every room
        operation, exactly as a relay-local room dict vanishing was."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM rooms WHERE room_id = ? AND closed = 0",
                (room_id,)).fetchone()
        return self._shape_room(row)

    def rooms_open(self) -> list[dict]:
        """Every live (not closed) room in the backend, oldest first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM rooms WHERE closed = 0"
                " ORDER BY opened_at ASC").fetchall()
        return [self._shape_room(r) for r in rows]

    def room_add_participant(self, room_id: str,
                             username: str) -> dict | None:
        """Join: returns the updated live room, or None when the
        room is unknown/closed."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM rooms WHERE room_id = ? AND closed = 0",
                (room_id,)).fetchone()
            room = self._shape_room(row)
            if room is None:
                return None
            if username not in room["participants"]:
                room["participants"].append(username)
                self._db.execute(
                    "UPDATE rooms SET participants = ?, updated_at = ?"
                    " WHERE room_id = ?",
                    (json.dumps(room["participants"]), now_ts(), room_id))
                self._db.commit()
            return room

    def room_remove_participant(self, room_id: str,
                                username: str) -> dict | None:
        """Leave (or a connection's death, via the hosting relay):
        returns the updated room, or None when the room is
        unknown/closed. A room whose last participant leaves is
        CLOSED in the same write — an empty room is not a live room."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM rooms WHERE room_id = ? AND closed = 0",
                (room_id,)).fetchone()
            room = self._shape_room(row)
            if room is None:
                return None
            if username in room["participants"]:
                room["participants"] = [
                    p for p in room["participants"] if p != username]
                closed = 0 if room["participants"] else 1
                room["closed"] = bool(closed)
                self._db.execute(
                    "UPDATE rooms SET participants = ?, updated_at = ?,"
                    " closed = ? WHERE room_id = ?",
                    (json.dumps(room["participants"]), now_ts(),
                     closed, room_id))
                self._db.commit()
            return room

    def room_close(self, room_id: str) -> dict | None:
        """Close a room outright (creator / group admin). Returns
        the room as it stood, or None when unknown/already closed."""
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM rooms WHERE room_id = ? AND closed = 0",
                (room_id,)).fetchone()
            room = self._shape_room(row)
            if room is None:
                return None
            self._db.execute(
                "UPDATE rooms SET closed = 1, updated_at = ?"
                " WHERE room_id = ?", (now_ts(), room_id))
            self._db.commit()
            room["closed"] = True
            return room

    def rooms_of_participant(self, username: str) -> list[dict]:
        """Every live room this username is currently a participant
        of — the disconnect reaper's work list."""
        return [r for r in self.rooms_open()
                if username in r["participants"]]

    # -- store-mediated room frames (v1.3.9) ----------------------------
    # A room_signal / room_event for a participant connected to a
    # BROTHER relay cannot ride that relay's socket; it rides here.
    # Each relay drains frames for its own local peers on its scan
    # tick (claim = select + delete, the queue's discipline) and
    # writes them to the socket. Signalling is perishable: a frame
    # older than ROOM_FRAME_TTL_SECONDS at drain time is dropped,
    # never delivered late — a stale ICE candidate or a superseded
    # offer must not surface on a fresh connection.

    def room_frame_put(self, to_username: str, frame: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO room_frames (to_username, frame, ts)"
                " VALUES (?, ?, ?)",
                (to_username, json.dumps(frame), now_ts()))
            self._db.commit()

    def room_frames_drain(self, usernames,
                          max_age: int = 120) -> dict:
        """Claim every pending room frame for the given usernames:
        returns {username: [frame, ...]} in insertion order. Stale
        frames (older than max_age) are deleted WITHOUT delivery.
        The claim is atomic under the store lock, so two relays
        racing the same username can never deliver the same frame
        twice."""
        wanted = [u for u in (usernames or []) if u]
        if not wanted:
            return {}
        now = now_ts()
        marks = ",".join("?" * len(wanted))
        out: dict[str, list] = {}
        with self._lock:
            rows = self._db.execute(
                f"SELECT seq, to_username, frame, ts FROM room_frames"
                f" WHERE to_username IN ({marks}) ORDER BY seq ASC",
                wanted).fetchall()
            if rows:
                seqs = [r["seq"] for r in rows]
                smarks = ",".join("?" * len(seqs))
                self._db.execute(
                    f"DELETE FROM room_frames WHERE seq IN ({smarks})",
                    seqs)
                self._db.commit()
        for r in rows:
            if now - int(r["ts"] or 0) > max_age:
                continue  # stale signalling: claimed and dropped
            try:
                frame = json.loads(r["frame"])
            except Exception:
                continue
            frame["queued"] = True
            out.setdefault(r["to_username"], []).append(frame)
        return out

    def list_room_audit(self) -> list[dict]:
        """EVERY voice-room lifecycle row, oldest first, no limit —
        the shared-store source for the dashboard's Voice Rooms
        view (parity with list_content_audit's no-window rule)."""
        marks = ",".join("?" * len(ROOM_AUDIT_KINDS))
        with self._lock:
            rows = self._db.execute(
                self._AUDIT_COLS + f" WHERE kind IN ({marks})"
                " ORDER BY seq ASC", ROOM_AUDIT_KINDS).fetchall()
            return self._shape_audit_rows(rows)

    def dashboard_digest(self) -> str:
        """A cheap change signal over the backend facts the
        dashboard renders: the newest presence beat, the connection
        registry's shape, the server registry's newest heartbeat and
        the audit tail. The dashboard's push loop compares it once a
        second; a change means SOMETHING happened on SOME server, so
        the open page rebuilds and pushes — real-time reflection of
        backend-wide state, not just of the serving relay's own
        events."""
        with self._lock:
            row = self._db.execute(
                "SELECT"
                " (SELECT COALESCE(MAX(last_seen), 0) FROM users),"
                " (SELECT COUNT(*) FROM connections),"
                " (SELECT COALESCE(MAX(updated_at), 0)"
                "   FROM connections),"
                " (SELECT COALESCE(MAX(last_seen), 0) FROM servers),"
                " (SELECT COALESCE(MAX(seq), 0) FROM audit_log),"
                " (SELECT COALESCE(MAX(updated_at), 0) FROM rooms),"
                " (SELECT COALESCE(MAX(seq), 0) FROM room_frames)"
            ).fetchone()
        return "|".join(str(int(v or 0)) for v in row)

    # -- server registry (v1.2.0 peer mesh) --------------------------------
    # Every relay registers ITSELF in the shared backend on boot and
    # heartbeats the row; clients discover the live mesh from any
    # relay (welcome payload / 'servers' request) and race home +
    # every live peer. The registry is how "another agent's server"
    # becomes a real, findable thing instead of a configured guess.

    # -- server registry (v1.2.0 peer mesh; v1.3.0 carrying) -------------
    # Every relay registers ITSELF in the shared backend on boot and
    # heartbeats the row; clients discover the live mesh from any
    # relay (welcome payload / 'servers' request) and race home +
    # every live peer. The registry is how "another agent's server"
    # becomes a real, findable thing instead of a configured guess.
    #
    # v1.3.0: a server's identity is its server_id — STABLE across
    # endpoint changes. A per-agent server (owner_agent set) keeps
    # its permanent home endpoint in home_endpoint; while a brother
    # carries it, `endpoint` points at the carrier's alias for it,
    # carried_by names the temporary helper, and a lease
    # (carry_lease_token/until) makes the claim single-winner.
    # Ownership NEVER moves: owner_agent is permanent.

    def register_server(self, label: str, endpoint: str,
                        host_agent: str = "", version: str = "",
                        health: int = -1, riders: int = 0,
                        capacity: int = 10, server_id: str = "",
                        owner_agent: str = "", home_host: str = "",
                        home_endpoint: str = "",
                        can_carry: bool = True) -> None:
        from .timing import (CARRY_HANDBACK_SECONDS,
                             SERVER_STALE_SECONDS)
        now = now_ts()
        sid = server_id or endpoint
        home_ep = home_endpoint or (endpoint if owner_agent else "")
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM servers WHERE server_id = ?",
                (sid,)).fetchone()
            if row is None:
                self._db.execute(
                    "INSERT INTO servers (endpoint, label, host_agent,"
                    " version, health, riders, capacity, last_seen,"
                    " first_seen, server_id, owner_agent, home_host,"
                    " home_endpoint, home_last_seen,"
                    " home_healthy_since, home_health, home_riders,"
                    " home_capacity, carry_state, can_carry)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                    " ?, ?, ?, ?, ?, ?, ?)",
                    (endpoint, label, host_agent, version,
                     int(health), int(riders), int(capacity), now, now,
                     sid, owner_agent, home_host or host_agent,
                     home_ep, now if owner_agent else 0,
                     now if owner_agent else 0,
                     int(health) if owner_agent else -1,
                     int(riders) if owner_agent else 0,
                     int(capacity) if owner_agent else 0,
                     "home" if owner_agent else "",
                     1 if can_carry else 0))
                self._db.commit()
                return
            row = dict(row)
            if owner_agent:
                # This call is the HOME instance heartbeating. Its
                # home stats always update; the CURRENT serving
                # fields belong to whoever serves the server now.
                prev_home = int(row.get("home_last_seen") or 0)
                if prev_home and now - prev_home <= \
                        SERVER_STALE_SECONDS:
                    healthy_since = int(
                        row.get("home_healthy_since") or now)
                else:
                    healthy_since = now
                state = row.get("carry_state") or "home"
                lease_until = int(row.get("carry_lease_until") or 0)
                if state == "carried" and lease_until > now:
                    # A brother is carrying this server: record the
                    # home heartbeat ONLY — never steal the serving
                    # row back from under the carrier.
                    self._db.execute(
                        "UPDATE servers SET home_last_seen = ?,"
                        " home_healthy_since = ?, home_health = ?,"
                        " home_riders = ?, home_capacity = ?,"
                        " version = ?, can_carry = ?"
                        " WHERE server_id = ?",
                        (now, healthy_since, int(health),
                         int(riders), int(capacity), version,
                         1 if can_carry else 0, sid))
                    self._db.commit()
                    return
                if state == "carried" and lease_until <= now and \
                        now - healthy_since < CARRY_HANDBACK_SECONDS:
                    # The carrier is gone (lease expired) but home
                    # has not yet proven itself strongly: stay
                    # 'carried' on paper until the handback window
                    # completes — nobody serves a half-returned home.
                    self._db.execute(
                        "UPDATE servers SET home_last_seen = ?,"
                        " home_healthy_since = ?, home_health = ?,"
                        " home_riders = ?, home_capacity = ?,"
                        " version = ?, can_carry = ?"
                        " WHERE server_id = ?",
                        (now, healthy_since, int(health),
                         int(riders), int(capacity), version,
                         1 if can_carry else 0, sid))
                    self._db.commit()
                    return
                # At home (or reclaiming after the handback window):
                # the home instance IS the serving instance.
                self._db.execute(
                    "UPDATE servers SET endpoint = ?, label = ?,"
                    " host_agent = ?, version = ?, health = ?,"
                    " riders = ?, capacity = ?, last_seen = ?,"
                    " home_host = ?, home_endpoint = ?,"
                    " home_last_seen = ?, home_healthy_since = ?,"
                    " home_health = ?, home_riders = ?,"
                    " home_capacity = ?, carry_state = 'home',"
                    " carried_by = '', carried_by_id = '',"
                    " carry_endpoint = '', carry_lease_token = '',"
                    " carry_lease_until = 0, carry_claimed_at = 0,"
                    " can_carry = ? WHERE server_id = ?",
                    (home_ep, label, host_agent, version,
                     int(health), int(riders), int(capacity), now,
                     home_host or host_agent, home_ep, now,
                     healthy_since, int(health), int(riders),
                     int(capacity), 1 if can_carry else 0, sid))
                self._db.commit()
                return
            self._db.execute(
                "UPDATE servers SET endpoint = ?, label = ?,"
                " host_agent = ?, version = ?, health = ?,"
                " riders = ?, capacity = ?, last_seen = ?,"
                " can_carry = ? WHERE server_id = ?",
                (endpoint, label, host_agent, version, int(health),
                 int(riders), int(capacity), now,
                 1 if can_carry else 0, sid))
            self._db.commit()

    def list_servers(self, stale_after: int | None = None) -> list[dict]:
        """Live servers only: registry rows whose heartbeat is fresh
        (timing.SERVER_STALE_SECONDS unless overridden). A dead
        relay's row ages out and is never offered as a peer."""
        from .timing import SERVER_STALE_SECONDS
        if stale_after is None:
            stale_after = SERVER_STALE_SECONDS
        cutoff = now_ts() - int(stale_after)
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM servers WHERE last_seen >= ?"
                " ORDER BY endpoint", (cutoff,)).fetchall()
        return [dict(r) for r in rows]

    def list_agent_servers(self) -> list[dict]:
        """ALL per-agent servers (owner_agent set), fresh or not —
        the carrier watch list and the dashboard's honest state
        view. Oldest home heartbeat first, so the longest-down
        server is claimed first."""
        with self._lock:
            rows = self._db.execute(
                "SELECT * FROM servers WHERE owner_agent <> ''"
                " ORDER BY home_last_seen, server_id").fetchall()
        return [dict(r) for r in rows]

    def get_server(self, server_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM servers WHERE server_id = ?",
                (server_id,)).fetchone()
        return dict(row) if row else None

    def claim_carry(self, server_id: str, *, carrier_id: str,
                    carrier_agent: str, endpoint: str,
                    carrier_health: int, carrier_capacity: int,
                    carrier_riders: int = 0,
                    carrier_can_carry: bool = True,
                    carrier_carrying: int = 0,
                    now: int | None = None,
                    lease_seconds: int = 45,
                    stale_after: int = 20,
                    home_probe_failed: bool = False) -> dict | None:
        """Claim the carry of a DOWN per-agent server — single
        winner. The claim lands only if, atomically at write time:
        the target's home heartbeat is stale, no live lease stands,
        and the lease token still equals the one read (optimistic
        concurrency: a racing brother's landed claim changes the
        token and this write matches zero rows). The claimant must
        also be the best eligible carrier (carry_claim_blocked)."""
        if now is None:
            now = now_ts()
        if carrier_id == server_id:
            return None  # a server never carries itself
        with self._lock:
            rows = [dict(r) for r in self._db.execute(
                "SELECT * FROM servers").fetchall()]
            target = next((r for r in rows
                           if r.get("server_id") == server_id), None)
            if target is None or not target.get("owner_agent"):
                return None
            if not home_probe_failed and \
                    now - int(target.get("home_last_seen") or 0) \
                    <= stale_after:
                return None  # home is still answering
            if target.get("carry_state") == "carried" and \
                    int(target.get("carry_lease_until") or 0) > now:
                return None  # a brother already carries it
            if carry_claim_blocked(
                    rows, claimant_id=carrier_id,
                    claimant_health=carrier_health,
                    claimant_capacity=carrier_capacity,
                    claimant_riders=carrier_riders,
                    claimant_can_carry=carrier_can_carry,
                    claimant_carrying=carrier_carrying,
                    now=now, stale_after=stale_after):
                return None
            token = secrets.token_hex(16)
            cur = self._db.execute(
                "UPDATE servers SET endpoint = ?, host_agent = ?,"
                " health = ?, riders = 0, capacity = ?,"
                " last_seen = ?, carry_state = 'carried',"
                " carried_by = ?, carried_by_id = ?,"
                " carry_endpoint = ?, carry_lease_token = ?,"
                " carry_lease_until = ?, carry_claimed_at = ?"
                " WHERE server_id = ? AND carry_lease_token = ?"
                " AND carry_lease_until = ?",
                (endpoint, carrier_agent, int(carrier_health),
                 int(carrier_capacity), now, carrier_agent,
                 carrier_id, endpoint, token, now + lease_seconds,
                 now, server_id,
                 str(target.get("carry_lease_token") or ""),
                 int(target.get("carry_lease_until") or 0)))
            self._db.commit()
            if cur.rowcount != 1:
                return None
            row = self._db.execute(
                "SELECT * FROM servers WHERE server_id = ?",
                (server_id,)).fetchone()
        return dict(row) if row else None

    def renew_carry(self, server_id: str, *, carrier_id: str,
                    token: str, carrier_agent: str, endpoint: str,
                    health: int, riders: int, capacity: int,
                    now: int | None = None,
                    lease_seconds: int = 45) -> bool:
        """Extend a held lease and refresh the carried row's live
        stats. Matches on the lease token: a carrier that lost the
        lease (handback, expiry + re-claim) renews nothing."""
        if now is None:
            now = now_ts()
        with self._lock:
            cur = self._db.execute(
                "UPDATE servers SET endpoint = ?, host_agent = ?,"
                " health = ?, riders = ?, capacity = ?,"
                " last_seen = ?, carry_lease_until = ?"
                " WHERE server_id = ? AND carry_state = 'carried'"
                " AND carried_by_id = ? AND carry_lease_token = ?",
                (endpoint, carrier_agent, int(health), int(riders),
                 int(capacity), now, now + lease_seconds, server_id,
                 carrier_id, token))
            self._db.commit()
        return cur.rowcount == 1

    def release_carry(self, server_id: str, *, carrier_id: str,
                      token: str, now: int | None = None) -> bool:
        """Release a held lease: the row flips back to its home
        endpoint with the home instance's last known stats and
        state 'down' — the home instance's next heartbeat (it is
        heartbeating throughout a handback) flips it to 'home'.
        Until then the row is honestly not-serving."""
        if now is None:
            now = now_ts()
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM servers WHERE server_id = ?",
                (server_id,)).fetchone()
            if row is None:
                return False
            row = dict(row)
            cur = self._db.execute(
                "UPDATE servers SET endpoint = home_endpoint,"
                " host_agent = home_host, health = home_health,"
                " riders = home_riders, capacity = home_capacity,"
                " last_seen = home_last_seen,"
                " carry_state = 'down', carried_by = '',"
                " carried_by_id = '', carry_endpoint = '',"
                " carry_lease_token = '', carry_lease_until = 0,"
                " carry_claimed_at = 0 WHERE server_id = ?"
                " AND carry_state = 'carried'"
                " AND carried_by_id = ? AND carry_lease_token = ?",
                (server_id, carrier_id, token))
            self._db.commit()
        return cur.rowcount == 1

    def set_capabilities(self, username: str, capabilities,
                         cap_desc: str = "") -> None:
        with self._lock:
            self._db.execute(
                "UPDATE users SET capabilities = ?, cap_desc = ?"
                " WHERE username = ?",
                (json.dumps(capabilities or []), cap_desc, username))
            self._db.commit()

    def set_mode(self, username: str, mode: str) -> None:
        """Persist the agent's platform mode (autonomy law, v1.1.7).
        Recorded from the agent's own hello — an agent declares its
        mode; the relay never assigns one. Unknown values are
        refused so a profile can never drift out of the two lawful
        states."""
        if mode not in ("manual", "autonomous"):
            return
        with self._lock:
            self._db.execute(
                "UPDATE users SET mode = ? WHERE username = ?",
                (mode, username))
            self._db.commit()

    def set_designation(self, username: str, designation: str,
                        actor: str = "operator") -> bool:
        """OPERATOR-ONLY designation change (v1.6.0). The one door
        through which a registered agent's production/test
        designation may change after registration — the relay never
        calls this from a hello (an agent's own designation
        declaration is honoured only by claim(), at registration),
        so an agent can never flip itself out of (or into) the
        test segregation. Every executed change is written to the
        append-only audit log as kind 'designation_changed'.
        Returns True when the stored value actually changed."""
        if designation not in ("production", "test"):
            return False
        with self._lock:
            row = self._db.execute(
                "SELECT designation FROM users WHERE username = ?",
                (username,)).fetchone()
            if row is None:
                return False
            current = row[0] if row[0] in (
                "production", "test") else "production"
            if current == designation:
                return False
            self._db.execute(
                "UPDATE users SET designation = ? WHERE username = ?",
                (designation, username))
            self._db.commit()
        self.audit("designation_changed", actor, target=username,
                   status=designation)
        return True

    def designation_of(self, username: str) -> str:
        """The stored designation, presented by the standing rule:
        anything not explicitly 'test' is production."""
        with self._lock:
            row = self._db.execute(
                "SELECT designation FROM users WHERE username = ?",
                (username,)).fetchone()
        if row is None:
            return "production"
        return "test" if row[0] == "test" else "production"

    def set_decision_link(self, username: str, state: str) -> None:
        """Persist the agent's declared decision-link state
        (v1.3.5). Recorded from the agent's own hello — the agent
        declares whether its connection is linked to its own
        decision-making; the relay never assigns one. Unknown
        values are refused so a profile can never drift out of the
        lawful states ('linked' / 'pending')."""
        if state not in ("linked", "pending"):
            return
        with self._lock:
            self._db.execute(
                "UPDATE users SET decision_link = ? WHERE username = ?",
                (state, username))
            self._db.commit()

    def set_decision_link_detail(self, username: str,
                                 detail: dict) -> None:
        """Persist the auto-link DETAIL (v1.8.0): how the client
        wired itself and whether its self-check verified the
        path — {"mode", "verified", "checked_at"}. Normalised
        here so no store can carry a mode outside the lawful set;
        the relay only ever records what the agent declared."""
        if not isinstance(detail, dict):
            return
        mode = detail.get("mode")
        if mode not in ("config", "in_process", "handlers",
                        "convention", "none"):
            return
        clean = {"mode": mode,
                 "verified": bool(detail.get("verified")),
                 "checked_at": int(detail.get("checked_at") or 0)}
        with self._lock:
            self._db.execute(
                "UPDATE users SET decision_link_detail = ?"
                " WHERE username = ?",
                (json.dumps(clean), username))
            self._db.commit()

    # -- one-time admin grant (v1.8.0) --------------------------------
    # The grant record, its append-only signed receipts, and its
    # approval queue. Receipts have NO update or delete path —
    # append-only is structural, and every receipt is signed with
    # the platform receipt key (grant_meta) and chained to the
    # previous receipt's hash at insert time, under the store
    # lock, so the chain can never fork inside one store.

    def grant_of(self, username: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM grants WHERE username = ?",
                (username,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        try:
            d["scopes"] = json.loads(d.get("scopes") or "[]")
        except Exception:
            d["scopes"] = []
        return d

    def record_grant_request(self, username: str, request_id: str,
                             reason: str = "") -> dict | None:
        """Record the AGENT-initiated permission request (v1.8.1):
        the agent asked its owner for the one-time permission;
        the request now awaits the owner's allow, agent-side.
        There is deliberately NO store method that creates an
        active grant — activation exists only as
        ``activate_grant`` acting on a recorded request, driven
        by the relay's verified signed-statement path. An agent
        with an ACTIVE grant keeps it (a new request changes
        nothing); a revoked or absent grant may be re-requested
        (the owner's one-time permission, asked again)."""
        ts = now_ts()
        with self._lock:
            row = self._db.execute(
                "SELECT status FROM grants WHERE username = ?",
                (username,)).fetchone()
            if row is not None and row["status"] == "active":
                return self.grant_of(username)
            self._db.execute(
                "INSERT INTO grants (username, scopes, granted_by,"
                " granted_at, status, bound_sign_pub, updated_at,"
                " request_id, requested_at, request_reason)"
                " VALUES (?, '[]', '', 0, 'requested', '', ?,"
                " ?, ?, ?)"
                " ON CONFLICT(username) DO UPDATE SET"
                " status = 'requested',"
                " request_id = excluded.request_id,"
                " requested_at = excluded.requested_at,"
                " request_reason = excluded.request_reason,"
                " updated_at = excluded.updated_at",
                (username, ts, request_id, ts, reason))
            self._db.commit()
        self.audit("grant_requested", username, target=username,
                   status=f"request {request_id} awaits the "
                          f"agent's owner")
        return self.grant_of(username)

    def activate_grant(self, username: str, grantor: str,
                       bound_sign_pub: str, request_id: str,
                       ceremony_at: int) -> dict | None:
        """The owner's ALLOW, recorded (v1.8.1): activates the
        grant ONLY from a recorded REQUESTED state whose request
        id matches the signed statement — an allow with no
        pending request behind it lands NOWHERE. The grantor
        attestation (WHO allowed it: the agent's own owner) and
        the ceremony timestamp are part of the record. The grant
        covers the agent's whole connector inventory (scopes
        stay [] — coverage is inventory-wide by design), bound
        to the identity key the signed statement verified
        against. Called ONLY from the relay's verified
        grant-allow path."""
        ts = now_ts()
        with self._lock:
            cur = self._db.execute(
                "UPDATE grants SET status = 'active', scopes = '[]',"
                " granted_by = ?, grantor = ?, granted_at = ?,"
                " ceremony_at = ?, bound_sign_pub = ?,"
                " updated_at = ? WHERE username = ?"
                " AND status = 'requested' AND request_id = ?",
                (grantor, grantor, ts, int(ceremony_at or ts),
                 bound_sign_pub, ts, username, request_id))
            self._db.commit()
        if not cur.rowcount:
            return None
        self.audit("grant_allowed", "agent-owner",
                   target=username,
                   status=f"grantor={grantor} "
                          f"request={request_id}")
        return self.grant_of(username)

    def revoke_grant(self, username: str, by: str = "") -> bool:
        """The kill switch: effective immediately — the broker
        re-reads the grant on every action. In the corrected
        model this is driven ONLY by the agent-side signed
        revoke statement (the agent's owner's act); the store
        method itself stays actor-agnostic and audit-logged."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE grants SET status = 'revoked',"
                " updated_at = ? WHERE username = ?"
                " AND status = 'active'",
                (now_ts(), username))
            self._db.commit()
        if cur.rowcount:
            self.audit("grant_revoked", by or "agent-owner",
                       target=username)
        return bool(cur.rowcount)

    def rebind_grants(self, username: str,
                      new_sign_pub: str) -> int:
        """Recovery rebind (v1.8.0): a v1.7.0 recovery login has
        already proven possession of the account (the recovery
        key), so an ACTIVE grant follows the identity to its new
        keys. Called ONLY from the relay's verified recovery
        path — nothing else may move a grant's binding."""
        with self._lock:
            cur = self._db.execute(
                "UPDATE grants SET bound_sign_pub = ?,"
                " updated_at = ? WHERE username = ?"
                " AND status = 'active'"
                " AND bound_sign_pub != ?",
                (new_sign_pub, now_ts(), username, new_sign_pub))
            self._db.commit()
        if cur.rowcount:
            self.audit("grant_rebound", "relay", target=username,
                       status="identity rebound by recovery login")
        return cur.rowcount

    # -- the connector vault (v1.8.1) ------------------------------
    # The agent's declared inventory of OAuth-linked connectors,
    # stored per agent. Declarations arrive only over the agent's
    # own authenticated connection (hello / signed
    # connector_update) and are validated before they reach here
    # (connectors.validate_inventory): the store keeps exactly
    # what was lawfully declared. The broker gates on this; the
    # dashboard renders linkage from this.

    def set_connector_inventory(self, username: str,
                                inventory: list) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO agent_connectors (username, inventory,"
                " updated_at) VALUES (?, ?, ?)"
                " ON CONFLICT(username) DO UPDATE SET"
                " inventory = excluded.inventory,"
                " updated_at = excluded.updated_at",
                (username, json.dumps(list(inventory or [])),
                 now_ts()))
            self._db.commit()

    def connector_inventory_of(self, username: str) -> list:
        with self._lock:
            row = self._db.execute(
                "SELECT inventory FROM agent_connectors"
                " WHERE username = ?", (username,)).fetchone()
        if row is None:
            return []
        try:
            inv = json.loads(row["inventory"] or "[]")
        except Exception:
            return []
        return inv if isinstance(inv, list) else []

    def all_connector_inventories(self) -> dict:
        with self._lock:
            rows = self._db.execute(
                "SELECT username, inventory FROM agent_connectors"
            ).fetchall()
        out = {}
        for r in rows:
            try:
                inv = json.loads(r["inventory"] or "[]")
            except Exception:
                inv = []
            out[r["username"]] = inv if isinstance(inv, list) else []
        return out

    def _grant_keypair_nolock(self) -> tuple[str, str]:
        """(seed_b64, pub_b64) of the receipt keypair, minting it
        on first use. CALLER MUST HOLD the store lock — the public
        accessor and add_receipt both funnel here so the lock is
        never taken twice (the store lock is not re-entrant)."""
        row = self._db.execute(
            "SELECT value FROM grant_meta WHERE key = ?",
            ("receipt_signing_key",)).fetchone()
        if row is not None:
            seed_b64, pub_b64 = row["value"].split(":", 1)
            return seed_b64, pub_b64
        from cryptography.hazmat.primitives.asymmetric.ed25519 \
            import Ed25519PrivateKey
        from cryptography.hazmat.primitives import \
            serialization
        import base64 as _b64
        key = Ed25519PrivateKey.generate()
        seed = key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption())
        pub = key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw)
        seed_b64 = _b64.b64encode(seed).decode()
        pub_b64 = _b64.b64encode(pub).decode()
        self._db.execute(
            "INSERT INTO grant_meta (key, value) VALUES (?, ?)",
            ("receipt_signing_key", f"{seed_b64}:{pub_b64}"))
        self._db.commit()
        return seed_b64, pub_b64

    def grant_receipt_pubkey(self) -> str:
        """The platform receipt public key (base64), minting the
        keypair on first use. The private seed lives ONLY in
        grant_meta inside the relay's own store — the same trust
        domain as the store file itself (0600, operator-only)."""
        with self._lock:
            return self._grant_keypair_nolock()[1]

    def _receipt_sign_nolock(self, canonical: bytes) -> str:
        """Sign with the receipt key. CALLER MUST HOLD the store
        lock (see _grant_keypair_nolock)."""
        import base64 as _b64
        from cryptography.hazmat.primitives.asymmetric.ed25519 \
            import Ed25519PrivateKey
        seed_b64, _pub = self._grant_keypair_nolock()
        key = Ed25519PrivateKey.from_private_bytes(
            _b64.b64decode(seed_b64))
        return _b64.b64encode(key.sign(canonical)).decode()

    def add_receipt(self, rec: dict) -> dict:
        """Append ONE grant receipt: id + timestamp assigned
        here, chained to the previous receipt's hash, signed.
        There is deliberately no update/delete counterpart."""
        from .grants import receipt_canonical, receipt_hash
        rec = dict(rec)
        rec.setdefault("id", new_id("rcpt-"))
        rec.setdefault("ts", now_ts())
        for k in ("scope", "connector", "action", "target",
                  "work_ref", "status"):
            rec[k] = str(rec.get(k) or "")
        if not isinstance(rec.get("detail"), dict):
            rec["detail"] = {}
        with self._lock:
            prev = self._db.execute(
                "SELECT id, username, ts, scope, connector, action,"
                " target, work_ref, status, detail, prev_hash, sig"
                " FROM grant_receipts ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            if prev is not None:
                pd = dict(prev)
                try:
                    pd["detail"] = json.loads(pd.get("detail")
                                              or "{}")
                except Exception:
                    pd["detail"] = {}
                rec["prev_hash"] = receipt_hash(pd)
            else:
                rec["prev_hash"] = ""
            rec["sig"] = self._receipt_sign_nolock(
                receipt_canonical(rec))
            self._db.execute(
                "INSERT INTO grant_receipts (id, username, ts,"
                " scope, connector, action, target, work_ref,"
                " status, detail, prev_hash, sig)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (rec["id"], rec["username"], rec["ts"],
                 rec["scope"], rec["connector"], rec["action"],
                 rec["target"], rec["work_ref"], rec["status"],
                 json.dumps(rec["detail"]), rec["prev_hash"],
                 rec["sig"]))
            self._db.commit()
        return rec

    def list_receipts(self, username: str | None = None,
                      since: int = 0, until: int | None = None,
                      limit: int = 300) -> list[dict]:
        q = ("SELECT * FROM grant_receipts WHERE ts >= ?")
        args: list = [int(since)]
        if username:
            q += " AND username = ?"
            args.append(username)
        if until is not None:
            q += " AND ts <= ?"
            args.append(int(until))
        q += " ORDER BY seq ASC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d.pop("seq", None)
            try:
                d["detail"] = json.loads(d.get("detail") or "{}")
            except Exception:
                d["detail"] = {}
            out.append(d)
        return out

    def receipt_count(self, username: str, scope: str,
                      since: int, status: str = "executed") -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) AS n FROM grant_receipts"
                " WHERE username = ? AND scope = ? AND ts >= ?"
                " AND status = ?",
                (username, scope, int(since), status)).fetchone()
        return int(row["n"])

    def add_approval(self, ap: dict) -> dict:
        ap = dict(ap)
        ap.setdefault("id", new_id("gappr-"))
        ap.setdefault("ts", now_ts())
        ap.setdefault("status", "awaiting_approval")
        with self._lock:
            self._db.execute(
                "INSERT INTO grant_approvals (id, username, ts,"
                " scope, connector, action, target, params,"
                " work_ref, reason, status) VALUES"
                " (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (ap["id"], ap["username"], ap["ts"],
                 str(ap.get("scope") or ""),
                 str(ap.get("connector") or ""),
                 str(ap.get("action") or ""),
                 str(ap.get("target") or ""),
                 json.dumps(ap.get("params") or {}),
                 str(ap.get("work_ref") or ""),
                 str(ap.get("reason") or ""), ap["status"]))
            self._db.commit()
        self.audit("grant_approval_queued", ap["username"],
                   status=str(ap.get("reason") or ""),
                   ref_id=ap["id"])
        return self.get_approval(ap["id"])

    def get_approval(self, approval_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM grant_approvals WHERE id = ?",
                (approval_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        try:
            d["params"] = json.loads(d.get("params") or "{}")
        except Exception:
            d["params"] = {}
        return d

    def list_approvals(self, status: str | None = None,
                       username: str | None = None,
                       limit: int = 100) -> list[dict]:
        q = "SELECT * FROM grant_approvals WHERE 1 = 1"
        args: list = []
        if status:
            q += " AND status = ?"
            args.append(status)
        if username:
            q += " AND username = ?"
            args.append(username)
        q += " ORDER BY ts DESC LIMIT ?"
        args.append(int(limit))
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            try:
                d["params"] = json.loads(d.get("params") or "{}")
            except Exception:
                d["params"] = {}
            out.append(d)
        return out

    def decide_approval(self, approval_id: str, approved: bool,
                        by: str = "") -> dict | None:
        """The owner's decision on a queued red-line action —
        the approval gate's second half. Only an
        awaiting_approval row can be decided; the decision is
        audit-recorded either way."""
        ap = self.get_approval(approval_id)
        if ap is None or ap.get("status") != "awaiting_approval":
            return ap
        status = "approved" if approved else "rejected"
        with self._lock:
            self._db.execute(
                "UPDATE grant_approvals SET status = ?,"
                " decided_by = ?, decided_at = ? WHERE id = ?",
                (status, by or "operator", now_ts(), approval_id))
            self._db.commit()
        self.audit("grant_approval_" + status, by or "operator",
                   target=ap["username"], ref_id=approval_id)
        return self.get_approval(approval_id)

    def set_approval_receipt(self, approval_id: str,
                             receipt_id: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE grant_approvals SET receipt_id = ?,"
                " status = 'executed' WHERE id = ?"
                " AND status = 'approved'",
                (receipt_id, approval_id))
            self._db.commit()

    def set_delivery_ack(self, username: str, flag) -> None:
        """Persist the agent's declared delivery-ack capability
        (v1.3.7). Recorded from the agent's own hello, exactly like
        set_decision_link — the agent declares whether its client
        acks queued frames into its durable journal; the relay
        never assigns it. Normalised to the two lawful states
        (1 = ack-capable, 0 = legacy flush)."""
        with self._lock:
            self._db.execute(
                "UPDATE users SET delivery_ack = ? WHERE username = ?",
                (1 if flag else 0, username))
            self._db.commit()

    def set_auth_method(self, username: str, method: str) -> None:
        """Persist how the agent's most recent hello authenticated
        (v1.3.9). Recorded from the hello itself, exactly like
        set_delivery_ack — the relay reports what the connection
        DID, never assigns it. Unknown values are refused so the
        record can never drift out of the lawful states."""
        if method not in ("key", "secret", "resume", "bootstrap",
                          "recovery"):
            return
        with self._lock:
            self._db.execute(
                "UPDATE users SET auth_method = ? WHERE username = ?",
                (method, username))
            self._db.commit()

    def set_vault_meta(self, username: str, labels: str,
                       blob_id: str, version: int,
                       entries: int, content: str = "") -> bool:
        """Publish the relay-side pointer to an agent's credentials
        vault (v1.4.0). Only a pointer is stored: the self-sealed
        document's blob id, its document revision, the entry count,
        and the OVERSIGHT-SEALED envelopes (labels, and since
        v1.5.0 the full content for the owner's Credentials view —
        ciphertext to this store; it holds no key that opens
        either). A publish whose revision is OLDER than the stored
        pointer is REFUSED (returns False) so a stale/zombie host
        can never rewind an agent's vault; an equal revision
        re-points idempotently."""
        with self._lock:
            row = self._db.execute(
                "SELECT vault_version FROM users WHERE username = ?",
                (username,)).fetchone()
            if row is None:
                return False
            if int(version) < int(row[0]):
                return False
            self._db.execute(
                "UPDATE users SET vault_labels = ?, "
                "vault_content = ?, vault_blob = ?, "
                "vault_version = ?, vault_entries = ? "
                "WHERE username = ?",
                (labels or "", content or "", blob_id or "",
                 int(version), int(entries), username))
            self._db.commit()
            return True

    def get_vault_meta(self, username: str) -> dict | None:
        """The vault pointer for one agent, or None when the agent
        is unknown or has never published a vault."""
        with self._lock:
            row = self._db.execute(
                "SELECT vault_labels, vault_blob, vault_version, "
                "vault_entries, vault_content FROM users "
                "WHERE username = ?",
                (username,)).fetchone()
        if row is None or not (row[1] or row[0]):
            return None
        return {"labels": row[0] or "", "blob_id": row[1] or "",
                "version": int(row[2] or 0),
                "entries": int(row[3] or 0),
                "content": row[4] or ""}

    def sign_pub_of(self, username: str) -> str:
        with self._lock:
            row = self._db.execute(
                "SELECT sign_pub FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row["sign_pub"] if row else ""

    def set_sign_pub(self, username: str, sign_pub: str) -> None:
        if not sign_pub:
            return
        with self._lock:
            self._db.execute(
                "UPDATE users SET sign_pub = ? WHERE username = ?",
                (sign_pub, username))
            self._db.commit()

    def verify(self, username: str, secret: str | None) -> bool:
        if not secret:
            return False
        with self._lock:
            row = self._db.execute(
                "SELECT secret FROM users WHERE username = ?", (username,)
            ).fetchone()
        return bool(row) and row["secret"] == _hash_token(secret)

    def exists(self, username: str) -> bool:
        with self._lock:
            row = self._db.execute(
                "SELECT 1 FROM users WHERE username = ?", (username,)
            ).fetchone()
        return row is not None

    def set_display_name(self, username: str, display_name: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE users SET display_name = ? WHERE username = ?",
                (display_name, username),
            )
            self._db.commit()

    def list_users(self, query: str = "", capability: str = "") -> list[dict]:
        with self._lock:
            if query:
                rows = self._db.execute(
                    "SELECT username, display_name, pubkey, sign_pub,"
                    " capabilities, cap_desc, mode, decision_link,"
                    " decision_link_detail,"
                    " delivery_ack, auth_method, designation, last_seen,"
                    " recovery_hash, recovery_used_at, created_at"
                    " FROM users"
                    " WHERE username LIKE ? ORDER BY username",
                    (f"%{query}%",),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT username, display_name, pubkey, sign_pub,"
                    " capabilities, cap_desc, mode, decision_link,"
                    " decision_link_detail,"
                    " delivery_ack, auth_method, designation, last_seen,"
                    " recovery_hash, recovery_used_at, created_at"
                    " FROM users ORDER BY username"
                ).fetchall()
            out = []
            for r in rows:
                d = dict(r)
                try:
                    d["capabilities"] = json.loads(d.get("capabilities")
                                                   or "[]")
                except Exception:
                    d["capabilities"] = []
                # Presentation rule (autonomy law): anything that is
                # not an explicit 'manual' presents as autonomous.
                d["mode"] = d.get("mode") if d.get("mode") in (
                    "manual", "autonomous") else "autonomous"
                # Presentation rule (segregation, v1.6.0): anything
                # not explicitly 'test' presents as production.
                d["designation"] = "test" \
                    if d.get("designation") == "test" else "production"
                # Delivery-ack declaration (v1.3.7): anything not
                # explicitly recorded as ack-capable presents as 0.
                d["delivery_ack"] = 1 if d.get("delivery_ack") else 0
                # Recovery enrollment (v1.7.0): surfaces expose
                # ONLY the enrolled flag + last-used stamp — the
                # stored hash itself never leaves the store.
                d["recovery_enrolled"] = bool(d.pop(
                    "recovery_hash", ""))
                d["recovery_used_at"] = int(
                    d.get("recovery_used_at") or 0)
                if capability and capability.lower() not in \
                        [c.lower() for c in d["capabilities"]]:
                    continue
                out.append(d)
            return out

    # -- registration removal (v1.1.10) --------------------------------
    # Two doors, ONE cascade:
    #   * SELF-DEREGISTER — an agent removes its own registration
    #     (relay `deregister` frame on its authenticated connection).
    #     Fail-closed: refused while live entanglements stand
    #     (removal_blockers) — live work is never silently orphaned.
    #   * OPERATOR REMOVAL — the relay host's operator removes an
    #     orphaned/test registration whose secret is lost
    #     (`agentlink remove-user`, dry-run first; force=True here,
    #     and the CLI adds its own live-heartbeat guard).
    # The cascade deletes everything that BELONGS to the identity:
    # the user row, its offline queue, group/channel memberships and
    # wrapped keys, invites it created, its read receipts, its
    # upload sessions, its username-keyed alerts, its blob metadata
    # and library entries, its work history (with the deliveries and
    # checkpoints hanging off the work) and the chains it created
    # (with their steps). KEPT, deliberately: the audit_log (an
    # append-only trail — the removal itself is recorded there and
    # must survive the deletion), the groups/channels it created
    # (shared spaces; the creator name becomes provenance once its
    # membership is gone), vault entries (group property; added_by
    # is provenance) and blob BYTES (content-addressed ciphertext
    # other registrations may share — only metadata rows go).

    def _removal_refs(self, username: str) -> tuple[list[str], list[str]]:
        """(work_ids, chain_ids) whose rows hang off this identity."""
        with self._lock:
            work_ids = [r["id"] for r in self._db.execute(
                "SELECT id FROM work WHERE assigner = ? OR assignee = ?",
                (username, username)).fetchall()]
            chain_ids = [r["id"] for r in self._db.execute(
                "SELECT id FROM chains WHERE creator = ?",
                (username,)).fetchall()]
        return work_ids, chain_ids

    def _removal_steps(self, username: str) -> list[tuple[str, str, tuple]]:
        """(table, WHERE clause, args) in delete order — shared by
        removal_plan (COUNT) and remove_user (DELETE) so the dry run
        can never drift from the execution."""
        work_ids, chain_ids = self._removal_refs(username)
        mw = ",".join("?" * len(work_ids)) or "NULL"
        mc = ",".join("?" * len(chain_ids)) or "NULL"
        u = username
        return [
            ("work_deliveries",
             f"work_id IN ({mw}) OR deliverer = ?", (*work_ids, u)),
            ("work_checkpoints",
             f"work_id IN ({mw}) OR by_user = ?", (*work_ids, u)),
            ("work", f"id IN ({mw})", tuple(work_ids)),
            ("chain_steps", f"chain_id IN ({mc})", tuple(chain_ids)),
            ("chains", f"id IN ({mc})", tuple(chain_ids)),
            ("queue", "to_username = ?", (u,)),
            ("message_reads", "reader = ?", (u,)),
            ("group_keys", "username = ?", (u,)),
            ("group_members", "username = ?", (u,)),
            ("channel_keys", "username = ?", (u,)),
            ("channel_members", "username = ?", (u,)),
            ("invites", "created_by = ?", (u,)),
            ("upload_sessions", "owner = ? OR for_user = ?", (u, u)),
            ("alerts", "subject = ?", (u,)),
            ("blobs", "owner = ? OR for_user = ?", (u, u)),
            ("library", "sender = ? OR to_user = ?", (u, u)),
            # One-time admin grant (v1.8.0): the grant, its
            # receipts and its approvals belong to the
            # registration — a name re-claimed later by a
            # DIFFERENT identity must never inherit them.
            ("grant_approvals", "username = ?", (u,)),
            ("grant_receipts", "username = ?", (u,)),
            ("grants", "username = ?", (u,)),
            ("agent_connectors", "username = ?", (u,)),
            ("users", "username = ?", (u,)),
        ]

    def removal_blockers(self, username: str) -> list[str]:
        """Live entanglements that refuse a SELF-deregistration."""
        blockers: list[str] = []
        with self._lock:
            n = self._db.execute(
                "SELECT COUNT(*) AS n FROM queue WHERE to_username = ?",
                (username,)).fetchone()["n"]
            if n:
                blockers.append(
                    f"{n} undelivered frame(s) in the offline queue")
            marks = ",".join("?" * len(NON_TERMINAL_WORK_STATUSES))
            n = self._db.execute(
                "SELECT COUNT(*) AS n FROM work WHERE"
                f" (assigner = ? OR assignee = ?) AND status IN ({marks})",
                (username, username, *NON_TERMINAL_WORK_STATUSES)
            ).fetchone()["n"]
            if n:
                blockers.append(
                    f"{n} non-terminal work item(s) as assigner/assignee")
            n = self._db.execute(
                "SELECT COUNT(*) AS n FROM chains WHERE creator = ?"
                " AND status IN ('running', 'paused')",
                (username,)).fetchone()["n"]
            if n:
                blockers.append(f"{n} live chain(s) created by this agent")
            n = self._db.execute(
                "SELECT COUNT(*) AS n FROM chain_steps cs"
                " JOIN chains ch ON ch.id = cs.chain_id"
                " WHERE ch.creator != ?"
                " AND ch.status IN ('running', 'paused')"
                " AND cs.status IN ('pending', 'active')"
                " AND (cs.target = ? OR cs.assignees LIKE ?)",
                (username, username, f"%\"{username}\"%")
            ).fetchone()["n"]
            if n:
                blockers.append(
                    f"{n} live chain step(s) in other agents' chains"
                    " target this agent")
        return blockers

    def removal_plan(self, username: str) -> dict:
        """Exactly what remove_user(username) would delete, counted
        per table — the dry-run view. Performs no writes."""
        plan: dict = {"username": username,
                      "exists": self.exists(username),
                      "blockers": [], "remove": {}}
        if not plan["exists"]:
            return plan
        plan["blockers"] = self.removal_blockers(username)
        steps = self._removal_steps(username)
        with self._lock:
            for table, where, args in steps:
                plan["remove"][table] = self._db.execute(
                    f"SELECT COUNT(*) AS n FROM {table} WHERE {where}",
                    args).fetchone()["n"]
        return plan

    def remove_user(self, username: str, *, force: bool = False,
                    actor: str = "", via: str = "self") -> dict:
        """Delete a registration and everything that belongs to it
        (the cascade above). Returns the per-table counts actually
        removed. Raises NotFound for an unknown username and, unless
        force, RemovalBlocked while live entanglements stand. The
        removal is written to the audit log AFTER the cascade, so
        the record survives the deletion it describes."""
        if not self.exists(username):
            raise NotFound(username)
        blockers = [] if force else self.removal_blockers(username)
        if blockers:
            raise RemovalBlocked(username, blockers)
        removed: dict[str, int] = {}
        steps = self._removal_steps(username)
        with self._lock:
            for table, where, args in steps:
                removed[table] = self._db.execute(
                    f"DELETE FROM {table} WHERE {where}", args).rowcount
            self._db.commit()
        total = sum(removed.values())
        self.audit("user_removed", actor or username, target=username,
                   status=f"via={via};rows={total}")
        return {"username": username, "removed": removed, "total": total}

    # -- offline queue ----------------------------------------------------
    def enqueue(self, to_username: str, payload: dict) -> None:
        weight = PRIORITY_WEIGHT.get(str(payload.get("priority") or "normal"), 0)
        with self._lock:
            self._db.execute(
                "INSERT INTO queue (to_username, payload, priority, ts)"
                " VALUES (?, ?, ?, ?)",
                (to_username, json.dumps(payload), weight, now_ts()),
            )
            self._db.commit()

    def dequeue_all(self, to_username: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM queue WHERE to_username = ?"
                " ORDER BY priority DESC, seq ASC",
                (to_username,),
            ).fetchall()
            self._db.execute("DELETE FROM queue WHERE to_username = ?", (to_username,))
            self._db.commit()
        out = []
        for r in rows:
            frame = json.loads(r["payload"])
            frame["queued"] = True
            out.append(frame)
        return out

    # -- delivery custody (v1.3.7): the queue as an acked outbox -------
    # dequeue_all above stays the LEGACY path (flush = delivered).
    # For ack-capable clients the queue is a custody outbox instead:
    # the relay PEEKS with pending_frames, writes the frames to the
    # socket, and the frames leave the store only when the receiving
    # client acks them (ack_frames) — i.e. only once they are inside
    # the client's durable journal. A crash anywhere before the ack
    # leaves the frames queued for the next hello; nothing is lost
    # by being "sent".

    def pending_frames(self, to_username: str) -> list[dict]:
        """Peek the offline queue WITHOUT deleting: the same frames
        in the same order dequeue_all would return (priority DESC,
        seq ASC, each stamped queued=True) — but custody stays with
        the store until ack_frames releases it."""
        with self._lock:
            rows = self._db.execute(
                "SELECT payload FROM queue WHERE to_username = ?"
                " ORDER BY priority DESC, seq ASC",
                (to_username,),
            ).fetchall()
        out = []
        for r in rows:
            frame = json.loads(r["payload"])
            frame["queued"] = True
            out.append(frame)
        return out

    def ack_frames(self, to_username: str, ids) -> list[dict]:
        """Release custody: delete ONLY this user's queue rows whose
        payload matches an acked id (ids the user does not hold are
        ignored). A frame matches by its top-level "id" (message
        frames), or — for a work_assigned frame, which carries no
        top-level id — by its nested work id: the client acks work by
        work id after journaling the assignment, and that ack must
        retire the frame or custody never completes for work.
        Returns the acked frames (parsed payloads, in queue seq
        order). The whole match+delete runs under the store lock,
        exactly dequeue_all's discipline, so concurrent acks can
        never double-release a frame."""
        wanted = {str(i) for i in (ids or []) if i}
        if not wanted:
            return []
        acked: list[dict] = []
        with self._lock:
            rows = self._db.execute(
                "SELECT seq, payload FROM queue WHERE to_username = ?"
                " ORDER BY seq ASC",
                (to_username,),
            ).fetchall()
            seqs = []
            for r in rows:
                try:
                    frame = json.loads(r["payload"])
                except Exception:
                    continue
                if _ack_id_matches(frame, wanted):
                    seqs.append(r["seq"])
                    acked.append(frame)
            for seq in seqs:
                self._db.execute(
                    "DELETE FROM queue WHERE seq = ?", (seq,))
            if seqs:
                self._db.commit()
        return acked

    def queue_stats(self, to_username: str) -> dict:
        """Custody view for one user: how many frames the store
        still holds for them, and the ts of the oldest (None when
        the queue is empty)."""
        with self._lock:
            row = self._db.execute(
                "SELECT COUNT(*) AS n, MIN(ts) AS oldest FROM queue"
                " WHERE to_username = ?",
                (to_username,)).fetchone()
        return {"count": int(row["n"]),
                "oldest_ts": int(row["oldest"])
                if row["oldest"] is not None else None}

    def queue_stats_all(self) -> dict:
        """queue_stats for every user with a non-empty queue, keyed
        by username (users with count 0 are absent)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT to_username, COUNT(*) AS n, MIN(ts) AS oldest"
                " FROM queue GROUP BY to_username").fetchall()
        return {r["to_username"]: {
            "count": int(r["n"]),
            "oldest_ts": int(r["oldest"])
            if r["oldest"] is not None else None} for r in rows}

    # -- groups ------------------------------------------------------------
    def create_group(self, name: str, creator: str, settings: dict | None) -> str:
        gid = new_id("g-")[:14]
        merged = dict(DEFAULT_SETTINGS)
        if settings:
            for k in DEFAULT_SETTINGS:
                if k in settings:
                    merged[k] = settings[k]
        with self._lock:
            self._db.execute(
                "INSERT INTO groups (id, name, creator, settings, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (gid, name, creator, json.dumps(merged), now_ts()),
            )
            self._db.commit()
        self.add_member(gid, creator, role="superadmin", added_by=creator)
        return gid

    def get_group(self, group_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM groups WHERE id = ?", (group_id,)
            ).fetchone()
        if row is None:
            return None
        g = dict(row)
        g["settings"] = json.loads(g["settings"])
        return g

    def set_settings(self, group_id: str, settings: dict) -> dict:
        g = self.get_group(group_id)
        if g is None:
            raise NotFound(group_id)
        merged = dict(g["settings"])
        for k in DEFAULT_SETTINGS:
            if k in settings:
                merged[k] = settings[k]
        with self._lock:
            self._db.execute(
                "UPDATE groups SET settings = ? WHERE id = ?",
                (json.dumps(merged), group_id),
            )
            self._db.commit()
        return merged

    def add_member(self, group_id: str, username: str, role: str = "member",
                   added_by: str = "") -> bool:
        with self._lock:
            existing = self._db.execute(
                "SELECT 1 FROM group_members WHERE group_id = ? AND username = ?",
                (group_id, username)).fetchone()
            if existing:
                return False
            count = self._db.execute(
                "SELECT COUNT(*) AS n FROM group_members WHERE group_id = ?",
                (group_id,)).fetchone()["n"]
            if count >= MAX_GROUP_MEMBERS:
                raise GroupFull(group_id)
            cur = self._db.execute(
                "INSERT OR IGNORE INTO group_members"
                " (group_id, username, role, added_by, joined_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (group_id, username, role, added_by, now_ts()),
            )
            self._db.commit()
        return cur.rowcount > 0

    def remove_member(self, group_id: str, username: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM group_members WHERE group_id = ? AND username = ?",
                (group_id, username),
            )
            self._db.execute(
                "DELETE FROM group_keys WHERE group_id = ? AND username = ?",
                (group_id, username))
            self._db.commit()
        return cur.rowcount > 0

    def set_nickname(self, group_id: str, username: str, nickname: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE group_members SET nickname = ?"
                " WHERE group_id = ? AND username = ?",
                (nickname[:48], group_id, username))
            self._db.commit()

    def set_custom_role(self, group_id: str, username: str, custom_role: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE group_members SET custom_role = ?"
                " WHERE group_id = ? AND username = ?",
                (custom_role[:48], group_id, username))
            self._db.commit()

    # -- group keys (wrapped ciphertext only; relay cannot unwrap) ---------
    def set_group_key(self, group_id: str, username: str, epoch: int,
                      wrapped: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO group_keys (group_id, username, epoch, wrapped)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT(group_id, username) DO UPDATE SET"
                " epoch = excluded.epoch, wrapped = excluded.wrapped",
                (group_id, username, epoch, json.dumps(wrapped)))
            self._db.commit()

    def group_key_for(self, group_id: str, username: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT epoch, wrapped FROM group_keys"
                " WHERE group_id = ? AND username = ?",
                (group_id, username)).fetchone()
        if row is None:
            return None
        return {"epoch": row["epoch"], "wrapped": json.loads(row["wrapped"])}

    def group_key_epoch(self, group_id: str) -> int:
        with self._lock:
            row = self._db.execute(
                "SELECT COALESCE(MAX(epoch), 0) AS e FROM group_keys"
                " WHERE group_id = ?", (group_id,)).fetchone()
        return int(row["e"])

    def set_role(self, group_id: str, username: str, role: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE group_members SET role = ?"
                " WHERE group_id = ? AND username = ?",
                (role, group_id, username),
            )
            self._db.commit()

    def role_of(self, group_id: str, username: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT role FROM group_members"
                " WHERE group_id = ? AND username = ?",
                (group_id, username),
            ).fetchone()
        return row["role"] if row else None

    def members(self, group_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT username, role, nickname, custom_role, added_by,"
                " joined_at FROM group_members"
                " WHERE group_id = ? ORDER BY joined_at",
                (group_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def all_groups(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT g.id, g.name, g.creator, g.created_at,"
                " (SELECT COUNT(*) FROM group_members m"
                "  WHERE m.group_id = g.id) AS member_count"
                " FROM groups g ORDER BY g.created_at").fetchall()
        return [dict(r) for r in rows]

    # -- invites -------------------------------------------------------------
    def create_invite(self, group_id: str, created_by: str,
                      ttl_seconds: int = INVITE_TTL_SECONDS) -> str:
        """Canonical shape (Supabase al_invites): the row stores the
        token's SHA-256 AS the token column plus created_at; validity
        is created_at + INVITE_TTL_SECONDS >= now. created_at is
        shifted by (ttl - INVITE_TTL) so a custom ttl_seconds keeps
        its exact meaning."""
        token = secrets.token_urlsafe(24)
        created_at = now_ts() + int(ttl_seconds) - INVITE_TTL_SECONDS
        with self._lock:
            self._db.execute(
                "INSERT INTO invites (token, group_id, created_by,"
                " created_at) VALUES (?, ?, ?, ?)",
                (_hash_token(token), group_id, created_by, created_at),
            )
            self._db.commit()
        return token

    def invite_valid(self, group_id: str, token: str | None) -> bool:
        if not token:
            return False
        with self._lock:
            row = self._db.execute(
                "SELECT created_at FROM invites WHERE token = ?"
                " AND group_id = ?",
                (_hash_token(token), group_id),
            ).fetchone()
        return bool(row) and \
            row["created_at"] + INVITE_TTL_SECONDS >= now_ts()

    @staticmethod
    def invite_link(group_id: str, token: str) -> str:
        return f"agentlink://join/{group_id}?token={token}"

    @staticmethod
    def parse_invite_link(link: str) -> tuple[str, str] | None:
        # agentlink://join/<group_id>?token=<token>
        try:
            rest = link.split("join/", 1)[1]
            gid, _, qs = rest.partition("?")
            token = qs.split("token=", 1)[1].split("&")[0]
            return gid, token
        except (IndexError, AttributeError):
            return None

    # -- work ------------------------------------------------------------------
    def create_work(self, assigner: str, assignee: str, group_id: str | None,
                    content_enc: dict, content_self: dict,
                    deadline: int | None, batch_id: str | None = None,
                    priority: str = "normal", auto_reassign: bool = True,
                    assignee_role: str = "",
                    content_group: dict | None = None,
                    chain_id: str = "", chain_step: int = 0,
                    require_approval: bool = False) -> dict:
        wid = new_id("w-")[:14]
        ts = now_ts()
        with self._lock:
            self._db.execute(
                "INSERT INTO work (id, assigner, assignee, group_id,"
                " content_enc, content_self, content_group, batch_id,"
                " chain_id, chain_step,"
                " priority, auto_reassign, assignee_role, deadline,"
                " require_approval, status, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,"
                " 'assigned', ?, ?)",
                (wid, assigner, assignee, group_id, json.dumps(content_enc),
                 json.dumps(content_self),
                 json.dumps(content_group) if content_group else "",
                 batch_id, chain_id, chain_step, priority,
                 1 if auto_reassign else 0,
                 assignee_role, deadline, 1 if require_approval else 0,
                 ts, ts),
            )
            self._db.commit()
        return self.get_work(wid)

    # -- state machine (point 32: no skipping states, fail-closed) ------------
    WORK_TRANSITIONS = {
        "assigned": {"in_progress", "delivered", "awaiting_approval",
                     "covered", "awaiting_agent"},
        "in_progress": {"delivered", "awaiting_approval", "covered",
                        "awaiting_agent"},
        "changes_requested": {"in_progress", "delivered",
                              "awaiting_approval", "covered",
                              "awaiting_agent"},
        "delivered": {"completed", "changes_requested"},
        # Approval gate (v1.1.0): a proven delivery on gated work parks
        # here until the assigner (or a group admin) decides.
        "awaiting_approval": {"completed", "changes_requested"},
        "awaiting_agent": {"assigned"},
        "covered": set(),
        "completed": set(),
    }

    def set_checkpoint(self, work_id: str, attempt: int, by_user: str,
                       content_assigner: dict | None,
                       content_group: dict | None) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO work_checkpoints (work_id, attempt, by_user,"
                " content_assigner, content_group, ts)"
                " VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(work_id) DO UPDATE SET"
                " attempt = excluded.attempt, by_user = excluded.by_user,"
                " content_assigner = excluded.content_assigner,"
                " content_group = excluded.content_group,"
                " ts = excluded.ts",
                (work_id, attempt, by_user,
                 json.dumps(content_assigner) if content_assigner else "",
                 json.dumps(content_group) if content_group else "",
                 now_ts()))
            self._db.commit()

    def get_checkpoint(self, work_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM work_checkpoints WHERE work_id = ?",
                (work_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        for k in ("content_assigner", "content_group"):
            try:
                d[k] = json.loads(d[k]) if d[k] else None
            except Exception:
                d[k] = None
        return d

    def reassign_work(self, work_id: str, new_assignee: str) -> dict:
        """Dead-agent reassignment: attempt increments (dedup key is
        work_id + attempt), progress resets, status returns to
        'assigned' for the replacement."""
        with self._lock:
            self._db.execute(
                "UPDATE work SET assignee = ?, attempt = attempt + 1,"
                " status = 'assigned', progress_percent = 0,"
                " updated_at = ? WHERE id = ?",
                (new_assignee, now_ts(), work_id))
            self._db.commit()
        return self.get_work(work_id)

    def set_awaiting_agent(self, work_id: str) -> dict:
        with self._lock:
            self._db.execute(
                "UPDATE work SET status = 'awaiting_agent', updated_at = ?"
                " WHERE id = ?", (now_ts(), work_id))
            self._db.commit()
        return self.get_work(work_id)

    def restore_awaiting(self, work_id: str) -> dict:
        """Direct-work restoration (v1.3.1): the NAMED assignee of a
        parked 1:1 work is back, so the work returns to 'assigned'
        unchanged — same assignee, same attempt (it was parked, never
        reassigned to a replacement). Guarded on the parked status so
        a racing sweep/reassign can never be clobbered."""
        with self._lock:
            self._db.execute(
                "UPDATE work SET status = 'assigned', updated_at = ?"
                " WHERE id = ? AND status = 'awaiting_agent'",
                (now_ts(), work_id))
            self._db.commit()
        return self.get_work(work_id)

    def open_work(self, statuses=("assigned", "in_progress")) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT id FROM work WHERE status IN (%s)"
                % ",".join("?" * len(statuses)), tuple(statuses)).fetchall()
        return [self.get_work(r["id"]) for r in rows]

    def set_work_progress(self, work_id: str, percent: int) -> dict:
        with self._lock:
            row = self._db.execute(
                "SELECT status FROM work WHERE id = ?", (work_id,)).fetchone()
            if row is None:
                raise NotFound(work_id)
            status = row["status"]
            if status == "assigned":
                status = "in_progress"
            self._db.execute(
                "UPDATE work SET progress_percent = ?, progress_at = ?,"
                " status = ?, updated_at = ? WHERE id = ?",
                (percent, now_ts(), status, now_ts(), work_id))
            self._db.commit()
        return self.get_work(work_id)

    def cover_batch(self, batch_id: str, delivered_work_id: str) -> list[dict]:
        """Role assignment: one delivery satisfies the batch — every
        other open copy in the batch closes as 'covered'."""
        if not batch_id:
            return []
        with self._lock:
            rows = self._db.execute(
                "SELECT id FROM work WHERE batch_id = ? AND id != ?"
                " AND status IN ('assigned', 'in_progress',"
                " 'changes_requested')",
                (batch_id, delivered_work_id)).fetchall()
            ids = [r["id"] for r in rows]
            for wid in ids:
                self._db.execute(
                    "UPDATE work SET status = 'covered', updated_at = ?"
                    " WHERE id = ?", (now_ts(), wid))
            self._db.commit()
        return [self.get_work(wid) for wid in ids]

    def resolve_role(self, group_id: str, role_name: str) -> list[str]:
        """Usernames of group members holding a custom role (case-insensitive)."""
        with self._lock:
            rows = self._db.execute(
                "SELECT username FROM group_members WHERE group_id = ?"
                " AND LOWER(custom_role) = LOWER(?) ORDER BY joined_at",
                (group_id, role_name)).fetchall()
        return [r["username"] for r in rows]

    # -- trust score ---------------------------------------------------------
    def compute_trust(self, username: str) -> int:
        """Server-computed trust, 0-100, from REAL work history only.

        Formula (documented in README; messages never count).
        Owner's ruling (2026-11-06): trust STARTS AT ZERO for
        every agent and rises only when work has been given,
        done successfully AND reviewed successfully — delivery
        alone earns nothing:
          start 0
          +4 per completed assignment (as assignee; completed is
             the post-review state)
          -6 per changes-requested round against the assignee
          -6 per missed deadline (deadline passed while not completed,
             or completed after the deadline)
          -10 per invalid signed-delivery proof
          clamped to [0, 100].
        Pinned real percentages (same ruling): phoenix and its
        probe deploy-probe keep the percentages they actually
        earned under the prior formula — 100 and 56 — returned
        as-is for now.
        """
        real_trust = {"phoenix": 100, "deploy-probe": 56}
        if username in real_trust:
            return real_trust[username]
        with self._lock:
            rows = self._db.execute(
                "SELECT status, deadline, updated_at FROM work"
                " WHERE assignee = ?", (username,)).fetchall()
            changes = self._db.execute(
                "SELECT COUNT(*) AS n FROM audit_log WHERE kind ="
                " 'work_changes_requested' AND target = ?",
                (username,)).fetchone()["n"]
            bad_proofs = self._db.execute(
                "SELECT COUNT(*) AS n FROM audit_log WHERE kind ="
                " 'delivery_proof_verified' AND actor = ? AND status ="
                " 'false'", (username,)).fetchone()["n"]
        score = 0
        now = now_ts()
        for r in rows:
            if r["status"] in ("completed", "covered"):
                score += 4
            if r["deadline"]:
                if r["status"] == "completed" and                         r["updated_at"] > r["deadline"]:
                    score -= 6
                elif r["status"] not in ("completed", "covered",
                                         "delivered", "awaiting_approval") \
                        and now > r["deadline"]:
                    score -= 6
        score -= 6 * changes
        score -= 10 * bad_proofs
        return max(0, min(100, score))

    def get_work(self, work_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM work WHERE id = ?", (work_id,)
            ).fetchone()
            deliveries = []
            if row is not None:
                drows = self._db.execute(
                    "SELECT * FROM work_deliveries WHERE work_id = ? ORDER BY ts",
                    (work_id,),
                ).fetchall()
                deliveries = [
                    {**dict(d),
                     "content_enc": json.loads(d["content_enc"] or "{}"),
                     "content_self": json.loads(d["content_self"] or "{}"),
                     "content_group": json.loads(d["content_group"]
                                                 or "null"),
                     "content_next": json.loads(d["content_next"]
                                                or "null")
                     if "content_next" in d.keys() else None}
                    for d in drows
                ]
        if row is None:
            return None
        w = dict(row)
        w["content_enc"] = json.loads(w["content_enc"] or "{}")
        w["content_self"] = json.loads(w["content_self"] or "{}")
        try:
            w["content_group"] = json.loads(w["content_group"] or "null")
        except Exception:
            w["content_group"] = None
        w["deliveries"] = deliveries
        cp = self.get_checkpoint(work_id)
        if cp is not None:
            w["checkpoint"] = cp
        return w

    def list_work_meta(self) -> list[dict]:
        """Metadata only (parties, status, times) — for the dashboard."""
        with self._lock:
            rows = self._db.execute(
                "SELECT id, assigner, assignee, group_id, status, priority,"
                " batch_id, progress_percent, progress_at, proof_verified,"
                " proof_hash, deadline, chain_id, chain_step, attempt,"
                " require_approval, created_at, updated_at FROM work"
                " ORDER BY updated_at DESC LIMIT 200").fetchall()
        return [dict(r) for r in rows]

    # -- channels (broadcast: admins post, subscribers read) -------------------
    def create_channel(self, name: str, creator: str) -> str:
        cid = new_id("c-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO channels (id, name, creator, created_at)"
                " VALUES (?, ?, ?, ?)", (cid, name, creator, now_ts()))
            self._db.commit()
        self.add_subscriber(cid, creator, role="superadmin", added_by=creator)
        return cid

    def get_channel(self, channel_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM channels WHERE id = ?",
                (channel_id,)).fetchone()
        return dict(row) if row else None

    def add_subscriber(self, channel_id: str, username: str,
                       role: str = "subscriber", added_by: str = "") -> bool:
        with self._lock:
            existing = self._db.execute(
                "SELECT 1 FROM channel_members WHERE channel_id = ?"
                " AND username = ?", (channel_id, username)).fetchone()
            if existing:
                return False
            count = self._db.execute(
                "SELECT COUNT(*) AS n FROM channel_members"
                " WHERE channel_id = ?", (channel_id,)).fetchone()["n"]
            if count >= MAX_CHANNEL_SUBSCRIBERS:
                raise GroupFull(channel_id)
            cur = self._db.execute(
                "INSERT OR IGNORE INTO channel_members (channel_id,"
                " username, role, added_by, joined_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (channel_id, username, role, added_by, now_ts()))
            self._db.commit()
        return cur.rowcount > 0

    def remove_subscriber(self, channel_id: str, username: str) -> bool:
        with self._lock:
            cur = self._db.execute(
                "DELETE FROM channel_members WHERE channel_id = ?"
                " AND username = ?", (channel_id, username))
            self._db.execute(
                "DELETE FROM channel_keys WHERE channel_id = ?"
                " AND username = ?", (channel_id, username))
            self._db.commit()
        return cur.rowcount > 0

    def channel_role_of(self, channel_id: str, username: str) -> str | None:
        with self._lock:
            row = self._db.execute(
                "SELECT role FROM channel_members WHERE channel_id = ?"
                " AND username = ?", (channel_id, username)).fetchone()
        return row["role"] if row else None

    def set_channel_role(self, channel_id: str, username: str,
                         role: str) -> None:
        with self._lock:
            self._db.execute(
                "UPDATE channel_members SET role = ? WHERE channel_id = ?"
                " AND username = ?", (role, channel_id, username))
            self._db.commit()

    def channel_members(self, channel_id: str) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT username, role, added_by, joined_at"
                " FROM channel_members WHERE channel_id = ?"
                " ORDER BY joined_at", (channel_id,)).fetchall()
        return [dict(r) for r in rows]

    def all_channels(self) -> list[dict]:
        with self._lock:
            rows = self._db.execute(
                "SELECT c.id, c.name, c.creator, c.created_at,"
                " (SELECT COUNT(*) FROM channel_members m"
                "  WHERE m.channel_id = c.id) AS member_count"
                " FROM channels c ORDER BY c.created_at").fetchall()
        return [dict(r) for r in rows]

    def set_channel_key(self, channel_id: str, username: str, epoch: int,
                        wrapped: dict) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO channel_keys (channel_id, username, epoch,"
                " wrapped) VALUES (?, ?, ?, ?)"
                " ON CONFLICT(channel_id, username) DO UPDATE SET"
                " epoch = excluded.epoch, wrapped = excluded.wrapped",
                (channel_id, username, epoch, json.dumps(wrapped)))
            self._db.commit()

    def channel_key_for(self, channel_id: str, username: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT epoch, wrapped FROM channel_keys"
                " WHERE channel_id = ? AND username = ?",
                (channel_id, username)).fetchone()
        if row is None:
            return None
        return {"epoch": row["epoch"], "wrapped": json.loads(row["wrapped"])}

    # -- chunked upload sessions -------------------------------------------------
    def create_upload_session(self, owner: str, whole_sha: str, ct_sha: str,
                              size: int, chunk_size: int, for_user: str = "",
                              for_group: str = "",
                              for_channel: str = "") -> str:
        sid = new_id("u-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO upload_sessions (session_id, owner, for_user,"
                " for_group, whole_sha, ct_sha, size,"
                " chunk_size, chunks, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, '[]', ?)",
                (sid, owner, for_user, for_group, whole_sha,
                 ct_sha, size, chunk_size, now_ts()))
            self._db.commit()
        return sid

    def get_upload_session(self, session_id: str) -> dict | None:
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM upload_sessions WHERE session_id = ?",
                (session_id,)).fetchone()
        if row is None:
            return None
        d = dict(row)
        d["chunks"] = json.loads(d["chunks"])
        # Canonical sessions carry no channel scope (v1.1.0); the key
        # stays present (empty) so relay consumers keep a stable shape.
        # The relay asserts channel scope from the finish frame.
        d.setdefault("for_channel", "")
        return d

    def record_chunk(self, session_id: str, index: int) -> list[int]:
        sess = self.get_upload_session(session_id)
        if sess is None:
            raise NotFound(session_id)
        chunks = sorted(set(sess["chunks"]) | {index})
        with self._lock:
            self._db.execute(
                "UPDATE upload_sessions SET chunks = ? WHERE session_id = ?",
                (json.dumps(chunks), session_id))
            self._db.commit()
        return chunks

    def delete_upload_session(self, session_id: str) -> None:
        with self._lock:
            self._db.execute(
                "DELETE FROM upload_sessions WHERE session_id = ?",
                (session_id,))
            self._db.commit()

    def escalate_work_priority(self, work_id: str) -> dict:
        with self._lock:
            self._db.execute(
                "UPDATE work SET priority = 'urgent', updated_at = ?"
                " WHERE id = ?", (now_ts(), work_id))
            self._db.commit()
        return self.get_work(work_id)

    def set_work_status(self, work_id: str, status: str) -> dict:
        current = self.get_work(work_id)
        if current is None:
            raise NotFound(work_id)
        allowed = self.WORK_TRANSITIONS.get(current["status"], set())
        if status != current["status"] and status not in allowed:
            raise InvalidTransition(
                f"{current['status']} -> {status} is not a legal"
                " transition (states cannot be skipped)")
        with self._lock:
            self._db.execute(
                "UPDATE work SET status = ?, updated_at = ? WHERE id = ?",
                (status, now_ts(), work_id),
            )
            self._db.commit()
        return self.get_work(work_id)

    def add_delivery(self, work_id: str, deliverer: str, content_enc: dict,
                     content_self: dict, proof: dict | None = None,
                     content_group: dict | None = None,
                     content_next: dict | None = None) -> dict:
        did = new_id("d-")[:14]
        with self._lock:
            self._db.execute(
                "INSERT INTO work_deliveries (id, work_id, deliverer,"
                " content_enc, content_self, content_group, content_next,"
                " ts) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (did, work_id, deliverer, json.dumps(content_enc),
                 json.dumps(content_self),
                 json.dumps(content_group) if content_group else "",
                 json.dumps(content_next) if content_next else "",
                 now_ts()),
            )
            if proof:
                self._db.execute(
                    "UPDATE work SET proof_hash = ?, proof_ts = ?,"
                    " proof_sig = ?, proof_verified = ? WHERE id = ?",
                    (proof.get("hash", ""), int(proof.get("ts") or 0),
                     proof.get("sig", ""),
                     1 if proof.get("verified") else 0, work_id))
            self._db.commit()
        with self._lock:
            row = self._db.execute(
                "SELECT require_approval FROM work WHERE id = ?",
                (work_id,)).fetchone()
        gated = bool(row and row["require_approval"])
        self.set_work_status(
            work_id, "awaiting_approval" if gated else "delivered")
        return self.get_work(work_id)

    def list_work(self, username: str, status: str | None = None,
                  group_id: str | None = None) -> list[dict]:
        """Work where the user is assignee OR assigner."""
        q = ("SELECT id FROM work WHERE (assignee = ? OR assigner = ?)")
        args: list = [username, username]
        if status:
            q += " AND status = ?"
            args.append(status)
        if group_id:
            q += " AND group_id = ?"
            args.append(group_id)
        q += " ORDER BY created_at"
        with self._lock:
            rows = self._db.execute(q, args).fetchall()
        return [self.get_work(r["id"]) for r in rows]
