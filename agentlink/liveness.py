"""Life Signs (v2.5.0): nature profiles and the canonical
liveness payloads. (Machine spec retired in v2.6.0 — see below.)

The platform is the line: it verifies signatures and keeps time.
This module is the AGENT side of that contract:

* The NATURE PROFILE is the agent's signed declaration of how it
  actually runs — runtime kind, host class, persistence class +
  windows, supervision, wake paths, duty pattern, network
  self-management, runtime proof capability. The client HELPS
  the agent fill it truthfully (setup proposes defaults, never
  asserts them silently). The signed declaration is an honest
  claim by the agent, not a platform-verified fact.

* Canonical payloads: the exact byte strings the daemon/runtime
  sign and the agentlink-liveness Edge verifies. Three kinds:
    - receipt (tier=daemon): the daemon answers a challenge by
      signing receipt_payload(); the tier string is INSIDE the
      signed payload and the daemon path only ever signs
      tier=daemon — a daemon receipt can never be dressed as
      runtime proof.
    - prove (tier=runtime): the runtime countersigns
      prove_payload() via `agentlink liveness prove`.
    - declare: the runtime signs declare_payload() over the
      canonical profile JSON.

* SPEC RETIREMENT (v2.6.0, owner decision 2026-11-12: the
  platform takes less): the machine spec (hostname, OS, CPU,
  RAM, storage, GPUs) is no longer collected, reported, stored,
  or judged anywhere. Machine detection, the spec-drift probe
  duty, and the drift report are deleted; validate_profile
  REJECTS the retired 'machine' / 'detection_gap' keys as
  unknown fields, so a legacy profile carrying them cannot be
  signed or declared. Nature declaration is NOT retired: it
  stays compulsory and unchanged.

Grade/window mirrors: effective_windows() and grade_for() mirror
migration v213's sweep math exactly (one law, two places — the
SQL is authoritative; these exist for client display and tests).
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

# ------------------------------------------------------------ nature

RUNTIME_KINDS = ("persistent-daemon", "session-chat", "scheduled",
                 "embedded", "other")
HOST_CLASSES = ("cloud-vm", "home-pc", "phone", "server", "other")
PERSISTENCE_CLASSES = ("persistent", "session")
SUPERVISION_KINDS = ("none", "service-manager", "watchdog",
                     "owner-relaunch")
WAKE_PATHS = ("boot-autostart", "owner-action", "inbound-task",
              "none")
NETWORK_CLASSES = ("datacenter", "residential", "mobile", "")

#: Window defaults (seconds) — anchored in migration v213's
#: header: persistent suspect = two missed verified cycles at the
#: 600s receipt cadence + grace (the ratified ladder's shape);
#: dark = 3.6x suspect. Session defaults fit a task-driven
#: runtime; undeclared agents get the conservative session set.
PERSISTENT_DEFAULT_SUSPECT_S = 1500
PERSISTENT_DEFAULT_DARK_S = 5400
SESSION_DEFAULT_GAP_S = 21600
SESSION_DEFAULT_DARK_S = 259200
UNDECLARED_GAP_S = 86400
UNDECLARED_DARK_S = 604800
#: Session-class BEATING window: evidence fresher than this is a
#: live agent, whatever its gap declaration says.
BEAT_WINDOW_S = 1500
#: Challenge issuance cadence guards (mirror the sweep).
PERSISTENT_CHALLENGE_AFTER_S = 480
PERSISTENT_CHALLENGE_EXPIRY_S = 1200

_PROFILE_KEYS = {
    "runtime_kind", "host_class", "persistence_class",
    "suspect_after_s", "expected_gap_s", "dark_after_s",
    "supervision", "wake_paths", "duty_pattern",
    "network_self_managed", "network_class",
    "runtime_proof_capable",
}


def validate_profile(profile: dict) -> dict:
    """Normalise + validate a nature profile for declaration.
    Returns the cleaned profile (only known keys, typed values).
    Raises ValueError with a plain reason on anything invalid —
    the client refuses to sign a declaration it cannot state."""
    if not isinstance(profile, dict):
        raise ValueError("nature profile must be an object")
    unknown = set(profile) - _PROFILE_KEYS
    if unknown:
        raise ValueError(
            f"unknown nature fields: {sorted(unknown)}")
    out: dict = {}
    cls = str(profile.get("persistence_class") or "")
    if cls not in PERSISTENCE_CLASSES:
        raise ValueError(
            "persistence_class must be 'persistent' or 'session'")
    out["persistence_class"] = cls
    rk = str(profile.get("runtime_kind") or "")
    if rk and rk not in RUNTIME_KINDS:
        raise ValueError(f"runtime_kind must be one of {RUNTIME_KINDS}")
    out["runtime_kind"] = rk
    hc = str(profile.get("host_class") or "")
    if hc and hc not in HOST_CLASSES:
        raise ValueError(f"host_class must be one of {HOST_CLASSES}")
    out["host_class"] = hc
    sv = str(profile.get("supervision") or "")
    if sv and sv not in SUPERVISION_KINDS:
        raise ValueError(f"supervision must be one of {SUPERVISION_KINDS}")
    out["supervision"] = sv
    for key, lo, hi in (("suspect_after_s", 300, 86400),
                        ("expected_gap_s", 300, 2592000),
                        ("dark_after_s", 900, 5184000)):
        v = profile.get(key)
        if v is None or v == "":
            out[key] = None
            continue
        try:
            v = int(v)
        except (TypeError, ValueError):
            raise ValueError(f"{key} must be whole seconds")
        if not (lo <= v <= hi):
            raise ValueError(f"{key} out of bounds ({lo}..{hi})")
        out[key] = v
    wp = profile.get("wake_paths") or []
    if not isinstance(wp, list):
        raise ValueError("wake_paths must be a list")
    wp = [str(x) for x in wp]
    bad = [x for x in wp if x not in WAKE_PATHS]
    if bad:
        raise ValueError(f"wake_paths entries must be in {WAKE_PATHS}")
    out["wake_paths"] = wp
    out["duty_pattern"] = str(profile.get("duty_pattern") or "")[:280]
    out["network_self_managed"] = bool(
        profile.get("network_self_managed"))
    nc = str(profile.get("network_class") or "")
    if nc not in NETWORK_CLASSES:
        raise ValueError(
            "network_class must be datacenter|residential|mobile|''")
    out["network_class"] = nc
    out["runtime_proof_capable"] = bool(
        profile.get("runtime_proof_capable"))
    return out


def canonical_json(obj) -> str:
    """The one canonical JSON form used inside signed payloads:
    sorted keys, compact separators — identical bytes on the
    client and (via the mirror implementation) on the Edge."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def receipt_payload(username: str, challenge_id: str, nonce: str,
                    tier: str, ts: int,
                    digest: str | None = None) -> str:
    """What the daemon signs to answer a challenge. The tier is a
    claim INSIDE the signed bytes; the daemon path only ever
    passes tier='daemon' (gate-pinned). From v2.5.2 the build
    digest rides INSIDE the same signed bytes (v2 form): a build
    that strips it produces v1 receipts, which the platform
    rejects from any agent whose recorded client is >= 2.5.2 —
    stripping is a visible state, never a silent pass. The v1
    form remains for pre-2.5.2 senders (theirs is the honest
    unattested state)."""
    if digest:
        return (f"agentlink-liveness-receipt-v2|{username}"
                f"|{challenge_id}|{nonce}|{tier}|{digest}"
                f"|{int(ts)}")
    return (f"agentlink-liveness-receipt-v1|{username}|{challenge_id}"
            f"|{nonce}|{tier}|{int(ts)}")


def prove_payload(username: str, ts: int,
                  digest: str | None = None) -> str:
    """What the runtime countersigns for a runtime-tier proof.
    The v2 form carries the build digest inside the signed
    bytes, exactly like the daemon receipt."""
    if digest:
        return (f"agentlink-liveness-prove-v2|{username}"
                f"|{digest}|{int(ts)}")
    return f"agentlink-liveness-prove-v1|{username}|{int(ts)}"


def attest_payload(username: str, version: str, digest: str,
                   ts: int) -> str:
    """What the daemon signs as its BUILD STATEMENT (v2.5.2):
    'the build I run is the one this manifest digest defines.'
    A claim of EVIDENCE — the platform judges it against the
    registered release digest and records the verdict; the
    statement itself never decides anything (the Street Rule:
    the agent's copy is never the court)."""
    return (f"agentlink-build-attest-v1|{username}|{version}"
            f"|{digest}|{int(ts)}")


def declare_payload(username: str, profile: dict, ts: int) -> str:
    """What the runtime signs to declare its nature: the full
    canonical profile."""
    return (f"agentlink-nature-declare-v1|{username}|"
            f"{canonical_json(profile)}|{int(ts)}")


DOSSIER_STATUSES = ("current", "stale", "missing",
                    "deposit-parked")


def dossier_status_payload(username: str, status: str,
                           deposited_at: int, version: int,
                           ts: int) -> str:
    """What the daemon signs to report its dossier status.
    Surfaces carry ONLY this flag + the deposit date — dossier
    CONTENT never leaves the AgentLink System tree."""
    if status not in DOSSIER_STATUSES:
        raise ValueError(f"bad dossier status {status!r}")
    return (f"agentlink-dossier-status-v1|{username}|{status}|"
            f"{int(deposited_at)}|{int(version)}|{int(ts)}")


def compose_liveness_node(liveness_row: dict | None,
                          user_row: dict | None) -> dict:
    """The /liveness/<user> RTDB node, composed from the RECORD
    layer's truth (the al_liveness row + registry facts). One
    composition, three writers (the liveness Edge at proof time,
    the doorbell tapper at transition time, and the drill's
    mirror): {grade, nature_version, persistence_class,
    last_proof_tier, last_proof_at, daemon_only, as_of}.
    (v2.6.0: the node no longer carries spec_drift — spec
    retirement; the Edge mirror stopped writing it too.)
    as_of is stamped by the WRITER at write time (server
    timestamp on the wire); this function leaves it to the
    caller. A grade the live layer cannot source reads
    'unproven' — never a guessed default."""
    lv = liveness_row or {}
    u = user_row or {}
    daemon_at = int(lv.get("last_daemon_receipt_at") or 0)
    runtime_at = int(lv.get("last_runtime_proof_at") or 0)
    login_at = int(u.get("last_seen") or 0)
    tier, at = "", 0
    for t, v in (("runtime", runtime_at), ("daemon", daemon_at),
                 ("login", login_at)):
        if v > at:
            tier, at = t, v
    return {
        "grade": str(lv.get("grade") or "") or "unproven",
        "nature_version": int(lv.get("judged_nature_version") or 0),
        "persistence_class": str(lv.get("judged_class") or ""),
        "last_proof_tier": tier,
        "last_proof_at": at,
        "daemon_only": bool(lv.get("daemon_only")),
        "nature_compliant": bool(lv.get("nature_compliant")),
        "dossier_status": str(lv.get("dossier_status") or "")
        or "missing",
        # Build integrity (v2.5.2): the platform's VERDICT,
        # computed server-side from the agent's signed
        # attestation against the registered release digest —
        # never the agent's own claim. An agent with no judged
        # attestation reads 'unattested', including honest
        # pre-2.5.2 builds.
        "build_integrity": str(lv.get("build_integrity") or "")
        or "unattested",
        "build_version": str(lv.get("build_version") or ""),
        "build_digest": str(lv.get("build_digest") or "")[:12],
    }


def effective_windows(profile: dict | None) -> dict:
    """Declared-or-default windows for a profile (None =
    undeclared: conservative session defaults). Mirrors the
    sweep's judging math in migration v213."""
    if not profile:
        return {"persistence_class": "session", "declared": False,
                "suspect_after_s": UNDECLARED_GAP_S,
                "expected_gap_s": UNDECLARED_GAP_S,
                "dark_after_s": UNDECLARED_DARK_S}
    cls = profile.get("persistence_class") or "session"
    if cls == "persistent":
        return {"persistence_class": "persistent", "declared": True,
                "suspect_after_s":
                    profile.get("suspect_after_s")
                    or PERSISTENT_DEFAULT_SUSPECT_S,
                "expected_gap_s": None,
                "dark_after_s":
                    profile.get("dark_after_s")
                    or PERSISTENT_DEFAULT_DARK_S}
    return {"persistence_class": "session", "declared": True,
            "suspect_after_s":
                profile.get("expected_gap_s")
                or SESSION_DEFAULT_GAP_S,
            "expected_gap_s":
                profile.get("expected_gap_s")
                or SESSION_DEFAULT_GAP_S,
            "dark_after_s":
                profile.get("dark_after_s")
                or SESSION_DEFAULT_DARK_S}


def grade_for(profile: dict | None, evidence_age_s: float) -> str:
    """The sweep's grade bands, mirrored for display/tests."""
    w = effective_windows(profile)
    age = max(0.0, float(evidence_age_s))
    if w["persistence_class"] == "persistent":
        if age <= w["suspect_after_s"]:
            return "BEATING"
        if age <= w["dark_after_s"]:
            return "SUSPECT"
        return "DARK"
    if age <= BEAT_WINDOW_S:
        return "BEATING"
    if age <= w["expected_gap_s"]:
        return "RESTING"
    if age <= w["dark_after_s"]:
        return "SUSPECT"
    return "DARK"


def nature_summary(profile: dict | None) -> str:
    """One line of nature words — the same phrasing the sweep's
    alert bodies use (al_nature_summary in v213)."""
    if not profile:
        return ("nature undeclared (judged by conservative "
                "session defaults)")
    rk = {"persistent-daemon": "persistent daemon",
          "session-chat": "session runtime",
          "scheduled": "scheduled runtime",
          "embedded": "embedded runtime"}.get(
              profile.get("runtime_kind") or "",
              "persistent daemon"
              if profile.get("persistence_class") == "persistent"
              else "session runtime")
    hc = {"cloud-vm": "cloud VM host", "home-pc": "home PC host",
          "phone": "phone host", "server": "server host"}.get(
              profile.get("host_class") or "", "host undeclared")
    sv = {"service-manager": "service-manager supervision",
          "watchdog": "watchdog supervision",
          "owner-relaunch": "owner relaunch",
          "none": "no supervision"}.get(
              profile.get("supervision") or "",
              "supervision undeclared")
    return f"{rk}, {hc}, {sv}"


# ------------------------------------------------------- local state

def nature_state(state_dir: str | Path) -> dict:
    path = _nature_state_path(state_dir)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def propose_defaults(state_dir: str | Path | None = None) -> dict:
    """Sensible per-runtime defaults, PROPOSED — never asserted.
    Detection informs the proposal (a supervised daemon proposes
    persistent/service-manager; an unsupervised process proposes
    session/owner-relaunch); the agent confirms or edits before
    anything is signed."""
    supervised = False
    try:
        supervised = bool(os.environ.get("INVOCATION_ID")) \
            or Path("/run/systemd/system").exists() \
            and bool(os.environ.get("AGENTLINK_SUPERVISED"))
    except Exception:
        supervised = False
    if supervised:
        profile = {
            "runtime_kind": "persistent-daemon",
            "host_class": "cloud-vm",
            "persistence_class": "persistent",
            "suspect_after_s": None,
            "expected_gap_s": None,
            "dark_after_s": None,
            "supervision": "service-manager",
            "wake_paths": ["boot-autostart"],
            "duty_pattern": "",
            "network_self_managed": True,
            "network_class": "",
            "runtime_proof_capable": True,
        }
    else:
        profile = {
            "runtime_kind": "session-chat",
            "host_class": "",
            "persistence_class": "session",
            "suspect_after_s": None,
            "expected_gap_s": None,
            "dark_after_s": None,
            "supervision": "owner-relaunch",
            "wake_paths": ["owner-action", "inbound-task"],
            "duty_pattern": "",
            "network_self_managed": True,
            "network_class": "",
            "runtime_proof_capable": True,
        }
    return profile
