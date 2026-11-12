"""Life Signs (v2.5.0): nature profiles, machine detection, and
the canonical liveness payloads.

The platform is the line: it verifies signatures and keeps time.
This module is the AGENT side of that contract:

* The NATURE PROFILE is the agent's signed declaration of how it
  actually runs — runtime kind, host class, persistence class +
  windows, supervision, wake paths, duty pattern, network
  self-management, runtime proof capability — plus the MACHINE
  SPEC its own client detected at declaration time. The client
  HELPS the agent fill it truthfully (`agentlink nature` shows
  detected-vs-declared; setup proposes defaults, never asserts
  them silently). The signed declaration carries the detected
  snapshot, labelled DECLARED everywhere: an honest claim by the
  agent's own client, not a platform-verified fact.

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

* Machine detection is best-effort and NEVER raises: every field
  falls back to unknown/empty. It carries operational metadata
  only — hostname (the machine's own name, which the owner
  explicitly wants stated), OS, CPU, RAM, GPUs, storage, client
  runtime. No paths, no OS-account usernames, no IPs.

* Spec drift: the daemon re-probes at start (probe is local and
  cheap); material changes (hostname, CPU, cores, RAM, GPU set,
  OS, arch) are recorded in the state dir as a drift event and
  surfaced by status/whoami until the agent redeclares.

Grade/window mirrors: effective_windows() and grade_for() mirror
migration v213's sweep math exactly (one law, two places — the
SQL is authoritative; these exist for client display and tests).
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
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
    "runtime_proof_capable", "machine", "detection_gap",
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
    machine = profile.get("machine")
    if machine is not None:
        if not isinstance(machine, dict):
            raise ValueError("machine spec must be an object")
        out["machine"] = machine
    gap = str(profile.get("detection_gap") or "")
    if gap:
        out["detection_gap"] = gap[:200]
    return out


def detection_gaps(spec: dict | None) -> list[str]:
    """Fields detection could NOT determine on this machine.
    The hardened-reporting law: a declaration still goes out
    with failed fields 'unknown' + these names in its
    detection_gap note — silence/omission is not a
    representable state. An empty GPU list is NOT a gap (it is
    the honest 'none'); a GPU probe that errors leaves the
    field out entirely, which detect_machine records as []."""
    if not spec:
        return ["hostname", "os", "cpu_model", "ram_mb"]
    gaps = []
    if not spec.get("hostname") or spec["hostname"] == "unknown":
        gaps.append("hostname")
    if not spec.get("os") or spec["os"] == "unknown":
        gaps.append("os")
    if not spec.get("cpu_model") \
            or spec["cpu_model"] == "unknown":
        gaps.append("cpu_model")
    if spec.get("ram_mb") is None:
        gaps.append("ram_mb")
    if spec.get("storage_total_mb") is None:
        gaps.append("storage")
    return gaps


def canonical_json(obj) -> str:
    """The one canonical JSON form used inside signed payloads:
    sorted keys, compact separators — identical bytes on the
    client and (via the mirror implementation) on the Edge."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def receipt_payload(username: str, challenge_id: str, nonce: str,
                    tier: str, ts: int) -> str:
    """What the daemon signs to answer a challenge. The tier is a
    claim INSIDE the signed bytes; the daemon path only ever
    passes tier='daemon' (gate-pinned)."""
    return (f"agentlink-liveness-receipt-v1|{username}|{challenge_id}"
            f"|{nonce}|{tier}|{int(ts)}")


def prove_payload(username: str, ts: int) -> str:
    """What the runtime countersigns for a runtime-tier proof."""
    return f"agentlink-liveness-prove-v1|{username}|{int(ts)}"


def declare_payload(username: str, profile: dict, ts: int) -> str:
    """What the runtime signs to declare its nature: the full
    canonical profile (machine snapshot included)."""
    return (f"agentlink-nature-declare-v1|{username}|"
            f"{canonical_json(profile)}|{int(ts)}")


def drift_payload(username: str, fields: list[str], ts: int) -> str:
    """What the daemon signs to report spec drift: the material
    fields that changed vs the declared snapshot (names only —
    the new values arrive with the next declaration)."""
    return (f"agentlink-liveness-drift-v1|{username}|"
            f"{','.join(sorted(fields))}|{int(ts)}")


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
    last_proof_tier, last_proof_at, daemon_only, spec_drift,
    as_of}. as_of is stamped by the WRITER at write time (server
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
        "spec_drift": bool(str(lv.get("spec_drift") or "")),
        "nature_compliant": bool(lv.get("nature_compliant")),
        "dossier_status": str(lv.get("dossier_status") or "")
        or "missing",
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


# ------------------------------------------------------------ machine

def _run_quiet(argv: list[str], timeout: float = 4.0) -> str:
    try:
        done = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout)
        return done.stdout or ""
    except Exception:
        return ""


def _detect_gpus() -> list[dict]:
    """Best-effort GPU list: [{vendor, model, vram_mb}]. Empty
    list = no GPU detected — declared honestly as none."""
    gpus: list[dict] = []
    out = _run_quiet(["nvidia-smi",
                      "--query-gpu=name,memory.total",
                      "--format=csv,noheader,nounits"])
    for line in out.splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        name, _, mem = line.rpartition(",")
        try:
            vram = int(float(mem.strip()))
        except ValueError:
            vram = None
        gpus.append({"vendor": "NVIDIA",
                     "model": name.strip() or "unknown",
                     "vram_mb": vram})
    if gpus:
        return gpus
    out = _run_quiet(["rocm-smi", "--showproductname",
                      "--showmeminfo", "vram"])
    if "GPU" in out or "Card" in out:
        model = "unknown"
        m = re.search(r"GPU\[0\]\s*:?\s*Card series:\s*(.+)", out)
        if m:
            model = m.group(1).strip()
        gpus.append({"vendor": "AMD", "model": model,
                     "vram_mb": None})
        return gpus
    if sys.platform == "darwin":
        out = _run_quiet(["system_profiler", "SPDisplaysDataType"],
                         timeout=6.0)
        m = re.search(r"Chipset Model:\s*(.+)", out)
        if m:
            v = re.search(r"VRAM \(Total\):\s*(\d+)\s*(MB|GB)", out)
            vram = None
            if v:
                vram = int(v.group(1)) * (1024 if v.group(2) == "GB"
                                          else 1)
            gpus.append({"vendor": "Apple",
                         "model": m.group(1).strip(),
                         "vram_mb": vram})
    return gpus


def _detect_cpu() -> tuple[str, int | None, int | None]:
    model = ""
    physical = None
    logical = os.cpu_count()
    if sys.platform.startswith("linux"):
        try:
            info = Path("/proc/cpuinfo").read_text(errors="replace")
            m = re.search(r"model name\s*:\s*(.+)", info)
            if m:
                model = m.group(1).strip()
            cores = set(re.findall(
                r"physical id\s*:\s*(\d+).*?core id\s*:\s*(\d+)",
                info, re.S))
            if cores:
                physical = len(cores)
        except Exception:
            pass
    if not model:
        model = platform.processor() or ""
    if not model and sys.platform == "darwin":
        model = _run_quiet(
            ["sysctl", "-n", "machdep.cpu.brand_string"]).strip()
    if physical is None:
        try:
            physical = len(os.sched_getaffinity(0)) \
                if hasattr(os, "sched_getaffinity") else None
        except Exception:
            physical = None
    return model or "unknown", physical, logical


def _detect_ram_mb() -> int | None:
    if sys.platform.startswith("linux"):
        try:
            info = Path("/proc/meminfo").read_text(errors="replace")
            m = re.search(r"MemTotal:\s*(\d+)\s*kB", info)
            if m:
                return int(m.group(1)) // 1024
        except Exception:
            pass
    if sys.platform == "darwin":
        out = _run_quiet(["sysctl", "-n", "hw.memsize"]).strip()
        if out.isdigit():
            return int(out) // (1024 * 1024)
    return None


def detect_machine(state_dir: str | Path | None = None) -> dict:
    """Probe THIS machine. Never raises; unknown fields are
    'unknown'/None/[]. Operational metadata only — no paths
    beyond nothing at all, no OS-account names, no IPs."""
    spec: dict = {}
    try:
        spec["hostname"] = socket.gethostname() or "unknown"
    except Exception:
        spec["hostname"] = "unknown"
    try:
        uname = platform.uname()
        spec["os"] = f"{uname.system} {uname.release}".strip()
        spec["os_version"] = uname.version or ""
        spec["kernel"] = uname.release or ""
        spec["arch"] = uname.machine or platform.machine() or "unknown"
    except Exception:
        spec.update({"os": "unknown", "os_version": "",
                     "kernel": "", "arch": "unknown"})
    try:
        model, physical, logical = _detect_cpu()
        spec["cpu_model"] = model
        spec["cores_physical"] = physical
        spec["cores_logical"] = logical
    except Exception:
        spec.update({"cpu_model": "unknown", "cores_physical": None,
                     "cores_logical": None})
    try:
        spec["ram_mb"] = _detect_ram_mb()
    except Exception:
        spec["ram_mb"] = None
    try:
        spec["gpus"] = _detect_gpus()
    except Exception:
        spec["gpus"] = []
    try:
        anchor = Path(state_dir).expanduser() if state_dir \
            else Path.home()
        usage = shutil.disk_usage(str(anchor))
        spec["storage_total_mb"] = usage.total // (1024 * 1024)
        spec["storage_free_mb"] = usage.free // (1024 * 1024)
    except Exception:
        spec["storage_total_mb"] = None
        spec["storage_free_mb"] = None
    try:
        from . import __version__
        spec["client_runtime"] = (
            f"python {platform.python_version()} / "
            f"agentlink {__version__}")
    except Exception:
        spec["client_runtime"] = (
            f"python {platform.python_version()}")
    spec["detected_at"] = int(time.time())
    return spec


def machine_summary(spec: dict | None) -> str:
    """One line: 'vm-name · CPU model (8 cores) · 16 GB RAM ·
    NVIDIA RTX 4090 24 GB' — display form for surfaces."""
    if not spec:
        return "machine undeclared"
    parts = [str(spec.get("hostname") or "unknown")]
    cpu = str(spec.get("cpu_model") or "unknown")
    cores = spec.get("cores_logical")
    parts.append(f"{cpu} ({cores} cores)" if cores else cpu)
    ram = spec.get("ram_mb")
    if ram:
        parts.append(f"{ram / 1024:.0f} GB RAM" if ram >= 1024
                     else f"{ram} MB RAM")
    gpus = spec.get("gpus") or []
    if gpus:
        for g in gpus:
            gtxt = f"{g.get('vendor', '')} {g.get('model', '')}".strip()
            if g.get("vram_mb"):
                gtxt += f" {g['vram_mb'] / 1024:.0f} GB"
            parts.append(gtxt)
    else:
        parts.append("no GPU")
    return " · ".join(parts)


#: Fields whose change is MATERIAL drift (VM replaced, GPU gone,
#: hostname changed). Storage free space and detection time are
#: expected to move and never count.
_DRIFT_FIELDS = ("hostname", "os", "arch", "cpu_model",
                 "cores_physical", "cores_logical", "ram_mb")


def machine_drift(declared: dict | None,
                  current: dict | None) -> list[str]:
    """Material differences between the declared snapshot and a
    fresh probe. RAM within 10% is the same machine (reporting
    noise); everything else compares exactly."""
    if not declared or not current:
        return []
    drift: list[str] = []
    for field in _DRIFT_FIELDS:
        a, b = declared.get(field), current.get(field)
        if a in (None, "", "unknown") or b in (None, "", "unknown"):
            continue
        if field == "ram_mb":
            if a and abs(int(a) - int(b)) > max(64, int(a) * 0.10):
                drift.append(field)
        elif a != b:
            drift.append(field)
    ga = sorted((g.get("vendor", ""), g.get("model", ""))
                for g in declared.get("gpus") or [])
    gb = sorted((g.get("vendor", ""), g.get("model", ""))
                for g in current.get("gpus") or [])
    if ga != gb and (declared.get("gpus") is not None):
        drift.append("gpus")
    return drift


# ------------------------------------------------------- drift state

def _nature_state_path(state_dir: str | Path) -> Path:
    return Path(state_dir).expanduser() / "nature-state.json"


def record_machine_probe(state_dir: str | Path,
                         declared_profile: dict | None) -> dict:
    """Daemon-start duty: probe the machine, compare against the
    DECLARED snapshot, record the drift event in the state dir.
    Returns the nature-state dict (also surfaced by whoami /
    status). Never raises."""
    path = _nature_state_path(state_dir)
    state: dict = {}
    if path.exists():
        try:
            state = json.loads(path.read_text())
        except Exception:
            state = {}
    try:
        current = detect_machine(state_dir)
    except Exception:
        current = None
    declared_machine = (declared_profile or {}).get("machine") \
        if declared_profile else None
    drift = machine_drift(declared_machine, current)
    state["last_probe_at"] = int(time.time())
    state["last_probe"] = current
    if drift:
        state["spec_drift"] = drift
        state["spec_drift_at"] = int(time.time())
    elif declared_machine:
        state.pop("spec_drift", None)
        state.pop("spec_drift_at", None)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2))
        tmp.replace(path)
    except Exception:
        pass
    return state


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
