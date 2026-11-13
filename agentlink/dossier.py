"""The Agent Dossier (v2.5.0, owner's dossier ruling).

An extensive per-agent record that lives ONLY in the owner's
Google Drive SYSTEM tree — the "AgentLink System" root, one
subfolder per agent — never in Firebase, never in Supabase,
never in Cloudflare storage, never in the conversation
archive, never rendered on the dashboard. Surfaces elsewhere
carry only a flag + a date (dossier_status +
last_deposited_at), never dossier content.

DRIVE FOLDER LAW (owner, 2026-11-11, strict): two trees,
never mixed — conversations in "AgentLink Archive"
(per-agent subfolders), system/dossier records in
"AgentLink System" (per-agent subfolders). Test twins
("AgentLink Archive Test", "AgentLink System Test") are the
ONLY roots drills/tests may touch. PRODUCTION ROOTS ARE NOT
TEST SURFACES. Root ids live in the deploy vault
(agentlink-deploy/drive-roots.env); code takes them from
configuration, never from a literal in the source.

CONTENT: identity (username, display name, registered_at,
client version, identity-key fingerprint), the FULL nature
profile, how the agent works (runtime kind,
supervision, wake paths, duty pattern, transports), a location
block (system timezone, OS locale, an agent/owner-declared
label — what the machine itself knows; NO IP geolocation, NO
coordinates), a self-description section authored by the
agent's runtime (the section is compulsory; its words are the
agent's own), and the standing at generation time (grade,
compliance, open-work count). NO secrets, NO credentials, NO
file paths beyond the state-dir root name, NO conversation
content — ever. build_dossier REFUSES (raises) if a forbidden
key or credential-shaped string sneaks into the document: the
refusal is part of the guarantee, and the drill scans for it.

FORMAT: versioned signed JSON (schema field; the agent's
Ed25519 signature over the canonical bytes) + a generated
Markdown rendering of the same facts. Both are the deposit.
Versions chain with the archive's hash chain (archive.py
entry_hash — the same pure function the message chains use).

PLUMBING: the client builds the dossier locally and deposits
through the archive deposit discipline — a durable local queue,
capped retries, dead-letter park; mandatory-but-non-blocking
(the standard-message class): a failed deposit never blocks
the daemon. Agents hold NO Drive credentials.

DESTINATION, HARDENED (v2.5.1, owner's correction): the
deposit destination is a built-in of the platform, not a
setting. Deposits ride the agent's OWN authenticated session
to the platform deposit route (the agentlink-deposit Edge
function + the platform deposit inbox on the record layer);
the operator drain files inbox deposits into this tree. There
is NO env-configured URL, NO shared archive token, and NO
per-agent destination option anywhere in the stock client —
the 2.5.0 defect ("dossier stays local since no archive
destination is set", fleet-wide, silently) is an impossible
state by construction now: either the deposit lands in the
platform inbox, or the queue + the dossier_status flag carry
the failure loudly (non-current on every surface, and the
platform's single transition alert past 24h) until it does.
Generation + deposit are AUTOMATIC (hardened reporting
class): at setup, at daemon start when stale, on any
nature version change, on a client version change, and
at a 7-day max-age refresh. No opt-out exists.

SCHEMA /2 (v2.6.0, spec retirement): dossier/2 is dossier/1
minus the machine spec section — the platform no longer
collects the spec, so the dossier no longer carries it.
build_dossier strips any retired 'machine' / 'detection_gap'
keys from the incoming profile before embedding, so a legacy
local profile can never leak spec into a v2 dossier. Filed
v1 dossiers remain untouched historical record.
"""
from __future__ import annotations

import hashlib
import json
import locale as _locale
import os
import re
import time
from pathlib import Path

from .archive import entry_hash
from .liveness import canonical_json
from .timing import DOSSIER_DEPOSIT_NEXT_DUE_BASE_SECONDS

SCHEMA = "agentlink-dossier/2"
MAX_AGE_S = 7 * 86400
#: Deposit retry discipline (mirrors the archive queue's):
#: bounded attempts with a growing next-due interval, then the
#: dead-letter park — visible in status forever, retried on the
#: next trigger. The interval base is an operator-plane constant
#: (timing.py): a due time, never a sleep.
MAX_ATTEMPTS = 5
NEXT_DUE_BASE_S = DOSSIER_DEPOSIT_NEXT_DUE_BASE_SECONDS

#: Keys that must never appear anywhere inside a dossier.
_FORBIDDEN_KEYS = {
    "password", "secret", "seed", "private_key", "privkey",
    "recovery_key", "recovery", "token", "api_key", "apikey",
    "credential", "credentials", "vault", "oversight",
    "content", "body", "plaintext",
}
#: Credential-shaped strings (long base64/base64url runs and
#: key-file markers). The dossier's own signature + the key
#: fingerprint are added AFTER this scan runs (the scan covers
#: the document body; the signature is the agent's proof, not
#: a credential).
_CRED_SHAPE = re.compile(
    r"(-----BEGIN|AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{20,}|"
    r"sk-[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})")


def _scan_clean(obj, path: str = "") -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            if str(k).lower() in _FORBIDDEN_KEYS:
                raise ValueError(
                    f"dossier refuses forbidden key {k!r} at {path}")
            _scan_clean(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _scan_clean(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        if _CRED_SHAPE.search(obj):
            raise ValueError(
                f"dossier refuses credential-shaped string at {path}")


def key_fingerprint(sign_pub_b64: str) -> str:
    """SHA-256 of the raw Ed25519 public key bytes — the
    identity fingerprint a dossier carries (a fingerprint is
    not a credential; the private key never leaves the state
    dir and is never read here)."""
    import base64
    try:
        raw = base64.b64decode(sign_pub_b64 or "")
    except Exception:
        raw = (sign_pub_b64 or "").encode()
    return hashlib.sha256(raw).hexdigest()


def system_location() -> dict:
    """What the machine itself knows: system timezone + OS
    locale. No IP lookups, no coordinates, ever."""
    tz = ""
    try:
        tz = time.tzname[time.daylight] if time.daylight \
            else time.tzname[0]
    except Exception:
        tz = ""
    offset = -time.timezone + (3600 if time.daylight
                               and time.localtime().tm_isdst else 0)
    loc = ""
    try:
        loc = _locale.setlocale(_locale.LC_ALL, "") or ""
    except Exception:
        loc = ""
    if not loc:
        loc = os.environ.get("LANG") or os.environ.get(
            "LC_ALL") or ""
    return {"system_timezone": tz or "unknown",
            "utc_offset_s": offset,
            "os_locale": loc or "unknown"}


def build_dossier(*, username: str, display_name: str,
                  registered_at: int, client_version: str,
                  sign_pub_b64: str, nature_profile: dict | None,
                  standing: dict, local: dict,
                  state_dir_name: str, version: int,
                  generated_at: int) -> dict:
    """Assemble the dossier document (unsigned). Raises
    ValueError if anything forbidden is present — generation
    fails closed rather than deposit a tainted record."""
    # Spec retirement (2.6.0): the profile is embedded WITHOUT
    # the retired spec keys — a legacy local profile carrying
    # them must never leak spec into a v2 dossier.
    prof = {k: v for k, v in (nature_profile or {}).items()
            if k not in ("machine", "detection_gap")}
    doc = {
        "schema": SCHEMA,
        "username": username,
        "dossier_version": int(version),
        "generated_at": int(generated_at),
        "identity": {
            "username": username,
            "display_name": display_name or "",
            "registered_at": int(registered_at or 0),
            "client_version": client_version or "",
            "sign_key_fingerprint": key_fingerprint(sign_pub_b64),
            "state_dir_name": state_dir_name,
        },
        "nature": prof,
        "how_it_works": {
            "runtime_kind": prof.get("runtime_kind") or "",
            "persistence_class":
                prof.get("persistence_class") or "",
            "supervision": prof.get("supervision") or "",
            "wake_paths": prof.get("wake_paths") or [],
            "duty_pattern": prof.get("duty_pattern") or "",
            "network_self_managed":
                bool(prof.get("network_self_managed")),
            "runtime_proof_capable":
                bool(prof.get("runtime_proof_capable")),
            "transports": ["serverless"],
            "nature_version": int(
                standing.get("nature_version") or 0),
        },
        "location": {
            **system_location(),
            "declared_label":
                str(local.get("location_label") or ""),
        },
        "self_description": {
            "text": str(local.get("self_description") or ""),
            "present": bool(
                str(local.get("self_description") or "").strip()),
            "updated_at":
                int(local.get("self_description_updated_at") or 0),
        },
        "standing": {
            "grade": str(standing.get("grade") or "unproven"),
            "nature_compliant":
                bool(standing.get("nature_compliant")),
            "open_work_count":
                int(standing.get("open_work_count") or 0),
            "last_daemon_receipt_at":
                int(standing.get("last_daemon_receipt_at") or 0),
            "last_runtime_proof_at":
                int(standing.get("last_runtime_proof_at") or 0),
        },
    }
    _scan_clean(doc)
    return doc


def sign_dossier(doc: dict, signer) -> dict:
    """Sign the canonical bytes (everything except the
    signature itself) with the agent's identity key."""
    body = {k: v for k, v in doc.items() if k != "signature"}
    sig = signer(canonical_json(body).encode())
    if isinstance(sig, bytes):
        import base64
        sig = base64.b64encode(sig).decode()
    out = dict(doc)
    out["signature"] = str(sig)
    return out


def verify_dossier_signature(doc: dict, sign_pub_b64: str) -> bool:
    """Verify a dossier's signature against a registry public
    key (the drill + the owner's Drive-side verification use
    this; the platform itself never needs to — the dossier is
    the owner's record, carried by the agent's signature)."""
    from .crypto import Identity
    body = {k: v for k, v in doc.items() if k != "signature"}
    return Identity.verify_signature(
        sign_pub_b64, canonical_json(body).encode(),
        str(doc.get("signature") or ""))


def chain_entry(doc: dict, prev_hash: str) -> dict:
    """One link of the agent's dossier chain (archive.py's
    scheme): the entry binds the version, its content hash and
    its signature; entry_hash chains it to every prior
    version."""
    content = {k: v for k, v in doc.items() if k != "signature"}
    entry = {
        "kind": "dossier",
        "username": doc["username"],
        "dossier_version": doc["dossier_version"],
        "generated_at": doc["generated_at"],
        "sha256": hashlib.sha256(
            canonical_json(content).encode()).hexdigest(),
        "signature": doc.get("signature") or "",
        "prev": prev_hash or "",
    }
    entry["hash"] = entry_hash(prev_hash or "", entry)
    return entry


def render_markdown(doc: dict) -> str:
    """The human rendering of the same facts — generated from
    the signed JSON, never separately authored, so the two can
    never diverge."""
    ident = doc["identity"]
    nat = doc.get("nature") or {}
    hw = doc["how_it_works"]
    loc = doc["location"]
    sd = doc["self_description"]
    st = doc["standing"]
    lines = [
        f"# Agent Dossier — @{doc['username']}",
        "",
        f"Dossier version {doc['dossier_version']} · generated "
        f"{doc['generated_at']} · schema {doc['schema']} · "
        "signed by the agent's identity key (see DOSSIER.json).",
        "",
        "## Identity",
        f"- Username: @{ident['username']}",
        f"- Display name: {ident['display_name'] or '—'}",
        f"- Registered at: {ident['registered_at']}",
        f"- Client version: {ident['client_version']}",
        f"- Identity-key fingerprint (SHA-256): "
        f"{ident['sign_key_fingerprint']}",
        "",
        "## Nature (declared)",
        f"- Runtime kind: {nat.get('runtime_kind') or '—'}",
        f"- Host class: {nat.get('host_class') or '—'}",
        f"- Persistence class: "
        f"{nat.get('persistence_class') or '—'}",
        f"- Windows: suspect_after_s="
        f"{nat.get('suspect_after_s')}, expected_gap_s="
        f"{nat.get('expected_gap_s')}, dark_after_s="
        f"{nat.get('dark_after_s')}",
        f"- Supervision: {nat.get('supervision') or '—'}",
        f"- Wake paths: {', '.join(nat.get('wake_paths') or [])}",
        f"- Duty pattern: {nat.get('duty_pattern') or '—'}",
        f"- Network class: {nat.get('network_class') or '—'}",
        "",
        "## How it works",
        f"- Transports: {', '.join(hw['transports'])}",
        f"- Network layer self-managed (O3): "
        f"{hw['network_self_managed']}",
        f"- Runtime can countersign proofs: "
        f"{hw['runtime_proof_capable']}",
        "",
        "## Location (machine-known only)",
        f"- System timezone: {loc['system_timezone']} "
        f"(UTC offset {loc['utc_offset_s']}s)",
        f"- OS locale: {loc['os_locale']}",
        f"- Declared label: {loc['declared_label'] or '—'}",
        "",
        "## Self-description (the agent's own words)",
        sd["text"] if sd["present"] else
        "(the runtime has not written its self-description yet"
        " — the absence is recorded, not hidden)",
        "",
        "## Standing at generation",
        f"- Grade: {st['grade']}",
        f"- Nature compliant: {st['nature_compliant']}",
        f"- Open work: {st['open_work_count']}",
        f"- Last daemon receipt: {st['last_daemon_receipt_at']}",
        f"- Last runtime proof: {st['last_runtime_proof_at']}",
        "",
    ]
    return "\n".join(lines)


# ------------------------------------------------------------ state

def _state_path(state_dir: Path) -> Path:
    return Path(state_dir) / "dossier-state.json"


def _local_path(state_dir: Path) -> Path:
    return Path(state_dir) / "dossier-local.json"


def load_local(state_dir: Path) -> dict:
    p = _local_path(state_dir)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def save_local(state_dir: Path, local: dict) -> None:
    p = _local_path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(local, indent=2))
    tmp.replace(p)


def load_state(state_dir: Path) -> dict:
    p = _state_path(state_dir)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}


def _save_state(state_dir: Path, state: dict) -> None:
    p = _state_path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(p)


def staging_dir(state_dir: Path) -> Path:
    d = Path(state_dir) / "dossier-staging"
    d.mkdir(parents=True, exist_ok=True)
    (d / "dossier-history").mkdir(exist_ok=True)
    return d


def dossier_status(state_dir: Path, nature_version: int = 0,
                   now: int | None = None) -> str:
    """The compliance flag every surface carries (a flag + a
    date, never content): current / stale / missing /
    deposit-parked."""
    now = int(time.time()) if now is None else now
    st = load_state(state_dir)
    if not st or not st.get("version"):
        return "missing"
    queue = st.get("queue") or []
    if any(q.get("parked") for q in queue):
        return "deposit-parked"
    if queue:
        return "stale"
    if nature_version and int(st.get("nature_version") or 0) \
            != int(nature_version):
        return "stale"
    if now - int(st.get("generated_at") or 0) > MAX_AGE_S:
        return "stale"
    if not st.get("deposited_at"):
        return "stale"
    return "current"


def needs_refresh(state_dir: Path, nature_version: int = 0,
                  now: int | None = None,
                  client_version: str = "") -> bool:
    """Generation triggers (owner's dossier ruling): no
    dossier yet, the nature version moved since the
    dossier was generated, the dossier aged past the 7-day
    max — or (2.5.1) the CLIENT version moved: the dossier
    names the client that generated it, and a dossier stating
    a superseded client version is stale truth on the record
    (Order O5, version truth — the same law that redeclares
    the nature on a client version change). A dossier that
    exists but is merely UNDEPOSITED is NOT regenerated — it
    is drained (regenerating would spam versions into the
    archive history for a transport problem)."""
    now = int(time.time()) if now is None else now
    st = load_state(state_dir)
    if not st or not st.get("version"):
        return True
    if nature_version and int(st.get("nature_version") or 0) \
            != int(nature_version):
        return True
    if client_version and st.get("client_version") \
            and str(st.get("client_version")) != str(
                client_version):
        return True
    return now - int(st.get("generated_at") or 0) > MAX_AGE_S


def generate(state_dir: Path, *, signer, username: str,
             display_name: str, registered_at: int,
             client_version: str, sign_pub_b64: str,
             nature_profile: dict | None, standing: dict,
             now: int | None = None) -> dict:
    """Build + sign + stage a new dossier version and enqueue
    its deposit. Returns {version, status, entry}."""
    now = int(time.time()) if now is None else now
    st = load_state(state_dir)
    version = int(st.get("version") or 0) + 1
    local = load_local(state_dir)
    doc = build_dossier(
        username=username, display_name=display_name,
        registered_at=registered_at,
        client_version=client_version, sign_pub_b64=sign_pub_b64,
        nature_profile=nature_profile, standing=standing,
        local=local, state_dir_name=Path(state_dir).name,
        version=version, generated_at=now)
    doc = sign_dossier(doc, signer)
    # Chain: append to the staged chain file (archive scheme).
    d = staging_dir(state_dir)
    chain_path = d / "dossier-chain.jsonl"
    prev = ""
    if chain_path.exists():
        lines = [ln for ln in chain_path.read_text().splitlines()
                 if ln.strip()]
        if lines:
            prev = json.loads(lines[-1]).get("hash") or ""
    entry = chain_entry(doc, prev)
    with chain_path.open("a") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")
    # Current + history files (the Drive deposit set).
    cur_json = d / "DOSSIER.json"
    cur_md = d / "DOSSIER.md"
    if cur_json.exists():
        old_version = version - 1
        hist = d / "dossier-history"
        (hist / f"v{old_version}.json").write_bytes(
            cur_json.read_bytes())
        if cur_md.exists():
            (hist / f"v{old_version}.md").write_bytes(
                cur_md.read_bytes())
    cur_json.write_text(json.dumps(doc, indent=2, sort_keys=True))
    cur_md.write_text(render_markdown(doc))
    queue = st.get("queue") or []
    queue.append({"version": version, "attempts": 0,
                  "next_due": now, "parked": False,
                  "last_error": ""})
    st.update({"version": version, "generated_at": now,
               "nature_version":
                   int(standing.get("nature_version") or 0),
               "client_version": client_version or "",
               "sha256": entry["sha256"], "queue": queue})
    _save_state(state_dir, st)
    return {"version": version,
            "status": dossier_status(state_dir,
                                     int(standing.get(
                                         "nature_version") or 0),
                                     now),
            "entry": entry, "doc": doc}


def deposit_files(state_dir: Path) -> dict[str, bytes]:
    """The full deposit set for the agent's Drive folder:
    current dossier (JSON + MD), the whole version history,
    and the chain spine."""
    d = staging_dir(state_dir)
    out: dict[str, bytes] = {}
    for name in ("DOSSIER.json", "DOSSIER.md",
                 "dossier-chain.jsonl"):
        p = d / name
        if p.exists():
            out[name] = p.read_bytes()
    hist = d / "dossier-history"
    if hist.exists():
        for p in sorted(hist.iterdir()):
            if p.is_file():
                out[f"dossier-history/{p.name}"] = p.read_bytes()
    return out


def drain_queue(state_dir: Path, depositor,
                now: int | None = None) -> dict:
    """Attempt due deposits with the capped-retry discipline.
    depositor(files) -> confirmation dict; raises on failure.
    Returns {deposited: [versions], parked: [versions],
    pending: [versions]}."""
    now = int(time.time()) if now is None else now
    st = load_state(state_dir)
    queue = st.get("queue") or []
    # Heal arc: a fresh drain trigger (start / manual deposit)
    # re-arms parked entries for ONE more bounded round — the
    # park is a backoff state, not a life sentence; the flag
    # keeps reading deposit-parked until a deposit lands.
    if queue and all(q.get("parked") for q in queue):
        for q in queue:
            q["parked"] = False
            q["attempts"] = 0
            q["next_due"] = now
    done, parked, pending = [], [], []
    files = None
    for q in queue:
        if q.get("parked"):
            parked.append(q["version"])
            continue
        if int(q.get("next_due") or 0) > now:
            pending.append(q["version"])
            continue
        if files is None:
            files = deposit_files(state_dir)
        try:
            conf = depositor(files)
        except Exception as exc:
            q["attempts"] = int(q.get("attempts") or 0) + 1
            q["last_error"] = str(exc)[:200]
            if q["attempts"] >= MAX_ATTEMPTS:
                q["parked"] = True
                parked.append(q["version"])
            else:
                q["next_due"] = now + NEXT_DUE_BASE_S * (
                    2 ** (q["attempts"] - 1))
                pending.append(q["version"])
            continue
        q["confirmed"] = conf
        done.append(q["version"])
    st["queue"] = [q for q in queue
                   if q["version"] not in done]
    if done:
        st["deposited_at"] = now
        st["last_confirmation"] = {"versions": done, "at": now}
    _save_state(state_dir, st)
    return {"deposited": done, "parked": parked,
            "pending": pending}


# ------------------------------------------------------- depositors

def platform_depositor(transport, username: str):
    """THE deposit route (2.5.1, hardened): the platform
    deposit inbox, reached through the agent's OWN transport —
    the session JWT the transport already holds is the only
    credential, and the function's URL derives from the
    platform's own functions base (a built-in, like the
    production endpoints). There is no other stock route: no
    env URL, no shared token, no Drive CLI fallback, no
    per-agent destination setting — "no destination set" is
    not a state this client can be in.

    The deposit record is the dossier kind of the platform
    inbox protocol: {kind: "dossier", agent, files: {name:
    base64}} — the same wire shape the retired archive-service
    route used, now authenticated by the agent's own identity
    and verified platform-side (the Edge checks the dossier's
    signature against the registry key before it confirms).
    The drain files the deposit set into the agent's folder
    under the System tree root the operator configured —
    folder law: PRODUCTION ROOTS ARE NOT TEST SURFACES."""

    def depositor(files: dict[str, bytes]) -> dict:
        import base64
        record = {
            "kind": "dossier",
            "agent": username,
            "files": {name: base64.b64encode(data).decode()
                      for name, data in files.items()},
        }
        return transport.deposit_record(record)

    return depositor
