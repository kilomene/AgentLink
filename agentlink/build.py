"""Build Integrity Attestation (v2.5.2) — THE STREET RULE.

The law lives on the PLATFORM, never in the agent. A release is
DEFINED by its update-manifest.json: the exact bytes whose file
map the updater verified, file by file, at install. This module
is the agent side of the attestation contract — it produces
EVIDENCE, never a verdict:

* At install, the updater records the exact manifest bytes it
  installed from into the install's own metadata dir
  (agentlink-<version>.dist-info/installed-manifest.json +
  build-record.json) — install data lives with the install,
  swapped and rolled back with it; an update never writes
  the agent's state dir (the v2.4.2 byte-identical-state
  law). attested_build consults that install record first
  and a state-dir copy second (the runtime bootstrap's
  fallback home, below). A client that cannot produce the
  manifest it installed from is, by definition, unattested.

* attested_build() computes the ONE digest the client can
  honestly sign for, at statement time:
    - a manifest (the recorded one, or — for installs made by
      pre-2.5.2 updaters, which wrote no record — the manifest
      fetched for the running version) whose file map EXACTLY
      describes the installed tree (every listed file's SHA-256
      matches; no stale files inside the governed scope) ->
      sha256 of those manifest bytes, basis "manifest";
    - a manifest exists but the tree does NOT match it (an
      edited file, a doctored manifest, a missing file) ->
      sha256 over the canonical map of the ACTUAL tree, basis
      "tree". That digest cannot equal any release digest, so
      the platform's judgment (stock iff the attested digest
      equals the registered digest for the attested version)
      reads MODIFIED — the fork is marked by its own evidence;
    - no manifest obtainable at all -> digest None. The client
      sends NO digest rather than a guess: unattested is an
      honest state, a fabricated digest is a lie with a
      signature on it.

* The platform judges. This module never decides stock /
  modified / unattested; it only ever states what it runs,
  signed. Local edits may change what the agent DOES; they can
  never change what the platform RECORDS about it.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

MANIFEST_NAME = "update-manifest.json"
RECORD_NAME = "build-record.json"
MANIFEST_COPY_NAME = "installed-manifest.json"

#: Where the update feed lives (mirror of updater's default;
#: duplicated here so this module never imports the updater at
#: module level — the updater imports THIS module).
DEFAULT_UPDATE_BASE = "https://x.novamail.store"


def manifest_digest(manifest_raw: bytes) -> str:
    """The build digest of a manifest: sha256 of its exact
    bytes. The release IS this digest — the dashboard serves
    the manifest, the Release carries it, the platform
    registers it."""
    return hashlib.sha256(manifest_raw).hexdigest()


def _install_record_home(install_dir, version: str) -> Path:
    """Where a real install's build record lives: inside the
    fresh metadata dir the installer wrote for that version
    (agentlink-<version>.dist-info at the install root)."""
    return Path(install_dir) / f"agentlink-{version}.dist-info"


def record_install(home, version: str,
                   manifest_raw: bytes | None) -> dict | None:
    """Record the manifest a successful install landed from:
    the raw bytes + their digest, in `home` — the directory
    that holds the record (the install's dist-info dir for
    real installs). Called by the updater ONLY after the
    install's health gates pass. Never raises — a failed
    record leaves the client unattested (honest), never
    broken."""
    if not manifest_raw:
        return None
    try:
        manifest = json.loads(manifest_raw)
        if not isinstance(manifest, dict) \
                or manifest.get("version") != version \
                or not isinstance(manifest.get("files"), dict):
            return None
    except Exception:
        return None
    record = {"version": str(version),
              "manifest_sha256": manifest_digest(manifest_raw),
              "recorded_at": int(time.time())}
    try:
        sd = Path(home).expanduser()
        sd.mkdir(parents=True, exist_ok=True)
        copy_path = sd / MANIFEST_COPY_NAME
        tmp = copy_path.with_suffix(".tmp")
        tmp.write_bytes(manifest_raw)
        tmp.replace(copy_path)
        rec_path = sd / RECORD_NAME
        tmp = rec_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(record, indent=2))
        tmp.replace(rec_path)
    except Exception:
        return None
    return record


def load_record(state_dir) -> dict | None:
    """The install record, when one exists and parses."""
    try:
        path = Path(state_dir).expanduser() / RECORD_NAME
        record = json.loads(path.read_text())
        if isinstance(record, dict) and record.get("version") \
                and record.get("manifest_sha256"):
            return record
    except Exception:
        pass
    return None


def _load_recorded_manifest(state_dir) -> tuple[bytes, dict] | None:
    """The recorded manifest bytes + parsed form, when the
    record and its byte copy agree (the copy's digest must
    equal the record's — a swapped copy is no record)."""
    record = load_record(state_dir)
    if not record:
        return None
    try:
        raw = (Path(state_dir).expanduser()
               / MANIFEST_COPY_NAME).read_bytes()
    except Exception:
        return None
    if manifest_digest(raw) != record.get("manifest_sha256"):
        return None
    try:
        manifest = json.loads(raw)
    except Exception:
        return None
    if not isinstance(manifest, dict) \
            or manifest.get("version") != record.get("version") \
            or not isinstance(manifest.get("files"), dict):
        return None
    return raw, manifest


def _sha256_file(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except Exception:
        return None


def verify_tree(install_dir, manifest: dict) -> bool:
    """True iff the installed tree is EXACTLY the tree this
    manifest describes: every listed file present with a
    matching SHA-256, and — for real installs — no stale files
    inside the governed scope. A source checkout is never
    judged on stale files (its unlisted files are source, not
    leftovers — the updater's own law), only on listed ones."""
    from .updater import _is_source_checkout, find_stale_files
    install_dir = Path(install_dir)
    files = manifest.get("files") or {}
    for rel, want in files.items():
        got = _sha256_file(install_dir / rel)
        if got is None or got != want:
            return False
    if _is_source_checkout(install_dir):
        return True
    try:
        return not find_stale_files(install_dir, files)
    except Exception:
        return False


def tree_digest(install_dir, manifest: dict) -> str:
    """The digest of the tree AS IT ACTUALLY STANDS: sha256
    over the canonical JSON map {path: actual sha256 | null}
    for every file the manifest governs, plus any stale file
    found inside the governed scope (with its actual hash).
    Any deviation from the manifest — one edited line, one
    missing file, one extra module — yields a different
    digest, and no tree digest can collide with a manifest
    digest (different preimage by construction)."""
    from .updater import find_stale_files
    install_dir = Path(install_dir)
    files = manifest.get("files") or {}
    actual: dict[str, str | None] = {}
    for rel in files:
        actual[rel] = _sha256_file(install_dir / rel)
    try:
        for rel in find_stale_files(install_dir, files):
            if rel not in actual:
                actual[rel] = _sha256_file(install_dir / rel)
    except Exception:
        pass
    canon = json.dumps(actual, sort_keys=True,
                       separators=(",", ":"))
    return hashlib.sha256(canon.encode()).hexdigest()


def attested_build(state_dir, install_dir=None, *,
                   fetch: bool = True,
                   base_url: str | None = None) -> dict:
    """The build statement this client can honestly sign:
    {version, digest, basis} — basis "manifest" (the tree is
    exactly the recorded/fetched manifest's tree; digest is
    the release digest), "tree" (a manifest exists but the
    tree deviates; digest is the actual tree's), or "none"
    (no manifest obtainable; digest None — send nothing).
    Never raises."""
    from . import __version__ as running
    if install_dir is None:
        install_dir = Path(__file__).resolve().parent.parent
    install_dir = Path(install_dir)
    raw = manifest = None
    # The install record first (installer-written, inside the
    # running version's dist-info dir); a state-dir copy
    # second (the bootstrap fallback home). Either must name
    # the running version to count.
    home = _install_record_home(install_dir, running)
    recorded = None
    if home.is_dir():
        cand = _load_recorded_manifest(home)
        if cand is not None and cand[1].get("version") \
                == running:
            recorded = cand
    if recorded is None:
        cand = _load_recorded_manifest(state_dir)
        if cand is not None and cand[1].get("version") \
                == running:
            recorded = cand
    if recorded is not None:
        raw, manifest = recorded
    if manifest is None and fetch:
        try:
            from .updater import _fetch
            # The feed this agent's own network config points
            # at (the same AGENTLINK_UPDATE_BASE the updater
            # itself honors), else the production feed.
            base = (base_url
                    or os.environ.get("AGENTLINK_UPDATE_BASE")
                    or DEFAULT_UPDATE_BASE).rstrip("/")
            fetched = _fetch(f"{base}/{MANIFEST_NAME}")
            parsed = json.loads(fetched)
            if isinstance(parsed, dict) \
                    and parsed.get("version") == running \
                    and isinstance(parsed.get("files"), dict):
                raw, manifest = fetched, parsed
        except Exception:
            raw = manifest = None
    if manifest is None or raw is None:
        return {"version": running, "digest": None,
                "basis": "none"}
    if verify_tree(install_dir, manifest):
        if recorded is None:
            # The bootstrap record: an install made by a
            # pre-2.5.2 updater wrote none; the fetched
            # manifest that exactly describes this tree IS
            # the manifest it installed from, in every
            # verifiable sense — record it now. The
            # bootstrap's home is the state dir: it is the
            # RUNTIME writing its own working bookkeeping at
            # start (like orders-state), not the updater
            # writing during a swap — the byte-identical-
            # state law binds the update, and the drill's
            # migration leg (d5/d8) pins exactly this split:
            # no record after the old updater lands, a
            # record after the new client first starts.
            record_install(state_dir, running, raw)
        return {"version": running,
                "digest": manifest_digest(raw),
                "basis": "manifest"}
    return {"version": running,
            "digest": tree_digest(install_dir, manifest),
            "basis": "tree"}
