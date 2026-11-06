"""AgentLink auto-update — from GitHub directly, with rollback.

Doctrine (same as the ACP auto-updater): check the repo for a newer
version, VERIFY before installing (the manifest lists a SHA-256 for
every file; one mismatch aborts the whole update before anything is
written), install, health-check, and ROLL BACK AUTOMATICALLY on any
failure. Identity, keys, config and databases live outside the code
directory and are never touched. Live connections are not disrupted:
files are swapped atomically per file and only a graceful daemon
restart (operator's supervisor) picks the new code up.

Manifest format (``update-manifest.json`` at the repo root)::

    {"version": "1.1.0",
     "files": {"agentlink/client.py": "<sha256>", ...}}

Files are fetched from ``<base>/<path>`` where base defaults to the raw
GitHub content URL for kilomene/AgentLink@main and can be overridden
with AGENTLINK_UPDATE_BASE (mirrors, tests).

Two apply paths share the same invariants (verify-before-write,
timestamped rollback backup, identity/config/state never touched):

* :meth:`Updater.apply` — the manual ``agentlink update`` one-shot:
  download + verify everything, install, health-check, roll back.
* :meth:`Updater.apply_staged` — the in-daemon path (v1.1.8): only
  files whose on-disk SHA-256 differs from the manifest are
  downloaded (each verified); the new tree is STAGED beside the
  install and must pass a subprocess import smoke test before a
  single installed byte is swapped; then backup → atomic swap →
  installed-tree health check → automatic rollback on failure. The
  daemon drives this from its own serve loop (see
  ``Agent._update_check_loop``) — no host cron is involved anywhere.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

from . import __version__

DEFAULT_UPDATE_BASE = \
    "https://raw.githubusercontent.com/kilomene/AgentLink/main"
MANIFEST_NAME = "update-manifest.json"


class UpdateError(Exception):
    pass


def _fetch(url: str, timeout: float = 30.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "agentlink-updater"})
    # Dial-time proxy-credential resolution + racing
    # (proxycreds.open_url): urllib's default opener takes the
    # proxy from the process environment — pinned at process
    # start, dead after a token rotation.
    from .proxycreds import open_url
    with open_url(req, timeout=timeout) as resp:
        return resp.read()


def _vtuple(v: str) -> tuple:
    return tuple(int(x) for x in v.split(".") if x.isdigit())


class Updater:
    def __init__(self, base_url: str | None = None,
                 install_dir: str | Path | None = None,
                 state_dir: str | Path = "~/.agentlink",
                 current_version: str = __version__,
                 census_guard=None):
        self.base = (base_url or os.environ.get("AGENTLINK_UPDATE_BASE")
                     or DEFAULT_UPDATE_BASE).rstrip("/")
        # install_dir = the directory that CONTAINS the agentlink package
        self.install_dir = Path(install_dir) if install_dir else \
            Path(__file__).resolve().parent.parent
        self.state_dir = Path(state_dir).expanduser()
        self.current_version = current_version
        # Immortality gate (v1.3.2): an optional CensusGuard over the
        # deployment's store. When set, apply paths census the store
        # BEFORE the swap and verify AFTER the health check — an
        # update window in which a conversation, group or channel
        # vanished is a FAILED update: roll back, alert, raise.
        self.census_guard = census_guard
        self._census_loss = None

    # -- immortality gate (v1.3.2) --------------------------------------

    def _census_before(self):
        if self.census_guard is None:
            return None
        return self.census_guard.compute()

    def _census_intact(self, before) -> bool:
        """True when the post-update census still holds everything
        the before-census held. On loss, the loss is written to the
        record (alert + audit rows) before returning False."""
        if before is None or self.census_guard is None:
            return True
        from .census import alert_loss, diff_census, losses_found
        after = self.census_guard.compute()
        diff = diff_census(before, after)
        if not losses_found(diff):
            return True
        self._census_loss = diff
        try:
            alert_loss(self.census_guard.store, diff)
        except Exception:
            pass
        return False

    def _fail_census_loss(self, backup, rels, backed_up,
                          new_version) -> None:
        """Roll back and raise for a census-loss update failure.
        Always raises UpdateError."""
        from .census import describe_losses
        self._restore(backup, rels, backed_up)
        detail = describe_losses(self._census_loss or {})
        try:
            from .alerts_local import record_local_alert
            record_local_alert(
                "census_loss_rollback", new_version,
                f"update to {new_version} coincided with lost "
                f"conversation content ({detail}); rolled back to "
                f"{self.current_version}",
                state_dir=self.state_dir)
        except Exception:
            pass
        raise UpdateError(
            f"conversation census loss during update to "
            f"{new_version} ({detail}); rolled back to "
            f"{self.current_version} from {backup}")

    def fetch_manifest(self) -> dict:
        raw = _fetch(f"{self.base}/{MANIFEST_NAME}")
        manifest = json.loads(raw)
        if "version" not in manifest or "files" not in manifest:
            raise UpdateError("manifest missing version/files")
        return manifest

    def check(self) -> dict:
        manifest = self.fetch_manifest()
        return {"current": self.current_version,
                "available": manifest["version"],
                "update_available":
                    _vtuple(manifest["version"]) > _vtuple(self.current_version),
                "files": len(manifest["files"])}

    def apply(self, manifest: dict | None = None, force: bool = False) -> dict:
        manifest = manifest or self.fetch_manifest()
        new_version = manifest["version"]
        if not force and _vtuple(new_version) <= _vtuple(self.current_version):
            return {"updated": False, "reason": "already up to date",
                    "version": self.current_version}
        # Immortality gate (v1.3.2): census BEFORE anything changes.
        census_before = self._census_before()
        # 1) Download + verify EVERY file before writing anything.
        payloads: dict[str, bytes] = {}
        for rel, want_sha in manifest["files"].items():
            if rel.startswith("/") or ".." in Path(rel).parts:
                raise UpdateError(f"unsafe path in manifest: {rel}")
            data = _fetch(f"{self.base}/{rel}")
            got = hashlib.sha256(data).hexdigest()
            if got != want_sha:
                raise UpdateError(
                    f"sha256 mismatch for {rel}: manifest {want_sha}, got {got}")
            payloads[rel] = data
        # 2) Back up current files.
        stamp = time.strftime("%Y%m%d%H%M%S")
        backup = self.state_dir / "update-backups" / stamp
        backup.mkdir(parents=True, exist_ok=True)
        backed_up = []
        for rel in payloads:
            src = self.install_dir / rel
            if src.exists():
                dst = backup / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                backed_up.append(rel)
        (backup / "VERSION").write_text(self.current_version)
        # 3) Install.
        for rel, data in payloads.items():
            dst = self.install_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_suffix(dst.suffix + ".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, dst)
        # 4) Health check; roll back automatically on failure.
        if not self._health_check(new_version):
            self._restore(backup, payloads.keys(), backed_up)
            try:
                from .alerts_local import record_local_alert
                record_local_alert(
                    "update_rollback", new_version,
                    f"update to {new_version} failed its health check"
                    f" and was rolled back to {self.current_version}",
                    state_dir=self.state_dir)
            except Exception:
                pass
            raise UpdateError(
                f"health check failed after installing {new_version};"
                f" rolled back to {self.current_version} from {backup}")
        # 5) Immortality gate (v1.3.2): a clean file swap over a
        # store that lost conversations is still a failed update.
        if not self._census_intact(census_before):
            self._fail_census_loss(backup, payloads.keys(), backed_up,
                                   new_version)
        return {"updated": True, "from": self.current_version,
                "to": new_version, "backup": str(backup),
                "restart": "restart the agent daemon to pick up the new"
                           " code (e.g. systemctl --user restart"
                           " agentlink-agent); live connections are not"
                           " dropped by the update itself"}

    def _restore(self, backup: Path, rels, backed_up) -> None:
        for rel in rels:
            dst = self.install_dir / rel
            if rel in backed_up:
                shutil.copy2(backup / rel, dst)
            elif dst.exists():
                dst.unlink()

    # -- staged apply (in-daemon self-update, v1.1.8) -------------------

    @staticmethod
    def _safe_rel(rel: str) -> None:
        if rel.startswith("/") or ".." in Path(rel).parts:
            raise UpdateError(f"unsafe path in manifest: {rel}")

    def changed_files(self, manifest: dict) -> list[str]:
        """Manifest files whose on-disk SHA-256 differs from the
        manifest (a missing file counts as changed)."""
        out = []
        for rel, want in manifest["files"].items():
            self._safe_rel(rel)
            cur = self.install_dir / rel
            if not cur.exists() or \
                    hashlib.sha256(cur.read_bytes()).hexdigest() != want:
                out.append(rel)
        return out

    def _import_check(self, tree: Path, expect_version: str) -> bool:
        """Subprocess import smoke: a fresh interpreter imports the
        package FROM ``tree`` and must report ``expect_version``."""
        code = ("import agentlink, sys;"
                "sys.exit(0 if agentlink.__version__ == "
                f"{expect_version!r} else 1)")
        env = dict(os.environ)
        env["PYTHONPATH"] = str(tree) + os.pathsep + env.get("PYTHONPATH", "")
        try:
            proc = subprocess.run([sys.executable, "-c", code],
                                  capture_output=True, timeout=30, env=env,
                                  cwd=str(tree))
            return proc.returncode == 0
        except Exception:
            return False

    def apply_staged(self, manifest: dict | None = None,
                     force: bool = False) -> dict:
        """Staged, smoke-tested apply (see prepare_staged /
        finish_staged). Kept as one call for tests and tooling; the
        daemon drives the two phases separately so it can drain
        in-flight operations and checkpoint between them."""
        prepared = self.prepare_staged(manifest, force)
        if not prepared.get("prepared"):
            return prepared
        return self.finish_staged(prepared)

    def prepare_staged(self, manifest: dict | None = None,
                       force: bool = False) -> dict:
        """Phases 1–3 of the staged apply: version gate → download +
        SHA-256-verify ONLY the changed files (any mismatch aborts)
        → stage the complete new tree under the state dir → subprocess
        import smoke against the STAGED tree (failure aborts).
        Writes NOTHING to the install tree. Returns a handle dict
        with ``prepared: True`` for finish_staged()/discard_staged(),
        or a no-op result (``prepared: False``, ``updated: False``).
        """
        manifest = manifest or self.fetch_manifest()
        new_version = manifest["version"]
        if not force and _vtuple(new_version) <= _vtuple(self.current_version):
            return {"prepared": False, "updated": False,
                    "reason": "already up to date",
                    "version": self.current_version}
        changed = self.changed_files(manifest)
        if not changed:
            return {"prepared": False, "updated": False,
                    "reason": "all files already match the manifest",
                    "version": self.current_version,
                    "available": new_version}
        # 1) Download + verify the changed files before writing.
        payloads: dict[str, bytes] = {}
        for rel in changed:
            data = _fetch(f"{self.base}/{rel}")
            got = hashlib.sha256(data).hexdigest()
            if got != manifest["files"][rel]:
                raise UpdateError(
                    f"sha256 mismatch for {rel}: manifest"
                    f" {manifest['files'][rel]}, got {got}")
            payloads[rel] = data
        # 2) Stage the complete new tree (changed payloads + current
        # bytes for everything the manifest leaves unchanged).
        stamp = time.strftime("%Y%m%d%H%M%S")
        stage = self.state_dir / "update-staging" / stamp
        if stage.exists():  # same-second re-run: never merge stale trees
            stage = self.state_dir / "update-staging" / (stamp + "-2")
        for rel in manifest["files"]:
            dst = stage / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if rel in payloads:
                dst.write_bytes(payloads[rel])
            else:
                shutil.copy2(self.install_dir / rel, dst)
        # 3) Smoke test the STAGED tree; a failure aborts the swap.
        if not self._import_check(stage, new_version):
            shutil.rmtree(stage, ignore_errors=True)
            raise UpdateError(
                f"staged tree for {new_version} failed the import"
                " smoke test; nothing was installed")
        return {"prepared": True, "new_version": new_version,
                "payloads": payloads, "stage": stage, "stamp": stamp}

    def discard_staged(self, prepared: dict) -> None:
        """Throw away a prepared (staged, smoke-passed) tree without
        installing it — the daemon does this when the continuity
        drain times out and the update defers to the next check."""
        stage = prepared.get("stage")
        if stage is not None:
            shutil.rmtree(stage, ignore_errors=True)

    def finish_staged(self, prepared: dict) -> dict:
        """Phases 4–6 of the staged apply, consuming a handle from
        prepare_staged(): timestamped rollback backup of the files
        being replaced → atomic per-file swap → health check of the
        installed tree, automatic rollback on failure (the same
        contract as apply()).
        """
        if not prepared.get("prepared"):
            raise UpdateError("finish_staged called on an unprepared"
                              " handle")
        new_version = prepared["new_version"]
        payloads = prepared["payloads"]
        stamp = prepared["stamp"]
        stage = prepared["stage"]
        # Immortality gate (v1.3.2): census BEFORE the swap.
        census_before = self._census_before()
        # 4) Back up the current copies of everything being replaced.
        backup = self.state_dir / "update-backups" / stamp
        backup.mkdir(parents=True, exist_ok=True)
        backed_up = []
        for rel in payloads:
            src = self.install_dir / rel
            if src.exists():
                dst = backup / rel
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                backed_up.append(rel)
        (backup / "VERSION").write_text(self.current_version)
        # 5) Atomic per-file swap.
        for rel, data in payloads.items():
            dst = self.install_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            tmp = dst.with_suffix(dst.suffix + ".tmp")
            tmp.write_bytes(data)
            os.replace(tmp, dst)
        shutil.rmtree(stage, ignore_errors=True)
        # 6) Health check the installed tree; roll back on failure.
        if not self._health_check(new_version):
            self._restore(backup, payloads.keys(), backed_up)
            try:
                from .alerts_local import record_local_alert
                record_local_alert(
                    "update_rollback", new_version,
                    f"update to {new_version} failed its health check"
                    f" and was rolled back to {self.current_version}",
                    state_dir=self.state_dir)
            except Exception:
                pass
            raise UpdateError(
                f"health check failed after installing {new_version};"
                f" rolled back to {self.current_version} from {backup}")
        # 7) Immortality gate (v1.3.2): as in apply() — the swap is
        # only a success while every conversation survives it.
        if not self._census_intact(census_before):
            self._fail_census_loss(backup, payloads.keys(), backed_up,
                                   new_version)
        return {"updated": True, "from": self.current_version,
                "to": new_version, "backup": str(backup),
                "changed": sorted(payloads), "staged_smoke": True,
                "restart": "the daemon re-execs itself to run the new"
                           " code; no supervisor or cron is involved"}

    def check_and_apply_staged(self) -> dict:
        """One in-daemon check tick. Never raises for feed problems:
        the result dict carries ``error`` instead, and the daemon
        keeps running its current code and retries next interval."""
        try:
            manifest = self.fetch_manifest()
        except Exception as exc:
            return {"updated": False,
                    "error": f"manifest fetch failed: {exc}"}
        try:
            return self.apply_staged(manifest)
        except UpdateError as exc:
            return {"updated": False, "error": str(exc)}
        except Exception as exc:
            return {"updated": False,
                    "error": f"{type(exc).__name__}: {exc}"}

    def _health_check(self, expect_version: str) -> bool:
        code = ("import agentlink, sys;"
                "sys.exit(0 if agentlink.__version__ == "
                f"{expect_version!r} else 1)")
        env = dict(os.environ)
        env["PYTHONPATH"] = str(self.install_dir) + os.pathsep + \
            env.get("PYTHONPATH", "")
        try:
            proc = subprocess.run([sys.executable, "-c", code],
                                  capture_output=True, timeout=30, env=env,
                                  cwd=str(self.install_dir))
            return proc.returncode == 0
        except Exception:
            return False


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="agentlink update")
    ap.add_argument("--check", action="store_true",
                    help="only report whether an update exists")
    ap.add_argument("--base", default=None)
    ap.add_argument("--census", action="store_true",
                    help="guard the update with the conversation "
                         "census (immortality gate): census the store "
                         "before the swap and verify after — any lost "
                         "conversation, group or channel rolls the "
                         "update back and fails it loudly")
    ap.add_argument("--db", default="~/.agentlink/relay.db",
                    help="relay DB path (sqlite census store source; "
                         "the baseline lives beside it)")
    ap.add_argument("--census-baseline", default=None,
                    help="census baseline path (default: beside "
                         "--db, matching the relay boot gate)")
    args = ap.parse_args(argv)
    guard = None
    if args.census:
        from .backend import create_store
        from .census import CensusGuard
        store = create_store(db_path=args.db)
        baseline = args.census_baseline or str(
            Path(args.db).expanduser().parent / "census-baseline.json")
        guard = CensusGuard(store, baseline)
    up = Updater(base_url=args.base, census_guard=guard)
    if args.check:
        print(json.dumps(up.check(), indent=2))
        return 0
    print(json.dumps(up.apply(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
