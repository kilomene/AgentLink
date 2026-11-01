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
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _vtuple(v: str) -> tuple:
    return tuple(int(x) for x in v.split(".") if x.isdigit())


class Updater:
    def __init__(self, base_url: str | None = None,
                 install_dir: str | Path | None = None,
                 state_dir: str | Path = "~/.agentlink",
                 current_version: str = __version__):
        self.base = (base_url or os.environ.get("AGENTLINK_UPDATE_BASE")
                     or DEFAULT_UPDATE_BASE).rstrip("/")
        # install_dir = the directory that CONTAINS the agentlink package
        self.install_dir = Path(install_dir) if install_dir else \
            Path(__file__).resolve().parent.parent
        self.state_dir = Path(state_dir).expanduser()
        self.current_version = current_version

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
    args = ap.parse_args(argv)
    up = Updater(base_url=args.base)
    if args.check:
        print(json.dumps(up.check(), indent=2))
        return 0
    print(json.dumps(up.apply(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
