"""v2.4.2 — FULL-REPLACEMENT updates (owner's ruling, restated
2026-11-10): an update replaces the installation ENTIRE. The old
updater overwrote files in place and (v2.0.11) mirror-purged
unlisted files inside the package dir — but the installation
itself survived: the pip metadata (dist-info) pip wrote at the
original install sits at the install ROOT, outside the purge's
governed scope, frozen at its first version forever (the fleet's
proof: code 2.4.1, `pip show` 2.2.1 / 1.3.0), and rollback backups
accumulated one per update, never pruned.

The pins:
(a) a file present in the old version but absent in the new one
    is GONE after update — both apply paths;
(b) stale dist-info (even SEVERAL, with wrong versions) is
    replaced: exactly one fresh dist-info remains and the
    pip-visible version == the code version after update;
(c) stale bytecode from the old version cannot shadow the new
    code: a sourceless ghost .pyc that imported before the update
    does not import after it, and no old __pycache__ survives;
(d) the agent state dir is untouched (identity/mailbox bytes
    identical);
(e) ONE rollback slot exists after an update, holding the whole
    previous tree; the NEXT successful update wipes it (the slot
    then holds the intermediate tree, not the original);
(+) a failed update (health check) restores the EXACT pre-update
    install — stale dist-info, ghost module and all;
(+) the first-boot self-clean converges a stale dist-info to the
    running version.
"""
from __future__ import annotations

import hashlib
import importlib.machinery
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from agentlink import __version__ as RUNNING_VERSION  # noqa: E402
from agentlink.updater import (Updater, UpdateError,  # noqa: E402
                               pip_visible_version,
                               self_clean_install)

_v = RUNNING_VERSION.split(".")
NEXT_VERSION = f"{_v[0]}.{_v[1]}.{int(_v[2]) + 1}"
NEXT2_VERSION = f"{_v[0]}.{_v[1]}.{int(_v[2]) + 2}"
OLD_VERSION = f"{_v[0]}.{_v[1]}.{int(_v[2]) - 1}"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bump(text: str, version: str) -> str:
    return re.sub(r'__version__ = "[^"]+"',
                  f'__version__ = "{version}"', text)


def _make_feed(tmp_path: Path, version: str, name: str = "feed") -> Path:
    """A release feed: the real package, version-bumped, with a
    manifest over exactly what ships (the 2.4.x manifest shape:
    relay.py/dashboard.py are source-only and never listed)."""
    feed = tmp_path / name
    pkg = feed / "agentlink"
    shutil.copytree(ROOT / "agentlink", pkg,
                    ignore=shutil.ignore_patterns("__pycache__"))
    init = pkg / "__init__.py"
    init.write_text(_bump(init.read_text(), version))
    old = json.loads((ROOT / "update-manifest.json").read_text())
    files = {}
    for rel in old["files"]:
        files[rel] = _sha((feed / rel).read_bytes())
    (feed / "update-manifest.json").write_text(
        json.dumps({"version": version, "files": files}))
    return feed


def _write_dist_info(install: Path, version: str) -> Path:
    dist = install / f"agentlink-{version}.dist-info"
    dist.mkdir(parents=True, exist_ok=True)
    (dist / "METADATA").write_text(
        f"Metadata-Version: 2.1\nName: agentlink\n"
        f"Version: {version}\n")
    (dist / "RECORD").write_text("")
    return dist


def _make_dirty_install(tmp_path: Path) -> Path:
    """A fake OLD install carrying every species of residue:
    a module the new release does not ship, TWO stale dist-infos
    with wrong versions, a legacy egg-info, a sourceless ghost
    .pyc that really imports, and stale __pycache__."""
    install = tmp_path / "install"
    pkg = install / "agentlink"
    shutil.copytree(ROOT / "agentlink", pkg,
                    ignore=shutil.ignore_patterns("__pycache__"))
    init = pkg / "__init__.py"
    init.write_text(_bump(init.read_text(), OLD_VERSION))
    # (a) a module the new manifest does not list
    (pkg / "removed_module.py").write_text("# old-version only\n")
    # (b) stale metadata: two dist-infos + an egg-info, all wrong
    _write_dist_info(install, "0.0.0")
    _write_dist_info(install, "9.9.9")
    egg = install / "agentlink.egg-info"
    egg.mkdir()
    (egg / "PKG-INFO").write_text(
        "Metadata-Version: 1.0\nName: agentlink\nVersion: 1.3.9\n")
    # (c) a sourceless ghost module: bytecode with NO source file.
    # Python imports a bare .pyc sitting in the package dir, so
    # this ghost is live code until the whole directory is removed.
    src = tmp_path / "ghost_src.py"
    src.write_text("GHOST = 'i survive overlay updates'\n")
    ghost_pyc = pkg / "ghost.pyc"
    import py_compile
    py_compile.compile(str(src), cfile=str(ghost_pyc), doraise=True)
    cache = pkg / "__pycache__"
    cache.mkdir(exist_ok=True)
    (cache / "removed_module.cpython-312.pyc").write_bytes(b"stale")
    (cache / "client.cpython-312.pyc").write_bytes(b"stale")
    return install


def _make_state(tmp_path: Path) -> Path:
    state = tmp_path / "state"
    state.mkdir(parents=True, exist_ok=True)
    (state / "secret-ghost.json").write_text(
        '{"username": "ghost", "secret": "same-bytes"}')
    (state / "mailbox-ghost.db").write_bytes(b"mailbox-bytes")
    return state


def _state_bytes(state: Path) -> dict:
    return {p.name: p.read_bytes()
            for p in sorted(state.iterdir()) if p.is_file()}


def _updater(feed, install, state) -> Updater:
    return Updater(base_url=feed.as_uri(), install_dir=install,
                   state_dir=state, current_version=OLD_VERSION)


def _import_probe(install: Path, code: str) -> subprocess.CompletedProcess:
    # `import agentlink` pulls third-party deps (websockets etc.),
    # so the probe keeps the ambient environment (the gate venv)
    # and only PREPENDS the install dir so the fake tree shadows
    # any real install. cwd is pinned INTO the install's parent:
    # for `-c`, sys.path[0] is the CWD, and a probe launched from
    # the repo root would resolve `agentlink` to the REPO tree no
    # matter what PYTHONPATH says.
    import os
    env = dict(os.environ)
    env["PYTHONPATH"] = str(install) + os.pathsep + \
        env.get("PYTHONPATH", "")
    return subprocess.run([sys.executable, "-c", code],
                          capture_output=True, text=True, env=env,
                          cwd=str(install), timeout=60)


_GHOST_PROBE = ("from agentlink import ghost;"
                "print(ghost.GHOST)")


def _ghost_importable(install: Path) -> bool:
    """True when the planted sourceless ghost really executes.

    The probe's interpreter must resolve `agentlink` to the fake
    install and nothing else — see _import_probe (PYTHONPATH
    prepend + cwd pinned into the install, since sys.path[0] for
    `-c` is the launch directory and otherwise shadows the fake
    tree with whatever checkout the suite runs from)."""
    return _import_probe(install, _GHOST_PROBE).returncode == 0


def _metadata_dirs(install: Path) -> list:
    return sorted(p.name for p in install.iterdir()
                  if p.is_dir() and (p.name.endswith(".dist-info")
                                     or p.name.endswith(".egg-info")))


def _assert_fully_replaced(install: Path, state: Path,
                           state_before: dict, version: str):
    pkg = install / "agentlink"
    # (a) the unlisted old module is gone
    assert not (pkg / "removed_module.py").exists()
    # (b) exactly one metadata dir, fresh, at the code's version
    assert _metadata_dirs(install) == [f"agentlink-{version}.dist-info"]
    assert pip_visible_version(install) == version
    probe = _import_probe(
        install,
        "import importlib.metadata;"
        "print(importlib.metadata.version('agentlink'))")
    assert probe.returncode == 0, probe.stderr
    assert probe.stdout.strip() == version
    # (c) the ghost cannot import anymore, and no STALE cache
    # entry survives: the health check's own import of the NEW
    # tree legitimately writes fresh bytecode for live modules,
    # but every cache entry must belong to a source file the new
    # version actually ships — nothing from the old tree's module
    # set may linger.
    assert not _ghost_importable(install)
    assert not (pkg / "ghost.pyc").exists()
    cache = pkg / "__pycache__"
    if cache.exists():
        for entry in cache.iterdir():
            mod = entry.name.split(".")[0]
            assert (pkg / f"{mod}.py").exists(), entry.name
    # the code itself reports the new version
    live = _import_probe(install, "import agentlink;"
                                  "print(agentlink.__version__)")
    assert live.stdout.strip() == version
    # (d) state byte-identical
    assert _state_bytes(state) == state_before


# ------------------------------------------------------------------
# the pins, on BOTH apply paths
# ------------------------------------------------------------------

def test_a_apply_full_replacement(tmp_path):
    install = _make_dirty_install(tmp_path)
    state = _make_state(tmp_path)
    before = _state_bytes(state)
    # the ghost really is live code before the update
    assert _ghost_importable(install)
    assert pip_visible_version(install) == "0.0.0"
    feed = _make_feed(tmp_path, NEXT_VERSION)
    result = _updater(feed, install, state).apply()
    assert result["updated"] is True
    assert result["replaced"] is True
    assert result["metadata_version"] == NEXT_VERSION
    _assert_fully_replaced(install, state, before, NEXT_VERSION)
    # (e) the ONE rollback slot holds the whole previous tree
    slot = Path(result["backup"])
    assert slot.name == "update-rollback-slot"
    assert (slot / "VERSION").read_text() == OLD_VERSION
    assert (slot / "agentlink" / "removed_module.py").exists()
    assert (slot / "agentlink-0.0.0.dist-info").is_dir()
    assert "agentlink/removed_module.py" in result["purged"]
    assert result["purged_caches"] >= 1


def test_a_staged_full_replacement(tmp_path):
    install = _make_dirty_install(tmp_path)
    state = _make_state(tmp_path)
    before = _state_bytes(state)
    feed = _make_feed(tmp_path, NEXT_VERSION)
    outcome = _updater(feed, install, state).check_and_apply_staged()
    assert outcome["updated"] is True
    assert outcome["replaced"] is True
    assert outcome["metadata_version"] == NEXT_VERSION
    _assert_fully_replaced(install, state, before, NEXT_VERSION)
    slot = Path(outcome["backup"])
    assert (slot / "VERSION").read_text() == OLD_VERSION


def test_e_slot_wiped_on_next_successful_update(tmp_path):
    install = _make_dirty_install(tmp_path)
    state = _make_state(tmp_path)
    feed1 = _make_feed(tmp_path, NEXT_VERSION, "feed1")
    first = _updater(feed1, install, state).apply()
    slot = Path(first["backup"])
    assert (slot / "agentlink" / "removed_module.py").exists()
    # a second update, driven as the intermediate version
    feed2 = _make_feed(tmp_path, NEXT2_VERSION, "feed2")
    up2 = Updater(base_url=feed2.as_uri(), install_dir=install,
                  state_dir=state, current_version=NEXT_VERSION)
    second = up2.apply()
    assert second["updated"] is True
    assert Path(second["backup"]) == slot
    # the slot now holds the INTERMEDIATE tree — the original
    # tree (and its unique residue) was wiped by this success
    assert (slot / "VERSION").read_text() == NEXT_VERSION
    assert not (slot / "agentlink" / "removed_module.py").exists()
    assert not (slot / "agentlink-0.0.0.dist-info").exists()
    assert (slot / f"agentlink-{NEXT_VERSION}.dist-info").is_dir()
    # no parked previous slot lingers either
    assert not list(state.glob("update-rollback-slot.prev-*"))
    assert pip_visible_version(install) == NEXT2_VERSION


def test_failed_update_restores_exact_install(tmp_path, monkeypatch):
    install = _make_dirty_install(tmp_path)
    state = _make_state(tmp_path)
    feed = _make_feed(tmp_path, NEXT_VERSION)
    up = _updater(feed, install, state)
    monkeypatch.setattr(up, "_health_check", lambda v: False)
    with pytest.raises(UpdateError):
        up.apply()
    pkg = install / "agentlink"
    # the EXACT pre-update install is back: old code, the unlisted
    # module, the ghost, and the stale metadata set
    assert f'__version__ = "{OLD_VERSION}"' in \
        (pkg / "__init__.py").read_text()
    assert (pkg / "removed_module.py").exists()
    assert (pkg / "ghost.pyc").exists()
    assert _ghost_importable(install)
    assert _metadata_dirs(install) == [
        "agentlink-0.0.0.dist-info", "agentlink-9.9.9.dist-info",
        "agentlink.egg-info"]
    assert pip_visible_version(install) == "0.0.0"


def test_self_clean_converges_stale_metadata(tmp_path):
    install = tmp_path / "install"
    pkg = install / "agentlink"
    shutil.copytree(ROOT / "agentlink", pkg,
                    ignore=shutil.ignore_patterns("__pycache__"))
    _write_dist_info(install, "0.0.0")
    state = _make_state(tmp_path)
    feed = _make_feed(tmp_path, RUNNING_VERSION)
    shutil.copy2(feed / "update-manifest.json",
                 install / "update-manifest.json")
    assert pip_visible_version(install) == "0.0.0"
    out = self_clean_install(install, state, RUNNING_VERSION)
    assert out["cleaned"] is True
    assert out["metadata_version"] == RUNNING_VERSION
    assert _metadata_dirs(install) == [
        f"agentlink-{RUNNING_VERSION}.dist-info"]
    assert pip_visible_version(install) == RUNNING_VERSION
