"""Conversation immortality (v1.3.2) — the owner's law as tests.

Owner's report (2026-11-02): after updates, WHOLE conversations
vanished from the dashboard (his phoenix<->beulah DM; the phoenix<->
deploy-probe drill history) while newer traffic rendered fine. Root
cause, proven against the production store before this fix: nothing
was deleted — Relay._conversations() composed the dashboard list
from list_audit(500), the 500 newest audit rows of EVERY kind, and
the presence/alert churn (856 of 1197 production rows) pushed every
real conversation older than the window out of the view. Store truth
at diagnosis: 3 conversations in the store, 1 in the snapshot, both
missing ones FULLY below the window floor (newest seq 1331 and 673
vs floor 1336).

These pins hold the law from here on:

* composition reads the FULL content history, so no quantity of
  feed noise can age a conversation out of existence;
* the census of a store is identical across a restart (fresh relay,
  cold caches) and equal to what the dashboard renders;
* the boot gate adopts a baseline, then DETECTS a loss loudly
  (alert + audit rows) without darkening the relay, exactly once;
* additions are never losses;
* a guarded update that coincides with a loss rolls back + fails.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import sqlite3
import threading
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from agentlink.census import (CensusGuard, CensusLossError,
                              census_digest, compute_census)
from agentlink.dashboard import DashboardServer
from agentlink.relay import Relay
from agentlink.store import Store
from agentlink.updater import Updater, UpdateError

OLD_DM_IDS = ["m-old-1", "m-old-2"]
PROBE_DM_IDS = ["m-probe-1", "m-probe-2", "m-probe-3"]
GROUP_IDS = ["m-grp-1", "m-grp-2"]


def _seed_conversations(store: Store) -> None:
    """Three conversations whose items are then buried under feed
    noise by the caller."""
    # The counterparties are the owner's production agents (the
    # exact threads of his 2026-11-02 report); register them so
    # the fixture models the production registry — since v1.6.1
    # the dashboard filing rule keys on registry membership.
    store.claim("beulah", "beulah", designation="production")
    store.claim("deploy-probe", "deploy-probe",
                designation="production")
    store.audit("message", "phoenix", target="beulah",
                ref_id=OLD_DM_IDS[0])
    store.audit("message", "beulah", target="phoenix",
                ref_id=OLD_DM_IDS[1])
    store.audit("message", "deploy-probe", target="phoenix",
                ref_id=PROBE_DM_IDS[0])
    store.audit("work_assigned", "phoenix", target="deploy-probe",
                work_id="w-probe-1")
    store.audit("message", "phoenix", target="deploy-probe",
                ref_id=PROBE_DM_IDS[1])
    store.audit("work_delivered", "deploy-probe", target="phoenix",
                work_id="w-probe-1")
    store.audit("message", "deploy-probe", target="phoenix",
                ref_id=PROBE_DM_IDS[2])
    store.audit("group_message", "phoenix", target="",
                group_id="g-family", ref_id=GROUP_IDS[0])
    store.audit("group_message", "beulah", target="",
                group_id="g-family", ref_id=GROUP_IDS[1])


def _flood_feed_noise(store: Store, n: int = 700) -> None:
    """Presence/alert churn — the rows that used to push real
    conversations out of the bounded window."""
    for i in range(n):
        kind = ("online", "offline", "alert")[i % 3]
        store.audit(kind, "someagent", ref_id="")


def _conv_map(convs) -> dict:
    return {c["key"]: sorted(i["id"] for i in c["items"])
            for c in convs}


EXPECTED = {
    "dm:beulah|phoenix": sorted(OLD_DM_IDS),
    "dm:deploy-probe|phoenix": sorted(
        PROBE_DM_IDS + ["w-probe-1", "w-probe-1"]),
    "group:g-family": sorted(GROUP_IDS),
}


def test_conversations_composed_from_full_history(tmp_path):
    relay = Relay(host="127.0.0.1", port=0,
                  db_path=str(tmp_path / "relay.db"),
                  dashboard_password="test")
    _seed_conversations(relay.store)
    _flood_feed_noise(relay.store)
    # Sanity: the old window really does bury them (the bug's shape).
    windowed = relay.store.list_audit(500)
    assert all(r["ref_id"] not in OLD_DM_IDS for r in windowed)
    got = _conv_map(relay._conversations())
    assert got == EXPECTED


def test_dashboard_payload_renders_every_conversation(tmp_path):
    relay = Relay(host="127.0.0.1", port=0,
                  db_path=str(tmp_path / "relay.db"),
                  dashboard_password="test")
    _seed_conversations(relay.store)
    _flood_feed_noise(relay.store)
    dash = DashboardServer(relay, "127.0.0.1", 0, "test")
    data = dash._serve_data()
    got = _conv_map(data["conversations"])
    assert got == EXPECTED
    # The activity FEED may stay a bounded window — labelled recent.
    assert len(data["activity"]) == 300


def test_census_identical_across_restart(tmp_path):
    db = str(tmp_path / "relay.db")
    relay1 = Relay(host="127.0.0.1", port=0, db_path=db,
                   dashboard_password="test")
    gid = relay1.store.create_group("Nova family", "phoenix", None)
    relay1.store.add_member(gid, "beulah", added_by="phoenix")
    _seed_conversations(relay1.store)
    _flood_feed_noise(relay1.store, 50)
    census1 = compute_census(relay1.store)
    assert census1["groups"] == [gid]
    assert set(census1["conversations"]) == set(EXPECTED)
    # Simulated restart: a brand-new relay + store handle on the
    # same file, all in-memory snapshot state cold.
    relay2 = Relay(host="127.0.0.1", port=0, db_path=db,
                   dashboard_password="test")
    census2 = compute_census(relay2.store)
    assert census_digest(census2) == census_digest(census1)
    # What the restarted relay RENDERS is the census, item for item
    # (work lifecycle rows share one work id across two items, so
    # the rendered list is the census set with lifecycle repeats).
    rendered = _conv_map(c for c in relay2._conversations()
                         if c["items"])
    assert rendered == EXPECTED
    # v1.3.3: the group created above ALSO renders as a
    # conversation — with zero items (first-class from creation).
    assert {c["key"] for c in relay2._conversations()
            if not c["items"]} == {"group:" + gid}
    assert {k: sorted(set(v)) for k, v in rendered.items()} == \
        census1["conversations"]


# -- the gate ---------------------------------------------------------

def _boot_relay(db_path: str) -> Relay:
    relay = Relay(host="127.0.0.1", port=0, db_path=db_path,
                  dashboard_password="test", dashboard_port=0)

    async def _run():
        await relay.start()
        await relay.stop()

    asyncio.run(_run())
    return relay


def test_boot_gate_adopts_then_detects_loss_loudly_once(tmp_path):
    db = str(tmp_path / "relay.db")
    store = Store(db)
    _seed_conversations(store)
    baseline = tmp_path / "census-baseline.json"
    assert not baseline.exists()
    # First boot: baseline adopted, no alert, relay served + stopped.
    _boot_relay(db)
    assert baseline.exists()
    store2 = Store(db)
    assert not [a for a in store2.list_alerts()
                if a["kind"] == "census_loss"]
    # A "bad migration" deletes one conversation's rows outright.
    conn = sqlite3.connect(db)
    conn.execute("DELETE FROM audit_log WHERE ref_id IN (?, ?)",
                 tuple(OLD_DM_IDS))
    conn.commit()
    conn.close()
    # Second boot: the loss is on the record — alert + audit — and
    # the relay STILL starts (loud, never dark).
    _boot_relay(db)
    store3 = Store(db)
    losses = [a for a in store3.list_alerts()
              if a["kind"] == "census_loss"]
    assert len(losses) == 1
    assert "dm:beulah|phoenix" in losses[0]["detail"]
    assert any(r["kind"] == "census_loss_detected"
               for r in store3.list_audit(50))
    # Third boot: re-baselined after the loud report — no re-alert.
    _boot_relay(db)
    store4 = Store(db)
    assert len([a for a in store4.list_alerts()
                if a["kind"] == "census_loss"]) == 1


def test_guard_additions_are_not_losses(tmp_path):
    store = Store(str(tmp_path / "relay.db"))
    _seed_conversations(store)
    guard = CensusGuard(store, tmp_path / "baseline.json")
    assert guard.verify()["status"] == "adopted"
    digest1 = census_digest(guard.load_baseline())
    # New content arrives (ordinary life): still ok, baseline grows.
    store.audit("message", "phoenix", target="beulah",
                ref_id="m-new-1")
    assert guard.verify()["status"] == "ok"
    assert census_digest(guard.load_baseline()) != digest1
    # An item vanishes: verify raises with the diff named.
    conn = sqlite3.connect(str(tmp_path / "relay.db"))
    conn.execute("DELETE FROM audit_log WHERE ref_id = 'm-new-1'")
    conn.commit()
    conn.close()
    with pytest.raises(CensusLossError) as ei:
        guard.verify()
    assert ei.value.diff["items_missing"]["dm:beulah|phoenix"] == \
        ["m-new-1"]
    # After the loud failure, explicit acceptance re-baselines.
    guard.accept_current()
    assert guard.verify()["status"] == "ok"


# -- the updater guard --------------------------------------------------

def _serve_dir(directory: Path):
    handler = lambda *a, **kw: SimpleHTTPRequestHandler(  # noqa: E731
        *a, directory=str(directory), **kw)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def _make_release(root: Path, version: str, init_body: str):
    pkg = root / "agentlink"
    pkg.mkdir(parents=True, exist_ok=True)
    body = init_body.encode()
    (pkg / "__init__.py").write_bytes(body)
    files = {"agentlink/__init__.py": hashlib.sha256(body).hexdigest()}
    (root / "update-manifest.json").write_text(
        json.dumps({"version": version, "files": files}))


def _guarded_updater(tmp_path, base, store):
    install = tmp_path / "install"
    (install / "agentlink").mkdir(parents=True, exist_ok=True)
    (install / "agentlink" / "__init__.py").write_text(
        '__version__ = "1.0.0"\n')
    guard = CensusGuard(store, tmp_path / "baseline.json")
    up = Updater(base_url=base, install_dir=install,
                 state_dir=tmp_path / "state", current_version="1.0.0",
                 census_guard=guard)
    return up, install


def test_guarded_update_clean_passes(tmp_path):
    store = Store(str(tmp_path / "relay.db"))
    _seed_conversations(store)
    rel = tmp_path / "release"
    rel.mkdir()
    _make_release(rel, "1.1.0", '__version__ = "1.1.0"\n')
    srv, base = _serve_dir(rel)
    try:
        up, install = _guarded_updater(tmp_path, base, store)
        result = up.apply()
        assert result["updated"] is True
        assert (install / "agentlink" / "__init__.py").read_text() == \
            '__version__ = "1.1.0"\n'
    finally:
        srv.shutdown()


def test_guarded_update_rolls_back_on_census_loss(tmp_path):
    store = Store(str(tmp_path / "relay.db"))
    _seed_conversations(store)
    rel = tmp_path / "release"
    rel.mkdir()
    _make_release(rel, "1.1.0", '__version__ = "1.1.0"\n')
    srv, base = _serve_dir(rel)
    try:
        up, install = _guarded_updater(tmp_path, base, store)
        real_health = up._health_check

        def _poisoned_health(version):
            # A "migration" landing mid-update deletes a whole
            # conversation; the file health check itself passes.
            conn = sqlite3.connect(str(tmp_path / "relay.db"))
            conn.execute(
                "DELETE FROM audit_log WHERE ref_id IN (?, ?)",
                tuple(OLD_DM_IDS))
            conn.commit()
            conn.close()
            return real_health(version)

        up._health_check = _poisoned_health
        with pytest.raises(UpdateError) as ei:
            up.apply()
        assert "census loss" in str(ei.value)
        # Rolled back: the old code is in place again.
        assert (install / "agentlink" / "__init__.py").read_text() == \
            '__version__ = "1.0.0"\n'
        # And the loss is on the store's record, loudly.
        assert any(a["kind"] == "census_loss"
                   for a in store.list_alerts())
    finally:
        srv.shutdown()
