"""v1.6.0 probe/test segregation — regression pins (owner's ruling
2026-11-04: probe tests must not disorganise the owner's main
dashboard; they get their own view, the production line stays
clean).

The design under test: segregation is by DESIGNATION +
server-side dashboard composition over the ONE shared store —
never by endpoint, never by username pattern, never
frontend-only filtering.

Pinned here:

  1. STORE DEFAULTS (both backends) — claim() without a
     designation stores production; claim(designation='test')
     stores test; an unknown designation normalises to
     production; list_users presents the designation on every
     row (anything not explicitly 'test' presents production).
  2. OPERATOR PATH — set_designation flips a registered agent,
     records an audit row (kind 'designation_changed'), refuses
     unknown values and unknown users, and is a no-op (no audit)
     when the value is already set. designation_of agrees.
  3. NO SELF-FLIP (live) — a test-designated agent that
     reconnects declaring 'production' keeps its stored test
     designation; a production agent declaring 'test' on a later
     hello stays production. The hello declaration is honoured
     ONLY by the claiming registration.
  4. PAYLOAD SPLIT (fixture shaped like production: 8 production
     + the owner's exact 7 test names = 15) — users/test_users
     split exactly; deploy-probe is PRODUCTION despite its name;
     splits sum to the totals (users, conversations).
  5. CONVERSATION RULES — a DM whose non-owner-seat participant
     is test files under test_conversations; a production DM
     stays; a group files under test iff EVERY member besides
     phoenix is test (mixed company stays production; a
     phoenix+only-test group files under test).
  6. WORK / CHAINS / LIBRARY / VAULT follow the same rule.
  7. IMMORTALITY — designation flips alone change NO census
     digest and no conversation/item totals.
  8. LEGACY CONSUMERS — the pre-split payload keys are all still
     present; the split keys are additive.
  9. LANDING — a plain relay's payload lands 'overview'; a
     per-agent server's (owner_agent set) lands 'probes'.
 10. CLIENT — Agent(designation='test') validates and declares;
     an invalid designation raises.
"""

from __future__ import annotations

import asyncio
import tempfile
import threading
from pathlib import Path

import pytest

from agentlink.census import census_digest, compute_census
from agentlink.client import Agent
from agentlink.relay import Relay
from agentlink.store import Store

HOST = "127.0.0.1"
DASH_PW = "probe-segregation-test-pw"

# The owner's production line and his exact retroactive test list
# (2026-11-04) — the fixture mirrors the production SHAPE; the
# live verification of these names is the production proof, not
# this file.
PRODUCTION = ["phoenix", "deploy-probe", "beulah", "swift-otter-7",
              "vertex-bcf0d5fb", "folk", "nova-bridge-7f3a",
              "agent-2eb7"]
TEST = ["folk-probe-6472", "glimmer_probe_tmp", "glimmer_muse6",
        "muse2", "muse3", "muse5", "toto"]


# ----------------------------------------------------------------------
# 1-2: the SQLite store
# ----------------------------------------------------------------------

def _store(tmp_path) -> Store:
    return Store(str(tmp_path / "relay.db"))


def test_designation_defaults_production_sqlite(tmp_path):
    s = _store(tmp_path)
    s.claim("plainagent", "Plain")
    assert s.designation_of("plainagent") == "production"
    rows = {u["username"]: u for u in s.list_users()}
    assert rows["plainagent"]["designation"] == "production"


def test_designation_declared_at_claim_sqlite(tmp_path):
    s = _store(tmp_path)
    s.claim("probeagent", "Probe", designation="test")
    assert s.designation_of("probeagent") == "test"
    rows = {u["username"]: u for u in s.list_users()}
    assert rows["probeagent"]["designation"] == "test"
    # Unknown declarations normalise to production, never error.
    s.claim("weirdagent", "Weird", designation="staging")
    assert s.designation_of("weirdagent") == "production"


def test_operator_set_designation_and_audit(tmp_path):
    s = _store(tmp_path)
    s.claim("someagent", "Some")
    assert s.set_designation("someagent", "test") is True
    assert s.designation_of("someagent") == "test"
    rows = [r for r in s.list_audit(500)
            if r["kind"] == "designation_changed"]
    assert len(rows) == 1
    assert rows[0]["from"] == "operator"
    assert rows[0]["to"] == "someagent"
    assert rows[0]["status"] == "test"
    # Same value again: no change, no second audit row.
    assert s.set_designation("someagent", "test") is False
    rows = [r for r in s.list_audit(500)
            if r["kind"] == "designation_changed"]
    assert len(rows) == 1
    # And back, recorded too.
    assert s.set_designation("someagent", "production") is True
    assert s.designation_of("someagent") == "production"
    # Refusals: unknown value, unknown user.
    assert s.set_designation("someagent", "staging") is False
    assert s.set_designation("ghostagent", "test") is False
    assert s.designation_of("ghostagent") == "production"


# ----------------------------------------------------------------------
# 1-2: the Supabase store (fake transport, the vault-parity pattern)
# ----------------------------------------------------------------------

def _supabase_fake():
    from agentlink.supabase_store import SupabaseStore
    store = SupabaseStore("https://example.invalid", "k")
    rows: dict[str, dict] = {}
    calls: list = []

    def fake_get(table, query):
        assert table == "users"
        out = [dict(r) for r in rows.values()]
        if query and "username=eq." in query:
            name = query.split("username=eq.")[1].split("&")[0]
            out = [r for r in out if r["username"] == name]
        return out

    def fake_req(method, table, query=None, body=None, prefer=None):
        calls.append((method, table, query, body))
        if method == "POST" and table == "users":
            rows[body["username"]] = dict(body)
            return None
        if method == "PATCH" and table == "users":
            name = query.split("eq.")[1].split("&")[0]
            rows[name].update(body or {})
            return None
        return None

    store._get = fake_get
    store._req = fake_req
    return store, rows, calls


def test_designation_supabase_store_parity():
    store, rows, calls = _supabase_fake()
    store.claim("plainagent", "Plain")
    assert rows["plainagent"]["designation"] == "production"
    store.claim("probeagent", "Probe", designation="test")
    assert rows["probeagent"]["designation"] == "test"
    store.claim("weirdagent", "Weird", designation="staging")
    assert rows["weirdagent"]["designation"] == "production"
    listed = {u["username"]: u for u in store.list_users()}
    assert listed["probeagent"]["designation"] == "test"
    assert listed["plainagent"]["designation"] == "production"
    # Operator path: PATCH + audit POST, same semantics as SQLite.
    audits = []
    store.audit = lambda *a, **k: audits.append((a, k))
    assert store.set_designation("plainagent", "test") is True
    assert rows["plainagent"]["designation"] == "test"
    assert audits and audits[0][0][0] == "designation_changed"
    assert store.set_designation("plainagent", "test") is False
    assert store.set_designation("plainagent", "staging") is False
    assert store.set_designation("ghostagent", "test") is False
    assert store.designation_of("probeagent") == "test"
    assert store.designation_of("ghostagent") == "production"


# ----------------------------------------------------------------------
# 4-9: the dashboard payload split
# ----------------------------------------------------------------------

def _relay(tmp_path) -> Relay:
    return Relay(host=HOST, port=0, db_path=str(tmp_path / "relay.db"),
                 dashboard_password=DASH_PW)


def _seeded_relay(tmp_path) -> Relay:
    relay = _relay(tmp_path)
    s = relay.store
    for name in PRODUCTION:
        # deploy-probe is claimed production EXPLICITLY here: its
        # name must never be what decides (no name inference).
        s.claim(name, name, designation="production")
    for name in TEST:
        s.claim(name, name, designation="test")
    # DMs.
    s.audit("message", "phoenix", target="muse2", ref_id="dm-t1")
    s.audit("message", "muse2", target="phoenix", ref_id="dm-t2")
    s.audit("message", "phoenix", target="beulah", ref_id="dm-p1")
    s.audit("message", "muse2", target="muse3", ref_id="dm-t3")
    # Groups: all-test (no phoenix), phoenix+only-test, mixed.
    g_test = s.create_group("probe lab", "muse2", None)
    for m in ("muse2", "muse3", "toto"):
        s.add_member(g_test, m, added_by="muse2")
    g_seat = s.create_group("seat and probes", "phoenix", None)
    for m in ("phoenix", "muse2", "muse3"):
        s.add_member(g_seat, m, added_by="phoenix")
    g_mixed = s.create_group("mixed company", "phoenix", None)
    for m in ("phoenix", "beulah", "muse2"):
        s.add_member(g_mixed, m, added_by="phoenix")
    s.audit("group_message", "muse2", group_id=g_test, ref_id="gm-t1")
    s.audit("group_message", "beulah", group_id=g_mixed,
            ref_id="gm-p1")
    # Work: test (phoenix->muse2), production (phoenix->beulah),
    # test-only (muse2->muse3).
    w_test = s.create_work("phoenix", "muse2", None, {}, {}, None)
    w_prod = s.create_work("phoenix", "beulah", None, {}, {}, None)
    s.create_work("muse2", "muse3", None, {}, {}, None)
    # Library: the test work's delivery files under test; the
    # production work's under production.
    s.add_library_entries("del-t", w_test,
                          [{"name": "probe.txt", "size": 3,
                            "sha256": "a" * 64}])
    s.add_library_entries("del-p", w_prod,
                          [{"name": "real.txt", "size": 3,
                            "sha256": "b" * 64}])
    # Group vault: an entry in the all-test group by a test agent;
    # an entry in the mixed group by a production agent.
    s.vault_add(g_test, {"name": "probe-file", "size": 1,
                         "sha256": "c" * 64}, "muse2")
    s.vault_add(g_mixed, {"name": "real-file", "size": 1,
                          "sha256": "d" * 64}, "beulah")
    # Chains: a test chain (test creator, test step target) and a
    # production chain.
    s.create_chain("muse2", "", "probe chain",
                   [{"target_type": "user", "target": "muse3",
                     "assignees": ["muse3"], "content_group": {}}])
    s.create_chain("phoenix", "", "real chain",
                   [{"target_type": "user", "target": "beulah",
                     "assignees": ["beulah"], "content_group": {}}])
    relay._test_ids = {"g_test": g_test, "g_seat": g_seat,
                       "g_mixed": g_mixed}
    return relay


def test_payload_split_users_exact(tmp_path):
    relay = _seeded_relay(tmp_path)
    d = relay._dashboard_data()
    assert [u["username"] for u in d["users"]] == sorted(PRODUCTION)
    assert [u["username"] for u in d["test_users"]] == sorted(TEST)
    assert len(d["users"]) + len(d["test_users"]) == 15
    # deploy-probe: production, permanently, name notwithstanding.
    assert "deploy-probe" in [u["username"] for u in d["users"]]
    # Online lists split the same way.
    assert set(d["online"]) <= set(PRODUCTION)
    assert set(d["test_online"]) <= set(TEST)


def test_payload_split_conversations(tmp_path):
    relay = _seeded_relay(tmp_path)
    d = relay._dashboard_data()
    prod_keys = {c["key"] for c in d["conversations"]}
    test_keys = {c["key"] for c in d["test_conversations"]}
    assert "dm:muse2|phoenix" in test_keys
    assert "dm:muse2|muse3" in test_keys
    assert "dm:beulah|phoenix" in prod_keys
    ids = relay._test_ids
    assert ids["g_test"] in {c["group_id"]
                             for c in d["test_conversations"]}
    # phoenix + only test members: every member besides phoenix is
    # test, so the group files under test (the stated rule).
    assert ids["g_seat"] in {c["group_id"]
                             for c in d["test_conversations"]}
    # Mixed company stays production.
    assert ids["g_mixed"] in {c["group_id"]
                              for c in d["conversations"]}
    # The split partitions the conversation list: sums to the
    # un-split total, nothing dropped, nothing duplicated.
    all_convs = relay._conversations()
    assert len(d["conversations"]) + len(d["test_conversations"]) \
        == len(all_convs)
    assert prod_keys.isdisjoint(test_keys)
    # Groups split the same way.
    assert {g["id"] for g in d["test_groups"]} == {
        ids["g_test"], ids["g_seat"]}
    assert {g["id"] for g in d["groups"]} == {ids["g_mixed"]}


def test_payload_split_work_chains_library_vault(tmp_path):
    relay = _seeded_relay(tmp_path)
    d = relay._dashboard_data()
    assert len(d["work"]) == 1 and len(d["test_work"]) == 2
    assert {w["assignee"] for w in d["test_work"]} == {"muse2",
                                                       "muse3"}
    assert {w["assignee"] for w in d["work"]} == {"beulah"}
    assert len(d["chains"]) == 1 and len(d["test_chains"]) == 1
    assert d["test_chains"][0]["creator"] == "muse2"
    assert {e["filename"] for e in d["test_library"]} == {"probe.txt"}
    assert {e["filename"] for e in d["library"]} == {"real.txt"}
    assert {v["name"] for v in d["test_vault"]} == {"probe-file"}
    assert {v["name"] for v in d["vault"]} == {"real-file"}


def test_designation_alone_changes_no_census(tmp_path):
    relay = _seeded_relay(tmp_path)
    before = census_digest(compute_census(relay.store))
    convs_before = len(relay._conversations())
    # Operator flips in both directions.
    assert relay.store.set_designation("beulah", "test") is True
    assert relay.store.set_designation("muse2", "production") is True
    after = census_digest(compute_census(relay.store))
    assert after == before
    assert len(relay._conversations()) == convs_before
    # Composition follows the flips (proof the census equality is
    # not masking a frozen payload).
    d = relay._dashboard_data()
    names_test = {u["username"] for u in d["test_users"]}
    assert "beulah" in names_test and "muse2" not in names_test


def test_payload_legacy_keys_and_landing(tmp_path):
    relay = _seeded_relay(tmp_path)
    d = relay._dashboard_data()
    for key in ("server", "servers", "online", "users", "groups",
                "channels", "rooms", "work", "alerts", "chains",
                "library", "vault", "conversations", "activity"):
        assert key in d, f"legacy key {key} missing"
    for key in ("test_users", "test_groups", "test_channels",
                "test_online", "test_work", "test_chains",
                "test_library", "test_vault", "test_conversations",
                "landing"):
        assert key in d, f"split key {key} missing"
    assert d["landing"] == "overview"
    # A per-agent server (owner_agent set) lands on Probe Tests.
    relay2 = Relay(host=HOST, port=0,
                   db_path=str(tmp_path / "relay2.db"),
                   dashboard_password=DASH_PW,
                   owner_agent="deploy-probe")
    assert relay2._dashboard_data()["landing"] == "probes"


# ----------------------------------------------------------------------
# 3 + 10: live hello behaviour
# ----------------------------------------------------------------------

@pytest.fixture()
def relay_env():
    tmp = tempfile.mkdtemp(prefix="agentlink-seg-")
    db = str(Path(tmp) / "relay.db")
    relay = Relay(host=HOST, port=0, db_path=db,
                  dashboard_password=DASH_PW, dashboard_port=0)
    ready = threading.Event()
    box: dict = {}

    def _thread():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        box["loop"] = loop

        async def _serve():
            await relay.start()
            ready.set()
            await asyncio.Future()

        try:
            loop.run_until_complete(_serve())
        except (RuntimeError, asyncio.CancelledError):
            pass

    t = threading.Thread(target=_thread, daemon=True)
    t.start()
    assert ready.wait(timeout=10)
    yield {"url": f"ws://{HOST}:{relay.port}", "relay": relay}
    fut = asyncio.run_coroutine_threadsafe(relay.stop(), box["loop"])
    fut.result(timeout=10)


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(prefix="agentlink-seg-agents-") as tmp:
        yield Path(tmp)


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


async def _make(relay_env, state_root, username, **kw):
    a = Agent(username, endpoint=relay_env["url"],
              state_dir=str(state_root / username), **kw)
    await a.start()
    return a


def test_registration_designation_lands_and_no_self_flip(relay_env,
                                                         state_root):
    async def main():
        probe = await _make(relay_env, state_root, "seg-probe",
                            designation="test")
        plain = await _make(relay_env, state_root, "seg-plain")
        assert probe.whoami()["designation"] == "test"
        assert plain.whoami()["designation"] == "production"
        store = relay_env["relay"].store
        assert store.designation_of("seg-probe") == "test"
        assert store.designation_of("seg-plain") == "production"
        d = relay_env["relay"]._dashboard_data()
        assert "seg-probe" in {u["username"]
                               for u in d["test_users"]}
        assert "seg-plain" in {u["username"] for u in d["users"]}
        await probe.close()
        await plain.close()
        # SELF-FLIP ATTEMPTS: same identities (same state dirs),
        # opposite declarations. The stored designations must not
        # move — the hello declaration binds only at registration.
        probe2 = await _make(relay_env, state_root, "seg-probe",
                             designation="production")
        plain2 = await _make(relay_env, state_root, "seg-plain",
                             designation="test")
        assert store.designation_of("seg-probe") == "test"
        assert store.designation_of("seg-plain") == "production"
        await probe2.close()
        await plain2.close()

    run(main())


def test_client_designation_validation():
    with pytest.raises(ValueError):
        Agent("badseg", designation="staging")
    a = Agent("okseg", designation="test")
    assert a.designation == "test"
    b = Agent("okseg2")
    assert b.designation == "production"


# ----------------------------------------------------------------------
# 11: checkpoint-before-ingestion (v1.6.0 hardening, found by the gate)
# ----------------------------------------------------------------------

def test_checkpoint_before_ingestion_fetches_and_mirrors(
        relay_env, state_root, tmp_path):
    """The v1.6.0 gate root-caused a latent checkpoint() defect
    (present since point 30, in code v1.6.0 did not otherwise
    touch): checkpoint() resolved the work from the local journal
    / assigned list only, and when the assignment's push had not
    been ingested yet — a checkpoint recorded the moment work
    lands races that push — it returned SILENTLY, the backend
    mirror stayed empty, and a later restart (43d's scenario) had
    nothing to recover. Recorded live in the gate evidence:
    checkpoint_call with journal=False, assigned=False, and the
    relay's work row checkpoint=None afterwards.

    The fix: unknown-locally work is fetched from the backend
    inbox, journaled, checkpointed locally, and mirrored as
    usual; a work id the backend does not hold for the agent
    raises loudly. This pin forces the not-ingested state
    deterministically (fresh journal + cleared assigned list)."""
    from agentlink.client import TaskJournal

    async def main():
        boss = await _make(relay_env, state_root, "cp-boss")
        w = await _make(relay_env, state_root, "cp-worker")
        g = await boss.group_create("CpG", ["cp-worker"])
        gid = g["group_id"]
        job = (await boss.assign_work(["cp-worker"], "cp job",
                                      group_id=gid))[0]
        # Force the not-yet-ingested state.
        w._journal = TaskJournal(str(tmp_path / "fresh-journal.db"))
        w.assigned_work.clear()
        await w.checkpoint(job["id"], {"stage": "kept"})
        # The mirror landed on the relay this time.
        raw = relay_env["relay"].store.get_work(job["id"])
        assert raw is not None and raw.get("checkpoint")
        assert raw["checkpoint"].get("content_group") or \
            raw["checkpoint"].get("content_assigner")
        # And the local journal carries it (journal-first order).
        entry = w._journal.get(job["id"])
        assert entry is not None
        assert entry.get("checkpoint") == {"stage": "kept"}
        # A work id the backend does not hold: loud, never silent.
        with pytest.raises(ValueError):
            await w.checkpoint("w-doesnotexist", {"stage": "x"})
        await boss.close()
        await w.close()

    run(main())
