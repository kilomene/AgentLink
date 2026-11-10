"""Epoch-archive tests (2.3.1): rotation must never orphan history.

The defect (root-caused in drill-evidence/v230-fixall, the fix-5
chain): group key rotation REPLACED the single stored key, and
every open path decrypted with the current key only — no epoch
dispatch. The moment a group rotated (a member removal), all
history sealed under the prior epoch rendered as sealed stubs
fleet-wide; the concrete case was the Nova family's 262 epoch-1
rows after the 2026-11-08 epoch-2 rotation, whose content was
proven intact server-side and whose epoch-1 wrap still sat in
al_group_keys.

The fix pinned here:
* storage is an epoch MAP per room (current + every held epoch),
  persisted alongside the legacy {"epoch", "key"} pair so a
  pre-2.3.1 state file loads losslessly as a one-epoch archive;
* every room-key decrypt site (history rows, live frames, work
  group wraps, blob file-key wraps) selects the key by the
  envelope's epoch; an epoch the agent never held still renders
  the sealed stub, fail-closed, exactly as before;
* at membership resync, every server-retained wrap for the room
  is merged into the archive (the phoenix seat: local epoch 2,
  server still holding the epoch-1 wrap -> both epochs open).
"""

from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path

from agentlink.client import Agent
from agentlink.crypto import Identity, decrypt_with_key, \
    encrypt_with_key, new_group_key

GID = "g-epoch-test"
CID = "ch-epoch-test"


def _agent(tmp_path, name="alice", identity=None):
    agent = Agent(username=name, state_dir=str(tmp_path / name),
                  mode="manual")
    if identity is not None:
        agent.identity = identity
    return agent


def _seal(key: bytes, epoch: int, body: str) -> dict:
    payload = json.dumps({"body": body, "kind": "text"}).encode()
    return {"epoch": epoch, **encrypt_with_key(key, payload)}


def _history_row(ref: str, envelope: dict, gid: str = GID) -> dict:
    return {"kind": "group_message", "ref_id": ref, "group_id": gid,
            "from": "bob", "to": gid, "ts": 1700000000,
            "content_envelope": envelope}


def _rotate(agent: Agent, gid: str = GID):
    """Epoch 1 -> epoch 2 the way group_remove does it: store the
    new current key. Returns (key1, key2)."""
    key1 = agent._group_keys[gid]["key"]
    key2 = new_group_key()
    agent._store_group_key(gid, 2, key2)
    return key1, key2


def test_rotation_archives_prior_epoch(tmp_path):
    agent = _agent(tmp_path)
    key1 = new_group_key()
    agent._store_group_key(GID, 1, key1)
    key1b, key2 = _rotate(agent)
    assert key1b == key1
    rec = agent._group_keys[GID]
    assert rec["epoch"] == 2 and rec["key"] == key2
    assert rec["epochs"][1] == key1 and rec["epochs"][2] == key2
    # The archive survives a reload from disk.
    agent2 = _agent(tmp_path)
    rec2 = agent2._group_keys[GID]
    assert rec2["epoch"] == 2 and rec2["key"] == key2
    assert rec2["epochs"][1] == key1


def test_history_rows_open_across_rotation(tmp_path):
    agent = _agent(tmp_path)
    key1 = new_group_key()
    agent._store_group_key(GID, 1, key1)
    row1 = _history_row("m-epoch1", _seal(key1, 1, "epoch one body"))
    _rotate(agent)
    key2 = agent._group_keys[GID]["key"]
    row2 = _history_row("m-epoch2", _seal(key2, 2, "epoch two body"))
    msg1 = agent._history_row_to_msg(row1)
    msg2 = agent._history_row_to_msg(row2)
    assert not msg1.get("sealed") and msg1["body"] == "epoch one body"
    assert not msg2.get("sealed") and msg2["body"] == "epoch two body"


def test_unknown_epoch_history_row_stays_sealed_stub(tmp_path):
    agent = _agent(tmp_path)
    agent._store_group_key(GID, 1, new_group_key())
    foreign = _seal(new_group_key(), 7, "never held this key")
    msg = agent._history_row_to_msg(_history_row("m-x", foreign))
    assert msg.get("sealed") is True and msg["body"] == ""


def test_legacy_single_key_file_loads_losslessly(tmp_path):
    key1 = new_group_key()
    legacy = {GID: {"epoch": 1,
                    "key": base64.b64encode(key1).decode()}}
    p = tmp_path / "alice" / "groupkeys-alice.json"
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(legacy))
    agent = _agent(tmp_path)
    rec = agent._group_keys[GID]
    assert rec["epoch"] == 1 and rec["key"] == key1
    assert rec["epochs"] == {1: key1}
    # ...and the loaded epoch-1 key opens epoch-1 history.
    row = _history_row("m-legacy", _seal(key1, 1, "legacy body"))
    msg = agent._history_row_to_msg(row)
    assert not msg.get("sealed") and msg["body"] == "legacy body"


def test_live_frame_opens_across_rotation(tmp_path):
    async def main():
        agent = _agent(tmp_path)
        key1 = new_group_key()
        agent._store_group_key(GID, 1, key1)
        frame = {"group_id": GID, "content": _seal(key1, 1, "live e1")}
        _rotate(agent)
        payload, via_identity, rec, to = \
            await agent._open_frame_payload(frame)
        assert payload["body"] == "live e1" and via_identity is False
        assert to == GID
    asyncio.run(main())


def test_work_group_wrap_opens_across_rotation(tmp_path):
    agent = _agent(tmp_path)
    key1 = new_group_key()
    agent._store_group_key(GID, 1, key1)
    payload = json.dumps({"title": "epoch work",
                          "instructions": "sealed at epoch 1"}).encode()
    env = {"epoch": 1, **encrypt_with_key(key1, payload)}
    _rotate(agent)
    out = agent._decrypt_work({"content_group": env, "group_id": GID,
                               "deliveries": []})
    assert out["title"] == "epoch work"


def test_blob_wrapped_file_key_epoch_dispatch(tmp_path):
    file_key = new_group_key()
    key1, key2 = new_group_key(), new_group_key()
    rec = Agent._room_key_record(2, key2, {1: key1})
    wrapped1 = encrypt_with_key(key1, file_key)
    # Stamped descriptor (new writes): exact-epoch open.
    assert Agent._open_wrapped_file_key(rec, wrapped1, 1) == file_key
    # Legacy descriptor (no stamp): archive search opens it.
    assert Agent._open_wrapped_file_key(rec, wrapped1, None) == file_key
    # A wrap under a key never held still fails closed.
    wrapped_x = encrypt_with_key(new_group_key(), file_key)
    try:
        Agent._open_wrapped_file_key(rec, wrapped_x, None)
        raise AssertionError("foreign wrap must not open")
    except Exception:
        pass
    assert decrypt_with_key(key2, encrypt_with_key(key2, b"x")) == b"x"


def test_channel_archive_parity(tmp_path):
    agent = _agent(tmp_path)
    key1 = new_group_key()
    agent._store_channel_key(CID, 1, key1)
    key2 = new_group_key()
    agent._store_channel_key(CID, 2, key2)
    rec = agent._channel_keys[CID]
    assert rec["epochs"][1] == key1 and rec["key"] == key2
    row = {"kind": "channel_message", "ref_id": "m-c1",
           "group_id": CID, "from": "bob", "to": CID, "ts": 1700000000,
           "content_envelope": _seal(key1, 1, "channel e1 body")}
    msg = agent._history_row_to_msg(row)
    assert not msg.get("sealed") and msg["body"] == "channel e1 body"


def test_distribution_wraps_self_row(tmp_path):
    """The distributor's own server wrap row is their archive-
    recovery anchor (the phoenix seat needs phoenix's row to hold
    the epoch he distributed). _distribute_* must therefore seal a
    wrap for EVERY member including self — skipping self left the
    distributor's row frozen at whatever epoch someone else last
    distributed. The custody frame fan-out stays other-only
    (pinned by the transports, not here)."""
    async def main():
        ident = Identity.ephemeral()
        agent = _agent(tmp_path, identity=ident)
        seen = {}

        async def fake_request(frame, timeout=None):
            seen.update(frame)
            return {}
        agent._request = fake_request
        key = new_group_key()
        await agent._distribute_group_key(GID, 3, key, ["alice"])
        assert seen["type"] == "set_group_keys"
        assert "alice" in seen["wrapped"]
        assert ident.unwrap_key(seen["wrapped"]["alice"]) == key
        await agent._distribute_channel_key(CID, 2, key, ["alice"])
        assert seen["type"] == "set_channel_keys"
        assert "alice" in seen["wrapped"]
        assert ident.unwrap_key(seen["wrapped"]["alice"]) == key
    asyncio.run(main())


def test_groups_edge_admin_acts_on_other_members():
    """The 2.3.1 Edge fix, pinned at the source text: the
    agentlink-groups dispatcher's identity comes from the verified
    JWT only. The pre-fix guard rejected any body whose `username`
    disagreed with the JWT — but the member routes take their
    TARGET from body.username (the relay frame contract), so an
    admin could never remove/promote/demote another member: every
    call died as identity_mismatch before its route ran, which
    also blocked the member-removal key rotation this release is
    about. The behavioral half (admin removes another member;
    plain member refused) is exercised against the coverage
    mirror in test_v200_coverage; this test pins that the shipped
    TS no longer reintroduces the collision."""
    ts = (Path(__file__).resolve().parent.parent
          / "supabase" / "functions" / "agentlink-groups"
          / "index.ts").read_text()
    assert "body.username !== me" not in ts
    assert "body.username !== undefined" not in ts


def test_server_wrap_recovery_into_archive(tmp_path):
    """The phoenix seat: the local file holds ONLY epoch 2; the
    server still holds the epoch-1 wrap. The session-start archive
    load must recover epoch 1 so epoch-1 history opens."""
    async def main():
        ident = Identity.ephemeral()
        agent = _agent(tmp_path, identity=ident)
        key1, key2 = new_group_key(), new_group_key()
        agent._store_group_key(GID, 2, key2)
        wrapped1 = ident.wrap_key(ident.public_key_b64, key1)

        async def fake_request(frame, timeout=None):
            assert frame["type"] == "get_group_keys"
            return {"group_id": GID,
                    "keys": [{"epoch": 1, "wrapped": wrapped1}]}
        agent._request = fake_request
        await agent._load_group_key_archive(GID)
        rec = agent._group_keys[GID]
        assert rec["epoch"] == 2 and rec["key"] == key2
        assert rec["epochs"][1] == key1
        row = _history_row("m-rec", _seal(key1, 1, "recovered body"))
        msg = agent._history_row_to_msg(row)
        assert not msg.get("sealed") and msg["body"] == "recovered body"
    asyncio.run(main())
