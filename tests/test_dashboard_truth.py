"""Dashboard truth (v1.3.3) — the two defects the owner caught by eye.

DEFECT 1 — threads rendered backwards. Relay._conversations()
composed each conversation's items oldest-first (both stores return
content rows seq-ascending) and then REVERSED every item list before
returning it, so the API payload — and the dashboard, which renders
payload order — opened every thread with its NEWEST item. On the
real dm:beulah|phoenix thread that put Beulah's reply (ts
1793616601) above Phoenix's opener (ts 1793616256, ~6 minutes
earlier), reading as if Beulah had started a conversation Phoenix
started at the owner's order. The v1.3.2 screenshot pass missed it
because nobody asserted RENDER ORDER.

DEFECT 2 — groups were not conversations. The conversations list
only contained keys derived from content rows, so a group or channel
with no messages yet existed only as registry metadata / an Overview
stat — the owner's Nova family group was invisible in the chat list
while sitting intact in the store.

Pins:
* composed items are ts-ascending, whatever order rows arrived or
  the store returned them in (head of thread = its first item);
* the beulah-shaped named truth: the opener is the head;
* group + channel threads and work envelopes obey the same order;
* a freshly created zero-message group and channel ARE entries in
  the conversations payload, with name + members;
* the chat list itself sorts by latest activity.
"""

from __future__ import annotations

import sqlite3

from agentlink.dashboard import DashboardServer
from agentlink.relay import Relay
from agentlink.store import Store

OPENER_ID = "0bcc9bd535034ad7a9714d5f7b8fb0ec"   # phoenix -> beulah
REPLY_ID = "0b200d08bc68459c91963217128c0493"    # beulah -> phoenix
OPENER_TS = 1793616256
REPLY_TS = 1793616601


def _relay(tmp_path) -> Relay:
    return Relay(host="127.0.0.1", port=0,
                 db_path=str(tmp_path / "relay.db"),
                 dashboard_password="test")


def _set_ts(db_path: str, ref_id: str, ts: int) -> None:
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE audit_log SET ts = ? WHERE ref_id = ?",
                 (ts, ref_id))
    conn.commit()
    conn.close()


def _conv(convs, key):
    for c in convs:
        if c["key"] == key:
            return c
    raise AssertionError(f"conversation {key} missing from "
                         f"{[c['key'] for c in convs]}")


def test_items_chronological_despite_out_of_order_arrival(tmp_path):
    relay = _relay(tmp_path)
    db = str(tmp_path / "relay.db")
    # Arrival (insertion) order is m1, m2, m3 — but their true
    # timestamps run m2 < m3 < m1 (late/out-of-order arrival).
    relay.store.audit("message", "phoenix", target="beulah",
                      ref_id="m1")
    relay.store.audit("message", "beulah", target="phoenix",
                      ref_id="m2")
    relay.store.audit("message", "phoenix", target="beulah",
                      ref_id="m3")
    _set_ts(db, "m1", 300)
    _set_ts(db, "m2", 100)
    _set_ts(db, "m3", 200)
    c = _conv(relay._conversations(), "dm:beulah|phoenix")
    assert [i["id"] for i in c["items"]] == ["m2", "m3", "m1"]
    assert [i["ts"] for i in c["items"]] == [100, 200, 300]


def test_named_truth_head_is_the_opener_whatever_store_order(tmp_path):
    relay = _relay(tmp_path)
    db = str(tmp_path / "relay.db")
    relay.store.audit("message", "phoenix", target="beulah",
                      ref_id=OPENER_ID)
    relay.store.audit("message", "beulah", target="phoenix",
                      ref_id=REPLY_ID)
    _set_ts(db, OPENER_ID, OPENER_TS)
    _set_ts(db, REPLY_ID, REPLY_TS)
    # Worst case: the store hands the rows back newest-first.
    real = relay.store.list_content_audit
    relay.store.list_content_audit = lambda: list(reversed(real()))
    try:
        c = _conv(relay._conversations(), "dm:beulah|phoenix")
    finally:
        relay.store.list_content_audit = real
    assert [i["id"] for i in c["items"]] == [OPENER_ID, REPLY_ID]
    assert c["items"][0]["from"] == "phoenix"
    assert c["items"][0]["ts"] == OPENER_TS


def test_group_channel_and_work_items_chronological(tmp_path):
    relay = _relay(tmp_path)
    db = str(tmp_path / "relay.db")
    gid = relay.store.create_group("Nova family", "phoenix", None)
    relay.store.add_member(gid, "beulah", added_by="phoenix")
    cid = relay.store.create_channel("Announcements", "phoenix")
    relay.store.audit("group_message", "beulah", target="",
                      group_id=gid, ref_id="g2")
    relay.store.audit("group_message", "phoenix", target="",
                      group_id=gid, ref_id="g1")
    relay.store.audit("channel_message", "phoenix", target="",
                      group_id=cid, ref_id="c2")
    relay.store.audit("channel_message", "phoenix", target="",
                      group_id=cid, ref_id="c1")
    relay.store.audit("work_delivered", "deploy-probe",
                      target="phoenix", work_id="w-1")
    relay.store.audit("work_assigned", "phoenix",
                      target="deploy-probe", work_id="w-1")
    _set_ts(db, "g1", 10)
    _set_ts(db, "g2", 20)
    _set_ts(db, "c1", 10)
    _set_ts(db, "c2", 20)
    conn = sqlite3.connect(db)
    conn.execute("UPDATE audit_log SET ts = 15 WHERE work_id = 'w-1'"
                 " AND kind = 'work_delivered'")
    conn.execute("UPDATE audit_log SET ts = 5 WHERE work_id = 'w-1'"
                 " AND kind = 'work_assigned'")
    conn.commit()
    conn.close()
    convs = relay._conversations()
    g = _conv(convs, "group:" + gid)
    assert [i["id"] for i in g["items"]] == ["g1", "g2"]
    assert g["kind"] == "group" and g["name"] == "Nova family"
    ch = _conv(convs, "group:" + cid)
    assert [i["id"] for i in ch["items"]] == ["c1", "c2"]
    assert ch["kind"] == "channel" and ch["name"] == "Announcements"
    dm = _conv(convs, "dm:deploy-probe|phoenix")
    assert [i["kind"] for i in dm["items"]] == [
        "work_assigned", "work_delivered"]


def test_zero_message_group_and_channel_are_conversations(tmp_path):
    relay = _relay(tmp_path)
    gid = relay.store.create_group("Nova family", "phoenix", None)
    relay.store.add_member(gid, "beulah", role="member",
                           added_by="phoenix")
    cid = relay.store.create_channel("Announcements", "phoenix")
    relay.store.add_subscriber(cid, "beulah", added_by="phoenix")
    convs = relay._conversations()
    g = _conv(convs, "group:" + gid)
    assert g["kind"] == "group"
    assert g["name"] == "Nova family"
    assert g["items"] == []
    members = {p["username"]: p for p in g["participants"]}
    assert set(members) == {"phoenix", "beulah"}
    assert members["beulah"]["role"] == "member"
    ch = _conv(convs, "group:" + cid)
    assert ch["kind"] == "channel"
    assert ch["name"] == "Announcements"
    assert ch["items"] == []
    assert {p["username"] for p in ch["participants"]} == {
        "phoenix", "beulah"}
    # And the dashboard payload itself carries them — the chat
    # list is rendered from this, nothing else.
    dash = DashboardServer(relay, "127.0.0.1", 0, "test")
    data = dash._serve_data()
    keys = {c["key"] for c in data["conversations"]}
    assert "group:" + gid in keys
    assert "group:" + cid in keys


def test_chat_list_sorted_by_latest_activity(tmp_path):
    relay = _relay(tmp_path)
    db = str(tmp_path / "relay.db")
    relay.store.audit("message", "phoenix", target="beulah",
                      ref_id="old-dm")
    relay.store.audit("message", "phoenix", target="deploy-probe",
                      ref_id="new-dm")
    _set_ts(db, "old-dm", 100)
    _set_ts(db, "new-dm", 900)
    keys = [c["key"] for c in relay._conversations()]
    assert keys.index("dm:deploy-probe|phoenix") < \
        keys.index("dm:beulah|phoenix")
