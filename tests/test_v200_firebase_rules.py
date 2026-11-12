"""Structural pins on firebase/database.rules.json (v2.0 Phase 3).

These tests parse the rules file as data and assert the access
invariants the blueprint promises — they run with no Firebase
project, no emulator and no network:

* presence: write own node only (auth.uid === $user);
* signals: read/write by any authenticated user (a forged signal
  is harmless by design — it can only cause a wasted fetch);
* doorbell: read own only; write by authenticated users only for
  OTHER users' doorbell (the tap pattern, auth.uid !== $user);
* every node shape-validates to exactly its documented fields
  (no extra-field smuggling — $other validates false);
* nothing anywhere grants anonymous/public access, and the root
  carries no grants (default-deny).
"""

from __future__ import annotations

import json
from pathlib import Path

FIREBASE_DIR = Path(__file__).resolve().parents[1] / "firebase"
RULES_PATH = FIREBASE_DIR / "database.rules.json"
FIREBASE_JSON_PATH = FIREBASE_DIR / "firebase.json"


def _rules() -> dict:
    return json.loads(RULES_PATH.read_text())


def _walk(node, path=""):
    """Yield (path, key, value) for every entry in the rules tree."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield (f"{path}/{k}", k, v)
            yield from _walk(v, f"{path}/{k}")


def test_rules_file_is_valid_json_with_rules_root():
    data = _rules()
    assert set(data.keys()) == {"rules"}
    # digest added at v2.0 integration (fan-out valve writer/reader);
    # inbox + directory added in 2.3.0 (the split's live layer:
    # message transit queue + directory working copy); liveness
    # added in 2.5.0 (Life Signs live grade nodes — written only
    # by the server path, read publicly like presence: grade
    # metadata only, no content ever).
    assert set(data["rules"].keys()) == \
        {"signals", "presence", "doorbell", "digest",
         "inbox", "directory", "liveness"}


def test_firebase_json_points_at_the_rules_file():
    cfg = json.loads(FIREBASE_JSON_PATH.read_text())
    assert cfg["database"]["rules"] == "database.rules.json"
    assert RULES_PATH.exists()


def test_no_public_access_anywhere():
    """No rule may grant unauthenticated access, with ONE deliberate
    exception (2026-11-06, the dashboard-presence correction): the
    /presence read is public. Presence holds metadata only —
    username, state, timestamps, client_version, transport — and
    no content ever travels through Firebase (blueprint law), while
    the owner's dashboard is a static page with no Firebase
    sign-in of its own; an auth-gated presence read left the
    dashboard permanently blind (verified live: anonymous read
    401 before the fix, 200 after, writes still denied). Every
    other .read/.write in the file must require auth, and every
    .write anywhere — presence included — must require auth.
    2.5.0 extends the same deliberate exception to the /liveness
    read: the grade node holds metadata only (grade word, proof
    tier + time, nature version, flags — never content), the
    dashboard subscribes to it exactly like presence, and its
    writes are server-only (the $user .write names a uid no
    agent token ever carries; the real writers use the
    service-account path, which bypasses rules)."""
    for path, key, value in _walk(_rules()):
        if key not in (".read", ".write"):
            continue
        if path in ("/rules/presence/.read",
                    "/rules/liveness/.read"):
            assert value is True
            continue
        assert value is not True, f"{path} grants public access"
        assert isinstance(value, str) and "auth" in value, (
            f"{path} does not require auth: {value!r}")


def test_root_has_no_grants_default_deny():
    rules = _rules()["rules"]
    assert ".read" not in rules
    assert ".write" not in rules


def test_signals_read_write_any_authenticated_user():
    signals = _rules()["rules"]["signals"]
    assert signals[".read"] == "auth != null"
    node = signals["$conversation"]
    assert node[".write"] == "auth != null"
    # Deliberately NO uid binding: any authenticated user may tap
    # any conversation's signal (harmless-forgery design).
    assert "uid" not in node[".write"]


def test_signals_shape_validation_is_exact():
    node = _rules()["rules"]["signals"]["$conversation"]
    validate = node[".validate"]
    for field in ("latest_item_id", "counter", "ts"):
        assert field in validate
    assert node["latest_item_id"][".validate"].startswith(
        "newData.isString()")
    assert node["counter"][".validate"].startswith("newData.isNumber()")
    assert node["ts"][".validate"].startswith("newData.isNumber()")
    # No extra fields may ride a signal — content smuggling denied.
    assert node["$other"][".validate"] is False


def test_presence_write_own_only():
    presence = _rules()["rules"]["presence"]
    # The read is the one deliberate public grant (metadata only,
    # for the owner's static dashboard — see
    # test_no_public_access_anywhere); the WRITE stays bound to
    # the record's own authenticated user, which is what this
    # test exists to pin.
    assert presence[".read"] is True
    node = presence["$user"]
    assert "auth != null" in node[".write"]
    assert "auth.uid === $user" in node[".write"]


def test_presence_shape_validation():
    node = _rules()["rules"]["presence"]["$user"]
    assert "state" in node[".validate"] and "ts" in node[".validate"]
    state = node["state"][".validate"]
    assert "'online'" in state and "'offline'" in state
    assert node["$other"][".validate"] is False


def test_presence_metadata_fields_are_validated():
    """Connection metadata (connected_at / client_version /
    transport) may ride the presence node — each with its own
    type validation, and nothing beyond the documented fields."""
    node = _rules()["rules"]["presence"]["$user"]
    assert node["connected_at"][".validate"].startswith(
        "newData.isNumber()")
    assert node["client_version"][".validate"] == "newData.isString()"
    assert node["transport"][".validate"] == "newData.isString()"
    assert node["$other"][".validate"] is False


def test_doorbell_read_own_only():
    node = _rules()["rules"]["doorbell"]["$user"]
    assert "auth != null" in node[".read"]
    assert "auth.uid === $user" in node[".read"]


def test_doorbell_write_others_only_tap_pattern():
    node = _rules()["rules"]["doorbell"]["$user"]
    assert "auth != null" in node[".write"]
    assert "auth.uid !== $user" in node[".write"]


def test_doorbell_has_no_blanket_read():
    """The doorbell subtree must not gain a parent-level read that
    would widen past own-only (RTDB rules cascade downward)."""
    doorbell = _rules()["rules"]["doorbell"]
    assert ".read" not in doorbell
    assert ".write" not in doorbell


def test_doorbell_shape_validation_is_exact():
    node = _rules()["rules"]["doorbell"]["$user"]
    for field in ("kind", "ref", "ts"):
        assert field in node[".validate"]
    assert node["kind"][".validate"].startswith("newData.isString()")
    assert node["ref"][".validate"].startswith("newData.isString()")
    assert node["ts"][".validate"].startswith("newData.isNumber()")
    assert node["$other"][".validate"] is False


def test_no_content_shaped_fields_in_any_validated_shape():
    """No validated node may admit a PLAINTEXT-bearing field
    name. (2.3.0: the inbox branch's frame child is the transit
    envelope — a wholesale sealed object, validated by its
    parent's hasChildren(['frame', 'ts']) exactly as custody
    payloads always were; no field INSIDE it is individually
    admitted by any rule, and plaintext field names stay
    forbidden everywhere.)"""
    forbidden = {"content", "body", "ct", "nonce", "eph_pub",
                 "oversight", "file", "data_b64", "envelope"}
    for path, key, value in _walk(_rules()):
        if key == ".validate" and isinstance(value, str) \
                and "hasChildren" in value:
            for name in forbidden:
                assert f"'{name}'" not in value, (
                    f"{path} admits content field {name}")


def test_inbox_branch_shape_and_access():
    """2.3.0 transit queue: the owner reads their own inbox;
    any authenticated agent may CREATE an item (a send), but a
    delete (consume) is the owner's alone — the write rule's
    newData.exists() arm makes non-owner deletes fail."""
    inbox = _rules()["rules"]["inbox"]["$user"]
    assert inbox[".read"] == "auth != null && auth.uid === $user"
    item = inbox["$item"]
    assert item[".write"] == \
        "auth != null && (newData.exists() || auth.uid === $user)"
    assert "hasChildren(['frame', 'ts'])" in item[".validate"]
    assert item["$other"][".validate"] is False
    # The frame child carries its OWN validate: without it, RTDB's
    # deeper-wins validate semantics apply the $other ban to every
    # field INSIDE the frame object and no inbox item can ever be
    # written (proven live in the 2.3.0 sandbox drills). The frame
    # is admitted on its frame shape (type + id — every frame the
    # protocol builds carries both); its content stays opaque,
    # never validated field by field.
    assert item["frame"][".validate"] == \
        "newData.hasChildren(['type', 'id'])"


def test_directory_branch_shape_and_access():
    """2.3.0 directory working copy: any authenticated agent may
    read (lookups are the point); only the owner writes their
    own entry."""
    directory = _rules()["rules"]["directory"]["$user"]
    assert directory[".read"] == "auth != null"
    assert directory[".write"] == "auth != null && auth.uid === $user"
    assert "hasChildren(['username', 'updated_at'])" in \
        directory[".validate"]
    assert directory["$other"][".validate"] is False
