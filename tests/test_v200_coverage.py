"""Serverless request-coverage tests (v2.0 coverage phase).

The daemon port left a list of relay-only request types failing
closed in serverless mode. This suite pins, per request type,
that the serverless path now answers with the RELAY's contract:
same response shapes, same refusal reasons in the same check
order, same audit kinds, same store effects.

How: a fake backend serves PostgREST (RLS is not simulated —
the transport's own checks and the Edge mirrors enforce the
contract, exactly the split the real deployment has between the
Phase 1 policies and the functions), in-memory R2, and PYTHON
MIRRORS of the six coverage Edge functions (agentlink-work,
-groups, -grants, -blobs, -library, -account) plus r2sign and
the login function's declaration handling. The mirrors implement
the same routes/contracts over the same tables; the shipped
TypeScript is pinned separately (static contract test at the
bottom: routes, refusal strings, audit kinds, payload formats)
and its one new crypto primitive (signEd25519) is cross-verified
against Python when Node is available.

Everything runs through the real client Agent API wherever the
client has one, so what is pinned is the contract an agent
handler actually sees.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import shutil
import subprocess
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

from agentlink.client import Agent, RequestFailed
from agentlink.crypto import Identity
from agentlink.doorbell import DoorbellError, sanitize_key
from agentlink.connectors import (
    derived_capabilities, validate_inventory)
from agentlink.grants import verify_receipt
from agentlink.protocol import inventory_digest
from agentlink.protocol import (
    auth_challenge_payload, grant_statement_payload)
from agentlink.transport_v2 import ServerlessConfig, ServerlessTransport

SUPA = "https://supa.test"
EDGE = "https://edge.test/agentlink-login"
RTDB = "https://proj-default-rtdb.firebaseio.com"
ROOT = Path(__file__).resolve().parent.parent
NOW = int(time.time())


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def make_jwt(payload: dict) -> str:
    head = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = _b64url(json.dumps(payload).encode())
    return f"{head}.{body}.fakesig"


def _nid(prefix: str, total: int) -> str:
    return (prefix + uuid.uuid4().hex)[:total]


# ----------------------------------------------------------------------
# The fake backend: PostgREST + R2 + Edge mirrors
# ----------------------------------------------------------------------

class CoverageBackend:
    TABLES = (
        "queue", "audit_log", "directory", "users", "activeness",
        "connections", "message_reads", "work", "work_deliveries",
        "work_checkpoints", "chains", "chain_steps", "groups",
        "group_members", "group_keys", "channels",
        "channel_members", "channel_keys", "invites", "vault",
        "blobs", "upload_sessions", "library", "alerts",
        "grants", "grant_approvals", "grant_receipts",
        "agent_connectors", "grant_meta", "grant_authz",
        "servers",
    )

    def __init__(self):
        self.tables = {name: [] for name in self.TABLES}
        self.r2 = {}            # key -> bytes
        self.calls = []
        self._seq = 1000
        # The platform receipt key (al_grant_meta mirror): a real
        # Ed25519 keypair so receipts verify in Python.
        self._platform = Ed25519PrivateKey.generate()
        pub = base64.b64encode(
            self._platform.public_key().public_bytes_raw()).decode()
        seed = base64.b64encode(
            self._platform.private_bytes_raw()).decode()
        self.tables["grant_meta"].append({
            "key": "receipt_signing_key", "value": f"{seed}:{pub}"})
        self.platform_pub = pub

    # -- tiny store helpers ------------------------------------------
    def rows(self, table):
        return self.tables[table]

    def find(self, table, **eq):
        return [r for r in self.tables[table]
                if all(r.get(k) == v for k, v in eq.items())]

    def one(self, table, **eq):
        found = self.find(table, **eq)
        return found[0] if found else None

    def insert(self, table, row):
        row = dict(row)
        if table in ("queue", "audit_log") and "seq" not in row:
            self._seq += 1
            row["seq"] = self._seq
        self.tables[table].append(row)
        return row

    def audit(self, kind, actor, target="", group_id="", work_id="",
              status="", ref_id=""):
        return self.insert("audit_log", {
            "ts": int(time.time()), "kind": kind, "actor": actor,
            "target": target, "group_id": group_id,
            "work_id": work_id, "status": status, "priority": "",
            "size": 0, "mentions": [], "ref_id": ref_id,
            "sender_nickname": "", "sender_role": "",
            "sender_custom_role": "", "oversight": "",
            "content_envelope": ""})

    def enqueue(self, to_username, frame):
        weight = {"normal": 0, "high": 1, "urgent": 2}.get(
            str(frame.get("priority") or "normal"), 0)
        return self.insert("queue", {
            "to_username": to_username,
            "payload": json.dumps(frame), "priority": weight,
            "ts": int(time.time())})

    def queue_frames(self, to_username, type_=None):
        out = []
        for r in self.tables["queue"]:
            if r["to_username"] != to_username:
                continue
            frame = json.loads(r["payload"])
            if type_ is None or frame.get("type") == type_:
                out.append(frame)
        return out

    # -- opener ---------------------------------------------------------
    def opener(self, method, url, headers, body):
        self.calls.append((method, url))
        if url.startswith("https://r2.test/"):
            return self._r2(method, url, body)
        if url.startswith(EDGE):
            return self._login(method, url, body, headers)
        if url.startswith("https://edge.test/agentlink-"):
            return self._edge(method, url, body, headers)
        if "/rest/v1/" in url:
            return self._rest(method, url, body, headers)
        raise AssertionError(f"unexpected URL {url}")

    def _r2(self, method, url, body):
        key = urllib.parse.urlsplit(url).path.lstrip("/")
        key = urllib.parse.unquote(key)
        if method == "PUT":
            self.r2[key] = body or b""
            return 200, {}, b""
        if method == "GET":
            if key not in self.r2:
                return 404, {}, b"NoSuchKey"
            return 200, {}, self.r2[key]
        if method == "DELETE":
            self.r2.pop(key, None)
            return 204, {}, b""
        return 405, {}, b""

    # -- PostgREST -------------------------------------------------------
    def _rest(self, method, url, body, headers):
        split = urllib.parse.urlsplit(url)
        table = split.path.rsplit("/", 1)[-1]
        if table.startswith("al_"):
            table = table[3:]
        params = urllib.parse.parse_qs(split.query)
        rows = self.tables[table]

        def cond(row, key, val):
            if val.startswith("eq."):
                return str(row.get(key)) == val[3:]
            if val.startswith("neq."):
                return str(row.get(key)) != val[4:]
            if val.startswith("lt."):
                return row.get(key) is not None and \
                    row.get(key) < type(row.get(key))(val[3:])
            if val.startswith("gt."):
                return row.get(key) is not None and \
                    row.get(key) > type(row.get(key))(val[3:])
            if val.startswith("gte."):
                return row.get(key) is not None and \
                    row.get(key) >= type(row.get(key))(val[4:])
            if val.startswith("lte."):
                return row.get(key) is not None and \
                    row.get(key) <= type(row.get(key))(val[4:])
            if val.startswith("in.("):
                wanted = {v.strip().strip('"')
                          for v in val[4:-1].split(",") if v.strip()}
                return str(row.get(key)) in wanted
            if val.startswith("is."):
                want = val[3:]
                if want == "null":
                    return row.get(key) is None
                return str(row.get(key)).lower() == want
            raise AssertionError(f"unsupported filter {val}")

        def matches(row):
            for key, vals in params.items():
                if key in ("select", "order", "limit", "offset",
                           "on_conflict"):
                    continue
                val = vals[0]
                if key == "or":
                    inner = val.strip()[1:-1]
                    parts = [p for p in inner.split(",") if p]
                    ok = False
                    for part in parts:
                        col, op, rest = part.split(".", 2)
                        if cond(row, col, f"{op}.{rest}"):
                            ok = True
                            break
                    if not ok:
                        return False
                    continue
                if key == "and":
                    inner = val.strip()[1:-1]
                    for part in [p for p in inner.split(",") if p]:
                        col, op, rest = part.split(".", 2)
                        if not cond(row, col, f"{op}.{rest}"):
                            return False
                    continue
                if not cond(row, key, val):
                    return False
            return True

        prefer = (headers or {}).get("Prefer", "") or \
            (headers or {}).get("prefer", "")
        if method == "GET":
            out = [dict(r) for r in rows if matches(r)]
            order = params.get("order", [None])[0]
            if order:
                for spec in reversed(order.split(",")):
                    col, _, direction = spec.partition(".")
                    out.sort(key=lambda r: (r.get(col) is None,
                                            r.get(col)),
                             reverse=(direction == "desc"))
            if "offset" in params:
                out = out[int(params["offset"][0]):]
            if "limit" in params:
                out = out[:int(params["limit"][0])]
            return 200, {}, json.dumps(out).encode()
        if method == "POST":
            payload = json.loads(body or b"{}")
            items = payload if isinstance(payload, list) else [payload]
            on_conflict = params.get("on_conflict", [None])[0]
            merge = "merge-duplicates" in prefer
            out = []
            for item in items:
                row = dict(item)
                replaced = False
                if on_conflict:
                    keys = [k.strip() for k in on_conflict.split(",")]
                    for i, old in enumerate(rows):
                        if all(str(old.get(k)) == str(row.get(k))
                               for k in keys):
                            if merge:
                                old.update(row)
                                out.append(dict(old))
                            else:
                                rows[i] = row
                                out.append(dict(row))
                            replaced = True
                            break
                if not replaced:
                    out.append(dict(self.insert(table, row)))
            if "return=representation" in prefer:
                return 201, {}, json.dumps(out).encode()
            return 201, {}, b""
        if method == "PATCH":
            patch = json.loads(body or b"{}")
            changed = []
            for r in rows:
                if matches(r):
                    r.update(patch)
                    changed.append(dict(r))
            if "return=representation" in prefer:
                return 200, {}, json.dumps(changed).encode()
            return 204, {}, b""
        if method == "DELETE":
            kept = [r for r in rows if not matches(r)]
            gone = [r for r in rows if matches(r)]
            self.tables[table] = kept
            if "return=representation" in prefer:
                return 200, {}, json.dumps(gone).encode()
            return 204, {}, b""
        return 405, {}, b""

    # -- login Edge mirror ------------------------------------------------
    def _login(self, method, url, body, headers):
        payload = json.loads(body or b"{}")
        if url.endswith("/challenge"):
            user = self.one("users", username=payload["username"])
            if user is None:
                return 404, {}, json.dumps(
                    {"error": "unknown_username"}).encode()
            return 200, {}, json.dumps({
                "nonce": "nonce-1", "relay": "edge.test",
                "expires": int(time.time()) + 300}).encode()
        if url.endswith("/verify"):
            username = payload["username"]
            user = self.one("users", username=username)
            raw = base64.b64decode(user["sign_pub"])
            pub = Ed25519PublicKey.from_public_bytes(raw)
            signed = auth_challenge_payload(
                payload["nonce"], payload["relay"], username,
                payload["expires"])
            try:
                pub.verify(base64.b64decode(payload["signature"]),
                           signed)
            except Exception:
                return 401, {}, b'{"error":"bad_signature"}'
            # The declaration handling added by the coverage
            # phase: validated exactly like the relay's setters.
            declared = payload.get("decision_link")
            patch = {"last_seen": int(time.time()),
                     "auth_method": "key-v2"}
            if declared in ("linked", "pending"):
                patch["decision_link"] = declared
            detail = payload.get("decision_link_detail")
            if isinstance(detail, dict):
                mode = detail.get("mode")
                if mode in ("config", "in_process", "handlers",
                            "convention", "none"):
                    patch["decision_link_detail"] = json.dumps({
                        "mode": mode,
                        "verified": bool(detail.get("verified")),
                        "checked_at": int(
                            detail.get("checked_at") or 0)})
            user.update(patch)
            jwt = make_jwt({"sub": username,
                            "role": "authenticated",
                            "exp": int(time.time()) + 3600})
            return 200, {}, json.dumps({
                "supabase_jwt": jwt,
                "firebase_custom_token": "custom-1",
                "refresh_token": f"rt-{username}",
                "expires_at": int(time.time()) + 3600}).encode()
        if url.endswith("/recovery"):
            return 401, {}, b'{"error":"recovery_failed"}'
        return 404, {}, b"{}"

    # -- Edge dispatch ------------------------------------------------------
    def _edge(self, method, url, body, headers):
        split = urllib.parse.urlsplit(url)
        parts = [p for p in split.path.split("/") if p]
        fn = parts[0]
        route = parts[1] if len(parts) > 1 else ""
        auth = (headers or {}).get("Authorization", "")
        me = None
        if auth.startswith("Bearer "):
            token = auth[7:]
            try:
                payload = token.split(".")[1]
                payload += "=" * (-len(payload) % 4)
                me = json.loads(base64.urlsafe_b64decode(
                    payload)).get("sub")
            except Exception:
                me = None
        if not me:
            return 401, {}, json.dumps(
                {"error": "unauthorized"}).encode()
        payload = json.loads(body or b"{}")
        handler = {
            "agentlink-r2sign": self._fn_r2sign,
            "agentlink-work": self._fn_work,
            "agentlink-groups": self._fn_groups,
            "agentlink-grants": self._fn_grants,
            "agentlink-blobs": self._fn_blobs,
            "agentlink-library": self._fn_library,
            "agentlink-account": self._fn_account,
        }.get(fn)
        if handler is None:
            return 404, {}, json.dumps({"error": "not_found"}).encode()
        status, data = handler(me, route, payload)
        return status, {}, json.dumps(data).encode()


def _err(reason, detail="", status=400):
    return status, {"ok": False, "error": reason, "detail": detail}


def _ok(data):
    return 200, {"ok": True, **data}


# ----------------------------------------------------------------------
# Edge mirrors (Python twins of the shipped TypeScript contracts)
# ----------------------------------------------------------------------

ADMIN_ROLES = ("admin", "superadmin")
TRANSITIONS = {
    "assigned": {"in_progress", "delivered", "awaiting_approval",
                 "covered", "awaiting_agent"},
    "in_progress": {"delivered", "awaiting_approval", "covered",
                    "awaiting_agent"},
    "changes_requested": {"in_progress", "delivered",
                          "awaiting_approval", "covered",
                          "awaiting_agent"},
    "delivered": {"completed", "changes_requested"},
    "awaiting_approval": {"completed", "changes_requested"},
    "awaiting_agent": {"assigned"},
    "covered": set(), "completed": set(),
}


def _is_env(x):
    return isinstance(x, dict) and bool(x.get("ct"))


def _valid_oversight(ov):
    return isinstance(ov, dict) and \
        ov.get("alg") == "x25519-chacha20poly1305" and all(
            isinstance(ov.get(k), str) and ov.get(k)
            for k in ("eph_pub", "nonce", "ct"))


def _work_shape(be, row):
    out = dict(row)
    out["content_enc"] = row.get("content_enc") or {}
    out["content_self"] = row.get("content_self") or {}
    out.setdefault("content_group", None)
    deliveries = [d for d in be.rows("work_deliveries")
                  if d["work_id"] == row["id"]]
    deliveries.sort(key=lambda d: d["ts"])
    out["deliveries"] = [dict(d) for d in deliveries]
    cp = be.one("work_checkpoints", work_id=row["id"])
    if cp is not None:
        out["checkpoint"] = dict(cp)
    return out


def _get_work(be, work_id):
    row = be.one("work", id=work_id)
    return _work_shape(be, row) if row else None


def _create_work(be, **fields):
    now = int(time.time())
    row = {"id": _nid("w-", 14), "attempt": 1, "progress_percent": 0,
           "progress_at": 0, "proof_hash": "", "proof_ts": 0,
           "proof_sig": "", "proof_verified": 0, "status": "assigned",
           "chain_id": "", "chain_step": 0, "batch_id": None,
           "created_at": now, "updated_at": now}
    row.update(fields)
    be.insert("work", row)
    return _get_work(be, row["id"])


def _set_status(be, work_id, status):
    row = be.one("work", id=work_id)
    allowed = TRANSITIONS.get(row["status"], set())
    assert status == row["status"] or status in allowed, \
        f"invalid transition {row['status']} -> {status}"
    row["status"] = status
    row["updated_at"] = int(time.time())
    return _get_work(be, work_id)


def _resolve_alerts(be, kind, subject):
    for a in be.rows("alerts"):
        if a["kind"] == kind and a["subject"] == subject \
                and a["status"] == "open":
            a["status"] = "resolved"
            a["resolved_at"] = int(time.time())


def _open_alert(be, kind, subject, detail=""):
    for a in be.rows("alerts"):
        if a["kind"] == kind and a["subject"] == subject \
                and a["status"] == "open":
            return a
    return be.insert("alerts", {
        "id": _nid("a-", 14), "kind": kind, "subject": subject,
        "detail": detail, "status": "open", "reminders": 0,
        "last_reminder_at": 0, "created_at": int(time.time()),
        "resolved_at": 0})


def _chain_shape(be, row):
    steps = [s for s in be.rows("chain_steps")
             if s["chain_id"] == row["id"]]
    steps.sort(key=lambda s: s["position"])
    out = dict(row)
    out["steps"] = [dict(s) for s in steps]
    return out


def _get_chain(be, chain_id):
    row = be.one("chains", id=chain_id)
    return _chain_shape(be, row) if row else None


def _release_step(be, chain, step):
    gid = step.get("group_id") or chain.get("group_id") or None
    assignees = list(step.get("assignees") or [])
    envelopes = step.get("envelopes") or {}
    if step.get("target_type") == "member":
        members = [m for m in be.rows("group_members")
                   if m["group_id"] == gid]
        pick = ""
        now = int(time.time())
        for m in members:
            if m["username"] == chain["creator"]:
                continue
            act = be.one("activeness", username=m["username"])
            if act and act.get("state") in ("online", "suspect") \
                    and now - int(act.get("beat_at") or 0) <= 60:
                pick = m["username"]
                break
        if not pick:
            for m in members:
                if m["username"] != chain["creator"]:
                    pick = m["username"]
                    break
        assignees = [pick] if pick else []
    batch = _nid("batch-", 20) if len(assignees) > 1 else None
    first = None
    for assignee in assignees:
        pair = envelopes.get(assignee) or {}
        role = ""
        if gid:
            mrow = be.one("group_members", group_id=gid,
                          username=assignee)
            if mrow:
                role = mrow.get("custom_role") or ""
        work = _create_work(
            be, assigner=chain["creator"], assignee=assignee,
            group_id=gid, content_enc=pair.get("enc") or {},
            content_self=pair.get("self") or pair.get("enc") or {},
            content_group=step.get("content_group"),
            deadline=step.get("deadline"), batch_id=batch,
            priority=step.get("priority") or "normal",
            auto_reassign=1, assignee_role=role,
            chain_id=chain["id"], chain_step=step["position"],
            require_approval=1 if step.get("require_approval") else 0)
        view = dict(work)
        view["prev_deliverables"] = step.get("handoff") or []
        be.enqueue(assignee, {"type": "work_assigned", "work": view,
                              "chain_id": chain["id"],
                              "chain_step": step["position"]})
        if first is None:
            first = work
    if first is not None:
        step["status"] = "active"
        step["work_id"] = first["id"]
        row = be.one("chain_steps", id=step["id"])
        if row is not None:
            row["status"] = "active"
            row["work_id"] = first["id"]


def _advance_chain(be, work):
    chain = _get_chain(be, work["chain_id"])
    if not chain or chain["status"] not in ("running", "paused"):
        return
    step = next((s for s in chain["steps"]
                 if s.get("work_id") == work["id"]), None)
    if step is None or step["status"] == "completed":
        return
    step_row = be.one("chain_steps", id=step["id"])
    if step_row is not None:
        step_row["status"] = "completed"
    entries = [e for e in be.rows("library")
               if e["work_id"] == work["id"]]
    handoff = [{"library_id": e["id"], "filename": e["filename"],
                "sha256": e["sha256"], "size": e["size"],
                "sender": e["sender"]} for e in entries]
    nxt = next((s for s in chain["steps"]
                if s["position"] == step["position"] + 1), None)
    if nxt is None:
        crow = be.one("chains", id=chain["id"])
        crow["status"] = "completed"
        _resolve_alerts(be, "chain_paused", chain["id"])
        be.enqueue(chain["creator"], {"type": "chain_event",
                                      "event": "completed",
                                      "chain_id": chain["id"]})
        be.audit("chain_completed", chain["creator"],
                 group_id=chain.get("group_id") or "",
                 status=chain["id"])
        _open_alert(be, "chain_completed", chain["id"],
                    "chain finished all steps")
        return
    nxt_row = be.one("chain_steps", id=nxt["id"])
    if nxt_row is not None:
        nxt_row["handoff"] = handoff
    nxt["handoff"] = handoff
    for entry in handoff:
        for nxt_user in (nxt.get("assignees") or []):
            lib = be.one("library", id=entry["library_id"])
            if lib:
                lib["chain_next"] = nxt_user
    crow = be.one("chains", id=chain["id"])
    if crow["status"] == "paused":
        crow["status"] = "running"
        _resolve_alerts(be, "chain_paused", chain["id"])
    _release_step(be, _get_chain(be, chain["id"]),
                  be.one("chain_steps", id=nxt["id"]))


def _fn_r2sign(be, me, route, body):
    action = body.get("action")
    blob_id = body.get("blob_id") or ""
    row = be.one("blobs", id=blob_id)
    if action == "put":
        if row is None:
            return _err("blob_not_found", "", 404)
        return 200, {"url": f"https://r2.test/{blob_id}",
                     "method": "PUT", "expires_in": 900}
    if action == "get":
        if row is None:
            return _err("blob_not_found", "", 404)
        allowed = row.get("owner") == me or \
            row.get("for_user") == me or \
            be.one("group_members", group_id=row.get("for_group"),
                   username=me) is not None or \
            be.one("channel_members",
                   channel_id=row.get("for_channel"),
                   username=me) is not None
        if not allowed:
            return _err("not_entitled", "", 403)
        return 200, {"url": f"https://r2.test/{blob_id}",
                     "method": "GET", "expires_in": 900}
    return _err("bad_action")


def _fn_work(be, me, route, body):
    if route == "assign":
        return _work_assign(be, me, body)
    if route == "deliver":
        return _work_deliver(be, me, body)
    if route == "action":
        return _work_action(be, me, body)
    if route == "chain_create":
        return _chain_create(be, me, body)
    if route == "chain_cancel":
        return _chain_cancel(be, me, body)
    return _err("not_found", "", 404)


def _work_assign(be, me, body):
    gid = body.get("group_id") or None
    group = None
    if gid:
        group = be.one("groups", id=gid)
        if group is None:
            return _err("unknown_group")
        my = be.one("group_members", group_id=gid, username=me)
        if my is None:
            return _err("not_a_member")
        settings = group.get("settings") or {}
        if settings.get("assign_work") == "admins_only" and \
                my["role"] not in ADMIN_ROLES:
            return _err("permission_denied",
                        "only admins can assign work in this group")
    batch = None
    target_role = body.get("target_role")
    if target_role:
        if not gid:
            return _err("bad_assign", "role assignment needs a group")
        holders = sorted(
            m["username"] for m in be.rows("group_members")
            if m["group_id"] == gid and
            (m.get("custom_role") or "").lower()
            == str(target_role).lower())
        if not holders:
            return _err("empty_role",
                        f"nobody in this group holds the role "
                        f"'{target_role}'")
        if sorted(body.get("assignees") or []) != holders:
            return _err("role_mismatch",
                        "assignees must be exactly the current "
                        "role holders")
        batch = _nid("batch-", 20)
    priority = body.get("priority") or "normal"
    if priority not in ("normal", "high", "urgent"):
        priority = "normal"
    envelopes = body.get("envelopes") or {}
    if "title" in body or "instructions" in body:
        return _err("plaintext_not_allowed",
                    "work content must be end-to-end encrypted")
    created, notices = [], []
    for assignee in body.get("assignees") or []:
        if be.one("users", username=assignee) is None:
            return _err("unknown_username", assignee)
        if group is not None and be.one(
                "group_members", group_id=gid,
                username=assignee) is None:
            return _err("assignee_not_in_group", assignee)
        pair = envelopes.get(assignee) or {}
        if not _is_env(pair.get("enc")):
            return _err("bad_assign",
                        f"missing encrypted content for {assignee}")
        role = ""
        if gid:
            mrow = be.one("group_members", group_id=gid,
                          username=assignee)
            if mrow:
                role = mrow.get("custom_role") or ""
        work = _create_work(
            be, assigner=me, assignee=assignee, group_id=gid,
            content_enc=pair["enc"],
            content_self=pair.get("self") or pair["enc"],
            content_group=body.get("content_group"),
            deadline=body.get("deadline"), batch_id=batch,
            priority=priority,
            auto_reassign=1 if body.get("auto_reassign", True) else 0,
            assignee_role=role,
            require_approval=1 if body.get("require_approval") else 0)
        profile = be.one("users", username=assignee)
        if assignee != me and profile is not None and \
                (profile.get("mode") or "autonomous") == "autonomous" \
                and (profile.get("decision_link") or "") == "pending":
            notice = {
                "kind": "decision_link_pending", "assignee": assignee,
                "work_id": work["id"],
                "message": f"@{assignee}'s connection has not "
                           "declared a decision link — left alone, "
                           "its unattended runtime will not answer "
                           "or execute work on its own, so this "
                           "work is delivered to its connection and "
                           "queues there. Nothing counts as accepted "
                           "until the agent itself delivers, "
                           "with proof."}
            work["notice"] = notice
            notices.append(notice)
            be.enqueue(me, {"type": "work_update", "work": work,
                            "note": notice["message"]})
            be.audit("decision_link_notice", "system",
                     target=assignee, group_id=gid or "",
                     work_id=work["id"],
                     status="decision_link_pending")
        created.append(work)
        be.enqueue(assignee, {"type": "work_assigned", "work": work})
        be.audit("work_assigned", me, target=assignee,
                 group_id=gid or "", work_id=work["id"],
                 status="assigned")
        if body.get("require_approval"):
            be.audit("approval_gate_set", me, target=assignee,
                     group_id=gid or "", work_id=work["id"],
                     status="require_approval")
    if not created:
        return _err("bad_assign", "no assignees")
    out = {"work": created}
    if notices:
        out["notices"] = notices
    return _ok(out)


def _work_deliver(be, me, body):
    work = be.one("work", id=body.get("work_id") or "")
    if work is None:
        return _err("unknown_work")
    if work["assignee"] != me:
        return _err("permission_denied",
                    "only the assignee can deliver this work")
    attempt = body.get("attempt")
    if attempt is not None and int(attempt) != int(
            work.get("attempt") or 1):
        be.audit("stale_attempt_delivery", me,
                 target=work["assigner"],
                 group_id=work.get("group_id") or "",
                 work_id=work["id"], status=f"attempt {attempt}")
        return _err("stale_attempt",
                    f"this assignment was reassigned; attempt "
                    f"{attempt} is closed")
    if work["status"] not in ("assigned", "in_progress",
                              "changes_requested"):
        return _err("bad_status",
                    f"work is {work['status']}, cannot deliver")
    proof = body.get("proof") or {}
    user = be.one("users", username=me)
    verified = False
    if proof.get("sig") and user and user.get("sign_pub"):
        canonical = "{}|{}|{}|{}".format(
            work["id"], proof.get("hash", ""), proof.get("ts", ""),
            me).encode()
        try:
            Ed25519PublicKey.from_public_bytes(
                base64.b64decode(user["sign_pub"])).verify(
                    base64.b64decode(proof["sig"]), canonical)
            verified = True
        except Exception:
            verified = False
    be.audit("delivery_proof_verified", me, target=work["assigner"],
             group_id=work.get("group_id") or "",
             work_id=work["id"],
             status="true" if verified else "false")
    if not verified:
        return _err("bad_proof",
                    "delivery signature did not verify")
    if "body" in body or "files" in body:
        return _err("plaintext_not_allowed",
                    "deliveries must be end-to-end encrypted")
    if not _is_env(body.get("content_enc")):
        return _err("bad_delivery",
                    "missing encrypted delivery content")
    did = _nid("d-", 14)
    now = int(time.time())
    be.insert("work_deliveries", {
        "id": did, "work_id": work["id"], "deliverer": me,
        "content_enc": body["content_enc"],
        "content_self": body.get("content_self") or body["content_enc"],
        "content_group": body.get("content_group"),
        "content_next": body.get("content_next"), "ts": now})
    work["proof_hash"] = str(proof.get("hash") or "")
    work["proof_ts"] = int(proof.get("ts") or 0)
    work["proof_sig"] = str(proof.get("sig") or "")
    work["proof_verified"] = 1
    work["updated_at"] = now
    updated = _set_status(be, work["id"],
                          "awaiting_approval" if work.get(
                              "require_approval") else "delivered")
    for f in body.get("library") or []:
        be.insert("library", {
            "id": _nid("lib-", 16), "delivery_id": did,
            "work_id": work["id"], "filename": f.get("name", ""),
            "size": int(f.get("size") or 0),
            "sha256": f.get("sha256", ""), "sender": work["assignee"],
            "to_user": work["assigner"],
            "group_id": work.get("group_id") or "",
            "chain_next": "", "ts": now})
        updated = _get_work(be, work["id"])
    _resolve_alerts(be, "reassignment", work["id"])
    be.enqueue(work["assigner"], {"type": "work_update",
                                  "work": updated})
    be.audit("work_delivered", me, target=work["assigner"],
             work_id=work["id"], status=updated["status"])
    if updated["status"] == "awaiting_approval":
        be.audit("work_awaiting_approval", me,
                 target=work["assigner"],
                 group_id=work.get("group_id") or "",
                 work_id=work["id"], status="awaiting_approval")
    if work.get("batch_id"):
        for sib in list(be.rows("work")):
            if sib["id"] == work["id"] or \
                    sib.get("batch_id") != work["batch_id"] or \
                    sib["status"] not in ("assigned", "in_progress",
                                          "changes_requested"):
                continue
            covered = _set_status(be, sib["id"], "covered")
            be.enqueue(sib["assignee"], {
                "type": "work_update", "work": covered,
                "covered_by": work["id"]})
            be.enqueue(work["assigner"], {
                "type": "work_update", "work": covered,
                "covered_by": work["id"]})
            be.audit("work_covered", me, target=sib["assignee"],
                     group_id=sib.get("group_id") or "",
                     work_id=sib["id"], status="covered")
    return _ok({"work": updated})


def _work_action(be, me, body):
    work = be.one("work", id=body.get("work_id") or "")
    if work is None:
        return _err("unknown_work")
    action = body.get("action") or ""
    gated = work["status"] == "awaiting_approval"
    if gated:
        is_admin = False
        if work.get("group_id"):
            mrow = be.one("group_members",
                          group_id=work["group_id"], username=me)
            is_admin = mrow is not None and \
                mrow["role"] in ADMIN_ROLES
        if work["assigner"] != me and not is_admin:
            return _err("permission_denied",
                        "only the assigner or a group admin can "
                        "decide an approval gate")
        if action in ("approve", "complete"):
            status = "completed"
        elif action in ("reject", "request_changes"):
            status = "changes_requested"
        else:
            return _err("bad_action", action)
    else:
        if work["assigner"] != me:
            return _err("permission_denied",
                        "only the assigner can do that")
        if work["status"] != "delivered":
            return _err("bad_status",
                        f"work is {work['status']}, not delivered")
        if action == "complete":
            status = "completed"
        elif action == "request_changes":
            status = "changes_requested"
        else:
            return _err("bad_action", action)
    updated = _set_status(be, work["id"], status)
    if gated:
        be.audit("work_approved" if status == "completed"
                 else "work_approval_rejected", me,
                 target=work["assignee"],
                 group_id=work.get("group_id") or "",
                 work_id=work["id"], status=status)
    be.audit(f"work_{status}", me, target=work["assignee"],
             work_id=work["id"], status=status)
    if work.get("chain_id"):
        if status == "changes_requested":
            chain = be.one("chains", id=work["chain_id"])
            if chain:
                chain["status"] = "paused"
            be.audit("chain_paused", me,
                     group_id=work.get("group_id") or "",
                     work_id=work["id"], status=work["chain_id"])
        elif status == "completed":
            _advance_chain(be, work)
    be.enqueue(work["assignee"], {"type": "work_update",
                                  "work": updated,
                                  "note": body.get("note")})
    return _ok({"work": updated})


def _parse_deadline(value):
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value:
        try:
            from datetime import datetime, timezone
            text = value.replace("Z", "+00:00")
            return int(datetime.fromisoformat(text)
                       .astimezone(timezone.utc).timestamp())
        except Exception:
            return None
    return None


def _chain_create(be, me, body):
    steps = body.get("steps") or []
    if not steps:
        return _err("bad_chain", "a chain needs at least one step")
    gid = body.get("group_id") or None
    if gid:
        if be.one("groups", id=gid) is None:
            return _err("unknown_group")
        if be.one("group_members", group_id=gid,
                  username=me) is None:
            return _err("not_a_member")
    for st in steps:
        for a in st.get("assignees") or []:
            if be.one("users", username=a) is None:
                return _err("unknown_username", a)
    now = int(time.time())
    chain_id = _nid("chain-", 18)
    be.insert("chains", {"id": chain_id, "creator": me,
                         "group_id": gid or "",
                         "name": body.get("name") or "",
                         "status": "running", "paused_since": 0,
                         "created_at": now, "updated_at": now})
    for i, st in enumerate(steps):
        be.insert("chain_steps", {
            "id": _nid("step-", 16), "chain_id": chain_id,
            "position": i + 1,
            "target_type": st.get("target_type") or "user",
            "target": st.get("target") or "",
            "group_id": st.get("group_id") or gid or "",
            "assignees": st.get("assignees") or [],
            "envelopes": st.get("envelopes") or {},
            "content_group": st.get("content_group"),
            "deadline": _parse_deadline(st.get("deadline")),
            "priority": st.get("priority") or "normal",
            "require_approval": 1 if st.get("require_approval")
            else 0,
            "status": "pending", "work_id": "", "handoff": [],
            "created_at": now})
    chain = _get_chain(be, chain_id)
    _release_step(be, chain, chain["steps"][0])
    be.audit("chain_created", me, group_id=gid or "",
             status=chain_id)
    return _ok({"chain": _get_chain(be, chain_id)})


def _chain_cancel(be, me, body):
    chain = _get_chain(be, body.get("chain_id") or "")
    if chain is None:
        return _err("unknown_chain")
    is_admin = False
    if chain.get("group_id"):
        mrow = be.one("group_members", group_id=chain["group_id"],
                      username=me)
        is_admin = mrow is not None and mrow["role"] in ADMIN_ROLES
    if me != chain["creator"] and not is_admin:
        return _err("permission_denied",
                    "only the chain creator (or a group admin) can "
                    "cancel a chain")
    if chain["status"] in ("completed", "cancelled"):
        return _err("bad_status", f"chain is {chain['status']}")
    crow = be.one("chains", id=chain["id"])
    crow["status"] = "cancelled"
    involved = {chain["creator"]}
    for st in chain["steps"]:
        if st["status"] == "pending":
            st_row = be.one("chain_steps", id=st["id"])
            st_row["status"] = "cancelled"
        for a in st.get("assignees") or []:
            involved.add(a)
        if st.get("work_id"):
            w = be.one("work", id=st["work_id"])
            if w:
                involved.add(w["assignee"])
    for user in involved:
        if user != me:
            be.enqueue(user, {"type": "chain_event",
                              "event": "cancelled",
                              "chain_id": chain["id"], "by": me})
    be.audit("chain_cancelled", me,
             group_id=chain.get("group_id") or "", status=chain["id"])
    return _ok({"chain": _get_chain(be, chain["id"])})


CoverageBackend._fn_r2sign = _fn_r2sign
CoverageBackend._fn_work = _fn_work


# ----------------------------------------------------------------------
# groups mirror
# ----------------------------------------------------------------------

MAX_GROUP = 50
MAX_CHANNEL = 1000
SETTINGS_KEYS = ("send_messages", "add_members", "assign_work",
                 "vault_add")


def _gmembers(be, gid):
    return [m for m in be.rows("group_members")
            if m["group_id"] == gid]


def _gview(rows):
    return [{"username": m["username"], "role": m["role"],
             "nickname": m.get("nickname") or "",
             "custom_role": m.get("custom_role") or "",
             "added_by": m.get("added_by") or "",
             "joined_at": m["joined_at"]} for m in rows]


def _cmembers(be, cid):
    return [m for m in be.rows("channel_members")
            if m["channel_id"] == cid]


def _cview(rows):
    return [{"username": m["username"], "role": m["role"],
             "added_by": m.get("added_by") or "",
             "joined_at": m["joined_at"]} for m in rows]


def _gevent(be, group, event, actor, target, targets=None):
    members = _gmembers(be, group["id"])
    frame = {"type": "group_event", "id": group["id"],
             "group_id": group["id"], "group_name": group["name"],
             "event": event, "actor": actor, "target": target,
             "ts": int(time.time()), "members": _gview(members)}
    if targets is not None:
        frame["targets"] = targets
    for m in members:
        if m["username"] != actor:
            be.enqueue(m["username"], frame)
    return frame


def _cevent(be, channel, event, actor, target, targets=None):
    members = _cmembers(be, channel["id"])
    frame = {"type": "channel_event", "id": channel["id"],
             "channel_id": channel["id"],
             "channel_name": channel["name"], "event": event,
             "actor": actor, "target": target,
             "ts": int(time.time()), "members": _cview(members)}
    if targets is not None:
        frame["targets"] = targets
    for m in members:
        if m["username"] != actor:
            be.enqueue(m["username"], frame)
    return frame


def _invite(be, scope_id):
    token = base64.urlsafe_b64encode(
        uuid.uuid4().bytes + uuid.uuid4().bytes).decode()[:32]
    be.insert("invites", {
        "group_id": scope_id,
        "token_hash": hashlib.sha256(token.encode()).hexdigest(),
        "created_at": int(time.time())})
    return token


def _invite_valid(be, scope_id, token):
    if not token:
        return False
    digest = hashlib.sha256(str(token).encode()).hexdigest()
    row = be.one("invites", group_id=scope_id, token_hash=digest)
    return row is not None and \
        int(row["created_at"]) + 604800 >= int(time.time())


def _parse_link(link):
    if not str(link).startswith("agentlink://"):
        return None
    rest = str(link)[len("agentlink://"):]
    if "/" not in rest:
        return None
    scope, token = rest.split("/", 1)
    return (scope, token) if scope and token else None


def _fn_groups(be, me, route, body):
    now = int(time.time())
    if route == "group_create":
        name = str(body.get("name") or "")[:80]
        if not name:
            return _err("bad_group", "a group needs a name")
        members = body.get("members") or []
        for m in members:
            if be.one("users", username=m) is None:
                return _err("unknown_username", m)
        gid = "g-" + uuid.uuid4().hex[:12]
        group = {"id": gid, "name": name, "creator": me,
                 "key_epoch": 0,
                 "settings": {k: "everyone" for k in SETTINGS_KEYS},
                 "created_at": now}
        be.insert("groups", group)
        be.insert("group_members", {
            "group_id": gid, "username": me, "role": "superadmin",
            "nickname": "", "custom_role": "", "added_by": me,
            "joined_at": now})
        added = []
        for m in members:
            if m == me:
                continue
            if len(_gmembers(be, gid)) >= MAX_GROUP:
                return _err("group_full",
                            "groups are capped at 50 agents")
            be.insert("group_members", {
                "group_id": gid, "username": m, "role": "member",
                "nickname": "", "custom_role": "", "added_by": me,
                "joined_at": now})
            added.append(m)
        _gevent(be, group, "added_to_group", me, me, added)
        return _ok({"group_id": gid, "name": name,
                    "members": _gview(_gmembers(be, gid))})
    if route == "group_add":
        gid = body.get("group_id") or ""
        group = be.one("groups", id=gid)
        if group is None:
            return _err("unknown_group")
        my = be.one("group_members", group_id=gid, username=me)
        if my is None:
            return _err("not_a_member")
        if (group.get("settings") or {}).get("add_members") == \
                "admins_only" and my["role"] not in ADMIN_ROLES:
            return _err("permission_denied",
                        "only admins can add members in this group")
        targets = body.get("members") or body.get("usernames") or []
        for t in targets:
            if be.one("users", username=t) is None:
                return _err("unknown_username", t)
        added = []
        for t in targets:
            if be.one("group_members", group_id=gid,
                      username=t) is not None:
                continue
            if len(_gmembers(be, gid)) >= MAX_GROUP:
                return _err("group_full",
                            "groups are capped at 50 agents")
            be.insert("group_members", {
                "group_id": gid, "username": t, "role": "member",
                "nickname": "", "custom_role": "", "added_by": me,
                "joined_at": now})
            added.append(t)
        _gevent(be, group, "added_to_group", me, me, added)
        return _ok({"group_id": gid, "added": added,
                    "members": _gview(_gmembers(be, gid))})
    if route == "group_remove":
        gid = body.get("group_id") or ""
        group = be.one("groups", id=gid)
        if group is None:
            return _err("unknown_group")
        target = body.get("username") or ""
        trow = be.one("group_members", group_id=gid, username=target)
        if trow is None:
            return _err("not_a_member", target)
        my = be.one("group_members", group_id=gid, username=me)
        self_ = target == me
        if not self_ and (my is None
                          or my["role"] not in ADMIN_ROLES):
            return _err("permission_denied",
                        "only admins can remove other members")
        if trow["role"] == "superadmin" and not self_:
            return _err("permission_denied",
                        "the group creator cannot be removed")
        be.tables["group_keys"] = [
            k for k in be.rows("group_keys")
            if not (k["group_id"] == gid and k["username"] == target)]
        be.tables["group_members"] = [
            m for m in be.rows("group_members")
            if not (m["group_id"] == gid
                    and m["username"] == target)]
        frame = {"type": "group_event", "id": gid, "group_id": gid,
                 "group_name": group["name"],
                 "event": "removed_from_group", "actor": me,
                 "target": target, "ts": now,
                 "members": _gview(_gmembers(be, gid))}
        be.enqueue(target, frame)
        _gevent(be, group, "member_removed", me, target, [target])
        return _ok({"group_id": gid,
                    "members": _gview(_gmembers(be, gid))})
    if route in ("group_promote", "group_demote"):
        gid = body.get("group_id") or ""
        group = be.one("groups", id=gid)
        if group is None:
            return _err("unknown_group")
        my = be.one("group_members", group_id=gid, username=me)
        if my is None or my["role"] != "superadmin":
            return _err("permission_denied",
                        "only the group creator can change admin "
                        "roles")
        target = body.get("username") or ""
        trow = be.one("group_members", group_id=gid, username=target)
        if trow is None:
            return _err("not_a_member", target)
        trow["role"] = "member" if route == "group_demote" else "admin"
        _gevent(be, group, "demoted" if route == "group_demote"
                else "promoted", me, target, [target])
        return _ok({"group_id": gid,
                    "members": _gview(_gmembers(be, gid))})
    if route == "group_nickname":
        gid = body.get("group_id") or ""
        group = be.one("groups", id=gid)
        if group is None:
            return _err("unknown_group")
        target = body.get("username") or me
        my = be.one("group_members", group_id=gid, username=me)
        trow = be.one("group_members", group_id=gid, username=target)
        if my is None or trow is None:
            return _err("not_a_member")
        if target != me and my["role"] not in ADMIN_ROLES:
            return _err("permission_denied",
                        "only admins can set another member's "
                        "nickname")
        trow["nickname"] = str(body.get("nickname") or "")[:48]
        _gevent(be, group, "nickname_changed", me, target, [target])
        return _ok({"group_id": gid, "username": target,
                    "members": _gview(_gmembers(be, gid))})
    if route == "group_custom_role":
        gid = body.get("group_id") or ""
        group = be.one("groups", id=gid)
        if group is None:
            return _err("unknown_group")
        my = be.one("group_members", group_id=gid, username=me)
        if my is None or my["role"] not in ADMIN_ROLES:
            return _err("permission_denied",
                        "only admins can set custom roles")
        target = body.get("username") or ""
        trow = be.one("group_members", group_id=gid, username=target)
        if trow is None:
            return _err("not_a_member", target)
        trow["custom_role"] = str(body.get("custom_role") or "")[:48]
        _gevent(be, group, "custom_role_changed", me, target,
                [target])
        return _ok({"group_id": gid, "username": target,
                    "members": _gview(_gmembers(be, gid))})
    if route == "group_settings":
        gid = body.get("group_id") or ""
        group = be.one("groups", id=gid)
        if group is None:
            return _err("unknown_group")
        my = be.one("group_members", group_id=gid, username=me)
        if my is None or my["role"] not in ADMIN_ROLES:
            return _err("permission_denied",
                        "only admins can change group settings")
        merged = dict(group.get("settings") or {})
        for key in SETTINGS_KEYS:
            value = (body.get("settings") or {}).get(key)
            if value in ("everyone", "admins_only"):
                merged[key] = value
        group["settings"] = merged
        _gevent(be, group, "settings_changed", me, me)
        return _ok({"group_id": gid, "settings": merged})
    if route == "group_join_link":
        gid = body.get("group_id") or ""
        if be.one("groups", id=gid) is None:
            return _err("unknown_group")
        if be.one("group_members", group_id=gid,
                  username=me) is None:
            return _err("not_a_member")
        token = _invite(be, gid)
        return _ok({"group_id": gid, "token": token,
                    "link": f"agentlink://{gid}/{token}"})
    if route == "group_join":
        gid = body.get("group_id") or ""
        token = body.get("token") or body.get("link") or ""
        if str(token).startswith("agentlink://"):
            parsed = _parse_link(str(token))
            if parsed:
                gid, token = parsed
        group = be.one("groups", id=gid) if gid else None
        if group is None:
            return _err("unknown_group")
        if not _invite_valid(be, gid, token):
            return _err("invalid_invite")
        if be.one("group_members", group_id=gid,
                  username=me) is None:
            if len(_gmembers(be, gid)) >= MAX_GROUP:
                return _err("group_full",
                            "groups are capped at 50 agents")
            be.insert("group_members", {
                "group_id": gid, "username": me, "role": "member",
                "nickname": "", "custom_role": "",
                "added_by": "invite-link", "joined_at": now})
        _gevent(be, group, "joined_group", me, me)
        return _ok({"group_id": gid,
                    "members": _gview(_gmembers(be, gid))})
    if route == "channel_create":
        name = str(body.get("name") or "")[:80]
        if not name:
            return _err("bad_channel", "a channel needs a name")
        subs = body.get("members") or body.get("subscribers") or []
        for s in subs:
            if be.one("users", username=s) is None:
                return _err("unknown_username", s)
        cid = "c-" + uuid.uuid4().hex[:12]
        channel = {"id": cid, "name": name, "creator": me,
                   "key_epoch": 0, "created_at": now}
        be.insert("channels", channel)
        be.insert("channel_members", {
            "channel_id": cid, "username": me, "role": "superadmin",
            "added_by": me, "joined_at": now})
        added = []
        for s in subs:
            if s == me:
                continue
            if len(_cmembers(be, cid)) >= MAX_CHANNEL:
                return _err("channel_full",
                            "channels are capped at 1000 subscribers")
            be.insert("channel_members", {
                "channel_id": cid, "username": s,
                "role": "subscriber", "added_by": me,
                "joined_at": now})
            added.append(s)
        _cevent(be, channel, "added_to_channel", me, me, added)
        be.audit("channel_created", me, group_id=cid, status=name)
        return _ok({"channel_id": cid, "name": name,
                    "members": _cview(_cmembers(be, cid))})
    if route == "channel_add":
        cid = body.get("channel_id") or ""
        channel = be.one("channels", id=cid)
        if channel is None:
            return _err("unknown_channel")
        my = be.one("channel_members", channel_id=cid, username=me)
        if my is None or my["role"] not in ADMIN_ROLES:
            return _err("permission_denied",
                        "only channel admins can add subscribers")
        targets = body.get("members") or body.get("usernames") or []
        for t in targets:
            if be.one("users", username=t) is None:
                return _err("unknown_username", t)
        added = []
        for t in targets:
            if be.one("channel_members", channel_id=cid,
                      username=t) is not None:
                continue
            if len(_cmembers(be, cid)) >= MAX_CHANNEL:
                return _err("channel_full",
                            "channels are capped at 1000 subscribers")
            be.insert("channel_members", {
                "channel_id": cid, "username": t,
                "role": "subscriber", "added_by": me,
                "joined_at": now})
            added.append(t)
        _cevent(be, channel, "added_to_channel", me, me, added)
        return _ok({"channel_id": cid, "added": added,
                    "members": _cview(_cmembers(be, cid))})
    if route == "channel_remove":
        cid = body.get("channel_id") or ""
        channel = be.one("channels", id=cid)
        if channel is None:
            return _err("unknown_channel")
        target = body.get("username") or ""
        my = be.one("channel_members", channel_id=cid, username=me)
        if target != me and (my is None
                             or my["role"] not in ADMIN_ROLES):
            return _err("permission_denied",
                        "only channel admins can remove subscribers")
        be.tables["channel_keys"] = [
            k for k in be.rows("channel_keys")
            if not (k["channel_id"] == cid
                    and k["username"] == target)]
        be.tables["channel_members"] = [
            m for m in be.rows("channel_members")
            if not (m["channel_id"] == cid
                    and m["username"] == target)]
        return _ok({"channel_id": cid,
                    "members": _cview(_cmembers(be, cid))})
    if route == "channel_promote":
        cid = body.get("channel_id") or ""
        channel = be.one("channels", id=cid)
        if channel is None:
            return _err("unknown_channel")
        my = be.one("channel_members", channel_id=cid, username=me)
        if my is None or my["role"] != "superadmin":
            return _err("permission_denied",
                        "only the channel creator can promote admins")
        target = body.get("username") or ""
        trow = be.one("channel_members", channel_id=cid,
                      username=target)
        if trow is None:
            return _err("not_a_member", target)
        trow["role"] = "admin"
        _cevent(be, channel, "promoted", me, target, [target])
        return _ok({"channel_id": cid,
                    "members": _cview(_cmembers(be, cid))})
    if route == "channel_join_link":
        cid = body.get("channel_id") or ""
        if be.one("channels", id=cid) is None:
            return _err("unknown_channel")
        if be.one("channel_members", channel_id=cid,
                  username=me) is None:
            return _err("not_a_member")
        token = _invite(be, cid)
        return _ok({"channel_id": cid, "token": token,
                    "link": f"agentlink://{cid}/{token}"})
    if route == "channel_join":
        cid = body.get("channel_id") or ""
        token = body.get("token") or body.get("link") or ""
        if str(token).startswith("agentlink://"):
            parsed = _parse_link(str(token))
            if parsed:
                cid, token = parsed
        channel = be.one("channels", id=cid) if cid else None
        if channel is None:
            return _err("unknown_channel")
        if not _invite_valid(be, cid, token):
            return _err("invalid_invite")
        if be.one("channel_members", channel_id=cid,
                  username=me) is None:
            if len(_cmembers(be, cid)) >= MAX_CHANNEL:
                return _err("channel_full",
                            "channels are capped at 1000 subscribers")
            be.insert("channel_members", {
                "channel_id": cid, "username": me,
                "role": "subscriber", "added_by": "invite-link",
                "joined_at": now})
        _cevent(be, channel, "joined_channel", me, me)
        _cevent(be, channel, "subscribed_to_channel", me, me)
        return _ok({"channel_id": cid,
                    "members": _cview(_cmembers(be, cid))})
    if route in ("vault_pin", "vault_remove"):
        entry = be.one("vault",
                       id=body.get("vault_id")
                       or body.get("entry_id") or "")
        if entry is None:
            return _err("unknown_vault_entry")
        my = be.one("group_members", group_id=entry["group_id"],
                    username=me)
        authorized = my is not None and (
            entry["added_by"] == me or my["role"] in ADMIN_ROLES)
        if not authorized:
            return _err("permission_denied",
                        "only the contributor or a group admin can "
                        "do that")
        if route == "vault_pin":
            entry["pinned"] = 1 if body.get("pinned") else 0
            return _ok({"entry": _vault_shape(entry)})
        be.tables["vault"] = [v for v in be.rows("vault")
                              if v["id"] != entry["id"]]
        return _ok({"entry_id": entry["id"], "removed": True})
    return _err("not_found", "", 404)


def _vault_shape(row):
    out = dict(row)
    out["pinned"] = bool(out.get("pinned"))
    out["descriptor"] = out.get("descriptor") or {}
    return out


CoverageBackend._fn_groups = _fn_groups


# ----------------------------------------------------------------------
# grants mirror — the broker, seated on the real grants.py
# primitives (statement payload, inventory validation, digest,
# receipt canonical/hash) so the mirror is faithful by
# construction where the relay's own code defines the contract.
# ----------------------------------------------------------------------

from agentlink.connectors import (  # noqa: E402
    lawful_action_class)
from agentlink.grants import (  # noqa: E402
    GRANT_RATE_LIMITS, DEFAULT_RATE_LIMIT,
    receipt_canonical, receipt_hash, red_line_reason)

RECEIPT_FIELDS = ("id", "username", "ts", "scope", "connector",
                  "action", "target", "work_ref", "status", "detail")


def _grant_summary(row):
    if row is None:
        return None
    return {"status": row["status"],
            "grantor": row.get("grantor") or "",
            "granted_by": row.get("granted_by") or "",
            "granted_at": row.get("granted_at") or 0,
            "ceremony_at": row.get("ceremony_at") or 0,
            "requested_at": row.get("requested_at") or 0,
            "request_reason": str(row.get("request_reason") or "")[:200],
            "coverage": "connector_vault"}


def _add_receipt(be, username, scope, connector, action, target,
                 work_ref, status, detail):
    if not isinstance(detail, dict):
        detail = {}
    rec = {"id": "rcpt-" + uuid.uuid4().hex, "username": username,
           "ts": int(time.time()), "scope": scope,
           "connector": connector, "action": action, "target": target,
           "work_ref": work_ref, "status": status, "detail": detail}
    prevs = sorted(be.rows("grant_receipts"),
                   key=lambda r: r.get("seq", 0))
    if prevs:
        prev = dict(prevs[-1])
        if isinstance(prev.get("detail"), str):
            prev["detail"] = json.loads(prev["detail"] or "{}")
        rec["prev_hash"] = receipt_hash(prev)
    else:
        rec["prev_hash"] = ""
    sig = be._platform.sign(receipt_canonical(rec))
    rec["sig"] = base64.b64encode(sig).decode()
    row = dict(rec)
    row["detail"] = json.dumps(detail)
    be.insert("grant_receipts", row)
    be.audit("grant_action", username, target=target,
             work_id=work_ref, status=status, ref_id=rec["id"])
    return rec


def _verify_stmt(be, body, username, kind):
    stmt = body.get("statement")
    sig = body.get("sig")
    if not isinstance(stmt, dict) or not sig:
        return None
    if stmt.get("kind") != kind:
        return None
    ts = int(stmt.get("ts") or 0)
    if not ts or abs(int(time.time()) - ts) > 300:
        return None
    user = be.one("users", username=username)
    if not user or not user.get("sign_pub"):
        return None
    fields = {k: v for k, v in stmt.items() if k not in ("kind", "ts")}
    payload = grant_statement_payload(kind, username, ts, fields)
    try:
        Ed25519PublicKey.from_public_bytes(
            base64.b64decode(user["sign_pub"])).verify(
                base64.b64decode(sig), payload)
    except Exception:
        return None
    return stmt


def _load_inventory(be, username):
    row = be.one("agent_connectors", username=username)
    if not row:
        return []
    try:
        parsed = json.loads(row.get("inventory") or "[]")
        return parsed if isinstance(parsed, list) else []
    except Exception:
        return []


def _target_of(params):
    for k in ("to", "target", "id", "with"):
        v = (params or {}).get(k)
        if v:
            return str(v)
    return ""


def _bounded_result(result):
    raw = json.dumps(result or {}, sort_keys=True)
    if len(raw) <= 4096:
        return {"result": result or {}}
    return {"result_summary": raw[:1000], "truncated": True}


def _authorize(be, username, connector, action, params, work_ref,
               skip_red_line=False, skip_rate=False, approval_id=""):
    params = params or {}
    target = _target_of(params)

    def refusal(reason, outcome_reason, scope=""):
        rec = _add_receipt(be, username, scope, connector, action,
                           target, work_ref, "refused",
                           {"reason": reason})
        return {"status": "refused", "receipt_id": rec["id"],
                "reason": outcome_reason}

    inventory = _load_inventory(be, username)
    entry = next((e for e in inventory
                  if e.get("name") == connector), None)
    if entry is None:
        return refusal(
            f"connector {connector!r} is not in @{username}'s "
            "connector vault",
            f"connector {connector!r} is not in @{username}'s "
            "connector vault — the grant covers the connectors "
            "the owner has linked, and this is not one of them")
    if not entry.get("linked", True):
        return refusal(
            f"connector {connector!r} is not linked",
            f"connector {connector!r} is in the vault but "
            "not linked")
    scope = (entry.get("actions") or {}).get(action)
    if scope is None or not lawful_action_class(scope):
        return refusal(
            f"connector {connector!r} declares no action {action!r}",
            f"connector {connector!r} declares no action {action!r}")
    grant = be.one("grants", username=username)
    if grant is None or grant.get("status") != "active":
        state = "no grant on record" if grant is None else \
            f"grant status is {grant.get('status')!r}"
        rec = _add_receipt(be, username, scope, connector, action,
                           target, work_ref, "refused",
                           {"reason": f"no active grant ({state})"})
        return {"status": "refused", "receipt_id": rec["id"],
                "reason": f"@{username} holds no active grant "
                          f"({state}); the agent must ask its owner "
                          "for the one-time permission and the owner "
                          "must allow it"}
    user = be.one("users", username=username)
    bound = grant.get("bound_sign_pub") or ""
    if not bound or bound != (user or {}).get("sign_pub", ""):
        return refusal(
            "the grant is bound to a different identity",
            "the grant is bound to a different identity than the "
            "one presenting this name", scope)
    if not skip_red_line:
        reason = red_line_reason(connector, action)
        if reason is not None:
            approval = {"id": "gappr-" + uuid.uuid4().hex,
                        "username": username,
                        "ts": int(time.time()), "scope": scope,
                        "connector": connector, "action": action,
                        "target": target,
                        "params": json.dumps(params),
                        "work_ref": work_ref, "reason": reason,
                        "status": "awaiting_approval", "decided_by": "",
                        "decided_at": 0, "receipt_id": ""}
            be.insert("grant_approvals", approval)
            rec = _add_receipt(be, username, scope, connector,
                               action, target, work_ref,
                               "approval_queued",
                               {"reason": reason,
                                "approval_id": approval["id"]})
            return {"status": "awaiting_approval",
                    "approval_id": approval["id"],
                    "receipt_id": rec["id"], "reason": reason}
    if not skip_rate:
        limit = GRANT_RATE_LIMITS.get(scope, DEFAULT_RATE_LIMIT)
        since = int(time.time()) - 3600
        used = sum(1 for r in be.rows("grant_receipts")
                   if r["username"] == username
                   and r["scope"] == scope
                   and r["status"] == "executed"
                   and int(r["ts"]) >= since)
        if used >= limit:
            rec = _add_receipt(
                be, username, scope, connector, action, target,
                work_ref, "rate_limited",
                {"reason": f"platform rate limit for action class "
                           f"{scope} reached", "limit": limit,
                 "window_seconds": 3600})
            _open_alert(be, "grant_rate_limit", f"{username}:{scope}",
                        f"@{username} tripped the platform rate "
                        f"limit for action class {scope} ({limit} "
                        "actions / 3600s) — further actions in this "
                        "class fail closed until the window clears")
            return {"status": "rate_limited",
                    "receipt_id": rec["id"],
                    "reason": "platform rate limit reached for "
                              f"action class {scope}; the action "
                              "failed closed and a fleet alert "
                              "was raised"}
    token = "authz-" + uuid.uuid4().hex
    be.insert("grant_authz", {
        "token": token, "username": username, "connector": connector,
        "action": action, "scope": scope,
        "params_hash": hashlib.sha256(json.dumps(
            params, sort_keys=True,
            separators=(",", ":")).encode()).hexdigest(),
        "work_ref": work_ref, "approval_id": approval_id,
        "expires": int(time.time()) + 120})
    out = {"status": "authorized", "authorization": token,
           "scope": scope}
    if approval_id:
        out["approval_id"] = approval_id
    return out


def _fn_grants(be, me, route, body):
    now = int(time.time())
    if route == "request":
        stmt = _verify_stmt(be, body, me, "request")
        if stmt is None:
            return _err("grant statement did not verify")
        request_id = str(stmt.get("request_id") or "")[:64]
        if not request_id:
            return _err("request statement carries no request id")
        existing = be.one("grants", username=me)
        if existing is None:
            be.insert("grants", {
                "username": me, "status": "requested", "scopes": "[]",
                "granted_by": "", "grantor": "", "granted_at": 0,
                "ceremony_at": 0, "bound_sign_pub": "",
                "request_id": request_id, "requested_at": now,
                "request_reason": str(stmt.get("reason") or "")[:500],
                "updated_at": now})
        elif existing.get("status") != "active":
            existing.update({
                "status": "requested", "scopes": "[]",
                "granted_by": "", "grantor": "", "granted_at": 0,
                "ceremony_at": 0, "bound_sign_pub": "",
                "request_id": request_id, "requested_at": now,
                "request_reason": str(stmt.get("reason") or "")[:500],
                "updated_at": now})
        return _ok({"grant": _grant_summary(
            be.one("grants", username=me))})
    if route in ("allow", "ceremony"):
        stmt = _verify_stmt(be, body, me, "allow")
        if stmt is None:
            return _err("grant statement did not verify")
        grant = be.one("grants", username=me)
        if grant is None or grant.get("status") != "requested" or \
                grant.get("request_id") != str(stmt.get(
                    "request_id") or ""):
            return _err("no pending permission request matches "
                        "this allow — the agent must ask first")
        user = be.one("users", username=me)
        grantor = str(stmt.get("grantor") or "")[:80]
        grant.update({"status": "active", "scopes": "[]",
                      "granted_by": grantor, "grantor": grantor,
                      "granted_at": now,
                      "ceremony_at": int(stmt.get("ts") or 0),
                      "bound_sign_pub": (user or {}).get(
                          "sign_pub", ""),
                      "updated_at": now})
        return _ok({"grant": _grant_summary(grant)})
    if route == "revoke":
        stmt = _verify_stmt(be, body, me, "revoke")
        if stmt is None:
            return _err("grant statement did not verify")
        grant = be.one("grants", username=me)
        revoked = bool(grant and grant.get("status") == "active")
        if revoked:
            grant.update({"status": "revoked",
                          "granted_by": "agent-owner",
                          "updated_at": now})
        return _ok({"grant": _grant_summary(grant),
                    "revoked": revoked})
    if route == "query":
        inventory = _load_inventory(be, me)
        return _ok({"grant": _grant_summary(
            be.one("grants", username=me)),
            "connectors": inventory,
            "derived_capabilities": derived_capabilities(inventory)})
    if route == "connector_update":
        stmt = _verify_stmt(be, body, me, "connector_update")
        if stmt is None:
            return _err("connector statement did not verify")
        inventory = validate_inventory(body.get("connectors"))
        if inventory is None:
            be.audit("connector_inventory_refused", me)
            return _err("connector inventory failed validation")
        if inventory_digest(inventory) != str(
                stmt.get("inventory_digest") or ""):
            return _err("inventory digest does not match the "
                        "signed statement")
        existing = be.one("agent_connectors", username=me)
        if existing is None:
            be.insert("agent_connectors", {
                "username": me, "inventory": json.dumps(inventory),
                "updated_at": now})
        else:
            existing.update({"inventory": json.dumps(inventory),
                             "updated_at": now})
        return _ok({"connectors": len(inventory),
                    "derived_capabilities":
                        derived_capabilities(inventory)})
    if route == "action":
        return _ok(_authorize(be, me, str(body.get("connector") or ""),
                              str(body.get("action") or ""),
                              body.get("params") or {},
                              str(body.get("work_ref") or "")))
    if route == "report":
        token = str(body.get("authorization") or "")
        rows = [r for r in be.rows("grant_authz")
                if r["token"] == token]
        rec0 = rows[0] if rows else None
        if rec0 is not None:
            be.tables["grant_authz"] = [
                r for r in be.rows("grant_authz")
                if r["token"] != token]
        if rec0 is None or rec0["username"] != me or \
                int(rec0["expires"]) <= now:
            return _ok({"status": "refused",
                        "reason": "unknown, consumed or expired "
                                  "authorization — no receipt written"})
        status = body.get("status")
        error = str(body.get("error") or "")
        if status not in ("executed", "error"):
            status = "error"
            error = error or "bad reported status 'error'"
        if status == "executed":
            detail = _bounded_result(body.get("result"))
        else:
            detail = {"reason": error or "connector error"}
        if rec0.get("approval_id"):
            detail["approval_id"] = rec0["approval_id"]
        rec = _add_receipt(be, me, rec0["scope"], rec0["connector"],
                           rec0["action"], "",
                           rec0.get("work_ref") or "", status, detail)
        if rec0.get("approval_id"):
            approval = be.one("grant_approvals",
                              id=rec0["approval_id"])
            if approval:
                approval["status"] = "executed"
                approval["receipt_id"] = rec["id"]
        out = {"status": status, "receipt_id": rec["id"]}
        if status == "executed":
            out["result"] = body.get("result")
        else:
            out["reason"] = detail["reason"]
        return _ok(out)
    if route == "approvals":
        rows = [r for r in be.rows("grant_approvals")
                if r["username"] == me]
        if body.get("status"):
            rows = [r for r in rows
                    if r["status"] == body["status"]]
        rows.sort(key=lambda r: -int(r["ts"]))
        out = []
        for r in rows[:50]:
            row = dict(r)
            try:
                row["params"] = json.loads(row.get("params") or "{}")
            except Exception:
                row["params"] = {}
            out.append(row)
        return _ok({"approvals": out})
    if route == "decide":
        stmt = _verify_stmt(be, body, me, "decide")
        if stmt is None:
            return _err("grant statement did not verify")
        approval = be.one("grant_approvals",
                          id=str(stmt.get("approval_id") or ""))
        if approval is None or approval["username"] != me:
            return _err("no such approval in this agent's queue")
        if approval["status"] != "awaiting_approval":
            return _err("approval already decided "
                        f"({approval['status']})")
        approved = bool(stmt.get("approved"))
        approval["status"] = "approved" if approved else "rejected"
        approval["decided_by"] = str(stmt.get("decided_by") or "")[:80]
        approval["decided_at"] = now
        be.audit(f"grant_approval_{approval['status']}", me,
                 status=approval["status"])
        if not approved:
            return _ok({"status": "rejected",
                        "approval_id": approval["id"]})
        try:
            params = json.loads(approval.get("params") or "{}")
        except Exception:
            params = {}
        outcome = _authorize(
            be, me, approval["connector"], approval["action"],
            params, approval.get("work_ref") or "",
            skip_red_line=True, skip_rate=True,
            approval_id=approval["id"])
        return _ok(outcome)
    return _err("not_found", "", 404)


CoverageBackend._fn_grants = _fn_grants


# ----------------------------------------------------------------------
# blobs / library / account mirrors
# ----------------------------------------------------------------------

def _fn_blobs(be, me, route, body):
    if route == "delete":
        blob_id = body.get("blob_id") or ""
        meta = be.one("blobs", id=blob_id)
        allowed = False
        if meta:
            if meta.get("owner") == me:
                allowed = True
            elif meta.get("for_group"):
                mrow = be.one("group_members",
                              group_id=meta["for_group"], username=me)
                allowed = mrow is not None and \
                    mrow["role"] in ADMIN_ROLES
        if not allowed:
            return _err("permission_denied")
        be.r2.pop(blob_id, None)
        be.tables["blobs"] = [b for b in be.rows("blobs")
                              if b["id"] != blob_id]
        return _ok({"blob_id": blob_id, "deleted": True})
    if route == "chunk":
        sess = be.one("upload_sessions",
                      session_id=body.get("session_id") or "")
        if sess is None or sess["owner"] != me:
            return _err("unknown_session")
        try:
            data = base64.b64decode(body.get("data_b64") or "")
        except Exception:
            return _err("bad_chunk")
        if hashlib.sha256(data).hexdigest() != \
                (body.get("chunk_sha") or ""):
            return _err("bad_chunk_hash")
        index = int(body.get("index") or 0)
        be.r2[f"{sess['session_id']}-{index}"] = data
        try:
            have = json.loads(sess.get("chunks") or "[]")
        except Exception:
            have = []
        have = sorted(set(have) | {index})
        sess["chunks"] = json.dumps(have)
        return _ok({"have": have})
    if route == "session_finish":
        sess = be.one("upload_sessions",
                      session_id=body.get("session_id") or "")
        if sess is None or sess["owner"] != me:
            return _err("unknown_session")
        size = int(sess.get("size") or 0)
        chunk_size = int(sess.get("chunk_size") or 0)
        total = -(-size // chunk_size) if size and chunk_size else 0
        try:
            have = sorted(json.loads(sess.get("chunks") or "[]"))
        except Exception:
            have = []
        if have != list(range(total)):
            return _err("incomplete_upload",
                        f"have {len(have)} of {total} chunks")
        parts = []
        for i in range(total):
            key = f"{sess['session_id']}-{i}"
            if key not in be.r2:
                return _err("incomplete_upload",
                            f"chunk {i} object missing")
            parts.append(be.r2[key])
        whole = b"".join(parts)
        ct_sha = hashlib.sha256(whole).hexdigest()
        if ct_sha != (sess.get("ct_sha") or ""):
            return _err("bad_whole_hash")
        fin_channel = body.get("for_channel") or ""
        if fin_channel and be.one(
                "channel_members", channel_id=fin_channel,
                username=me) is None:
            return _err("not_a_member")
        blob_id = "b-" + ct_sha
        be.r2[blob_id] = whole
        for i in range(total):
            be.r2.pop(f"{sess['session_id']}-{i}", None)
        be.insert("blobs", {
            "id": blob_id, "owner": me,
            "for_user": sess.get("for_user") or "",
            "for_group": sess.get("for_group") or "",
            "for_channel": fin_channel,
            "whole_sha": sess.get("whole_sha") or "",
            "size": size, "created_at": int(time.time())})
        be.tables["upload_sessions"] = [
            s for s in be.rows("upload_sessions")
            if s["session_id"] != sess["session_id"]]
        be.audit("blob_upload_completed", me,
                 target=sess.get("for_user") or "",
                 group_id=sess.get("for_group") or "",
                 work_id=blob_id)
        return _ok({"blob_id": blob_id, "size": size})
    return _err("not_found", "", 404)


def _fn_library(be, me, route, body):
    def member_of(scope_id):
        if not scope_id:
            return False
        return be.one("group_members", group_id=scope_id,
                      username=me) is not None or \
            be.one("channel_members", channel_id=scope_id,
                   username=me) is not None

    if route == "search":
        rows = sorted(be.rows("library"),
                      key=lambda r: -int(r["ts"]))[:1000]
        q = str(body.get("q") or "").lower()
        out = []
        for row in rows:
            visible = row["sender"] == me or row["to_user"] == me \
                or (row.get("chain_next") and row["chain_next"] == me) \
                or (row.get("group_id")
                    and member_of(row["group_id"]))
            if not visible:
                continue
            if q and q not in str(row["filename"]).lower():
                continue
            if body.get("sender") and row["sender"] != body["sender"]:
                continue
            if body.get("group_id") and \
                    row["group_id"] != body["group_id"]:
                continue
            if body.get("hash_prefix") and not str(
                    row["sha256"]).startswith(body["hash_prefix"]):
                continue
            out.append(dict(row))
            if len(out) >= 100:
                break
        return _ok({"entries": out})
    if route == "fetch":
        entry = be.one("library", id=body.get("library_id") or "")
        if entry is None:
            return _err("unknown_library_entry")
        entitled = entry["sender"] == me or entry["to_user"] == me \
            or (entry.get("chain_next") and entry["chain_next"] == me)
        if not entitled and entry.get("group_id"):
            entitled = member_of(entry["group_id"])
        work = be.one("work", id=entry.get("work_id") or "")
        if not entitled or work is None:
            return _err("permission_denied")
        delivery = be.one("work_deliveries",
                          id=entry.get("delivery_id") or "")
        if delivery is None:
            return _err("unknown_library_entry")
        if entry["to_user"] == me:
            content = delivery.get("content_enc") or {}
        elif entry["sender"] == me:
            content = delivery.get("content_self") or {}
        elif entry.get("chain_next") and entry["chain_next"] == me:
            content = (delivery.get("content_next") or {}).get(
                me) or {}
        else:
            content = delivery.get("content_group") or {}
        return _ok({"entry": dict(entry), "content": content})
    return _err("not_found", "", 404)


def _compute_trust(be, username):
    score = 50
    now = int(time.time())
    for r in be.rows("work"):
        if r["assignee"] != username:
            continue
        status = r["status"]
        if status in ("completed", "covered"):
            score += 4
        elif status in ("delivered", "awaiting_approval"):
            score += 1
        deadline = r.get("deadline") or 0
        if deadline:
            if status == "completed" and \
                    int(r.get("updated_at") or 0) > deadline:
                score -= 6
            elif status not in ("completed", "covered", "delivered",
                                "awaiting_approval") \
                    and now > deadline:
                score -= 6
    changes = sum(1 for a in be.rows("audit_log")
                  if a["kind"] == "work_changes_requested"
                  and a["target"] == username)
    bad = sum(1 for a in be.rows("audit_log")
              if a["kind"] == "delivery_proof_verified"
              and a["actor"] == username and a["status"] == "false")
    score -= 6 * changes
    score -= 10 * bad
    return max(0, min(100, score))


NON_TERMINAL = ("assigned", "in_progress", "changes_requested",
                "delivered", "awaiting_approval", "awaiting_agent")


def _fn_account(be, me, route, body):
    if route == "directory":
        query = str(body.get("query") or "")
        capability = str(body.get("capability") or "")
        users = []
        for raw in sorted(be.rows("users"),
                          key=lambda r: r["username"]):
            if query and query not in raw["username"]:
                continue
            caps = raw.get("capabilities") or []
            if isinstance(caps, str):
                try:
                    caps = json.loads(caps)
                except Exception:
                    caps = []
            if capability and capability not in caps:
                continue
            row = {k: raw.get(k) for k in (
                "username", "display_name", "pubkey", "sign_pub",
                "cap_desc", "decision_link", "decision_link_detail",
                "delivery_ack", "auth_method", "designation",
                "last_seen", "recovery_hash", "recovery_used_at",
                "created_at")}
            row["capabilities"] = caps
            row["mode"] = "manual" if raw.get("mode") == "manual" \
                else "autonomous"
            act = be.one("activeness", username=raw["username"])
            row["online"] = bool(act) and act.get("state") in (
                "online", "suspect")
            row["trust_score"] = _compute_trust(be, raw["username"])
            row["core"] = {}
            row["core_compliant"] = None
            row["connection_pattern"] = ""
            detail = raw.get("decision_link_detail") or {}
            if isinstance(detail, str):
                try:
                    detail = json.loads(detail)
                except Exception:
                    detail = {}
            declared = raw.get("decision_link") or ""
            if declared not in ("linked", "pending"):
                declared = ""
            row["decision_link"] = declared
            row["decision_state"] = "operator" \
                if row["mode"] == "manual" else (declared
                                                 or "undeclared")
            row["decision_mode"] = detail.get("mode") or ""
            row["decision_verified"] = bool(detail.get("verified"))
            row["auth_legacy"] = raw.get("auth_method") in (
                "secret", "resume")
            users.append(row)
        users.sort(key=lambda r: (not r["online"], r["username"]))
        return _ok({"users": users})
    if route == "capabilities":
        caps = [str(c) for c in (body.get("capabilities") or [])]
        desc = str(body.get("description") or "")
        user = be.one("users", username=me)
        canonical = f"caps|{me}|{','.join(caps)}|{desc}".encode()
        ok = False
        if body.get("sig") and user and user.get("sign_pub"):
            try:
                Ed25519PublicKey.from_public_bytes(
                    base64.b64decode(user["sign_pub"])).verify(
                        base64.b64decode(body["sig"]), canonical)
                ok = True
            except Exception:
                ok = False
        if not ok:
            return _err("bad_signature",
                        "capability declaration did not verify")
        user["capabilities"] = json.dumps(caps)
        user["cap_desc"] = desc
        return _ok({"capabilities": caps, "description": desc})
    if route == "deregister":
        user = be.one("users", username=me)
        if user is None:
            return _err("unknown_username")
        blockers = []
        queued = sum(1 for q in be.rows("queue")
                     if q["to_username"] == me)
        if queued:
            blockers.append(
                f"{queued} undelivered frame(s) in the offline queue")
        live_work = [w for w in be.rows("work")
                     if (w["assignee"] == me or w["assigner"] == me)
                     and w["status"] in NON_TERMINAL]
        if live_work:
            blockers.append(
                f"{len(live_work)} non-terminal work item(s) as "
                "assigner/assignee")
        live_chains = [c for c in be.rows("chains")
                       if c["creator"] == me
                       and c["status"] in ("running", "paused")]
        if live_chains:
            blockers.append(
                f"{len(live_chains)} live chain(s) created by "
                "this agent")
        live_ids = {c["id"] for c in be.rows("chains")
                    if c["creator"] != me
                    and c["status"] in ("running", "paused")}
        hits = 0
        for s in be.rows("chain_steps"):
            if s["chain_id"] not in live_ids:
                continue
            if s["status"] not in ("pending", "active"):
                continue
            if s.get("target") == me or \
                    me in (s.get("assignees") or []):
                hits += 1
        if hits:
            blockers.append(
                f"{hits} live chain step(s) in other agents' "
                "chains target this agent")
        if blockers:
            return _err("deregister_blocked", "; ".join(blockers))
        removed = {}

        def wipe(table, pred):
            kept = [r for r in be.rows(table) if not pred(r)]
            removed[table] = len(be.rows(table)) - len(kept)
            be.tables[table] = kept

        work_ids = {w["id"] for w in be.rows("work")
                    if w["assignee"] == me or w["assigner"] == me}
        chain_ids = {c["id"] for c in be.rows("chains")
                     if c["creator"] == me}
        wipe("work_deliveries",
             lambda r: r["work_id"] in work_ids
             or r.get("deliverer") == me)
        wipe("work_checkpoints",
             lambda r: r["work_id"] in work_ids)
        wipe("work", lambda r: r["id"] in work_ids)
        wipe("chain_steps", lambda r: r["chain_id"] in chain_ids)
        wipe("chains", lambda r: r["id"] in chain_ids)
        wipe("queue", lambda r: r["to_username"] == me)
        wipe("message_reads", lambda r: r["reader"] == me)
        wipe("group_keys", lambda r: r["username"] == me)
        wipe("group_members", lambda r: r["username"] == me)
        wipe("channel_keys", lambda r: r["username"] == me)
        wipe("channel_members", lambda r: r["username"] == me)
        removed["invites"] = 0
        wipe("upload_sessions",
             lambda r: r["owner"] == me or r.get("for_user") == me)
        wipe("alerts", lambda r: r["subject"] == me)
        wipe("blobs",
             lambda r: r["owner"] == me or r.get("for_user") == me)
        wipe("library",
             lambda r: r["sender"] == me or r.get("to_user") == me)
        wipe("grant_approvals", lambda r: r["username"] == me)
        wipe("grant_receipts", lambda r: r["username"] == me)
        wipe("grants", lambda r: r["username"] == me)
        wipe("agent_connectors", lambda r: r["username"] == me)
        wipe("users", lambda r: r["username"] == me)
        total = sum(removed.values())
        be.audit("user_removed", me, target=me,
                 status=f"via=self;rows={total}")
        return _ok({"username": me, "removed": removed,
                    "total": total})
    return _err("not_found", "", 404)


CoverageBackend._fn_blobs = _fn_blobs
CoverageBackend._fn_library = _fn_library
CoverageBackend._fn_account = _fn_account


# ----------------------------------------------------------------------
# Doorbell stub + agent factory
# ----------------------------------------------------------------------

class StubDoorbell:
    def __init__(self):
        self.custom_token = None
        self.exchanged = False
        self.presence_writes = []
        self.heartbeat = None
        self.heartbeat_stopped = False
        self.cleared = []
        self.taps = []
        self.presence_listeners = []
        self.signals_started = threading.Event()
        self._signal_release = threading.Event()

    @property
    def has_token(self):
        return bool(self.custom_token)

    def set_custom_token(self, token):
        self.custom_token = token

    def exchange_custom_token(self):
        self.exchanged = True
        return {"idToken": "id-token"}

    def set_presence(self, username, client_version="", transport=""):
        self.presence_writes.append(username)
        return {}

    def start_heartbeat(self, username, on_transition=None):
        self.heartbeat = (username, on_transition)

    def stop_heartbeat(self, fire_offline=True):
        self.heartbeat_stopped = True

    def clear_presence(self, username):
        self.cleared.append(username)
        return {}

    def tap_signal(self, conversation_id, item_id):
        self.taps.append((conversation_id, item_id))
        return {}

    def listen_signals(self, callback, on_error=None):
        self.signals_started.set()
        self._signal_release.wait(timeout=60)
        raise DoorbellError("stream ended")

    def release_signals(self):
        self._signal_release.set()

    def listen_presence(self, username, callback, stop_event=None):
        self.presence_listeners.append(username)
        if stop_event is not None:
            stop_event.wait(timeout=60)

    def listen_digest(self, username, callback, stop_event=None):
        self.presence_listeners.append(username)
        if stop_event is not None:
            stop_event.wait(timeout=60)


def register_user(backend, username, identity, mode="autonomous"):
    backend.insert("users", {
        "username": username, "display_name": "",
        "pubkey": identity.public_key_b64,
        "sign_pub": identity.signing_public_key_b64,
        "capabilities": "[]", "cap_desc": "", "mode": mode,
        "decision_link": "", "decision_link_detail": "",
        "delivery_ack": 1, "auth_method": "key-v2",
        "designation": "production", "last_seen": 0,
        "recovery_hash": "", "recovery_used_at": 0,
        "created_at": NOW, "secret_hash": "unused",
        "vault_labels": "", "vault_content": "", "vault_blob": "",
        "vault_version": 0, "vault_entries": 0})
    backend.insert("directory", {
        "username": username, "pubkey": identity.public_key_b64,
        "sign_pub": identity.signing_public_key_b64})


def make_agent(tmp_path, backend, username, **kw):
    config = ServerlessConfig(
        supabase_url=SUPA, anon_key="anon-key",
        firebase_project_id="proj", firebase_api_key="fb-key",
        firebase_database_url=RTDB, login_edge_url=EDGE)
    doorbell = StubDoorbell()
    transport = ServerlessTransport(config, opener=backend.opener,
                                    doorbell=doorbell)
    kw.setdefault("mode", "manual")
    agent = Agent(username=username,
                  state_dir=str(tmp_path / username),
                  transport="serverless",
                  serverless_transport=transport, **kw)
    register_user(backend, username, agent.identity,
                  mode=kw["mode"])
    return agent, transport, doorbell


async def start(agent):
    await agent.start()
    return agent


async def stop(agent, doorbell):
    doorbell.release_signals()
    await agent.close()


def run(coro_fn):
    asyncio.run(coro_fn())


def audit_kinds(backend, kind=None, actor=None):
    rows = backend.rows("audit_log")
    if kind is not None:
        rows = [r for r in rows if r["kind"] == kind]
    if actor is not None:
        rows = [r for r in rows if r["actor"] == actor]
    return rows


# ----------------------------------------------------------------------
# Work lifecycle
# ----------------------------------------------------------------------

def test_work_lifecycle_end_to_end(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        alice, _ta, da = make_agent(tmp_path, backend, "alice")
        bob, _tb, db = make_agent(tmp_path, backend, "bob")
        await start(alice)
        await start(bob)
        try:
            created = await alice.assign_work(
                ["bob"], "Report", "Write the report")
            assert len(created) == 1
            wid = created[0]["id"]
            assert wid.startswith("w-")
            row = backend.one("work", id=wid)
            assert row["status"] == "assigned"
            assert row["assigner"] == "alice"
            frames = backend.queue_frames("bob", "work_assigned")
            assert len(frames) == 1
            assert frames[0]["work"]["id"] == wid
            # Bob's inbox decrypts the assignment.
            inbox = await bob.work_inbox()
            mine = next(w for w in inbox if w["id"] == wid)
            assert mine["title"] == "Report"
            # Progress: shape, mirror, frame, audit.
            out = await bob.report_progress(wid, 40, "halfway")
            assert out["progress_percent"] == 40
            row = backend.one("work", id=wid)
            assert row["status"] == "in_progress"
            assert any(f["work"]["id"] == wid for f in
                       backend.queue_frames("alice", "work_progress"))
            audits = audit_kinds(backend, "work_progress", "bob")
            assert audits and audits[-1]["status"] == "40"
            # Checkpoint mirror lands in the store + the row view.
            await bob.checkpoint(wid, {"step": "draft"})
            cp = backend.one("work_checkpoints", work_id=wid)
            assert cp is not None
            view = await alice._request(
                {"type": "work_inbox"})
            wview = next(w for w in view["work"] if w["id"] == wid)
            assert "checkpoint" in wview
            # Delivery with a file: proof verified, library entry.
            fpath = tmp_path / "report.txt"
            fpath.write_bytes(b"the report bytes")
            delivered = await bob.deliver_work(
                wid, "done", files=[str(fpath)])
            assert delivered["status"] == "delivered"
            row = backend.one("work", id=wid)
            assert row["proof_verified"] == 1
            proof_audits = audit_kinds(
                backend, "delivery_proof_verified", "bob")
            assert proof_audits[-1]["status"] == "true"
            entries = await alice.library_search(q="report.txt")
            assert len(entries) == 1
            fetched = await alice.library_fetch(entries[0]["id"])
            assert fetched["entry"]["filename"] == "report.txt"
            # Completion by the assigner.
            done = await alice._request({
                "type": "work_action", "work_id": wid,
                "action": "complete"})
            assert done["work"]["status"] == "completed"
            assert audit_kinds(backend, "work_completed", "alice")
            # Fail-closed pins, relay reasons in relay order:
            with pytest.raises(RequestFailed) as ei:
                await bob.deliver_work(wid, "again")
            assert ei.value.reason == "bad_status"
            with pytest.raises(RequestFailed) as ei:
                await alice._request({
                    "type": "deliver_work", "work_id": wid,
                    "attempt": 1, "proof": {},
                    "content_enc": {"ct": "x"}})
            assert ei.value.reason == "permission_denied"
            with pytest.raises(RequestFailed) as ei:
                await alice._request({
                    "type": "assign", "assignees": ["bob"],
                    "envelopes": {}})
            assert ei.value.reason == "bad_assign"
            with pytest.raises(RequestFailed) as ei:
                await alice.assign_work(["ghost"], "T", "x")
            assert ei.value.reason == "unknown_username"
            with pytest.raises(RequestFailed) as ei:
                await bob._request({
                    "type": "work_progress", "work_id": "w-nope",
                    "percent": 10, "content_enc": {"ct": "x"},
                    "content_self": {"ct": "y"}})
            assert ei.value.reason == "unknown_work"
            with pytest.raises(RequestFailed) as ei:
                await bob._request({
                    "type": "work_resume_failed",
                    "work_id": "w-nope", "reason": "x"})
            assert ei.value.reason == "unknown_work"
            # resume_failed on real work: two audits + the frame.
            out = await bob._request({
                "type": "work_resume_failed", "work_id": wid,
                "reason": "context lost"})
            assert out == {"work_id": wid}
            kinds = [r["status"] for r in audit_kinds(
                backend, "resume_failed", "bob")]
            assert "context lost" in kinds and "explicit" in kinds
        finally:
            await stop(alice, da)
            await stop(bob, db)

    run(scenario)


def test_work_approval_gate_and_chain(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        alice, _ta, da = make_agent(tmp_path, backend, "alice")
        bob, _tb, db = make_agent(tmp_path, backend, "bob")
        await start(alice)
        await start(bob)
        try:
            created = await alice.assign_work(
                ["bob"], "Gated", "needs approval",
                require_approval=True)
            wid = created[0]["id"]
            await bob.deliver_work(wid, "ready")
            row = backend.one("work", id=wid)
            assert row["status"] == "awaiting_approval"
            assert audit_kinds(
                backend, "work_awaiting_approval", "bob")
            # Bob cannot decide his own gate.
            with pytest.raises(RequestFailed) as ei:
                await bob._request({
                    "type": "work_action", "work_id": wid,
                    "action": "complete"})
            assert ei.value.reason == "permission_denied"
            out = await alice._request({
                "type": "work_action", "work_id": wid,
                "action": "approve"})
            assert out["work"]["status"] == "completed"
            assert audit_kinds(backend, "work_approved", "alice")
            # --- chain: bob -> alice, handoff carries the file --
            def env(agent, pub, obj):
                return agent._encrypt_obj(pub, obj)

            step1 = {"assignees": ["bob"], "envelopes": {"bob": {
                "enc": env(alice, bob.identity.public_key_b64,
                           {"title": "s1", "instructions": "one"}),
                "self": env(alice, alice.identity.public_key_b64,
                            {"title": "s1", "instructions": "one"})}}}
            step2 = {"assignees": ["alice"], "envelopes": {"alice": {
                "enc": env(alice, alice.identity.public_key_b64,
                           {"title": "s2", "instructions": "two"}),
                "self": env(alice, alice.identity.public_key_b64,
                            {"title": "s2", "instructions": "two"})}}}
            out = await alice._request({
                "type": "chain_create", "name": "pipeline",
                "steps": [step1, step2]})
            chain = out["chain"]
            assert chain["status"] == "running"
            assert chain["steps"][0]["status"] == "active"
            w1 = chain["steps"][0]["work_id"]
            assert w1
            fpath = tmp_path / "step1.bin"
            fpath.write_bytes(b"step one output")
            await bob.deliver_work(w1, "s1 done",
                                   files=[str(fpath)])
            await alice._request({
                "type": "work_action", "work_id": w1,
                "action": "complete"})
            chain = await alice.chain_get(chain["id"])
            assert chain["steps"][0]["status"] == "completed"
            assert chain["steps"][1]["status"] == "active"
            w2 = chain["steps"][1]["work_id"]
            frames = backend.queue_frames("alice", "work_assigned")
            mine = [f for f in frames
                    if f["work"]["id"] == w2]
            assert mine and mine[0]["work"]["prev_deliverables"]
            assert mine[0]["work"]["prev_deliverables"][0][
                "filename"] == "step1.bin"
            await alice.deliver_work(w2, "s2 done")
            await alice._request({
                "type": "work_action", "work_id": w2,
                "action": "complete"})
            chain = await alice.chain_get(chain["id"])
            assert chain["status"] == "completed"
            assert audit_kinds(backend, "chain_completed", "alice")
            # chain_list / chain_context / cancel pins
            chains = await alice.chain_list()
            assert any(c["id"] == chain["id"] for c in chains)
            out = await alice._request({
                "type": "chain_create", "name": "second",
                "steps": [step1]})
            second = out["chain"]["id"]
            with pytest.raises(RequestFailed) as ei:
                await bob.chain_cancel(second)
            assert ei.value.reason == "permission_denied"
            out = await alice.chain_cancel(second)
            assert out["status"] == "cancelled"
            assert audit_kinds(backend, "chain_cancelled", "alice")
            with pytest.raises(RequestFailed) as ei:
                await alice._request({
                    "type": "chain_create", "name": "empty",
                    "steps": []})
            assert ei.value.reason == "bad_chain"
        finally:
            await stop(alice, da)
            await stop(bob, db)

    run(scenario)


# ----------------------------------------------------------------------
# Groups / channels admin
# ----------------------------------------------------------------------

def test_groups_and_channels_admin(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        alice, _ta, da = make_agent(tmp_path, backend, "alice")
        bob, _tb, db = make_agent(tmp_path, backend, "bob")
        dave, _td, dd = make_agent(tmp_path, backend, "dave")
        for name in ("carol",):
            register_user(backend, name, Identity.ephemeral())
        await start(alice)
        await start(bob)
        await start(dave)
        try:
            out = await alice.group_create("Team", ["bob"])
            gid = out["group_id"]
            assert len(out["members"]) == 2
            assert backend.queue_frames("bob", "group_event")
            out = await alice.group_add(gid, ["carol"])
            assert len(out["members"]) == 3
            # Member cannot change settings; admin can.
            with pytest.raises(RequestFailed) as ei:
                await bob.group_settings(gid, {"assign_work":
                                               "admins_only"})
            assert ei.value.reason == "permission_denied"
            out = await alice.group_settings(
                gid, {"assign_work": "admins_only",
                      "bogus_key": "admins_only"})
            assert out["settings"]["assign_work"] == "admins_only"
            assert "bogus_key" not in out["settings"]
            # Nickname: member cannot set another's; admin can.
            with pytest.raises(RequestFailed) as ei:
                await bob.group_set_nickname(
                    gid, "C", username="carol")
            assert ei.value.reason == "permission_denied"
            out = await alice.group_set_nickname(
                gid, "Caz", username="carol")
            assert any(m["nickname"] == "Caz"
                       for m in out["members"])
            # Custom role via admin, then role-based assignment.
            out = await alice.group_set_custom_role(
                gid, "carol", "reviewer")
            assert any(m["custom_role"] == "reviewer"
                       for m in out["members"])
            # Promote bob; bob (admin) removes carol; the removed
            # frame reaches carol and nobody else as that event.
            await alice.group_promote(gid, "bob")
            out = await bob.group_remove(gid, "carol")
            assert len(out["members"]) == 2
            removed = [f for f in backend.queue_frames(
                "carol", "group_event")
                if f["event"] == "removed_from_group"]
            assert len(removed) == 1
            # The creator cannot be removed by an admin.
            with pytest.raises(RequestFailed) as ei:
                await bob.group_remove(gid, "alice")
            assert ei.value.reason == "permission_denied"
            # Read paths (transport): members view + settings.
            view = await bob.group_members(gid)
            assert view["settings"]["assign_work"] == "admins_only"
            assert len(view["members"]) == 2
            # Invite flow: link -> dave joins; bad token refused.
            link = await bob.group_join_link(gid)
            out = await dave.group_join(link["link"])
            assert any(m["username"] == "dave"
                       for m in out["members"])
            with pytest.raises(RequestFailed) as ei:
                await dave.group_join(f"agentlink://{gid}/bogus")
            assert ei.value.reason == "invalid_invite"
            # Capacity: fill to 50, the 51st refuses group_full.
            fillers = [f"user{i:02d}" for i in range(60)]
            for name in fillers:
                register_user(backend, name, Identity.ephemeral())
            out = await alice.group_create("Big", [])
            big = out["group_id"]
            added = await alice.group_add(big, fillers[:49])
            assert len(added["members"]) == 50
            with pytest.raises(RequestFailed) as ei:
                await alice.group_add(big, ["user59"])
            assert ei.value.reason == "group_full"
            # Channels: create, admin rules, join's two events.
            out = await alice.channel_create("News", ["bob"])
            cid = out["channel_id"]
            assert audit_kinds(backend, "channel_created", "alice")
            with pytest.raises(RequestFailed) as ei:
                await bob.channel_add(cid, ["dave"])
            assert ei.value.reason == "permission_denied"
            await alice.channel_promote(cid, "bob")
            out = await bob.channel_add(cid, ["dave"])
            assert len(out["members"]) == 3
            # Dave leaves (self-remove is silent), rejoins by link.
            await dave.channel_remove(cid, "dave")
            link = await alice.channel_join_link(cid)
            before = len(backend.queue_frames("alice",
                                              "channel_event"))
            out = await dave.channel_join(link["link"])
            assert any(m["username"] == "dave"
                       for m in out["members"])
            events = [f["event"] for f in backend.queue_frames(
                "alice", "channel_event")[before:]]
            assert events[-2:] == ["joined_channel",
                                   "subscribed_to_channel"]
            view = await bob.channel_members(cid)
            assert len(view["members"]) == 3
        finally:
            await stop(alice, da)
            await stop(bob, db)
            await stop(dave, dd)

    run(scenario)


# ----------------------------------------------------------------------
# Vault + blobs
# ----------------------------------------------------------------------

def test_vault_and_blob_paths(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        alice, _ta, da = make_agent(tmp_path, backend, "alice")
        bob, _tb, db = make_agent(tmp_path, backend, "bob")
        register_user(backend, "carol", Identity.ephemeral())
        await start(alice)
        await start(bob)
        try:
            out = await alice.group_create("VaultTeam", ["bob"])
            gid = out["group_id"]
            fpath = tmp_path / "secret.txt"
            fpath.write_bytes(b"vault bytes")
            entry = await alice.vault_put(gid, str(fpath))
            assert entry["name"] == "secret.txt"
            audits = audit_kinds(backend, "vault_added", "alice")
            assert audits and audits[-1]["status"] == "secret.txt"
            files = await bob.vault_list(gid)
            assert len(files) == 1
            # A member is entitled to the vault blob itself (the
            # group-key decrypt is the daemon-phase path).
            blob = await bob._request({
                "type": "blob_get",
                "blob_id": files[0]["descriptor"]["blob_id"]})
            assert blob["size"] > 0
            # Pin: contributor/admin only.
            with pytest.raises(RequestFailed) as ei:
                await bob.vault_pin(entry["id"])
            assert ei.value.reason == "permission_denied"
            pinned = await alice.vault_pin(entry["id"])
            assert pinned["pinned"] is True
            with pytest.raises(RequestFailed) as ei:
                await bob.vault_remove(entry["id"])
            assert ei.value.reason == "permission_denied"
            # A descriptor without its blob refuses, relay-shaped.
            with pytest.raises(RequestFailed) as ei:
                await alice._request({
                    "type": "vault_add", "group_id": gid,
                    "descriptor": {"name": "x"}})
            assert ei.value.reason == "bad_vault_file"
            removed = await alice.vault_remove(entry["id"])
            assert removed["removed"] is True
            assert await bob.vault_list(gid) == []
            # Credentials vault: publish + fetch_meta + blob.
            await alice.vault_remember(
                "mail", "alice@example.com", "s3cret")
            meta = await alice._request(
                {"type": "vault_fetch_meta"})
            assert meta["present"] is True
            assert meta["version"] >= 1
            user = backend.one("users", username="alice")
            assert user["vault_blob"]
            blob = await alice._request(
                {"type": "blob_get", "blob_id": user["vault_blob"]})
            assert blob["size"] > 0
            # Small blob roundtrip + entitlement + delete rules.
            up = await alice.upload_blob(b"tiny", for_user="bob")
            assert isinstance(up, str) and up.startswith("b-")
            got = await bob._request(
                {"type": "blob_get", "blob_id": up})
            assert base64.b64decode(got["data_b64"]) == b"tiny"
            with pytest.raises(RequestFailed) as ei:
                await alice._request({
                    "type": "blob_get", "blob_id": "b-missing"})
            assert ei.value.reason == "permission_denied"
            with pytest.raises(RequestFailed) as ei:
                await bob._request({
                    "type": "blob_delete", "blob_id": up})
            assert ei.value.reason == "permission_denied"
            out = await alice._request({
                "type": "blob_delete", "blob_id": up})
            assert out["deleted"] is True
            # Chunked session: >1 chunk, dedup, bad hash pin.
            data = bytes(range(256)) * 9000  # ~2.3 MB
            up = await alice.upload_blob(data, for_user="bob")
            assert isinstance(up, str) and up.startswith("b-")
            got = await bob._request(
                {"type": "blob_get", "blob_id": up})
            assert base64.b64decode(got["data_b64"]) == data
            again = await alice.upload_blob(data, for_user="bob")
            assert again == up
            assert audit_kinds(
                backend, "blob_upload_completed", "alice")
            with pytest.raises(RequestFailed) as ei:
                await alice._request({
                    "type": "blob_chunk", "session_id": "u-nope",
                    "index": 0, "chunk_sha": "x", "data_b64": ""})
            assert ei.value.reason == "unknown_session"
        finally:
            await stop(alice, da)
            await stop(bob, db)

    run(scenario)


# ----------------------------------------------------------------------
# Grants: the full broker ceremony in serverless mode
# ----------------------------------------------------------------------

def test_grants_full_ceremony(tmp_path):
    backend = CoverageBackend()
    from agentlink.connectors import CallableConnector

    async def scenario():
        alice, _ta, da = make_agent(
            tmp_path, backend, "alice", mode="autonomous")
        await start(alice)
        try:
            calls = []

            def execute(action, params):
                calls.append((action, params))
                return {"echo": action}

            conn = CallableConnector(
                "gmail", execute, service="gmail", label="Gmail",
                oauth_scopes=("https://mail.google.com/",),
                actions={"read_inbox": "mail.read",
                         "send_mail": "mail.send",
                         "delete_all": "delete.bulk"},
                capabilities=())
            await alice.register_connector(conn)
            inv = await alice.my_connectors()
            assert inv["connectors"][0]["name"] == "gmail"
            assert "email.receive" in inv["derived_capabilities"]
            assert "email.send" in inv["derived_capabilities"]
            # No grant yet: refused WITH a receipt, scope resolved.
            out = await alice.connector_action(
                "gmail", "read_inbox", {"to": "x@y.z"})
            assert out["status"] == "refused"
            assert "no active grant" in out["reason"]
            # Ceremony: request -> allow -> active.
            req = await alice.request_permission("for mail")
            assert req["status"] == "requested"
            summary = await alice.my_grant()
            assert summary["status"] == "requested"
            out = await alice.connector_action(
                "gmail", "read_inbox", {})
            assert out["status"] == "refused"
            allowed = await alice.allow_permission("Alice Owner")
            assert allowed["grant"]["status"] == "active"
            assert allowed["grant"]["grantor"] == "Alice Owner"
            assert allowed["grant"]["coverage"] == "connector_vault"
            # Authorized action executes on the host and receipts.
            out = await alice.connector_action(
                "gmail", "read_inbox", {"to": "x@y.z"})
            assert out["status"] == "executed"
            assert out["result"] == {"echo": "read_inbox"}
            assert calls == [("read_inbox", {"to": "x@y.z"})]
            # The receipt chain verifies end to end.
            receipts = list(backend.rows("grant_receipts"))
            assert len(receipts) >= 3
            prev = None
            for rec in receipts:
                view = dict(rec)
                view["detail"] = json.loads(rec["detail"] or "{}")
                assert verify_receipt(backend.platform_pub, view)
                if prev is not None:
                    assert rec["prev_hash"] == receipt_hash(prev)
                prev = view
            executed = [r for r in receipts
                        if r["status"] == "executed"]
            assert executed and executed[-1]["scope"] == "mail.read"
            # The report-path receipt carries target "" (the
            # broker receipts executions without a target); the
            # params-derived target lives on authorize-time
            # receipts like the pre-grant refusal.
            assert executed[-1]["target"] == ""
            refused = [r for r in receipts
                       if r["status"] == "refused"]
            assert refused[0]["target"] == "x@y.z"
            assert refused[0]["scope"] == "mail.read"
            # Red line: approval queue -> owner decides -> executes.
            out = await alice.connector_action(
                "gmail", "delete_all", {})
            assert out["status"] == "awaiting_approval"
            approvals = await alice.pending_approvals()
            assert len(approvals) == 1
            assert approvals[0]["connector"] == "gmail"
            decided = await alice.decide_approval(
                approvals[0]["id"], True, decided_by="Alice Owner")
            assert decided["status"] == "executed"
            approval = backend.one(
                "grant_approvals", id=approvals[0]["id"])
            assert approval["status"] == "executed"
            assert approval["receipt_id"]
            # Granularity pins: undeclared action / unknown
            # connector refuse with the broker's exact shape.
            out = await alice.connector_action(
                "gmail", "teleport", {})
            assert out["status"] == "refused"
            assert "declares no action" in out["reason"]
            out = await alice.connector_action("nope", "read", {})
            assert out["status"] == "refused"
            assert "is not in" in out["reason"]
            # Digest mismatch on a hand-built connector statement.
            out = await alice._statement_request(
                "connector_update", "connector_update",
                {"inventory_digest": "0" * 64},
                {"connectors": []})
            assert out["status"] == "refused"
            assert "digest does not match" in out["reason"]
            # Revoke closes the gate again.
            out = await alice.revoke_permission()
            assert out["grant"]["status"] == "revoked"
            out = await alice.connector_action(
                "gmail", "read_inbox", {})
            assert out["status"] == "refused"
            assert "grant status is 'revoked'" in out["reason"]
        finally:
            await stop(alice, da)

    run(scenario)


# ----------------------------------------------------------------------
# Decision-link declaration + directory/capabilities/deregister
# ----------------------------------------------------------------------

def test_decision_link_declaration(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        carol, transport, dc = make_agent(
            tmp_path, backend, "carol", mode="autonomous")
        try:
            # Transport-level: the declaration rides the login
            # ceremony's verify and lands on the registry row.
            transport.login(
                "carol", carol.identity.sign,
                decision_link="pending",
                decision_link_detail={
                    "mode": "handlers", "verified": False,
                    "checked_at": 123})
            user = backend.one("users", username="carol")
            assert user["decision_link"] == "pending"
            detail = json.loads(user["decision_link_detail"])
            assert detail == {"mode": "handlers",
                              "verified": False, "checked_at": 123}
            # The setter path (link-state changes after login).
            transport.update_decision_link(
                "linked", {"mode": "handlers", "verified": True,
                           "checked_at": 456})
            user = backend.one("users", username="carol")
            assert user["decision_link"] == "linked"
            assert json.loads(user["decision_link_detail"])[
                "verified"] is True
            # Invalid shapes are ignored, never written.
            transport.update_decision_link(
                "bogus", {"mode": "handlers", "verified": True,
                          "checked_at": 789})
            user = backend.one("users", username="carol")
            assert user["decision_link"] == "linked"
            # A re-login re-sends the stored declaration.
            transport.login("carol", carol.identity.sign)
            user = backend.one("users", username="carol")
            assert user["decision_link"] == "linked"
        finally:
            dc.release_signals()

        # Agent-level: an autonomous agent with handlers wired
        # declares the verified form at start; a manual agent
        # declares nothing and reads as the operator's seat.
        alice, _ta, da = make_agent(
            tmp_path, backend, "alice", mode="autonomous")
        alice.on_message(lambda msg: None)
        await start(alice)
        try:
            user = backend.one("users", username="alice")
            assert user["decision_link"] == "linked"
            detail = json.loads(user["decision_link_detail"])
            assert detail["mode"] == "handlers"
            assert detail["verified"] is True
        finally:
            await stop(alice, da)
        man, _tm, dm = make_agent(
            tmp_path, backend, "mandy", mode="manual")
        await start(man)
        try:
            user = backend.one("users", username="mandy")
            assert (user["decision_link"] or "") == ""
            users = await man.directory()
            row = next(u for u in users
                       if u["username"] == "mandy")
            assert row["decision_state"] == "operator"
        finally:
            await stop(man, dm)

    run(scenario)


def test_directory_capabilities_deregister(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        alice, _ta, da = make_agent(tmp_path, backend, "alice")
        bob, _tb, db = make_agent(tmp_path, backend, "bob")
        carol, _tc, dc = make_agent(tmp_path, backend, "carol")
        await start(alice)
        await start(bob)
        await start(carol)
        try:
            register_user(backend, "dave", Identity.ephemeral())
            users = await alice.directory()
            names = {u["username"] for u in users}
            assert {"alice", "bob", "carol", "dave"} <= names
            bob_row = next(u for u in users
                           if u["username"] == "bob")
            assert bob_row["trust_score"] == 50
            # Bob's agent is started: login wrote his activeness,
            # so he reads online. Dave never connected: offline.
            assert bob_row["online"] is True
            dave_row = next(u for u in users
                            if u["username"] == "dave")
            assert dave_row["online"] is False
            # Capabilities: signed declaration lands; a forged
            # signature refuses.
            out = await bob.update_capabilities(
                ["email.receive"], "reads mail")
            assert out["capabilities"] == ["email.receive"]
            users = await alice.directory(
                capability="email.receive")
            assert [u["username"] for u in users] == ["bob"]
            with pytest.raises(RequestFailed) as ei:
                await bob._request({
                    "type": "update_capabilities",
                    "capabilities": ["x"], "description": "",
                    "sig": "AAAA"})
            assert ei.value.reason == "bad_signature"
            # Deregister blockers: a queued frame blocks carol.
            backend.enqueue("carol", {"type": "message",
                                      "id": "held-1"})
            with pytest.raises(RequestFailed) as ei:
                await carol.deregister()
            assert ei.value.reason == "deregister_blocked"
            assert "undelivered frame(s)" in ei.value.detail
            backend.tables["queue"] = [
                q for q in backend.rows("queue")
                if q["to_username"] != "carol"]
            out = await carol.deregister()
            assert out["removed"]["users"] == 1
            assert backend.one("users", username="carol") is None
            assert audit_kinds(backend, "user_removed", "carol")
        finally:
            await stop(alice, da)
            await stop(bob, db)
            await stop(carol, dc)

    run(scenario)


# ----------------------------------------------------------------------
# History backfill: exactly-once journal merge
# ----------------------------------------------------------------------

def test_history_backfill_exactly_once(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        alice, _ta, da = make_agent(tmp_path, backend, "alice")
        bob, _tb, db = make_agent(tmp_path, backend, "bob")
        await start(alice)
        await start(bob)
        try:
            gout = await alice.group_create("Hist", ["bob"])
            hist_gid = gout["group_id"]
            bob_id = bob.identity
            alice_pub = alice.identity.public_key_b64

            def audit_row(kind, actor, target, ref_id, body=None,
                          group_id=""):
                env = None
                if body is not None:
                    env = bob_id.encrypt_for(alice_pub, json.dumps(
                        {"body": body, "kind": "text"}).encode())
                row = {"ts": NOW, "kind": kind, "actor": actor,
                       "target": target, "group_id": group_id,
                       "work_id": "", "status": "", "priority": "",
                       "size": 0, "mentions": [], "ref_id": ref_id,
                       "sender_nickname": "", "sender_role": "",
                       "sender_custom_role": "", "oversight": "",
                       "content_envelope": json.dumps(env)
                       if env else ""}
                return backend.insert("audit_log", row)

            audit_row("message", "bob", "alice", "hist-1", "first")
            audit_row("message", "bob", "alice", "hist-2", "second")
            audit_row("group_message", "bob", "", "hist-3",
                      "in group", group_id=hist_gid)
            # An undecryptable row becomes a sealed stub, kept.
            bad = audit_row("message", "bob", "alice", "hist-4")
            bad["content_envelope"] = json.dumps(
                {"alg": "x25519-chacha20poly1305",
                 "eph_pub": "AAAA", "nonce": "AAAA", "ct": "AAAA"})
            # A work row becomes a sealed work record.
            audit_row("work_delivered", "bob", "alice", "hist-5")
            # Alice's OWN sent message is her history too (the
            # party test counts actor == user, as on the relay);
            # it merges as a born-taken sent record.
            audit_row("message", "alice", "bob", "hist-9", "mine")
            # hist-2 was ALSO delivered live: journal already has it.
            alice.mailbox.put_if_absent(
                {"id": "hist-2", "from": "bob", "to": "alice",
                 "group_id": None, "channel_id": None,
                 "body": "second", "kind": "text", "ts": NOW},
                taken=True)
            out = await alice.sync_history()
            assert "error" not in out
            assert out["fetched"] == 6
            assert out["inserted"] == 5  # hist-2 already journaled
            for mid in ("hist-1", "hist-2", "hist-3", "hist-4",
                        "hist-5", "hist-9"):
                assert alice.mailbox.get(mid) is not None, mid
            assert alice.mailbox.get("hist-1")["body"] == "first"
            stub = alice.mailbox.get("hist-4")
            assert stub is not None and not stub.get("body")
            work_rec = alice.mailbox.get("hist-5")
            assert work_rec["kind"] == "work"
            # Second pass: nothing new, nothing duplicated.
            out = await alice.sync_history()
            assert out["inserted"] == 0
            assert out["fetched"] == 6
        finally:
            await stop(alice, da)
            await stop(bob, db)

    run(scenario)


# ----------------------------------------------------------------------
# Deliberate dispositions: servers + rooms
# ----------------------------------------------------------------------

def test_servers_and_rooms_dispositions(tmp_path):
    backend = CoverageBackend()

    async def scenario():
        alice, _ta, da = make_agent(tmp_path, backend, "alice")
        await start(alice)
        try:
            # The mesh question, answered truthfully: no peer
            # servers exist in serverless mode.
            assert await alice.servers() == []
            out = await alice._request({"type": "servers"})
            assert out == {"servers": []}
            # Voice signalling stays fail-closed BY NAME: the
            # leg is parked by the owner's standing ruling, and
            # signalling without media would be a half-wired path.
            for ftype in ("room_open", "room_join", "room_leave",
                          "room_close", "room_signal"):
                with pytest.raises(RequestFailed) as ei:
                    await alice._request({"type": ftype})
                assert ei.value.reason == "serverless_unsupported"
            # whoami + self_report ride the transport too.
            me = alice.whoami()
            assert me["username"] == "alice"
            out = await alice._request(
                {"type": "self_report", "event": "disk_full"})
            assert out == {"ok": True}
            reps = audit_kinds(backend, "self_repair", "alice")
            assert len(reps) == 2
            assert all(r["status"] == "disk_full" for r in reps)
        finally:
            await stop(alice, da)

    run(scenario)


# ----------------------------------------------------------------------
# Static pins on the shipped TypeScript + the coverage migration
# ----------------------------------------------------------------------

FN_DIR = ROOT / "supabase" / "functions"


def _fn(name):
    return (FN_DIR / name / "index.ts").read_text()


def test_ts_contract_pins():
    work = _fn("agentlink-work")
    for route in ('case "assign"', 'case "deliver"',
                  'case "action"', 'case "chain_create"',
                  'case "chain_cancel"'):
        assert route in work
    for s in ("unknown_group", "not_a_member", "bad_assign",
              "empty_role", "role_mismatch", "plaintext_not_allowed",
              "unknown_work", "stale_attempt", "bad_proof",
              "bad_delivery", "delivery_proof_verified",
              "work_assigned", "decision_link_notice",
              "chain_completed", "work_covered"):
        assert s in work, s
    groups = _fn("agentlink-groups")
    for route in ("group_create", "group_add", "group_remove",
                  "group_promote", "group_demote", "group_nickname",
                  "group_custom_role", "group_settings",
                  "group_join_link", "group_join",
                  "channel_create", "channel_add",
                  "channel_remove", "channel_promote",
                  "channel_join_link", "channel_join", "vault_pin",
                  "vault_remove"):
        assert f'case "{route}"' in groups, route
    for s in ("group_full", "channel_full", "invalid_invite",
              "removed_from_group", "subscribed_to_channel",
              "channel_created", "unknown_vault_entry"):
        assert s in groups, s
    grants = _fn("agentlink-grants")
    for route in ("request", "allow", "ceremony", "revoke",
                  "query", "connector_update", "action", "report",
                  "approvals", "decide"):
        assert f'case "{route}"' in grants, route
    for s in ("grant statement did not verify",
              "connector statement did not verify",
              "no pending permission request matches this allow",
              "inventory digest does not match the signed statement",
              "connector inventory failed validation",
              "approval_queued", "rate_limited", "al_grant_authz",
              "agentlink-grant-v1"):
        assert s in grants, s
    # The Phase 2 append pipe is gone — receipts are minted by
    # the broker inside the function, nowhere else.
    assert 'case "receipt"' not in grants
    blobs = _fn("agentlink-blobs")
    for route in ("delete", "chunk", "session_finish"):
        assert f'case "{route}"' in blobs, route
    for s in ("unknown_session", "bad_chunk_hash",
              "incomplete_upload", "bad_whole_hash",
              "blob_upload_completed"):
        assert s in blobs, s
    library = _fn("agentlink-library")
    assert 'case "search"' in library and 'case "fetch"' in library
    assert "unknown_library_entry" in library
    account = _fn("agentlink-account")
    for route in ("directory", "capabilities", "deregister"):
        assert f'case "{route}"' in account, route
    for s in ("deregister_blocked", "bad_signature",
              "user_removed", "NON_TERMINAL"):
        assert s in account, s
    login = _fn("agentlink-login")
    assert "decision_link" in login and \
        "decision_link_detail" in login
    shared = (FN_DIR / "_shared" / "v200.ts").read_text()
    assert "signEd25519" in shared
    assert "0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, " \
        "0x2b, 0x65" in shared
    migration = (ROOT / "supabase" /
                 "migration-v200-coverage.sql").read_text()
    assert "al_grant_authz" in migration
    assert "al_grant_receipts_prev_hash_key" in migration
    assert "grant-authz-purge" in migration


def test_sign_ed25519_construction_crosscheck(tmp_path):
    """The PKCS#8 construction the shared signEd25519 uses —
    0x302e020100300506032b657004220420 prefix + 32-byte seed —
    produces signatures Python verifies. (Node's WebCrypto is
    the same implementation family Deno ships; the TypeScript
    body itself is pinned statically above.)"""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available")
    script = tmp_path / "sign.mjs"
    seed = base64.b64encode(bytes(range(32))).decode()
    script.write_text(f"""
import {{ webcrypto }} from "node:crypto";
const prefix = Buffer.from(
  "302e020100300506032b657004220420", "hex");
const seed = Buffer.from("{seed}", "base64");
const pkcs8 = Buffer.concat([prefix, seed]);
const key = await webcrypto.subtle.importKey(
  "pkcs8", pkcs8, {{ name: "Ed25519" }}, false, ["sign"]);
const sig = await webcrypto.subtle.sign(
  "Ed25519", key, new TextEncoder().encode("agentlink"));
console.log(Buffer.from(sig).toString("base64"));
""")
    out = subprocess.run([node, str(script)], capture_output=True,
                         text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    sig = base64.b64decode(out.stdout.strip())
    priv = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    pub = Ed25519PublicKey.from_public_bytes(
        priv.public_key().public_bytes_raw())
    pub.verify(sig, b"agentlink")  # raises on mismatch


def test_sha256hex_accepts_bytes_and_strings(tmp_path):
    """The shared sha256Hex must hash RAW BYTES as well as
    strings: agentlink-blobs passes Uint8Array chunk/whole bytes
    and agentlink-groups passes TextEncoder-encoded invite
    tokens, while login/dashboard/oversight pass strings. The
    pre-fix helper ran TextEncoder().encode() on whatever it
    received, so a Uint8Array was stringified to "0,1,2,..."
    text and hashed wrong — every blob chunk/whole check would
    have failed closed in production. Caught by the deploy
    review (2026-11-05); pinned here with a Node cross-check
    against hashlib (Node's WebCrypto is the implementation
    family Deno ships)."""
    shared = (FN_DIR / "_shared" / "v200.ts").read_text()
    assert "data: string | Uint8Array" in shared
    assert 'typeof data === "string"' in shared
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available")
    script = tmp_path / "sha.mjs"
    script.write_text("""
function hexEncode(bytes){return [...bytes].map(
  (b)=>b.toString(16).padStart(2,"0")).join("");}
async function sha256Bytes(data){return new Uint8Array(
  await crypto.subtle.digest("SHA-256", data));}
async function sha256Hex(data){
  const bytes = typeof data === "string"
    ? new TextEncoder().encode(data) : data;
  return hexEncode(await sha256Bytes(bytes));}
const chunk = new Uint8Array([0,1,2,250,251,252,10,20,30]);
console.log(await sha256Hex(chunk));
console.log(await sha256Hex("hello-agentlink"));
console.log(await sha256Hex(
  new TextEncoder().encode("invite-token-abc")));
""")
    out = subprocess.run([node, str(script)], capture_output=True,
                         text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    got = out.stdout.strip().splitlines()
    assert got[0] == hashlib.sha256(
        bytes([0, 1, 2, 250, 251, 252, 10, 20, 30])).hexdigest()
    assert got[1] == hashlib.sha256(b"hello-agentlink").hexdigest()
    assert got[2] == hashlib.sha256(b"invite-token-abc").hexdigest()
