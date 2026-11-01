"""Supabase (Postgres via PostgREST) backend for the AgentLink relay.

PRODUCTION backend. The relay talks to ONE store interface; this class
implements exactly the same semantics as the SQLite dev/test Store
(``agentlink/store.py``) against the tables in
``deploy/supabase-schema.sql``. Because every relay reads/writes the
same Postgres, ANY relay can serve ANY agent — that shared backend is
what makes own-server-first failover lossless: queues, groups and work
follow the agent to whichever relay it is riding.

Operator configuration (relay-side only; agents never see these):
    SUPABASE_URL          https://<project>.supabase.co
    SUPABASE_SERVICE_KEY  service-role key for the relay process

Realtime: Supabase Realtime can mirror table changes to other relays;
AgentLink's own live sync rides the relay's websocket + dashboard SSE
push, so Realtime is an enhancement, not a requirement.

Files are NOT stored in Supabase Storage (owner storage split):
Supabase is database + realtime only; file ciphertext lives in
Cloudflare R2 behind the relay (see blobstore.py).

NOTE: this adapter is interface-complete and unit-checked for
construction/factory wiring, but has NOT been live-verified against a
real Supabase project in this build (no AgentLink Supabase project or
service key was provided). The SQLite backend is the verified path;
verify this one against your project before production use.
"""

from __future__ import annotations

import hashlib
import json
import urllib.parse
import urllib.request

from .protocol import new_id, new_secret, now_ts
from .store import DEFAULT_SETTINGS, MAX_GROUP_MEMBERS, GroupFull, NotFound, UsernameTaken


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class SupabaseStore:
    def __init__(self, url: str, service_key: str):
        if not url or not service_key:
            raise ValueError(
                "SupabaseStore needs SUPABASE_URL and SUPABASE_SERVICE_KEY")
        self.base = url.rstrip("/") + "/rest/v1"
        self._key = service_key

    # -- transport -----------------------------------------------------------
    def _req(self, method: str, table: str, query: str = "",
             body=None, prefer: str = ""):
        import os as _os
        prefix = _os.environ.get("AGENTLINK_SUPABASE_TABLE_PREFIX", "")
        if prefix and not table.startswith(prefix):
            table = prefix + table
        url = f"{self.base}/{table}"
        if query:
            url += "?" + query
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("apikey", self._key)
        req.add_header("Authorization", f"Bearer {self._key}")
        if data:
            req.add_header("Content-Type", "application/json")
        if prefer:
            req.add_header("Prefer", prefer)
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
        return json.loads(raw) if raw else None

    def _get(self, table: str, query: str) -> list[dict]:
        return self._req("GET", table, query) or []

    def _one(self, table: str, query: str) -> dict | None:
        rows = self._get(table, query + ("&" if query else "") + "limit=1")
        return rows[0] if rows else None

    @staticmethod
    def _eq(col: str, val) -> str:
        return f"{col}=eq.{urllib.parse.quote(str(val), safe='')}"

    def close(self) -> None:
        pass

    # -- users -----------------------------------------------------------------
    def claim(self, username, display_name, pubkey="", sign_pub="",
              capabilities=None, cap_desc=""):
        secret = new_secret()
        try:
            self._req("POST", "users", body={
                "username": username, "secret": _sha(secret),
                "display_name": display_name, "pubkey": pubkey,
                "sign_pub": sign_pub,
                "capabilities": json.dumps(capabilities or []),
                "cap_desc": cap_desc,
                "created_at": now_ts()}, prefer="return=minimal")
        except Exception as exc:
            if "409" in str(exc) or "duplicate" in str(exc):
                raise UsernameTaken(username)
            raise
        return secret

    def verify(self, username, secret):
        if not secret:
            return False
        row = self._one("users", self._eq("username", username) + "&select=secret")
        return bool(row) and row["secret"] == _sha(secret)

    def exists(self, username):
        return self._one("users", self._eq("username", username)
                         + "&select=username") is not None

    def set_display_name(self, username, display_name):
        self._req("PATCH", "users", self._eq("username", username),
                  body={"display_name": display_name}, prefer="return=minimal")

    def pubkey_of(self, username):
        row = self._one("users", self._eq("username", username) + "&select=pubkey")
        return row["pubkey"] if row else ""

    def set_pubkey(self, username, pubkey):
        if pubkey:
            self._req("PATCH", "users", self._eq("username", username),
                      body={"pubkey": pubkey}, prefer="return=minimal")

    def sign_pub_of(self, username):
        row = self._one("users", self._eq("username", username)
                        + "&select=sign_pub")
        return row["sign_pub"] if row else ""

    def set_sign_pub(self, username, sign_pub):
        if sign_pub:
            self._req("PATCH", "users", self._eq("username", username),
                      body={"sign_pub": sign_pub}, prefer="return=minimal")

    def touch(self, username):
        self._req("PATCH", "users", self._eq("username", username),
                  body={"last_seen": now_ts()}, prefer="return=minimal")

    def last_seen_of(self, username):
        row = self._one("users", self._eq("username", username)
                        + "&select=last_seen")
        return int(row["last_seen"]) if row else 0

    def set_capabilities(self, username, capabilities, cap_desc=""):
        self._req("PATCH", "users", self._eq("username", username),
                  body={"capabilities": json.dumps(capabilities or []),
                        "cap_desc": cap_desc}, prefer="return=minimal")

    def list_users(self, query="", capability=""):
        q = ("select=username,display_name,pubkey,sign_pub,capabilities,"
             "cap_desc,last_seen,created_at&order=username")
        if query:
            q += f"&username=like.%25{urllib.parse.quote(query)}%25"
        rows = self._get("users", q)
        out = []
        for r in rows:
            try:
                r["capabilities"] = json.loads(r.get("capabilities")
                                               or "[]")
            except Exception:
                r["capabilities"] = []
            if capability and capability.lower() not in \
                    [c.lower() for c in r["capabilities"]]:
                continue
            out.append(r)
        return out

    # -- queue ---------------------------------------------------------------------
    def enqueue(self, to_username, payload):
        from .store import PRIORITY_WEIGHT
        weight = PRIORITY_WEIGHT.get(str(payload.get("priority")
                                         or "normal"), 0)
        self._req("POST", "queue", body={
            "to_username": to_username, "payload": json.dumps(payload),
            "priority": weight, "ts": now_ts()}, prefer="return=minimal")

    def oldest_urgent_queued(self):
        rows = self._get("queue", "priority=gte.2"
                                  "&select=to_username,ts&order=ts.asc")
        seen = {}
        for r in rows:
            seen.setdefault(r["to_username"], r["ts"])
        return [{"to_username": k, "since": v} for k, v in seen.items()]

    def dequeue_all(self, to_username):
        rows = self._get("queue", self._eq("to_username", to_username)
                         + "&select=payload"
                         + "&order=priority.desc,seq.asc")
        self._req("DELETE", "queue", self._eq("to_username", to_username),
                  prefer="return=minimal")
        out = []
        for r in rows:
            frame = json.loads(r["payload"])
            frame["queued"] = True
            out.append(frame)
        return out

    # -- groups ----------------------------------------------------------------------
    def create_group(self, name, creator, settings=None):
        gid = new_id("g-")[:14]
        merged = dict(DEFAULT_SETTINGS)
        if settings:
            for k in DEFAULT_SETTINGS:
                if k in settings:
                    merged[k] = settings[k]
        self._req("POST", "groups", body={
            "id": gid, "name": name, "creator": creator,
            "settings": json.dumps(merged), "created_at": now_ts()},
            prefer="return=minimal")
        self.add_member(gid, creator, role="superadmin", added_by=creator)
        return gid

    def get_group(self, group_id):
        row = self._one("groups", self._eq("id", group_id))
        if row is None:
            return None
        row["settings"] = json.loads(row["settings"])
        return row

    def set_settings(self, group_id, settings):
        g = self.get_group(group_id)
        if g is None:
            raise NotFound(group_id)
        merged = dict(g["settings"])
        for k in DEFAULT_SETTINGS:
            if k in settings:
                merged[k] = settings[k]
        self._req("PATCH", "groups", self._eq("id", group_id),
                  body={"settings": json.dumps(merged)},
                  prefer="return=minimal")
        return merged

    def add_member(self, group_id, username, role="member", added_by=""):
        if self.role_of(group_id, username) is not None:
            return False
        if len(self.members(group_id)) >= MAX_GROUP_MEMBERS:
            raise GroupFull(group_id)
        self._req("POST", "group_members", body={
            "group_id": group_id, "username": username, "role": role,
            "added_by": added_by, "joined_at": now_ts()},
            prefer="return=minimal,resolution=ignore-duplicates")
        return True

    def remove_member(self, group_id, username):
        existed = self.role_of(group_id, username) is not None
        self._req("DELETE", "group_members",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username), prefer="return=minimal")
        self._req("DELETE", "group_keys",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username), prefer="return=minimal")
        return existed

    def set_role(self, group_id, username, role):
        self._req("PATCH", "group_members",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username),
                  body={"role": role}, prefer="return=minimal")

    def role_of(self, group_id, username):
        row = self._one("group_members",
                        self._eq("group_id", group_id) + "&"
                        + self._eq("username", username) + "&select=role")
        return row["role"] if row else None

    def members(self, group_id):
        return self._get(
            "group_members",
            self._eq("group_id", group_id)
            + "&select=username,role,nickname,custom_role,added_by,joined_at"
            + "&order=joined_at.asc")

    def set_nickname(self, group_id, username, nickname):
        self._req("PATCH", "group_members",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username),
                  body={"nickname": nickname[:48]}, prefer="return=minimal")

    def set_custom_role(self, group_id, username, custom_role):
        self._req("PATCH", "group_members",
                  self._eq("group_id", group_id) + "&"
                  + self._eq("username", username),
                  body={"custom_role": custom_role[:48]},
                  prefer="return=minimal")

    def all_groups(self):
        rows = self._get("groups", "select=id,name,creator,created_at"
                                   "&order=created_at.asc")
        for r in rows:
            r["member_count"] = len(self.members(r["id"]))
        return rows

    # -- group keys ---------------------------------------------------------------------
    def set_group_key(self, group_id, username, epoch, wrapped):
        self._req("POST", "group_keys", body={
            "group_id": group_id, "username": username, "epoch": epoch,
            "wrapped": json.dumps(wrapped)},
            prefer="return=minimal,resolution=merge-duplicates")

    def group_key_for(self, group_id, username):
        row = self._one("group_keys",
                        self._eq("group_id", group_id) + "&"
                        + self._eq("username", username))
        if row is None:
            return None
        return {"epoch": row["epoch"], "wrapped": json.loads(row["wrapped"])}

    def group_key_epoch(self, group_id):
        rows = self._get("group_keys",
                         self._eq("group_id", group_id)
                         + "&select=epoch&order=epoch.desc&limit=1")
        return int(rows[0]["epoch"]) if rows else 0

    # -- invites ---------------------------------------------------------------------------
    def create_invite(self, group_id, created_by, ttl_seconds=7 * 24 * 3600):
        import secrets as _s
        token = _s.token_urlsafe(24)
        self._req("POST", "invites", body={
            "token_hash": _sha(token), "group_id": group_id,
            "created_by": created_by,
            "expires_at": now_ts() + ttl_seconds}, prefer="return=minimal")
        return token

    def invite_valid(self, group_id, token):
        if not token:
            return False
        row = self._one("invites",
                        self._eq("token_hash", _sha(token)) + "&"
                        + self._eq("group_id", group_id)
                        + "&select=expires_at")
        return bool(row) and row["expires_at"] >= now_ts()

    @staticmethod
    def invite_link(group_id, token):
        from .store import Store
        return Store.invite_link(group_id, token)

    @staticmethod
    def parse_invite_link(link):
        from .store import Store
        return Store.parse_invite_link(link)

    # -- work ----------------------------------------------------------------------------------
    def create_work(self, assigner, assignee, group_id, content_enc,
                    content_self, deadline, batch_id=None,
                    priority="normal", auto_reassign=True,
                    assignee_role="", content_group=None,
                    chain_id="", chain_step=0):
        wid = new_id("w-")[:14]
        ts = now_ts()
        self._req("POST", "work", body={
            "id": wid, "assigner": assigner, "assignee": assignee,
            "group_id": group_id, "content_enc": json.dumps(content_enc),
            "content_self": json.dumps(content_self),
            "content_group": json.dumps(content_group)
            if content_group else "",
            "batch_id": batch_id, "chain_id": chain_id,
            "chain_step": chain_step,
            "priority": priority,
            "auto_reassign": 1 if auto_reassign else 0,
            "assignee_role": assignee_role, "deadline": deadline,
            "status": "assigned", "created_at": ts, "updated_at": ts},
            prefer="return=minimal")
        return self.get_work(wid)

    def get_work(self, work_id):
        row = self._one("work", self._eq("id", work_id))
        if row is None:
            return None
        row["content_enc"] = json.loads(row["content_enc"] or "{}")
        row["content_self"] = json.loads(row["content_self"] or "{}")
        try:
            row["content_group"] = json.loads(row["content_group"]
                                              or "null")
        except Exception:
            row["content_group"] = None
        drows = self._get("work_deliveries",
                          self._eq("work_id", work_id) + "&order=ts.asc")
        row["deliveries"] = [
            {**d, "content_enc": json.loads(d["content_enc"] or "{}"),
             "content_self": json.loads(d["content_self"] or "{}"),
             "content_group": json.loads(d["content_group"] or "null")
             if "content_group" in d else None}
            for d in drows]
        cp = self.get_checkpoint(work_id)
        if cp is not None:
            row["checkpoint"] = cp
        return row

    def set_checkpoint(self, work_id, attempt, by_user, content_assigner,
                       content_group):
        self._req("POST", "work_checkpoints", body={
            "work_id": work_id, "attempt": attempt, "by_user": by_user,
            "content_assigner": json.dumps(content_assigner)
            if content_assigner else "",
            "content_group": json.dumps(content_group)
            if content_group else "", "ts": now_ts()},
            prefer="return=minimal,resolution=merge-duplicates")

    def get_checkpoint(self, work_id):
        row = self._one("work_checkpoints", self._eq("work_id", work_id))
        if row is None:
            return None
        for k in ("content_assigner", "content_group"):
            try:
                row[k] = json.loads(row[k]) if row.get(k) else None
            except Exception:
                row[k] = None
        return row

    WORK_TRANSITIONS = None  # bound from store.Store below

    def set_work_status(self, work_id, status):
        from .store import InvalidTransition, Store
        current = self.get_work(work_id)
        if current is None:
            raise NotFound(work_id)
        allowed = Store.WORK_TRANSITIONS.get(current["status"], set())
        if status != current["status"] and status not in allowed:
            raise InvalidTransition(
                f"{current['status']} -> {status} is not legal")
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"status": status, "updated_at": now_ts()},
                  prefer="return=minimal")
        return self.get_work(work_id)

    def set_work_progress(self, work_id, percent):
        row = self._one("work", self._eq("id", work_id) + "&select=status")
        if row is None:
            raise NotFound(work_id)
        status = "in_progress" if row["status"] == "assigned" \
            else row["status"]
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"progress_percent": percent,
                        "progress_at": now_ts(), "status": status,
                        "updated_at": now_ts()}, prefer="return=minimal")
        return self.get_work(work_id)

    def escalate_work_priority(self, work_id):
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"priority": "urgent", "updated_at": now_ts()},
                  prefer="return=minimal")
        return self.get_work(work_id)

    def cover_batch(self, batch_id, delivered_work_id):
        if not batch_id:
            return []
        rows = self._get("work", self._eq("batch_id", batch_id)
                         + "&select=id,status")
        out = []
        for r in rows:
            if r["id"] != delivered_work_id and r["status"] in (
                    "assigned", "in_progress", "changes_requested"):
                self._req("PATCH", "work", self._eq("id", r["id"]),
                          body={"status": "covered",
                                "updated_at": now_ts()},
                          prefer="return=minimal")
                out.append(self.get_work(r["id"]))
        return out

    def resolve_role(self, group_id, role_name):
        rows = self._get("group_members",
                         self._eq("group_id", group_id)
                         + "&select=username,custom_role&order=joined_at.asc")
        return [r["username"] for r in rows
                if (r.get("custom_role") or "").lower()
                == role_name.lower()]

    def compute_trust(self, username):
        from .store import Store
        rows = self._get("work", self._eq("assignee", username)
                         + "&select=status,deadline,updated_at")
        changes = self._get(
            "audit_log", "kind=eq.work_changes_requested&"
            + self._eq("target", username) + "&select=seq")
        bad = self._get(
            "audit_log", "kind=eq.delivery_proof_verified&status=eq.false&"
            + self._eq("actor", username) + "&select=seq")
        score = 50
        now = now_ts()
        for r in rows:
            if r["status"] in ("completed", "covered"):
                score += 4
            elif r["status"] == "delivered":
                score += 1
            if r.get("deadline"):
                if r["status"] == "completed" and \
                        r["updated_at"] > r["deadline"]:
                    score -= 6
                elif r["status"] not in ("completed", "covered",
                                         "delivered") \
                        and now > r["deadline"]:
                    score -= 6
        score -= 6 * len(changes) + 10 * len(bad)
        return max(0, min(100, score))

    def add_delivery(self, work_id, deliverer, content_enc, content_self,
                     proof=None, content_group=None, content_next=None):
        did = new_id("d-")[:14]
        self._req("POST", "work_deliveries", body={
            "id": did, "work_id": work_id, "deliverer": deliverer,
            "content_enc": json.dumps(content_enc),
            "content_self": json.dumps(content_self),
            "content_group": json.dumps(content_group)
            if content_group else "",
            "content_next": json.dumps(content_next)
            if content_next else "", "ts": now_ts()},
            prefer="return=minimal")
        if proof:
            self._req("PATCH", "work", self._eq("id", work_id),
                      body={"proof_hash": proof.get("hash", ""),
                            "proof_ts": int(proof.get("ts") or 0),
                            "proof_sig": proof.get("sig", ""),
                            "proof_verified": 1 if proof.get("verified")
                            else 0}, prefer="return=minimal")
        return self.set_work_status(work_id, "delivered")

    def reassign_work(self, work_id, new_assignee):
        row = self._one("work", self._eq("id", work_id)
                        + "&select=attempt")
        attempt = int(row["attempt"] or 1) + 1 if row else 2
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"assignee": new_assignee, "attempt": attempt,
                        "status": "assigned", "progress_percent": 0,
                        "updated_at": now_ts()}, prefer="return=minimal")
        return self.get_work(work_id)

    def set_awaiting_agent(self, work_id):
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"status": "awaiting_agent",
                        "updated_at": now_ts()}, prefer="return=minimal")
        return self.get_work(work_id)

    def open_work(self, statuses=("assigned", "in_progress")):
        q = "status=in.(" + ",".join(statuses) + ")&select=id"
        rows = self._get("work", q)
        return [self.get_work(r["id"]) for r in rows]

    def list_work(self, username, status=None, group_id=None):
        q = (f"or=(assignee.eq.{username},assigner.eq.{username})"
             "&select=id&order=created_at.asc")
        if status:
            q += f"&status=eq.{status}"
        if group_id:
            q += f"&group_id=eq.{group_id}"
        rows = self._get("work", q)
        return [self.get_work(r["id"]) for r in rows]

    def list_work_meta(self):
        return self._get(
            "work", "select=id,assigner,assignee,group_id,status,priority,"
                    "batch_id,progress_percent,progress_at,proof_verified,"
                    "proof_hash,deadline,chain_id,chain_step,attempt,"
                    "created_at,updated_at"
                    "&order=updated_at.desc&limit=200")

    # -- blob metadata -----------------------------------------------------
    def put_blob_meta(self, blob_id, owner, for_user="", for_group="",
                      size=0, for_channel="", whole_sha=""):
        self._req("POST", "blobs", body={
            "id": blob_id, "owner": owner, "for_user": for_user,
            "for_group": for_group, "for_channel": for_channel,
            "whole_sha": whole_sha, "size": size,
            "created_at": now_ts()},
            prefer="return=minimal,resolution=merge-duplicates")

    def find_blob_by_whole_sha(self, whole_sha, owner="", for_user="",
                               for_group="", for_channel=""):
        return self._one(
            "blobs", self._eq("whole_sha", whole_sha) + "&"
            + self._eq("owner", owner) + "&" + self._eq("for_user", for_user)
            + "&" + self._eq("for_group", for_group) + "&"
            + self._eq("for_channel", for_channel))

    def get_blob_meta(self, blob_id):
        return self._one("blobs", self._eq("id", blob_id))

    def delete_blob_meta(self, blob_id):
        self._req("DELETE", "blobs", self._eq("id", blob_id),
                  prefer="return=minimal")

    def list_blob_meta(self):
        return self._get("blobs", "select=*&order=id.asc")

    # -- channels / uploads / alerts / library / vault / chains (parity) --
    def create_channel(self, name, creator):
        cid = new_id("c-")[:14]
        self._req("POST", "channels", body={
            "id": cid, "name": name, "creator": creator,
            "created_at": now_ts()}, prefer="return=minimal")
        self.add_subscriber(cid, creator, role="superadmin",
                            added_by=creator)
        return cid

    def get_channel(self, channel_id):
        row = self._one("channels", self._eq("id", channel_id))
        if row is None:
            return None
        row["member_count"] = len(self.subscribers(channel_id))
        return row

    def all_channels(self):
        rows = self._get("channels",
                         "select=id,name,creator,created_at"
                         "&order=created_at.asc")
        for r in rows:
            r["member_count"] = len(self.subscribers(r["id"]))
        return rows

    def add_subscriber(self, channel_id, username, role="member",
                       added_by=""):
        if self.subscriber_role(channel_id, username) is not None:
            return False
        from .store import MAX_CHANNEL_SUBSCRIBERS
        if len(self.subscribers(channel_id)) >= MAX_CHANNEL_SUBSCRIBERS:
            raise GroupFull(channel_id)
        self._req("POST", "channel_members", body={
            "channel_id": channel_id, "username": username, "role": role,
            "added_by": added_by, "joined_at": now_ts()},
            prefer="return=minimal,resolution=ignore-duplicates")
        return True

    def remove_subscriber(self, channel_id, username):
        existed = self.subscriber_role(channel_id, username) is not None
        self._req("DELETE", "channel_members",
                  self._eq("channel_id", channel_id) + "&"
                  + self._eq("username", username),
                  prefer="return=minimal")
        self._req("DELETE", "channel_keys",
                  self._eq("channel_id", channel_id) + "&"
                  + self._eq("username", username),
                  prefer="return=minimal")
        return existed

    def subscriber_role(self, channel_id, username):
        row = self._one("channel_members",
                        self._eq("channel_id", channel_id) + "&"
                        + self._eq("username", username) + "&select=role")
        return row["role"] if row else None

    def set_subscriber_role(self, channel_id, username, role):
        self._req("PATCH", "channel_members",
                  self._eq("channel_id", channel_id) + "&"
                  + self._eq("username", username),
                  body={"role": role}, prefer="return=minimal")

    def subscribers(self, channel_id):
        return self._get("channel_members",
                         self._eq("channel_id", channel_id)
                         + "&select=username,role,added_by,joined_at"
                         + "&order=joined_at.asc")

    def set_channel_key(self, channel_id, username, epoch, wrapped):
        self._req("POST", "channel_keys", body={
            "channel_id": channel_id, "username": username,
            "epoch": epoch, "wrapped": json.dumps(wrapped)},
            prefer="return=minimal,resolution=merge-duplicates")

    def channel_key_for(self, channel_id, username):
        row = self._one("channel_keys",
                        self._eq("channel_id", channel_id) + "&"
                        + self._eq("username", username))
        if row is None:
            return None
        return {"epoch": row["epoch"],
                "wrapped": json.loads(row["wrapped"])}

    def channel_key_epoch(self, channel_id):
        rows = self._get("channel_keys",
                         self._eq("channel_id", channel_id)
                         + "&select=epoch&order=epoch.desc&limit=1")
        return int(rows[0]["epoch"]) if rows else 0

    def create_channel_invite(self, channel_id, created_by,
                              ttl_seconds=7 * 24 * 3600):
        import secrets as _s
        token = _s.token_urlsafe(24)
        self._req("POST", "invites", body={
            "token_hash": _sha(token), "group_id": "ch:" + channel_id,
            "created_by": created_by,
            "expires_at": now_ts() + ttl_seconds}, prefer="return=minimal")
        return token

    def channel_invite_valid(self, channel_id, token):
        if not token:
            return False
        row = self._one("invites",
                        self._eq("token_hash", _sha(token)) + "&"
                        + self._eq("group_id", "ch:" + channel_id)
                        + "&select=expires_at")
        return bool(row) and row["expires_at"] >= now_ts()

    def create_upload_session(self, session_id, owner, blob_id, whole_sha,
                              chunk_size, total_chunks, for_user="",
                              for_group="", for_channel=""):
        self._req("POST", "upload_sessions", body={
            "id": session_id, "owner": owner, "blob_id": blob_id,
            "whole_sha": whole_sha, "chunk_size": chunk_size,
            "total_chunks": total_chunks, "for_user": for_user,
            "for_group": for_group, "for_channel": for_channel,
            "got": "[]", "created_at": now_ts()}, prefer="return=minimal")

    def get_upload_session(self, session_id):
        row = self._one("upload_sessions", self._eq("id", session_id))
        if row is None:
            return None
        row["got"] = json.loads(row.get("got") or "[]")
        return row

    def record_chunk(self, session_id, index):
        row = self.get_upload_session(session_id)
        got = sorted(set(row["got"]) | {int(index)})
        self._req("PATCH", "upload_sessions", self._eq("id", session_id),
                  body={"got": json.dumps(got)}, prefer="return=minimal")
        return got

    def delete_upload_session(self, session_id):
        self._req("DELETE", "upload_sessions", self._eq("id", session_id),
                  prefer="return=minimal")

    def open_alert(self, kind, subject):
        row = self._one("alerts", self._eq("kind", kind) + "&"
                        + self._eq("subject", subject) + "&resolved=eq.0")
        if row is not None:
            return False, row
        aid = new_id("al-")[:14]
        self._req("POST", "alerts", body={
            "id": aid, "kind": kind, "subject": subject,
            "created_at": now_ts(), "last_reminder": now_ts(),
            "resolved": 0}, prefer="return=minimal")
        rec = self._one("alerts", self._eq("id", aid))
        return True, rec

    def resolve_alert(self, kind, subject):
        row = self._one("alerts", self._eq("kind", kind) + "&"
                        + self._eq("subject", subject) + "&resolved=eq.0")
        if row is None:
            return None
        self._req("PATCH", "alerts", self._eq("id", row["id"]),
                  body={"resolved": 1, "resolved_at": now_ts()},
                  prefer="return=minimal")
        row["resolved"] = 1
        return row

    def bump_reminder(self, alert_id):
        self._req("PATCH", "alerts", self._eq("id", alert_id),
                  body={"last_reminder": now_ts()}, prefer="return=minimal")

    def list_alerts(self, limit=100):
        return self._get("alerts", f"select=*&order=created_at.desc"
                                   f"&limit={limit}")

    def library_add(self, lib_id, filename, size, sha256, sender,
                    dest_kind, dest_id, work_id=""):
        self._req("POST", "library", body={
            "id": lib_id, "filename": filename[:200],
            "size": int(size or 0), "sha256": sha256, "sender": sender,
            "dest_kind": dest_kind, "dest_id": dest_id, "work_id": work_id,
            "created_at": now_ts()},
            prefer="return=minimal,resolution=ignore-duplicates")

    def library_search(self, user, q="", sender="", group_id="",
                       sha_prefix="", limit=200):
        rows = self._get("library", "select=*&order=created_at.desc"
                                    f"&limit={limit}")
        out = []
        for r in rows:
            if r["dest_kind"] == "dm":
                if user not in (r["sender"], r["dest_id"]):
                    continue
            elif self.role_of(r["dest_id"], user) is None \
                    and r["sender"] != user:
                continue
            if q and q.lower() not in r["filename"].lower():
                continue
            if sender and r["sender"] != sender:
                continue
            if group_id and r["dest_id"] != group_id:
                continue
            if sha_prefix and not r["sha256"].startswith(sha_prefix):
                continue
            out.append(r)
        return out

    def library_entry(self, lib_id):
        return self._one("library", self._eq("id", lib_id))

    def library_all_meta(self, limit=300):
        return self._get("library", "select=*&order=created_at.desc"
                                    f"&limit={limit}")

    def library_for_work(self, work_id):
        return self._get("library", self._eq("work_id", work_id))

    def vault_add(self, vault_id, group_id, filename, size, sha256,
                  added_by, blob_id, pinned=False):
        self._req("POST", "vault", body={
            "id": vault_id, "group_id": group_id,
            "filename": filename[:200], "size": int(size or 0),
            "sha256": sha256, "added_by": added_by, "blob_id": blob_id,
            "pinned": 1 if pinned else 0, "created_at": now_ts()},
            prefer="return=minimal,resolution=ignore-duplicates")
        return vault_id

    def vault_list(self, group_id):
        return self._get("vault", self._eq("group_id", group_id)
                         + "&order=pinned.desc,created_at.desc")

    def vault_entry(self, vault_id):
        return self._one("vault", self._eq("id", vault_id))

    def vault_set_pinned(self, vault_id, pinned):
        self._req("PATCH", "vault", self._eq("id", vault_id),
                  body={"pinned": 1 if pinned else 0},
                  prefer="return=minimal")

    def vault_remove(self, vault_id):
        self._req("DELETE", "vault", self._eq("id", vault_id),
                  prefer="return=minimal")

    def create_chain(self, chain_id, creator, group_id, steps):
        ts = now_ts()
        self._req("POST", "chains", body={
            "id": chain_id, "creator": creator, "group_id": group_id,
            "status": "running", "current_step": 0,
            "created_at": ts, "updated_at": ts}, prefer="return=minimal")
        for i, st in enumerate(steps):
            self._req("POST", "chain_steps", body={
                "chain_id": chain_id, "step_index": i,
                "work_id": st.get("work_id"),
                "target_kind": st.get("target_kind", "user"),
                "target": st.get("target", ""),
                "status": "pending"}, prefer="return=minimal")
        return self.get_chain(chain_id)

    def get_chain(self, chain_id):
        row = self._one("chains", self._eq("id", chain_id))
        if row is None:
            return None
        row["steps"] = self._get(
            "chain_steps", self._eq("chain_id", chain_id)
            + "&order=step_index.asc")
        return row

    def set_chain_status(self, chain_id, status):
        self._req("PATCH", "chains", self._eq("id", chain_id),
                  body={"status": status, "updated_at": now_ts()},
                  prefer="return=minimal")
        return self.get_chain(chain_id)

    def set_step_status(self, chain_id, step_index, status):
        self._req("PATCH", "chain_steps",
                  self._eq("chain_id", chain_id) + "&"
                  + f"step_index=eq.{step_index}",
                  body={"status": status,
                        "released_at": now_ts()
                        if status == "active" else None},
                  prefer="return=minimal")
        cur = self.get_chain(chain_id)
        if status == "active" and cur:
            self._req("PATCH", "chains", self._eq("id", chain_id),
                      body={"current_step": step_index,
                            "updated_at": now_ts()},
                      prefer="return=minimal")
        return self.get_chain(chain_id)

    def set_step_handoff(self, chain_id, step_index, refs):
        self._req("PATCH", "chain_steps",
                  self._eq("chain_id", chain_id) + "&"
                  + f"step_index=eq.{step_index}",
                  body={"handoff": json.dumps(refs)},
                  prefer="return=minimal")

    def step_by_work(self, work_id):
        return self._one("chain_steps", self._eq("work_id", work_id))

    def list_chains_meta(self, limit=100):
        rows = self._get("chains", "select=*&order=updated_at.desc"
                                   f"&limit={limit}")
        return [self.get_chain(r["id"]) for r in rows]

    def chains_for_user(self, username):
        return [c for c in self.list_chains_meta()
                if c["creator"] == username
                or any((s.get("work_id") and
                        (self.get_work(s["work_id"]) or {})
                        .get("assignee") == username)
                       for s in c["steps"])]

    def groups_for_user(self, username):
        rows = self._get("group_members",
                         self._eq("username", username)
                         + "&select=group_id")
        out = []
        for r in rows:
            g = self.get_group(r["group_id"])
            if g is None:
                continue
            g["members"] = self.members(g["id"])
            mine = next((m for m in g["members"]
                         if m["username"] == username), None)
            out.append({"group_id": g["id"], "name": g["name"],
                        "settings": g["settings"], "my": mine,
                        "members": g["members"]})
        return out

    def channels_for_user(self, username):
        rows = self._get("channel_members",
                         self._eq("username", username)
                         + "&select=channel_id,role")
        out = []
        for r in rows:
            c = self.get_channel(r["channel_id"])
            if c:
                out.append({"channel_id": c["id"], "name": c["name"],
                            "my_role": r["role"]})
        return out

    # -- name parity aliases (relay calls the Store API names) ---------
    resolve_alerts = resolve_alert

    def channel_members(self, channel_id):
        return self.subscribers(channel_id)

    def channel_role_of(self, channel_id, username):
        return self.subscriber_role(channel_id, username)

    def set_channel_role(self, channel_id, username, role):
        return self.set_subscriber_role(channel_id, username, role)

    def add_library_entries(self, delivery_id, work, files):
        ids = []
        for f in files:
            lid = new_id("lib-")[:16]
            self.library_add(lid, f.get("name", ""), f.get("size", 0),
                             f.get("sha256", ""), work["assignee"],
                             "group" if work.get("group_id") else "dm",
                             work.get("group_id") or work["assigner"],
                             work["id"])
            ids.append(lid)
        return ids

    def search_library(self, requester, q="", sender="", group_id="",
                       sha_prefix="", limit=200):
        return self.library_search(requester, q=q, sender=sender,
                                   group_id=group_id,
                                   sha_prefix=sha_prefix, limit=limit)

    def library_all(self, limit=200):
        return self.library_all_meta(limit)

    def vault_meta(self):
        rows = self._get("vault", "select=*&order=created_at.desc"
                                  "&limit=300")
        return rows

    # -- dashboard sessions -----------------------------------------------------------------------
    def create_session(self, token_hash, expires_at):
        self._req("POST", "dashboard_sessions", body={
            "token_hash": token_hash, "created_at": now_ts(),
            "expires_at": expires_at}, prefer="return=minimal")

    def session_valid(self, token_hash):
        row = self._one("dashboard_sessions",
                        self._eq("token_hash", token_hash)
                        + "&select=expires_at")
        return bool(row) and row["expires_at"] >= now_ts()

    def revoke_session(self, token_hash):
        self._req("DELETE", "dashboard_sessions",
                  self._eq("token_hash", token_hash), prefer="return=minimal")

    # -- audit ---------------------------------------------------------------------------------------
    def audit(self, kind, actor, target="", group_id="", work_id="",
              status="", priority="", size=0, mentions=None, ref_id=""):
        self._req("POST", "audit_log", body={
            "ts": now_ts(), "kind": kind, "actor": actor, "target": target,
            "group_id": group_id, "work_id": work_id, "status": status,
            "priority": priority, "size": int(size or 0),
            "mentions": json.dumps(mentions or []), "ref_id": ref_id},
            prefer="return=minimal")

    def list_audit(self, limit=300):
        rows = self._get(
            "audit_log",
            "select=ts,kind,actor,target,group_id,work_id,status,priority,"
            f"size,mentions,ref_id&order=seq.desc&limit={limit}")
        out = []
        for r in rows:
            try:
                mentions = json.loads(r.get("mentions") or "[]")
            except Exception:
                mentions = []
            out.append({"ts": r["ts"], "kind": r["kind"],
                        "from": r["actor"], "to": r["target"],
                        "group_id": r["group_id"], "work_id": r["work_id"],
                        "status": r["status"],
                        "priority": r.get("priority", ""),
                        "size": r.get("size", 0), "mentions": mentions,
                        "ref_id": r.get("ref_id", "")})
        return out
