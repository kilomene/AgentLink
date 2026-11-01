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
    def claim(self, username, display_name, pubkey=""):
        secret = new_secret()
        try:
            self._req("POST", "users", body={
                "username": username, "secret": _sha(secret),
                "display_name": display_name, "pubkey": pubkey,
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

    def list_users(self, query=""):
        q = "select=username,display_name,pubkey,created_at&order=username"
        if query:
            q += f"&username=like.%25{urllib.parse.quote(query)}%25"
        return self._get("users", q)

    # -- queue ---------------------------------------------------------------------
    def enqueue(self, to_username, payload):
        self._req("POST", "queue", body={
            "to_username": to_username, "payload": json.dumps(payload),
            "ts": now_ts()}, prefer="return=minimal")

    def dequeue_all(self, to_username):
        rows = self._get("queue", self._eq("to_username", to_username)
                         + "&select=payload&order=seq.asc")
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
                    content_self, deadline):
        wid = new_id("w-")[:14]
        ts = now_ts()
        self._req("POST", "work", body={
            "id": wid, "assigner": assigner, "assignee": assignee,
            "group_id": group_id, "content_enc": json.dumps(content_enc),
            "content_self": json.dumps(content_self), "deadline": deadline,
            "status": "assigned", "created_at": ts, "updated_at": ts},
            prefer="return=minimal")
        return self.get_work(wid)

    def get_work(self, work_id):
        row = self._one("work", self._eq("id", work_id))
        if row is None:
            return None
        row["content_enc"] = json.loads(row["content_enc"] or "{}")
        row["content_self"] = json.loads(row["content_self"] or "{}")
        drows = self._get("work_deliveries",
                          self._eq("work_id", work_id) + "&order=ts.asc")
        row["deliveries"] = [
            {**d, "content_enc": json.loads(d["content_enc"] or "{}"),
             "content_self": json.loads(d["content_self"] or "{}")}
            for d in drows]
        return row

    def set_work_status(self, work_id, status):
        self._req("PATCH", "work", self._eq("id", work_id),
                  body={"status": status, "updated_at": now_ts()},
                  prefer="return=minimal")
        return self.get_work(work_id)

    def add_delivery(self, work_id, deliverer, content_enc, content_self):
        self._req("POST", "work_deliveries", body={
            "id": new_id("d-")[:14], "work_id": work_id,
            "deliverer": deliverer, "content_enc": json.dumps(content_enc),
            "content_self": json.dumps(content_self), "ts": now_ts()},
            prefer="return=minimal")
        return self.set_work_status(work_id, "delivered")

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
            "work", "select=id,assigner,assignee,group_id,status,"
                    "created_at,updated_at&order=updated_at.desc&limit=200")

    # -- blob metadata -----------------------------------------------------
    def put_blob_meta(self, blob_id, owner, for_user="", for_group="",
                      size=0):
        self._req("POST", "blobs", body={
            "id": blob_id, "owner": owner, "for_user": for_user,
            "for_group": for_group, "size": size, "created_at": now_ts()},
            prefer="return=minimal,resolution=merge-duplicates")

    def get_blob_meta(self, blob_id):
        return self._one("blobs", self._eq("id", blob_id))

    def delete_blob_meta(self, blob_id):
        self._req("DELETE", "blobs", self._eq("id", blob_id),
                  prefer="return=minimal")

    def list_blob_meta(self):
        return self._get("blobs", "select=*&order=id.asc")

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
              status=""):
        self._req("POST", "audit_log", body={
            "ts": now_ts(), "kind": kind, "actor": actor, "target": target,
            "group_id": group_id, "work_id": work_id, "status": status},
            prefer="return=minimal")

    def list_audit(self, limit=300):
        rows = self._get("audit_log",
                         "select=ts,kind,actor,target,group_id,work_id,status"
                         f"&order=seq.desc&limit={limit}")
        return [{"ts": r["ts"], "kind": r["kind"], "from": r["actor"],
                 "to": r["target"], "group_id": r["group_id"],
                 "work_id": r["work_id"], "status": r["status"]}
                for r in rows]
