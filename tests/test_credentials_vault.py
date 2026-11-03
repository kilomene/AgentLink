"""Credentials vault pins (v1.4.0, owner's direct order).

Every agent gets its OWN credentials vault: logins an agent saves
when it creates accounts, sealed to the agent's identity key, synced
as sealed blobs so the vault follows the agent when its server is
carried, labels visible to the owner's dashboard under oversight —
passwords never oversight-sealed, never in any payload.

Pinned here:
  1. put/remember -> get round-trip byte-exact (the auto-save path
     included — remember IS put, exercised end to end);
  2. list() exposes LABELS ONLY — no password, no notes, in the
     list output, the vault document, the relay DB bytes, or any
     dashboard payload (byte-searched);
  3. upsert: same service + account updates in place;
  4. foreign-agent refusal BY CONSTRUCTION: agent B cannot adopt
     agent A's document (signature) and cannot decrypt a single
     entry envelope with its own identity;
  5. tamper fails closed: a flipped byte anywhere in the synced
     document refuses the whole adopt — no partial plaintext; a
     corrupted local file quarantines loudly, never silently
     overwrites;
  6. restart persistence (fresh core + fresh Agent, same state
     dir — the state-dir law a self-update cycle also obeys);
  7. relay sync + dashboard: pointer lands in the store, the
     dashboard payload (owner session) shows presence + count +
     oversight-opened labels, and byte-searching the whole payload
     finds no password; without the oversight key, labels stay
     sealed (None) while presence stays factual;
  8. carried vault: identity files alone move to a fresh state
     dir; the new process restores the vault through the blob
     layer on connect and opens every entry;
  9. decision-link context carries the vault summary + a working
     vault_get; the HTTP endpoint payload strips the callable and
     carries no secret;
 10. CLI parity (one-shot + control-channel forwarding to a
     running daemon);
 11. a legacy agent that never touches the vault: dashboard shows
     vault present=False, nothing breaks;
 12. the shipped GROUP vault surface (Agent.vault_put et al.) is
     untouched by the new credentials namespace.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from agentlink.client import Agent, forward_command
from agentlink.crypto import Identity, OversightKey
from agentlink.dashboard import DashboardServer
from agentlink.relay import Relay
from agentlink.vault import CredentialsVault, VaultError

HOST = "127.0.0.1"
REPO = Path(__file__).resolve().parent.parent
PASSWORD = "Pr00f-Passw0rd!☃-xyz"
NOTES = "s3cret-note-do-not-leak"


# -- harnesses (the test_key_hello / test_control_channel shapes) ----------

class RelayHandle:
    def __init__(self, db, name, **kw):
        self.db = db
        self.name = name
        self.kw = kw
        self.relay = None
        self.loop = None
        self.thread = None
        self.port = 0

    def start(self):
        self.relay = Relay(host=HOST, port=0, db_path=self.db,
                           server_name=self.name,
                           dashboard_password="test",
                           dashboard_port=0, **self.kw)
        ready = threading.Event()

        def _thread():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self.loop = loop

            async def _serve():
                await self.relay.start()
                ready.set()
                await asyncio.Future()

            try:
                loop.run_until_complete(_serve())
            except (RuntimeError, asyncio.CancelledError):
                pass

        self.thread = threading.Thread(target=_thread, daemon=True)
        self.thread.start()
        assert ready.wait(timeout=10)
        self.port = self.relay.port
        return f"ws://{HOST}:{self.relay.port}"

    def stop(self):
        if self.relay is not None and self.loop is not None:
            fut = asyncio.run_coroutine_threadsafe(
                self.relay.stop(), self.loop)
            try:
                fut.result(timeout=10)
            except Exception:
                pass
            self.relay = None


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, timeout=90))


@pytest.fixture()
def state_root():
    with tempfile.TemporaryDirectory(
            prefix="agentlink-vault-agents-") as tmp:
        yield Path(tmp)


def _core(state_dir: Path, username: str) -> CredentialsVault:
    state_dir.mkdir(parents=True, exist_ok=True)
    return CredentialsVault(Identity(username, str(state_dir)),
                            state_dir, username)


# -- 1-6: the local core -----------------------------------------------------

def test_put_get_roundtrip_byte_exact(tmp_path):
    v = _core(tmp_path / "a", "valice")
    entry = v.remember("Example Mail", "valice@example.com",
                       PASSWORD, notes=NOTES)
    assert entry["service"] == "Example Mail"
    got = v.get(entry["id"])
    assert got["password"] == PASSWORD
    assert got["username"] == "valice@example.com"
    assert got["notes"] == NOTES
    # get by service name resolves too (case-insensitive service).
    assert v.get("example mail")["id"] == entry["id"]
    # put is the same road under the plain name.
    e2 = v.put("Other", "valice@other.example", "pw2")
    assert v.get("Other")["password"] == "pw2"
    assert len(v) == 2


def test_list_labels_only_and_document_sealed(tmp_path):
    v = _core(tmp_path / "a", "valice")
    v.put("Example Mail", "valice@example.com", PASSWORD, notes=NOTES)
    labels = v.list()
    assert set(labels[0]) == {"id", "service", "username",
                              "created_at", "updated_at"}
    blob = json.dumps(labels)
    assert PASSWORD not in blob and NOTES not in blob
    assert labels[0]["service"] == "Example Mail"
    # The persisted/synced document carries NO plaintext secrets —
    # not the password, not the notes, not even the service/account
    # (those live inside the sealed entry; labels travel separately,
    # sealed to oversight).
    doc = v.document_bytes()
    assert PASSWORD.encode() not in doc
    assert NOTES.encode() not in doc
    assert b"Example Mail" not in doc
    assert b"valice@example.com" not in doc
    # The local file is mode 0600.
    assert (os.stat(v.path).st_mode & 0o777) == 0o600


def test_upsert_same_service_account(tmp_path):
    v = _core(tmp_path / "a", "valice")
    e1 = v.put("Example Mail", "valice@example.com", "old-pw")
    rev1 = v.revision
    e2 = v.remember("example mail", "VALICE@example.com", "new-pw")
    assert e2["id"] == e1["id"]
    assert len(v) == 1
    assert v.revision > rev1
    assert v.get("Example Mail")["password"] == "new-pw"
    assert e2["created_at"] == e1["created_at"]
    assert e2["updated_at"] >= e1["updated_at"]


def test_foreign_agent_refused(tmp_path):
    a = _core(tmp_path / "a", "valice")
    a.put("Example Mail", "valice@example.com", PASSWORD)
    doc = a.document_bytes()
    b_identity = Identity("vmallory", str(tmp_path / "b"))
    b = CredentialsVault(b_identity, tmp_path / "b", "vmallory")
    # B cannot adopt A's document: the signature is A's.
    with pytest.raises(VaultError):
        b.adopt_document(doc)
    # B cannot open a single entry envelope with its own key.
    rec = a.document()["entries"][0]
    with pytest.raises(Exception):
        b_identity.decrypt_envelope(rec["content"])
    # And B's vault stayed empty — refusal, not partial adoption.
    assert len(b) == 0


def test_tamper_fails_closed(tmp_path):
    a = _core(tmp_path / "a", "valice")
    entry = a.put("Example Mail", "valice@example.com", PASSWORD)
    doc = bytearray(a.document_bytes())
    # Flip one byte inside the sealed entry's ciphertext.
    raw = bytes(doc)
    i = raw.index(b'"ct": "') + len(b'"ct": "') + 4
    doc[i] = ord("A") if doc[i] != ord("A") else ord("B")
    fresh = _core(tmp_path / "a2", "valice")
    with pytest.raises(VaultError):
        fresh.adopt_document(bytes(doc))
    assert len(fresh) == 0
    # A corrupted LOCAL file quarantines loudly and starts empty —
    # the entries are never half-read and never silently dropped
    # without a recorded fact.
    vpath = tmp_path / "a" / "credentials-vault-valice.json"
    data = bytearray(vpath.read_bytes())
    data[-40] = ord("x") if data[-40] != ord("x") else ord("y")
    vpath.write_bytes(bytes(data))
    v2 = _core(tmp_path / "a", "valice")
    assert v2.load_error and "quarantined" in v2.load_error
    assert len(v2) == 0
    assert any(p.name.startswith("credentials-vault-valice")
               and "corrupt" in p.name
               for p in (tmp_path / "a").iterdir())
    assert entry  # the original entry id existed before the tamper


def test_persistence_across_restart(tmp_path):
    d = tmp_path / "a"
    v = _core(d, "valice")
    v.put("Example Mail", "valice@example.com", PASSWORD, notes=NOTES)
    again = _core(d, "valice")
    assert again.get("Example Mail")["password"] == PASSWORD
    assert again.list()[0]["username"] == "valice@example.com"


def test_ephemeral_identity_has_no_vault(tmp_path):
    with pytest.raises(VaultError):
        CredentialsVault(Identity.ephemeral(), tmp_path, "ghost")


def test_remove_returns_label_only(tmp_path):
    v = _core(tmp_path / "a", "valice")
    e = v.put("Example Mail", "valice@example.com", PASSWORD)
    label = v.remove(e["id"])
    assert PASSWORD not in json.dumps(label)
    assert label["service"] == "Example Mail"
    assert len(v) == 0
    with pytest.raises(VaultError):
        v.get("Example Mail")
    with pytest.raises(VaultError):
        v.remove(e["id"])


# -- store-level version guard ------------------------------------------------

def test_store_version_guard(tmp_path):
    from agentlink.store import Store
    store = Store(str(tmp_path / "relay.db"))
    store.claim("valice", "Valice")
    assert store.get_vault_meta("valice") is None
    assert store.set_vault_meta("valice", "{}", "b-1", 3, 2)
    assert store.get_vault_meta("valice")["version"] == 3
    # A stale (zombie-host) publish is refused and changes nothing.
    assert not store.set_vault_meta("valice", "{}", "b-old", 2, 9)
    meta = store.get_vault_meta("valice")
    assert meta["blob_id"] == "b-1" and meta["entries"] == 2
    # Equal revision re-points idempotently.
    assert store.set_vault_meta("valice", "{}", "b-2", 3, 2)
    assert store.get_vault_meta("valice")["blob_id"] == "b-2"


def test_supabase_store_vault_meta_parity_and_failsoft():
    """The Supabase store carries the same pointer semantics, and
    an unmigrated/unreachable backend reads as 'no vault yet' —
    never as a raise into the relay's loops (the migration may
    land after the code; see supabase/migration-vault.sql)."""
    from agentlink.supabase_store import SupabaseStore
    store = SupabaseStore("https://example.invalid", "k")
    row = {"vault_labels": "", "vault_blob": "",
           "vault_version": 0, "vault_entries": 0}

    def fake_get(table, query):
        assert table == "users"
        return [dict(row)]

    def fake_req(method, table, query, body=None, prefer=None):
        assert method == "PATCH"
        row.update(body or {})
        return None

    store._get = fake_get
    store._req = fake_req
    assert store.get_vault_meta("valice") is None
    assert store.set_vault_meta("valice", "LBL", "b-1", 3, 2)
    meta = store.get_vault_meta("valice")
    assert meta == {"labels": "LBL", "blob_id": "b-1",
                    "version": 3, "entries": 2}
    assert not store.set_vault_meta("valice", "LBL", "b-old", 2, 9)
    assert store.get_vault_meta("valice")["blob_id"] == "b-1"

    def boom(*a, **k):
        raise RuntimeError("column al_users.vault_blob does not exist")

    store._get = boom
    assert store.get_vault_meta("valice") is None
    assert store.set_vault_meta("valice", "LBL", "b-1", 4, 1) is False


# -- 7-8, 11: relay sync, dashboard, carrying ---------------------------------

def _oversight_env(tmp_path, monkeypatch):
    okey = OversightKey.generate()
    key_path = okey.save(str(tmp_path / "oversight-key.json"))
    monkeypatch.setenv("AGENTLINK_OVERSIGHT_KEY_FILE", str(key_path))
    return okey


def test_sync_dashboard_labels_and_no_password(tmp_path, state_root,
                                               monkeypatch):
    okey = _oversight_env(tmp_path, monkeypatch)
    db = str(tmp_path / "relay.db")
    h = RelayHandle(db, "vault-home",
                    oversight_pubkey=okey.public_key_b64)
    url = h.start()

    async def _t():
        a = Agent("valice", endpoint=url,
                  state_dir=str(state_root / "valice"),
                  oversight_pubkey=okey.public_key_b64)
        await a.start()
        try:
            entry = await a.vault.remember(
                "Example Mail", "valice@example.com", PASSWORD,
                notes=NOTES)
            assert entry["id"]
            # The pointer landed in the store.
            meta = h.relay.store.get_vault_meta("valice")
            assert meta and meta["blob_id"]
            assert meta["entries"] == 1 and meta["version"] >= 1
            # The stored labels are SEALED: no service, account or
            # password plaintext in the store's copy.
            assert "Example Mail" not in meta["labels"]
            assert "valice@example.com" not in meta["labels"]
            assert PASSWORD not in meta["labels"]
            # The synced blob itself is sealed end to end.
            import base64 as _b64
            resp = await a._request(
                {"type": "blob_get", "blob_id": meta["blob_id"]})
            blob = _b64.b64decode(resp["data_b64"])
            assert PASSWORD.encode() not in blob
            assert NOTES.encode() not in blob
            assert b"Example Mail" not in blob
            # The password is nowhere in the relay's DB file either.
            assert PASSWORD.encode() not in Path(db).read_bytes()
            return meta
        finally:
            await a.close()

    run(_t())
    # Dashboard payload (owner session, oversight key loaded):
    # presence + count + opened labels; password byte-absent from
    # the ENTIRE payload.
    dash = DashboardServer(h.relay, "127.0.0.1", 0, "test")
    data = dash._serve_data()
    users = {u["username"]: u for u in data["users"]}
    v = users["valice"]["vault"]
    assert v["present"] is True and v["entries"] == 1
    assert v["labels"] and v["labels"][0]["service"] == "Example Mail"
    assert v["labels"][0]["username"] == "valice@example.com"
    assert "labels_sealed" not in v
    assert PASSWORD not in json.dumps(data)
    assert NOTES not in json.dumps(data)
    h.stop()
    # Without the oversight key the labels stay sealed (None) but
    # presence/count remain factual.
    monkeypatch.delenv("AGENTLINK_OVERSIGHT_KEY_FILE")
    h2 = RelayHandle(db, "vault-nokey")
    h2.start()
    dash2 = DashboardServer(h2.relay, "127.0.0.1", 0, "test")
    data2 = dash2._serve_data()
    v2 = {u["username"]: u for u in data2["users"]}["valice"]["vault"]
    assert v2["present"] is True and v2["entries"] == 1
    assert v2["labels"] is None
    assert PASSWORD not in json.dumps(data2)
    h2.stop()


def test_carried_vault_restores_on_new_state_dir(tmp_path, state_root):
    db = str(tmp_path / "relay.db")
    h = RelayHandle(db, "vault-carry")
    url = h.start()
    home1 = state_root / "vcarol"
    home2 = state_root / "vcarol-moved"

    async def _t1():
        a = Agent("vcarol", endpoint=url, state_dir=str(home1))
        await a.start()
        try:
            await a.vault_remember("Example Mail",
                                   "vcarol@example.com", PASSWORD,
                                   notes=NOTES)
        finally:
            await a.close()

    async def _t2():
        b = Agent("vcarol", endpoint=url, state_dir=str(home2))
        await b.start()
        try:
            # Restored through the blob layer by the post-boot sync
            # task (replication, deliberately not gated into
            # start()'s boot sequence) — poll for its landing.
            async def _restored():
                try:
                    await b.vault.get("Example Mail")
                    return True
                except Exception:
                    return False

            deadline = asyncio.get_event_loop().time() + 15
            while not await _restored():
                assert asyncio.get_event_loop().time() < deadline, \
                    "vault restore never landed"
                await asyncio.sleep(0.1)
            got = await b.vault.get("Example Mail")
            assert got["password"] == PASSWORD
            assert got["notes"] == NOTES
            labels = await b.vault.list()
            assert labels[0]["username"] == "vcarol@example.com"
        finally:
            await b.close()

    run(_t1())
    # The carry: identity files ALONE move (keys + account secret) —
    # no vault file crosses by hand; the blob layer carries it.
    home2.mkdir(parents=True)
    for name in ("keys-vcarol.json", "secret-vcarol.json"):
        (home2 / name).write_bytes((home1 / name).read_bytes())
    assert not (home2 / "credentials-vault-vcarol.json").exists()
    run(_t2())
    assert (home2 / "credentials-vault-vcarol.json").exists()
    h.stop()


def test_legacy_agent_shows_no_vault(tmp_path, state_root):
    db = str(tmp_path / "relay.db")
    h = RelayHandle(db, "vault-legacy")
    url = h.start()

    async def _t():
        a = Agent("vold", endpoint=url, state_dir=str(state_root / "vold"))
        await a.start()
        await a.close()

    run(_t())
    dash = DashboardServer(h.relay, "127.0.0.1", 0, "test")
    data = dash._serve_data()
    v = {u["username"]: u for u in data["users"]}["vold"]["vault"]
    assert v["present"] is False and v["entries"] == 0
    h.stop()


# -- 9: decision-link context ---------------------------------------------------

def test_decision_ctx_vault_and_endpoint_payload(tmp_path, state_root):
    a = Agent("vdec", endpoint="ws://127.0.0.1:1/ws",
              state_dir=str(state_root / "vdec"))

    async def _t():
        await a.vault.put("Example Mail", "vdec@example.com",
                          PASSWORD, notes=NOTES)
        fields = a._vault_ctx_fields()
        assert fields["vault"] == {"available": True, "entries": 1}
        got = fields["vault_get"]("Example Mail")
        assert got["password"] == PASSWORD
        assert fields["vault_get"]("no-such-service") is None
        # The HTTP endpoint payload strips the callable and carries
        # only the JSON-safe summary — no secret crosses.
        captured = {}

        class _H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                captured["body"] = self.rfile.read(n)
                self.send_response(204)
                self.end_headers()

            def log_message(self, *a_):
                pass

        srv = HTTPServer(("127.0.0.1", 0), _H)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            a.decision_endpoint = \
                f"http://127.0.0.1:{srv.server_port}/decide"
            ctx = {"kind": "message", **fields}
            assert await a._call_decision_endpoint(ctx) is None
        finally:
            srv.shutdown()
        body = json.loads(captured["body"])
        assert "vault_get" not in body
        assert body["vault"] == {"available": True, "entries": 1}
        assert PASSWORD not in captured["body"].decode()
        assert NOTES not in captured["body"].decode()

    run(_t())


# -- 10: CLI parity ---------------------------------------------------------------

def test_cli_credentials_roundtrip(tmp_path, state_root):
    db = str(tmp_path / "relay.db")
    h = RelayHandle(db, "vault-cli")
    url = h.start()
    sd = str(state_root / "vcli")

    def cli(*args):
        proc = subprocess.run(
            [sys.executable, "-m", "agentlink.cli", *args],
            capture_output=True, text=True, cwd=str(REPO),
            timeout=60)
        assert proc.returncode == 0, proc.stderr
        return proc.stdout

    out = cli("credentials", "put", "Example Mail",
              "vcli@example.com", PASSWORD, "--notes", NOTES,
              "--username", "vcli", "--state-dir", sd,
              "--endpoint", url)
    entry = json.loads(out)
    assert entry["service"] == "Example Mail"
    out = cli("credentials", "list", "--username", "vcli",
              "--state-dir", sd, "--endpoint", url)
    assert "Example Mail" in out
    assert PASSWORD not in out and NOTES not in out
    out = cli("credentials", "get", "Example Mail",
              "--username", "vcli", "--state-dir", sd,
              "--endpoint", url)
    assert json.loads(out)["password"] == PASSWORD
    out = cli("credentials", "remove", entry["id"],
              "--username", "vcli", "--state-dir", sd,
              "--endpoint", url)
    assert json.loads(out)["id"] == entry["id"]
    out = cli("credentials", "list", "--username", "vcli",
              "--state-dir", sd, "--endpoint", url)
    assert json.loads(out) == []
    h.stop()


def test_control_channel_vault_forwarding(tmp_path, state_root):
    db = str(tmp_path / "relay.db")
    h = RelayHandle(db, "vault-cc")
    url = h.start()
    sd = str(state_root / "vseat")

    async def _t():
        daemon = Agent("vseat", endpoint=url, state_dir=sd)
        await daemon.start()
        try:
            put = await forward_command(
                sd, "vseat", {"cmd": "vault_put",
                              "service": "Example Mail",
                              "username": "vseat@example.com",
                              "password": PASSWORD, "notes": NOTES})
            assert put["service"] == "Example Mail"
            lst = await forward_command(sd, "vseat",
                                        {"cmd": "vault_list"})
            assert lst["entries"][0]["username"] == \
                "vseat@example.com"
            assert PASSWORD not in json.dumps(lst)
            got = await forward_command(
                sd, "vseat", {"cmd": "vault_get",
                              "service_or_id": "Example Mail"})
            assert got["password"] == PASSWORD
            rem = await forward_command(
                sd, "vseat", {"cmd": "vault_remove",
                              "entry_id": put["id"]})
            assert rem["id"] == put["id"]
        finally:
            await daemon.close()

    run(_t())
    h.stop()


# -- 12: group vault surface untouched ---------------------------------------------

def test_group_vault_surface_untouched():
    for name in ("vault_put", "vault_list", "vault_pin",
                 "vault_remove"):
        assert callable(getattr(Agent, name))
    params = list(inspect.signature(Agent.vault_put).parameters)
    assert params[1:3] == ["group_id", "path"]
    # The credentials facade is an instance attribute (set in
    # __init__), not a class member shadowing the group methods.
    assert "vault" not in vars(Agent)
