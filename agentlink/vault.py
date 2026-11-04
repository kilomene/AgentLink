"""Per-agent credentials vault (v1.4.0, owner's direct order).

Every agent gets its OWN credentials vault, shaped like the Muse
Secure Vault: when the agent creates an account with its email, the
login (service, email/username, password) is saved into its vault
through the one paved call — :meth:`VaultAccess.remember` (also
``Agent.vault_remember``) — and the agent later opens its own vault
to log in with NO permission step: possession of the agent's identity
key IS the permission. There is no prompt, no approval, no second
party.

Crypto (the codebase's existing machinery, no parallel stack):

* Each entry's content (service, account username, password, notes,
  timestamps) is sealed to the agent's OWN X25519 identity public
  key with the standard 1:1 envelope scheme
  (:meth:`Identity.encrypt_for`). Only the identity private key —
  which never leaves the agent's state dir — can open an entry.
* The vault document (the local file AND the synced blob are the
  same bytes) carries only sealed entries plus ids/timestamps, and
  is SIGNED with the identity Ed25519 key. Any tampering — a flipped
  ciphertext byte, a swapped entry, a foreign agent's document —
  fails verification and the vault refuses to open: fail closed, no
  partial plaintext, ever.
* Entry LABELS (service + account username + created/updated
  timestamps — never the password, never notes) are ADDITIONALLY
  sealed to the owner-oversight key and published to the relay, so
  the owner's dashboard can list what the vault holds inside his
  authenticated session. PASSWORDS ARE NEVER OVERSIGHT-SEALED: the
  owner cannot read them, no operator can, and that is deliberate —
  the vault is the agent's own, exactly like the owner's Muse
  vault is his.

Storage + sync: the signed document lives in the agent's state dir
(``credentials-vault-<username>.json``, mode 0600). On every mutation
(and on every connect) the client also uploads the document through
the relay blob layer (content-addressed, owner-scoped) and publishes
the pointer + labels; when the agent's server is CARRIED to another
host, the same identity fetches the document back through the blob
layer and the vault opens there — the vault follows the agent while
carrier, relay and object store only ever hold ciphertext.

A vault whose identity keys are lost is unreadable — by anyone,
including its owner. Key backup is the operator's existing
identity-backup story (the keys file in the state dir); there is no
recovery backdoor and this module will never grow one.
"""

from __future__ import annotations

import json
import os
import threading
import time
from pathlib import Path

from .crypto import Identity, encrypt_to_pubkey
from .protocol import new_id

VAULT_KIND = "agentlink-credentials-vault"
VAULT_FORMAT = 1
LABELS_KIND = "vault_labels"
CONTENT_KIND = "vault_content"
# The forms an entry's secret can take (v1.5.0, owner's ruling):
# a login is not always a password — agents hold API keys, tokens
# and other auth material too. "password" is the default and the
# reading of every pre-1.5.0 entry (which carries no auth_type).
AUTH_TYPES = ("password", "api_key", "token", "other")


class VaultError(Exception):
    """A vault operation failed closed: unreadable or tampered
    vault, a foreign document, a missing entry, an ephemeral
    identity. The message names the fact; no plaintext is ever
    produced on this path."""


def _canonical(doc: dict) -> bytes:
    """The signed bytes of a vault document: the document without
    its ``sig`` member, canonical JSON."""
    body = {k: v for k, v in doc.items() if k != "sig"}
    return json.dumps(body, sort_keys=True,
                      separators=(",", ":")).encode()


def _service_key(service: str) -> str:
    return str(service or "").strip().lower()


class CredentialsVault:
    """The agent's own vault: a signed document of self-sealed
    entries, persisted in the state dir. All operations are local
    and synchronous — any process holding the identity + state dir
    (the agent daemon, its decision-link endpoint, a one-shot CLI)
    opens the same vault with no connection and no permission step.
    Sync/publish live on the Agent (see client.py), because they
    need the line; the vault itself never does."""

    def __init__(self, identity: Identity, state_dir: str | Path,
                 username: str):
        if identity is None or getattr(identity, "path", None) is None:
            raise VaultError(
                "a credentials vault needs the agent's persistent "
                "identity (an ephemeral identity has no vault)")
        self._identity = identity
        self.username = username
        self.path = (Path(state_dir).expanduser()
                     / f"credentials-vault-{username}.json")
        self._lock = threading.RLock()
        self._entries: dict[str, dict] = {}
        self._revision = 0
        # Set when the on-disk document failed verification and was
        # quarantined: the vault starts empty LOCALLY, the fact is
        # recorded loudly, and the synced copy (which outranks a
        # quarantined file) is what sync restores from.
        self.load_error: str | None = None
        self._load()

    # -- persistence ----------------------------------------------------

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            doc = json.loads(self.path.read_text())
            entries, revision = self._verify_document(doc)
        except Exception as exc:
            quarantine = self.path.with_suffix(
                f".corrupt-{int(time.time())}")
            try:
                self.path.rename(quarantine)
            except OSError:
                pass
            self.load_error = (
                f"vault document failed verification "
                f"({type(exc).__name__}: {exc}); quarantined to "
                f"{quarantine.name} and started empty — the synced "
                f"copy is authoritative for restore")
            return
        self._entries = entries
        self._revision = revision

    def _verify_document(self, doc) -> tuple[dict, int]:
        """Verify a parsed vault document end to end and return
        (entries-by-id, revision). Raises VaultError on ANY defect:
        wrong kind/format/owner, bad signature, malformed entry.
        The signature is checked against THIS identity's signing
        public key — a foreign agent's document fails here, which
        is the access control: the vault opens only for its owner."""
        if not isinstance(doc, dict) \
                or doc.get("kind") != VAULT_KIND \
                or doc.get("version") != VAULT_FORMAT:
            raise VaultError("not a credentials vault document")
        if doc.get("username") != self.username:
            raise VaultError(
                "vault document belongs to a different agent")
        sig = doc.get("sig") or ""
        if not Identity.verify_signature(
                self._identity.signing_public_key_b64,
                _canonical(doc), sig):
            raise VaultError(
                "vault document signature does not verify under "
                "this identity (foreign or tampered document)")
        entries: dict[str, dict] = {}
        for rec in doc.get("entries") or []:
            if not isinstance(rec, dict) \
                    or not isinstance(rec.get("id"), str) \
                    or not isinstance(rec.get("content"), dict):
                raise VaultError("malformed vault entry record")
            entries[rec["id"]] = {
                "id": rec["id"],
                "created_at": int(rec.get("created_at") or 0),
                "updated_at": int(rec.get("updated_at") or 0),
                "content": rec["content"]}
        return entries, int(doc.get("revision") or 0)

    def document(self) -> dict:
        """The signed vault document (entries as sealed records)."""
        doc = {"kind": VAULT_KIND, "version": VAULT_FORMAT,
               "username": self.username,
               "revision": self._revision,
               "entries": [self._entries[k]
                           for k in sorted(self._entries)]}
        doc["sig"] = self._identity.sign(_canonical(doc))
        return doc

    def document_bytes(self) -> bytes:
        return json.dumps(self.document()).encode()

    def document_revision(self, data: bytes) -> int:
        """The revision of a synced document WITHOUT adopting it —
        verified first (a foreign or tampered document raises, so
        a revision is only ever read from an authentic document of
        this identity)."""
        try:
            doc = json.loads(data.decode())
        except Exception as exc:
            raise VaultError(
                f"synced vault document is not valid JSON: {exc}")
        _entries, revision = self._verify_document(doc)
        return revision

    def adopt_document(self, data: bytes) -> int:
        """Replace the local vault with a verified synced document
        (the carried/restore path). Returns the entry count. Fails
        closed on a foreign or tampered document — nothing is
        adopted and the local vault is untouched."""
        try:
            doc = json.loads(data.decode())
        except Exception as exc:
            raise VaultError(
                f"synced vault document is not valid JSON: {exc}")
        entries, revision = self._verify_document(doc)
        with self._lock:
            self._entries = entries
            self._revision = revision
            self.load_error = None
            self._save()
        return len(entries)

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.document()))
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    # -- entry plumbing ---------------------------------------------------

    def _open_entry(self, rec: dict) -> dict:
        """Decrypt one entry record into its full plaintext dict.
        AEAD failure raises — a tampered entry fails closed, never
        partially."""
        try:
            raw = self._identity.decrypt_envelope(rec["content"])
            obj = json.loads(raw)
        except Exception as exc:
            raise VaultError(
                f"vault entry {rec.get('id')} does not decrypt "
                f"under this identity (tampered or foreign): {exc}")
        return {"id": rec["id"],
                "service": obj.get("service") or "",
                "username": obj.get("username") or "",
                "password": obj.get("password") or "",
                "auth_type": obj.get("auth_type") or "password",
                "notes": obj.get("notes") or "",
                # Grant provenance (v1.8.0): the id of the signed
                # grant receipt under which this credential was
                # created, or "" when it was not created under a
                # grant. Carried into the oversight content payload
                # so the dashboard can show the provenance.
                "grant_receipt": obj.get("grant_receipt") or "",
                "created_at": int(obj.get("created_at")
                                  or rec["created_at"]),
                "updated_at": int(obj.get("updated_at")
                                  or rec["updated_at"])}

    def _find(self, service_or_id: str) -> dict:
        """Resolve an id, or a service name (most recently updated
        entry for that service), to an entry record."""
        if service_or_id in self._entries:
            return self._entries[service_or_id]
        key = _service_key(service_or_id)
        matches = []
        for rec in self._entries.values():
            entry = self._open_entry(rec)
            if _service_key(entry["service"]) == key:
                matches.append((entry["updated_at"], rec))
        if not matches:
            raise VaultError(
                f"no vault entry for {service_or_id!r}")
        matches.sort()
        return matches[-1][1]

    # -- the paved surface --------------------------------------------------

    @property
    def revision(self) -> int:
        return self._revision

    def __len__(self) -> int:
        return len(self._entries)

    def put(self, service: str, username: str, password: str,
            notes: str = "", auth_type: str = "password",
            grant_receipt: str = "") -> dict:
        """Save one account login into the vault and return the full
        entry (including its id). Saving the same service + account
        again UPDATES that entry (new password/notes, fresh
        updated_at) rather than piling up duplicates — an agent
        rotating a password it owns lands on the same entry.
        ``auth_type`` names the FORM of the secret (v1.5.0):
        "password" (default), "api_key", "token" or "other" — the
        secret value itself rides in ``password`` either way.
        ``grant_receipt`` (v1.8.0) records provenance: the id of
        the signed grant receipt under which this credential was
        created (empty when it was not). An update that passes no
        receipt keeps the entry's existing provenance — a
        credential's origin does not wash off by being edited."""
        service = str(service or "").strip()
        username = str(username or "").strip()
        if not service or not username:
            raise VaultError(
                "a vault entry needs a service and an account "
                "username (the email the account was created with)")
        auth_type = str(auth_type or "password").strip().lower()
        if auth_type not in AUTH_TYPES:
            raise VaultError(
                f"unknown auth_type {auth_type!r} — expected one of "
                f"{', '.join(AUTH_TYPES)}")
        now = int(time.time())
        with self._lock:
            existing = None
            for rec in self._entries.values():
                entry = self._open_entry(rec)
                if _service_key(entry["service"]) \
                        == _service_key(service) \
                        and entry["username"].lower() \
                        == username.lower():
                    existing = (rec, entry)
                    break
            if existing is not None:
                rec, entry = existing
                entry.update({"service": service,
                              "username": username,
                              "password": str(password),
                              "auth_type": auth_type,
                              "notes": str(notes or ""),
                              "grant_receipt": str(
                                  grant_receipt
                                  or entry.get("grant_receipt")
                                  or ""),
                              "updated_at": now})
                entry_id = rec["id"]
                created = entry["created_at"]
            else:
                entry_id = new_id("cred-")
                created = now
                entry = {"service": service, "username": username,
                         "password": str(password),
                         "auth_type": auth_type,
                         "notes": str(notes or ""),
                         "grant_receipt": str(grant_receipt or ""),
                         "created_at": now, "updated_at": now}
            envelope = self._identity.encrypt_for(
                self._identity.public_key_b64,
                json.dumps(entry).encode())
            self._entries[entry_id] = {
                "id": entry_id, "created_at": created,
                "updated_at": now, "content": envelope}
            self._revision += 1
            self._save()
            return {"id": entry_id, **entry}

    def remember(self, service: str, username: str, password: str,
                 notes: str = "", auth_type: str = "password",
                 grant_receipt: str = "") -> dict:
        """THE auto-save path (owner's order): the one call an agent
        — or its account-creation helper — makes the moment it
        creates an account, so the login lands in its vault
        automatically. Identical semantics to put(); the separate
        name is the paved road, documented as the default."""
        return self.put(service, username, password, notes,
                        auth_type=auth_type,
                        grant_receipt=grant_receipt)

    def get(self, service_or_id: str) -> dict:
        """Open one entry in full (password included) — the agent
        retrieving its own login to sign in. No permission step
        exists on this path by design."""
        with self._lock:
            return self._open_entry(self._find(str(service_or_id)))

    def list(self) -> list[dict]:
        """Entry LABELS only — id, service, account username and
        timestamps. Passwords and notes are never projected here,
        so list() output is safe to log, show and sync as metadata."""
        with self._lock:
            out = []
            for rec in self._entries.values():
                entry = self._open_entry(rec)
                out.append({"id": entry["id"],
                            "service": entry["service"],
                            "username": entry["username"],
                            "created_at": entry["created_at"],
                            "updated_at": entry["updated_at"]})
            out.sort(key=lambda e: (e["service"].lower(),
                                    e["username"].lower()))
            return out

    def remove(self, entry_id: str) -> dict:
        """Remove one entry by id; returns its label (never the
        password — a removal receipt must not leak the secret it
        destroyed)."""
        with self._lock:
            rec = self._entries.pop(str(entry_id), None)
            if rec is None:
                raise VaultError(f"no vault entry {entry_id!r}")
            entry = self._open_entry(rec)
            self._revision += 1
            self._save()
            return {"id": entry["id"], "service": entry["service"],
                    "username": entry["username"],
                    "created_at": entry["created_at"],
                    "updated_at": entry["updated_at"]}

    # -- owner-oversight labels --------------------------------------------

    def labels_envelope(self, oversight_pub_b64: str) -> dict | None:
        """The entry labels sealed to the OWNER-OVERSIGHT key, for
        the dashboard's Agents cell. The payload is labels only
        (service, account, timestamps): never the password, never
        notes. (The FULL content travels in its own oversight
        envelope — content_envelope — for the dashboard's
        Credentials view, per the owner's v1.5.0 ruling.) Returns
        None when no oversight key is known (nothing is published
        then — labels stay home)."""
        if not oversight_pub_b64:
            return None
        payload = {"kind": LABELS_KIND, "username": self.username,
                   "revision": self._revision,
                   "labels": self.list()}
        env = encrypt_to_pubkey(
            oversight_pub_b64, json.dumps(payload).encode())
        env["kind"] = LABELS_KIND
        return env

    def content_envelope(self, oversight_pub_b64: str) -> dict | None:
        """The FULL entry content sealed to the OWNER-OVERSIGHT key
        (v1.5.0, owner's explicit ruling, superseding the v1.4.0
        labels-only dashboard design): service, account, auth_type,
        the SECRET itself and notes — everything the vault holds —
        sealed the same way conversation content is sealed to
        oversight, so the owner's dashboard can show it inside his
        authenticated session (the Credentials view). The relay and
        stores hold this envelope as ciphertext only; plaintext
        exists in exactly two places: the agent (identity key) and
        the owner's authenticated dashboard session (oversight
        key). The owner's stated safety basis: no agent can open
        the dashboard. Returns None when no oversight key is known
        (the agent then shares labels only)."""
        if not oversight_pub_b64:
            return None
        payload = {"kind": CONTENT_KIND, "username": self.username,
                   "revision": self._revision,
                   "entries": [self._open_entry(rec) for rec in
                               self._entries.values()]}
        env = encrypt_to_pubkey(
            oversight_pub_b64, json.dumps(payload).encode())
        env["kind"] = CONTENT_KIND
        return env


class VaultAccess:
    """The Agent-bound facade (``agent.vault``): the synchronous
    local core plus line sync — every mutation is saved locally
    FIRST (the vault is the agent's own; the line is only its
    replication) and then published when connected, so the vault
    follows the agent across servers and hosts. Constructed by the
    Agent; operators normally just call these methods (or the flat
    ``Agent.vault_remember`` for the auto-save path)."""

    def __init__(self, agent):
        self._agent = agent

    def _core(self) -> CredentialsVault:
        return self._agent._credentials_vault()

    async def put(self, service: str, username: str, password: str,
                  notes: str = "", auth_type: str = "password",
                  grant_receipt: str = "") -> dict:
        entry = self._core().put(service, username, password, notes,
                                 auth_type=auth_type,
                                 grant_receipt=grant_receipt)
        await self._agent._vault_sync_after_mutation()
        return entry

    async def remember(self, service: str, username: str,
                       password: str, notes: str = "",
                       auth_type: str = "password",
                       grant_receipt: str = "") -> dict:
        """THE auto-save path: call this the moment an account is
        created and the login is in the vault — no permission, no
        prompt, no second step."""
        entry = self._core().remember(service, username, password,
                                      notes, auth_type=auth_type,
                                      grant_receipt=grant_receipt)
        await self._agent._vault_sync_after_mutation()
        return entry

    async def get(self, service_or_id: str) -> dict:
        return self._core().get(service_or_id)

    async def list(self) -> list[dict]:
        return self._core().list()

    async def remove(self, entry_id: str) -> dict:
        label = self._core().remove(entry_id)
        await self._agent._vault_sync_after_mutation()
        return label
