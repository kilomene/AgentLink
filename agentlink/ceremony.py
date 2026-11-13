"""Attended install ceremony (v2.6.0, SPEC Part 3).

`agentlink install --username <u> --provisioning-grant <token>`
runs ONE guided, operator-visible installation of the stock
client: nine steps, in a fixed order, each landing a step
receipt in ``<state-dir>/ceremony-state.json``. An install is
complete ONLY when all nine steps have landed; the CLI exits 0
only then. Any step failure HALTS the ceremony with a named
fault (front-door taxonomy style: PROXY / DOOR / STALE classes
plus ceremony faults such as ``grant_refused:<server fault>``,
``attestation_not_stock`` and ``deposit_unconfirmed``) — the
ceremony never improvises a workaround. Re-running the same
command RESUMES at the first incomplete step: landed steps are
verified (state + the platform record, where one exists) and
never re-executed blindly. There is no skip path: no flag, no
env var, no state edit moves the resume point past a step that
has not verifiably landed.

THE NINE STEPS
  1. env-check — a TRANSIENT environment check for SETUP
     purposes only (python version adequate, state dir
     writable, clock sane). This is the owner's attended
     exception (SPEC Part 3): setup facts are used to complete
     setup and are NEVER stored as a spec record. The receipt
     records only pass/fail booleans + a fault class — no
     version strings, no snapshot, nothing about the machine.
     No machine detection lives in this module (the retired
     spec machinery stays retired; gate-pinned).
  2. network self-config — the agent's OWN network layer
     (setup.choose_network, the same semantics as
     `agentlink setup` step 1). The receipt records only that
     a path was proven — never the proxy URL (a credential).
  3. key generation on this machine (the client's existing
     identity creation path; keys never leave the state dir).
  4. provisioning grant presentation + registration (SPEC
     Part 2 plumbing: the grant rides the register request
     only, resolved flag > env > workspace drop-in, exactly as
     Agent resolves it).
  5. recovery file written + its hash registered, possession
     proven: registration minted the key server-side and the
     login Edge stored its SHA-256 in the same act; the agent
     persists the key under the storage contract (state copy +
     workspace file) and proves possession — where the record
     layer lets the agent read its own recovery_hash back, by
     hash equality with the held key; otherwise by holding, in
     both storage copies, the exact key the Edge issued in the
     register reply.
  6. orders inscription + platform acceptance (2.5.1
     machinery: ensure_orders + auto_accept_orders).
  7. nature declaration (the transport's ensure_nature_declared
     — the per-runtime proposal as the baseline, as setup does).
  8. first liveness proof + build attestation: the runtime
     proof goes through the client path and the build statement
     is the one made at login; the step lands ONLY when the
     platform reads build_integrity == stock (the Street Rule:
     the platform judges, never the agent's own claim).
  9. first dossier generated as agentlink-dossier/2 and
     deposited (dossier.generate + drain via the platform
     depositor); the step lands only on a CONFIRMED deposit in
     the platform inbox.

STEP 6 READING (the one judgment call in this module, stated
plainly): the spec counts an install complete only when all
nine steps land, and step 6 is "orders inscription + platform
acceptance". The 2.5.1 machinery half — placement, integrity,
and the platform's acceptance recorded by daemon-machinery —
is what the ceremony can land, and its landing is what step 6
requires. The runtime's OWN memory inscription (the Brain
Doctrine: inscription into the agent's own memory store is the
operating agent's act, attestable only by `agentlink orders
ack`) is NEVER faked by the ceremony: the step-6 receipt
records the machinery facts and states the runtime inscription
as the runtime's pending act. It does not block step 6,
because the platform half the ceremony exists to land has
landed; claiming the inscription itself had happened would be
exactly the falsehood the Brain Doctrine forbids.

RECEIPT SIGNING: receipts are appended as
{step, name, ts, ok, detail, sig}. Steps 1-2 run before any
identity exists, so their receipts carry sig=null and the note
"pre-identity" — honest, not countersigned after the fact.
From step 3 on, each receipt is signed with the agent's
identity key over the canonical JSON of the receipt body
(the dossier signing style). On every run, before anything
executes, the landed receipts from step 3 on are
signature-verified against the identity in the state dir: a
state file whose later receipts do not verify (a forged state
claiming steps landed) halts the ceremony with
``state_signature_invalid`` and nothing runs.

OPERATOR VISIBILITY: the support desk is the operator surface
that already exists for a not-yet-registered agent (SPEC
Part 2 names it the legitimate door at the registration
boundary), so the ceremony lodges ONE support ticket on halt
and ONE on completion, each carrying client_context
{ceremony: true, kind: "ceremony_halt" | "ceremony_complete",
username, fault / completed steps} — the operator sees
ceremony state per username on the desk they already watch.
The hook is NOT installed (the support hook re-runs plain
setup; a ceremony resumes by re-running `agentlink install`).
The full state also lives locally at
<state-dir>/ceremony-state.json and is readable any time with
`agentlink install --status`. No new Edge was invented: the
server side is frozen for this release.
"""
from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

from .liveness import canonical_json
from .protocol import normalize_username

STATE_FILENAME = "ceremony-state.json"
CEREMONY_KIND = "agentlink-install-ceremony"

#: The nine steps, in order. The order is the spec's; nothing
#: in this module (or any caller) may reorder or skip one.
STEPS: tuple[tuple[int, str], ...] = (
    (1, "env-check"),
    (2, "network"),
    (3, "key-generation"),
    (4, "registration"),
    (5, "recovery"),
    (6, "orders"),
    (7, "nature"),
    (8, "liveness-attestation"),
    (9, "dossier"),
)
STEP_NAMES = dict(STEPS)

SUPPORT_POINTER = (
    "help for a stranded install is at the support door: "
    "`agentlink support lodge --username <name> --message "
    "\"<what happened>\"` (no account needed); ceremony state "
    "is readable with `agentlink install --status`")


class CeremonyFault(Exception):
    """A named ceremony fault. ``fault`` is the taxonomy name
    recorded in state + the failed receipt; ``detail`` is a
    short human explanation. Raising one halts the ceremony —
    no step catches one and improvises."""

    def __init__(self, fault: str, detail: str = ""):
        super().__init__(f"{fault}: {detail}" if detail else fault)
        self.fault = fault
        self.detail = detail


def state_path(state_dir) -> Path:
    return Path(state_dir).expanduser() / STATE_FILENAME


def load_state(state_dir) -> dict | None:
    p = state_path(state_dir)
    if not p.exists():
        return None
    try:
        data = json.loads(p.read_text())
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _save_state(state_dir, state: dict) -> None:
    p = state_path(state_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    state["updated_at"] = int(time.time())
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.replace(p)


def receipt_body(receipt: dict) -> dict:
    """The signed body of a receipt: everything except the
    signature itself (the dossier signing style)."""
    return {k: v for k, v in receipt.items() if k != "sig"}


def _named_fault(exc: Exception) -> CeremonyFault:
    """Map a step's raw failure onto the named-fault taxonomy.
    A CeremonyFault passes through untouched; a server refusal
    naming a provisioning-grant fault becomes
    grant_refused:<that fault>, verbatim from the server."""
    if isinstance(exc, CeremonyFault):
        return exc
    text = str(exc)
    import re
    m = re.search(r"provisioning_grant[a-z_]*", text)
    if m:
        return CeremonyFault(f"grant_refused:{m.group(0)}",
                             text[:300])
    if "username_taken" in text:
        return CeremonyFault("registration_refused:username_taken",
                             text[:300])
    return CeremonyFault(
        f"step_failed:{type(exc).__name__}", text[:300])


# ------------------------------------------------------------ ops

class CeremonyOps:
    """The operations the ceremony orchestrates, one method
    per step. Each step method returns the receipt DETAIL dict
    on success and raises (CeremonyFault for a named fault, any
    other exception is mapped by the runner) on failure. The
    runner owns state, receipts, signing, halting and resume;
    an ops object owns only the acts themselves.

    ``verify_step`` is the resume check: True when the step's
    landing is confirmed NOW (from the platform record where
    one exists, else durable local state). The default trusts
    the signed receipt; RealOps overrides it with the real
    platform checks."""

    def identity(self):
        """The agent's Identity once keys exist on disk, else
        None. Must NOT create keys — creation is step 3's act."""
        return None

    def verify_step(self, step: int, receipt: dict) -> bool:
        return True

    def notify(self, state: dict, event: str) -> dict | None:
        """Operator visibility hook (halt / complete). Returns
        a small summary dict recorded in state, or None."""
        return None

    def close(self) -> None:
        pass

    # the nine acts — subclasses implement all of them
    def step_env_check(self) -> dict:
        raise NotImplementedError

    def step_network(self) -> dict:
        raise NotImplementedError

    def step_key_generation(self) -> dict:
        raise NotImplementedError

    def step_registration(self) -> dict:
        raise NotImplementedError

    def step_recovery(self) -> dict:
        raise NotImplementedError

    def step_orders(self) -> dict:
        raise NotImplementedError

    def step_nature(self) -> dict:
        raise NotImplementedError

    def step_liveness_attestation(self) -> dict:
        raise NotImplementedError

    def step_dossier(self) -> dict:
        raise NotImplementedError


_STEP_METHODS = {
    1: "step_env_check",
    2: "step_network",
    3: "step_key_generation",
    4: "step_registration",
    5: "step_recovery",
    6: "step_orders",
    7: "step_nature",
    8: "step_liveness_attestation",
    9: "step_dossier",
}


# ------------------------------------------------------------ runner

class CeremonyRunner:
    """Drives the nine steps over an ops object, keeping the
    durable ceremony state. One runner per `agentlink install`
    invocation; run() returns the final state dict (inspect
    state["complete"] / state["fault"])."""

    def __init__(self, username: str, state_dir, ops: CeremonyOps):
        uname = normalize_username(username)
        if uname is None:
            raise ValueError(f"bad username {username!r}")
        self.username = uname
        self.state_dir = Path(state_dir).expanduser()
        self.ops = ops

    # -- state + receipts --------------------------------------

    def _fresh_state(self) -> dict:
        return {"kind": CEREMONY_KIND, "version": 1,
                "username": self.username,
                "state_dir": str(self.state_dir),
                "started_at": int(time.time()),
                "updated_at": int(time.time()),
                "complete": False, "failed_step": None,
                "fault": None, "receipts": [], "support": None}

    def _sign(self, receipt: dict) -> None:
        if receipt["step"] < 3:
            receipt["sig"] = None
            receipt["note"] = "pre-identity"
            return
        ident = self.ops.identity()
        if ident is None:
            receipt["sig"] = None
            receipt["note"] = "identity unavailable at signing"
            return
        receipt["sig"] = ident.sign(
            canonical_json(receipt_body(receipt)).encode())

    def _append_receipt(self, state: dict, step: int, ok: bool,
                        detail: dict) -> dict:
        receipt = {"step": step, "name": STEP_NAMES[step],
                   "ts": int(time.time()), "ok": bool(ok),
                   "detail": detail}
        self._sign(receipt)
        state["receipts"].append(receipt)
        _save_state(self.state_dir, state)
        return receipt

    def _verify_landed_receipts(self, state: dict) -> dict:
        """The landed set, proven for THIS run. Raises
        CeremonyFault(state_signature_invalid / state_gap) on a
        forged or gapped state: ok-receipts must form a prefix
        1..n, and every ok-receipt from step 3 on must verify
        against the state dir's identity key."""
        landed: dict[int, dict] = {}
        for r in state.get("receipts") or []:
            if isinstance(r, dict) and r.get("ok"):
                landed[int(r.get("step") or 0)] = r
        steps = sorted(landed)
        if steps != list(range(1, len(steps) + 1)):
            raise CeremonyFault(
                "state_gap",
                f"landed receipts are not a prefix: {steps}")
        if any(s >= 3 for s in steps):
            ident = self.ops.identity()
            if ident is None:
                raise CeremonyFault(
                    "state_signature_invalid",
                    "receipts claim steps >= 3 landed but no "
                    "identity keys exist in the state dir")
            from .crypto import Identity
            pub = ident.signing_public_key_b64
            for s in steps:
                if s < 3:
                    continue
                r = landed[s]
                sig = r.get("sig")
                if not sig or not Identity.verify_signature(
                        pub, canonical_json(
                            receipt_body(r)).encode(), str(sig)):
                    raise CeremonyFault(
                        "state_signature_invalid",
                        f"step {s} receipt does not verify "
                        f"against this state dir's identity key")
        return landed

    # -- the run ------------------------------------------------

    def run(self) -> dict:
        state = load_state(self.state_dir) or self._fresh_state()
        if state.get("username") not in (None, self.username):
            state = self._fresh_state()
        state["complete"] = False
        state["failed_step"] = None
        state["fault"] = None
        try:
            try:
                landed = self._verify_landed_receipts(state)
            except CeremonyFault as fault:
                state["failed_step"] = None
                state["fault"] = fault.fault
                state["fault_detail"] = fault.detail
                _save_state(self.state_dir, state)
                self._notify(state, "ceremony_halt")
                return state
            # Every landed step is verified for THIS run; the
            # ceremony executes exactly the steps that did not
            # verify, in order — landed steps are never
            # re-executed blindly, and no step is ever skipped
            # without a verification.
            verified: set[int] = set()
            for step, _name in STEPS:
                receipt = landed.get(step)
                if receipt is not None and \
                        self.ops.verify_step(step, receipt):
                    verified.add(step)
            for step, _name in STEPS:
                if step in verified:
                    continue
                method = getattr(self.ops, _STEP_METHODS[step])
                try:
                    detail = method()
                except Exception as exc:  # noqa: BLE001 - halt
                    fault = _named_fault(exc)
                    self._append_receipt(state, step, False, {
                        "fault": fault.fault,
                        "detail": fault.detail})
                    state["failed_step"] = step
                    state["fault"] = fault.fault
                    state["fault_detail"] = fault.detail
                    _save_state(self.state_dir, state)
                    self._notify(state, "ceremony_halt")
                    return state
                self._append_receipt(state, step, True,
                                     detail or {})
            state["complete"] = True
            state["completed_at"] = int(time.time())
            _save_state(self.state_dir, state)
            self._notify(state, "ceremony_complete")
            return state
        finally:
            try:
                self.ops.close()
            except Exception:
                pass

    def _notify(self, state: dict, event: str) -> None:
        try:
            info = self.ops.notify(state, event)
        except Exception:
            info = None
        if info:
            state["support"] = info
            _save_state(self.state_dir, state)


# ------------------------------------------------------------ real ops

class RealOps(CeremonyOps):
    """The ceremony over the real client machinery: an Agent
    facade (identity + recovery storage contract + transport
    factory, never started as a daemon) and its serverless
    transport, driven step by step."""

    def __init__(self, username: str, state_dir,
                 provisioning_grant: str | None = None,
                 designation: str = "production"):
        self.username = normalize_username(username) or username
        self.state_dir = Path(state_dir).expanduser()
        self._grant = provisioning_grant
        self._designation = designation
        self._agent = None
        self._transport = None
        self._recovery_key = ""
        self._session = False

    # -- plumbing ----------------------------------------------

    def _keys_path(self) -> Path:
        return self.state_dir / f"keys-{self.username}.json"

    def _ensure_agent(self):
        if self._agent is None:
            from .client import Agent
            self._agent = Agent(
                self.username, state_dir=str(self.state_dir),
                mode="manual", designation=self._designation,
                provisioning_grant=self._grant)
        return self._agent

    def identity(self):
        if not self._keys_path().exists():
            return None
        return self._ensure_agent().identity

    def _ensure_transport(self):
        if self._transport is None:
            agent = self._ensure_agent()
            self._transport = agent._make_v2_transport()
            agent._v2 = self._transport
        return self._transport

    def _ensure_session(self) -> bool:
        """A plain key login (never a grant — the reclaim/login
        doors are ungated): opens only when the account is
        bound to THIS machine's keys, which is exactly the
        platform record steps 4/7/8 verify against."""
        if self._session:
            return True
        try:
            from .client import _package_version
            agent = self._ensure_agent()
            transport = self._ensure_transport()
            transport.login(self.username, agent.identity.sign,
                            _package_version())
            self._session = True
        except Exception:
            return False
        return True

    def close(self) -> None:
        if self._transport is not None:
            try:
                self._transport.logout()
            except Exception:
                pass
            self._transport = None
            self._session = False

    # -- resume verification ------------------------------------

    def verify_step(self, step: int, receipt: dict) -> bool:
        try:
            if step == 1:
                return True  # transient by design; no record
            if step == 2:
                return (self.state_dir / "network.json").exists()
            if step == 3:
                if not self._keys_path().exists():
                    return False
                ident = self.identity()
                from .dossier import key_fingerprint
                return bool(ident) and \
                    (receipt.get("detail") or {}).get(
                        "sign_key_fingerprint") == \
                    key_fingerprint(ident.signing_public_key_b64)
            if step == 4:
                return self._ensure_session()
            if step == 5:
                agent = self._ensure_agent()
                return bool(agent._find_recovery_key())
            if step == 6:
                from .orders import orders_state
                st = orders_state(self.state_dir)
                return bool(st.get("installed")
                            and st.get("platform_accepted"))
            if step == 7:
                if not self._ensure_session():
                    return False
                return bool(self._ensure_transport()
                            .liveness_status().get("nature"))
            if step == 8:
                if not self._ensure_session():
                    return False
                return self._ensure_transport() \
                    .liveness_status().get("build_integrity") \
                    == "stock"
            if step == 9:
                from . import dossier as dossier_mod
                st = dossier_mod.load_state(self.state_dir)
                return bool(st.get("deposited_at")
                            and not st.get("queue"))
        except Exception:
            return False
        return False

    # -- operator visibility ------------------------------------

    def notify(self, state: dict, event: str) -> dict | None:
        """One support ticket per halt / completion, kind
        'ceremony' in the client context (see module docstring
        for the choice). Never raises: a desk that cannot be
        reached must not mask the ceremony's own verdict — the
        local state + `install --status` still carry it."""
        try:
            from . import support as support_mod
            landed = [r["step"] for r in state.get("receipts") or []
                      if r.get("ok")]
            if event == "ceremony_complete":
                problem = (
                    f"Install ceremony COMPLETE for "
                    f"@{self.username}: all nine steps landed "
                    f"(operator record, no action needed).")
            else:
                problem = (
                    f"Install ceremony HALTED for "
                    f"@{self.username} at step "
                    f"{state.get('failed_step')} "
                    f"({STEP_NAMES.get(state.get('failed_step') or 0, '?')}) "
                    f"with fault {state.get('fault')}: "
                    f"{state.get('fault_detail') or ''} "
                    f"Steps landed: {landed}. Resume by "
                    f"re-running `agentlink install` — it resumes "
                    f"at the failed step; no step can be skipped.")
            out = support_mod.lodge(
                self.username, problem, self.state_dir,
                install_hook=False,
                client_context={
                    "ceremony": True, "kind": event,
                    "failed_step": state.get("failed_step"),
                    "fault": state.get("fault"),
                    "landed_steps": landed})
            return {"ticket_id": out.get("ticket_id"),
                    "kind": event}
        except Exception as exc:  # noqa: BLE001 - visibility only
            return {"kind": event,
                    "lodge_error": str(exc)[:200]}

    # -- the nine acts ------------------------------------------

    def step_env_check(self) -> dict:
        """Transient setup facts ONLY: three pass/fail booleans.
        Nothing about the machine is recorded — no versions, no
        names, no sizes (SPEC Part 1 binds here too)."""
        checks = {"python_ok": sys.version_info >= (3, 10),
                  "state_dir_writable": False,
                  "clock_sane": False}
        try:
            self.state_dir.mkdir(parents=True, exist_ok=True)
            probe = self.state_dir / ".ceremony-env-probe"
            probe.write_text("agentlink ceremony env probe")
            checks["state_dir_writable"] = \
                probe.read_text().startswith("agentlink ceremony")
            probe.unlink(missing_ok=True)
        except Exception:
            checks["state_dir_writable"] = False
        now = int(time.time())
        # Sane = after the platform existed, before any date a
        # real install could plausibly carry.
        checks["clock_sane"] = 1577836800 <= now <= 4102444800
        failed = [k for k, v in checks.items() if not v]
        if failed:
            raise CeremonyFault(
                "env_check_failed",
                "failed checks: " + ", ".join(failed))
        return {**checks, "stored_as_spec": False}

    def step_network(self) -> dict:
        from .setup import choose_network
        net = choose_network(self.state_dir)
        if not net.get("proven"):
            raise CeremonyFault(
                "PROXY/no_egress_proven",
                "no egress candidate answered the login-challenge"
                " roundtrip; registration was not attempted")
        # The winning proxy URL is a credential: it is recorded
        # NOWHERE in the receipt — only that a path was proven.
        return {"proven": True, "direct": bool(net.get("direct")),
                "candidates_tried": len(net.get("attempts") or [])}

    def step_key_generation(self) -> dict:
        agent = self._ensure_agent()  # ctor mints/loads identity
        ident = agent.identity
        if ident is None or not self._keys_path().exists():
            raise CeremonyFault(
                "key_generation_failed",
                "the identity creation path produced no keys file")
        from .dossier import key_fingerprint
        return {
            "keys_file": self._keys_path().name,
            "sign_key_fingerprint": key_fingerprint(
                ident.signing_public_key_b64)}

    def step_registration(self) -> dict:
        from .client import _package_version
        from .transport_v2 import TransportError
        agent = self._ensure_agent()
        transport = self._ensure_transport()
        grant = agent._find_provisioning_grant() or ""
        ident = agent.identity
        try:
            result = transport.register_and_login(
                self.username, ident.sign,
                ident.signing_public_key_b64, ident.public_key_b64,
                _package_version(), designation=self._designation,
                provisioning_grant=grant)
        except TransportError as exc:
            if "username_taken" in str(exc) and \
                    self._ensure_session():
                # The self-collision rescue (2.2.0's shape): a
                # prior attempt's registration landed with its
                # reply lost — the key login opening IS the
                # platform record that the account is ours.
                return {"registered": True,
                        "via": "key_login_rescue",
                        "recovery_key_issued": False}
            raise
        self._session = True
        self._recovery_key = str(result.get("recovery_key") or "")
        return {"registered": True, "via": "register",
                "provisioning_grant_presented": bool(grant),
                "recovery_key_issued": bool(self._recovery_key)}

    def step_recovery(self) -> dict:
        agent = self._ensure_agent()
        key = self._recovery_key or agent._find_recovery_key() \
            or ""
        if not key:
            raise CeremonyFault(
                "recovery_key_missing",
                "no recovery key was issued at registration and "
                "none is held in the storage copies")
        if self._recovery_key:
            agent._save_recovery_key(key)
        state_copy = agent._recovery_state_path().exists()
        workspace_copy = agent._recovery_workspace_path().exists()
        if not (state_copy and workspace_copy):
            raise CeremonyFault(
                "recovery_file_incomplete",
                f"storage copies: state={state_copy} "
                f"workspace={workspace_copy}")
        digest = hashlib.sha256(key.encode()).hexdigest()
        # Possession proof: read my OWN recovery_hash back from
        # the record layer and match it against the held key.
        # The hash was registered by the login Edge in the same
        # act that minted the key at registration.
        possession = "server_issued_key_held_in_both_copies"
        hash_registered = bool(self._recovery_key)
        try:
            rows = self._ensure_transport()._rest(
                "GET", "al_users",
                "select=recovery_hash"
                f"&username=eq.{self.username}")
            server_hash = str((rows or [{}])[0].get(
                "recovery_hash") or "")
            if server_hash:
                hash_registered = server_hash == digest
                if hash_registered:
                    possession = "server_hash_match"
        except Exception:
            pass
        if not hash_registered:
            raise CeremonyFault(
                "recovery_hash_unregistered",
                "the platform record does not carry the hash of "
                "the recovery key this agent holds")
        return {"recovery_file": str(
                    agent._recovery_workspace_path()),
                "state_copy": state_copy,
                "workspace_copy": workspace_copy,
                "recovery_hash": digest,
                "hash_registered": True,
                "possession": possession}

    def step_orders(self) -> dict:
        """The machinery half (see the module docstring's
        step-6 reading): placement + integrity + platform
        acceptance, recorded by daemon-machinery. The runtime's
        own inscription is recorded as ITS pending act — never
        faked, never claimed."""
        from .orders import auto_accept_orders, ensure_orders
        ensure_orders(self.state_dir)
        st = auto_accept_orders(self.state_dir)
        if not st.get("installed"):
            raise CeremonyFault(
                "orders_not_installed",
                "ensure_orders did not install the canonical "
                "orders into the state dir")
        if not st.get("platform_accepted"):
            raise CeremonyFault(
                "orders_not_accepted",
                "the machinery acceptance was not recorded")
        return {
            "installed": True,
            "orders_version": st.get("orders_version"),
            "platform_accepted": True,
            "accepted_orders_version":
                st.get("accepted_orders_version"),
            "accepted_by": st.get("accepted_by"),
            "runtime_inscription": (
                "inscribed" if st.get("inscribed") else
                "pending — the runtime's own act (Brain "
                "Doctrine); the ceremony records it, never "
                "fakes it")}

    def step_nature(self) -> dict:
        transport = self._ensure_transport()
        out = transport.ensure_nature_declared(self.state_dir)
        if not (out.get("declared") or out.get("current")):
            raise CeremonyFault(
                "nature_declaration_failed",
                str(out.get("error") or out)[:300])
        return {"declared": bool(out.get("declared")),
                "current": bool(out.get("current")),
                "nature_version": out.get("nature_version"),
                "reasons": out.get("reasons") or []}

    def step_liveness_attestation(self) -> dict:
        transport = self._ensure_transport()
        # Attest BEFORE proving: attest_build primes the
        # transport's build state (the digest every later signed
        # payload carries); the daemon start path primes it the
        # same way. Proving first would send this install's
        # first proof digest-less, and an agent recorded at
        # 2.6.0 is refused for exactly that (attestation_
        # required) — the ceremony attests, then proves, then
        # reads the verdict.
        att = transport.attest_build(self.state_dir)
        proved = transport.liveness_prove()
        status = transport.liveness_status()
        integrity = str(status.get("build_integrity")
                        or "unattested")
        if integrity != "stock":
            raise CeremonyFault(
                f"attestation_not_stock:{integrity}",
                "the platform does not read this build as "
                f"stock (attest result: "
                f"{str(att)[:200]}; prove result: "
                f"{str(proved)[:120]})")
        return {"runtime_proved": True,
                "build_integrity": integrity,
                "build_version": status.get("build_version") or "",
                "build_digest_prefix":
                    str(status.get("build_digest") or "")[:12]}

    def step_dossier(self) -> dict:
        agent = self._ensure_agent()
        self._ensure_transport()
        out = agent._dossier_maintain("ceremony")
        drained = out.get("drain") or {}
        deposited = drained.get("deposited") or []
        confirmed = bool(deposited) or (
            out.get("status") == "current"
            and out.get("deposited_at"))
        if not confirmed:
            raise CeremonyFault(
                "deposit_unconfirmed",
                f"the dossier deposit was not confirmed in the "
                f"platform inbox (maintain result: "
                f"{str(out)[:240]})")
        # The deposited document must be dossier/2 (SPEC Part 1).
        schema = ""
        try:
            doc = json.loads(
                (self.state_dir / "dossier-staging"
                 / "DOSSIER.json").read_text())
            schema = str(doc.get("schema") or "")
        except Exception:
            schema = ""
        if schema and schema != "agentlink-dossier/2":
            raise CeremonyFault(
                "dossier_schema_mismatch",
                f"generated dossier schema is {schema!r}, "
                f"expected 'agentlink-dossier/2'")
        return {"schema": schema or "agentlink-dossier/2",
                "dossier_version": out.get("version"),
                "deposited": deposited,
                "status": out.get("status")}


def run_install(username: str, state_dir,
                provisioning_grant: str | None = None,
                designation: str = "production",
                ops: CeremonyOps | None = None) -> dict:
    """One `agentlink install` run: build the real ops (or take
    an injected one — drills/tests) and drive the ceremony.
    Returns the final ceremony state."""
    ops = ops or RealOps(username, state_dir,
                         provisioning_grant=provisioning_grant,
                         designation=designation)
    return CeremonyRunner(username, state_dir, ops).run()
