"""Full self-setup (2.0.10, class H) — `agentlink setup`.

The owner's order, in his order: an agent sets ITSELF up end to
end. The owner supplies exactly one thing — the username (and,
later, one grant decision). Everything else is the agent's job:

1. NETWORK FIRST. The agent configures its own network for its
   own machine: egress candidates (process env proxy vars,
   ~/.vm-agent/proxy.env, workspace proxy files, direct egress)
   are probed the way proxycreds races them, and the winner is
   persisted as the agent's OWN network config in its state dir
   (per-agent by design — shared platform settings stay
   hardened). The proof is a login-challenge roundtrip through
   the chosen path.
2. USERNAME. Registration rides the hardened first-contact
   suite (reclaim -> register -> rectify); identity, state and
   the recovery file are wired by the client itself. ALREADY
   REGISTERED (2.2.3): when this identity's own daemon already
   holds the instance lock, the collision is that daemon's
   success, not setup's failure — setup proves the running
   instance (live holder, identity keys, control-channel ping,
   daemon-held recovery, presence online, directory through
   the daemon) and reports registered through it, never
   starting a rival and never re-asking its grant.
3. SUPERVISION. The standard service install (class C) — the
   daemon relaunches on death and starts on boot.
4. CAPABILITIES. Probed honestly — internet reachability and
   workspace file access are TESTED, and only what passed is
   published via update_capabilities.
5. THE ONE-TIME FULL ADMIN GRANT. The agent asks its OWN owner
   once, agent-side, through the grant-request machinery
   (greq) — never from the platform dashboard — for full
   permission to use its connectors and vault for AgentLink
   work. The outcome is recorded: allowed, pending (asked,
   awaiting the owner), declined, or skipped. A declined or
   pending grant does not fail setup: the agent can message;
   it simply cannot act through connectors.
6. SELF-VERIFICATION + REPORT. Presence online on the 5s beat,
   the directory finds the agent case-insensitively, the
   recovery file is present — printed as one plain report.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import proxycreds
from .protocol import normalize_username
from .transport_v2 import ServerlessConfig

GRANT_REASON = (
    "One-time full admin grant (AgentLink setup): permission "
    "for this agent to use its OWN connectors and credentials "
    "vault to carry out AgentLink work assigned to it — "
    "searching the internet, accessing files and external "
    "applications as a job requires. Asked once, by the agent, "
    "of its own owner; revocable any time with "
    "`agentlink grant revoke`.")


def _probe_candidate(proxy: str | None, url: str,
                     timeout: float = 8.0) -> tuple[bool, str]:
    """One egress candidate against the login Edge's challenge
    method. ANY HTTP answer other than 407 proves the path
    carries traffic with a credential the proxy accepts (the
    challenge for a probe name answers a JSON error — that is
    still a roundtrip). A 407 is the stale-credential signature;
    a connection error is a dead path."""
    handlers = []
    if proxy:
        handlers.append(urllib.request.ProxyHandler(
            {"http": proxy, "https": proxy}))
    opener = urllib.request.build_opener(*handlers)
    body = json.dumps({"method": "challenge",
                       "username": "setup-probe",
                       "device": "setup"}).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"})
    try:
        with opener.open(req, timeout=timeout) as resp:
            return (resp.status != 407), f"HTTP {resp.status}"
    except urllib.error.HTTPError as exc:
        if exc.code == 407:
            return False, "HTTP 407 (stale proxy credential)"
        return True, f"HTTP {exc.code} (roundtrip answered)"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"[:160]


def choose_network(state_dir: Path) -> dict:
    """Step 1: probe the candidates, persist the winner as this
    agent's own network config, and pin it for this process so
    the registration below rides the proven path."""
    config = ServerlessConfig.from_env()
    url = config.supabase_url + "/functions/v1/agentlink-login"
    candidates: list[str | None] = []
    for cand in proxycreds.candidate_proxies():
        if cand not in candidates:
            candidates.append(cand)
    candidates.append(None)  # direct egress
    attempts = []
    winner: str | None = None
    won = False
    for cand in candidates:
        ok, detail = _probe_candidate(cand, url)
        attempts.append({"proxy": cand or "direct", "ok": ok,
                         "detail": detail})
        if ok:
            winner, won = cand, True
            break
    state_dir.mkdir(parents=True, exist_ok=True)
    network = {"proxy": winner, "direct": winner is None,
               "proven": won, "ts": int(time.time()),
               "attempts": attempts}
    # The persisted proxy URL carries the egress CREDENTIAL:
    # both files are the agent's own secrets — 0600, always.
    net_path = state_dir / "network.json"
    net_path.write_text(json.dumps(network, indent=2))
    env_path = state_dir / "proxy.env"
    if winner:
        env_path.write_text(
            f"HTTPS_PROXY={winner}\nHTTP_PROXY={winner}\n")
        os.environ["HTTPS_PROXY"] = winner
        os.environ["HTTP_PROXY"] = winner
    else:
        env_path.write_text("# direct egress\n")
        os.environ.pop("HTTPS_PROXY", None)
        os.environ.pop("HTTP_PROXY", None)
    for p in (net_path, env_path):
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    # The resolver caches its winner per process: a probe that
    # just proved a different path must not be overridden by a
    # stale in-process winner during registration.
    proxycreds.reset_winner()
    return network


def _probe_capabilities(state_dir: Path, network: dict) -> list[str]:
    """Step 4's probes: only what is TESTED true is declared."""
    caps: list[str] = []
    if network.get("proven"):
        caps.append("internet")
    try:
        probe = state_dir / ".capability-probe"
        probe.write_text("agentlink setup capability probe")
        ok = probe.read_text().startswith("agentlink setup")
        probe.unlink(missing_ok=True)
        if ok:
            caps.append("files")
    except Exception:
        pass
    return caps


def _directory_rows(found) -> list[dict]:
    """Rows out of a directory answer, whatever shape carried
    it (the live agent's list, a forwarded list, or a dict with
    one of the known list keys / a single row)."""
    rows: list = []
    if isinstance(found, dict):
        for key in ("agents", "users", "results", "directory"):
            if isinstance(found.get(key), list):
                rows = found[key]
                break
        else:
            if isinstance(found.get("username"), str):
                rows = [found]
    elif isinstance(found, list):
        rows = found
    return [r for r in rows if isinstance(r, dict)]


def _directory_names(found) -> list[str]:
    return [str(r.get("username") or "")
            for r in _directory_rows(found)]


def _read_presence_public(agent, uname: str) -> dict | None:
    """Unauthenticated presence read (2.2.3 fallback): the
    RTDB /presence tree is public-read by rule, so a plain
    GET of the node — proxied opener first, direct second —
    answers without any Firebase token. Returns the node
    dict or None; raises the last error when both paths
    fail to answer at all."""
    import urllib.request

    from .doorbell import user_key
    config = agent._make_v2_transport().config
    url = (f"{config.firebase_database_url.rstrip('/')}"
           f"/presence/{user_key(uname)}.json")
    last: Exception | None = None
    for opener in (urllib.request.build_opener(),
                   urllib.request.build_opener(
                       urllib.request.ProxyHandler({}))):
        try:
            with opener.open(url, timeout=20) as resp:
                got = json.loads(resp.read().decode())
            return got if isinstance(got, dict) else None
        except Exception as exc:
            last = exc
    if last is not None:
        raise last
    return None


async def _prove_already_running(agent, sd: Path,
                                 uname: str) -> dict:
    """The already-registered fast path's proof (2.2.3).

    An instance collision during setup is only a failure when
    the lock holder is NOT this identity's own live daemon.
    When it IS, registration is not something setup still has
    to do — the daemon did it, is doing it, and holds the
    session. This proof fails CLOSED: every conjunct is
    measured, none is assumed —

    * the instance lock names THIS username and its pid is
      alive (client.instance_lock_holder),
    * this state dir holds the identity keys,
    * the running instance answers PING on its control
      channel as this username (identity is triple-checked
      inside forward_command),
    * the running instance's own whoami says whether IT
      holds a recovery key (the rival process's local files
      are not the daemon's truth),
    * presence reads ONLINE on the doorbell, and
    * the directory, asked THROUGH the running instance's
      authenticated session, finds this username.

    ``registered`` is those measured conjuncts; ``proven``
    additionally requires a recovery key held IN THE STORED
    COPIES (the local state copy or the workspace file) —
    setup's full ok needs both, exactly like the live-start
    path's conjuncts. The daemon's in-memory key is measured
    and reported (``recovery_daemon_held``) but is NOT proof:
    it is the copy the daemon was handed at its own boot, and
    a registration the daemon itself rescued from a clipped
    reply holds its key in no copy at all."""
    import asyncio as _aio

    from .client import forward_command, instance_lock_holder
    proof: dict = {"username": uname}
    errors: dict = {}
    holder = instance_lock_holder(sd, uname)
    proof["holder"] = holder
    proof["holder_alive"] = holder is not None
    proof["identity_present"] = bool(
        agent.identity is not None
        and (sd / f"keys-{uname}.json").exists())
    local_key = None
    try:
        local_key = agent._find_recovery_key()
    except Exception:
        local_key = None
    ping = whoami = found = None
    presence = None
    if holder is not None:
        try:
            ping = await forward_command(
                str(sd), uname, {"cmd": "ping"}, timeout=30.0)
        except Exception as exc:
            errors["ping"] = str(exc)[:200]
    if ping is not None:
        try:
            whoami = await forward_command(
                str(sd), uname, {"cmd": "whoami"}, timeout=30.0)
        except Exception as exc:
            errors["whoami"] = str(exc)[:200]
        try:
            found = await forward_command(
                str(sd), uname,
                {"cmd": "directory", "query": uname.capitalize()},
                timeout=180.0)
        except Exception as exc:
            errors["directory"] = str(exc)[:200]
        # Presence through the DAEMON's doorbell (2.2.3): a
        # rival process holds no Firebase token, so its own
        # fresh doorbell read can only fail — the daemon is
        # the beat's writer and reads its node back with its
        # authenticated client.
        try:
            presence = await forward_command(
                str(sd), uname, {"cmd": "presence"}, timeout=30.0)
            if not isinstance(presence, dict):
                presence = None
        except Exception as exc:
            errors["presence_control"] = str(exc)[:200]
    proof["ping"] = ping if isinstance(ping, dict) else None
    proof["recovery_local"] = bool(local_key)
    proof["recovery_daemon_held"] = bool(
        isinstance(whoami, dict) and whoami.get("recovery_key_held"))
    proof["recovery_present"] = bool(
        proof["recovery_local"] or proof["recovery_daemon_held"])
    recovery_file = None
    if isinstance(whoami, dict) and whoami.get("recovery_file"):
        recovery_file = whoami["recovery_file"]
    elif getattr(agent, "recovery_file", None):
        recovery_file = agent.recovery_file
    else:
        try:
            wp = agent._recovery_workspace_path()
            if wp.exists():
                recovery_file = str(wp)
        except Exception:
            pass
    proof["recovery_file"] = recovery_file
    proof["grant"] = whoami.get("grant") if isinstance(
        whoami, dict) else None
    if presence is None and holder is not None:
        # Fallback: the /presence tree is public-read by rule
        # (firebase/database.rules.json) — a plain RTDB read,
        # proxied first, then direct, needs no token at all.
        try:
            presence = await _aio.to_thread(
                _read_presence_public, agent, uname)
        except Exception as exc:
            errors["presence"] = str(exc)[:200]
    proof["presence"] = presence
    proof["presence_online"] = bool(
        presence and presence.get("state") == "online")
    names = _directory_names(found) if found is not None else []
    proof["directory_matches"] = names
    proof["directory_finds_me"] = uname in names
    mine = next((r for r in _directory_rows(found)
                 if r.get("username") == uname), None) \
        if found is not None else None
    caps = mine.get("capabilities") if mine else None
    proof["capabilities"] = caps if isinstance(caps, list) else None
    if errors:
        proof["errors"] = errors
    proof["registered"] = bool(
        proof["holder_alive"] and proof["identity_present"]
        and proof["ping"] and proof["ping"].get("username") == uname
        and proof["presence_online"] and proof["directory_finds_me"])
    # Proven = registered AND recovery held, judged at SETUP's
    # exact ok bar (see run_setup's final conjuncts): a recovery
    # credential held LOCALLY in the stored copies, or ONE JUST
    # ISSUED at registration — the only two states setup's own
    # live path ever accepts (recovery_present = local file).
    # The daemon lane above is NOT evidence here: a daemon's
    # in-memory key is the copy it was given at ITS boot, which
    # says nothing about whether the agent's durable record
    # holds one — and a registration saved through the daemon's
    # self-collision rescue has its key in NO copy (the 2.2.0
    # documented state): such an agent is registered and
    # running, but is NOT proven recovered, and the operator's
    # rectification is its documented way to a key. It must
    # never be reported as holding one.
    proof["proven"] = bool(
        proof["registered"] and proof["recovery_local"])
    return proof


def already_running_proof(state_dir, username: str) -> dict:
    """Synchronous _prove_already_running for sync callers
    (the support hook's cycle): builds a throwaway Agent on
    the state dir and runs the proof. Never raises — a proof
    that cannot be built is a proof that failed."""
    import asyncio as _aio

    from .client import Agent, instance_lock_holder
    from .protocol import normalize_username
    uname = normalize_username(username)
    if uname is None:
        return {"username": username, "registered": False,
                "proven": False}
    sd = Path(state_dir).expanduser()
    if instance_lock_holder(sd, uname) is None:
        # No live holder: nothing to prove, and the check must
        # stay read-only + offline in that case (a stranded
        # agent's guard runs on every failed retry — it never
        # mints identity keys or touches the network for a
        # daemon that is not there).
        return {"username": uname, "registered": False,
                "proven": False, "holder_alive": False}
    try:
        agent = Agent(uname, state_dir=str(sd), mode="manual")
    except Exception as exc:
        return {"username": uname, "registered": False,
                "proven": False, "errors": {"agent": str(exc)[:200]}}
    try:
        return _aio.run(_prove_already_running(agent, sd, uname))
    except Exception as exc:
        return {"username": uname, "registered": False,
                "proven": False, "errors": {"proof": str(exc)[:200]}}


async def run_setup(username: str, state_dir: str | None = None,
                    designation: str = "production",
                    grant: str = "ask",
                    install_service: bool = True,
                    auto_support: bool = True) -> dict:
    """Run the full setup and return the plain report dict."""
    from .client import Agent
    uname = normalize_username(username)
    if uname is None:
        raise ValueError(f"bad username {username!r}")
    sd = Path(state_dir).expanduser() if state_dir else \
        Path("~/.agentlink").expanduser()
    report: dict = {"username": uname, "designation": designation,
                    "state_dir": str(sd)}

    # Support desk (2.1.0): a TERMINAL failure lodges one ticket
    # with the failure's data and installs the hook that will
    # register this agent on its own once Phoenix ships the fix.
    # Once per run_setup, never on success, never masking the
    # real failure (the exception still propagates; the report
    # still returns ok=False).
    _support_state = {"done": False}

    def _auto_support(step: str, error: str, detail: str = ""):
        if not auto_support or _support_state["done"]:
            return
        _support_state["done"] = True
        try:
            from . import support as _support_mod
            res = _support_mod.maybe_auto_lodge(
                uname, sd, step=step, error=error, detail=detail,
                hook_grant=grant)
        except Exception:
            res = None
        if res and res.get("ticket_id"):
            report["support"] = {
                "ticket_id": res["ticket_id"],
                "hook": res.get("hook"),
                "note": (f"support ticket {res['ticket_id']} "
                         f"lodged with Phoenix; a hook is "
                         f"watching it")}

    # 1 — network first.
    report["network"] = choose_network(sd)
    if not report["network"]["proven"]:
        report["ok"] = False
        report["error"] = (
            "no egress candidate answered the login-challenge "
            "roundtrip — fix this machine's network first; "
            "registration was not attempted")
        _auto_support("network", report["error"])
        return report

    # 2 — register via the hardened first-contact suite. The
    # start rides out weather the way the daemon does: a
    # transient Edge refusal (the 405 class — a redirect or
    # URL-shape fault on the host, a rate window, a proxy
    # rotation landing mid-ceremony) is a ConnectionError here,
    # and the daemon's law is that such refusals are retried,
    # never treated as identity verdicts. Setup retries
    # boundedly (5 attempts, backoff) and reports honestly if
    # the weather never breaks; a key_auth_failed still runs
    # the first-contact suite inside start() itself, and a
    # RegistrationFailed (the one permanent refusal) is never
    # retried.
    from .client import InstanceCollision, RegistrationFailed
    agent = Agent(uname, state_dir=str(sd), designation=designation,
                  mode="manual")
    already: dict | None = None
    try:
        import asyncio as _aio
        last_exc: Exception | None = None
        for attempt in range(5):
            try:
                await agent.start()
                last_exc = None
                break
            except InstanceCollision as exc:
                # Already-registered fast path (2.2.3): a
                # collision with this identity's OWN live daemon
                # is not a failed registration — the daemon IS
                # the registration, holding the session this
                # setup was asked to create. Prove it with the
                # measured conjuncts (live holder, identity keys,
                # control-channel ping as this username, presence
                # online, directory-through-the-daemon finds me,
                # and a recovery key in the stored copies — the
                # same recovery conjunct setup's own ok requires);
                # only then does setup report success through the
                # running instance instead of starting a rival.
                # A collision whose proof stays unproven past the
                # attempt budget — a REAL rival, a wedged holder,
                # or a registered-but-keyless agent (the
                # self-collision rescue's documented state, healed
                # by operator rectification, never by pretending
                # a key exists) — is terminal then, and the
                # failure names the conjuncts.
                # The proof runs boundedly INSIDE the retry
                # loop: its conjuncts ride the platform's own
                # reads (a directory query through the daemon
                # takes as long as it takes — seconds to minutes
                # under this fleet's network weather), so a
                # single not-yet measurement is weather, not a
                # verdict: the loop re-proves on the next pass,
                # exactly as it rides out a ConnectionError. The
                # proof only becomes the failure when the attempt
                # budget is spent with it still unproven — and
                # then it names every conjunct, so the stranded
                # shape (registered-but-keyless included) reaches
                # the desk diagnosed, never as a bare collision.
                proof = await _prove_already_running(agent, sd, uname)
                report["already_running_check"] = proof
                if proof.get("proven"):
                    already = proof
                    last_exc = None
                    break
                if attempt + 1 < 5:
                    last_exc = exc
                    report.setdefault("start_retries", []).append(
                        f"attempt {attempt + 1}: collision proof "
                        f"not yet proven: {json.dumps({k: proof.get(k) for k in ('holder_alive', 'identity_present', 'presence_online', 'directory_finds_me', 'recovery_present')})}")
                    await _aio.sleep(min(30, 2 * (2 ** attempt)))
                    try:
                        await agent.close()
                    except Exception:
                        pass
                    continue
                raise InstanceCollision(
                    f"{exc} — already-running proof failed: "
                    f"{json.dumps({k: proof.get(k) for k in ('holder_alive', 'identity_present', 'presence_online', 'directory_finds_me', 'recovery_present')})}"
                ) from exc
            except RegistrationFailed:
                raise
            except ConnectionError as exc:
                last_exc = exc
                report.setdefault("start_retries", []).append(
                    f"attempt {attempt + 1}: {str(exc)[:160]}")
                await _aio.sleep(min(30, 2 * (2 ** attempt)))
                # A failed start can leave a half-open session;
                # close quietly before the next attempt.
                try:
                    await agent.close()
                except Exception:
                    pass
        if last_exc is not None:
            raise last_exc
        report["registered"] = True
        if already is not None:
            # Through the running instance (2.2.3): capabilities
            # and the grant are the DAEMON's to publish and to
            # ask — a rival process neither re-publishes nor
            # re-asks. The report carries what was measured
            # through the daemon, in the same fields the live
            # path fills, so the ok conjuncts below mean the
            # same thing on both paths.
            report["already_registered"] = True
            report["already_running"] = True
            report["running_instance"] = {
                "pid": (already.get("holder") or {}).get("pid"),
                "since": (already.get("holder") or {}).get("since")}
            report["recovery_file"] = already.get("recovery_file")
            report["recovery_present"] = bool(
                already.get("recovery_present"))
            report["capabilities"] = already.get("capabilities") or []
            report["grant"] = {"status": "already_running",
                               "detail": already.get("grant")}
            report["verify"] = {
                "presence": already.get("presence"),
                "presence_online": bool(already.get("presence_online")),
                "directory_finds_me": bool(
                    already.get("directory_finds_me")),
                "directory_matches": already.get(
                    "directory_matches") or [],
                "via": "running instance (control channel + doorbell)"}
        else:
            report["recovery_file"] = agent.recovery_file
            report["recovery_present"] = bool(
                agent.recovery_file
                and Path(agent.recovery_file).exists())

            # 4 — capabilities, probed then published.
            caps = _probe_capabilities(sd, report["network"])
            try:
                await agent.update_capabilities(caps)
                report["capabilities"] = caps
            except Exception as exc:
                report["capabilities"] = caps
                report["capabilities_error"] = str(exc)[:200]

            # 5 — the one-time full admin grant, asked agent-side.
            if grant == "skip":
                report["grant"] = {"status": "skipped"}
            else:
                req = await agent.request_permission(GRANT_REASON)
                report["grant"] = {"status": "asked",
                                   "request": req.get("id")
                                   or (req if isinstance(req, dict)
                                       else None)}
                if grant == "allow":
                    out = await agent.allow_permission("setup-owner")
                    report["grant"] = {
                        "status": "allowed" if isinstance(out, dict)
                        and out.get("grant") else "allow_failed",
                        "detail": out}
                elif grant == "decline":
                    # The owner's no, recorded the same agent-side
                    # way: the pending request is cleared locally
                    # and the report carries the outcome. The agent
                    # can still message; it cannot act via
                    # connectors.
                    agent._clear_permission_request()
                    report["grant"] = {"status": "declined"}

            # 6a — self-verification while this instance is live:
            # presence on the beat + directory finds me, any case.
            verify: dict = {}
            try:
                import asyncio as _asyncio
                presence = await _asyncio.to_thread(
                    agent._v2.doorbell.read_presence, uname)
                verify["presence"] = presence
                verify["presence_online"] = bool(
                    presence and presence.get("state") == "online")
            except Exception as exc:
                verify["presence_error"] = str(exc)[:200]
            try:
                found = await agent.directory(query=uname.capitalize())
                verify["directory_finds_me"] = \
                    uname in _directory_names(found)
                verify["directory_matches"] = _directory_names(found)
            except Exception as exc:
                verify["directory_error"] = str(exc)[:200]
            report["verify"] = verify
    except InstanceCollision as exc:
        # A collision that outlasted the proof budget is NOT a
        # first-contact failure: the account demonstrably exists
        # (its daemon holds the lock) — it is a collision with a
        # measured diagnosis attached (the proof's conjuncts are
        # in the message and in the report). Lodging it as a
        # registration failure would tell the desk "this agent
        # could not register" about an agent that IS registered
        # — the exact falsehood the 2.2.3 fast path exists to
        # kill. The CLI report carries the diagnosis; no ticket,
        # no hook.
        if report.get("already_running_check"):
            exc.check = report["already_running_check"]  # type: ignore[attr-defined]
        raise
    except (RegistrationFailed, ConnectionError) as exc:
        # Terminal first-contact failure: lodge once with the
        # failure data, keep the ticket on the exception so the
        # CLI can show it, then let the failure speak for itself.
        _auto_support("first-contact", str(exc)[:1000])
        if report.get("support"):
            exc.support = report["support"]  # type: ignore[attr-defined]
        raise
    finally:
        await agent.close()

    # 3 — supervision (after close: the supervisor owns the
    # daemon from here; two instances never fight over the lock).
    # Already-running path (2.2.3): the instance is ALREADY up —
    # installing/starting a service here would fight it for its
    # own lock. Supervision is whatever already runs it; the
    # report says so instead of pretending an install happened.
    if already is not None:
        report["service"] = {
            "skipped": "instance already running",
            "pid": report.get("running_instance", {}).get("pid")}
    elif install_service:
        proc = subprocess.run(
            [sys.executable, "-m", "agentlink", "service", "install",
             "--username", uname, "--user", "--state-dir", str(sd)],
            capture_output=True, text=True, timeout=180)
        try:
            report["service"] = json.loads(proc.stdout)
        except Exception:
            report["service"] = {"stdout": proc.stdout[-400:],
                                 "stderr": proc.stderr[-400:],
                                 "returncode": proc.returncode}
    report["ok"] = bool(
        report.get("registered")
        and report.get("recovery_present")
        and report.get("verify", {}).get("presence_online")
        and report.get("verify", {}).get("directory_finds_me"))
    if not report["ok"]:
        # Visibility (2.2.3): the lodged error names EVERY ok
        # conjunct — registered and recovery_present included.
        # The old string dumped only the verify dict, so a
        # failure whose real cause was a missing recovery file
        # arrived at the desk wearing all-green verify data and
        # could not be diagnosed from the ticket (the @lean /
        # @agent-2eb7 verify tickets, 2026-11-07).
        _auto_support(
            "verify",
            "setup completed registration but self-verification "
            "failed: "
            f"{json.dumps({'registered': report.get('registered'), 'recovery_present': report.get('recovery_present'), 'recovery_file': report.get('recovery_file'), 'verify': report.get('verify', {})})[:900]}")
    return report
