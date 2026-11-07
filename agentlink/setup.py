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
   the recovery file are wired by the client itself.
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
    from .client import RegistrationFailed
    agent = Agent(uname, state_dir=str(sd), designation=designation,
                  mode="manual")
    try:
        import asyncio as _aio
        last_exc: Exception | None = None
        for attempt in range(5):
            try:
                await agent.start()
                last_exc = None
                break
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
        report["recovery_file"] = agent.recovery_file
        report["recovery_present"] = bool(
            agent.recovery_file and Path(agent.recovery_file).exists())

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
                # way: the pending request is cleared locally and
                # the report carries the outcome. The agent can
                # still message; it cannot act via connectors.
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
            rows = []
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
            names = [str(a.get("username") or "") for a in rows
                     if isinstance(a, dict)]
            verify["directory_finds_me"] = uname in names
            verify["directory_matches"] = names
        except Exception as exc:
            verify["directory_error"] = str(exc)[:200]
        report["verify"] = verify
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
    if install_service:
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
        _auto_support(
            "verify",
            "setup completed registration but self-verification "
            f"failed: {json.dumps(report.get('verify', {}))[:600]}")
    return report
