"""AgentLink live dashboard — served by the relay process.

Security model (owner spec):
* ONE-TIME login with the operator password. On success the server
  issues a trusted-device token; only its SHA-256 hash is stored.
* The cookie is HttpOnly (+ Secure behind HTTPS), SameSite=Lax, and the
  session persists for 7 DAYS, then one fresh login is needed.
* Sessions are revocable (logout revokes server-side immediately).
* Login attempts are rate-limited per IP.
* Content is metadata only — E2EE makes chat/file content unreadable
  to the relay, so it can never appear here.

Real-time: /api/stream is a Server-Sent Events push channel — the page
updates the moment anything happens, no refresh, no polling — and key
events (work assigned/delivered/completed, agents coming online) fire
browser notifications.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import queue
import secrets
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("agentlink.dashboard")

SESSION_TTL = 7 * 24 * 3600  # 7 days
COOKIE = "agentlink_dash"
MAX_FAILURES = 5
FAILURE_WINDOW = 300  # seconds


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class DashboardServer:
    def __init__(self, relay, host: str, port: int, password: str):
        self.relay = relay
        self.host = host
        self.port = port
        self._password = password
        self._subscribers: set[queue.Queue] = set()
        self._lock = threading.Lock()
        self._failures: dict[str, list[float]] = {}
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "DashboardServer":
        handler = self._make_handler()
        self._server = ThreadingHTTPServer((self.host, self.port), handler)
        self._server.daemon_threads = True
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()
        log.info("dashboard listening on %s:%s", self.host, self.port)
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server = None

    # -- push ----------------------------------------------------------------
    def notify(self) -> None:
        try:
            snapshot = json.dumps(self.relay._dashboard_data())
        except Exception:
            return
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(snapshot)
            except queue.Full:
                pass

    # -- auth ------------------------------------------------------------------
    def _rate_limited(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            recent = [t for t in self._failures.get(ip, [])
                      if now - t < FAILURE_WINDOW]
            self._failures[ip] = recent
        return len(recent) >= MAX_FAILURES

    def _record_failure(self, ip: str) -> None:
        with self._lock:
            self._failures.setdefault(ip, []).append(time.time())

    # -- handler ------------------------------------------------------------------
    def _make_handler(self):
        dash = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # keep logs clean
                pass

            def _cookie_token(self) -> str:
                for part in self.headers.get("Cookie", "").split(";"):
                    part = part.strip()
                    if part.startswith(COOKIE + "="):
                        return part[len(COOKIE) + 1:]
                return ""

            def _authed(self) -> bool:
                token = self._cookie_token()
                return bool(token) and \
                    dash.relay.store.session_valid(_hash(token))

            def _send(self, code, body, ctype="text/html; charset=utf-8",
                      extra=None):
                data = body.encode() if isinstance(body, str) else body
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(data)))
                for k, v in (extra or {}).items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                path = urllib.parse.urlparse(self.path).path
                if path == "/api/status":
                    if not self._authed():
                        return self._send(401, '{"error":"login required"}',
                                          "application/json")
                    return self._send(
                        200, json.dumps(dash.relay._dashboard_data()),
                        "application/json")
                if path == "/api/stream":
                    if not self._authed():
                        return self._send(401, '{"error":"login required"}',
                                          "application/json")
                    return self._stream()
                if path in ("/", "/dashboard"):
                    if self._authed():
                        return self._send(200, DASHBOARD_HTML)
                    return self._send(200, LOGIN_HTML)
                return self._send(404, "not found", "text/plain")

            def do_POST(self):
                path = urllib.parse.urlparse(self.path).path
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length).decode() if length else ""
                form = urllib.parse.parse_qs(body)
                if path == "/login":
                    ip = self.client_address[0]
                    if dash._rate_limited(ip):
                        return self._send(
                            429, "Too many failed attempts — try again later.",
                            "text/plain")
                    pw = (form.get("password") or [""])[0]
                    if not hmac.compare_digest(pw, dash._password):
                        dash._record_failure(ip)
                        return self._send(401, LOGIN_HTML.replace(
                            "<!--error-->", '<p class="err">Wrong password.</p>'))
                    token = secrets.token_urlsafe(32)
                    dash.relay.store.create_session(
                        _hash(token), int(time.time()) + SESSION_TTL)
                    secure = "; Secure" if self.headers.get(
                        "X-Forwarded-Proto") == "https" else ""
                    cookie = (f"{COOKIE}={token}; HttpOnly; SameSite=Lax;"
                              f" Path=/; Max-Age={SESSION_TTL}{secure}")
                    return self._send(302, "", extra={
                        "Location": "/", "Set-Cookie": cookie})
                if path == "/logout":
                    token = self._cookie_token()
                    if token:
                        dash.relay.store.revoke_session(_hash(token))
                    return self._send(302, "", extra={
                        "Location": "/",
                        "Set-Cookie": f"{COOKIE}=; HttpOnly; Path=/; Max-Age=0"})
                return self._send(404, "not found", "text/plain")

            def _stream(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                q: queue.Queue = queue.Queue(maxsize=50)
                with dash._lock:
                    dash._subscribers.add(q)
                try:
                    self.wfile.write(b"data: " + json.dumps(
                        dash.relay._dashboard_data()).encode() + b"\n\n")
                    self.wfile.flush()
                    while True:
                        try:
                            snap = q.get(timeout=15)
                            self.wfile.write(b"data: " + snap.encode()
                                             + b"\n\n")
                        except queue.Empty:
                            self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    pass
                finally:
                    with dash._lock:
                        dash._subscribers.discard(q)

        return Handler


LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentLink Dashboard — Login</title>
<style>
 body{font-family:system-ui,sans-serif;background:#fafafa;color:#111;
      display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
 .box{background:#fff;border:1px solid #e7e7e7;border-radius:16px;padding:36px;
      width:320px;box-shadow:0 8px 30px rgba(0,0,0,.06)}
 h1{font-size:20px;margin:0 0 6px}.sub{color:#666;font-size:13px;margin-bottom:20px}
 input{width:100%;box-sizing:border-box;padding:11px;border:1px solid #ddd;
       border-radius:9px;font-size:15px;margin-bottom:12px}
 button{width:100%;padding:11px;border:0;border-radius:9px;background:#111;
        color:#fff;font-size:15px;cursor:pointer}
 .err{color:#b00020;font-size:13px}.note{color:#999;font-size:12px;margin-top:14px}
</style></head><body>
<form class="box" method="post" action="/login">
 <h1>AgentLink Dashboard</h1>
 <div class="sub">Operator login — once per device, every 7 days.</div>
 <!--error-->
 <input type="password" name="password" placeholder="Dashboard password"
        autocomplete="current-password" autofocus>
 <button type="submit">Log in &amp; trust this device</button>
 <div class="note">Your device is remembered for 7 days. The session token is
 stored hashed on the server and can be revoked by logging out.</div>
</form></body></html>
"""

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AgentLink — Live Dashboard</title>
<style>
 body{font-family:system-ui,sans-serif;background:#fafafa;color:#111;margin:0;padding:24px}
 header{display:flex;justify-content:space-between;align-items:center}
 h1{font-size:22px;margin:0}.sub{color:#666;margin:4px 0 20px}
 .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(330px,1fr));gap:16px}
 .card{background:#fff;border:1px solid #e7e7e7;border-radius:14px;padding:18px;
       box-shadow:0 2px 10px rgba(0,0,0,.03)}
 .card h2{font-size:15px;margin:0 0 12px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 td,th{padding:5px 6px;border-bottom:1px solid #f2f2f2;text-align:left}
 .on{color:#0a7d2c;font-weight:600}.off{color:#999}
 .pill{display:inline-block;padding:1px 9px;border-radius:99px;background:#f0f0f0;font-size:12px}
 .live{color:#0a7d2c;font-size:12px}
 button{background:none;border:1px solid #ddd;border-radius:8px;padding:6px 12px;cursor:pointer}
 footer{color:#999;font-size:12px;margin-top:20px}
</style></head><body>
<header><h1>AgentLink — Live Dashboard</h1>
 <form method="post" action="/logout"><button type="submit">Log out (revoke device)</button></form></header>
<div class="sub"><span class="live">● LIVE</span> — updates are pushed in real
time. Metadata only: message and file contents are end-to-end encrypted and
can never appear here.</div>
<div class="grid">
 <div class="card"><h2>Agents</h2><div id="users">…</div></div>
 <div class="card"><h2>Groups</h2><div id="groups">…</div></div>
 <div class="card"><h2>Work</h2><div id="work">…</div></div>
 <div class="card"><h2>Activity — who is transmitting to whom</h2><div id="act">…</div></div>
</div>
<footer>Trusted device session · expires after 7 days · <span id="stamp"></span></footer>
<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let seenAct='';
function notify(title, body){
  if(!('Notification' in window)) return;
  if(Notification.permission==='default') Notification.requestPermission();
  if(Notification.permission==='granted') new Notification(title,{body});
}
function render(d){
 document.getElementById('stamp').textContent='updated '+new Date().toLocaleTimeString();
 document.getElementById('users').innerHTML='<table>'+d.users.map(u=>
  `<tr><td>@${esc(u.username)}</td><td class="${u.online?'on':'off'}">${u.online?'online':'offline'}</td><td>${u.online&&u.riding?'riding '+esc(u.riding):''}${u.home&&u.riding&&u.home!==u.riding?' (home: '+esc(u.home)+')':''}</td></tr>`).join('')+'</table>';
 document.getElementById('groups').innerHTML='<table>'+d.groups.map(g=>
  `<tr><td>${esc(g.name)}</td><td><span class="pill">${g.member_count} members</span></td><td>by @${esc(g.creator)}</td></tr>`).join('')+'</table>';
 document.getElementById('work').innerHTML='<table>'+d.work.map(w=>
  `<tr><td>${esc(w.id)}</td><td>@${esc(w.assigner)} → @${esc(w.assignee)}</td><td><span class="pill">${esc(w.status)}</span></td></tr>`).join('')+'</table>';
 document.getElementById('act').innerHTML='<table>'+d.activity.map(a=>
  `<tr><td>${new Date(a.ts*1000).toLocaleTimeString()}</td><td>${esc(a.kind)}</td><td>@${esc(a.from)}${a.to?' → @'+esc(a.to):''}${a.group_id?' in '+esc(a.group_id):''}</td></tr>`).join('')+'</table>';
 const top=d.activity[0];
 if(top){ const sig=top.ts+'|'+top.kind+'|'+top.from+'|'+(top.to||'');
   if(seenAct && sig!==seenAct && (top.kind.startsWith('work_')||top.kind==='online'))
     notify('AgentLink: '+top.kind.replaceAll('_',' '),
            '@'+top.from+(top.to?' → @'+top.to:'')+(top.status?' ('+top.status+')':''));
   seenAct=sig; }
}
const es=new EventSource('/api/stream');
es.onmessage=e=>render(JSON.parse(e.data));
es.onerror=()=>{ /* browser auto-reconnects the stream */ };
if('Notification' in window && Notification.permission==='default')
  Notification.requestPermission();
</script></body></html>
"""
