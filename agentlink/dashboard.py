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

from .timing import DEVICE_TRUST_SECONDS

SESSION_TTL = DEVICE_TRUST_SECONDS  # 7 days — see agentlink/timing.py
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
        self._dirty = False
        self._builder: threading.Thread | None = None
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
        # Coalesced snapshot builds (production fix, 2026-11-02): the
        # snapshot is a full store scan. Building it synchronously in
        # the caller's thread — often the relay event loop, via
        # _log_activity — stalls agent traffic for the whole build on
        # a network-backed store (hundreds of round trips). Builds now
        # run on a dedicated thread, at most once per second, only
        # when something changed; subscribers still get pushed fresh
        # snapshots, and /api/status still builds on demand.
        with self._lock:
            self._dirty = True
            if self._builder is None:
                self._builder = threading.Thread(
                    target=self._build_loop, daemon=True)
                self._builder.start()

    def _build_loop(self) -> None:
        while True:
            with self._lock:
                dirty = self._dirty
                self._dirty = False
            if dirty:
                try:
                    snapshot = json.dumps(self.relay._dashboard_data())
                except Exception:
                    snapshot = None
                if snapshot is not None:
                    with self._lock:
                        subs = list(self._subscribers)
                    for q in subs:
                        try:
                            q.put_nowait(snapshot)
                        except queue.Full:
                            pass
            time.sleep(1.0)

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
 body{font-family:system-ui,sans-serif;background:#fafafa;color:#111;margin:0}
 /* ---------- side drawer navigation (owner's Nova design rule) ---------- */
 #drawer{position:fixed;left:0;top:0;bottom:0;width:264px;background:#fff;
   border-right:1px solid #e7e7e7;z-index:40;display:flex;flex-direction:column;
   transform:translateX(0);transition:transform .32s cubic-bezier(.32,.72,.28,1);
   box-shadow:2px 0 14px rgba(0,0,0,.04)}
 #drawer.closed{transform:translateX(-105%);box-shadow:none}
 .brand{display:flex;gap:12px;align-items:center;padding:20px 18px 14px}
 .mark{width:40px;height:40px;border-radius:11px;background:#111;color:#fff;
   display:flex;align-items:center;justify-content:center;font-size:20px}
 .bname{font-size:17px;font-weight:700;line-height:1.1}
 .bsub{color:#777;font-size:12px}
 .conn{display:flex;gap:8px;align-items:center;margin:0 18px;padding:9px 11px;
   background:#f6f6f6;border:1px solid #eee;border-radius:10px;font-size:12px}
 .serverline{margin:8px 18px 2px;color:#888;font-size:11px;word-break:break-all}
 #drawer nav{padding:10px 10px 6px;overflow-y:auto;flex:1}
 .navgroup{color:#999;font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   margin:14px 8px 5px}
 .navitem{display:block;padding:8px 10px;border-radius:9px;color:#222;font-size:14px;
   cursor:pointer;text-decoration:none;transition:background .18s,color .18s}
 .navitem:hover{background:#f3f3f3}
 .navitem.active{background:#111;color:#fff}
 .drawerfoot{padding:14px 18px;border-top:1px solid #eee}
 .drawerfoot .session{color:#999;font-size:11.5px;margin-top:9px;line-height:1.5}
 #navtoggle{position:fixed;left:14px;bottom:14px;z-index:50;width:44px;height:44px;
   border-radius:50%;background:#111;color:#fff;border:0;font-size:18px;cursor:pointer;
   box-shadow:0 6px 18px rgba(0,0,0,.25)}
 #backdrop{position:fixed;inset:0;background:rgba(0,0,0,.32);z-index:35;opacity:0;
   pointer-events:none;transition:opacity .3s}
 #backdrop.show{opacity:1;pointer-events:auto}
 main{margin-left:264px;padding:24px;transition:margin .32s cubic-bezier(.32,.72,.28,1)}
 body.nav-closed main{margin-left:0}
 @media (max-width:900px){ main{margin-left:0;padding:16px} }
 /* ---------- animation system ---------- */
 @keyframes livePulse{0%{box-shadow:0 0 0 0 rgba(10,125,44,.45)}
   70%{box-shadow:0 0 0 8px rgba(10,125,44,0)}100%{box-shadow:0 0 0 0 rgba(10,125,44,0)}}
 @keyframes riseIn{from{opacity:0;transform:translateY(7px)}
   to{opacity:1;transform:translateY(0)}}
 @keyframes dotPulse{0%{transform:scale(1)}50%{transform:scale(1.25)}100%{transform:scale(1)}}
 .live-dot{width:9px;height:9px;border-radius:50%;background:#0a7d2c;flex:none;
   animation:livePulse 1.6s ease-out infinite}
 .live-dot.down{background:#b00020;animation:none}
 .enter{animation:riseIn .38s ease both}
 .dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;
   background:#bbb;transition:background .3s}
 .dot.on{background:#0a7d2c;animation:dotPulse 2.2s ease-in-out infinite}
 section.card{scroll-margin-top:14px}
 @media (prefers-reduced-motion: reduce){
   *,*::before,*::after{animation:none!important;transition:none!important} }
 /* ---------- classical cards & tables (kept from v1.0) ---------- */
 header h1{font-size:22px;margin:0}
 .sub{color:#666;margin:4px 0 20px;font-size:13.5px;line-height:1.55}
 .card{background:#fff;border:1px solid #e7e7e7;border-radius:14px;padding:18px;
   box-shadow:0 2px 10px rgba(0,0,0,.03);margin-bottom:16px;
   transition:box-shadow .25s}
 .card:hover{box-shadow:0 4px 18px rgba(0,0,0,.06)}
 .card h2{font-size:15px;margin:0 0 12px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 td,th{padding:5px 6px;border-bottom:1px solid #f2f2f2;text-align:left;vertical-align:top}
 .on{color:#0a7d2c;font-weight:600}.off{color:#999}
 .pill{display:inline-block;padding:1px 9px;border-radius:99px;background:#f0f0f0;font-size:12px}
 .pill.urgent{background:#b00020;color:#fff;font-weight:700}
 .pill.high{background:#ffecb3}
 .pill.claimed{background:#fff3e0;color:#a35b00;border:1px solid #f0c27a}
 .pill.verified{background:#e6f4ea;color:#0a7d2c;border:1px solid #9fd3ab}
 .pill.trust{background:#eef2ff;color:#243b8b}
 .pill.gate{background:#eef2ff;color:#243b8b;border:1px solid #b9c6f5}
 .pill.awaiting{background:#fff3e0;color:#8a5a00;border:1px solid #e0a93e;font-weight:700}
 .bar{background:#eee;border-radius:99px;height:8px;min-width:90px}
 .bar>i{display:block;height:8px;border-radius:99px;background:#0a7d2c;transition:width .4s}
 tr.urgent-row{background:#fff1f1}
 .conv{cursor:pointer}.conv:hover{background:#f7f7f7}
 .hidden{display:none}
 button{background:none;border:1px solid #ddd;border-radius:8px;padding:6px 12px;cursor:pointer}
 input{padding:7px;border:1px solid #ddd;border-radius:8px}
 footer{color:#999;font-size:12px;margin-top:20px}
 .alert{background:#fff8e1;border:1px solid #f0c27a;border-radius:10px;padding:8px 12px;margin-bottom:8px;font-size:13px}
 .alert.res{opacity:.55}
 small{color:#777}
 .stats{display:flex;flex-wrap:wrap;gap:9px}
 .stat{background:#f7f7f7;border:1px solid #eee;border-radius:11px;padding:9px 13px;font-size:13px}
 .stat b{font-size:16px}
 .parts{font-size:12.5px;color:#444;margin:2px 0 8px;line-height:1.7}
 .part{background:#f6f6f6;border:1px solid #eee;border-radius:99px;padding:1px 9px;
   display:inline-block;margin:1px 2px}
</style></head><body>
<button id="navtoggle" type="button" aria-label="Toggle navigation">☰</button>
<div id="backdrop"></div>
<aside id="drawer">
 <div class="brand"><div class="mark">◆</div>
  <div><div class="bname">AgentLink</div><div class="bsub">Live Dashboard</div></div></div>
 <div class="conn"><span class="live-dot" id="livedot"></span><span id="conntext">LIVE — connecting…</span></div>
 <div class="serverline" id="serverline"></div>
 <nav>
  <div class="navgroup">Monitor</div>
  <a class="navitem active" data-target="sec-overview">Overview</a>
  <a class="navitem" data-target="sec-agents">Agents</a>
  <a class="navitem" data-target="sec-convs">Conversations</a>
  <div class="navgroup">Work</div>
  <a class="navitem" data-target="sec-work">Work</a>
  <a class="navitem" data-target="sec-chains">Chains</a>
  <div class="navgroup">Files</div>
  <a class="navitem" data-target="sec-library">Library</a>
  <a class="navitem" data-target="sec-vault">Vault</a>
  <div class="navgroup">Live</div>
  <a class="navitem" data-target="sec-rooms">Voice Rooms</a>
  <a class="navitem" data-target="sec-activity">Alerts &amp; Activity</a>
 </nav>
 <div class="drawerfoot">
  <form method="post" action="/logout"><button type="submit">Log out (revoke device)</button></form>
  <div class="session">Trusted device session · expires after 7 days<br><span id="stamp"></span></div>
 </div>
</aside>
<main id="main">
 <section class="card" id="sec-overview">
  <header><h1>AgentLink — Live Dashboard</h1></header>
  <div class="sub"><span class="live-dot" style="display:inline-block;vertical-align:middle"></span>
  <b>LIVE</b> — server-pushed in real time.
  Monitor only: this dashboard can never send, assign or chat. Contents are
  end-to-end encrypted and can never appear here; you see envelope details,
  <span class="pill claimed">claimed</span> (agent-reported) vs
  <span class="pill verified">verified</span> (proof/heartbeat/hash-checked) —
  always separated. All deadlines render in Pacific Time only.
  Work behind an <span class="pill gate">🔒 approval gate</span> parks as
  <span class="pill awaiting">awaiting approval</span> after a proven delivery —
  the decision happens on the line, by the assigner or a group admin, never here.</div>
  <div class="stats" id="ovstats"></div>
 </section>
 <div id="alerts"></div>
 <section class="card" id="sec-agents"><h2>Agents — presence, activity, trust</h2>
   <table><tbody id="users"></tbody></table></section>
 <section class="card" id="sec-groups"><h2>Groups &amp; Channels</h2>
   <table><tbody id="groups"></tbody></table></section>
 <section class="card" id="sec-work"><h2>Work — progress, deadlines (PT), proofs</h2>
   <table><tbody id="work"></tbody></table></section>
 <section class="card" id="sec-chains"><h2>Chains</h2>
   <table><tbody id="chains"></tbody></table></section>
 <section class="card" id="sec-convs"><h2>Conversations — click for envelope drill-down</h2>
   <table><tbody id="convs"></tbody></table><div id="convdetail"></div></section>
 <section class="card" id="sec-library"><h2>Delivery Library (metadata)</h2>
   <table><tbody id="library"></tbody></table></section>
 <section class="card" id="sec-vault"><h2>Group Vault (metadata)</h2>
   <table><tbody id="vault"></tbody></table></section>
 <section class="card" id="sec-rooms"><h2>Voice Rooms — signalling only, media is WebRTC P2P</h2>
   <table><tbody id="rooms"></tbody></table>
   <div style="margin-top:10px">
     <input id="roomid" placeholder="room id" size="16">
     <button id="joinroom" type="button">Join room with mic</button>
     <button id="leaveroom" type="button">Leave</button>
     <div id="voicestatus"><small>Browser voice client: joins as an ephemeral
     browser peer (visible in room metadata). Agents join from their own
     WebRTC stack; the relay never carries audio.</small></div>
     <div id="audios"></div>
   </div></section>
 <section class="card" id="sec-activity"><h2>Activity — who is transmitting to whom</h2>
   <table><tbody id="act"></tbody></table></section>
 <footer>AgentLink dashboard · real-time via server push · metadata only, always.</footer>
</main>
<script>
const esc=s=>String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const ptFmt=new Intl.DateTimeFormat('en-US',{timeZone:'America/Los_Angeles',
  year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hour12:false});
function pt(ts){ if(!ts) return ''; const d=new Date(ts*1000);
  return ptFmt.format(d)+' PT'; }
function countdown(w){ if(!w.deadline) return '';
  const left=w.deadline-Math.floor(Date.now()/1000);
  if(w.status==='completed') return 'done';
  if(left<0) return '<b style="color:#b00020">overdue '+Math.floor(-left/60)+'m</b>';
  if(left<3600) return Math.floor(left/60)+'m left';
  return Math.floor(left/3600)+'h '+Math.floor(left%3600/60)+'m left'; }
/* ---- keyed list rendering: SSE snapshots diff against the live DOM;
   only NEW nodes animate in (riseIn), changed nodes update in place,
   order is corrected by node moves — no bare innerHTML swaps. ---- */
let booted=false;
function nodeFrom(html){ const t=document.createElement('template');
  t.innerHTML=html.trim(); return t.content.firstElementChild; }
function keyed(tbody, items, keyFn, htmlFn, bindFn){
  const seen=new Set(), counts={};
  const existing=new Map();
  [...tbody.children].forEach(n=>{ if(n.dataset&&n.dataset.k) existing.set(n.dataset.k,n); });
  let prev=null;
  for(const it of items){
    let k=keyFn(it); const base=k;
    if(seen.has(k)){ counts[base]=(counts[base]||1)+1; k=base+'#'+counts[base]; }
    seen.add(k);
    const html=htmlFn(it);
    let node=existing.get(k);
    if(node){ existing.delete(k);
      if(node._h!==html){ node.innerHTML=nodeFrom(html).innerHTML; node._h=html; if(bindFn) bindFn(node,it); } }
    else{ node=nodeFrom(html); node.dataset.k=k; node._h=html;
      if(booted) node.classList.add('enter');
      if(bindFn) bindFn(node,it); }
    if(prev){ if(prev.nextSibling!==node) tbody.insertBefore(node, prev.nextSibling); }
    else if(tbody.firstChild!==node) tbody.insertBefore(node, tbody.firstChild);
    prev=node;
  }
  existing.forEach(n=>n.remove());
}
let seenAct='', lastData=null, openConv='';
function notify(title, body){
  if(!('Notification' in window)) return;
  if(Notification.permission==='default') Notification.requestPermission();
  if(Notification.permission==='granted') new Notification(title,{body});
}
function senderBits(i){ let h='';
  if(i.sender_nickname) h+=' <small>“'+esc(i.sender_nickname)+'”</small>';
  if(i.sender_role) h+=' <span class="pill">'+esc(i.sender_role)+'</span>';
  if(i.sender_custom_role) h+=' <span class="pill">'+esc(i.sender_custom_role)+'</span>';
  return h; }
function render(d){
 lastData=d;
 document.getElementById('stamp').textContent='updated '+new Date().toLocaleTimeString();
 document.getElementById('serverline').textContent=d.server||'';
 document.getElementById('livedot').classList.remove('down');
 document.getElementById('conntext').textContent='LIVE — real-time push connected';
 const openAlerts=(d.alerts||[]).filter(a=>a.status==='open');
 document.getElementById('alerts').innerHTML=openAlerts.map(a=>
  `<div class="alert enter">⚠ <b>${esc(a.kind)}</b> — ${esc(a.subject)} <small>${esc(a.detail||'')} · ${pt(a.created_at)}</small></div>`).join('');
 const openWork=(d.work||[]).filter(w=>!['completed','covered'].includes(w.status));
 const awaiting=(d.work||[]).filter(w=>w.status==='awaiting_approval');
 document.getElementById('ovstats').innerHTML=
  `<span class="stat"><b>${(d.online||[]).length}</b> agents online</span>`+
  `<span class="stat"><b>${openWork.length}</b> work open</span>`+
  `<span class="stat"><b>${awaiting.length}</b> awaiting approval</span>`+
  `<span class="stat"><b>${(d.chains||[]).filter(c=>c.status==='running').length}</b> chains running</span>`+
  `<span class="stat"><b>${openAlerts.length}</b> alerts open</span>`;
 keyed(document.getElementById('users'), d.users||[], u=>u.username, u=>
  `<tr><td>@${esc(u.username)}<br><small>${esc((u.capabilities||[]).join(', '))}</small></td>
   <td class="${u.online?'on':'off'}"><span class="dot ${u.online?'on':''}"></span>${u.online?'online':'offline'}<br><small>${esc(u.activity_state||'')}</small></td>
   <td><span class="pill trust">trust ${u.trust_score}</span></td>
   <td>${u.reachability?esc(u.reachability):''}${u.home&&u.riding&&u.home!==u.riding?'<br><small>home: '+esc(u.home)+'</small>':''}</td></tr>`);
 keyed(document.getElementById('groups'),
  [...(d.groups||[]).map(g=>({k:'g:'+g.id,html:`<tr><td>${esc(g.name)}</td><td><span class="pill">${g.member_count} members</span></td><td>by @${esc(g.creator)}</td></tr>`})),
   ...(d.channels||[]).map(c=>({k:'c:'+c.id,html:`<tr><td>📣 ${esc(c.name)}</td><td><span class="pill">${c.member_count} subscribers</span></td><td>channel · by @${esc(c.creator)}</td></tr>`}))],
  x=>x.k, x=>x.html);
 keyed(document.getElementById('work'), d.work||[], w=>w.id, w=>
  `<tr class="${w.priority==='urgent'?'urgent-row':''}"><td>${esc(w.id)}<br><small>${pt(w.updated_at)}</small></td>
   <td>@${esc(w.assigner)} → @${esc(w.assignee)}${w.group_id?'<br><small>'+esc(w.group_id)+'</small>':''}</td>
   <td>${w.status==='awaiting_approval'?'<span class="pill awaiting">⏳ awaiting approval</span>':'<span class="pill">'+esc(w.status)+'</span>'} ${w.priority==='urgent'?'<span class="pill urgent">URGENT</span>':''} ${w.require_approval?'<span class="pill gate">🔒 approval gate</span>':''}
   <div class="bar"><i style="width:${w.progress_percent||0}%"></i></div>
   <small>${w.progress_percent||0}% agent-reported</small>
   ${w.status==='awaiting_approval'?'<br><small>⏳ decision by @'+esc(w.assigner)+(w.group_id?' or a group admin':'')+' — on the line, not here</small>':''}
   ${w.deadline?'<br><small>⏰ '+pt(w.deadline)+' · '+countdown(w)+'</small>':''}
   ${w.proof_verified?'<br><span class="pill verified">signed proof ✓</span>':''}</td></tr>`);
 keyed(document.getElementById('chains'), d.chains||[], c=>c.id, c=>
  `<tr><td>${esc(c.id)}<br><small>by @${esc(c.creator)}</small></td>
   <td><span class="pill">${esc(c.status)}</span></td>
   <td>${(c.steps||[]).map(s=>`<div>${s.position}. ${esc(s.target||s.target_type)} — ${esc(s.work_status||s.status)} ${s.progress_percent? '('+s.progress_percent+'%)':''}</div>`).join('')}</td></tr>`);
 keyed(document.getElementById('convs'), d.conversations||[], c=>c.key, c=>
  `<tr class="conv" data-key="${esc(c.key)}"><td>${c.group_id?'group '+esc(c.group_id)+' <small>· '+(c.participants||[]).length+' participants</small>':'@'+(c.participants||[]).join(' ↔ @')}</td><td>${c.items.length} items</td><td><small>${c.items.length?pt(c.items[c.items.length-1].ts):''}</small></td></tr>`,
  (node,c)=>{ node.onclick=()=>{ openConv=c.key; showConv(); }; });
 showConv();
 keyed(document.getElementById('library'), d.library||[], e=>e.id, e=>
  `<tr><td>${esc(e.filename)}<br><small>${esc(e.sha256).slice(0,12)}… · ${e.size} B</small></td><td>@${esc(e.sender)} → @${esc(e.to_user)}</td><td><small>${pt(e.ts)}</small></td></tr>`);
 keyed(document.getElementById('vault'), d.vault||[], v=>v.id, v=>
  `<tr><td>${v.pinned?'📌 ':''}${esc(v.name)}<br><small>${esc(v.sha256).slice(0,12)}… · ${v.size} B</small></td><td>${esc(v.group_id)}</td><td><small>by @${esc(v.added_by)}</small></td></tr>`);
 keyed(document.getElementById('rooms'), d.rooms||[], r=>r.id, r=>
  `<tr><td>${esc(r.id)}</td><td>${esc(r.group_id)}</td><td>${(r.participants||[]).map(p=>'@'+esc(p)).join(', ')}</td></tr>`);
 keyed(document.getElementById('act'), d.activity||[],
  a=>[a.ts,a.kind,a.from,a.to||'',a.work_id||'',a.status||''].join('|'), a=>
  `<tr class="${a.priority==='urgent'?'urgent-row':''}"><td><small>${pt(a.ts)}</small></td><td>${esc(a.kind)} <span class="pill ${a.evidence}">${a.evidence}</span>${a.priority==='urgent'?' <span class="pill urgent">URGENT</span>':''}</td><td>@${esc(a.from)}${senderBits(a)}${a.to?' → @'+esc(a.to):''}${a.group_id?' in '+esc(a.group_id):''}${a.status?' · '+esc(a.status):''}</td></tr>`);
 booted=true;
 const top=(d.activity||[])[0];
 if(top){ const sig=top.ts+'|'+top.kind+'|'+top.from+'|'+(top.to||'');
   if(seenAct && sig!==seenAct && (top.kind.startsWith('work_')||top.kind==='online'||top.kind==='alert'))
     notify('AgentLink: '+top.kind.replaceAll('_',' '),
            '@'+top.from+(top.to?' → @'+top.to:'')+(top.status?' ('+top.status+')':''));
   seenAct=sig; }
}
function showConv(){
 const el=document.getElementById('convdetail');
 if(!openConv||!lastData){ el.innerHTML=''; return; }
 const c=(lastData.conversations||[]).find(x=>x.key===openConv);
 if(!c){ el.innerHTML=''; return; }
 let head='';
 if(c.group_id){
   head='<div class="parts"><b>Participants</b> '+(c.participants||[]).map(p=>
     `<span class="part">@${esc(p.username)}${p.nickname?' “'+esc(p.nickname)+'”':''}${p.role?' · '+esc(p.role):''}${p.custom_role?' · '+esc(p.custom_role):''}</span>`).join(' ')+'</div>';
 } else {
   head='<div class="parts"><b>Direct conversation</b> — '+(c.participants||[]).map(p=>'@'+esc(p)).join(' ↔ ')+'</div>';
 }
 el.innerHTML='<h3 style="margin:12px 0 6px;font-size:14px">Envelope details — '+esc(c.key)+'</h3>'+head+'<table><tbody>'+
  c.items.map(i=>`<tr><td><small>${pt(i.ts)}</small></td><td>@${esc(i.from)}${senderBits(i)}${i.to?' → @'+esc(i.to):''}</td>
   <td>${esc(i.kind)}<br><small>id ${esc(i.id)} · ${i.size} B ct · mentions ${(i.mentions||[]).map(m=>'@'+esc(m)).join(' ')||'—'} · ${esc(i.priority)} · ${esc(i.status||'')}</small></td>
   <td><span class="pill ${i.evidence}">${i.evidence}</span></td></tr>`).join('')+'</tbody></table>';
}
/* ---- drawer behaviour ---- */
const drawer=document.getElementById('drawer'), backdrop=document.getElementById('backdrop');
function setDrawer(open){ drawer.classList.toggle('closed',!open);
  document.body.classList.toggle('nav-closed',!open);
  backdrop.classList.toggle('show', open&&window.innerWidth<900); }
document.getElementById('navtoggle').onclick=()=>setDrawer(drawer.classList.contains('closed'));
backdrop.onclick=()=>setDrawer(false);
if(window.innerWidth<900) setDrawer(false);
document.querySelectorAll('.navitem').forEach(a=>{ a.onclick=()=>{
  document.querySelectorAll('.navitem').forEach(x=>x.classList.remove('active'));
  a.classList.add('active');
  const t=document.getElementById(a.dataset.target);
  if(t) t.scrollIntoView({behavior:'smooth',block:'start'});
  if(window.innerWidth<900) setDrawer(false); }; });
const es=new EventSource('/api/stream');
es.onmessage=e=>render(JSON.parse(e.data));
es.onerror=()=>{ document.getElementById('livedot').classList.add('down');
  document.getElementById('conntext').textContent='RECONNECTING…'; };
if('Notification' in window && Notification.permission==='default')
  Notification.requestPermission();
/* ---- Browser voice client (WebRTC peer-to-peer; relay = signalling
   only). Media flows browser<->agent directly over DTLS-SRTP. ---- */
let vws=null, vstream=null, vroom='', vname='', vpeers={};
function vsend(o){ if(vws&&vws.readyState===1) vws.send(JSON.stringify(o)); }
function vstatus(t){ document.getElementById('voicestatus').innerHTML='<small>'+esc(t)+'</small>'; }
async function makePeer(other, offer){
  const pc=new RTCPeerConnection({iceServers:[{urls:'stun:stun.l.google.com:19302'}]});
  vpeers[other]=pc;
  vstream.getTracks().forEach(t=>pc.addTrack(t, vstream));
  pc.onicecandidate=e=>{ if(e.candidate) vsend({type:'room_signal', room_id:vroom, to:other, kind:'ice', payload:e.candidate, req_id:'v'+Math.random()}); };
  pc.ontrack=e=>{ const a=document.createElement('audio'); a.autoplay=true; a.srcObject=e.streams[0]; a.id='aud-'+other; document.getElementById('audios').appendChild(a); };
  if(offer){ const off=await pc.createOffer(); await pc.setLocalDescription(off);
    vsend({type:'room_signal', room_id:vroom, to:other, kind:'offer', payload:off, req_id:'v'+Math.random()}); }
  return pc;
}
document.getElementById('joinroom').onclick=async()=>{
  vroom=document.getElementById('roomid').value.trim(); if(!vroom) return;
  try{ vstream=await navigator.mediaDevices.getUserMedia({audio:true}); }
  catch(e){ vstatus('microphone unavailable: '+e.message); return; }
  const proto=location.protocol==='https:'?'wss:':'ws:';
  const data=lastData; const label=(data&&data.server)||'';
  const m=label.match(new RegExp('^(wss?)://([^/]+)'));
  const url=m?label:(proto+'//'+location.hostname+':8765');
  vws=new WebSocket(url);
  vws.onopen=()=>vsend({type:'hello', ephemeral:true, display_name:'dashboard browser'});
  vws.onmessage=async ev=>{
    const f=JSON.parse(ev.data);
    if(f.type==='welcome'){ vname=f.username;
      vsend({type:'room_join', room_id:vroom, req_id:'vj'});
      vstatus('joined room '+vroom+' as '+vname+' (ephemeral browser peer)'); }
    if(f.type==='result'&&f.data&&f.data.participants){
      for(const p of f.data.participants){ if(p!==vname&&!vpeers[p]) makePeer(p,true); } }
    if(f.type==='room_event'&&f.event==='joined'&&f.actor!==vname&&!vpeers[f.actor]) makePeer(f.actor,true);
    if(f.type==='room_signal'){ const pc=vpeers[f.from]||await makePeer(f.from,false);
      if(f.kind==='offer'){ await pc.setRemoteDescription(f.payload);
        const ans=await pc.createAnswer(); await pc.setLocalDescription(ans);
        vsend({type:'room_signal', room_id:vroom, to:f.from, kind:'answer', payload:ans, req_id:'v'+Math.random()}); }
      else if(f.kind==='answer'){ await pc.setRemoteDescription(f.payload); }
      else if(f.kind==='ice'){ try{ await pc.addIceCandidate(f.payload); }catch(e){} } }
  };
};
document.getElementById('leaveroom').onclick=()=>{
  if(vroom) vsend({type:'room_leave', room_id:vroom, req_id:'vl'});
  Object.values(vpeers).forEach(pc=>pc.close()); vpeers={};
  if(vstream) vstream.getTracks().forEach(t=>t.stop());
  if(vws) vws.close(); vstatus('left the room'); };
</script></body></html>
"""
