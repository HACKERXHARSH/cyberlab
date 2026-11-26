"""
Cyber Lab (Web Edition)
=======================
Runs the Cyber Lab dashboard in your browser at http://127.0.0.1:8000
Python 3.8+, standard library only. Works on Windows and Kali/Debian.

    python cyberlab_web.py            # serves on 127.0.0.1:8000
    python cyberlab_web.py 8080       # optional: another port

Security notes
- Binds to 127.0.0.1 only (not reachable from other machines).
- Rejects requests whose Host header isn't localhost (DNS-rebinding guard)
  and cross-site requests.
- Password analysis and generation happen in your browser; passwords are
  never sent to the server.
- The port auditor only ever connects to 127.0.0.1.
"""

import datetime
import ipaddress
import json
import re
import socket
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 8080

COMMON_LOCALHOST_PORTS = [
    (21, "FTP (File Transfer Protocol)"), (22, "SSH (Secure Shell)"),
    (25, "SMTP (Simple Mail Transfer)"), (53, "DNS (Domain Name Service)"),
    (80, "HTTP (World Wide Web)"), (135, "MS RPC (EPMAP)"),
    (139, "NetBIOS Session Service"), (443, "HTTPS (Secure Web HTTP)"),
    (445, "Microsoft SMB (File Sharing)"), (1433, "Microsoft SQL Server"),
    (3000, "Node / React Dev Server"), (3306, "MySQL Database Engine"),
    (3389, "RDP (Remote Desktop)"), (5000, "Flask / Python Dev Server"),
    (5432, "PostgreSQL Database Engine"), (6379, "Redis In-Memory Store"),
    (8000, "Python HTTP / Django Server"), (8080, "HTTP Proxy / Spring Boot"),
    (8443, "HTTPS Alternate / Tomcat"), (27017, "MongoDB NoSQL Database"),
]


# ----------------------------------------------------------------------------
# Security logic (same as the desktop edition)
# ----------------------------------------------------------------------------
def analyze_ip_address(ip_str):
    clean = ip_str.strip()
    if not clean:
        raise ValueError("Please provide an IP address.")
    try:
        ip = ipaddress.ip_address(clean)
    except ValueError:
        raise ValueError(f"Invalid IP address format: '{clean}'")
    cats = []
    if ip.is_private: cats.append("Private (RFC 1918 / Local Scope)")
    if ip.is_global: cats.append("Public / Globally Routable")
    if ip.is_loopback: cats.append("Loopback (Host Internal)")
    if ip.is_multicast: cats.append("Multicast Group")
    if ip.is_reserved: cats.append("Reserved (IETF Special)")
    if ip.is_link_local: cats.append("Link-Local (APIPA / FE80::)")
    if ip.is_unspecified: cats.append("Unspecified (0.0.0.0 / ::)")
    return {
        "ip": str(ip), "version": f"IPv{ip.version}",
        "is_private": ip.is_private, "is_global": ip.is_global,
        "classification": ", ".join(cats) or "Standard Unclassified",
        "reverse_pointer": ip.reverse_pointer,
        "integer_value": str(int(ip)), "hex_value": hex(int(ip)),
        "exploded": ip.exploded, "compressed": ip.compressed,
        "max_prefix_len": ip.max_prefixlen,
    }


def _clean_host(value):
    h = value.strip().lower()
    h = re.sub(r"^https?://", "", h)
    return h.split("/")[0].split(":")[0]


def query_dns_records(domain):
    host = _clean_host(domain)
    if not host:
        raise ValueError("Please provide a valid domain name or hostname.")
    t0 = time.perf_counter()
    v4, v6, aliases, canon = [], [], [], host
    try:
        for fam, _, _, _, sa in socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM):
            ip = sa[0]
            if fam == socket.AF_INET and ip not in v4: v4.append(ip)
            elif fam == socket.AF_INET6 and ip not in v6: v6.append(ip)
        try:
            name, aliases, ips = socket.gethostbyname_ex(host)
            for i in ips:
                if i not in v4: v4.append(i)
            canon = name or host
        except Exception:
            aliases = []
    except socket.gaierror as e:
        raise ConnectionError(f"DNS Resolution Failed: {e.strerror} (host unreachable or offline).")
    return {"domain": host, "canonical_name": canon, "ipv4": v4, "ipv6": v6,
            "aliases": aliases, "latency_ms": round((time.perf_counter() - t0) * 1000, 2)}


def inspect_ssl_certificate(hostname, port=443, timeout=6.0):
    host = _clean_host(hostname)
    if not host:
        raise ValueError("Please provide a valid hostname.")
    t0 = time.perf_counter()
    cert = cipher = None
    tls_version, reason = "Unknown", ""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert, cipher, tls_version = s.getpeercert(), s.cipher(), s.version()
    except ssl.SSLCertVerificationError as e:
        reason = getattr(e, "verify_message", None) or str(e)
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    cipher, tls_version = s.cipher(), s.version()
        except Exception:
            raise ConnectionError(f"Certificate Verification Error: {reason}")
    except socket.timeout:
        raise ConnectionError(f"Connection timed out: {host}:{port} exceeded {timeout}s.")
    except socket.gaierror as e:
        raise ConnectionError(f"Hostname resolution failed: {e.strerror}")
    except ConnectionRefusedError:
        raise ConnectionError(f"Connection refused: remote host rejected port {port}.")
    except Exception as e:
        raise ConnectionError(f"SSL inspection failed: {e}")

    latency = round((time.perf_counter() - t0) * 1000, 1)
    base = {"hostname": host, "port": port, "tls_version": tls_version,
            "cipher_suite": cipher[0] if cipher else "Unknown",
            "cipher_bits": cipher[2] if cipher else 0, "latency_ms": latency}
    if not cert:
        base.update({"status": "UNTRUSTED", "subject_cn": host,
                     "subject_org": f"Untrusted ({reason})", "issuer_cn": "Self-signed or unknown CA",
                     "issuer_org": "N/A", "valid_from": "Unknown", "valid_until": "Unknown",
                     "days_remaining": 0, "is_expired": False, "serial_number": "N/A",
                     "san_count": 0, "san_list": []})
        return base

    def flat(entries):
        return {k: v for rdn in entries for k, v in rdn}

    subj, iss = flat(cert.get("subject", [])), flat(cert.get("issuer", []))
    fmt = "%b %d %H:%M:%S %Y %Z"
    nb = datetime.datetime.strptime(cert["notBefore"], fmt).replace(tzinfo=datetime.timezone.utc)
    na = datetime.datetime.strptime(cert["notAfter"], fmt).replace(tzinfo=datetime.timezone.utc)
    now = datetime.datetime.now(datetime.timezone.utc)
    days = (na - now).days
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    status = "VALID"
    if now > na: status = "EXPIRED"
    elif now < nb: status = "NOT_YET_VALID"
    elif days <= 14: status = "EXPIRING_SOON"
    base.update({
        "status": status, "subject_cn": subj.get("commonName", "Unknown"),
        "subject_org": subj.get("organizationName", "N/A"),
        "issuer_cn": iss.get("commonName", "Unknown"),
        "issuer_org": iss.get("organizationName", "N/A"),
        "valid_from": nb.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "valid_until": na.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "days_remaining": days, "is_expired": now > na,
        "serial_number": cert.get("serialNumber", "N/A"),
        "san_count": len(sans), "san_list": sans[:15]})
    return base


def scan_single_localhost_port(port, timeout=0.2):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex(("127.0.0.1", port)) == 0


# ----------------------------------------------------------------------------
# HTTP server
# ----------------------------------------------------------------------------
ALLOWED_HOSTS = {f"127.0.0.1:{PORT}", f"localhost:{PORT}"}


class Handler(BaseHTTPRequestHandler):
    server_version = "CyberLab"

    def log_message(self, fmt, *args):
        pass

    def _send(self, code, body, ctype):
        data = body if isinstance(body, bytes) else body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy",
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; "
                         "script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
        self.end_headers()
        self.wfile.write(data)

    def _json(self, payload, code=200):
        self._send(code, json.dumps(payload), "application/json; charset=utf-8")

    def do_GET(self):
        if self.headers.get("Host", "") not in ALLOWED_HOSTS:
            return self._send(403, "Forbidden host", "text/plain")
        if self.headers.get("Sec-Fetch-Site", "same-origin") == "cross-site":
            return self._send(403, "Cross-site requests are blocked", "text/plain")

        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}

        if url.path == "/":
            return self._send(200, INDEX_HTML, "text/html; charset=utf-8")
        if url.path == "/api/portlist":
            return self._json({"ok": True, "data": COMMON_LOCALHOST_PORTS})
        if url.path == "/api/port":
            try:
                port = int(q.get("port", ""))
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                return self._json({"ok": False, "error": "Port must be 1-65535."}, 400)
            return self._json({"ok": True, "data": {"port": port, "open": scan_single_localhost_port(port, 0.18)}})

        handlers = {
            "/api/ip": lambda: analyze_ip_address(q.get("q", "")),
            "/api/dns": lambda: query_dns_records(q.get("q", "")),
            "/api/ssl": lambda: inspect_ssl_certificate(q.get("host", ""), int(q.get("port", "443"))),
        }
        fn = handlers.get(url.path)
        if not fn:
            return self._send(404, "Not found", "text/plain")
        try:
            self._json({"ok": True, "data": fn()})
        except (ValueError, ConnectionError) as e:
            self._json({"ok": False, "error": str(e)})
        except Exception as e:
            self._json({"ok": False, "error": f"Unexpected error: {e}"}, 500)


# ----------------------------------------------------------------------------
# Front-end (single page)
# ----------------------------------------------------------------------------
INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Cyber Lab</title>
<style>
:root{--bg:#000;--surface:#0f0f0f;--surface2:#171717;--border:#262626;--text:#ededed;--muted:#8c8c8c;--accent:#10b981;--on:#000;--ok:#10b981;--warn:#f59e0b;--bad:#ef4444;
--sans:system-ui,"Segoe UI",Roboto,Ubuntu,"Helvetica Neue",Arial,sans-serif;--mono:ui-monospace,"Cascadia Mono",Consolas,"DejaVu Sans Mono",monospace}
*{box-sizing:border-box}
html,body{height:100%;margin:0}
body{display:flex;background:var(--bg);color:var(--text);font:14px/1.5 var(--sans);-webkit-font-smoothing:antialiased}
aside{width:236px;flex:none;border-right:1px solid var(--border);padding:18px 12px;display:flex;flex-direction:column;gap:4px;overflow:auto}
.brand{display:flex;align-items:center;gap:10px;font-weight:650;font-size:16px;padding:2px 10px 18px}
.brand svg{color:var(--accent)}
nav{display:flex;flex-direction:column;gap:2px;flex:1}
nav a{display:flex;align-items:center;gap:12px;padding:9px 10px;border-radius:8px;color:var(--muted);text-decoration:none;position:relative;transition:background .15s,color .15s}
nav a:hover{background:var(--surface2);color:var(--text)}
nav a.on{background:color-mix(in srgb,var(--accent) 13%,transparent);color:var(--text);font-weight:600}
nav a.on::before{content:"";position:absolute;left:-12px;top:8px;bottom:8px;width:3px;border-radius:0 3px 3px 0;background:var(--accent)}
nav a.on svg{color:var(--accent)}
.side-foot{display:flex;align-items:center;gap:8px;color:var(--muted);font:12px var(--mono);padding:10px}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);flex:none}
main{flex:1;min-width:0;display:flex;flex-direction:column;height:100vh}
header{display:flex;align-items:center;gap:16px;padding:16px 32px;border-bottom:1px solid var(--border);flex-wrap:wrap}
header h1{margin:0;font-size:20px;font-weight:650}
header p{margin:2px 0 0;color:var(--muted);font-size:13px}
.sp{flex:1}
#content{flex:1;overflow:auto;padding:28px 32px 40px}
.wrap{max-width:1040px;margin:0 auto}
.view{display:none;flex-direction:column;gap:20px}.view.on{display:flex;animation:in .25s ease}
@keyframes in{from{opacity:0;transform:translateY(6px)}}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:22px}
h2{margin:0 0 4px;font-size:15px;font-weight:650}
h4{margin:18px 0 6px;font-size:13px;font-weight:650;color:var(--muted)}
.mu{color:var(--muted)}.hint{color:var(--muted);font-size:13px;margin:0 0 16px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.row+.row{margin-top:12px}
input{height:40px;background:var(--bg);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:0 12px;font:14px var(--mono);flex:1;min-width:140px;transition:border-color .15s,box-shadow .15s}
input:hover{border-color:color-mix(in srgb,var(--muted) 50%,var(--border))}
input:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px color-mix(in srgb,var(--accent) 22%,transparent)}
input.port{flex:0 0 96px;min-width:0}
input[type=color]{flex:none;min-width:0;width:44px;padding:3px;cursor:pointer}
.btn{height:40px;padding:0 16px;border-radius:8px;border:1px solid var(--border);background:var(--surface2);color:var(--text);font:600 13px var(--sans);cursor:pointer;transition:background .15s,border-color .15s,transform .1s}
.btn:hover{border-color:var(--muted)}.btn:active{transform:scale(.98)}
.btn.primary{background:var(--accent);border-color:var(--accent);color:var(--on)}
.btn.primary:hover{filter:brightness(1.1)}
.btn.sm{height:30px;padding:0 11px;font-size:12px}
.btn:disabled{opacity:.5;cursor:not-allowed}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.chips{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-top:14px}
.chip{height:28px;padding:0 12px;border-radius:999px;border:1px solid var(--border);background:transparent;color:var(--muted);font:12px var(--sans);cursor:pointer;transition:.15s}
.chip:hover{color:var(--text);border-color:var(--muted)}
.card-head{display:flex;align-items:center;gap:12px;margin-bottom:14px}
.card-head h2{margin:0}
.badge{display:inline-flex;align-items:center;gap:6px;height:24px;padding:0 10px;border-radius:999px;font-size:12px;font-weight:600;background:color-mix(in srgb,var(--c,var(--muted)) 16%,transparent);color:var(--c,var(--muted))}
.badge::before{content:"";width:6px;height:6px;border-radius:50%;background:currentColor}
.ok{--c:var(--ok)}.warn{--c:var(--warn)}.bad{--c:var(--bad)}
.kv{display:grid;grid-template-columns:180px 1fr;margin:0;border-top:1px solid var(--border)}
.kv:empty{display:none}
.kv dt,.kv dd{margin:0;padding:9px 0;border-bottom:1px solid var(--border)}
.kv dt{color:var(--muted)}
.kv dd{font-family:var(--mono);font-size:13px;word-break:break-all}
.res-top{margin-bottom:14px}
.empty{color:var(--muted);margin:0;padding:28px 0;text-align:center}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:16px}
.stat .mu{font-size:13px}.stat b{display:block;font-size:22px;font-weight:650;margin:6px 0 2px}
.tools{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:16px}
.tool{display:flex;gap:14px;align-items:flex-start;cursor:pointer;transition:border-color .15s,background .15s}
.tool:hover{border-color:var(--accent);background:var(--surface2)}
.tool svg{color:var(--accent);flex:none;margin-top:2px}
.tool b{display:block}.tool span{color:var(--muted);font-size:13px}
.log{font:12.5px/1.7 var(--mono);color:var(--muted);max-height:180px;overflow:auto}
.log div b{color:var(--text);font-weight:400}
.meter{height:8px;border-radius:8px;background:var(--surface2);overflow:hidden;flex:1;min-width:160px}
.meter i{display:block;height:100%;width:0;border-radius:8px;background:var(--c,var(--accent));transition:width .3s ease,background .3s}
.status{font-weight:650;min-width:130px;text-align:right}
.two{display:grid;grid-template-columns:1fr 1fr;gap:20px}
.checks{list-style:none;margin:0;padding:0;display:grid;gap:2px}
.checks li{display:flex;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);color:var(--muted)}
.checks li::before{content:"–";width:16px;text-align:center}
.checks li.ok{color:var(--text)}.checks li.ok::before{content:"✓";color:var(--ok);font-weight:700}
.tips{margin:14px 0 0;padding-left:18px;color:var(--muted)}.tips li{margin:3px 0}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;color:var(--muted);font-weight:500;padding:8px 10px;border-bottom:1px solid var(--border)}
td{padding:9px 10px;border-bottom:1px solid var(--border)}
td.n{font-family:var(--mono)}
tr.open td{background:color-mix(in srgb,var(--ok) 7%,transparent)}
.spin{width:16px;height:16px;border-radius:50%;border:2px solid var(--border);border-top-color:var(--accent);animation:sp .7s linear infinite;display:none}
.spin.on{display:inline-block}@keyframes sp{to{transform:rotate(360deg)}}
.themes{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:12px}
.tile{border:1px solid var(--border);border-radius:10px;padding:12px;cursor:pointer;transition:border-color .15s}
.tile:hover{border-color:var(--muted)}.tile.sel{border-color:var(--accent);box-shadow:0 0 0 1px var(--accent)}
.tile .pv{height:46px;border-radius:6px;margin-bottom:10px;display:flex;gap:4px;padding:6px;border:1px solid rgba(128,128,128,.25)}
.tile .pv i{flex:1;border-radius:4px}
.sw{width:32px;height:32px;border-radius:50%;border:2px solid transparent;cursor:pointer;box-shadow:inset 0 0 0 2px var(--surface);transition:transform .12s}
.sw:hover{transform:scale(1.1)}.sw.sel{border-color:var(--text)}
@media(max-width:860px){body{flex-direction:column}aside{width:100%;flex-direction:row;border-right:0;border-bottom:1px solid var(--border);padding:8px}
 nav{flex-direction:row}.brand,.side-foot,nav a span{display:none}nav a.on::before{display:none}main{height:auto;flex:1;min-height:0}.two{grid-template-columns:1fr}.kv{grid-template-columns:120px 1fr}#content,header{padding:18px}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
</style>
</head>
<body>
<aside>
  <div class="brand"><svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/></svg>Cyber Lab</div>
  <nav id="nav"></nav>
  <div class="side-foot"><i class="dot"></i><span id="host">127.0.0.1</span></div>
</aside>
<main>
  <header>
    <div><h1 id="ttl"></h1><p id="sub"></p></div>
    <div class="sp"></div>
    <input id="jump" placeholder="Jump to… (e.g. ssl)" style="flex:0 1 200px;font-family:var(--sans)">
    <button class="btn" id="ldBtn">Light / dark</button>
  </header>
  <div id="content"><div class="wrap">

  <section class="view" id="v-overview">
    <div class="stats">
      <div class="card stat"><span class="mu">Tools</span><b>5 modules</b><span class="mu">Available offline</span></div>
      <div class="card stat"><span class="mu">Passwords</span><b>Browser only</b><span class="mu">Never sent to the server</span></div>
      <div class="card stat"><span class="mu">Port audit scope</span><b>127.0.0.1</b><span class="mu">External scanning disabled</span></div>
      <div class="card stat"><span class="mu">Served from</span><b id="origin"></b><span class="mu">Loopback interface only</span></div>
    </div>
    <div class="tools" id="tools"></div>
    <div class="card"><div class="card-head"><h2>Activity</h2><div class="sp"></div><button class="btn sm" id="clrLog">Clear</button></div><div class="log" id="log"></div></div>
  </section>

  <section class="view" id="v-password">
    <div class="card">
      <h2>Check a password</h2><p class="hint">Analysis runs in this tab. Nothing is stored or transmitted.</p>
      <div class="row"><input type="password" id="pw" autocomplete="off" spellcheck="false" placeholder="Type or generate a password"><button class="btn" id="pwShow">Show</button><button class="btn primary" id="pwGen">Generate</button><button class="btn" id="pwClr">Clear</button></div>
      <div class="row"><div class="meter"><i id="pwBar"></i></div><div class="status" id="pwStat">No password</div></div>
    </div>
    <div class="two">
      <div class="card"><h2>Requirements</h2><p class="hint">Checked live as you type.</p><ul class="checks" id="chk"></ul></div>
      <div class="card"><div class="card-head"><h2>Analysis</h2><div class="sp"></div><button class="btn sm" data-copy="pwOut">Copy</button></div><div id="pwOut"></div></div>
    </div>
  </section>

  <section class="view" id="v-ip">
    <div class="card"><h2>Check an IP address</h2><p class="hint">IPv4 or IPv6. Validated locally with no external lookups.</p>
      <div class="row"><input id="ipIn" value="8.8.8.8" placeholder="e.g. 192.168.1.1 or ::1"><button class="btn primary" id="ipGo">Analyze</button><button class="btn" id="ipClr">Clear</button></div>
      <div class="chips" id="ipChips"></div></div>
    <div class="card"><div class="card-head"><h2>Result</h2><div class="sp"></div><button class="btn sm" data-copy="ipOut">Copy</button></div><div id="ipOut"></div></div>
  </section>

  <section class="view" id="v-dns">
    <div class="card"><h2>Resolve a hostname</h2><p class="hint">Returns the IPv4 and IPv6 addresses and the lookup time.</p>
      <div class="row"><input id="dnsIn" value="google.com" placeholder="example.com"><button class="btn primary" id="dnsGo">Resolve</button><button class="btn" id="dnsClr">Clear</button></div>
      <div class="chips" id="dnsChips"></div></div>
    <div class="card"><div class="card-head"><h2>Result</h2><span class="spin" id="dnsSp"></span><div class="sp"></div><button class="btn sm" data-copy="dnsOut">Copy</button></div><div id="dnsOut"></div></div>
  </section>

  <section class="view" id="v-ssl">
    <div class="card"><h2>Inspect a certificate</h2><p class="hint">Connects to the host, then reports validity, issuer, cipher and alternative names.</p>
      <div class="row"><input id="sslHost" value="github.com" placeholder="example.com"><input id="sslPort" class="port" value="443" inputmode="numeric" aria-label="Port"><button class="btn primary" id="sslGo">Inspect</button><button class="btn" id="sslClr">Clear</button></div>
      <div class="chips" id="sslChips"></div></div>
    <div class="card"><div class="card-head"><h2>Result</h2><span class="spin" id="sslSp"></span><div class="sp"></div><button class="btn sm" data-copy="sslOut">Copy</button></div><div id="sslOut"></div></div>
  </section>

  <section class="view" id="v-ports">
    <div class="card"><h2>Audit local ports</h2><p class="hint">Checks 20 common ports on 127.0.0.1 only. Other hosts cannot be scanned.</p>
      <div class="row"><button class="btn primary" id="pScan">Start audit</button><button class="btn" id="pStop" disabled>Stop</button><button class="btn" id="pClr">Clear</button></div>
      <div class="row"><div class="meter"><i id="pBar"></i></div><div class="status mu" id="pSt">Ready</div></div></div>
    <div class="card"><div class="card-head"><h2>Results</h2><div class="sp"></div><button class="btn sm" data-copy="pOut">Copy</button></div>
      <div id="pOut"><p class="empty">Start an audit to see which ports are listening.</p></div></div>
  </section>

  <section class="view" id="v-settings">
    <div class="card"><h2>Theme</h2><p class="hint">Applies instantly and is remembered in this browser.</p><div class="themes" id="themes"></div></div>
    <div class="card"><h2>Accent colour</h2><p class="hint">Used for buttons, focus rings and the active page.</p>
      <div class="row" id="accents"></div>
      <div class="row"><span class="mu">Custom</span><input type="color" id="cA" aria-label="Custom accent colour"><button class="btn" id="reset" style="margin-left:auto">Reset to default</button></div></div>
  </section>

  </div></div>
</main>

<script>
"use strict";
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const IC={overview:'<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
 password:'<circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/>',
 ip:'<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18"/>',
 dns:'<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
 ssl:'<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
 ports:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
 settings:'<path d="M4 6h10M18 6h2M4 12h4M12 12h8M4 18h12M20 18h0"/><circle cx="16" cy="6" r="2"/><circle cx="10" cy="12" r="2"/><circle cx="18" cy="18" r="2"/>'};
const icon=k=>`<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round">${IC[k]}</svg>`;
const NAV=[["overview","Overview","Status, shortcuts and activity"],["password","Password checker","Strength, entropy and secure generation"],["ip","IP information","Validate and classify an address"],["dns","DNS lookup","Resolve a hostname to addresses"],["ssl","SSL / TLS checker","Inspect a server certificate"],["ports","Port audit","Listening sockets on 127.0.0.1"],["settings","Appearance","Theme and accent colour"]];

/* theme */
const TH={"AMOLED Black":{bg:"#000000",s:"#0f0f0f",s2:"#171717",bd:"#262626",tx:"#ededed",mu:"#8c8c8c"},
 "Midnight":{bg:"#0b0f17",s:"#111827",s2:"#1a2233",bd:"#243047",tx:"#e6edf7",mu:"#8896ad"},
 "Graphite":{bg:"#121212",s:"#1a1a1a",s2:"#232323",bd:"#2e2e2e",tx:"#ececec",mu:"#9a9a9a"},
 "Daylight":{bg:"#f6f7f9",s:"#ffffff",s2:"#f0f2f5",bd:"#dfe3e8",tx:"#111827",mu:"#5b6472",l:1}};
const ACC=["#10b981","#3b82f6","#8b5cf6","#f59e0b","#ef4444","#06b6d4"];
const DEF={theme:"AMOLED Black",accent:"#10b981"};
let S=Object.assign({},DEF);
try{Object.assign(S,JSON.parse(localStorage.getItem("cyberlab3")||"{}"))}catch(e){}
const lum=h=>{const[r,g,b]=[1,3,5].map(i=>parseInt(h.substr(i,2),16));return(.299*r+.587*g+.114*b)/255};
function applyTheme(){
  if(!TH[S.theme])S.theme=DEF.theme;if(!/^#[0-9a-f]{6}$/i.test(S.accent))S.accent=DEF.accent;
  const t=TH[S.theme],r=document.documentElement.style;
  Object.entries({bg:t.bg,surface:t.s,surface2:t.s2,border:t.bd,text:t.tx,muted:t.mu,accent:S.accent,on:lum(S.accent)>.6?"#000":"#fff",
    ok:t.l?"#047857":"#10b981",warn:t.l?"#b45309":"#f59e0b",bad:t.l?"#dc2626":"#ef4444"}).forEach(([k,v])=>r.setProperty("--"+k,v));
  r.colorScheme=t.l?"light":"dark";
  $$(".tile").forEach(x=>x.classList.toggle("sel",x.dataset.n===S.theme));
  $$(".sw").forEach(x=>x.classList.toggle("sel",x.dataset.c===S.accent));
  $("#cA").value=S.accent;
  try{localStorage.setItem("cyberlab3",JSON.stringify(S))}catch(e){}
}
const set=o=>{Object.assign(S,o);applyTheme()};

/* log + copy */
const LOG=[];
function log(m){LOG.push(`<div><span>${new Date().toTimeString().slice(0,8)}</span>  <b>${esc(m)}</b></div>`);$("#log").innerHTML=LOG.join("");$("#log").scrollTop=1e9}
$("#clrLog").onclick=()=>{LOG.length=0;$("#log").innerHTML=""};
document.addEventListener("click",e=>{const b=e.target.closest("[data-copy]");if(!b)return;
  const t=$("#"+b.dataset.copy).dataset.txt||"";if(!t)return;
  navigator.clipboard.writeText(t).then(()=>{const o=b.textContent;b.textContent="Copied";setTimeout(()=>b.textContent=o,1200)})});

/* api + rendering */
async function api(path,params){
  const r=await fetch(path+"?"+new URLSearchParams(params));
  const j=await r.json().catch(()=>({ok:false,error:"Bad server response"}));
  if(!j.ok)throw new Error(j.error||"Request failed");return j.data;
}
function kv(el,rows,badge){
  let h=badge?`<div class="res-top"><span class="badge ${badge[1]}">${esc(badge[0])}</span></div>`:"",t=badge?badge[0]+"\n":"";h+='<dl class="kv">';
  for(const[k,v]of rows){
    if(k==="#"){h+=`</dl><h4>${esc(v)}</h4><dl class="kv">`;t+=`\n${v}\n`;continue}
    const a=Array.isArray(v)?v:[v];
    h+=`<dt>${esc(k)}</dt><dd>${a.length?a.map(esc).join("<br>"):'<span class="mu">None</span>'}</dd>`;t+=`${k}: ${a.join(", ")||"None"}\n`}
  el.innerHTML=h+"</dl>";el.dataset.txt=t.trim();
}
function msg(el,text,cls){el.innerHTML=`<p class="empty ${cls||""}">${esc(text)}</p>`;el.dataset.txt=text}
function chips(id,items,fn){$(id).innerHTML=items.map(([l,v])=>`<button class="chip" data-v="${esc(v)}">${esc(l)}</button>`).join("");$(id).onclick=e=>{const b=e.target.closest("[data-v]");if(b)fn(b.dataset.v)}}
const busy=(b,sp,on)=>{b.disabled=on;sp.classList.toggle("on",on)};

/* nav + routing */
$("#nav").innerHTML=NAV.map(n=>`<a href="#${n[0]}" data-k="${n[0]}">${icon(n[0])}<span>${n[1]}</span></a>`).join("");
$("#tools").innerHTML=NAV.slice(1,6).map(n=>`<div class="card tool" data-go="${n[0]}" tabindex="0" role="link">${icon(n[0])}<div><b>${n[1]}</b><span>${n[2]}</span></div></div>`).join("");
$$(".tool").forEach(t=>{t.onclick=()=>location.hash=t.dataset.go;t.onkeydown=e=>{if(e.key==="Enter")t.click()}});
function route(){
  const k=NAV.some(n=>n[0]===location.hash.slice(1))?location.hash.slice(1):"overview",n=NAV.find(x=>x[0]===k);
  $$(".view").forEach(v=>v.classList.toggle("on",v.id==="v-"+k));
  $$("#nav a").forEach(a=>a.classList.toggle("on",a.dataset.k===k));
  $("#ttl").textContent=n[1];$("#sub").textContent=n[2];document.title=n[1]+" · Cyber Lab";$("#content").scrollTop=0;
}
addEventListener("hashchange",route);
$("#jump").onkeydown=e=>{if(e.key!=="Enter")return;const q=e.target.value.toLowerCase();
  const m=[["pass","password"],["ip","ip"],["dns","dns"],["domain","dns"],["ssl","ssl"],["tls","ssl"],["cert","ssl"],["port","ports"],["scan","ports"],["dash","overview"],["home","overview"],["theme","settings"],["color","settings"],["appear","settings"]].find(x=>q.includes(x[0]));
  if(m){location.hash=m[1];e.target.value=""}else e.target.select()};
$("#ldBtn").onclick=()=>set(S.theme==="Daylight"?{theme:"AMOLED Black"}:{theme:"Daylight"});

/* password (browser only) */
const CRIT=[["l8","At least 8 characters"],["l12","12 or more characters"],["up","Uppercase letter"],["lo","Lowercase letter"],["di","Number"],["sy","Symbol"],["nr","No character repeated 3+ times"]];
$("#chk").innerHTML=CRIT.map(c=>`<li id="c-${c[0]}">${c[1]}</li>`).join("");
function evalPw(p){
  const up=/[A-Z]/.test(p),lo=/[a-z]/.test(p),di=/[0-9]/.test(p),sy=/[^A-Za-z0-9]/.test(p),nr=!/(.)\1{2,}/.test(p);
  const pool=(lo?26:0)+(up?26:0)+(di?10:0)+(sy?33:0),ent=pool?p.length*Math.log2(pool):0;
  let pts=(p.length>=8?15:0)+(p.length>=12?20:0)+(p.length>=16?15:0)+(up?12:0)+(lo?12:0)+(di?13:0)+(sy?13:0)+(nr?10:-15);
  if((di&&!(up||lo||sy))||(lo&&!(up||di||sy)))pts=Math.min(pts,40);
  pts=Math.max(0,Math.min(100,pts));
  const tips=[];if(p.length<12)tips.push("Use at least 12 to 16 characters.");if(!up)tips.push("Add an uppercase letter.");if(!lo)tips.push("Add a lowercase letter.");
  if(!di)tips.push("Add a number.");if(!sy)tips.push("Add a symbol such as ! or #.");if(!nr)tips.push("Avoid repeating a character three or more times.");
  return{c:{l8:p.length>=8,l12:p.length>=12,up,lo,di,sy,nr},score:pts,ent:Math.round(ent*10)/10,status:pts>=80&&ent>=60?"Strong":pts>=50?"Medium":"Weak",tips:tips.length?tips:["No changes needed. This password is resistant to brute force."]};
}
function genPw(n=16){
  const A="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+",u=new Uint32Array(1),lim=Math.floor(2**32/A.length)*A.length;
  const pick=()=>{do crypto.getRandomValues(u);while(u[0]>=lim);return A[u[0]%A.length]};
  for(;;){const p=Array.from({length:n},pick).join("");if(/[a-z]/.test(p)&&/[A-Z]/.test(p)&&/[0-9]/.test(p)&&/[^A-Za-z0-9]/.test(p))return p}
}
function onPw(){
  const p=$("#pw").value,r=evalPw(p),cls=p?{Strong:"ok",Medium:"warn",Weak:"bad"}[r.status]:"";
  const col=cls?`var(--${cls==="ok"?"ok":cls==="warn"?"warn":"bad"})`:"var(--muted)";
  $("#pwBar").style.cssText=`width:${p?r.score:0}%;--c:${col}`;
  $("#pwStat").textContent=p?`${r.status} · ${r.score}/100`:"No password";$("#pwStat").style.color=col;
  CRIT.forEach(c=>$("#c-"+c[0]).classList.toggle("ok",!!p&&r.c[c[0]]));
  if(!p){msg($("#pwOut"),"Type or generate a password to see its analysis.");return}
  kv($("#pwOut"),[["Length",p.length+" characters"],["Entropy",r.ent+" bits"],["Score",r.score+" / 100"],["Rating",r.status]],[r.status,cls]);
  $("#pwOut").insertAdjacentHTML("beforeend",`<h4>Suggestions</h4><ul class="tips">${r.tips.map(t=>`<li>${esc(t)}</li>`).join("")}</ul>`);
  $("#pwOut").dataset.txt+="\n\nSuggestions:\n"+r.tips.map(t=>"- "+t).join("\n");
}
$("#pw").oninput=onPw;
$("#pwShow").onclick=()=>{const h=$("#pw").type==="password";$("#pw").type=h?"text":"password";$("#pwShow").textContent=h?"Hide":"Show"};
$("#pwGen").onclick=()=>{$("#pw").value=genPw();onPw();log("Generated a 16-character password.")};
$("#pwClr").onclick=()=>{$("#pw").value="";onPw()};

/* ip */
async function runIp(){
  const v=$("#ipIn").value.trim(),o=$("#ipOut");
  try{const r=await api("/api/ip",{q:v});
    kv(o,[["Address",r.ip],["Version",r.version],["Scope",r.is_private?"Private (non-routable)":r.is_global?"Public (globally routable)":"Special use"],["Classification",r.classification],
      ["Max prefix length","/"+r.max_prefix_len],["Exploded",r.exploded],["Compressed",r.compressed],["Reverse DNS pointer",r.reverse_pointer],["Integer",r.integer_value],["Hexadecimal",r.hex_value]],
      [r.is_private?"Private":r.is_global?"Public":"Special","ok"]);
    log(`Analyzed ${r.version} address ${r.ip}`)}
  catch(e){msg(o,e.message+". Enter a valid IPv4 or IPv6 address.","bad");log("IP check failed: "+e.message)}
}
$("#ipGo").onclick=runIp;$("#ipIn").onkeydown=e=>{if(e.key==="Enter")runIp()};
$("#ipClr").onclick=()=>{$("#ipIn").value="";msg($("#ipOut"),"Enter an address to analyze.")};
chips("#ipChips",[["127.0.0.1 loopback","127.0.0.1"],["10.0.0.1 private","10.0.0.1"],["8.8.8.8 public","8.8.8.8"],["::1 IPv6 loopback","::1"],["2001:4860:4860::8888","2001:4860:4860::8888"]],v=>{$("#ipIn").value=v;runIp()});

/* dns */
async function runDns(){
  const d=$("#dnsIn").value.trim(),o=$("#dnsOut");if(!d){msg(o,"Enter a hostname to resolve.");return}
  busy($("#dnsGo"),$("#dnsSp"),true);
  try{const r=await api("/api/dns",{q:d});
    kv(o,[["Hostname",r.domain],["Canonical name",r.canonical_name],["Lookup time",r.latency_ms+" ms"],["IPv4 (A)",r.ipv4],["IPv6 (AAAA)",r.ipv6],["Aliases",r.aliases]],["Resolved","ok"]);
    log(`Resolved ${r.domain} in ${r.latency_ms} ms`)}
  catch(e){msg(o,e.message,"bad");log(`DNS lookup failed for ${d}`)}
  busy($("#dnsGo"),$("#dnsSp"),false);
}
$("#dnsGo").onclick=runDns;$("#dnsIn").onkeydown=e=>{if(e.key==="Enter")runDns()};
$("#dnsClr").onclick=()=>{$("#dnsIn").value="";msg($("#dnsOut"),"Enter a hostname to resolve.")};
chips("#dnsChips",["google.com","cloudflare.com","wikipedia.org","github.com"].map(x=>[x,x]),v=>{$("#dnsIn").value=v;runDns()});

/* ssl */
async function runSsl(){
  const h=$("#sslHost").value.trim(),p=parseInt($("#sslPort").value,10),o=$("#sslOut");
  if(!h){msg(o,"Enter a hostname to inspect.");return}
  if(!(p>=1&&p<=65535)){msg(o,"Port must be between 1 and 65535.","bad");return}
  busy($("#sslGo"),$("#sslSp"),true);
  try{const r=await api("/api/ssl",{host:h,port:p});
    const b={VALID:[`Valid · ${r.days_remaining} days left`,"ok"],EXPIRING_SOON:[`Expiring soon · ${r.days_remaining} days left`,"warn"]}[r.status]||[r.status.replace(/_/g," ").toLowerCase().replace(/^./,c=>c.toUpperCase()),"bad"];
    kv(o,[["#","Connection"],["Endpoint",`${r.hostname}:${r.port}`],["TLS version",r.tls_version],["Cipher",`${r.cipher_suite} (${r.cipher_bits} bits)`],["Handshake time",r.latency_ms+" ms"],
      ["#","Identity"],["Common name",r.subject_cn],["Organization",r.subject_org],["Issuer",r.issuer_cn],["Issuer organization",r.issuer_org],["Serial number",r.serial_number],
      ["#","Validity"],["Valid from",r.valid_from],["Expires",r.valid_until],["Days remaining",String(r.days_remaining)],
      ["#",`Subject alternative names (${r.san_count})`],["Names",r.san_list.concat(r.san_count>r.san_list.length?[`…and ${r.san_count-r.san_list.length} more`]:[])]],b);
    log(`Inspected ${r.hostname}: ${b[0]}`)}
  catch(e){msg(o,e.message,"bad");log(`SSL check failed for ${h}:${p}`)}
  busy($("#sslGo"),$("#sslSp"),false);
}
$("#sslGo").onclick=runSsl;$("#sslHost").onkeydown=e=>{if(e.key==="Enter")runSsl()};
$("#sslClr").onclick=()=>{$("#sslHost").value="";$("#sslPort").value="443";msg($("#sslOut"),"Enter a hostname to inspect.")};
chips("#sslChips",["github.com","google.com","python.org","wikipedia.org"].map(x=>[x,x]),v=>{$("#sslHost").value=v;runSsl()});

/* ports */
let scanning=false,stopFlag=false;
async function runScan(){
  if(scanning)return;scanning=true;stopFlag=false;
  $("#pScan").disabled=true;$("#pStop").disabled=false;$("#pBar").style.width="0";
  const list=await api("/api/portlist",{}),o=$("#pOut");let open=0,txt="";
  o.innerHTML='<table><thead><tr><th>Port</th><th>Service</th><th>State</th></tr></thead><tbody></tbody></table><p class="mu" id="pSum" style="margin:14px 0 0"></p>';
  const tb=o.querySelector("tbody");log("Started port audit on 127.0.0.1");
  for(let i=0;i<list.length&&!stopFlag;i++){
    const[port,name]=list[i];let on=false;
    try{on=(await api("/api/port",{port})).open}catch(e){}
    if(on)open++;txt+=`${port}\t${name}\t${on?"open":"closed"}\n`;
    tb.insertAdjacentHTML("beforeend",`<tr class="${on?"open":""}"><td class="n">${port}</td><td>${esc(name)}</td><td><span class="badge ${on?"ok":""}">${on?"Open":"Closed"}</span></td></tr>`);
    $("#pBar").style.width=((i+1)/list.length*100)+"%";$("#pSt").textContent=`Checking ${i+1} of ${list.length}`;
  }
  const sum=`${stopFlag?"Stopped early":"Complete"}: ${open} open port${open===1?"":"s"} found.`;
  $("#pSum").textContent=sum;o.dataset.txt=txt+sum;$("#pSt").textContent=stopFlag?"Stopped":"Complete";
  scanning=false;$("#pScan").disabled=false;$("#pStop").disabled=true;log("Port audit finished: "+sum);
}
$("#pScan").onclick=runScan;$("#pStop").onclick=()=>{stopFlag=true;$("#pSt").textContent="Stopping…"};
$("#pClr").onclick=()=>{if(scanning)return;msg($("#pOut"),"Start an audit to see which ports are listening.");$("#pBar").style.width="0";$("#pSt").textContent="Ready"};

/* appearance */
$("#themes").innerHTML=Object.entries(TH).map(([n,t])=>`<div class="tile" data-n="${n}" tabindex="0" role="button"><div class="pv" style="background:${t.bg}"><i style="background:${t.s}"></i><i style="background:${t.s2}"></i><i style="background:${t.bd}"></i></div><b>${n}</b></div>`).join("");
$("#themes").onclick=e=>{const t=e.target.closest(".tile");if(t)set({theme:t.dataset.n})};
$("#themes").onkeydown=e=>{if(e.key==="Enter"||e.key===" "){const t=e.target.closest(".tile");if(t){e.preventDefault();set({theme:t.dataset.n})}}};
$("#accents").innerHTML=ACC.map(c=>`<div class="sw" data-c="${c}" style="background:${c}" title="${c}"></div>`).join("");
$("#accents").onclick=e=>{const s=e.target.closest(".sw");if(s)set({accent:s.dataset.c})};
$("#cA").oninput=e=>set({accent:e.target.value});
$("#reset").onclick=()=>set(DEF);

/* boot */
$("#origin").textContent=location.host;$("#host").textContent=location.host;
applyTheme();route();onPw();runIp();msg($("#dnsOut"),"Enter a hostname to resolve.");msg($("#sslOut"),"Enter a hostname to inspect.");
log("Cyber Lab ready.");
</script>
</body>
</html>
"""


def main():
    try:
        httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    except OSError as e:
        sys.exit(f"Could not bind {HOST}:{PORT} ({e}). Try another port: python cyberlab_web.py 8080")
    print(f"Cyber Lab running at http://{HOST}:{PORT}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()