#!/usr/bin/env python3
"""Padlocke Ledger Systems — sealed-record integrity service.

Single-file HTTP service (stdlib + pycryptodome). Sessions travel as
AES-128-CBC sealed envelopes in the `sess` cookie.
"""
import base64
import binascii
import json
import os
import pickle
import re
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

KEY_PATH = "/opt/keys/session.key"
VAULT_DIR = "/var/lib/vault"
MAX_BODY = 1024 * 1024
DEMO_USER, DEMO_PASS = "auditor", "audit20" + "26"
NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
PORT = 8000


def load_key():
    try:
        with open(KEY_PATH, "rb") as f:
            key = f.read()
        if len(key) == 16:
            return key
    except OSError:
        pass
    key = get_random_bytes(16)
    os.makedirs(os.path.dirname(KEY_PATH), exist_ok=True)
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    os.chmod(KEY_PATH, 0o600)
    return key


SESSION_KEY = load_key()

LANDING = """<!doctype html>
<html><head><meta charset="utf-8"><title>Padlocke Ledger Systems</title>
<style>
body{font-family:Georgia,'Times New Roman',serif;background:#101418;color:#cfd6dd;
max-width:44em;margin:4em auto;padding:0 1.2em;line-height:1.5}
h1{color:#e2b13c;letter-spacing:.04em}
code{color:#8fd3a0;background:#1a2026;padding:.1em .35em;border-radius:3px}
a{color:#e2b13c}
.foot{margin-top:3em;font-size:.85em;color:#5c6670}
</style></head>
<body>
<h1>Padlocke Ledger Systems</h1>
<p>Integrity services for sealed records. Every request to the portal is
checked against a signed <em>session envelope</em> issued at login.</p>
<h2>Public service surface</h2>
<ul>
<li><code>POST /api/v1/auth/login</code> &mdash; JSON body
<code>{"user": "...", "password": "..."}</code>; issues the sealed
session envelope cookie.</li>
<li><code>GET /api/v1/session</code> &mdash; current envelope status.</li>
<li><code>GET /api/health</code> &mdash; liveness.</li>
</ul>
<p>Staff demo account: <code>__DEMO_USER__</code> / <code>__DEMO_PASS__</code></p>
<p class="foot">Padlocke Ledger Systems &mdash; sealed since MMXIX</p>
</body></html>"""

ROBOTS = "User-agent: *\nDisallow: /admin/portal\nDisallow: /api/v1/telemetry\n"

PORTAL = """PADLOCKE ADMIN REPORT
tier: admin (sealed)
restore path    : POST /api/v1/restore   (raw vendor .snap snapshot bytes)
report vault    : GET  /api/v1/vault?name=<report-name>
integrity sweep : /usr/local/bin/vaultcheck <report-name>   (nightly)
"""


def pkcs7_pad(data):
    n = 16 - len(data) % 16
    return data + bytes([n]) * n


def pkcs7_unpad(data):
    if not data or len(data) % 16:
        raise ValueError("bad block length")
    n = data[-1]
    if n < 1 or n > 16 or data[-n:] != bytes([n]) * n:
        raise ValueError("bad padding")
    return data[:-n]


def encrypt_session(payload):
    pt = pkcs7_pad(json.dumps(payload, separators=(",", ":")).encode())
    iv = get_random_bytes(16)
    ct = AES.new(SESSION_KEY, AES.MODE_CBC, iv).encrypt(pt)
    return base64.b64encode(iv + ct).decode()


def decrypt_session(token):
    """Return (state, payload); state in: ok | padding | malformed."""
    try:
        raw = base64.b64decode(token, validate=True)
    except (binascii.Error, ValueError):
        return "malformed", None
    if len(raw) < 32 or (len(raw) - 16) % 16:
        return "padding", None
    iv, ct = raw[:16], raw[16:]
    try:
        pt = pkcs7_unpad(AES.new(SESSION_KEY, AES.MODE_CBC, iv).decrypt(ct))
    except ValueError:
        return "padding", None
    try:
        obj = json.loads(pt.decode("utf-8", "replace"))
    except (ValueError, UnicodeDecodeError):
        return "malformed", None
    if not isinstance(obj, dict) or "u" not in obj:
        return "malformed", None
    return "ok", obj


class Handler(BaseHTTPRequestHandler):
    server_version = "httpd"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # ---- plumbing -------------------------------------------------------
    def _send(self, code, body, ctype="application/json", extra=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for h, v in (extra or {}).items():
            self.send_header(h, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def send_error(self, code, message=None, explain=None):
        self._send(code, json.dumps({"error": (message or "error").lower()}))

    def _cookie(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == "sess":
                return v
        return None

    def _session_state(self):
        """-> (code, session_or_none). Non-200 code = respond with it."""
        tok = self._cookie()
        if tok is None:
            return 401, None
        state, obj = decrypt_session(tok)
        if state == "padding":
            return 500, None
        if state == "malformed":
            return 403, None
        return 200, obj

    def _read_body(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
        except ValueError:
            length = 0
        if length > MAX_BODY:
            return None
        data = b""
        while len(data) < length:
            chunk = self.rfile.read(min(length - len(data), 65536))
            if not chunk:
                break
            data += chunk
        return data

    # ---- routes ---------------------------------------------------------
    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._send(
                200,
                LANDING.replace("__DEMO_USER__", DEMO_USER)
                       .replace("__DEMO_PASS__", DEMO_PASS),
                "text/html; charset=utf-8")
        if path == "/robots.txt":
            return self._send(200, ROBOTS, "text/plain")
        if path == "/api/health":
            return self._send(200, '{"ok":true,"sealed":true}')
        if path == "/api/v1/session":
            code, obj = self._session_state()
            if code != 200:
                body = {401: '{"error":"no session envelope"}',
                        403: '{"error":"session envelope malformed"}',
                        500: '{"error":"internal: envelope unwrap failed"}'}[code]
                return self._send(code, body)
            return self._send(200, json.dumps({
                "u": obj.get("u"), "role": obj.get("role"),
                "admin": obj.get("admin"), "portal": "/admin/portal"}))
        if path == "/admin/portal":
            code, obj = self._session_state()
            if code != 200:
                return self._send(code, json.dumps({"error": "admin seal required"}))
            if obj.get("admin") != 1:
                return self._send(403, '{"error":"staff tier - admin seal required '
                                       '(restore path: /api/v1/restore)"}')
            return self._send(200, PORTAL, "text/plain")
        if path == "/api/v1/vault":
            code, obj = self._session_state()
            if code != 200:
                return self._send(code, json.dumps({"error": "valid envelope required"}))
            q = parse_qs(urlparse(self.path).query)
            name = (q.get("name") or [""])[0]
            if not NAME_RE.match(name):
                return self._send(400, '{"error":"invalid report name"}')
            fp = os.path.join(VAULT_DIR, name)
            if not os.path.isfile(fp):
                return self._send(404, '{"error":"no such report"}')
            try:
                with open(fp, "rb") as f:
                    data = f.read(262144)
            except OSError:
                return self._send(403, '{"error":"report unreadable"}')
            return self._send(200, data, "text/plain; charset=utf-8")
        return self._send(404, '{"error":"not found"}')

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/v1/auth/login":
            body = self._read_body()
            if body is None:
                return self._send(413, '{"error":"body too large"}')
            try:
                creds = json.loads(body or b"{}")
            except ValueError:
                return self._send(400, '{"error":"expected JSON body"}')
            if (isinstance(creds, dict) and creds.get("user") == DEMO_USER
                    and creds.get("password") == DEMO_PASS):
                tok = encrypt_session({"admin": 0, "u": DEMO_USER,
                                       "role": "staff", "ts": int(time.time())})
                return self._send(200, '{"session":"issued","profile":"/api/v1/session"}',
                                  extra={"Set-Cookie": f"sess={tok}; Path=/; HttpOnly"})
            return self._send(401, '{"error":"invalid credentials"}')
        if path == "/api/v1/restore":
            body = self._read_body()
            code, obj = self._session_state()
            if code != 200:
                return self._send(code, json.dumps({"error": "admin seal required"}))
            if obj.get("admin") != 1:
                return self._send(403, '{"error":"staff tier - restore is admin-only"}')
            if body is None:
                return self._send(413, '{"error":"snapshot too large"}')
            try:
                pickle.loads(body)
            except BaseException:
                return self._send(400, '{"error":"snapshot unsupported: '
                                       'vendor .snap binary expected"}')
            return self._send(202, '{"applied":true}')
        return self._send(404, '{"error":"not found"}')


def main():
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    srv.daemon_threads = True
    print(f"padlocke ledger service up on :{PORT}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
