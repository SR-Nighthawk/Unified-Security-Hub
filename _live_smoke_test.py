# -*- coding: utf-8 -*-
"""
Offline functional test - uses http://httpbin.org patterns but against
a local test fixture. Validates all OWASP functions with mock responses.
"""
import sys, os, time, json, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

os.environ["PYTHONIOENCODING"] = "utf-8"
sys.stdout.reconfigure(encoding="utf-8")
sys.path.insert(0, ".")

from backend.modules.pentest_module import (
    _sqli_test, _xss_test, _headers_test, _exposed_files_test,
    _cors_test, _http_methods_test, _lfi_test, _cmdi_test,
    _extract_forms, deduplicate, safe_parse, AIRateLimiter,
    _normalize, OWASP, SEV_RANK
)

PASS = "[PASS]"; FAIL = "[FAIL]"; INFO = "[INFO]"
errors = []
findings = []

def check(name, cond):
    ok = bool(cond)
    print(f"  {PASS if ok else FAIL}  {name}")
    if not ok: errors.append(name)

def section(name): print(f"\n-- {name} {'-'*(52-len(name))}")

# ══════════════════════════════════════════════════════
# MOCK HTTP SERVER  (simulates vulnerable responses)
# ══════════════════════════════════════════════════════
PORT = 18765
SQL_ERROR  = "You have an error in your SQL syntax near '' at line 1"
XSS_MARKER = "SECHUB_XSS_7F3A"

class VulnHandler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass   # silence access log

    def _send(self, code, body, headers=None):
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        purl = urlparse(self.path)
        qs   = parse_qs(purl.query)

        # /.git/HEAD - exposed
        if purl.path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n")

        # /.env - exposed
        if purl.path == "/.env":
            return self._send(200, "DB_PASSWORD=secret123\nAPP_KEY=base64:abc\n")

        # SQLi vulnerable endpoint
        if purl.path == "/search":
            q = qs.get("q", [""])[0]
            if "'" in q:
                return self._send(200, f"<html><body>{SQL_ERROR}</body></html>",
                                  headers={"X-Powered-By": "PHP/7.4"})
            return self._send(200, f"<html><body>Results for: {q}</body></html>",
                              headers={"X-Powered-By": "PHP/7.4"})

        # XSS-vulnerable search
        if purl.path == "/find":
            q = qs.get("q", [""])[0]
            return self._send(200, f"<html><body>You searched: {q}</body></html>")

        # LFI-vulnerable endpoint
        if purl.path == "/view":
            f = qs.get("file", ["index.html"])[0]
            if "passwd" in f or "etc/passwd" in f:
                return self._send(200, "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            return self._send(200, "<html><body>File content</body></html>")

        # CORS test endpoint
        if purl.path == "/api/data":
            origin = self.headers.get("Origin", "")
            return self._send(200, '{"data":"secret"}',
                              headers={
                                  "Access-Control-Allow-Origin":      origin,
                                  "Access-Control-Allow-Credentials": "true",
                                  "Content-Type": "application/json",
                              })

        # Admin panel
        if purl.path in ("/admin", "/admin/"):
            return self._send(200, "<html><title>Admin Panel</title><body><h1>Admin Dashboard</h1><a href='/logout'>Logout</a></body></html>")

        # phpinfo
        if purl.path == "/phpinfo.php":
            return self._send(200, "<html><body>PHP Version 7.4.33 phpinfo()</body></html>")

        # Normal page
        return self._send(200, "<html><body>Normal page</body></html>",
                          headers={"Server": "Apache/2.4.41"})

    def do_OPTIONS(self):
        self._send(200, "", headers={
            "Allow": "GET, POST, OPTIONS, TRACE, DELETE, PUT",
            "Public": "GET, POST, OPTIONS",
        })

    def do_TRACE(self):
        self._send(200, "")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length).decode()
        purl   = urlparse(self.path)
        # Login form
        if purl.path == "/login":
            if "admin" in body and "admin" in body:
                return self._send(200, "<html><body>Welcome to the Dashboard! <a href='/logout'>Logout</a></body></html>")
            return self._send(200, "<html><body>Invalid credentials</body></html>")
        self._send(200, "<html><body>OK</body></html>")

def start_mock_server():
    srv = HTTPServer(("127.0.0.1", PORT), VulnHandler)
    t = threading.Thread(target=srv.serve_forever)
    t.daemon = True
    t.start()
    return srv

# Start server
srv = start_mock_server()
time.sleep(0.3)
BASE = f"http://127.0.0.1:{PORT}"
from backend.modules.pentest_module import _session
sess = _session()

print(f"\n{'='*60}")
print(f"  OFFLINE OWASP FUNCTIONAL TESTS (mock server :{PORT})")
print(f"{'='*60}")

# ── 1. SQLi detection ────────────────────────────────────────
section("A03 SQL Injection")
try:
    sf = _sqli_test(sess, f"{BASE}/search?q=test", [], "test")
    check("SQLi detected",     len(sf) > 0)
    check("confirmed=True",    sf and sf[0].get("confirmed"))
    check("severity=Critical", sf and sf[0].get("severity") == "Critical")
    check("OWASP A03",         sf and "A03" in sf[0].get("owasp",""))
    check("has curl command",  sf and bool(sf[0].get("curl")))
    print(f"  {INFO} {len(sf)} findings | evidence: {sf[0].get('evidence','')[:70] if sf else 'N/A'}")
    findings.extend(sf)
except Exception as e:
    check(f"SQLi ({e})", False)

# ── 2. XSS Reflection ───────────────────────────────────────
section("A03 Reflected XSS")
try:
    xf = _xss_test(sess, f"{BASE}/find?q=test", [])
    check("XSS detected",     len(xf) > 0)
    check("confirmed=True",   xf and xf[0].get("confirmed"))
    check("severity=High",    xf and xf[0].get("severity") == "High")
    check("OWASP A03",        xf and "A03" in xf[0].get("owasp",""))
    print(f"  {INFO} {len(xf)} findings | evidence: {xf[0].get('evidence','')[:70] if xf else 'N/A'}")
    findings.extend(xf)
except Exception as e:
    check(f"XSS ({e})", False)

# ── 3. LFI ──────────────────────────────────────────────────
section("A01 Path Traversal / LFI")
try:
    lf = _lfi_test(sess, f"{BASE}/view?file=index.html", [])
    check("LFI detected",     len(lf) > 0)
    check("confirmed=True",   lf and lf[0].get("confirmed"))
    check("OWASP A01",        lf and "A01" in lf[0].get("owasp",""))
    print(f"  {INFO} {len(lf)} findings | evidence: {lf[0].get('evidence','')[:70] if lf else 'N/A'}")
    findings.extend(lf)
except Exception as e:
    check(f"LFI ({e})", False)

# ── 4. Exposed files ────────────────────────────────────────
section("A05/A08 Exposed Sensitive Files")
try:
    ef = _exposed_files_test(sess, BASE, "test")
    check("found exposed files", len(ef) > 0)
    git = [f for f in ef if ".git" in f.get("injection_point","")]
    env = [f for f in ef if ".env" in f.get("injection_point","")]
    check(".git/HEAD found",    len(git) > 0)
    check(".env found",         len(env) > 0)
    check("Critical severity",  any(f.get("severity")=="Critical" for f in ef))
    for f in ef[:4]:
        print(f"  {INFO} {f['severity']:8} {f['injection_point']} | {f.get('evidence','')[:60]}")
    findings.extend(ef)
except Exception as e:
    check(f"Exposed files ({e})", False)

# ── 5. Missing headers ───────────────────────────────────────
section("A02/A05 Missing Security Headers")
# Our mock server sends no security headers
resp_hdrs = {"Server": "Apache/2.4.41", "Content-Type": "text/html", "X-Powered-By": "PHP/7.4"}
try:
    hf = _headers_test(resp_hdrs, BASE)
    check("header findings > 0",  len(hf) > 0)
    check("CSP missing detected",  any("Content-Security-Policy" in f.get("type","") for f in hf))
    check("HSTS missing detected", any("Transport-Security" in f.get("type","") for f in hf))
    print(f"  {INFO} {len(hf)} missing headers")
    for f in hf[:4]:
        print(f"  {INFO} {f['severity']:8} {f['type']}")
    findings.extend(hf)
except Exception as e:
    check(f"Headers ({e})", False)

# ── 6. CORS ─────────────────────────────────────────────────
section("A01 CORS Misconfiguration")
try:
    cf = _cors_test(sess, f"{BASE}/api/data")
    check("CORS finding detected", len(cf) > 0)
    check("OWASP A01",            cf and "A01" in cf[0].get("owasp",""))
    check("confirmed=True",       cf and cf[0].get("confirmed"))
    print(f"  {INFO} {len(cf)} findings | evidence: {cf[0].get('evidence','')[:70] if cf else 'N/A'}")
    findings.extend(cf)
except Exception as e:
    check(f"CORS ({e})", False)

# ── 7. HTTP Methods ─────────────────────────────────────────
section("A05 Dangerous HTTP Methods")
try:
    mf = _http_methods_test(sess, BASE)
    check("method findings detected", len(mf) > 0)
    check("TRACE detected",           any("TRACE" in f.get("type","") for f in mf))
    print(f"  {INFO} {len(mf)} findings")
    for f in mf:
        print(f"  {INFO} {f['type']} | {f.get('evidence','')[:60]}")
    findings.extend(mf)
except Exception as e:
    check(f"HTTP methods ({e})", False)

# ── 8. Deduplication ────────────────────────────────────────
section("Deduplication engine")
# Inject deliberate duplicates
dup1 = {"type":"SQL Injection","severity":"High",     "injection_point":"URL param: q","target_endpoint":f"{BASE}/search","confirmed":True,"evidence":"err"}
dup2 = {"type":"SQL Injection","severity":"Critical",  "injection_point":"URL param: q","target_endpoint":f"{BASE}/search","confirmed":True,"evidence":"err"}
dup3 = {"type":"SQL Injection","severity":"Critical",  "injection_point":"URL param: q","target_endpoint":f"{BASE}/search","confirmed":True,"evidence":"err"}
test_set = findings + [dup1, dup2, dup3]
deduped = deduplicate(test_set)
check("duplicates removed",   len(deduped) < len(test_set))
sqli_dups = [f for f in deduped if f.get("type")=="SQL Injection" and "URL param: q" in f.get("injection_point","")]
check("only 1 SQLi/q kept",   len(sqli_dups) <= 1)
check("highest sev kept",     sqli_dups and sqli_dups[0].get("severity")=="Critical")
sev_counts = {}
for f in deduped:
    s = f.get("severity","?"); sev_counts[s] = sev_counts.get(s,0)+1
print(f"  {INFO} {len(test_set)} raw -> {len(deduped)} deduped | {sev_counts}")

# ── 9. safe_parse edge cases ────────────────────────────────
section("safe_parse (6 edge cases)")
cases = [
    ('<think>analysis</think>\n[{"type":"SQLi"}]',         list,  "think+array"),
    ('```json\n{"score":85}\n```',                          dict,  "fence+object"),
    ('Here is analysis:\n[{"type":"XSS"}]',                 list,  "preamble+array"),
    ('{"a":1,"b":[{"c":2}',                                 dict,  "truncated repair"),
    ('<think>x</think>```json\n{"ok":true}\n```',           dict,  "think+fence"),
    ('[{"sev":"Critical"},{"sev":"High"}]',                  list,  "plain array"),
]
for raw, expected_type, label in cases:
    try:
        r = safe_parse(raw)
        check(f"safe_parse: {label}", isinstance(r, expected_type))
    except Exception as e:
        check(f"safe_parse: {label} ({e})", False)

# ── 10. Rate limiter ────────────────────────────────────────
section("AIRateLimiter (rps burst)")
rl = AIRateLimiter(rpm=10)
t0 = time.time()
for _ in range(10): rl.acquire()
elapsed = time.time() - t0
check("10 burst calls < rpm=10 complete fast", elapsed < 2.0)
print(f"  {INFO} 10 calls took {elapsed:.3f}s")

# ── 11. OWASP completeness ──────────────────────────────────
section("OWASP category coverage")
check("All 10 OWASP categories defined", len(OWASP) == 10)
check("SEV_RANK consistent",             SEV_RANK["Critical"] > SEV_RANK["High"] > SEV_RANK["Medium"] > SEV_RANK["Low"])
owasp_found = {f.get("owasp","") for f in deduped if f.get("owasp")}
print(f"  {INFO} OWASP categories in findings: {len(owasp_found)}")
for cat in sorted(owasp_found):
    cnt = sum(1 for f in deduped if f.get("owasp")==cat)
    print(f"  {INFO}   {cat[:30]:30} x{cnt}")

# ── Summary ─────────────────────────────────────────────────
srv.shutdown()
print(f"\n{'='*60}")
critical = sum(1 for f in deduped if f.get("severity")=="Critical")
high     = sum(1 for f in deduped if f.get("severity")=="High")
medium   = sum(1 for f in deduped if f.get("severity")=="Medium")
low      = sum(1 for f in deduped if f.get("severity")=="Low")
risk     = min(100, critical*25 + high*15 + medium*8 + low*3)

if errors:
    print(f"{FAIL} {len(errors)} FAILED: {', '.join(errors)}")
else:
    print(f"{PASS} ALL {len(cases)+9} CHECKS PASSED!")
    print(f"\n  Simulated report stats:")
    print(f"    Total findings : {len(deduped)}")
    print(f"    Critical       : {critical}")
    print(f"    High           : {high}")
    print(f"    Medium         : {medium}")
    print(f"    Low            : {low}")
    print(f"    Risk score     : {risk}/100")
    print(f"    OWASP coverage : {len(owasp_found)} categories\n")
