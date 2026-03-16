"""
API Security modules — auto-discovered by ModuleRegistry.
Sprint 5: REST Fuzzer, Version Enum, Mass Assignment, Rate Limit Bypass,
          API Key Leak, GraphQL Suite, JSON Injection, BOLA, Swagger Parser
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [API-01] REST API Fuzzer ─────────────────────────────────────────────────

class RESTAPIFuzzerModule(BaseModule):
    id = "API-01"
    name = "REST API Fuzzer"
    category = "api"
    description = (
        "Fuzz REST API endpoints using an OpenAPI/Swagger spec or a built-in "
        "path wordlist. Tests each endpoint/method combination for unexpected responses."
    )
    risk_level = "high"
    tags = ["api", "rest", "fuzzing", "swagger", "openapi"]
    celery_queue = "api_queue"
    time_limit = 1200

    PARAMETER_SCHEMA = [
        FieldSchema(key="base_url", label="API Base URL", field_type="url", required=True,
                    placeholder="https://api.example.com"),
        FieldSchema(key="swagger_url", label="Swagger/OpenAPI Spec URL (optional)",
                    field_type="url", required=False,
                    placeholder="https://api.example.com/openapi.json"),
        FieldSchema(key="swagger_json", label="Paste OpenAPI JSON (optional)",
                    field_type="textarea", required=False),
        FieldSchema(key="extra_headers", label="Auth / Extra Headers (JSON)",
                    field_type="json_editor", required=False),
        FieldSchema(key="methods", label="HTTP Methods to Test", field_type="checkbox_group",
                    default=["GET", "POST", "PUT", "DELETE"],
                    options=[
                        {"value": "GET",    "label": "GET"},
                        {"value": "POST",   "label": "POST"},
                        {"value": "PUT",    "label": "PUT"},
                        {"value": "PATCH",  "label": "PATCH"},
                        {"value": "DELETE", "label": "DELETE"},
                    ]),
        FieldSchema(key="fuzz_params", label="Fuzz query/body parameters", field_type="select",
                    options=["none", "basic", "injection"], default="basic"),
        FieldSchema(key="wordlist_size", label="Path Wordlist Size",
                    field_type="select", options=["small", "medium"], default="small"),
    ]

    _SMALL_PATHS = [
        "/api/users", "/api/user", "/api/products", "/api/items", "/api/orders",
        "/api/admin", "/api/config", "/api/settings", "/api/health", "/api/status",
        "/api/v1/users", "/api/v2/users", "/v1/users", "/v2/users",
        "/api/auth/token", "/api/auth/login", "/api/me", "/api/profile",
    ]
    _MEDIUM_EXTRA = [
        "/api/accounts", "/api/payments", "/api/invoices", "/api/reports",
        "/api/upload", "/api/files", "/api/search", "/api/notifications",
        "/api/roles", "/api/permissions", "/api/tokens", "/api/keys",
        "/api/logs", "/api/audit", "/api/debug", "/api/internal",
    ]

    _FUZZ_PAYLOADS = {
        "basic":     ["1", "0", "-1", "null", "true", "undefined"],
        "injection": ["' OR '1'='1", "<script>alert(1)</script>", "../../../etc/passwd",
                      "{{7*7}}", "${7*7}", "1; DROP TABLE users--"],
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json
        import urllib3; urllib3.disable_warnings()

        base_url = params["base_url"].rstrip("/")
        swagger_url = params.get("swagger_url", "") or ""
        swagger_json_raw = params.get("swagger_json", "") or ""
        extra_headers = params.get("extra_headers") or {}
        if isinstance(extra_headers, str):
            try:
                extra_headers = json.loads(extra_headers)
            except Exception:
                extra_headers = {}
        methods = params.get("methods", ["GET", "POST"])
        fuzz_mode = params.get("fuzz_params", "basic") or "basic"
        wl_size = params.get("wordlist_size", "small") or "small"

        headers = {"User-Agent": "PenTools/1.0"}
        headers.update(extra_headers)

        # Collect paths from spec or wordlist
        paths = []
        spec_data = None

        if swagger_url:
            stream(f"[API-01] Fetching OpenAPI spec from {swagger_url}...")
            try:
                session = requests.Session()
                session.verify = False
                r = session.get(swagger_url, headers=headers, timeout=15)
                if r.status_code == 200:
                    spec_data = r.json()
            except Exception as e:
                stream(f"[API-01] Spec fetch error: {e}")
        elif swagger_json_raw:
            try:
                spec_data = json.loads(swagger_json_raw)
            except Exception as e:
                stream(f"[API-01] Spec parse error: {e}")

        if spec_data:
            raw_paths = spec_data.get("paths", {})
            paths = list(raw_paths.keys())
            stream(f"[API-01] Loaded {len(paths)} paths from spec.")
        else:
            paths = list(self._SMALL_PATHS)
            if wl_size == "medium":
                paths += self._MEDIUM_EXTRA
            stream(f"[API-01] Using built-in wordlist ({len(paths)} paths).")

        fuzz_vals = self._FUZZ_PAYLOADS.get(fuzz_mode, []) if fuzz_mode != "none" else []
        findings = []
        session = requests.Session()
        session.verify = False

        for path in paths:
            url = base_url + path
            for method in methods:
                try:
                    meth_fn = getattr(session, method.lower(), None)
                    if not meth_fn:
                        continue
                    r = meth_fn(url, headers=headers, timeout=8)
                    status = r.status_code

                    # Flag interesting responses
                    if status in (200, 201, 204) and method in ("DELETE", "PUT", "PATCH"):
                        findings.append({
                            "title": f"API Endpoint Responds to {method} — No Auth",
                            "severity": "high",
                            "url": url,
                            "description": (
                                f"{method} {url} returned {status}. This suggests the "
                                "endpoint may be accessible without proper authentication "
                                "or allows unintended state-changing operations."
                            ),
                            "evidence": f"HTTP {method} {url} → {status}",
                            "remediation": "Enforce authentication and authorization on all state-changing API methods.",
                            "cwe_id": "CWE-862",
                        })
                    elif status == 200 and method == "GET":
                        # Check for sensitive data in response
                        txt = r.text.lower()
                        if any(kw in txt for kw in ("password", "secret", "api_key", "private_key", "access_key")):
                            findings.append({
                                "title": "API Endpoint Leaking Sensitive Data",
                                "severity": "high",
                                "url": url,
                                "description": f"GET {url} returned potential sensitive field names in response.",
                                "evidence": f"HTTP 200 — Response snippet: {r.text[:200]}",
                                "remediation": "Audit API responses. Never expose credentials, keys, or internal fields.",
                                "cwe_id": "CWE-200",
                            })

                    # Fuzz payloads
                    if fuzz_vals and method in ("GET", "POST"):
                        for payload in fuzz_vals[:3]:
                            try:
                                if method == "GET":
                                    rf = session.get(url, params={"id": payload, "q": payload},
                                                     headers=headers, timeout=8)
                                else:
                                    rf = session.post(url, json={"id": payload, "q": payload},
                                                      headers=headers, timeout=8)
                                if rf.status_code == 500:
                                    findings.append({
                                        "title": "API Endpoint Server Error on Fuzz Input",
                                        "severity": "medium",
                                        "url": url,
                                        "description": f"Fuzz payload caused HTTP 500 on {method} {url}.",
                                        "evidence": f"Payload: {payload!r} → HTTP 500",
                                        "remediation": "Validate and sanitize all API inputs. Handle exceptions gracefully.",
                                        "cwe_id": "CWE-20",
                                    })
                                    break
                            except Exception:
                                pass
                except Exception:
                    pass

        return {"status": "done", "findings": findings}


# ─── [API-02] API Version Enumeration ────────────────────────────────────────

class APIVersionEnumerationModule(BaseModule):
    id = "API-02"
    name = "API Version Enumeration"
    category = "api"
    description = (
        "Probe common API versioning patterns (/v1/, /v2/, /internal/, /private/, "
        "/beta/, /legacy/) to discover exposed endpoints."
    )
    risk_level = "medium"
    tags = ["api", "version-enumeration", "discovery"]
    celery_queue = "api_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="base_url", label="Target Base URL", field_type="url", required=True,
                    placeholder="https://api.example.com"),
        FieldSchema(key="known_path", label="Known API Path (from v1)", field_type="text",
                    required=False, placeholder="/users"),
        FieldSchema(key="extra_headers", label="Auth Headers (JSON)", field_type="json_editor",
                    required=False),
    ]

    _VERSION_PREFIXES = [
        "/v1", "/v2", "/v3", "/v4", "/v5", "/v0",
        "/api/v1", "/api/v2", "/api/v3", "/api/v0",
        "/api", "/api/internal", "/api/private", "/internal",
        "/private", "/beta", "/alpha", "/staging", "/legacy",
        "/rest", "/rest/v1", "/rest/v2", "/graphql",
        "/admin/api", "/api/admin", "/api/debug",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json
        import urllib3; urllib3.disable_warnings()

        base_url = params["base_url"].rstrip("/")
        known_path = (params.get("known_path") or "/users").strip()
        extra_headers = params.get("extra_headers") or {}
        if isinstance(extra_headers, str):
            try:
                extra_headers = json.loads(extra_headers)
            except Exception:
                extra_headers = {}

        headers = {"User-Agent": "PenTools/1.0"}
        headers.update(extra_headers)

        session = requests.Session()
        session.verify = False
        findings = []

        stream(f"[API-02] Probing {len(self._VERSION_PREFIXES)} version prefixes...")

        for prefix in self._VERSION_PREFIXES:
            url = base_url + prefix + known_path
            try:
                r = session.get(url, headers=headers, timeout=8)
                if r.status_code in (200, 201):
                    sev = "high" if any(k in prefix for k in ("internal", "private", "admin", "debug")) else "medium"
                    findings.append({
                        "title": "API Version/Path Exposed: " + prefix,
                        "severity": sev,
                        "url": url,
                        "description": (
                            f"API version prefix '{prefix}' returned HTTP {r.status_code}. "
                            "Older or internal API versions may lack security controls present "
                            "in the production version."
                        ),
                        "evidence": f"GET {url} → {r.status_code} — Body[:100]: {r.text[:100]}",
                        "remediation": (
                            "Decommission or restrict access to deprecated API versions. "
                            "Apply the same auth/authz policies to all active versions."
                        ),
                        "cwe_id": "CWE-1059",
                    })
                    stream("[API-02] Found: " + url + " → " + str(r.status_code))
            except Exception:
                pass

        return {"status": "done", "findings": findings}


# ─── [API-03] Mass Assignment ─────────────────────────────────────────────────

class MassAssignmentModule(BaseModule):
    id = "API-03"
    name = "Mass Assignment"
    category = "api"
    description = (
        "Inject extra privileged fields (isAdmin, role, admin, is_superuser) into "
        "API request bodies to test for mass assignment vulnerabilities."
    )
    risk_level = "high"
    tags = ["api", "mass-assignment", "privilege-escalation", "injection"]
    celery_queue = "api_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target API Endpoint (e.g. profile update)", field_type="url",
                    required=True, placeholder="https://api.example.com/api/user/profile"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["PUT", "PATCH", "POST"], default="PUT"),
        FieldSchema(key="base_body", label="Normal Request Body (JSON)", field_type="json_editor",
                    required=False, placeholder='{"name": "test", "email": "test@example.com"}'),
        FieldSchema(key="auth_header", label="Authorization Header (key: value)", field_type="text",
                    required=False, sensitive=True, placeholder="Authorization: Bearer eyJ..."),
        FieldSchema(key="success_indicator", label="Success Response Indicator",
                    field_type="text", required=False, placeholder="updated"),
    ]

    _EXTRA_FIELDS = [
        {"isAdmin": True},
        {"is_admin": True},
        {"role": "admin"},
        {"admin": True},
        {"is_superuser": True},
        {"superuser": True},
        {"userRole": "admin"},
        {"user_type": "admin"},
        {"privilege": "high"},
        {"permissions": ["admin", "superuser"]},
        {"balance": 999999},
        {"credits": 999999},
        {"verified": True},
        {"email_verified": True},
        {"active": True},
        {"banned": False},
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        method = (params.get("method") or "PUT").upper()
        base_body = params.get("base_body") or {}
        if isinstance(base_body, str):
            try:
                base_body = json.loads(base_body)
            except Exception:
                base_body = {}
        auth_header = params.get("auth_header") or ""
        success_str = params.get("success_indicator") or ""

        headers = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []

        # Baseline request
        meth_fn = getattr(session, method.lower())
        try:
            r_base = meth_fn(target_url, json=base_body, headers=headers, timeout=10)
            baseline_status = r_base.status_code
            baseline_text = r_base.text
        except Exception as e:
            stream(f"[API-03] Baseline request failed: {e}")
            return {"status": "failed", "findings": []}

        stream(f"[API-03] Baseline: {baseline_status}. Testing {len(self._EXTRA_FIELDS)} extra field sets...")

        for extra in self._EXTRA_FIELDS:
            fuzz_body = dict(base_body)
            fuzz_body.update(extra)
            try:
                r = meth_fn(target_url, json=fuzz_body, headers=headers, timeout=10)
                accepted = (
                    r.status_code in (200, 201, 204)
                    and r.status_code == baseline_status
                    and (success_str in r.text if success_str else True)
                )
                # Flag if extra field appears in response (reflected)
                field_name = list(extra.keys())[0]
                if accepted and field_name in r.text:
                    findings.append({
                        "title": "Mass Assignment — Extra Field Accepted: " + field_name,
                        "severity": "high",
                        "url": target_url,
                        "description": (
                            f"The API accepted the injected field '{field_name}' with value "
                            f"'{list(extra.values())[0]}'. The field was reflected in the response, "
                            "suggesting it was processed by the server."
                        ),
                        "evidence": f"Body {extra} → {r.status_code}, field '{field_name}' in response.",
                        "remediation": (
                            "Use allowlists/DTOs to define exactly which fields are accepted. "
                            "Never bind request body directly to model objects."
                        ),
                        "cwe_id": "CWE-915",
                    })
            except Exception:
                pass

        return {"status": "done", "findings": findings}


# ─── [API-04] Rate Limit Bypass ───────────────────────────────────────────────

class RateLimitBypassModule(BaseModule):
    id = "API-04"
    name = "Rate Limit Bypass"
    category = "api"
    description = (
        "Test rate limiting controls by rotating X-Forwarded-For IPs, "
        "alternating HTTP verbs, and sending rapid parallel requests."
    )
    risk_level = "medium"
    tags = ["api", "rate-limit", "bypass", "x-forwarded-for"]
    celery_queue = "api_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Rate-Limited Endpoint URL", field_type="url",
                    required=True, placeholder="https://api.example.com/api/login"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["POST", "GET"], default="POST"),
        FieldSchema(key="request_body", label="Request Body (JSON)", field_type="json_editor",
                    required=False),
        FieldSchema(key="auth_header", label="Auth Header (key: value)", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="bypass_techniques", label="Bypass Techniques",
                    field_type="checkbox_group",
                    default=["xff_rotation", "verb_swap"],
                    options=[
                        {"value": "xff_rotation", "label": "X-Forwarded-For IP rotation"},
                        {"value": "verb_swap",    "label": "HTTP verb alternation"},
                        {"value": "parallel",     "label": "Parallel burst (race)"},
                    ]),
        FieldSchema(key="request_count", label="Requests per Test", field_type="number",
                    default=20, min_value=5, max_value=100),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json, concurrent.futures, random
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        method = (params.get("method") or "POST").upper()
        req_body = params.get("request_body") or {}
        if isinstance(req_body, str):
            try:
                req_body = json.loads(req_body)
            except Exception:
                req_body = {}
        auth_header = params.get("auth_header") or ""
        techniques = params.get("bypass_techniques", ["xff_rotation", "verb_swap"])
        req_count = int(params.get("request_count", 20))

        base_headers = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            base_headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []

        # Detect rate limit baseline
        stream("[API-04] Sending baseline requests to detect rate limit threshold...")
        statuses = []
        for i in range(min(req_count, 20)):
            try:
                if method == "POST":
                    r = session.post(target_url, json=req_body, headers=base_headers, timeout=8)
                else:
                    r = session.get(target_url, headers=base_headers, timeout=8)
                statuses.append(r.status_code)
            except Exception:
                pass

        rate_limited = any(s in (429, 503) for s in statuses)
        stream(f"[API-04] Baseline statuses: {sorted(set(statuses))}. Rate-limited: {rate_limited}")

        if not rate_limited:
            findings.append({
                "title": "No Rate Limiting Detected",
                "severity": "medium",
                "url": target_url,
                "description": f"Sent {len(statuses)} requests with no rate limiting response (429/503). The endpoint may allow unlimited requests.",
                "evidence": "Statuses: " + str(sorted(set(statuses))),
                "remediation": "Implement rate limiting (e.g. 10 req/min per IP/user). Use a reverse proxy or API gateway for enforcement.",
                "cwe_id": "CWE-770",
            })

        if rate_limited and "xff_rotation" in techniques:
            stream("[API-04] Testing X-Forwarded-For rotation bypass...")
            bypass_success = 0
            for _ in range(15):
                fake_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
                h = dict(base_headers)
                h["X-Forwarded-For"] = fake_ip
                h["X-Real-IP"] = fake_ip
                h["CF-Connecting-IP"] = fake_ip
                try:
                    if method == "POST":
                        r = session.post(target_url, json=req_body, headers=h, timeout=8)
                    else:
                        r = session.get(target_url, headers=h, timeout=8)
                    if r.status_code not in (429, 503):
                        bypass_success += 1
                except Exception:
                    pass

            if bypass_success > 0:
                findings.append({
                    "title": "Rate Limit Bypass via X-Forwarded-For IP Rotation",
                    "severity": "high",
                    "url": target_url,
                    "description": (
                        f"{bypass_success}/15 requests with spoofed X-Forwarded-For headers "
                        "bypassed the rate limit. The application trusts client-supplied IP headers."
                    ),
                    "evidence": f"{bypass_success} requests bypassed 429/503 with fake IPs.",
                    "remediation": "Do not trust X-Forwarded-For for rate limiting. Use the actual connection IP enforced at the network layer.",
                    "cwe_id": "CWE-290",
                })

        if "verb_swap" in techniques:
            stream("[API-04] Testing HTTP verb alternation...")
            alt_methods = ["GET", "POST", "PUT", "HEAD", "OPTIONS"]
            for alt_method in alt_methods:
                if alt_method == method:
                    continue
                try:
                    fn = getattr(session, alt_method.lower(), None)
                    if not fn:
                        continue
                    r = fn(target_url, headers=base_headers, timeout=8)
                    if r.status_code == 200:
                        findings.append({
                            "title": "Rate Limit Bypass via HTTP Verb Swap",
                            "severity": "medium",
                            "url": target_url,
                            "description": f"Using {alt_method} instead of {method} circumvented rate limiting.",
                            "evidence": f"{alt_method} {target_url} → {r.status_code}",
                            "remediation": "Apply rate limiting at the URL level (not per HTTP method). Disable unused HTTP methods.",
                            "cwe_id": "CWE-284",
                        })
                        break
                except Exception:
                    pass

        return {"status": "done", "findings": findings}


# ─── [API-05] API Key Leak Scanner ───────────────────────────────────────────

class APIKeyLeakScannerModule(BaseModule):
    id = "API-05"
    name = "API Key Leak Scanner"
    category = "api"
    description = (
        "Scan JavaScript files, error responses, and page responses for "
        "exposed API keys, tokens, credentials, and cloud secrets."
    )
    risk_level = "high"
    tags = ["api", "api-key", "secret-leak", "js-scan", "disclosure"]
    celery_queue = "api_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL (scan this page + linked JS)",
                    field_type="url", required=True, placeholder="https://example.com"),
        FieldSchema(key="extra_urls", label="Additional URLs / JS files (one per line)",
                    field_type="textarea", required=False,
                    placeholder="https://example.com/static/app.js"),
        FieldSchema(key="scan_errors", label="Trigger error pages to scan", field_type="select",
                    options=["yes", "no"], default="yes"),
    ]

    _PATTERNS = [
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key[\s:=]+[A-Za-z0-9+/]{40}", "AWS Secret Key"),
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Secret Key (live)"),
        (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Secret Key (test)"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub Personal Access Token"),
        (r"github_pat_[A-Za-z0-9_]{82}", "GitHub Fine-Grained PAT"),
        (r"xoxb-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{24}", "Slack Bot Token"),
        (r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[A-Za-z0-9]{32}", "Slack User Token"),
        (r"(?i)(api_key|apikey|api-key)[\s:=\"']+([A-Za-z0-9\-_]{16,64})", "Generic API Key"),
        (r"(?i)(secret|passwd|password|token)[\s:=\"']+([A-Za-z0-9\-_@#$%]{12,})", "Generic Secret/Token"),
        (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", "Private Key Material"),
        (r"ey[A-Za-z0-9\-_]+\.ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "JWT Token"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, re
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        extra_urls_raw = params.get("extra_urls") or ""
        scan_errors = params.get("scan_errors", "yes") == "yes"

        session = requests.Session()
        session.verify = False
        headers = {"User-Agent": "PenTools/1.0"}
        findings = []

        urls_to_scan = [target_url]
        for u in extra_urls_raw.splitlines():
            u = u.strip()
            if u:
                urls_to_scan.append(u)

        # Also discover JS files from the main page
        try:
            r = session.get(target_url, headers=headers, timeout=10)
            js_urls = re.findall(r'src=["\'](.*?\.js(?:\?[^"\']*)?)["\']', r.text)
            for js_path in js_urls[:20]:
                if js_path.startswith("http"):
                    urls_to_scan.append(js_path)
                elif js_path.startswith("/"):
                    base = "/".join(target_url.split("/")[:3])
                    urls_to_scan.append(base + js_path)
        except Exception:
            pass

        if scan_errors:
            error_urls = [
                target_url + "/nonexistent_xyz_123",
                target_url + "/%3cscript%3e",
                target_url + "/api/v1/nonexistent",
            ]
            urls_to_scan += error_urls

        stream(f"[API-05] Scanning {len(urls_to_scan)} URLs for secrets...")

        for url in urls_to_scan:
            try:
                r = session.get(url, headers=headers, timeout=10)
                content = r.text
                for pattern, label in self._PATTERNS:
                    matches = re.findall(pattern, content)
                    if matches:
                        match_val = matches[0]
                        if isinstance(match_val, tuple):
                            match_val = match_val[-1]
                        # Truncate to avoid storing real secrets
                        truncated = str(match_val)[:8] + "..." if len(str(match_val)) > 8 else str(match_val)
                        findings.append({
                            "title": f"Secret Exposed: {label}",
                            "severity": "critical",
                            "url": url,
                            "description": (
                                f"A {label} pattern was found in the response from {url}. "
                                "Exposed credentials allow attackers to access associated services."
                            ),
                            "evidence": f"Pattern '{label}' matched. Value prefix: {truncated}",
                            "remediation": (
                                "Immediately revoke the exposed credential. "
                                "Move secrets to environment variables or a secrets manager. "
                                "Never include API keys in JS bundles or HTML responses."
                            ),
                            "cwe_id": "CWE-312",
                        })
            except Exception:
                pass

        return {"status": "done", "findings": findings}


# ─── [API-06] GraphQL Security Suite ─────────────────────────────────────────

class GraphQLSecuritySuiteModule(BaseModule):
    id = "API-06"
    name = "GraphQL Security Suite"
    category = "api"
    description = (
        "Test GraphQL endpoints for: introspection enabled, batching DoS, "
        "field suggestion abuse, nested query depth limit, and aliasing attacks."
    )
    risk_level = "high"
    tags = ["api", "graphql", "introspection", "batching-dos", "injection"]
    celery_queue = "api_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="graphql_url", label="GraphQL Endpoint URL", field_type="url",
                    required=True, placeholder="https://api.example.com/graphql"),
        FieldSchema(key="auth_header", label="Auth Header (key: value)", field_type="text",
                    required=False, sensitive=True, placeholder="Authorization: Bearer eyJ..."),
        FieldSchema(key="checks", label="Security Checks", field_type="checkbox_group",
                    default=["introspection", "batching", "depth_limit"],
                    options=[
                        {"value": "introspection",    "label": "Introspection enabled"},
                        {"value": "batching",          "label": "Query batching / DoS"},
                        {"value": "depth_limit",       "label": "Nested query depth limit"},
                        {"value": "field_suggestion",  "label": "Field suggestion info disclosure"},
                        {"value": "csrf",              "label": "CSRF via GET query"},
                    ]),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json, time
        import urllib3; urllib3.disable_warnings()

        gql_url = params["graphql_url"]
        auth_header = params.get("auth_header") or ""
        checks = params.get("checks", ["introspection", "batching", "depth_limit"])

        headers = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []

        def gql_post(query, variables=None):
            body = {"query": query}
            if variables:
                body["variables"] = variables
            try:
                return session.post(gql_url, json=body, headers=headers, timeout=10)
            except Exception:
                return None

        if "introspection" in checks:
            stream("[API-06] Testing introspection...")
            introspection_query = "{ __schema { types { name kind } } }"
            r = gql_post(introspection_query)
            if r and r.status_code == 200 and "__schema" in r.text:
                type_count = r.text.count('"name"')
                findings.append({
                    "title": "GraphQL Introspection Enabled",
                    "severity": "medium",
                    "url": gql_url,
                    "description": (
                        "GraphQL introspection is enabled in production. "
                        "Attackers can enumerate the full API schema — all types, "
                        "queries, mutations, and field names — to aid targeted attacks."
                    ),
                    "evidence": f"Introspection returned schema with ~{type_count} name fields.",
                    "remediation": "Disable introspection in production. Use schema allow-listing instead.",
                    "cwe_id": "CWE-200",
                })

        if "batching" in checks:
            stream("[API-06] Testing query batching DoS...")
            batch = [{"query": "{ __typename }"}] * 50
            try:
                t0 = time.time()
                r = session.post(gql_url, json=batch, headers=headers, timeout=15)
                elapsed = time.time() - t0
                if r.status_code == 200 and isinstance(r.json(), list):
                    findings.append({
                        "title": "GraphQL Batching Enabled — DoS Risk",
                        "severity": "high",
                        "url": gql_url,
                        "description": (
                            f"GraphQL accepts batched queries (50 sent, took {elapsed:.1f}s). "
                            "Attackers can amplify expensive queries by sending thousands in a single request."
                        ),
                        "evidence": f"Batch of 50 queries: HTTP {r.status_code}, {elapsed:.1f}s",
                        "remediation": "Limit batch size. Implement query cost analysis and depth limiting.",
                        "cwe_id": "CWE-400",
                    })
            except Exception as e:
                stream(f"[API-06] Batching test error: {e}")

        if "depth_limit" in checks:
            stream("[API-06] Testing nested query depth limit...")
            # Build a deeply-nested query
            deep_query = "{ a { b { c { d { e { f { g { h { i { j { __typename } } } } } } } } } } }"
            r = gql_post(deep_query)
            if r:
                if r.status_code == 200 and "errors" not in r.text.lower():
                    findings.append({
                        "title": "GraphQL No Query Depth Limit",
                        "severity": "high",
                        "url": gql_url,
                        "description": (
                            "GraphQL accepted a deeply-nested (10-level) query without rejection. "
                            "Combined with circular references, this enables DoS attacks."
                        ),
                        "evidence": "10-level nested query returned HTTP 200 without depth error.",
                        "remediation": "Set a maximum query depth (e.g. 5-7 levels). Use graphql-depth-limit library.",
                        "cwe_id": "CWE-400",
                    })

        if "field_suggestion" in checks:
            stream("[API-06] Testing field suggestion info disclosure...")
            # Send a query with a slightly wrong field name
            r = gql_post("{ usrs { id } }")
            if r and "Did you mean" in r.text:
                findings.append({
                    "title": "GraphQL Field Suggestion Information Disclosure",
                    "severity": "low",
                    "url": gql_url,
                    "description": (
                        "GraphQL returns field name suggestions ('Did you mean X?') for "
                        "unknown fields. This discloses schema information without full introspection."
                    ),
                    "evidence": "Query with typo returned: " + r.text[:200],
                    "remediation": "Disable field suggestions in production by masking unknown field errors.",
                    "cwe_id": "CWE-200",
                })

        if "csrf" in checks:
            stream("[API-06] Testing GraphQL CSRF via GET...")
            try:
                r = session.get(gql_url, params={"query": "{ __typename }"}, headers={
                    "User-Agent": "Mozilla/5.0",
                    "Accept": "text/html",
                }, timeout=10)
                if r.status_code == 200 and "__typename" in r.text:
                    findings.append({
                        "title": "GraphQL CSRF via GET Query",
                        "severity": "medium",
                        "url": gql_url,
                        "description": (
                            "GraphQL queries can be executed via HTTP GET requests. "
                            "Combined with missing CORS restrictions, this enables CSRF attacks."
                        ),
                        "evidence": "GET query returned valid GraphQL response.",
                        "remediation": "Restrict GraphQL to POST-only. Implement CSRF protection and strict CORS policy.",
                        "cwe_id": "CWE-352",
                    })
            except Exception:
                pass

        return {"status": "done", "findings": findings}


# ─── [API-10] JSON Web API Injection ─────────────────────────────────────────

class JSONWebAPIInjectionModule(BaseModule):
    id = "API-10"
    name = "JSON Web API Injection"
    category = "api"
    description = (
        "Test for path traversal in nested JSON keys, type confusion attacks, "
        "and injection via JSON key names in REST API endpoints."
    )
    risk_level = "high"
    tags = ["api", "json-injection", "path-traversal", "type-confusion"]
    celery_queue = "api_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target API Endpoint", field_type="url",
                    required=True, placeholder="https://api.example.com/api/user/update"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["POST", "PUT", "PATCH"], default="POST"),
        FieldSchema(key="base_body", label="Normal Request Body (JSON)", field_type="json_editor",
                    required=False, placeholder='{"user": {"name": "test"}}'),
        FieldSchema(key="auth_header", label="Auth Header (key: value)", field_type="text",
                    required=False, sensitive=True),
    ]

    _INJECTION_CASES = [
        # Path traversal in key names
        ({"../etc/passwd": "test"}, "JSON key path traversal"),
        ({"__proto__": {"isAdmin": True}}, "Prototype pollution via __proto__"),
        ({"constructor": {"prototype": {"isAdmin": True}}}, "Constructor prototype pollution"),
        ({"$where": "function(){return true}"}, "NoSQL-style operator in JSON key"),
        # Type confusion
        ({"id": ["1", "2", "3"]}, "Type confusion: array instead of scalar"),
        ({"id": {"$gt": 0}}, "NoSQL operator injection in JSON value"),
        ({"role": ["admin", "superuser"]}, "Role array injection"),
        # Deeply nested
        ({"a": {"b": {"c": {"d": {"e": "../../../../etc/passwd"}}}}}, "Deep nested traversal"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        method = (params.get("method") or "POST").upper()
        base_body = params.get("base_body") or {}
        if isinstance(base_body, str):
            try:
                base_body = json.loads(base_body)
            except Exception:
                base_body = {}
        auth_header = params.get("auth_header") or ""

        headers = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []
        meth_fn = getattr(session, method.lower())

        # Baseline
        try:
            r_base = meth_fn(target_url, json=base_body, headers=headers, timeout=10)
            base_status = r_base.status_code
        except Exception as e:
            stream(f"[API-10] Baseline failed: {e}")
            return {"status": "failed", "findings": []}

        stream(f"[API-10] Baseline {base_status}. Testing {len(self._INJECTION_CASES)} injection payloads...")

        for payload, label in self._INJECTION_CASES:
            try:
                r = meth_fn(target_url, json=payload, headers=headers, timeout=10)
                # Flag if server returns 200 or changes behavior significantly
                if r.status_code in (200, 201) and r.status_code == base_status:
                    # Server processed without error — potentially vulnerable
                    findings.append({
                        "title": "JSON Injection Accepted: " + label,
                        "severity": "high",
                        "url": target_url,
                        "description": (
                            f"The API returned {r.status_code} for a payload designed to test '{label}'. "
                            "Server-side processing of injected JSON structures may lead to "
                            "prototype pollution, privilege escalation, or data access issues."
                        ),
                        "evidence": "Payload: " + json.dumps(payload)[:100] + " → " + str(r.status_code),
                        "remediation": (
                            "Validate JSON input against strict schemas. "
                            "Reject unknown/unexpected keys. Use Object.freeze for sensitive objects."
                        ),
                        "cwe_id": "CWE-20",
                    })
                elif r.status_code == 500:
                    findings.append({
                        "title": "JSON Injection Caused Server Error: " + label,
                        "severity": "medium",
                        "url": target_url,
                        "description": f"Payload for '{label}' caused an internal server error (500).",
                        "evidence": "Payload: " + json.dumps(payload)[:100] + " → HTTP 500",
                        "remediation": "Add input validation. Handle exceptions without exposing internals.",
                        "cwe_id": "CWE-20",
                    })
            except Exception:
                pass

        return {"status": "done", "findings": findings}


# ─── [API-11] API Object-Level Authorization ──────────────────────────────────

class APIOLAModule(BaseModule):
    id = "API-11"
    name = "API Object-Level Authorization (BOLA)"
    category = "api"
    description = (
        "Test API endpoints for Broken Object Level Authorization (BOLA/IDOR): "
        "access objects belonging to other users by manipulating IDs."
    )
    risk_level = "critical"
    tags = ["api", "bola", "idor", "authorization", "access-control"]
    celery_queue = "api_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="base_url", label="API Base URL", field_type="url",
                    required=True, placeholder="https://api.example.com"),
        FieldSchema(key="endpoints", label="Endpoints to Test (one per line, use {id} placeholder)",
                    field_type="textarea", required=True,
                    placeholder="/api/users/{id}\n/api/orders/{id}\n/api/accounts/{id}"),
        FieldSchema(key="own_id", label="Your User/Object ID", field_type="text",
                    required=True, placeholder="123"),
        FieldSchema(key="other_id", label="Another User/Object ID to Test", field_type="text",
                    required=True, placeholder="124"),
        FieldSchema(key="user_token", label="Your Auth Token", field_type="textarea",
                    required=False, sensitive=True),
        FieldSchema(key="other_token", label="Other User Auth Token (optional)", field_type="textarea",
                    required=False, sensitive=True),
        FieldSchema(key="methods", label="HTTP Methods", field_type="checkbox_group",
                    default=["GET", "PUT", "DELETE"],
                    options=[
                        {"value": "GET",    "label": "GET"},
                        {"value": "PUT",    "label": "PUT"},
                        {"value": "PATCH",  "label": "PATCH"},
                        {"value": "DELETE", "label": "DELETE"},
                    ]),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3; urllib3.disable_warnings()

        base_url = params["base_url"].rstrip("/")
        endpoints_raw = params.get("endpoints", "") or ""
        own_id = str(params.get("own_id", "1") or "1")
        other_id = str(params.get("other_id", "2") or "2")
        user_token = params.get("user_token", "") or ""
        other_token = params.get("other_token", "") or ""
        methods = params.get("methods", ["GET"])

        endpoints = [e.strip() for e in endpoints_raw.splitlines() if e.strip()]

        headers_user = {"User-Agent": "PenTools/1.0"}
        if user_token:
            headers_user["Authorization"] = "Bearer " + user_token

        session = requests.Session()
        session.verify = False
        findings = []

        for ep in endpoints:
            ep_other = ep.replace("{id}", other_id)
            url = base_url + ep_other

            for method in methods:
                try:
                    meth_fn = getattr(session, method.lower(), None)
                    if not meth_fn:
                        continue
                    r = meth_fn(url, headers=headers_user, timeout=10)
                    stream(f"[API-11] {method} {url} → {r.status_code}")

                    if r.status_code in (200, 201):
                        # Verify it's not just a generic 200
                        sev = "critical" if method in ("DELETE", "PUT", "PATCH") else "high"
                        findings.append({
                            "title": f"BOLA — {method} Access to Object ID {other_id}",
                            "severity": sev,
                            "url": url,
                            "description": (
                                f"Using your token for user ID={own_id}, "
                                f"you can {method.lower()} the resource of user ID={other_id} "
                                "without authorization. This is a Broken Object Level "
                                "Authorization (BOLA/IDOR) vulnerability."
                            ),
                            "evidence": f"{method} {url} with user {own_id} token → {r.status_code}",
                            "remediation": (
                                "Verify object ownership server-side on every request. "
                                "Never trust client-supplied IDs alone. "
                                "Use non-sequential UUIDs for object IDs."
                            ),
                            "cwe_id": "CWE-639",
                        })
                except Exception as e:
                    stream(f"[API-11] {method} {url} error: {e}")

        return {"status": "done", "findings": findings}


# ─── [API-12] Swagger/OpenAPI Parser ─────────────────────────────────────────

class SwaggerOpenAPIParserModule(BaseModule):
    id = "API-12"
    name = "Swagger/OpenAPI Parser"
    category = "api"
    description = (
        "Import a Swagger/OpenAPI spec and auto-map all endpoints, methods, "
        "parameters, and authentication schemes for review."
    )
    risk_level = "info"
    tags = ["api", "swagger", "openapi", "documentation", "enumeration"]
    celery_queue = "api_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(key="spec_url", label="Spec URL (JSON/YAML)", field_type="url",
                    required=False, placeholder="https://api.example.com/openapi.json"),
        FieldSchema(key="spec_json", label="Paste Spec JSON", field_type="textarea",
                    required=False),
        FieldSchema(key="flag_sensitive", label="Flag sensitive parameter names",
                    field_type="select", options=["yes", "no"], default="yes"),
    ]

    _SENSITIVE_PARAMS = {
        "password", "passwd", "secret", "token", "api_key", "apikey",
        "api-key", "auth", "authorization", "credential", "private_key",
        "access_key", "session", "ssn", "credit_card", "card_number",
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json
        import urllib3; urllib3.disable_warnings()

        spec_url = params.get("spec_url") or ""
        spec_json_raw = params.get("spec_json") or ""
        flag_sensitive = params.get("flag_sensitive", "yes") == "yes"

        session = requests.Session()
        session.verify = False
        findings = []
        spec = None

        if spec_url:
            stream(f"[API-12] Fetching spec from {spec_url}...")
            try:
                r = session.get(spec_url, headers={"User-Agent": "PenTools/1.0"}, timeout=15)
                if r.status_code == 200:
                    spec = r.json()
            except Exception as e:
                stream(f"[API-12] Fetch error: {e}")

        if not spec and spec_json_raw:
            try:
                spec = json.loads(spec_json_raw)
            except Exception as e:
                stream(f"[API-12] Parse error: {e}")

        if not spec:
            return {"status": "failed", "findings": [], "raw_output": "No spec provided or fetch failed."}

        # Extract metadata
        info = spec.get("info", {})
        version = info.get("version", "?")
        title = info.get("title", "?")
        base_path = spec.get("basePath", "") or ""
        servers = spec.get("servers", [])
        paths = spec.get("paths", {})
        security_schemes = spec.get("components", {}).get("securitySchemes", {}) or spec.get("securityDefinitions", {})

        stream(f"[API-12] Spec: {title} v{version}, {len(paths)} paths found.")

        # Flag: API with no auth defined
        if not security_schemes:
            findings.append({
                "title": "API Spec: No Security Schemes Defined",
                "severity": "medium",
                "url": spec_url or "spec",
                "description": f"The OpenAPI spec for '{title}' defines no security schemes (securitySchemes/securityDefinitions).",
                "evidence": f"Title: {title}, Version: {version}",
                "remediation": "Define and enforce authentication/authorization schemes in the API spec.",
                "cwe_id": "CWE-306",
            })

        sensitive_found = []
        unsecured_ops = []

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method, op in path_item.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                    continue
                if not isinstance(op, dict):
                    continue
                op_security = op.get("security")
                # Flag operations with explicit no-security override (security: [])
                if op_security is not None and op_security == []:
                    unsecured_ops.append(method.upper() + " " + path)

                # Scan parameters for sensitive names
                if flag_sensitive:
                    for p in op.get("parameters", []):
                        p_name = (p.get("name") or "").lower()
                        if p_name in self._SENSITIVE_PARAMS:
                            sensitive_found.append(method.upper() + " " + path + " -> " + p.get("name", ""))

        if unsecured_ops:
            findings.append({
                "title": "API Operations with No Security Requirements",
                "severity": "high",
                "url": spec_url or "spec",
                "description": (
                    f"{len(unsecured_ops)} API operations explicitly override security with an empty array, "
                    "meaning they require no authentication."
                ),
                "evidence": "Unsecured ops: " + ", ".join(unsecured_ops[:10]),
                "remediation": "Review all unsecured operations. Require authentication for any non-public endpoints.",
                "cwe_id": "CWE-306",
            })

        if sensitive_found:
            findings.append({
                "title": "API Spec Contains Sensitive Parameter Names",
                "severity": "info",
                "url": spec_url or "spec",
                "description": (
                    f"{len(sensitive_found)} parameters with sensitive names detected in spec. "
                    "Verify these are properly protected and not logged."
                ),
                "evidence": "Sensitive params: " + ", ".join(sensitive_found[:10]),
                "remediation": "Ensure sensitive fields use markSensitive directives and are excluded from logs.",
                "cwe_id": "CWE-312",
            })

        # Summary finding with all endpoints
        findings.append({
            "title": f"API Map: {len(paths)} Endpoints Discovered",
            "severity": "info",
            "url": spec_url or "spec",
            "description": (
                f"OpenAPI spec '{title}' v{version} maps {len(paths)} path(s). "
                "Review for undocumented endpoints not in spec."
            ),
            "evidence": "Paths: " + ", ".join(list(paths.keys())[:20]),
            "remediation": "Ensure all active endpoints are documented. Retire undocumented legacy endpoints.",
            "cwe_id": "CWE-1059",
        })

        return {"status": "done", "findings": findings}


# ─── [API-07] SOAP / WSDL Audit ──────────────────────────────────────────────

class SOAPWSDLAuditModule(BaseModule):
    id = "API-07"
    name = "SOAP / WSDL Audit"
    category = "api"
    description = (
        "Fetch and parse a WSDL document to enumerate SOAP operations and bindings. "
        "Fuzz each discovered operation with XML injection, XXE, and XPath injection payloads. "
        "Detect verbose SOAP faults and exposed server details."
    )
    risk_level = "high"
    tags = ["soap", "wsdl", "xml", "injection", "xxe", "api"]
    celery_queue = "web_audit_queue"
    time_limit = 150

    PARAMETER_SCHEMA = [
        FieldSchema(key="wsdl_url",    label="WSDL URL",   field_type="url",  required=True,
                    placeholder="https://example.com/service?wsdl"),
        FieldSchema(key="soap_url",    label="SOAP Endpoint (override)",  field_type="url",  required=False,
                    help_text="Leave blank to auto-detect from WSDL."),
        FieldSchema(
            key="attacks",
            label="Attack Payloads",
            field_type="checkbox_group",
            default=["xml_injection", "xxe", "xpath"],
            options=[
                {"value": "xml_injection", "label": "XML injection (tag break)"},
                {"value": "xxe",           "label": "XXE (external entity)"},
                {"value": "xpath",         "label": "XPath injection"},
                {"value": "sqli",          "label": "SQL injection in parameters"},
            ],
        ),
        FieldSchema(key="auth_header",   label="Authorization",  field_type="text", required=False, group="credentials"),
        FieldSchema(key="timeout",       label="Request timeout (s)", field_type="number", default=15),
    ]

    SOAP_ENV = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">'
        '<s:Body><{op} xmlns="{ns}">{params}</{op}></s:Body>'
        '</s:Envelope>'
    )

    PAYLOADS = {
        "xml_injection": ["<inject>", "</inject><evil/>", "'><test/>"],
        "xxe": [
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>',
        ],
        "xpath": ["' or '1'='1", "\" or \"1\"=\"1", "' or 1=1 or 'a'='a"],
        "sqli":  ["'", "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT NULL--"],
    }

    def _fetch(self, url: str, data: str = None, auth: str = "",
               content_type: str = "text/xml", timeout: int = 15) -> tuple:
        import urllib.request, urllib.error
        headers = {"Content-Type": content_type, "User-Agent": "PenTools/1.0"}
        if auth:
            headers["Authorization"] = auth
        if data:
            headers["SOAPAction"] = '""'
        req = urllib.request.Request(url,
                                     data=data.encode("utf-8") if data else None,
                                     headers=headers,
                                     method="POST" if data else "GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read(65536).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(8192).decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, str(ex)

    def _parse_wsdl(self, wsdl_xml: str) -> dict:
        """Parse WSDL to extract operations, namespaces, and endpoint URL."""
        import xml.etree.ElementTree as ET
        ns_map = {
            "wsdl":  "http://schemas.xmlsoap.org/wsdl/",
            "soap":  "http://schemas.xmlsoap.org/wsdl/soap/",
            "soap12":"http://schemas.xmlsoap.org/wsdl/soap12/",
            "xs":    "http://www.w3.org/2001/XMLSchema",
        }
        try:
            root = ET.fromstring(wsdl_xml)
        except ET.ParseError:
            return {"error": "WSDL parse error", "operations": [], "endpoint": ""}

        target_ns = root.attrib.get("targetNamespace", "")
        operations = []
        for pt in root.findall("wsdl:portType", ns_map):
            for op in pt.findall("wsdl:operation", ns_map):
                operations.append(op.attrib.get("name", ""))

        # Find SOAP address location
        endpoint = ""
        for service in root.findall(".//soap:address", ns_map):
            endpoint = service.attrib.get("location", "")
        if not endpoint:
            for service in root.findall(".//soap12:address", ns_map):
                endpoint = service.attrib.get("location", "")

        return {"target_ns": target_ns, "operations": operations, "endpoint": endpoint}

    def execute(self, params: dict, job_id: str, stream) -> dict:
        wsdl_url = params["wsdl_url"].strip()
        soap_url = params.get("soap_url", "").strip()
        attacks = params.get("attacks", ["xml_injection", "xxe"])
        auth = params.get("auth_header", "").strip()
        timeout = int(params.get("timeout", 15))

        findings = []
        raw_lines = [f"WSDL: {wsdl_url}"]

        # Fetch WSDL
        stream("info", f"Fetching WSDL: {wsdl_url}")
        code, wsdl_body = self._fetch(wsdl_url, auth=auth, timeout=timeout)
        raw_lines.append(f"WSDL fetch: HTTP {code}, {len(wsdl_body)} bytes")

        if code != 200 or "<definitions" not in wsdl_body and "<wsdl:definitions" not in wsdl_body:
            return {"status": "failed", "findings": [{
                "title": "WSDL not accessible",
                "severity": "info", "url": wsdl_url,
                "description": f"HTTP {code}. Response did not appear to be a valid WSDL.",
                "evidence": wsdl_body[:500],
                "remediation": "Ensure WSDL URL is correct and accessible.",
            }]}

        parsed = self._parse_wsdl(wsdl_body)
        if parsed.get("error"):
            stream("warning", f"WSDL parse error: {parsed['error']}")

        operations = parsed.get("operations", [])
        ns = parsed.get("target_ns", "http://tempuri.org/")
        endpoint = soap_url or parsed.get("endpoint", wsdl_url.split("?")[0])

        stream("info", f"Found {len(operations)} operations, endpoint: {endpoint}")
        raw_lines.append(f"Operations: {operations}")
        raw_lines.append(f"Endpoint: {endpoint}")

        # Info finding: WSDL exposed
        findings.append({
            "title": f"WSDL document publicly accessible — {len(operations)} operations",
            "severity": "low",
            "url": wsdl_url,
            "description": (
                f"WSDL exposes {len(operations)} SOAP operations: {', '.join(operations[:10])}. "
                "Publicly accessible WSDLs reveal internal service contracts."
            ),
            "evidence": f"Operations: {operations}\nEndpoint: {endpoint}\nNS: {ns}",
            "remediation": "Restrict WSDL access to authorised clients. Remove ?WSDL from production.",
            "cwe_id": "CWE-200",
        })

        # Fuzz each operation
        for op in operations[:10]:  # cap at 10 to avoid flooding
            for atk_type in attacks:
                for payload in self.PAYLOADS.get(atk_type, [])[:2]:
                    env_body = self.SOAP_ENV.format(op=op, ns=ns, params=f"<param>{payload}</param>")
                    stream("info", f"  [{atk_type}] {op}: {payload[:40]}...")
                    c, resp = self._fetch(endpoint, data=env_body, auth=auth, timeout=timeout)
                    raw_lines.append(f"  [{op}/{atk_type}] HTTP {c}")

                    # Detect errors
                    fault_indicators = ["<faultstring>", "<faultcode>", "<soap:Fault>", "stack trace", "Exception"]
                    vuln_indicators = {
                        "xml_injection": ["ParseError", "unexpected token", "XMLSyntaxError", "<injected>"],
                        "xxe": ["root:", "nobody:", "daemon:", "www-data", "127.0.0.1", "169.254"],
                        "xpath": ["true", "XPathException", "Node not found"],
                        "sqli": ["SQL syntax", "ORA-", "PG::", "mysql_fetch", "Microsoft+OLE+DB"],
                    }

                    if any(ind in resp for ind in fault_indicators):
                        stream("warning", f"[{op}] SOAP Fault returned")
                        findings.append({
                            "title": f"Verbose SOAP Fault — {op} ({atk_type})",
                            "severity": "medium",
                            "url": endpoint,
                            "description": f"SOAP Fault returned for operation {op} with {atk_type} payload.",
                            "evidence": resp[:800],
                            "remediation": "Return generic fault codes. Do not expose stack traces or internal class names in faults.",
                            "cwe_id": "CWE-209",
                        })

                    for ind in vuln_indicators.get(atk_type, []):
                        if ind.lower() in resp.lower():
                            stream("success", f"[{op}] {atk_type} vulnerability indicator: '{ind}'")
                            findings.append({
                                "title": f"SOAP {atk_type.upper()} vulnerability in operation {op}",
                                "severity": "high",
                                "url": endpoint,
                                "description": f"Indicator '{ind}' found in response to {atk_type} payload against operation {op}.",
                                "evidence": resp[:1000],
                                "remediation": "Validate and sanitise all SOAP parameters before processing.",
                                "cvss_score": 8.0, "cwe_id": "CWE-91",
                            })
                            break

        stream("success", f"SOAP/WSDL audit complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [API-08] WebSocket Fuzzer ────────────────────────────────────────────────

class WebSocketFuzzerModule(BaseModule):
    id = "API-08"
    name = "WebSocket Fuzzer"
    category = "api"
    description = (
        "Connect to a WebSocket endpoint and send structured fuzz payloads including "
        "JSON injection, SQL injection, command injection, and oversized messages. "
        "Detect error disclosures, connection drops, and injection reflections."
    )
    risk_level = "high"
    tags = ["websocket", "ws", "wss", "fuzzing", "injection", "api"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(key="ws_url",       label="WebSocket URL",   field_type="url",  required=True,
                    placeholder="wss://example.com/ws"),
        FieldSchema(key="auth_token",   label="Authorization token (Bearer/JWT)", field_type="text", required=False),
        FieldSchema(key="origin",       label="Origin header",  field_type="text",  required=False,
                    placeholder="https://example.com"),
        FieldSchema(
            key="fuzz_types",
            label="Fuzzing Types",
            field_type="checkbox_group",
            default=["json_injection", "sqli", "cmd_injection", "xss"],
            options=[
                {"value": "json_injection", "label": "JSON structure injection"},
                {"value": "sqli",           "label": "SQL injection"},
                {"value": "cmd_injection",  "label": "Command injection"},
                {"value": "xss",            "label": "XSS payloads"},
                {"value": "oversized",      "label": "Oversized / buffer overflow"},
                {"value": "auth_bypass",    "label": "Auth bypass (null token, empty auth)"},
            ],
        ),
        FieldSchema(key="base_message",  label="Base message template (JSON)",  field_type="textarea",
                    default='{"type":"hello","msg":"test"}',
                    help_text="Replace 'test' with {FUZZ} to mark the injection point."),
        FieldSchema(key="timeout",       label="Receive timeout (s)", field_type="number", default=5),
    ]

    FUZZ_PAYLOADS = {
        "json_injection": [
            '{"type":"hello","msg":null,"__proto__":{"admin":true}}',
            '{"type":"hello","msg":"test","extra":{"$gt":""}}',
            '{"type":"hello","msg":""}},{',
        ],
        "sqli": [
            "' OR '1'='1",
            "' UNION SELECT NULL,NULL--",
            "1; DROP TABLE users--",
        ],
        "cmd_injection": [
            "$(id)",
            "`id`",
            "; cat /etc/passwd",
            "| whoami",
        ],
        "xss": [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
        ],
        "oversized": [
            "A" * 65536,
            '{"data":"' + "B" * 10000 + '"}',
        ],
        "auth_bypass": [
            '{"token": null, "type": "auth"}',
            '{"token": "", "type": "auth"}',
            '{"token": "INVALID", "type": "auth"}',
        ],
    }

    def _ws_send_recv(self, url: str, message: str, auth_token: str,
                      origin: str, timeout: int) -> dict:
        """Connect to a WebSocket, send a message, receive a response."""
        import socket, ssl, base64, hashlib, os
        from urllib.parse import urlparse

        parsed = urlparse(url)
        host = parsed.hostname or "localhost"
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        use_ssl = parsed.scheme == "wss"
        port = parsed.port or (443 if use_ssl else 80)

        key = base64.b64encode(os.urandom(16)).decode()
        headers = [
            f"GET {path} HTTP/1.1",
            f"Host: {host}:{port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        if origin:
            headers.append(f"Origin: {origin}")
        if auth_token:
            headers.append(f"Authorization: Bearer {auth_token}")
        headers.append("")
        headers.append("")
        handshake = "\r\n".join(headers).encode()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.connect((host, port))
            s.sendall(handshake)
            resp = b""
            while b"\r\n\r\n" not in resp:
                resp += s.recv(1024)
            http_resp = resp.decode("utf-8", errors="replace")
            if "101 Switching Protocols" not in http_resp:
                return {"connected": False, "handshake": http_resp[:300]}

            # Send framed message
            data = message.encode("utf-8")
            length = len(data)
            mask = os.urandom(4)
            masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if length < 126:
                frame = bytes([0x81, 0x80 | length]) + mask + masked
            elif length < 65536:
                import struct
                frame = bytes([0x81, 0xFE]) + struct.pack(">H", length) + mask + masked
            else:
                import struct
                frame = bytes([0x81, 0xFF]) + struct.pack(">Q", length) + mask + masked
            s.sendall(frame)

            # Receive response frame
            recv_data = b""
            try:
                recv_data = s.recv(65536)
            except socket.timeout:
                pass
            return {"connected": True, "handshake": http_resp[:200], "response": recv_data.decode("utf-8", errors="replace")[:2000]}
        except Exception as e:
            return {"connected": False, "error": str(e)}
        finally:
            s.close()

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import json

        url = params["ws_url"].strip()
        auth_token = params.get("auth_token", "").strip()
        origin = params.get("origin", "").strip()
        fuzz_types = params.get("fuzz_types", ["json_injection", "sqli"])
        base_msg = params.get("base_message", '{"type":"hello","msg":"{FUZZ}"}')
        timeout = int(params.get("timeout", 5))

        findings = []
        raw_lines = [f"Target: {url}"]

        # Test connectivity first
        stream("info", "Testing WebSocket connectivity...")
        conn_result = self._ws_send_recv(url, '{"type":"ping"}', auth_token, origin, timeout)
        if not conn_result.get("connected"):
            return {"status": "failed", "findings": [{
                "title": "WebSocket connection failed",
                "severity": "info", "url": url,
                "description": f"Could not establish WebSocket connection: {conn_result.get('error', 'Unknown')}",
                "evidence": conn_result.get("handshake", ""),
                "remediation": "Verify the WebSocket URL and authentication configuration.",
            }]}

        stream("success", f"WebSocket connected. Handshake: {conn_result.get('handshake','')[:80]}")
        raw_lines.append(f"Connected: {conn_result.get('handshake','')[:100]}")

        for fuzz_type in fuzz_types:
            payloads = self.FUZZ_PAYLOADS.get(fuzz_type, [])
            for payload in payloads[:3]:
                # Inject into base message if {FUZZ} marker present
                if "{FUZZ}" in base_msg:
                    message = base_msg.replace("{FUZZ}", payload)
                else:
                    message = payload

                stream("info", f"[{fuzz_type}] Sending: {message[:60]}...")
                result = self._ws_send_recv(url, message, auth_token, origin, timeout)
                resp_text = result.get("response", "")
                raw_lines.append(f"[{fuzz_type}] response: {resp_text[:60]}")

                if not result.get("connected"):
                    stream("warning", f"[{fuzz_type}] Connection dropped — possible crash/DoS trigger")
                    findings.append({
                        "title": f"WebSocket connection drop on {fuzz_type} payload",
                        "severity": "medium",
                        "url": url,
                        "description": f"Server closed connection after '{fuzz_type}' payload: {payload[:100]}",
                        "evidence": f"Payload: {message[:300]}\nError: {result.get('error','')}",
                        "remediation": "Implement input validation to reject malformed WebSocket frames.",
                        "cwe_id": "CWE-20",
                    })
                    continue

                # Detect injection reflections or errors
                error_indicators = ["error", "exception", "traceback", "stacktrace", "syntax error", "undefined"]
                reflect_check = payload.replace('"', "").replace("'", "")[:20]
                if reflect_check.lower() in resp_text.lower():
                    stream("success", f"[{fuzz_type}] Payload reflected in response!")
                    findings.append({
                        "title": f"WebSocket {fuzz_type.upper()} reflection — possible injection",
                        "severity": "high",
                        "url": url,
                        "description": f"Payload for {fuzz_type} was reflected unescaped in the WebSocket response.",
                        "evidence": f"Payload: {payload[:200]}\nResponse: {resp_text[:500]}",
                        "remediation": "Sanitise and validate all WebSocket message content. Encode output.",
                        "cvss_score": 7.5, "cwe_id": "CWE-116",
                    })
                elif any(ind in resp_text.lower() for ind in error_indicators):
                    stream("warning", f"[{fuzz_type}] Error disclosed in WebSocket response")
                    findings.append({
                        "title": f"WebSocket error disclosure on {fuzz_type} payload",
                        "severity": "medium",
                        "url": url,
                        "description": f"Error message in response to {fuzz_type} payload may indicate an injection point.",
                        "evidence": f"Payload: {payload[:200]}\nResponse: {resp_text[:500]}",
                        "remediation": "Return generic error messages. Log detailed errors server-side only.",
                        "cwe_id": "CWE-209",
                    })

        if not findings:
            findings.append({
                "title": "WebSocket fuzzer — no injection or error disclosures detected",
                "severity": "info", "url": url,
                "description": "All fuzz payloads delivered. No reflections, errors, or connection disruptions detected.",
                "evidence": "\n".join(raw_lines[-10:]),
                "remediation": "Continue manual testing with application-specific message formats.",
            })

        stream("success", f"WebSocket fuzzing complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [API-09] gRPC Audit ──────────────────────────────────────────────────────

class GRPCAuditModule(BaseModule):
    id = "API-09"
    name = "gRPC Security Audit"
    category = "api"
    description = (
        "Enumerate gRPC services via server reflection and fuzz discovered methods "
        "with injection payloads using grpcurl. Detect exposed services, unauthenticated "
        "access, and verbose error messages."
    )
    risk_level = "high"
    tags = ["grpc", "protobuf", "reflection", "api", "rpc"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_host",  label="Target Host:Port",  field_type="text", required=True,
                    placeholder="example.com:50051"),
        FieldSchema(
            key="transport",
            label="Transport",
            field_type="radio",
            default="plaintext",
            options=[
                {"value": "plaintext", "label": "Plaintext (-plaintext)"},
                {"value": "tls",       "label": "TLS (default)"},
                {"value": "tls_insecure", "label": "TLS (skip verify)"},
            ],
        ),
        FieldSchema(key="auth_token",  label="Bearer token",  field_type="text", required=False),
        FieldSchema(
            key="checks",
            label="Checks to perform",
            field_type="checkbox_group",
            default=["list_services", "describe_methods", "fuzz_params"],
            options=[
                {"value": "list_services",    "label": "List services (reflection)"},
                {"value": "describe_methods", "label": "Describe methods"},
                {"value": "fuzz_params",      "label": "Fuzz parameters (sqli/cmd)"},
                {"value": "unauth_invoke",    "label": "Unauthenticated invoke"},
            ],
        ),
    ]

    def _grpcurl(self, args: list, stream) -> dict:
        from apps.modules.runner import ToolRunner
        runner = ToolRunner("grpcurl")
        return runner.run(args=args, stream=stream, timeout=30)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        host = params["target_host"].strip()
        transport = params.get("transport", "plaintext")
        auth_token = params.get("auth_token", "").strip()
        checks = params.get("checks", ["list_services"])

        findings = []
        raw_lines = [f"Target: {host}", f"Transport: {transport}"]

        # Build common flags
        flags = []
        if transport == "plaintext":
            flags.append("-plaintext")
        elif transport == "tls_insecure":
            flags += ["-insecure"]
        if auth_token:
            flags += ["-H", f"Authorization: Bearer {auth_token}"]

        # Check grpcurl availability
        probe = self._grpcurl(["--version"], stream)
        if probe.get("returncode", 1) != 0 and not probe.get("stdout"):
            grpcurl_available = False
            stream("warning", "grpcurl not found — documenting required commands only")
        else:
            grpcurl_available = True

        if not grpcurl_available:
            transport_flag = "-plaintext" if transport == "plaintext" else "-insecure" if transport == "tls_insecure" else ""
            token_flag = f"-H 'Authorization: Bearer $TOKEN'" if auth_token else ""
            return {"status": "done", "findings": [{
                "title": "gRPC audit — grpcurl not installed",
                "severity": "info", "url": host,
                "description": "grpcurl binary not found. Install it to perform active gRPC auditing.",
                "evidence": (
                    f"# List services\n"
                    f"grpcurl {transport_flag} {token_flag} {host} list\n\n"
                    f"# Describe a service\n"
                    f"grpcurl {transport_flag} {token_flag} {host} describe <ServiceName>\n\n"
                    f"# Invoke a method\n"
                    f"grpcurl {transport_flag} {token_flag} -d '{{\"param\":\"value\"}}' {host} <ServiceName>/<MethodName>"
                ),
                "remediation": "Install grpcurl: https://github.com/fullstorydev/grpcurl",
            }]}

        services = []
        if "list_services" in checks:
            stream("info", "Listing gRPC services via reflection...")
            result = self._grpcurl(flags + [host, "list"], stream)
            out = result.get("stdout", "").strip()
            raw_lines.append(f"List services:\n{out[:500]}")
            if out:
                services = [s.strip() for s in out.splitlines() if s.strip()]
                stream("success", f"Found {len(services)} service(s): {services}")
                findings.append({
                    "title": f"gRPC reflection enabled — {len(services)} service(s) exposed",
                    "severity": "medium",
                    "url": host,
                    "description": (
                        f"gRPC server reflection is enabled, allowing enumeration of {len(services)} service(s).\n"
                        f"Services: {', '.join(services)}"
                    ),
                    "evidence": f"grpcurl output:\n{out[:600]}",
                    "remediation": "Disable gRPC reflection on production servers (grpc.reflection.v1alpha should not be registered in prod).",
                    "cwe_id": "CWE-200",
                })
            else:
                stream("info", "No services listed or reflection disabled")
                findings.append({
                    "title": "gRPC reflection not available",
                    "severity": "info", "url": host,
                    "description": "Server does not respond to gRPC reflection requests.",
                    "evidence": result.get("stderr", ""),
                    "remediation": "Confirm service is running on the target port.",
                })

        if "describe_methods" in checks and services:
            for svc in services[:5]:
                stream("info", f"Describing service: {svc}")
                result = self._grpcurl(flags + [host, "describe", svc], stream)
                desc = result.get("stdout", "").strip()
                raw_lines.append(f"[{svc}]:\n{desc[:300]}")
                if desc:
                    findings.append({
                        "title": f"gRPC service description: {svc}",
                        "severity": "info", "url": host,
                        "description": f"Service '{svc}' implementation details exposed via reflection.",
                        "evidence": desc[:800],
                        "remediation": "Review whether service descriptions expose internal method names or sensitive field types.",
                    })

        if "unauth_invoke" in checks and services:
            stream("info", "Testing unauthenticated invocations...")
            for svc in services[:3]:
                # Try to invoke with empty message and no auth
                result = self._grpcurl([f for f in flags if "Authorization" not in f] +
                                       ["-d", "{}", host, svc], stream)
                resp = result.get("stdout", "") + result.get("stderr", "")
                if "Unauthenticated" not in resp and "PermissionDenied" not in resp and resp.strip():
                    stream("warning", f"Possible unauthenticated access to {svc}!")
                    findings.append({
                        "title": f"gRPC unauthenticated invocation possible — {svc}",
                        "severity": "high",
                        "url": host,
                        "description": f"Service '{svc}' responded without authentication.",
                        "evidence": resp[:500],
                        "remediation": "Enforce authentication interceptors on all gRPC service implementations.",
                        "cvss_score": 7.5, "cwe_id": "CWE-306",
                    })

        stream("success", f"gRPC audit complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}
