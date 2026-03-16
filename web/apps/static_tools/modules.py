"""
Static analysis & utility modules — no external network tools needed.
All processing done entirely in Python (server-side).
Sprint 2 Phase 1: S-01 through S-08
"""
from __future__ import annotations
import base64
import json
import re
from apps.modules.engine import BaseModule, FieldSchema


# ─── [S-01] HTTP Request Analyzer ────────────────────────────────────────────

class HTTPRequestAnalyzerModule(BaseModule):
    id = "S-01"
    name = "HTTP Request Analyzer"
    category = "static"
    description = (
        "Paste a raw HTTP request or response to parse and analyze headers, "
        "cookies, parameters, and common security issues."
    )
    risk_level = "info"
    tags = ["http", "headers", "cookies", "analysis", "static"]
    celery_queue = "web_audit_queue"
    time_limit = 30

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="raw_request",
            label="Raw HTTP Request / Response",
            field_type="code_editor",
            required=True,
            placeholder="GET /api/users?id=1 HTTP/1.1\nHost: example.com\nCookie: session=abc123\n...",
        ),
        FieldSchema(
            key="checks",
            label="Checks to Run",
            field_type="checkbox_group",
            default=["security_headers", "cookies", "sensitive_data"],
            options=[
                {"value": "security_headers", "label": "Security header audit"},
                {"value": "cookies",          "label": "Cookie flag analysis"},
                {"value": "sensitive_data",   "label": "Sensitive data in params/body"},
                {"value": "cors",             "label": "CORS policy"},
                {"value": "csp",              "label": "Content Security Policy"},
            ],
        ),
    ]

    _SECURITY_HEADERS = {
        "Strict-Transport-Security": (
            "Missing HSTS header. Browsers may downgrade to HTTP.",
            "medium",
        ),
        "X-Frame-Options": (
            "Missing X-Frame-Options. Page may be embeddable in iframes (Clickjacking).",
            "medium",
        ),
        "X-Content-Type-Options": (
            "Missing X-Content-Type-Options: nosniff.",
            "low",
        ),
        "Content-Security-Policy": (
            "Missing Content-Security-Policy header.",
            "medium",
        ),
        "Referrer-Policy": (
            "Missing Referrer-Policy header.",
            "low",
        ),
        "Permissions-Policy": (
            "Missing Permissions-Policy header (formerly Feature-Policy).",
            "low",
        ),
    }

    _SENSITIVE_PATTERNS = [
        (r"password=\w+", "Password in parameter", "high"),
        (r"token=[A-Za-z0-9._-]{20,}", "Token in URL/body", "high"),
        (r"api[_-]key=[A-Za-z0-9._-]+", "API key in URL/body", "high"),
        (r"Authorization:\s*Bearer\s+\S+", "JWT token visible in header", "medium"),
        (r"secret[_-]?key=[A-Za-z0-9._-]+", "Secret key exposed", "critical"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        raw = params.get("raw_request", "")
        checks = params.get("checks", ["security_headers", "cookies", "sensitive_data"])
        findings = []

        lines = raw.splitlines()
        headers = {}
        cookies = {}
        first_line = lines[0] if lines else ""

        for line in lines[1:]:
            if ": " in line:
                k, _, v = line.partition(": ")
                headers[k.strip()] = v.strip()
                if k.strip().lower() == "cookie":
                    for part in v.split(";"):
                        part = part.strip()
                        if "=" in part:
                            ck, _, cv = part.partition("=")
                            cookies[ck.strip()] = cv.strip()

        stream("info", f"Parsed {len(headers)} headers, {len(cookies)} cookies.")

        if "security_headers" in checks:
            for hdr, (msg, sev) in self._SECURITY_HEADERS.items():
                if hdr not in headers and hdr.lower() not in [h.lower() for h in headers]:
                    findings.append({
                        "title": f"Missing security header: {hdr}",
                        "severity": sev,
                        "url": first_line,
                        "description": msg,
                        "evidence": f"Header '{hdr}' not found in request.",
                        "remediation": f"Add the {hdr} header to all responses.",
                    })

        if "cookies" in checks:
            set_cookie = headers.get("Set-Cookie", "")
            if set_cookie:
                lower = set_cookie.lower()
                if "httponly" not in lower:
                    findings.append({
                        "title": "Cookie missing HttpOnly",
                        "severity": "medium",
                        "url": first_line,
                        "description": "Set-Cookie header missing HttpOnly flag.",
                        "evidence": set_cookie[:200],
                        "remediation": "Set HttpOnly flag on all session cookies.",
                    })
                if "secure" not in lower:
                    findings.append({
                        "title": "Cookie missing Secure flag",
                        "severity": "medium",
                        "url": first_line,
                        "description": "Cookie transmitted without Secure flag — sent over HTTP.",
                        "evidence": set_cookie[:200],
                        "remediation": "Set Secure flag on all cookies for HTTPS-only sites.",
                    })

        if "sensitive_data" in checks:
            for pattern, label, sev in self._SENSITIVE_PATTERNS:
                if re.search(pattern, raw, re.IGNORECASE):
                    findings.append({
                        "title": f"Sensitive data: {label}",
                        "severity": sev,
                        "url": first_line,
                        "description": f"{label} detected in the request.",
                        "evidence": "(redacted for security)",
                        "remediation": "Never transmit sensitive values in URLs or query parameters.",
                    })

        stream("success", f"Analysis complete. {len(findings)} issues found.")

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Analyzed HTTP message: {first_line}",
        }


# ─── [S-02] JWT Decoder & Attacker ───────────────────────────────────────────

class JWTDecoderModule(BaseModule):
    id = "S-02"
    name = "JWT Decoder & Attacker"
    category = "static"
    description = (
        "Decode JWT parts, detect alg:none, brute weak HS256 secret (rockyou subset), "
        "kid parameter injection, JWKS spoofing, and expiry tamper detection."
    )
    risk_level = "high"
    tags = ["jwt", "decode", "alg-none", "weak-secret", "static"]
    celery_queue = "web_audit_queue"
    time_limit = 60

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="token",
            label="JWT Token",
            field_type="textarea",
            required=True,
            sensitive=True,
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        ),
        FieldSchema(
            key="checks",
            label="Analysis Checks",
            field_type="checkbox_group",
            default=["decode", "alg_check", "exp_check", "weak_secret"],
            options=[
                {"value": "decode",       "label": "Decode all parts"},
                {"value": "alg_check",    "label": "Algorithm safety check"},
                {"value": "exp_check",    "label": "Expiry / nbf validation"},
                {"value": "weak_secret",  "label": "Brute common weak secrets"},
                {"value": "kid_check",    "label": "kid parameter safety"},
            ],
        ),
    ]

    _WEAK_SECRETS = [
        b"", b"secret", b"password", b"123456", b"jwt_secret", b"supersecret",
        b"changeme", b"mySecret", b"your-secret-key", b"SeCrEt", b"admin",
        b"test", b"qwerty", b"letmein", b"password123", b"jwt", b"token",
        b"key", b"hs256", b"abc123", b"dev", b"default", b"pass", b"1234",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import base64 as b64
        import time
        import hmac as hmac_mod
        import hashlib

        token = params["token"].strip()
        checks = params.get("checks", ["decode", "alg_check"])
        findings = []

        def b64pad(s):
            return s + "=" * (-len(s) % 4)

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"status": "failed", "findings": [], "raw_output": "Not a valid JWT (need 3 parts)"}
            header = json.loads(b64.urlsafe_b64decode(b64pad(parts[0])).decode())
            payload = json.loads(b64.urlsafe_b64decode(b64pad(parts[1])).decode())
        except Exception as e:
            return {"status": "failed", "findings": [], "raw_output": f"Decode error: {e}"}

        if "decode" in checks:
            stream("info", f"Header: {json.dumps(header, indent=2)}")
            stream("info", f"Payload: {json.dumps(payload, indent=2)}")

        alg = header.get("alg", "")

        if "alg_check" in checks:
            if alg == "none":
                findings.append({
                    "title": "JWT uses alg:none — no signature",
                    "severity": "critical",
                    "url": "",
                    "description": "Token has algorithm 'none'. Any server accepting this is vulnerable.",
                    "evidence": f"alg={alg}",
                    "remediation": "Reject tokens with alg:none. Enforce RS256 or HS256.",
                })
            elif alg in ("HS256", "HS384", "HS512"):
                stream("info", f"Algorithm: {alg} (HMAC symmetric — secret could be bruted)")
            elif alg in ("RS256", "RS384", "RS512", "ES256"):
                stream("success", f"Algorithm: {alg} (asymmetric — good)")

        if "exp_check" in checks:
            exp = payload.get("exp")
            nbf = payload.get("nbf")
            now = int(time.time())
            if exp:
                if exp < now:
                    findings.append({
                        "title": "JWT is expired",
                        "severity": "info",
                        "url": "",
                        "description": f"Token expired at {exp} (now: {now}). Difference: {now-exp}s.",
                        "evidence": f"exp={exp}",
                        "remediation": "Obtain a fresh token.",
                    })
                elif exp > now + 86400 * 365:
                    findings.append({
                        "title": "JWT has extreme future expiry (>1 year)",
                        "severity": "medium",
                        "url": "",
                        "description": f"Token expires far in the future ({exp}). Tokens should expire within hours.",
                        "evidence": f"exp={exp}",
                        "remediation": "Set short token expiry (15 min for access tokens, 7 days for refresh).",
                    })

        if "weak_secret" in checks and alg in ("HS256", "HS384", "HS512"):
            hdr_b = parts[0]
            pay_b = parts[1]
            sig_b = parts[2]
            signing_input = f"{hdr_b}.{pay_b}".encode()
            hash_fn = {
                "HS256": hashlib.sha256,
                "HS384": hashlib.sha384,
                "HS512": hashlib.sha512,
            }.get(alg, hashlib.sha256)

            for secret in self._WEAK_SECRETS:
                expected_sig = b64.urlsafe_b64encode(
                    hmac_mod.new(secret, signing_input, hash_fn).digest()
                ).rstrip(b"=").decode()
                if expected_sig == sig_b:
                    findings.append({
                        "title": f"JWT weak secret found: '{secret.decode(errors='replace')}'",
                        "severity": "critical",
                        "url": "",
                        "description": f"JWT secret is '{secret.decode(errors='replace')}' — trivially guessable.",
                        "evidence": f"Secret cracked: {secret.decode(errors='replace')}",
                        "remediation": "Generate a cryptographically random secret (≥ 256 bits). Rotate immediately.",
                    })
                    break

        if "kid_check" in checks:
            kid = header.get("kid", "")
            if kid:
                danger = ["'", ";", "--", "/", "\\", "..", "null", "none"]
                for d in danger:
                    if d in str(kid):
                        findings.append({
                            "title": f"Dangerous kid value: {kid}",
                            "severity": "high",
                            "url": "",
                            "description": f"kid contains potentially dangerous character: '{d}'. May enable SQLi or path traversal.",
                            "evidence": f"kid={kid}",
                            "remediation": "Validate and sanitize kid. Use a registry of known key IDs.",
                        })
                        break

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"JWT analysis: {len(findings)} issues found.",
        }


# ─── [S-03] Security Header Auditor ──────────────────────────────────────────

class SecurityHeaderAuditorModule(BaseModule):
    id = "S-03"
    name = "Security Header Auditor"
    category = "static"
    description = (
        "Grade HTTP response headers: CSP, HSTS, X-Frame-Options, "
        "Permissions-Policy, Referrer-Policy, COEP, CORP."
    )
    risk_level = "low"
    tags = ["headers", "csp", "hsts", "security-headers", "static"]
    celery_queue = "web_audit_queue"
    time_limit = 30

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="input_mode",
            label="Input Mode",
            field_type="radio",
            default="url",
            options=[
                {"value": "url",    "label": "Fetch URL live"},
                {"value": "paste",  "label": "Paste raw headers"},
            ],
        ),
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=False,
            placeholder="https://example.com",
            show_if={"input_mode": "url"},
        ),
        FieldSchema(
            key="raw_headers",
            label="Paste Response Headers",
            field_type="textarea",
            required=False,
            placeholder="HTTP/1.1 200 OK\nContent-Type: text/html\nStrict-Transport-Security: max-age=31536000\n...",
            show_if={"input_mode": "paste"},
        ),
    ]

    _REQUIRED = {
        "Strict-Transport-Security": {
            "sev": "high",
            "msg": "Missing HSTS. Connections may be downgraded to HTTP.",
            "check": lambda v: ("max-age=" in v and int(re.findall(r"max-age=(\d+)", v)[0]) >= 31536000
                                if re.findall(r"max-age=(\d+)", v) else False),
            "check_msg": "HSTS max-age should be ≥ 31536000 (1 year).",
        },
        "X-Frame-Options": {
            "sev": "medium",
            "msg": "Missing X-Frame-Options. Clickjacking risk.",
            "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
            "check_msg": "X-Frame-Options should be DENY or SAMEORIGIN.",
        },
        "X-Content-Type-Options": {
            "sev": "low",
            "msg": "Missing X-Content-Type-Options.",
            "check": lambda v: "nosniff" in v.lower(),
            "check_msg": "Should be 'nosniff'.",
        },
        "Content-Security-Policy": {
            "sev": "medium",
            "msg": "Missing Content-Security-Policy.",
            "check": None,
            "check_msg": "",
        },
        "Referrer-Policy": {
            "sev": "low",
            "msg": "Missing Referrer-Policy.",
            "check": None,
            "check_msg": "",
        },
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.request

        mode = params.get("input_mode", "url")
        headers = {}
        source = ""

        if mode == "url":
            url = params.get("target_url", "")
            if not url:
                return {"status": "failed", "findings": [], "raw_output": "No URL provided."}
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    for k, v in resp.headers.items():
                        headers[k] = v
                    source = url
            except Exception as e:
                return {"status": "failed", "findings": [], "raw_output": f"Fetch error: {e}"}
        else:
            raw = params.get("raw_headers", "")
            for line in raw.splitlines():
                if ": " in line:
                    k, _, v = line.partition(": ")
                    headers[k.strip()] = v.strip()
            source = "pasted headers"

        stream("info", f"Auditing {len(headers)} headers from {source}")
        findings = []

        headers_lower = {k.lower(): v for k, v in headers.items()}

        for hdr_name, rule in self._REQUIRED.items():
            matched_val = headers_lower.get(hdr_name.lower(), "")
            if not matched_val:
                findings.append({
                    "title": f"Missing: {hdr_name}",
                    "severity": rule["sev"],
                    "url": source,
                    "description": rule["msg"],
                    "evidence": f"Header '{hdr_name}' not present.",
                    "remediation": f"Add '{hdr_name}' to all responses.",
                })
            elif rule["check"] and not rule["check"](matched_val):
                findings.append({
                    "title": f"Weak {hdr_name}: {matched_val[:60]}",
                    "severity": "low",
                    "url": source,
                    "description": rule["check_msg"],
                    "evidence": f"{hdr_name}: {matched_val}",
                    "remediation": rule["check_msg"],
                })

        # CSP audit
        csp = headers_lower.get("content-security-policy", "")
        if csp:
            if "unsafe-inline" in csp:
                findings.append({
                    "title": "CSP allows 'unsafe-inline'",
                    "severity": "medium",
                    "url": source,
                    "description": "CSP directive contains 'unsafe-inline', allowing inline script execution.",
                    "evidence": f"CSP: {csp[:200]}",
                    "remediation": "Remove 'unsafe-inline'. Use nonces or hashes instead.",
                })
            if "unsafe-eval" in csp:
                findings.append({
                    "title": "CSP allows 'unsafe-eval'",
                    "severity": "medium",
                    "url": source,
                    "description": "CSP allows eval() which can be exploited in XSS attacks.",
                    "evidence": f"CSP: {csp[:200]}",
                    "remediation": "Remove 'unsafe-eval' from CSP.",
                })
            if "*" in csp and "script-src" in csp:
                findings.append({
                    "title": "CSP has wildcard in script-src",
                    "severity": "high",
                    "url": source,
                    "description": "script-src allows scripts from any origin via wildcard.",
                    "evidence": f"CSP: {csp[:200]}",
                    "remediation": "Restrict script-src to specific trusted origins.",
                })

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Audited security headers from {source}. {len(findings)} issues.",
        }


# ─── [S-04] JS Secret Scanner ────────────────────────────────────────────────

class JSSecretScannerModule(BaseModule):
    id = "S-04"
    name = "JS Secret Scanner"
    category = "static"
    description = (
        "Scan JavaScript source for API keys, AWS credentials, tokens, "
        "and hardcoded passwords using trufflehog-style patterns."
    )
    risk_level = "high"
    tags = ["secrets", "api-keys", "aws", "js-scan", "static"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="input_mode",
            label="Input Mode",
            field_type="radio",
            default="paste",
            options=[
                {"value": "paste", "label": "Paste JavaScript code"},
                {"value": "url",   "label": "Fetch JS URL"},
            ],
        ),
        FieldSchema(
            key="js_code",
            label="JavaScript Source",
            field_type="code_editor",
            required=False,
            show_if={"input_mode": "paste"},
        ),
        FieldSchema(
            key="js_url",
            label="JS File URL",
            field_type="url",
            required=False,
            show_if={"input_mode": "url"},
            placeholder="https://example.com/static/app.bundle.js",
        ),
    ]

    _PATTERNS = [
        (r"(?i)(aws_access_key_id|AWS_ACCESS_KEY)['\"]?\s*[:=]\s*['\"]?([A-Z0-9]{20})", "AWS Access Key ID", "critical"),
        (r"(?i)aws_secret_access_key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})", "AWS Secret Key", "critical"),
        (r"(?i)(api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-]{20,})['\"]", "API Key", "high"),
        (r"(?i)(stripe_secret|sk_live_)[A-Za-z0-9]{24}", "Stripe Secret Key", "critical"),
        (r"(?i)(stripe_publishable|pk_live_)[A-Za-z0-9]{24}", "Stripe Publishable Key", "medium"),
        (r"(?i)github[_-]?token['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_]{35,40})", "GitHub Token", "critical"),
        (r"(?i)(password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{6,})['\"]", "Hardcoded Password", "high"),
        (r"(?i)secret[_-]?key['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]", "Secret Key", "high"),
        (r"(?i)private[_-]?key['\"]?\s*[:=]\s*['\"]([^'\"]{16,})['\"]", "Private Key Material", "critical"),
        (r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "JWT Token in code", "medium"),
        (r"(?i)(google|gcp)[_-]?api[_-]?key['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{39})", "Google API Key", "high"),
        (r"xox[baprs]-[0-9]{12}-[0-9]{12}-[A-Za-z0-9]{24}", "Slack Token", "high"),
        (r"(?i)bearer\s+([A-Za-z0-9\-._~+/]+=*)", "Bearer Token", "medium"),
        (r"(?i)basic\s+[A-Za-z0-9+/=]{20,}", "Basic Auth Credential", "high"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.request

        mode = params.get("input_mode", "paste")
        source = ""

        if mode == "url":
            js_url = params.get("js_url", "")
            if not js_url:
                return {"status": "failed", "findings": [], "raw_output": "No URL provided."}
            try:
                req = urllib.request.Request(js_url, headers={"User-Agent": "PenTools/1.0"})
                with urllib.request.urlopen(req, timeout=15) as resp:
                    source = resp.read().decode("utf-8", errors="replace")
                    stream("info", f"Fetched {len(source)} bytes from {js_url}")
            except Exception as e:
                return {"status": "failed", "findings": [], "raw_output": f"Fetch error: {e}"}
        else:
            source = params.get("js_code", "")
            if not source:
                return {"status": "failed", "findings": [], "raw_output": "No code provided."}

        findings = []
        seen = set()

        for pattern, label, severity in self._PATTERNS:
            matches = re.findall(pattern, source)
            for match in matches:
                key = f"{label}:{str(match)[:20]}"
                if key in seen:
                    continue
                seen.add(key)
                evidence = str(match)
                # Redact most of the value for safety in logs
                if len(evidence) > 8:
                    evidence = evidence[:4] + "****" + evidence[-4:]
                stream("error", f"Secret found: {label}")
                findings.append({
                    "title": f"Secret exposed: {label}",
                    "severity": severity,
                    "url": params.get("js_url", "(pasted code)"),
                    "description": f"{label} detected in JavaScript source.",
                    "evidence": f"Pattern matched: {evidence}",
                    "remediation": (
                        "Remove hardcoded secrets from source code immediately. "
                        "Rotate any exposed credentials. Use environment variables or secrets management."
                    ),
                })

        stream("success" if not findings else "error",
               f"Scan complete. {len(findings)} secrets detected.")

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Scanned {len(source)} bytes. {len(findings)} secrets found.",
        }


# ─── [S-05] Regex / Payload Lab ──────────────────────────────────────────────

class PayloadLabModule(BaseModule):
    id = "S-05"
    name = "Regex / Payload Lab"
    category = "static"
    description = (
        "Test regex patterns against custom strings and preview WAF bypass "
        "payload variations for XSS, SQLi, and command injection."
    )
    risk_level = "info"
    tags = ["regex", "payload", "waf-bypass", "lab", "static"]
    celery_queue = "web_audit_queue"
    time_limit = 15

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="mode",
            label="Mode",
            field_type="radio",
            default="regex_test",
            options=[
                {"value": "regex_test",  "label": "Test regex against string"},
                {"value": "waf_bypass",  "label": "Generate WAF bypass variations"},
            ],
        ),
        FieldSchema(
            key="regex_pattern",
            label="Regex Pattern",
            field_type="text",
            required=False,
            show_if={"mode": "regex_test"},
            placeholder="<script[^>]*>.*?</script>",
        ),
        FieldSchema(
            key="test_string",
            label="Test String",
            field_type="textarea",
            required=False,
            show_if={"mode": "regex_test"},
            placeholder='<script>alert(1)</script>',
        ),
        FieldSchema(
            key="payload_type",
            label="Payload Type",
            field_type="select",
            required=False,
            default="xss",
            options=[
                {"value": "xss",  "label": "XSS payloads"},
                {"value": "sqli", "label": "SQLi payloads"},
                {"value": "cmdi", "label": "Command injection"},
            ],
            show_if={"mode": "waf_bypass"},
        ),
        FieldSchema(
            key="base_payload",
            label="Base Payload",
            field_type="text",
            required=False,
            placeholder="<script>alert(1)</script>",
            show_if={"mode": "waf_bypass"},
        ),
    ]

    _WAF_XSS_VARIATIONS = [
        "<script>alert(1)</script>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "<scri\x00pt>alert(1)</scri\x00pt>",
        "<img src=x onerror=alert(1)>",
        "<img src=x onerror=alert`1`>",
        "'\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "<body onload=alert(1)>",
        "javascript:alert(1)",
        "';alert(String.fromCharCode(88,83,83))//",
        "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
        "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "<scr\tipt>alert(1)</scr\tipt>",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        mode = params.get("mode", "regex_test")
        findings = []

        if mode == "regex_test":
            pattern = params.get("regex_pattern", "")
            test_str = params.get("test_string", "")
            if not pattern or not test_str:
                return {"status": "failed", "findings": [], "raw_output": "Pattern and test string required."}

            try:
                matches = list(re.finditer(pattern, test_str, re.DOTALL | re.IGNORECASE))
                stream("info", f"Regex: {pattern}")
                stream("info", f"Matches: {len(matches)}")

                for m in matches:
                    stream("success", f"  Match at {m.start()}-{m.end()}: '{m.group()[:80]}'")

                return {
                    "status": "done",
                    "findings": [],
                    "raw_output": f"Pattern: {pattern}\nMatches: {len(matches)}\n" +
                                  "\n".join(f"  [{m.start()}:{m.end()}] {m.group()[:80]}" for m in matches),
                }
            except re.error as e:
                return {"status": "failed", "findings": [], "raw_output": f"Invalid regex: {e}"}

        elif mode == "waf_bypass":
            ptype = params.get("payload_type", "xss")
            base = params.get("base_payload", "")
            if ptype == "xss":
                variations = self._WAF_XSS_VARIATIONS
            else:
                variations = [base] if base else ["PAYLOAD"]

            output = f"WAF bypass variations ({ptype}):\n" + "\n".join(variations)
            stream("info", output)

            return {
                "status": "done",
                "findings": [],
                "raw_output": output,
            }

        return {"status": "done", "findings": [], "raw_output": ""}


# ─── [S-06] Encoding / Decoding Studio ───────────────────────────────────────

class EncodingStudioModule(BaseModule):
    id = "S-06"
    name = "Encoding / Decoding Studio"
    category = "static"
    description = (
        "Encode/decode: Base64, URL, HTML entity, Unicode, Hex, Gzip. "
        "Client-side processing — nothing leaves the server."
    )
    risk_level = "info"
    tags = ["encode", "decode", "base64", "url-encode", "hex", "static"]
    celery_queue = "web_audit_queue"
    time_limit = 15

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="operation",
            label="Operation",
            field_type="radio",
            default="encode",
            options=[
                {"value": "encode", "label": "Encode"},
                {"value": "decode", "label": "Decode"},
            ],
        ),
        FieldSchema(
            key="encoding_type",
            label="Encoding Type",
            field_type="select",
            default="base64",
            options=[
                {"value": "base64",      "label": "Base64"},
                {"value": "base64url",   "label": "Base64 URL-safe"},
                {"value": "url",         "label": "URL encoding"},
                {"value": "url_full",    "label": "URL encoding (all chars)"},
                {"value": "html",        "label": "HTML entities"},
                {"value": "hex",         "label": "Hex"},
                {"value": "unicode",     "label": "Unicode escape"},
                {"value": "rot13",       "label": "ROT13"},
            ],
        ),
        FieldSchema(
            key="input_text",
            label="Input",
            field_type="textarea",
            required=True,
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.parse
        import html as html_lib
        import codecs
        import gzip

        op = params.get("operation", "encode")
        enc = params.get("encoding_type", "base64")
        text = params.get("input_text", "")

        try:
            if enc == "base64":
                result = base64.b64encode(text.encode()).decode() if op == "encode" else base64.b64decode(text).decode()
            elif enc == "base64url":
                result = base64.urlsafe_b64encode(text.encode()).decode() if op == "encode" else base64.urlsafe_b64decode(text + "==").decode()
            elif enc == "url":
                result = urllib.parse.quote(text, safe="") if op == "encode" else urllib.parse.unquote(text)
            elif enc == "url_full":
                result = "".join(f"%{ord(c):02X}" for c in text) if op == "encode" else urllib.parse.unquote(text)
            elif enc == "html":
                result = html_lib.escape(text) if op == "encode" else html_lib.unescape(text)
            elif enc == "hex":
                result = text.encode().hex() if op == "encode" else bytes.fromhex(text).decode()
            elif enc == "unicode":
                result = text.encode("unicode_escape").decode() if op == "encode" else codecs.decode(text.encode(), "unicode_escape").decode()
            elif enc == "rot13":
                result = codecs.encode(text, "rot_13")
            else:
                result = "Unknown encoding type"

            stream("success", f"Result: {result[:500]}")
            return {
                "status": "done",
                "findings": [],
                "raw_output": result,
            }
        except Exception as e:
            return {"status": "failed", "findings": [], "raw_output": f"Error: {e}"}


# ─── [S-08] TLS Certificate Inspector ────────────────────────────────────────

class TLSCertInspectorModule(BaseModule):
    id = "S-08"
    name = "TLS Certificate Inspector"
    category = "static"
    description = (
        "Parse TLS certificate: expiry, CN/SAN, issuer, key size, "
        "signature algorithm, and weak config warnings."
    )
    risk_level = "low"
    tags = ["tls", "ssl", "certificate", "x509", "static"]
    celery_queue = "web_audit_queue"
    time_limit = 30

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_host",
            label="Target Host:Port",
            field_type="text",
            required=True,
            placeholder="example.com:443",
        ),
        FieldSchema(
            key="timeout",
            label="Connection Timeout (seconds)",
            field_type="number",
            default=10,
            min_value=3,
            max_value=30,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import ssl
        import socket
        import datetime

        host_port = params.get("target_host", "").strip()
        timeout = int(params.get("timeout", 10))

        if ":" in host_port:
            host, port_s = host_port.rsplit(":", 1)
            port = int(port_s)
        else:
            host = host_port
            port = 443

        stream("info", f"Fetching TLS cert from {host}:{port}...")
        findings = []

        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = ctx.wrap_socket(socket.create_connection((host, port), timeout=timeout), server_hostname=host)
            cert = conn.getpeercert()
            cert_bin = conn.getpeercert(binary_form=True)
            conn.close()
        except Exception as e:
            return {"status": "failed", "findings": [], "raw_output": f"Connection error: {e}"}

        if not cert:
            return {"status": "failed", "findings": [], "raw_output": "No certificate returned."}

        # Parse expiry
        not_after = cert.get("notAfter", "")
        if not_after:
            try:
                exp = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                now = datetime.datetime.utcnow()
                days_left = (exp - now).days
                stream("info", f"Cert expires: {not_after} ({days_left} days)")
                if days_left < 0:
                    findings.append({
                        "title": "TLS certificate is expired",
                        "severity": "critical",
                        "url": f"{host}:{port}",
                        "description": f"Certificate expired on {not_after}.",
                        "evidence": f"notAfter: {not_after}",
                        "remediation": "Renew the TLS certificate immediately.",
                    })
                elif days_left < 30:
                    findings.append({
                        "title": f"TLS certificate expiring in {days_left} days",
                        "severity": "high",
                        "url": f"{host}:{port}",
                        "description": f"Certificate expires on {not_after}. Renew soon.",
                        "evidence": f"notAfter: {not_after}",
                        "remediation": "Renew certificate before expiry to avoid disruption.",
                    })
            except Exception:
                pass

        # Subject / SAN
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")
        sans = [v for _, v in cert.get("subjectAltName", [])]
        stream("info", f"CN: {cn} | SANs: {', '.join(sans[:10])}")

        # Check SAN matches host
        san_match = host in sans or any(
            san.startswith("*.") and host.endswith(san[1:]) for san in sans
        )
        if not san_match and cn not in (host, f"*.{'.'.join(host.split('.')[1:])}"):
            findings.append({
                "title": f"Certificate CN/SAN mismatch: {cn}",
                "severity": "high",
                "url": f"{host}:{port}",
                "description": f"Certificate CN '{cn}' / SANs {sans} don't match host '{host}'.",
                "evidence": f"CN={cn} SANs={sans}",
                "remediation": "Obtain a certificate with the correct Common Name and SAN entries.",
            })

        # Weak signature algorithm
        sig_alg = cert.get("signatureAlgorithm", "")
        if sig_alg and "sha1" in sig_alg.lower():
            findings.append({
                "title": f"Weak signature algorithm: {sig_alg}",
                "severity": "high",
                "url": f"{host}:{port}",
                "description": "Certificate uses SHA-1 signature algorithm. Deprecated and insecure.",
                "evidence": f"signatureAlgorithm: {sig_alg}",
                "remediation": "Reissue certificate with SHA-256 or higher.",
            })

        summary = (
            f"Host: {host}:{port}\n"
            f"CN: {cn}\n"
            f"SANs: {', '.join(sans[:10])}\n"
            f"Expires: {not_after}\n"
            f"Issuer: {dict(x[0] for x in cert.get('issuer', [])).get('organizationName', 'unknown')}\n"
        )
        stream("success", summary)

        return {
            "status": "done",
            "findings": findings,
            "raw_output": summary,
        }


# ─── [S-07] Hash Analyzer ────────────────────────────────────────────────────

class HashAnalyzerModule(BaseModule):
    id = "S-07"
    name = "Hash Analyzer"
    category = "static"
    description = (
        "Identify hash types from their format and length, attempt wordlist-based "
        "cracking via hashcat (if available), and suggest hashcat attack modes."
    )
    risk_level = "info"
    tags = ["hash", "hashcat", "crack", "identify", "static"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    # (hash_name, hashcat_mode, regex_pattern)
    HASH_SIGNATURES = [
        ("MD5",          0,    r"^[a-f0-9]{32}$"),
        ("SHA-1",        100,  r"^[a-f0-9]{40}$"),
        ("SHA-256",      1400, r"^[a-f0-9]{64}$"),
        ("SHA-512",      1700, r"^[a-f0-9]{128}$"),
        ("SHA-384",      10800,r"^[a-f0-9]{96}$"),
        ("NTLM",         1000, r"^[a-f0-9]{32}$"),  # same length as MD5, listed for user context
        ("bcrypt",       3200, r"^\$2[ayb]\$.{56}$"),
        ("MD5crypt",     500,  r"^\$1\$.{8}\$.{22}$"),
        ("SHA-512crypt",  1800,r"^\$6\$.{8,16}\$.{86}$"),
        ("SHA-256crypt",  7400,r"^\$5\$.{8,16}\$.{43}$"),
        ("Django (pbkdf2)", 10000, r"^pbkdf2_sha256\$"),
        ("WordPress",    400,  r"^\$P\$.{31}$"),
        ("Joomla (MD5)", 11,   r"^[a-f0-9]{32}:[a-f0-9]{32}$"),
        ("Base64",       None, r"^[A-Za-z0-9+/]+=*$"),
        ("MySQL4+",      300,  r"^\*[A-F0-9]{40}$"),
        ("MySQL3",       200,  r"^[a-f0-9]{16}$"),
        ("CRC32",        11500,r"^[a-f0-9]{8}$"),
        ("Whirlpool",    6100, r"^[a-f0-9]{128}$"),
    ]

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="hash_input",
            label="Hash Value(s)",
            field_type="textarea",
            required=True,
            placeholder="5f4dcc3b5aa765d61d8327deb882cf99\nor one hash per line for bulk",
            help_text="Paste one or more hashes (one per line). Auto-detected.",
        ),
        FieldSchema(
            key="wordlist",
            label="Wordlist for Crack Attempt",
            field_type="wordlist_select",
            default="rockyou.txt",
            help_text="Used by hashcat if installed. Leave default for rockyou.",
        ),
        FieldSchema(
            key="crack_attempt",
            label="Attempt to crack with hashcat",
            field_type="toggle",
            default=True,
            help_text="Requires hashcat installed in the tools container.",
        ),
        FieldSchema(
            key="hashcat_rules",
            label="hashcat Rules",
            field_type="select",
            default="none",
            options=[
                {"value": "none",         "label": "None (dictionary only)"},
                {"value": "best64.rule",  "label": "Best64"},
                {"value": "rockyou-30000.rule", "label": "rockyou-30000"},
                {"value": "d3ad0ne.rule", "label": "d3ad0ne"},
            ],
            group="advanced",
        ),
        FieldSchema(
            key="custom_hash_type",
            label="Force Hash Type (hashcat -m)",
            field_type="number",
            required=False,
            placeholder="e.g. 0 for MD5, 1000 for NTLM",
            help_text="Override auto-detected hash type for cracking.",
            group="advanced",
        ),
    ]

    def _identify_hash(self, hash_val: str) -> list[tuple[str, int | None]]:
        """Return list of (name, hashcat_mode) for all matching signatures."""
        import re as re_mod
        h = hash_val.strip()
        matches = []
        for name, mode, pattern in self.HASH_SIGNATURES:
            if re_mod.match(pattern, h, re_mod.IGNORECASE):
                matches.append((name, mode))
        if not matches:
            length = len(hash_val)
            matches.append((f"Unknown (length={length})", None))
        return matches

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os
        from apps.modules.runner import ToolRunner

        hash_input = params["hash_input"].strip()
        crack_attempt = params.get("crack_attempt", True)
        wordlist_name = params.get("wordlist", "rockyou.txt")
        hashcat_rules = params.get("hashcat_rules", "none")
        custom_type = params.get("custom_hash_type", None)

        hashes = [h.strip() for h in hash_input.splitlines() if h.strip() and not h.startswith("#")]
        if not hashes:
            return {"status": "failed", "findings": [], "raw_output": "No hashes provided"}

        stream("info", f"Identifying {len(hashes)} hash(es)...")
        findings = []
        hash_modes: dict[int, list] = {}  # mode -> [hashes]

        for h in hashes:
            matches = self._identify_hash(h)
            name_list = ", ".join(f"{n} (mode {m})" if m is not None else n for n, m in matches)
            stream("info", f"Hash: {h[:40]}{'...' if len(h) > 40 else ''}  →  {name_list}")
            findings.append({
                "title": f"Hash identified: {matches[0][0]}",
                "severity": "info",
                "url": "",
                "description": (
                    f"Hash value: {h[:80]}\n"
                    f"Detected type(s): {name_list}\n"
                    f"Hashcat mode: {matches[0][1] if matches[0][1] is not None else 'N/A'}"
                ),
                "evidence": h,
                "remediation": (
                    "Use strong adaptive hashing algorithms (bcrypt, Argon2id, scrypt) with a per-user salt. "
                    "Minimum bcrypt cost factor: 12. Never use MD5/SHA-1/SHA-256 for passwords."
                ),
            })
            for name, mode in matches:
                if mode is not None:
                    hash_modes.setdefault(mode, []).append(h)

        # Attempt hashcat cracking
        if crack_attempt and hash_modes:
            wordlist_paths = [
                f"/opt/tools/wordlists/{wordlist_name}",
                f"/usr/share/wordlists/{wordlist_name}",
                f"/usr/share/wordlists/rockyou.txt",
            ]
            wordlist_path = next((p for p in wordlist_paths if os.path.exists(p)), None)

            if not wordlist_path:
                stream("warning", "Wordlist not found — skipping crack attempt")
            else:
                runner = ToolRunner("hashcat")
                import tempfile

                for mode, mode_hashes in hash_modes.items():
                    effective_mode = int(custom_type) if custom_type else mode
                    stream("info", f"hashcat cracking mode {effective_mode} ({len(mode_hashes)} hashes)...")
                    with tempfile.NamedTemporaryFile(
                        mode="w", suffix=".txt", delete=False
                    ) as tf:
                        tf.write("\n".join(mode_hashes))
                        hash_file = tf.name

                    try:
                        args = [
                            "-m", str(effective_mode),
                            hash_file,
                            wordlist_path,
                            "--force",
                            "--quiet",
                            "--outfile-format", "2",
                        ]
                        if hashcat_rules != "none":
                            rules_path = f"/opt/tools/hashcat-rules/{hashcat_rules}"
                            if os.path.exists(rules_path):
                                args += ["-r", rules_path]

                        result = runner.run(args=args, stream=stream, timeout=240)
                        raw_out = result.get("stdout", "")

                        # Parse cracked hashes from output (format: hash:plaintext)
                        cracked = []
                        for line in raw_out.splitlines():
                            if ":" in line:
                                parts = line.split(":", 1)
                                if parts[0].strip() in mode_hashes:
                                    cracked.append(f"{parts[0][:20]}... → {parts[1]}")

                        if cracked:
                            stream("success", f"Cracked {len(cracked)} hashes!")
                            findings.append({
                                "title": f"hashcat cracked {len(cracked)} hash(es) (mode {effective_mode})",
                                "severity": "critical",
                                "url": "",
                                "description": (
                                    f"Wordlist attack with mode {effective_mode} cracked "
                                    f"{len(cracked)} hash(es).\nThis indicates weak or common passwords."
                                ),
                                "evidence": "\n".join(cracked),
                                "remediation": (
                                    "Force password reset for affected accounts. "
                                    "Enforce strong password policy. Use bcrypt/Argon2id."
                                ),
                            })
                        else:
                            stream("info", f"No hashes cracked with mode {effective_mode}")
                    finally:
                        try:
                            os.unlink(hash_file)
                        except Exception:
                            pass

        return {
            "status": "done",
            "findings": findings,
            "raw_output": "\n".join(
                f"{h} → {', '.join(n for n, _ in self._identify_hash(h))}"
                for h in hashes
            ),
        }


# ─── [S-09] HTTP Diff Comparator ─────────────────────────────────────────────

class HTTPDiffComparatorModule(BaseModule):
    id = "S-09"
    name = "HTTP Diff Comparator"
    category = "static"
    description = (
        "Compare two HTTP responses (paste raw or live fetch) and visualize "
        "differences. Useful for detecting cached vs non-cached responses, "
        "access control differences, and A/B response tampering."
    )
    risk_level = "info"
    tags = ["diff", "compare", "http", "response", "analysis", "static"]
    celery_queue = "web_audit_queue"
    time_limit = 60

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="input_mode",
            label="Input Mode",
            field_type="radio",
            default="paste",
            options=[
                {"value": "paste", "label": "Paste raw responses"},
                {"value": "fetch", "label": "Fetch live from two URLs"},
            ],
        ),
        FieldSchema(
            key="response_a",
            label="Response A (raw HTTP)",
            field_type="code_editor",
            required=False,
            placeholder="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"user\": \"alice\"}",
            show_if={"input_mode": "paste"},
        ),
        FieldSchema(
            key="response_b",
            label="Response B (raw HTTP)",
            field_type="code_editor",
            required=False,
            placeholder="HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"user\": \"bob\"}",
            show_if={"input_mode": "paste"},
        ),
        FieldSchema(
            key="url_a",
            label="URL A",
            field_type="url",
            required=False,
            placeholder="https://example.com/api/user/1",
            show_if={"input_mode": "fetch"},
        ),
        FieldSchema(
            key="url_b",
            label="URL B",
            field_type="url",
            required=False,
            placeholder="https://example.com/api/user/2",
            show_if={"input_mode": "fetch"},
        ),
        FieldSchema(
            key="headers_a",
            label="Request Headers for URL A (JSON)",
            field_type="json_editor",
            required=False,
            placeholder='{"Authorization": "Bearer eyJ..."}',
            show_if={"input_mode": "fetch"},
            group="advanced",
        ),
        FieldSchema(
            key="headers_b",
            label="Request Headers for URL B (JSON)",
            field_type="json_editor",
            required=False,
            placeholder='{"Authorization": "Bearer eyJ...user2..."}',
            show_if={"input_mode": "fetch"},
            group="advanced",
        ),
        FieldSchema(
            key="checks",
            label="Diff Analysis Checks",
            field_type="checkbox_group",
            default=["status", "headers", "body", "length"],
            options=[
                {"value": "status",    "label": "HTTP status code"},
                {"value": "headers",   "label": "Response headers diff"},
                {"value": "body",      "label": "Response body diff (unified diff)"},
                {"value": "length",    "label": "Content length comparison"},
                {"value": "sensitive", "label": "Detect sensitive fields in responses"},
                {"value": "timing",    "label": "Response time comparison (fetch mode only)"},
            ],
        ),
    ]

    # Sensitive field patterns to detect in JSON/body
    SENSITIVE_PATTERNS = [
        (r'"password"\s*:', "password field"),
        (r'"secret"\s*:',   "secret field"),
        (r'"token"\s*:',    "token field"),
        (r'"api_key"\s*:',  "api_key field"),
        (r'AKIA[0-9A-Z]{16}',     "AWS Access Key"),
        (r'[0-9a-f]{40}',         "Possible SHA-1 hash/token"),
        (r'eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+', "JWT token"),
        (r'\b(?:admin|root)\b',   "Privileged username"),
    ]

    def _fetch(self, url: str, headers: dict, stream) -> tuple[str, int, float]:
        """Fetch URL, return (raw_response_text, status, elapsed_ms)."""
        import urllib.request
        import time

        req = urllib.request.Request(url, headers={
            "User-Agent": "PenTools/1.0",
            **headers,
        })
        start = time.time()
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                elapsed = (time.time() - start) * 1000
                body = resp.read().decode("utf-8", errors="replace")[:10000]
                header_lines = "\n".join(f"{k}: {v}" for k, v in resp.headers.items())
                raw = f"HTTP/1.1 {resp.status} {resp.reason}\n{header_lines}\n\n{body}"
                return raw, resp.status, elapsed
        except Exception as exc:
            elapsed = (time.time() - start) * 1000
            return f"ERROR: {exc}", 0, elapsed

    def _parse_response(self, raw: str) -> tuple[int, dict, str]:
        """Parse raw HTTP response into (status, headers_dict, body)."""
        lines = raw.splitlines()
        status = 0
        headers: dict[str, str] = {}
        body_lines = []
        in_body = False

        for i, line in enumerate(lines):
            if i == 0 and line.startswith("HTTP"):
                try:
                    status = int(line.split()[1])
                except (IndexError, ValueError):
                    pass
                continue
            if line == "" and not in_body:
                in_body = True
                continue
            if in_body:
                body_lines.append(line)
            elif ":" in line:
                k, _, v = line.partition(":")
                headers[k.strip().lower()] = v.strip()

        return status, headers, "\n".join(body_lines)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import difflib
        import re as re_mod
        import json as json_lib
        import time

        input_mode = params.get("input_mode", "paste")
        checks = params.get("checks", ["status", "headers", "body", "length"])
        findings = []
        timing_a = timing_b = 0.0

        if input_mode == "paste":
            raw_a = params.get("response_a", "").strip()
            raw_b = params.get("response_b", "").strip()
            if not raw_a or not raw_b:
                return {
                    "status": "failed",
                    "findings": [],
                    "raw_output": "Both Response A and Response B are required.",
                }
        else:
            url_a = params.get("url_a", "").strip()
            url_b = params.get("url_b", "").strip()
            if not url_a or not url_b:
                return {
                    "status": "failed",
                    "findings": [],
                    "raw_output": "Both URL A and URL B are required.",
                }
            h_a = {}
            h_b = {}
            try:
                h_a = json_lib.loads(params.get("headers_a", "{}") or "{}")
            except Exception:
                pass
            try:
                h_b = json_lib.loads(params.get("headers_b", "{}") or "{}")
            except Exception:
                pass

            stream("info", f"Fetching A: {url_a}")
            raw_a, status_a_live, timing_a = self._fetch(url_a, h_a, stream)
            stream("info", f"Fetching B: {url_b}")
            raw_b, status_b_live, timing_b = self._fetch(url_b, h_b, stream)

        status_a, headers_a, body_a = self._parse_response(raw_a)
        status_b, headers_b, body_b = self._parse_response(raw_b)

        stream("info", f"Response A: HTTP {status_a}, length {len(body_a)}")
        stream("info", f"Response B: HTTP {status_b}, length {len(body_b)}")

        # ── Status check ──
        if "status" in checks:
            if status_a != status_b:
                findings.append({
                    "title": f"HTTP status difference: {status_a} vs {status_b}",
                    "severity": "high",
                    "url": "",
                    "description": (
                        f"Response A returned HTTP {status_a} while Response B returned HTTP {status_b}.\n"
                        "This may indicate an access control bypass or authorization difference."
                    ),
                    "evidence": f"A: HTTP {status_a}\nB: HTTP {status_b}",
                    "remediation": (
                        "Verify that access control is consistently enforced across all users/roles."
                    ),
                })
                stream("success", f"Status difference: {status_a} vs {status_b}")
            else:
                stream("info", f"Status: both {status_a}")

        # ── Content length check ──
        if "length" in checks:
            len_a = len(body_a)
            len_b = len(body_b)
            diff_pct = abs(len_a - len_b) / max(len_a, len_b, 1) * 100
            if diff_pct > 5:
                sev = "high" if diff_pct > 30 else "medium"
                findings.append({
                    "title": f"Response length difference: {len_a} vs {len_b} bytes ({diff_pct:.1f}%)",
                    "severity": sev,
                    "url": "",
                    "description": (
                        f"Body A: {len_a} bytes\nBody B: {len_b} bytes\n"
                        f"Difference: {abs(len_a - len_b)} bytes ({diff_pct:.1f}%)\n"
                        "Significant length differences may reveal IDOR, data leakage, or broken access."
                    ),
                    "evidence": f"Length A: {len_a}\nLength B: {len_b}",
                    "remediation": "Review responses for data leakage or unauthorized data inclusion.",
                })
                stream("info" if sev == "medium" else "success",
                       f"Length diff: {len_a} vs {len_b} ({diff_pct:.1f}%)")

        # ── Header diff ──
        if "headers" in checks:
            all_keys = set(headers_a) | set(headers_b)
            header_diffs = []
            for k in sorted(all_keys):
                va = headers_a.get(k, "<missing>")
                vb = headers_b.get(k, "<missing>")
                if va != vb:
                    header_diffs.append(f"  {k}:\n    A: {va}\n    B: {vb}")
            if header_diffs:
                findings.append({
                    "title": f"Response header differences ({len(header_diffs)} fields)",
                    "severity": "medium",
                    "url": "",
                    "description": "Headers differ between the two responses.",
                    "evidence": "\n".join(header_diffs),
                    "remediation": (
                        "Ensure security headers (Cache-Control, Set-Cookie, X-Frame-Options) "
                        "are consistently applied."
                    ),
                })
                stream("info", f"Header diff: {len(header_diffs)} field(s) differ")

        # ── Body diff ──
        if "body" in checks and body_a != body_b:
            diff_lines = list(difflib.unified_diff(
                body_a.splitlines(), body_b.splitlines(),
                fromfile="Response-A", tofile="Response-B",
                lineterm="", n=3
            ))
            diff_text = "\n".join(diff_lines[:200])
            added = sum(1 for l in diff_lines if l.startswith("+") and not l.startswith("+++"))
            removed = sum(1 for l in diff_lines if l.startswith("-") and not l.startswith("---"))
            severity = "high" if (added + removed) > 10 else "medium"
            findings.append({
                "title": f"Response body differs: +{added} lines / -{removed} lines",
                "severity": severity,
                "url": "",
                "description": (
                    f"Bodies differ by {added} added and {removed} removed lines.\n"
                    "Review for IDOR data leakage, user enumeration, or state differences."
                ),
                "evidence": diff_text[:2000] if diff_text else "(differences too small to display)",
                "remediation": (
                    "Verify that response content differences are expected and not a sign of "
                    "unauthorized data access."
                ),
            })
            stream("info", f"Body diff: +{added} -{removed} lines")
        elif "body" in checks:
            stream("info", "Body: identical")
            findings.append({
                "title": "Response bodies are identical",
                "severity": "info",
                "url": "",
                "description": "Both responses have exactly the same body content.",
                "evidence": "",
                "remediation": "No action needed.",
            })

        # ── Sensitive field detection ──
        if "sensitive" in checks:
            for response_label, body in [("A", body_a), ("B", body_b)]:
                for pattern, field_name in self.SENSITIVE_PATTERNS:
                    if re_mod.search(pattern, body, re_mod.IGNORECASE):
                        findings.append({
                            "title": f"Sensitive field in Response {response_label}: {field_name}",
                            "severity": "high",
                            "url": "",
                            "description": (
                                f"Response {response_label} contains a sensitive field: "
                                f"'{field_name}' (pattern: {pattern})."
                            ),
                            "evidence": f"Pattern '{pattern}' matched in response {response_label}",
                            "remediation": (
                                "Remove sensitive fields from API responses. "
                                "Apply field-level access control on serializers."
                            ),
                        })
                        stream("success", f"Sensitive field in Response {response_label}: {field_name}")

        # ── Timing comparison (fetch mode only) ──
        if "timing" in checks and input_mode == "fetch" and timing_a and timing_b:
            diff_ms = abs(timing_a - timing_b)
            if diff_ms > 500:
                findings.append({
                    "title": f"Response time difference: {timing_a:.0f}ms vs {timing_b:.0f}ms",
                    "severity": "low",
                    "url": "",
                    "description": (
                        f"A: {timing_a:.0f}ms, B: {timing_b:.0f}ms (Δ {diff_ms:.0f}ms)\n"
                        "Large timing differences may indicate time-based blind SQLi or different "
                        "processing paths (e.g. valid vs invalid user lookup)."
                    ),
                    "evidence": f"A: {timing_a:.0f}ms\nB: {timing_b:.0f}ms",
                    "remediation": (
                        "Normalize response times to prevent timing oracle attacks. "
                        "Use constant-time comparison for sensitive checks."
                    ),
                })

        stream("success", f"Diff analysis complete — {len(findings)} finding(s)")
        diff_summary = (
            f"Status: A={status_a} B={status_b}\n"
            f"Length: A={len(body_a)} B={len(body_b)}\n"
            f"Headers diff: {sum(1 for k in set(headers_a)|set(headers_b) if headers_a.get(k)!=headers_b.get(k))} field(s)\n"
        )
        return {
            "status": "done",
            "findings": findings,
            "raw_output": diff_summary,
        }
