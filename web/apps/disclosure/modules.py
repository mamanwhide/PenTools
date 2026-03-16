"""
Information Disclosure modules — auto-discovered by ModuleRegistry.
Sprint 2 Phase 1: Sensitive File Discovery, Error Message Mining,
                  Debug / Admin Panel Finder
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [D-01] Sensitive File Discovery ─────────────────────────────────────────

class SensitiveFileDiscoveryModule(BaseModule):
    id = "D-01"
    name = "Sensitive File Discovery"
    category = "disclosure"
    description = (
        "Discover sensitive files: .git, .env, .DS_Store, backup, config, "
        "phpinfo.php, server-status, and more using ffuf."
    )
    risk_level = "high"
    tags = ["ffuf", "dotfiles", "git-exposure", "sensitive-files", "recon"]
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
            default="sensitive",
            options=[
                {"value": "sensitive",  "label": "Sensitive files (.env, .git, backup)"},
                {"value": "dotfiles",   "label": "Dotfiles and hidden files"},
                {"value": "config",     "label": "Config file exposure"},
                {"value": "php_info",   "label": "PHP info & debug pages"},
            ],
        ),
        FieldSchema(
            key="filter_codes",
            label="Filter HTTP codes",
            field_type="text",
            default="404,400,410",
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

    _WORDLIST_MAP = {
        "sensitive":  "/opt/tools/wordlists/disclosure/sensitive-files.txt",
        "dotfiles":   "/opt/tools/wordlists/disclosure/dotfiles.txt",
        "config":     "/opt/tools/wordlists/disclosure/config-files.txt",
        "php_info":   "/opt/tools/wordlists/disclosure/php-debug.txt",
    }

    _SECLISTS_FALLBACK = {
        "sensitive":  "/usr/share/seclists/Discovery/Web-Content/Sensitive-Files.txt",
        "dotfiles":   "/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt",
        "config":     "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "php_info":   "/usr/share/seclists/Discovery/Web-Content/PHP.fuzz.txt",
    }

    # High-value paths that warrant higher severity
    _HIGH_SEVERITY = {
        ".env", ".git/", ".git/config", ".git/HEAD",
        "phpinfo.php", "server-status", "server-info",
        ".aws/credentials", ".ssh/id_rsa", "web.config",
        ".htpasswd", "wp-config.php", "config.php", "database.yml",
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os, json
        runner = ToolRunner("ffuf")
        base_url = params["base_url"].rstrip("/")
        threads = str(int(params.get("threads", 40)))
        fc = params.get("filter_codes", "404,400").replace(" ", "")
        wl_key = params.get("wordlist_preset", "sensitive")
        output_file = runner.output_file_path(job_id, "json")

        wordlist = self._WORDLIST_MAP.get(wl_key)
        if not wordlist or not os.path.exists(wordlist):
            wordlist = self._SECLISTS_FALLBACK.get(wl_key)
        if not wordlist or not os.path.exists(wordlist):
            return {"status": "failed", "findings": [], "raw_output": "Wordlist not found."}

        args = [
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-t", threads,
            "-o", str(output_file),
            "-of", "json",
            "-fc", fc,
            "-c",
        ]
        if params.get("follow_redirects"):
            args.append("-r")

        stream("info", f"Sensitive file discovery: {base_url}")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)
                for hit in data.get("results", []):
                    fuzz = hit.get("input", {}).get("FUZZ", "")
                    url = hit.get("url", f"{base_url}/{fuzz}")
                    status = hit.get("status", 0)
                    sev = "critical" if any(p in fuzz for p in (".env", ".git", "id_rsa", ".htpasswd")) else \
                          "high" if fuzz in self._HIGH_SEVERITY else "medium"
                    findings.append({
                        "title": f"Sensitive file exposed: /{fuzz}",
                        "severity": sev,
                        "url": url,
                        "description": f"File '{fuzz}' is accessible — HTTP {status}.",
                        "evidence": f"Length: {hit.get('length','')} Words: {hit.get('words','')}",
                        "remediation": (
                            "Remove or restrict access to sensitive files. "
                            "Add deny rules in .htaccess or nginx config."
                        ),
                    })
        except Exception as e:
            stream("warning", f"Parse error: {e}")

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [D-02] Error Message Mining ─────────────────────────────────────────────

class ErrorMessageMiningModule(BaseModule):
    id = "D-02"
    name = "Error Message Mining"
    category = "disclosure"
    description = (
        "Trigger HTTP errors and mine verbose messages for stack traces, "
        "DB names, source paths, framework versions, and internal IPs."
    )
    risk_level = "medium"
    tags = ["error-disclosure", "stack-trace", "info-leak", "debug"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="base_url",
            label="Base URL",
            field_type="url",
            required=True,
            placeholder="https://example.com",
        ),
        FieldSchema(
            key="trigger_methods",
            label="Error Trigger Methods",
            field_type="checkbox_group",
            default=["random_paths", "bad_params", "invalid_methods"],
            options=[
                {"value": "random_paths",    "label": "Random/nonexistent paths (404)"},
                {"value": "bad_params",      "label": "Malformed parameters (400/500)"},
                {"value": "invalid_methods", "label": "Invalid HTTP methods"},
                {"value": "sql_errors",      "label": "SQL error triggers in params"},
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

    _LEAK_PATTERNS = [
        (r"Traceback \(most recent call last\)", "Python stack trace", "high"),
        (r"at .+\.java:[0-9]+", "Java stack trace", "high"),
        (r"System\.Web\.HttpException", ".NET/ASP.NET exception", "high"),
        (r"ORA-[0-9]{5}", "Oracle DB error", "critical"),
        (r"MySQL server version", "MySQL version disclosure", "high"),
        (r"PostgreSQL.*ERROR", "PostgreSQL error", "high"),
        (r"SQLSTATE\[", "SQL state error", "high"),
        (r"Warning:.*mysql_", "PHP MySQL error", "high"),
        (r"Fatal error:.*PHP", "PHP fatal error", "high"),
        (r"/home/[a-z]+/", "Unix home path disclosure", "medium"),
        (r"C:\\Users\\|C:\\inetpub\\", "Windows path disclosure", "medium"),
        (r"192\.168\.|10\.\d+\.|172\.(1[6-9]|2\d|3[01])\.", "Internal IP in response", "medium"),
        (r"DEBUG\s*=\s*True", "Django DEBUG mode enabled", "critical"),
        (r"X-Powered-By: PHP", "PHP version header", "low"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.request
        import urllib.error
        import re
        import uuid

        base_url = params["base_url"].rstrip("/")
        cookie = params.get("auth_cookie")
        triggers = params.get("trigger_methods", ["random_paths", "bad_params"])
        findings = []
        responses_checked = []

        def fetch(url, method="GET", extra_headers=None):
            headers = {"User-Agent": "PenTools/1.0"}
            if cookie:
                headers["Cookie"] = cookie
            if extra_headers:
                headers.update(extra_headers)
            try:
                req = urllib.request.Request(url, headers=headers, method=method)
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read().decode("utf-8", errors="replace")
                    for hdr, val in resp.headers.items():
                        body += f"\n[HEADER] {hdr}: {val}"
                    return resp.status, body
            except urllib.error.HTTPError as e:
                try:
                    body = e.read().decode("utf-8", errors="replace")
                    return e.code, body
                except Exception:
                    return e.code, ""
            except Exception:
                return None, ""

        test_urls = []

        if "random_paths" in triggers:
            for _ in range(3):
                test_urls.append((f"{base_url}/{uuid.uuid4().hex}", "GET", None))

        if "bad_params" in triggers:
            test_urls += [
                (f"{base_url}/?id=''", "GET", None),
                (f"{base_url}/?id=<script>", "GET", None),
                (f"{base_url}/?page=-1", "GET", None),
            ]

        if "sql_errors" in triggers:
            test_urls += [
                (f"{base_url}/?id=1'", "GET", None),
                (f"{base_url}/?id=1 OR 1=1", "GET", None),
            ]

        if "invalid_methods" in triggers:
            test_urls.append((base_url, "INVALID", None))

        for url, method, extra in test_urls:
            status, body = fetch(url, method, extra)
            if body:
                responses_checked.append((url, status, body))

        for url, status, body in responses_checked:
            for pattern, label, severity in self._LEAK_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    stream("error", f"Leak detected: {label} at {url}")
                    findings.append({
                        "title": f"Info Disclosure: {label}",
                        "severity": severity,
                        "url": url,
                        "description": f"Error response revealed {label}.",
                        "evidence": body[:500],
                        "remediation": (
                            "Disable verbose error messages in production. "
                            "Use generic error pages. Disable DEBUG mode."
                        ),
                    })
                    break  # one finding per URL

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Checked {len(responses_checked)} error responses",
        }


# ─── [D-05] Debug / Admin Panel Finder ───────────────────────────────────────

class AdminPanelFinderModule(BaseModule):
    id = "D-05"
    name = "Debug / Admin Panel Finder"
    category = "disclosure"
    description = (
        "Find exposed admin panels, debug interfaces, monitoring dashboards, "
        "and developer consoles using ffuf."
    )
    risk_level = "high"
    tags = ["admin-panel", "debug", "ffuf", "actuator", "console", "recon"]
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
            label="Panel Type",
            field_type="select",
            default="all_panels",
            options=[
                {"value": "all_panels",    "label": "All admin & debug panels"},
                {"value": "java_actuator", "label": "Spring Boot Actuator endpoints"},
                {"value": "cms_admin",     "label": "CMS admin panels (WP, Drupal, Joomla)"},
                {"value": "framework",     "label": "Framework debug pages (Rails, Django, Laravel)"},
                {"value": "monitoring",    "label": "Monitoring / metrics (Prometheus, Grafana)"},
            ],
        ),
        FieldSchema(
            key="match_codes",
            label="Match HTTP Codes",
            field_type="text",
            default="200,301,302,403",
            group="advanced",
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=50,
            min_value=5,
            max_value=200,
            step=10,
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
    ]

    _WORDLISTS = {
        "all_panels":    "/opt/tools/wordlists/disclosure/admin-panels-all.txt",
        "java_actuator": "/opt/tools/wordlists/disclosure/spring-actuator.txt",
        "cms_admin":     "/opt/tools/wordlists/disclosure/cms-paths.txt",
        "framework":     "/opt/tools/wordlists/disclosure/framework-debug.txt",
        "monitoring":    "/opt/tools/wordlists/disclosure/monitoring-panels.txt",
    }

    _SECLISTS_FALLBACK = {
        "all_panels":    "/usr/share/seclists/Discovery/Web-Content/AdminPanels.txt",
        "java_actuator": "/usr/share/seclists/Discovery/Web-Content/spring-actuator.txt",
        "cms_admin":     "/usr/share/seclists/Discovery/Web-Content/CMS/wp-admin.txt",
        "framework":     "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "monitoring":    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os, json
        runner = ToolRunner("ffuf")
        base_url = params["base_url"].rstrip("/")
        threads = str(int(params.get("threads", 50)))
        mc = params.get("match_codes", "200,301,302,403").replace(" ", "")
        wl_key = params.get("wordlist_preset", "all_panels")
        output_file = runner.output_file_path(job_id, "json")

        wordlist = self._WORDLISTS.get(wl_key)
        if not wordlist or not os.path.exists(wordlist):
            wordlist = self._SECLISTS_FALLBACK.get(wl_key)
        if not wordlist or not os.path.exists(wordlist):
            return {"status": "failed", "findings": [], "raw_output": "Wordlist not found."}

        args = [
            "-u", f"{base_url}/FUZZ",
            "-w", wordlist,
            "-t", threads,
            "-o", str(output_file),
            "-of", "json",
            "-mc", mc,
            "-c",
        ]
        if params.get("auth_cookie"):
            args += ["-H", f"Cookie: {params['auth_cookie']}"]

        stream("info", f"Admin panel scan: {base_url} [{wl_key}]")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        _HIGH_RISK_PATHS = {
            "admin", "wp-admin", "administrator", "phpmyadmin", "console",
            "actuator/env", "actuator/health", "actuator/mappings", "actuator/beans",
            "debug", "server-info", "server-status", "_profiler", "telescope",
            "horizon", "graphiql", "graphql-playground",
        }

        findings = []
        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)
                for hit in data.get("results", []):
                    fuzz = hit.get("input", {}).get("FUZZ", "")
                    url = hit.get("url", f"{base_url}/{fuzz}")
                    status = hit.get("status", 0)
                    is_high = any(h in fuzz.lower() for h in _HIGH_RISK_PATHS)
                    sev = "high" if status == 200 and is_high else "medium"
                    findings.append({
                        "title": f"Admin/debug panel found: /{fuzz}",
                        "severity": sev,
                        "url": url,
                        "description": f"'{fuzz}' responded HTTP {status}. Potential admin or debug interface.",
                        "evidence": f"Length: {hit.get('length','')}",
                        "remediation": "Restrict access to admin panels via IP allowlist or authentication.",
                    })
        except Exception as e:
            stream("warning", f"Parse error: {e}")

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [D-03] Source Code Disclosure ───────────────────────────────────────────

class SourceCodeDisclosureModule(BaseModule):
    id = "D-03"
    name = "Source Code Disclosure"
    category = "disclosure"
    description = (
        "Detect exposed source control directories (.git, .svn, .hg) "
        "and common source code disclosure patterns."
    )
    risk_level = "critical"
    tags = ["disclosure", "git", "svn", "hg", "source-code"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target Base URL", field_type="url",
                    required=True, placeholder="https://example.com"),
        FieldSchema(key="checks", label="SCM Types to Check",
                    field_type="checkbox_group",
                    default=["git", "svn", "env"],
                    options=[
                        {"value": "git",      "label": ".git directory exposure"},
                        {"value": "svn",      "label": ".svn directory exposure"},
                        {"value": "hg",       "label": ".hg (Mercurial) exposure"},
                        {"value": "ds_store", "label": ".DS_Store & IDE files"},
                        {"value": "env",      "label": ".env / config leakage"},
                    ]),
    ]

    _GIT_PATHS = ["/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG", "/.git/index"]
    _SVN_PATHS = ["/.svn/entries", "/.svn/wc.db"]
    _HG_PATHS = ["/.hg/hgrc", "/.hg/store/manifest"]
    _MISC_PATHS = [
        "/.DS_Store", "/.env", "/.env.local", "/.env.production",
        "/.env.backup", "/config.php.bak", "/database.yml",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3; urllib3.disable_warnings()

        base_url = params["target_url"].rstrip("/")
        checks = params.get("checks", ["git", "svn", "env"])
        session = requests.Session()
        session.verify = False
        headers = {"User-Agent": "PenTools/1.0"}
        findings = []

        paths_to_check = []
        if "git" in checks:
            paths_to_check += [(p, "git", "critical") for p in self._GIT_PATHS]
        if "svn" in checks:
            paths_to_check += [(p, "svn", "critical") for p in self._SVN_PATHS]
        if "hg" in checks:
            paths_to_check += [(p, "hg", "critical") for p in self._HG_PATHS]
        if "ds_store" in checks or "env" in checks:
            paths_to_check += [(p, "misc", "high") for p in self._MISC_PATHS]

        stream(f"[D-03] Probing {len(paths_to_check)} paths for source code disclosure...")
        for path, scm_type, sev in paths_to_check:
            url = base_url + path
            try:
                r = session.get(url, headers=headers, timeout=8)
                if r.status_code == 200 and len(r.content) > 0:
                    is_real = False
                    if scm_type == "git" and any(kw in r.text for kw in ("ref:", "[core]", "HEAD")):
                        is_real = True
                    elif scm_type == "svn" and any(kw in r.text.lower() for kw in ("svn", "<?xml")):
                        is_real = True
                    elif scm_type == "hg" and any(kw in r.text.lower() for kw in ("hg", "[paths]")):
                        is_real = True
                    elif scm_type == "misc" and path == "/.env" and "=" in r.text:
                        is_real = True
                    elif scm_type == "misc" and len(r.content) < 100000:
                        is_real = True
                    if is_real:
                        findings.append({
                            "title": "Source Code/SCM Disclosure: " + path,
                            "severity": sev,
                            "url": url,
                            "description": (
                                "Path '" + path + "' returned HTTP 200 with apparent "
                                + scm_type.upper() + " content. "
                                "Attackers can reconstruct source code or extract secrets."
                            ),
                            "evidence": "HTTP 200 — Content[:80]: " + r.text[:80].replace("\n", " "),
                            "remediation": (
                                "Block access to SCM directories via web server config. "
                                "Never deploy SCM directories to production."
                            ),
                            "cwe_id": "CWE-540",
                        })
                        stream("[D-03] EXPOSED: " + url)
            except Exception:
                pass

        return {"status": "done", "findings": findings}


# ─── [D-04] Backup & Archive Finder ──────────────────────────────────────────

class BackupArchiveFinderModule(BaseModule):
    id = "D-04"
    name = "Backup & Archive Finder"
    category = "disclosure"
    description = (
        "Fuzz for backup and archive files (.bak, .old, .zip, .tar.gz, .sql) "
        "by appending extensions to common base path names."
    )
    risk_level = "high"
    tags = ["disclosure", "backup", "archive", "bak", "zip", "fuzzing"]
    celery_queue = "web_audit_queue"
    time_limit = 900

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target Base URL", field_type="url",
                    required=True, placeholder="https://example.com"),
        FieldSchema(key="base_paths", label="Base Paths to Test (one per line)",
                    field_type="textarea", required=False,
                    placeholder="/index\n/config\n/admin\n/database\n/backup"),
        FieldSchema(key="use_ffuf", label="Use ffuf for faster fuzzing",
                    field_type="select", options=["yes", "no"], default="no"),
    ]

    _EXTENSIONS = [
        ".bak", ".old", ".orig", ".backup", ".bkp",
        ".zip", ".tar.gz", ".tar", ".gz", ".tgz",
        ".sql", ".sql.gz", ".dump", ".log",
        ".php.bak", ".php.old", ".config.bak", ".yml.bak", "~", ".swp",
    ]
    _DEFAULT_PATHS = [
        "/index", "/config", "/admin", "/database", "/db",
        "/backup", "/app", "/main", "/settings", "/env",
        "/secrets", "/credentials", "/vars",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, tempfile, os
        import urllib3; urllib3.disable_warnings()

        base_url = params["target_url"].rstrip("/")
        paths_raw = params.get("base_paths") or ""
        base_paths = [p.strip() for p in paths_raw.splitlines() if p.strip()] or self._DEFAULT_PATHS
        use_ffuf = params.get("use_ffuf", "no") == "yes"
        session = requests.Session()
        session.verify = False
        headers = {"User-Agent": "PenTools/1.0"}
        findings = []

        if use_ffuf:
            runner = ToolRunner("ffuf")
            words = [p + ext for p in base_paths for ext in self._EXTENSIONS]
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as wf:
                wf.write("\n".join(words))
                wlist_path = wf.name
            try:
                result = runner.run(args=[
                    "-u", base_url + "/FUZZ",
                    "-w", wlist_path,
                    "-mc", "200,201",
                    "-fs", "0",
                    "-t", "20",
                    "-silent",
                ], stream=stream, timeout=300)
                for line in result.get("stdout", "").splitlines():
                    if "Status: 200" in line or "[200]" in line:
                        findings.append({
                            "title": "Backup File Found (ffuf)",
                            "severity": "high",
                            "url": base_url,
                            "description": "ffuf discovered a backup/archive file accessible on the server.",
                            "evidence": line[:200],
                            "remediation": "Delete backup files from webroot. Use .gitignore to prevent commits.",
                            "cwe_id": "CWE-538",
                        })
            finally:
                try:
                    os.unlink(wlist_path)
                except Exception:
                    pass
        else:
            total = len(base_paths) * len(self._EXTENSIONS)
            stream(f"[D-04] Testing {total} backup paths at {base_url}...")
            for path in base_paths:
                for ext in self._EXTENSIONS:
                    url = base_url + path + ext
                    try:
                        r = session.get(url, headers=headers, timeout=6)
                        if r.status_code == 200 and len(r.content) > 100:
                            findings.append({
                                "title": "Backup File Found: " + path + ext,
                                "severity": "high",
                                "url": url,
                                "description": (
                                    "Backup/archive '" + url + "' returned HTTP 200. "
                                    "May contain source code, DB dumps, or credentials."
                                ),
                                "evidence": "HTTP 200 — " + str(len(r.content)) + " bytes",
                                "remediation": "Remove backup files from webroot. Block sensitive extensions.",
                                "cwe_id": "CWE-538",
                            })
                            stream("[D-04] FOUND: " + url)
                    except Exception:
                        pass

        return {"status": "done", "findings": findings}


# ─── [D-06] API Key / Token in Response ──────────────────────────────────────

class APIKeyTokenInResponseModule(BaseModule):
    id = "D-06"
    name = "API Key / Token in Response"
    category = "disclosure"
    description = (
        "Scan API/page responses for exposed credentials: API keys, tokens, "
        "AWS keys, Stripe keys, GitHub tokens, and generic secrets."
    )
    risk_level = "critical"
    tags = ["disclosure", "api-key", "token", "secret", "credentials"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL to Scan", field_type="url",
                    required=True, placeholder="https://api.example.com/debug/info"),
        FieldSchema(key="extra_urls", label="Additional URLs (one per line)",
                    field_type="textarea", required=False),
        FieldSchema(key="auth_header", label="Auth Header", field_type="text",
                    required=False, sensitive=True),
    ]

    _PATTERNS = [
        (r"AIza[0-9A-Za-z\-_]{35}", "Google API Key"),
        (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
        (r"sk_live_[0-9a-zA-Z]{24,}", "Stripe Live Secret Key"),
        (r"sk_test_[0-9a-zA-Z]{24,}", "Stripe Test Secret Key"),
        (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
        (r"xoxb-[0-9\-]{20,}", "Slack Bot Token"),
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "Private Key"),
        (r"ey[A-Za-z0-9\-_]{10,}\.ey[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}", "JWT Token"),
        (r"(?i)\"(?:api_?key|access_?key|auth_?token|secret_?key)\"\s*:\s*\"([A-Za-z0-9\-_\.+/]{16,})\"",
         "Generic Key in JSON"),
        (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{8,})['\"]", "Password in Response"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, re
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        extra_raw = params.get("extra_urls") or ""
        auth_header = params.get("auth_header") or ""
        urls = [target_url] + [u.strip() for u in extra_raw.splitlines() if u.strip()]
        headers = {"User-Agent": "PenTools/1.0"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []
        stream(f"[D-06] Scanning {len(urls)} URL(s) for credentials in responses...")

        for url in urls:
            try:
                r = session.get(url, headers=headers, timeout=10)
                content = r.text
                for pattern, label in self._PATTERNS:
                    matches = re.findall(pattern, content)
                    if matches:
                        m = matches[0]
                        if isinstance(m, tuple):
                            m = m[-1]
                        truncated = str(m)[:12] + "..." if len(str(m)) > 12 else str(m)
                        findings.append({
                            "title": "Credential in Response: " + label,
                            "severity": "critical",
                            "url": url,
                            "description": (
                                "A " + label + " was found in the HTTP response from " + url + ". "
                                "Exposed credentials allow direct service compromise."
                            ),
                            "evidence": "Pattern: " + label + " — Prefix: " + truncated,
                            "remediation": (
                                "Immediately revoke the credential. Never include secrets in API responses. "
                                "Use secrets managers."
                            ),
                            "cwe_id": "CWE-312",
                        })
                        stream("[D-06] Credential at " + url + ": " + label)
            except Exception as e:
                stream(f"[D-06] {url} error: {e}")

        return {"status": "done", "findings": findings}


# ─── [D-07] Cloud Metadata Exposure ──────────────────────────────────────────

class CloudMetadataExposureModule(BaseModule):
    id = "D-07"
    name = "Cloud Metadata Exposure"
    category = "disclosure"
    description = (
        "Probe cloud metadata endpoints (AWS IMDSv1, GCP, Azure) directly "
        "and via SSRF to detect credential exposure and metadata leakage."
    )
    risk_level = "critical"
    tags = ["disclosure", "cloud", "metadata", "aws", "gcp", "azure", "ssrf"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="direct_probe", label="Direct Cloud Metadata Probe",
                    field_type="select", options=["yes", "no"], default="yes"),
        FieldSchema(key="ssrf_url", label="SSRF Endpoint for Indirect Probe (optional)",
                    field_type="url", required=False,
                    placeholder="https://victim.example.com/fetch?url="),
        FieldSchema(key="ssrf_param", label="SSRF Parameter Name",
                    field_type="text", required=False, default="url"),
        FieldSchema(key="clouds", label="Cloud Metadata Targets",
                    field_type="checkbox_group",
                    default=["aws", "gcp", "azure"],
                    options=[
                        {"value": "aws",   "label": "AWS EC2 Instance Metadata"},
                        {"value": "gcp",   "label": "GCP Compute Engine Metadata"},
                        {"value": "azure", "label": "Azure IMDS"},
                    ]),
    ]

    _METADATA_ENDPOINTS = {
        "aws": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
        ],
        "gcp": [
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
        ],
        "azure": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ],
    }
    _META_HEADERS = {
        "gcp":   {"Metadata-Flavor": "Google"},
        "azure": {"Metadata": "true"},
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3; urllib3.disable_warnings()

        direct_probe = params.get("direct_probe", "yes") == "yes"
        ssrf_url = params.get("ssrf_url") or ""
        ssrf_param = params.get("ssrf_param") or "url"
        clouds = params.get("clouds", ["aws", "gcp", "azure"])
        session = requests.Session()
        session.verify = False
        findings = []

        for cloud in clouds:
            endpoints = self._METADATA_ENDPOINTS.get(cloud, [])
            cloud_headers = self._META_HEADERS.get(cloud, {})
            for meta_url in endpoints:
                if direct_probe:
                    try:
                        h = {"User-Agent": "PenTools/1.0"}
                        h.update(cloud_headers)
                        r = session.get(meta_url, headers=h, timeout=5)
                        if r.status_code == 200 and len(r.content) > 0:
                            findings.append({
                                "title": "Cloud Metadata Accessible: " + cloud.upper(),
                                "severity": "critical",
                                "url": meta_url,
                                "description": (
                                    cloud.upper() + " metadata endpoint is directly accessible. "
                                    "Combined with SSRF, attackers can extract IAM credentials."
                                ),
                                "evidence": "HTTP 200 — Body[:100]: " + r.text[:100],
                                "remediation": "Enforce IMDSv2 for AWS. Block 169.254.169.254 at WAF/network layer.",
                                "cwe_id": "CWE-200",
                            })
                            stream("[D-07] " + cloud.upper() + ": " + meta_url)
                    except Exception:
                        pass
                if ssrf_url:
                    try:
                        r = session.get(ssrf_url, params={ssrf_param: meta_url},
                                        headers={"User-Agent": "PenTools/1.0"}, timeout=10)
                        if r.status_code == 200 and any(
                            kw in r.text for kw in ("ami-id", "instanceId", "project-id", "subscriptionId")
                        ):
                            findings.append({
                                "title": "SSRF → Cloud Metadata: " + cloud.upper(),
                                "severity": "critical",
                                "url": ssrf_url,
                                "description": (
                                    "SSRF successfully reached " + cloud.upper() + " metadata. "
                                    "IAM credentials and environment info can be extracted."
                                ),
                                "evidence": "SSRF → " + meta_url + " returned metadata indicators.",
                                "remediation": "Block outbound requests to 169.254.169.254. Validate all URL parameters.",
                                "cwe_id": "CWE-918",
                            })
                    except Exception:
                        pass

        return {"status": "done", "findings": findings}


# ─── [D-08] EXIF / Metadata Extractor ────────────────────────────────────────

class EXIFMetadataExtractorModule(BaseModule):
    id = "D-08"
    name = "EXIF / Metadata Extractor"
    category = "disclosure"
    description = (
        "Download images and extract EXIF metadata: GPS coordinates, "
        "device/camera info, timestamps, and software information."
    )
    risk_level = "medium"
    tags = ["disclosure", "exif", "metadata", "gps", "image", "privacy"]
    celery_queue = "web_audit_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="image_urls", label="Image URLs to Analyze (one per line)",
                    field_type="textarea", required=True,
                    placeholder="https://example.com/uploads/photo.jpg"),
        FieldSchema(key="auth_header", label="Auth Header (if images require auth)",
                    field_type="text", required=False, sensitive=True),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, struct, re
        import urllib3; urllib3.disable_warnings()

        urls_raw = params.get("image_urls") or ""
        auth_header = params.get("auth_header") or ""
        image_urls = [u.strip() for u in urls_raw.splitlines() if u.strip()]
        headers = {"User-Agent": "PenTools/1.0"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []

        def extract_exif_basic(data):
            result = {}
            if len(data) < 4 or data[:2] != b'\xff\xd8':
                return result
            i = 2
            while i < len(data) - 4:
                if data[i] == 0xFF and data[i + 1] == 0xE1:
                    seg_len = struct.unpack(">H", data[i + 2:i + 4])[0]
                    seg_data = data[i + 4:i + 2 + seg_len]
                    if seg_data[:4] == b'Exif':
                        result["exif_present"] = True
                        text = seg_data.decode("latin-1", errors="replace")
                        if "GPS" in text:
                            result["gps_data_present"] = True
                        for brand in ["Canon", "Nikon", "Apple", "Samsung", "Sony", "Fujifilm"]:
                            if brand in text:
                                result["camera_brand"] = brand
                                break
                        coords = re.findall(r'\d{1,3}\.\d+', text)
                        if coords:
                            result["possible_coords"] = coords[:4]
                    break
                i += 1
                while i < len(data) and data[i] != 0xFF:
                    i += 1
            return result

        stream(f"[D-08] Analyzing {len(image_urls)} image(s) for EXIF metadata...")
        for url in image_urls:
            try:
                r = session.get(url, headers=headers, timeout=15)
                if r.status_code != 200:
                    continue
                ct = r.headers.get("Content-Type", "")
                if "image" not in ct and not any(url.lower().endswith(e) for e in (".jpg", ".jpeg", ".tiff")):
                    continue
                exif = extract_exif_basic(r.content)
                if exif.get("exif_present"):
                    issues = []
                    sev = "low"
                    if exif.get("gps_data_present"):
                        issues.append("GPS coordinates present")
                        sev = "high"
                    if exif.get("camera_brand"):
                        issues.append("Device: " + exif["camera_brand"])
                        if sev == "low":
                            sev = "medium"
                    findings.append({
                        "title": "EXIF Metadata Exposed in Image",
                        "severity": sev,
                        "url": url,
                        "description": (
                            "Image contains EXIF revealing: "
                            + (", ".join(issues) if issues else "device/capture info")
                        ),
                        "evidence": "EXIF: " + str(exif),
                        "remediation": (
                            "Strip EXIF on upload via ImageMagick 'mogrify -strip' "
                            "or Pillow img.save() processing pipeline."
                        ),
                        "cwe_id": "CWE-200",
                    })
                    stream("[D-08] EXIF at " + url + ": " + str(issues))
            except Exception as e:
                stream(f"[D-08] {url} error: {e}")

        return {"status": "done", "findings": findings}
