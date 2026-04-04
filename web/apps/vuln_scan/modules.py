"""
Vulnerability scanning modules — auto-discovered by ModuleRegistry.
Sprint 2 Phase 1: Nuclei CVE scan, Misconfiguration scan, Web Templates scan
"""
from __future__ import annotations
import re
import time
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


class _NucleiBaseModule(BaseModule):
    """Shared base for all Nuclei wrapper modules."""

    celery_queue = "vuln_scan_queue"
    time_limit = 1200
    _TEMPLATE_TAGS: list[str] = []
    _SEVERITY_FILTER: str = "low,medium,high,critical"

    def _run_nuclei(self, params: dict, job_id: str, stream, extra_args: list[str] = None) -> dict:
        import os, json
        runner = ToolRunner("nuclei")
        target = params["target_url"]
        output_file = runner.output_file_path(job_id, "json")

        severity = params.get("severity", self._SEVERITY_FILTER)

        # Support scanning a list of URLs (set by V-01 URL discovery)
        targets_file = params.get("_targets_file")
        if targets_file and os.path.isfile(targets_file):
            target_args = ["-l", targets_file]
        else:
            target_args = ["-u", target]

        # Nuclei v3.7+ requires an explicit -t <templates-dir> when using -tags/-severity
        # without a specific template path. Provide the shared volume template directory,
        # but only when extra_args doesn't already specify its own -t (e.g. custom template module).
        nuclei_tpl_dir = "/opt/tools/nuclei-templates"
        has_explicit_t = extra_args and "-t" in extra_args
        template_args = (["-t", nuclei_tpl_dir]
                         if os.path.isdir(nuclei_tpl_dir) and not has_explicit_t
                         else [])

        args = target_args + template_args + [
            "-severity", severity,
            "-json-export", str(output_file),
            "-no-color",
            "-no-interactsh",  # avoid accidental OOB
            "-stats",
        ]

        if extra_args:
            args += extra_args

        headers = params.get("headers", [])
        if isinstance(headers, list):
            for h in headers:
                if isinstance(h, dict):
                    k, v = h.get("key", "").strip(), h.get("value", "").strip()
                    if k and v:
                        args += ["-H", f"{k}: {v}"]

        cookie = params.get("auth_cookie")
        if cookie:
            args += ["-H", f"Cookie: {cookie}"]

        stream("info", f"Running nuclei against {target} (severity: {severity})")
        result = runner.run(
            args=args,
            stream=stream,
            timeout=self.time_limit,
            # HOME=/opt/tools ensures nuclei finds templates downloaded by the tools container
            # at /opt/tools/.local/share/nuclei-templates (persisted in the tools_bin volume).
            env_extra={"HOME": "/opt/tools"},
        )

        findings = []
        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entry = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        sev_map = {
                            "critical": "critical",
                            "high": "high",
                            "medium": "medium",
                            "low": "low",
                            "info": "info",
                        }
                        sev = sev_map.get(entry.get("info", {}).get("severity", "info"), "info")
                        name = entry.get("info", {}).get("name", "Unknown")
                        matched_url = entry.get("matched-at", target)
                        desc = entry.get("info", {}).get("description", "")
                        remediation = entry.get("info", {}).get("remediation", "")
                        cve_ids = entry.get("info", {}).get("classification", {}).get("cve-id", [])
                        cve_id = ", ".join(cve_ids) if cve_ids else ""
                        evidence = entry.get("extracted-results", [])
                        req_block  = entry.get("request", "")
                        resp_block = entry.get("response", "")
                        if evidence:
                            evidence_str = "Extracted:\n" + "\n".join(evidence)
                            if req_block:
                                evidence_str += f"\n\n─── HTTP Request ───────────────────────────────\n{req_block[:800]}"
                            if resp_block:
                                evidence_str += f"\n\n─── HTTP Response ──────────────────────────────\n{resp_block[:800]}"
                        elif req_block:
                            evidence_str = f"─── HTTP Request ───────────────────────────────\n{req_block[:800]}"
                            if resp_block:
                                evidence_str += f"\n\n─── HTTP Response ──────────────────────────────\n{resp_block[:800]}"
                        else:
                            evidence_str = ""

                        findings.append({
                            "title": name,
                            "severity": sev,
                            "url": matched_url,
                            "description": desc,
                            "evidence": evidence_str,
                            "remediation": remediation,
                            "cve_id": cve_id,
                        })
        except Exception as e:
            stream("warning", f"Failed to parse nuclei output: {e}")

        stream("success" if findings else "info",
               f"Nuclei scan complete. {len(findings)} findings.")
        return {
            "status": "done" if result["returncode"] in (0, 1) else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [V-01] Nuclei — CVE Templates ───────────────────────────────────────────

class NucleiCVEModule(_NucleiBaseModule):
    id = "V-01"
    name = "Nuclei — CVE Scan"
    category = "vuln_scan"
    description = (
        "Deep CVE scan pipeline: historical URL discovery (waybackurls + gau) → "
        "Nuclei CVE templates with severity/year filtering → template coverage stats."
    )
    risk_level = "high"
    tags = ["nuclei", "cve", "vulnerability-scan", "templates", "waybackurls", "gau"]

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com",
        ),
        FieldSchema(
            key="severity",
            label="Minimum Severity",
            field_type="select",
            default="medium,high,critical",
            options=[
                {"value": "info,low,medium,high,critical", "label": "All (including info)"},
                {"value": "low,medium,high,critical",      "label": "Low and above"},
                {"value": "medium,high,critical",          "label": "Medium and above"},
                {"value": "high,critical",                 "label": "High and critical only"},
                {"value": "critical",                      "label": "Critical only"},
            ],
        ),
        FieldSchema(
            key="year_filter",
            label="CVE Year Filter",
            field_type="text",
            required=False,
            placeholder="2023,2024,2025",
            help_text="Filter to specific CVE years (comma-separated). Leave blank for all.",
            group="advanced",
        ),
        FieldSchema(
            key="url_discovery",
            label="Historical URL Discovery",
            field_type="select",
            default="none",
            options=[
                {"value": "none",         "label": "None — target URL only"},
                {"value": "waybackurls",  "label": "Wayback Machine (waybackurls)"},
                {"value": "gau",          "label": "All URL sources (gau: Wayback + OTX + CommonCrawl)"},
            ],
            help_text="Discover additional URLs before scanning. Greatly increases coverage.",
            group="advanced",
        ),
        FieldSchema(
            key="template_check",
            label="Show Template Coverage Stats",
            field_type="toggle",
            default=True,
            help_text="Report how many CVE templates are installed and their year breakdown.",
            group="advanced",
        ),
        FieldSchema(
            key="rate_limit",
            label="Rate Limit (req/s)",
            field_type="range_slider",
            default=150,
            min_value=10,
            max_value=500,
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
        FieldSchema(
            key="headers",
            label="Custom Headers",
            field_type="header_list",
            required=False,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os, json
        from pathlib import Path

        target = params["target_url"].strip()
        work_dir = Path(f"/tmp/pentools/{job_id}")
        work_dir.mkdir(parents=True, exist_ok=True)

        # ── Step 1: Template coverage check ──────────────────────────────────
        if params.get("template_check", True):
            stream("info", "[1/3] Checking nuclei template coverage...")
            # Check both possible template locations (new XDG path and legacy)
            for tpl_candidate in [
                Path("/opt/tools/nuclei-templates"),
                Path("/opt/tools/.local/share/nuclei-templates"),
            ]:
                if tpl_candidate.exists():
                    tmpl_base = tpl_candidate
                    break
            else:
                tmpl_base = None

            if tmpl_base:
                cve_templates = list(tmpl_base.rglob("*.yaml"))
                cve_only = [t for t in cve_templates if "/cves/" in str(t) or "CVE-" in t.name]
                years: dict[str, int] = {}
                for t in cve_only:
                    # Extract year from filename CVE-YYYY-NNNNN.yaml
                    import re
                    m = re.search(r"CVE-(\d{4})-", t.name)
                    if m:
                        years[m.group(1)] = years.get(m.group(1), 0) + 1
                yr_summary = ", ".join(f"{y}:{c}" for y, c in sorted(years.items(), reverse=True)[:8])
                stream("success",
                       f"Templates: {len(cve_templates)} total | {len(cve_only)} CVE | Years: {yr_summary}")
            else:
                stream("warning", "Nuclei templates not found. Run tools container to download them.")

        # ── Step 2: URL discovery ─────────────────────────────────────────────
        url_discovery = params.get("url_discovery", "none")
        targets_file = work_dir / "targets.txt"

        if url_discovery == "none":
            targets_file.write_text(target + "\n")
            stream("info", f"[2/3] URL discovery skipped — scanning {target} only.")
        else:
            import urllib.parse
            domain = urllib.parse.urlparse(target).hostname or target
            all_urls: set[str] = {target}

            if url_discovery in ("waybackurls", "gau"):
                wayback_bin = "/opt/tools/bin/waybackurls"
                if os.path.isfile(wayback_bin):
                    stream("info", f"[2/3] waybackurls — fetching historical URLs for {domain}...")
                    runner = ToolRunner("waybackurls")
                    result = runner.run(args=[domain], stream=stream, timeout=120)
                    for url in result.get("stdout", "").splitlines():
                        url = url.strip()
                        if url and url.startswith("http"):
                            all_urls.add(url)
                    stream("success", f"waybackurls: {len(all_urls)-1} historical URLs found.")
                else:
                    stream("warning", "waybackurls not installed yet — skipping.")

            if url_discovery == "gau":
                gau_bin = "/opt/tools/bin/gau"
                if os.path.isfile(gau_bin):
                    stream("info", f"[2/3] gau — fetching URLs from OTX/CommonCrawl/URLScan for {domain}...")
                    runner = ToolRunner("gau")
                    result = runner.run(
                        args=["--threads", "5", "--timeout", "60", domain],
                        stream=stream, timeout=120,
                    )
                    before = len(all_urls)
                    for url in result.get("stdout", "").splitlines():
                        url = url.strip()
                        if url and url.startswith("http"):
                            all_urls.add(url)
                    stream("success", f"gau: {len(all_urls) - before} additional URLs found.")
                else:
                    stream("warning", "gau not installed yet — skipping.")

            # Deduplicate and cap at 5000 URLs to prevent runaway scans
            url_list = sorted(all_urls)[:5000]
            targets_file.write_text("\n".join(url_list))
            stream("info", f"[2/3] Total scan targets: {len(url_list)} URLs.")

        # ── Step 3: Nuclei CVE scan ───────────────────────────────────────────
        extra = ["-tags", "cve", "-rate-limit", str(params.get("rate_limit", 150))]

        year = params.get("year_filter", "").strip()
        if year:
            for y in year.split(","):
                y = y.strip()
                if y.isdigit() and len(y) == 4:
                    extra += ["-tags", f"cve-{y}"]

        stream("info", f"[3/3] Running nuclei CVE scan...")

        # Use -list if we have more than 1 target
        url_count = len(targets_file.read_text().strip().splitlines())
        if url_count > 1:
            params = dict(params)  # copy so we can mutate
            params["_targets_file"] = str(targets_file)

        return self._run_nuclei(params, job_id, stream, extra_args=extra)


# ─── [V-02] Nuclei — Misconfiguration ────────────────────────────────────────

class NucleiMisconfigModule(_NucleiBaseModule):
    id = "V-02"
    name = "Nuclei — Misconfiguration Scan"
    category = "vuln_scan"
    description = (
        "Run Nuclei misconfiguration templates: exposed panels, "
        "default credentials, debug endpoints, and config leaks."
    )
    risk_level = "high"
    tags = ["nuclei", "misconfiguration", "default-creds", "exposed-panels"]

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com",
        ),
        FieldSchema(
            key="severity",
            label="Minimum Severity",
            field_type="select",
            default="medium,high,critical",
            options=[
                {"value": "info,low,medium,high,critical", "label": "All"},
                {"value": "medium,high,critical",          "label": "Medium and above"},
                {"value": "high,critical",                 "label": "High and critical only"},
            ],
        ),
        FieldSchema(
            key="tag_filter",
            label="Tag Filter",
            field_type="checkbox_group",
            required=False,
            default=["misconfig"],
            options=[
                {"value": "misconfig",      "label": "Misconfiguration"},
                {"value": "default-login",  "label": "Default login"},
                {"value": "exposure",       "label": "Exposure"},
                {"value": "panel",          "label": "Admin panel"},
                {"value": "config",         "label": "Config files"},
            ],
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
            key="headers",
            label="Custom Headers",
            field_type="header_list",
            required=False,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        tags = params.get("tag_filter", ["misconfig"])
        if isinstance(tags, list) and tags:
            tag_str = ",".join(tags)
        else:
            tag_str = "misconfig"
        return self._run_nuclei(params, job_id, stream, extra_args=["-tags", tag_str])


# ─── [V-03] Nuclei — Web Templates ───────────────────────────────────────────

class NucleiWebTemplatesModule(_NucleiBaseModule):
    id = "V-03"
    name = "Nuclei — Web Templates Scan"
    category = "vuln_scan"
    description = (
        "Run Nuclei web templates: injection points, SSRF, takeover patterns, "
        "XSS, SQLi, and other web application vulnerabilities."
    )
    risk_level = "high"
    tags = ["nuclei", "web", "injection", "ssrf", "xss", "sqli"]

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com",
        ),
        FieldSchema(
            key="severity",
            label="Minimum Severity",
            field_type="select",
            default="medium,high,critical",
            options=[
                {"value": "info,low,medium,high,critical", "label": "All"},
                {"value": "medium,high,critical",          "label": "Medium and above"},
                {"value": "high,critical",                 "label": "High and critical only"},
            ],
        ),
        FieldSchema(
            key="tag_filter",
            label="Vulnerability Types",
            field_type="checkbox_group",
            default=["xss", "sqli", "ssrf", "redirect"],
            options=[
                {"value": "xss",          "label": "Cross-Site Scripting (XSS)"},
                {"value": "sqli",         "label": "SQL Injection"},
                {"value": "ssrf",         "label": "SSRF"},
                {"value": "redirect",     "label": "Open Redirect"},
                {"value": "lfi",          "label": "LFI / Path Traversal"},
                {"value": "rce",          "label": "Remote Code Execution"},
                {"value": "ssti",         "label": "SSTI"},
                {"value": "xxe",          "label": "XXE"},
            ],
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
            key="headers",
            label="Custom Headers",
            field_type="header_list",
            required=False,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        tags = params.get("tag_filter", ["xss", "sqli", "ssrf"])
        if isinstance(tags, list) and tags:
            tag_str = ",".join(tags)
        else:
            tag_str = "xss,sqli,ssrf"
        return self._run_nuclei(params, job_id, stream, extra_args=["-tags", tag_str])


# ─── [V-04] Nuclei — API Templates ───────────────────────────────────────────

class NucleiAPITemplatesModule(_NucleiBaseModule):
    id = "V-04"
    name = "Nuclei — API Security Scan"
    category = "vuln_scan"
    description = (
        "Run Nuclei templates targeting API-specific vulnerabilities: "
        "JWT weaknesses, GraphQL introspection, REST API misconfigurations."
    )
    risk_level = "high"
    tags = ["nuclei", "api", "jwt", "graphql", "rest", "swagger"]
    celery_queue = "api_queue"

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target API Base URL", field_type="url",
                    required=True, placeholder="https://api.example.com"),
        FieldSchema(key="severity", label="Minimum Severity", field_type="select",
                    default="medium,high,critical",
                    options=[
                        {"value": "info,low,medium,high,critical", "label": "All"},
                        {"value": "medium,high,critical",          "label": "Medium and above"},
                        {"value": "high,critical",                 "label": "High and critical only"},
                    ]),
        FieldSchema(key="api_tag_filter", label="API Vulnerability Focus",
                    field_type="checkbox_group",
                    default=["jwt", "graphql", "rest", "swagger"],
                    options=[
                        {"value": "jwt",       "label": "JWT vulnerabilities"},
                        {"value": "graphql",   "label": "GraphQL exposure"},
                        {"value": "rest",      "label": "REST API issues"},
                        {"value": "swagger",   "label": "Swagger/OpenAPI exposure"},
                        {"value": "oauth",     "label": "OAuth2 misconfig"},
                        {"value": "api-key",   "label": "API Key exposure"},
                    ]),
        FieldSchema(key="auth_cookie", label="Session Cookie", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="headers", label="Custom Headers", field_type="header_list",
                    required=False),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        tags = params.get("api_tag_filter", ["jwt", "graphql", "rest"])
        if isinstance(tags, list) and tags:
            tag_str = ",".join(tags)
        else:
            tag_str = "jwt,graphql,rest"
        return self._run_nuclei(params, job_id, stream, extra_args=["-tags", tag_str])


# ─── [V-05] Nuclei — Network Templates ───────────────────────────────────────

class NucleiNetworkTemplatesModule(_NucleiBaseModule):
    id = "V-05"
    name = "Nuclei — Network & Service Scan"
    category = "vuln_scan"
    description = (
        "Run Nuclei network-type templates to detect open services, "
        "default credentials on network daemons, and service fingerprints."
    )
    risk_level = "high"
    tags = ["nuclei", "network", "ports", "service", "fingerprint"]
    celery_queue = "vuln_scan_queue"

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL / Host", field_type="url",
                    required=True, placeholder="https://example.com"),
        FieldSchema(key="severity", label="Minimum Severity", field_type="select",
                    default="medium,high,critical",
                    options=[
                        {"value": "info,low,medium,high,critical", "label": "All"},
                        {"value": "medium,high,critical",          "label": "Medium and above"},
                        {"value": "high,critical",                 "label": "High and critical only"},
                    ]),
        FieldSchema(key="net_tag_filter", label="Service Types",
                    field_type="checkbox_group",
                    default=["network", "exposed"],
                    options=[
                        {"value": "network",            "label": "Network service detection"},
                        {"value": "exposed",            "label": "Exposed panels/services"},
                        {"value": "default-login",      "label": "Default credentials"},
                        {"value": "ftp",                "label": "FTP vulnerabilities"},
                        {"value": "ssh",                "label": "SSH misconfig"},
                        {"value": "database",           "label": "Open databases"},
                    ]),
        FieldSchema(key="auth_cookie", label="Session Cookie", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="headers", label="Custom Headers", field_type="header_list",
                    required=False),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        tags = params.get("net_tag_filter", ["network", "exposed"])
        if isinstance(tags, list) and tags:
            tag_str = ",".join(tags)
        else:
            tag_str = "network,exposed"
        return self._run_nuclei(params, job_id, stream, extra_args=["-tags", tag_str, "-type", "network"])


# ─── [V-06] Nuclei — Custom Template ─────────────────────────────────────────

class NucleiCustomTemplateModule(_NucleiBaseModule):
    id = "V-06"
    name = "Nuclei — Custom YAML Template"
    category = "vuln_scan"
    description = (
        "Execute a user-supplied Nuclei YAML template against the target. "
        "Upload custom templates to test bespoke vulnerability logic."
    )
    risk_level = "high"
    tags = ["nuclei", "custom", "yaml", "template"]
    celery_queue = "vuln_scan_queue"

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL", field_type="url",
                    required=True, placeholder="https://example.com"),
        FieldSchema(key="template_yaml", label="Nuclei YAML Template Content",
                    field_type="textarea", required=True,
                    placeholder="id: my-check\ninfo:\n  name: ...\nrequests:\n  - ..."),
        FieldSchema(key="severity", label="Minimum Severity", field_type="select",
                    default="info,low,medium,high,critical",
                    options=[{"value": "info,low,medium,high,critical", "label": "All"}]),
        FieldSchema(key="auth_cookie", label="Session Cookie", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="headers", label="Custom Headers", field_type="header_list",
                    required=False),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os, tempfile
        yaml_content = params.get("template_yaml", "")
        if not yaml_content.strip():
            return {"status": "failed", "findings": [], "error": "No template YAML provided."}

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as tf:
            tf.write(yaml_content)
            tmp_path = tf.name

        try:
            result = self._run_nuclei(params, job_id, stream, extra_args=["-t", tmp_path])
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass
        return result


# ─── [V-07] CMS Scanner ───────────────────────────────────────────────────────

class CMSScannerModule(_NucleiBaseModule):
    id = "V-07"
    name = "CMS Vulnerability Scanner"
    category = "vuln_scan"
    description = (
        "Detect CMS (WordPress, Drupal, Joomla, Magento, etc.) and scan for "
        "known CVEs, plugin vulnerabilities, and weak configurations using Nuclei."
    )
    risk_level = "high"
    tags = ["nuclei", "cms", "wordpress", "drupal", "joomla", "magento"]
    celery_queue = "vuln_scan_queue"

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL", field_type="url",
                    required=True, placeholder="https://example.com"),
        FieldSchema(key="severity", label="Minimum Severity", field_type="select",
                    default="low,medium,high,critical",
                    options=[
                        {"value": "info,low,medium,high,critical", "label": "All"},
                        {"value": "low,medium,high,critical",      "label": "Low and above"},
                        {"value": "medium,high,critical",          "label": "Medium and above"},
                        {"value": "high,critical",                 "label": "High and critical only"},
                    ]),
        FieldSchema(key="cms_targets", label="CMS Types",
                    field_type="checkbox_group",
                    default=["wordpress", "drupal", "joomla"],
                    options=[
                        {"value": "wordpress", "label": "WordPress"},
                        {"value": "drupal",    "label": "Drupal"},
                        {"value": "joomla",    "label": "Joomla"},
                        {"value": "magento",   "label": "Magento"},
                        {"value": "cms",       "label": "Generic CMS templates"},
                    ]),
        FieldSchema(key="auth_cookie", label="Session Cookie", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="headers", label="Custom Headers", field_type="header_list",
                    required=False),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        cms_list = params.get("cms_targets", ["wordpress", "drupal", "joomla", "cms"])
        if isinstance(cms_list, list) and cms_list:
            tag_str = ",".join(cms_list)
        else:
            tag_str = "cms,wordpress,drupal,joomla"
        return self._run_nuclei(params, job_id, stream, extra_args=["-tags", tag_str])


# ─── [V-08] Dependency Vulnerability Scanner ─────────────────────────────────

class DependencyVulnModule(_NucleiBaseModule):
    id = "V-08"
    name = "Dependency Vulnerability Scanner"
    category = "vuln_scan"
    description = (
        "Detect exposed outdated technology versions using Nuclei CVE templates "
        "and tech-detection, then cross-reference for known vulnerabilities."
    )
    risk_level = "high"
    tags = ["nuclei", "cve", "dependency", "outdated", "version-detection", "tech"]
    celery_queue = "vuln_scan_queue"

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL", field_type="url",
                    required=True, placeholder="https://example.com"),
        FieldSchema(key="severity", label="Minimum Severity", field_type="select",
                    default="medium,high,critical",
                    options=[
                        {"value": "info,low,medium,high,critical", "label": "All (includes tech-detect)"},
                        {"value": "medium,high,critical",          "label": "Medium and above"},
                        {"value": "high,critical",                 "label": "High and critical only"},
                    ]),
        FieldSchema(key="scan_mode", label="Scan Mode",
                    field_type="select",
                    default="cve",
                    options=[
                        {"value": "cve",       "label": "CVE templates (known CVEs)"},
                        {"value": "tech",      "label": "Tech detection + version"},
                        {"value": "cve,tech",  "label": "Both (slowest, most thorough)"},
                    ]),
        FieldSchema(key="auth_cookie", label="Session Cookie", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="headers", label="Custom Headers", field_type="header_list",
                    required=False),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        scan_mode = params.get("scan_mode", "cve")
        tags = [t.strip() for t in scan_mode.split(",") if t.strip()]
        if not tags:
            tags = ["cve"]
        tag_str = ",".join(tags)
        return self._run_nuclei(params, job_id, stream, extra_args=["-tags", tag_str])


# ─── [V-09] Default Credentials Tester ───────────────────────────────────────

class DefaultCredsTesterModule(_NucleiBaseModule):
    id = "V-09"
    name = "Default Credentials Tester"
    category = "vuln_scan"
    description = (
        "Test login panels for default credentials using Nuclei default-login "
        "templates and a built-in common default credential list."
    )
    risk_level = "critical"
    tags = ["nuclei", "default-login", "credentials", "auth", "brute"]
    celery_queue = "vuln_scan_queue"

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target URL", field_type="url",
                    required=True, placeholder="https://example.com/admin"),
        FieldSchema(key="severity", label="Minimum Severity", field_type="select",
                    default="medium,high,critical",
                    options=[
                        {"value": "info,low,medium,high,critical", "label": "All"},
                        {"value": "medium,high,critical",          "label": "Medium and above"},
                        {"value": "high,critical",                 "label": "High and critical only"},
                    ]),
        FieldSchema(key="use_nuclei", label="Use Nuclei default-login templates",
                    field_type="select", options=["yes", "no"], default="yes"),
        FieldSchema(key="manual_creds", label="Also Test These Custom Creds (user:pass one per line)",
                    field_type="textarea", required=False,
                    placeholder="admin:admin\nroot:toor\nadmin:password"),
        FieldSchema(key="login_endpoint", label="Login Endpoint Path (for manual test)",
                    field_type="text", required=False, default="/admin/login",
                    show_if={"use_nuclei": "no"}),
        FieldSchema(key="username_field", label="Username Field", field_type="text",
                    default="username",
                    show_if={"use_nuclei": "no"}),
        FieldSchema(key="password_field", label="Password Field", field_type="text",
                    default="password",
                    show_if={"use_nuclei": "no"}),
        FieldSchema(key="auth_cookie", label="Session Cookie", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="headers", label="Custom Headers", field_type="header_list",
                    required=False),
    ]

    _BUILTIN_CREDS = [
        ("admin",  "admin"),       ("admin",    "password"),
        ("admin",  "123456"),      ("admin",    "1234"),
        ("root",   "root"),        ("root",     "toor"),
        ("root",   "admin"),       ("test",     "test"),
        ("guest",  "guest"),       ("admin",    "admin123"),
        ("admin",  "admin@123"),   ("admin",    ""),
        ("user",   "user"),        ("demo",     "demo"),
        ("support","support"),     ("operator", "operator"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3; urllib3.disable_warnings()

        use_nuclei = params.get("use_nuclei", "yes") == "yes"
        findings = []

        if use_nuclei:
            result = self._run_nuclei(params, job_id, stream, extra_args=["-tags", "default-login"])
            findings += result.get("findings", [])

        manual_raw = params.get("manual_creds") or ""
        cred_pairs = list(self._BUILTIN_CREDS)
        for line in manual_raw.splitlines():
            line = line.strip()
            if ":" in line:
                parts = line.split(":", 1)
                cred_pairs.append((parts[0], parts[1]))

        if not cred_pairs:
            return {"status": "done", "findings": findings}

        base_url = params["target_url"].rstrip("/")
        login_path = params.get("login_endpoint") or "/admin/login"
        u_field = params.get("username_field") or "username"
        p_field = params.get("password_field") or "password"
        login_url = base_url + login_path

        session = requests.Session()
        session.verify = False
        headers = {"User-Agent": "PenTools/1.0"}
        valid_creds = []

        stream(f"[V-09] Testing {len(cred_pairs)} default credential pairs against {login_url}...")
        for username, password in cred_pairs:
            try:
                r = session.post(login_url, json={u_field: username, p_field: password},
                                 headers=headers, timeout=8)
                if r.status_code in (200, 302) and any(
                    kw in r.text.lower() for kw in ("dashboard", "logout", "welcome", "access_token")
                ):
                    valid_creds.append(username + ":" + password)
                    stream("[V-09] VALID: " + username + ":" + password)
            except Exception:
                pass

        if valid_creds:
            findings.append({
                "title": "Default Credentials Accepted",
                "severity": "critical",
                "url": login_url,
                "description": (
                    str(len(valid_creds)) + " default credential pair(s) were accepted. "
                    "Attackers can gain immediate privileged access."
                ),
                "evidence": "Valid creds: " + "; ".join(valid_creds[:5]),
                "remediation": (
                    "Change all default credentials immediately. Enforce strong password policy. "
                    "Implement account lockout after failed attempts."
                ),
                "cwe_id": "CWE-1393",
            })

        return {"status": "done", "findings": findings}


# ─── [V-10] CVE PoC Auto-Matcher ─────────────────────────────────────────────

class CVEPoCMatcherModule(BaseModule):
    id = "V-10"
    name = "CVE PoC Auto-Matcher"
    category = "vuln_scan"
    description = (
        "Fingerprint detected software versions against a curated list of known CVEs, "
        "then automatically run matching Nuclei CVE templates. Identifies unpatched "
        "vulnerabilities based on version banners and HTTP response characteristics."
    )
    risk_level = "high"
    tags = ["cve", "poc", "nuclei", "version", "fingerprint", "exploit"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",         label="Target URL",   field_type="url",  required=True),
        FieldSchema(
            key="tech_hints",
            label="Technology version hints (one per line)",
            field_type="textarea",
            required=False,
            placeholder="nginx 1.18.0\napache 2.4.49\nwp 5.8.0\nlog4j 2.14.1",
            help_text="Enter 'product version' pairs. Blank = auto-fingerprint from headers.",
        ),
        FieldSchema(key="cvss_min",    label="Minimum CVSS score",  field_type="number", default=7.0,
                    help_text="Only show and test CVEs at or above this score."),
        FieldSchema(
            key="run_nuclei",
            label="Run Nuclei CVE templates",
            field_type="toggle",
            default=True,
        ),
        FieldSchema(
            key="nuclei_severity",
            label="Nuclei template severity",
            field_type="checkbox_group",
            default=["critical", "high"],
            options=[
                {"value": "critical", "label": "Critical"},
                {"value": "high",     "label": "High"},
                {"value": "medium",   "label": "Medium"},
            ],
            show_if={"run_nuclei": True},
        ),
        FieldSchema(key="auth_header", label="Authorization", field_type="text", required=False, group="credentials"),
    ]

    # Curated CVE fingerprint matching rules: (keyword, version_operator, affected_version, cve_id, cvss, description)
    CVE_DB = [
        # nginx
        ("nginx/1.18",  None, None, "CVE-2021-23017", 7.7, "nginx 1.18.x resolver overflow"),
        ("nginx/1.16",  None, None, "CVE-2021-23017", 7.7, "nginx 1.16.x resolver overflow"),
        ("nginx/1.14",  None, None, "CVE-2020-11724", 7.5, "nginx 1.14 request smuggling"),
        # Apache httpd
        ("apache/2.4.49", None, None, "CVE-2021-41773", 9.8, "Apache 2.4.49 path traversal + RCE"),
        ("apache/2.4.50", None, None, "CVE-2021-42013", 9.8, "Apache 2.4.50 path traversal + RCE"),
        ("apache/2.4.48", None, None, "CVE-2021-40438", 9.0, "Apache 2.4.48 mod_proxy SSRF"),
        # WordPress
        ("wp/5.8",     None, None, "CVE-2021-29447", 7.1, "WordPress 5.8 XXE via media upload"),
        ("wp/5.7",     None, None, "CVE-2021-29447", 7.1, "WordPress 5.8 XXE"),
        ("wordpress/5.8", None, None, "CVE-2021-29447", 7.1, "WordPress 5.8 XXE via media upload"),
        # Log4j
        ("log4j/2.14",  None, None, "CVE-2021-44228", 10.0, "Log4Shell — JNDI RCE (Log4j 2.14.x)"),
        ("log4j/2.15",  None, None, "CVE-2021-45046", 9.0, "Log4Shell bypass (Log4j 2.15.x)"),
        ("log4j/2.0",   None, None, "CVE-2021-44228", 10.0, "Log4Shell — JNDI RCE"),
        # Spring Framework
        ("spring/5.3.17", None, None, "CVE-2022-22963", 9.8, "Spring Cloud Function SpEL injection"),
        ("spring-boot/2.6.5", None, None, "CVE-2022-22965", 9.8, "Spring4Shell RCE"),
        # PHP
        ("php/7.4",    None, None, "CVE-2021-21703",  7.0, "PHP 7.4.x FPM privilege escalation"),
        ("php/8.0",    None, None, "CVE-2022-31625",  9.8, "PHP 8.0 use-after-free"),
        # OpenSSL
        ("openssl/1.1.1", None, None, "CVE-2022-0778", 7.5, "OpenSSL infinite loop in BN_mod_sqrt()"),
        ("openssl/3.0",   None, None, "CVE-2022-3786", 7.5, "OpenSSL 3.x buffer overflow"),
        # Drupal
        ("drupal/7",   None, None, "CVE-2014-3704", 10.0, "Drupalgeddon SQLi"),
        ("drupal/8",   None, None, "CVE-2018-7600",  9.8, "Drupalgeddon2 RCE"),
        # Jenkins
        ("jenkins/2.3", None, None, "CVE-2019-1003000", 8.8, "Jenkins Script Security sandbox bypass"),
        # Joomla
        ("joomla/3",   None, None, "CVE-2015-8562", 10.0, "Joomla PHP object injection"),
        # Struts
        ("struts/2",  None, None, "CVE-2017-5638",  10.0, "Apache Struts2 OGNL injection (S2-045)"),
    ]

    def _fingerprint(self, url: str, auth: str, timeout: int = 10) -> list:
        """Fingerprint technology from response headers and body."""
        import urllib.request, urllib.error, re
        headers = {"User-Agent": "PenTools/1.0"}
        if auth:
            headers["Authorization"] = auth
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                resp_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
                body = r.read(8192).decode("utf-8", errors="replace").lower()
        except urllib.error.HTTPError as e:
            resp_headers = {k.lower(): v.lower() for k, v in e.headers.items()}
            body = e.read(2048).decode("utf-8", errors="replace").lower()
        except Exception:
            return []

        detected = []
        # Server header
        server = resp_headers.get("server", "")
        if server:
            detected.append(server)
        # X-Powered-By
        xpb = resp_headers.get("x-powered-by", "")
        if xpb:
            detected.append(xpb)
        # Body generators
        for pattern in [
            r"wp-content", r"joomla", r"drupal", r"apache",
            r"nginx/[\d.]+", r"php/[\d.]+",
        ]:
            m = re.search(pattern, body + server + xpb)
            if m:
                detected.append(m.group(0))
        return list(set(detected))

    def _match_cves(self, tech_strings: list, cvss_min: float) -> list:
        matched = []
        for ts in tech_strings:
            ts_norm = ts.lower().replace(" ", "/")
            for keyword, _, _, cve_id, cvss, desc in self.CVE_DB:
                if cvss < cvss_min:
                    continue
                if keyword.lower() in ts_norm:
                    matched.append((cve_id, cvss, desc, ts))
        # Deduplicate by CVE ID
        seen = set()
        result = []
        for m in matched:
            if m[0] not in seen:
                seen.add(m[0])
                result.append(m)
        return sorted(result, key=lambda x: -x[1])

    def execute(self, params: dict, job_id: str, stream) -> dict:
        from apps.modules.runner import ToolRunner

        url = params["target_url"].strip()
        tech_hints_raw = params.get("tech_hints", "").strip()
        cvss_min = float(params.get("cvss_min", 7.0))
        run_nuclei = params.get("run_nuclei", True)
        nuclei_severity = params.get("nuclei_severity", ["critical", "high"])
        auth = params.get("auth_header", "").strip()

        findings = []
        raw_lines = [f"Target: {url}", f"CVSS min: {cvss_min}"]

        # Parse tech hints
        manual_techs = []
        if tech_hints_raw:
            for line in tech_hints_raw.splitlines():
                parts = line.strip().split()
                if len(parts) >= 2:
                    product, version = parts[0], parts[1]
                    manual_techs.append(f"{product}/{version}")
                elif parts:
                    manual_techs.append(parts[0])

        # Auto-fingerprint
        stream("info", "Fingerprinting target...")
        auto_techs = self._fingerprint(url, auth)
        stream("info", f"Auto-detected: {auto_techs}")
        raw_lines.append(f"Auto-detected: {auto_techs}")
        raw_lines.append(f"Manual hints: {manual_techs}")

        all_techs = list(set(auto_techs + manual_techs))

        # Match against CVE DB
        matched_cves = self._match_cves(all_techs, cvss_min)
        stream("info", f"Matched {len(matched_cves)} CVE(s): {[c[0] for c in matched_cves]}")

        if matched_cves:
            findings.append({
                "title": f"{len(matched_cves)} CVE(s) matched from detected technologies",
                "severity": "high",
                "url": url,
                "description": (
                    "The following CVEs match the detected technology stack and meet the CVSS threshold:\n\n"
                    + "\n".join(f"- {cve} (CVSS {cvss}): {desc} (from: {tech})"
                                for cve, cvss, desc, tech in matched_cves[:15])
                ),
                "evidence": f"Detected: {all_techs}\nMatched: {[(c[0], c[1]) for c in matched_cves]}",
                "remediation": (
                    "Update affected components to patched versions. "
                    "Apply vendor security patches. Enable WAF rules for critical CVEs."
                ),
                "cvss_score": matched_cves[0][1] if matched_cves else 7.0,
            })

            for cve_id, cvss, desc, tech in matched_cves[:5]:
                findings.append({
                    "title": f"{cve_id} — {desc}",
                    "severity": "critical" if cvss >= 9.0 else "high",
                    "url": url,
                    "description": f"{desc}\nCVSS: {cvss}\nAffected detect: {tech}",
                    "evidence": f"Technology fingerprint: {tech}",
                    "remediation": f"Patch or upgrade the affected component. See https://nvd.nist.gov/vuln/detail/{cve_id}",
                    "cvss_score": cvss,
                    "cve_id": cve_id,
                })

        # Run Nuclei CVE templates
        if run_nuclei and matched_cves:
            cve_ids = [c[0] for c in matched_cves[:10]]
            severity_filter = ",".join(nuclei_severity)
            nuclei_tpl_dir = "/opt/tools/nuclei-templates"
            stream("info", f"Running Nuclei for CVEs: {cve_ids}")
            runner = ToolRunner("nuclei")
            for cve_id in cve_ids[:5]:
                tpl_path = f"{nuclei_tpl_dir}/http/cves/{cve_id.lower()}.yaml"
                if not os.path.isfile(tpl_path):
                    tpl_path = f"{nuclei_tpl_dir}/cves/{cve_id.lower()}.yaml"
                if not os.path.isfile(tpl_path):
                    stream("warning", f"No template found for {cve_id}, skipping.")
                    continue
                result = runner.run(
                    args=["-u", url, "-t", tpl_path,
                          "-severity", severity_filter, "-j", "-silent"],
                    stream=stream, timeout=60
                )
                stdout = result.get("stdout", "").strip()
                if stdout:
                    for line in stdout.splitlines():
                        try:
                            import json
                            hit = json.loads(line)
                            template_id = hit.get("template-id", cve_id)
                            matched_at = hit.get("matched-at", url)
                            severity = hit.get("info", {}).get("severity", "high")
                            findings.append({
                                "title": f"Nuclei confirmed: {template_id}",
                                "severity": severity,
                                "url": matched_at,
                                "description": f"Nuclei template {template_id} matched on {matched_at}.",
                                "evidence": line[:500],
                                "remediation": "Apply patch for " + template_id,
                                "cvss_score": matched_cves[0][1],
                                "cve_id": cve_id,
                            })
                        except Exception:
                            raw_lines.append(f"[nuclei/{cve_id}] {line[:100]}")
        elif run_nuclei and not matched_cves:
            stream("info", "No matched CVEs — running broad nuclei CVE scan...")
            nuclei_tpl_dir = "/opt/tools/nuclei-templates"
            cve_dir = os.path.join(nuclei_tpl_dir, "http", "cves")
            if not os.path.isdir(cve_dir):
                cve_dir = os.path.join(nuclei_tpl_dir, "cves")
            runner = ToolRunner("nuclei")
            result = runner.run(
                args=["-u", url, "-t", cve_dir, "-severity", ",".join(nuclei_severity),
                      "-j", "-silent", "-rate-limit", "20"],
                stream=stream, timeout=120,
            )
            stdout = result.get("stdout", "").strip()
            for line in stdout.splitlines()[:20]:
                try:
                    import json
                    hit = json.loads(line)
                    findings.append({
                        "title": f"Nuclei CVE: {hit.get('template-id','unknown')}",
                        "severity": hit.get("info", {}).get("severity", "high"),
                        "url": hit.get("matched-at", url),
                        "description": hit.get("info", {}).get("description", ""),
                        "evidence": line[:500],
                        "remediation": "Apply vendor patch for detected CVE.",
                    })
                except Exception:
                    pass

        if not findings:
            findings.append({
                "title": "CVE PoC matcher — no CVEs matched",
                "severity": "info", "url": url,
                "description": "No CVEs matched detected technology stack above the CVSS threshold.",
                "evidence": f"Detected: {all_techs}\nCVSS min: {cvss_min}",
                "remediation": "Add technology version hints manually if auto-detect is insufficient.",
            })

        stream("success", f"CVE PoC matcher complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ═══════════════════════════════════════════════════════════════════════════════
# OWASP ZAP modules
# Prerequisites: the `zap` Docker service must be running (docker-compose up zap).
# ZAP_API_URL and ZAP_API_KEY must be set in .env (defaults: http://zap:8080 / changeme).
# ═══════════════════════════════════════════════════════════════════════════════

class _ZAPBaseModule(BaseModule):
    """
    Shared base for all OWASP ZAP integration modules.

    The ZAP daemon runs as a separate Docker service and is reachable
    at http://zap:8080 (service name DNS) from all containers in the
    same Compose network.  No binary is needed in the tools volume.
    """

    celery_queue = "vuln_scan_queue"
    time_limit   = 3600   # 1-hour hard cap per scan

    _BASE_PARAMS = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com",
        ),
        FieldSchema(
            key="auth_cookie",
            label="Session Cookie",
            field_type="text",
            required=False,
            sensitive=True,
            help_text="Full Cookie header value for authenticated scans.",
            group="credentials",
        ),
        FieldSchema(
            key="auth_header",
            label="Authorization Header",
            field_type="text",
            required=False,
            sensitive=True,
            placeholder="Bearer eyJ...",
            help_text="Value for the Authorization header (optional).",
            group="credentials",
        ),
        FieldSchema(
            key="zap_api_url",
            label="ZAP API URL",
            field_type="text",
            required=False,
            default="",
            placeholder="http://zap:8080",
            help_text="Leave blank to use ZAP_API_URL env-var (recommended).",
            group="advanced",
        ),
        FieldSchema(
            key="zap_api_key",
            label="ZAP API Key",
            field_type="text",
            required=False,
            default="",
            sensitive=True,
            help_text="Leave blank to use ZAP_API_KEY env-var (recommended).",
            group="advanced",
        ),
    ]

    def _get_client(self, params: dict):
        from apps.vuln_scan.zap import ZAPClient, ZAPNotAvailableError
        url = (params.get("zap_api_url") or "").strip() or None
        key = (params.get("zap_api_key") or "").strip() or None
        client = ZAPClient(api_url=url, api_key=key)
        try:
            info = client.ping()
            version = info.get("version", "unknown")
            return client, version
        except ZAPNotAvailableError as exc:
            raise RuntimeError(
                "OWASP ZAP daemon is not reachable. "
                "Make sure the 'zap' service is running: docker compose up -d zap\n"
                f"Detail: {exc}"
            ) from exc

    def _setup_auth(self, client, params: dict, target_url: str) -> None:
        from apps.vuln_scan.zap import ZAPClient
        cookie = (params.get("auth_cookie") or "").strip()
        auth   = (params.get("auth_header") or "").strip()
        if cookie:
            client.add_session_cookie(target_url, cookie)
        if auth:
            client.set_custom_header("Authorization", auth)


# ─── [ZAP-01] OWASP ZAP — Web Spider ─────────────────────────────────────────

class ZAPSpiderModule(_ZAPBaseModule):
    id          = "ZAP-01"
    name        = "OWASP ZAP — Web Spider"
    category    = "vuln_scan"
    description = (
        "Pure URL discovery and site-mapping using OWASP ZAP's traditional spider "
        "and optional Ajax spider. Crawls the target without sending any attack payloads "
        "and categorises every discovered endpoint by type: admin panels, API routes, "
        "authentication pages, sensitive file extensions, and static assets. "
        "Produces a structured site map that can feed directly into ZAP-02 (Passive "
        "Audit) or ZAP-03 (Active Audit)."
    )
    risk_level  = "low"
    tags        = ["zap", "owasp", "spider", "crawler", "recon", "sitemap"]

    # Patterns to classify discovered URLs into categories
    _ADMIN_PAT    = re.compile(
        r"/admin|/manager|/console|/dashboard|/panel|/cpanel|/wp-admin|"
        r"/phpmyadmin|/myadmin|/webadmin|/backend|/sys/|/manage/", re.I)
    _API_PAT      = re.compile(
        r"/api/|/v\d+/|/graphql|/rest/|/swagger|/openapi|/api-docs|"
        r"\.json$|\.xml$|/rpc|/query", re.I)
    _AUTH_PAT     = re.compile(
        r"/login|/signin|/auth|/oauth|/logout|/register|/signup|"
        r"/reset-password|/forgot|/token|/session", re.I)
    _SENSITIVE_PAT = re.compile(
        r"\.(bak|sql|conf|config|env|log|old|txt|git|svn|tar\.gz|"
        r"zip|rar|7z|pem|key|crt|csr|pfx|p12|dump|backup)$", re.I)
    _STATIC_PAT   = re.compile(
        r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf)$", re.I)

    PARAMETER_SCHEMA = _ZAPBaseModule._BASE_PARAMS + [
        FieldSchema(
            key="max_depth",
            label="Max Crawl Depth",
            field_type="number",
            default=5,
            help_text="Maximum link depth the spider will follow (0 = unlimited).",
        ),
        FieldSchema(
            key="use_ajax_spider",
            label="Also run Ajax Spider (JavaScript-rendered pages)",
            field_type="toggle",
            default=False,
            help_text="Slower but discovers JS-rendered routes and single-page-app content.",
            group="advanced",
        ),
        FieldSchema(
            key="ajax_spider_mins",
            label="Ajax Spider Max Minutes",
            field_type="number",
            default=5,
            group="advanced",
        ),
        FieldSchema(
            key="include_out_of_scope",
            label="Report out-of-scope external links",
            field_type="toggle",
            default=False,
            help_text="Create a finding for external hostnames discovered during crawl.",
            group="advanced",
        ),
    ]

    def _categorise_urls(self, urls: list[str]) -> dict:
        import urllib.parse as _up
        cats: dict[str, list[str]] = {
            "admin": [], "api": [], "auth": [], "sensitive": [], "static": [], "other": [],
        }
        for url in urls:
            path = _up.urlparse(url).path
            if self._ADMIN_PAT.search(path):
                cats["admin"].append(url)
            elif self._API_PAT.search(url):
                cats["api"].append(url)
            elif self._AUTH_PAT.search(path):
                cats["auth"].append(url)
            elif self._SENSITIVE_PAT.search(path):
                cats["sensitive"].append(url)
            elif self._STATIC_PAT.search(path):
                cats["static"].append(url)
            else:
                cats["other"].append(url)
        return cats

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.parse as _up
        client, version = self._get_client(params)
        target    = params["target_url"].strip()
        max_depth = int(params.get("max_depth", 5))
        use_ajax  = params.get("use_ajax_spider", False)
        ajax_mins = int(params.get("ajax_spider_mins", 5))
        incl_oos  = params.get("include_out_of_scope", False)

        stream("info", f"[ZAP {version}] Starting Web Spider → {target}")
        stream("info",  "[ZAP] Mode: URL discovery & site mapping — no attack payloads sent")
        client.new_session(f"spider-{job_id[:8]}")
        self._setup_auth(client, params, target)

        # ── Phase 1: Traditional spider ─────────────────────────────────────
        phases = "2" if use_ajax else "1"
        stream("info", f"[ZAP] Phase 1/{phases} — Traditional spider (max depth: {max_depth})…")
        scan_id = client.spider_start(target, max_depth=max_depth)
        client.wait_spider(scan_id, timeout=self.time_limit - 300, stream=stream)

        full_res  = client.spider_full_results(scan_id)
        full_list = full_res.get("fullResults", [])
        # ZAP returns fullResults as a list of single-key dicts:
        # [{"urlsInScope": [...]}, {"urlsOutOfScope": [...]}, {"urlsIoError": [...]}]
        full_data: dict = {}
        for _item in (full_list if isinstance(full_list, list) else []):
            if isinstance(_item, dict):
                full_data.update(_item)
        in_scope  = full_data.get("urlsInScope", [])
        out_scope = full_data.get("urlsOutOfScope", [])
        io_errors = full_data.get("urlsIoError", [])

        # urlsInScope items are dicts {url, statusCode, method, …};
        # urlsOutOfScope items are plain strings
        urls_in  = [u["url"] if isinstance(u, dict) else u for u in in_scope]
        urls_out = [u if isinstance(u, str) else u.get("url", "") for u in out_scope]

        # Build a set of URLs that returned a real "live" HTTP response.
        # Treat 4xx/5xx as non-existent so they don't generate false-positive findings
        # (e.g. robots.txt → 404, .bak → 410).
        _DEAD_STATUS = {400, 401, 403, 404, 405, 408, 410, 451, 500, 502, 503, 504}
        live_urls: list[str] = []
        dead_count = 0
        for u in in_scope:
            if isinstance(u, dict):
                try:
                    code = int(u.get("statusCode", 0))
                except (TypeError, ValueError):
                    code = 0
                if code in _DEAD_STATUS:
                    dead_count += 1
                    continue
            live_urls.append(u["url"] if isinstance(u, dict) else u)

        stream("success",
               f"[ZAP] Traditional spider done — "
               f"{len(urls_in)} in-scope ({dead_count} dead/404 skipped) | "
               f"{len(urls_out)} out-of-scope | {len(io_errors)} I/O errors")

        # ── Phase 2: Ajax spider (optional) ─────────────────────────────────
        ajax_new: list[str] = []
        if use_ajax:
            stream("info", f"[ZAP] Phase 2/2 — Ajax spider (budget: {ajax_mins} min)…")
            client.ajax_spider_start(target)
            deadline = time.time() + ajax_mins * 60
            last_status = ""
            while time.time() < deadline:
                status = client.ajax_spider_status()
                if status != last_status:
                    stream("info", f"[ZAP] Ajax spider: {status}")
                    last_status = status
                if status == "stopped":
                    break
                time.sleep(15)
            ajax_all  = client.ajax_spider_results()
            ajax_new  = [u for u in ajax_all if u not in urls_in]
            urls_in   = list(dict.fromkeys(urls_in + ajax_new))  # deduplicate
            # Ajax results are plain strings without status codes; treat them as live
            live_urls = list(dict.fromkeys(live_urls + [u for u in ajax_new if u not in live_urls]))
            stream("success", f"[ZAP] Ajax spider found {len(ajax_new)} additional JS-rendered URLs.")

        # ── Categorise & report ──────────────────────────────────────────────
        # Only categorise URLs that returned a live HTTP response (not 4xx/5xx)
        cats = self._categorise_urls(live_urls)
        stream("info",
               f"[ZAP] Site map breakdown — "
               f"Admin: {len(cats['admin'])} | API: {len(cats['api'])} | "
               f"Auth: {len(cats['auth'])} | Sensitive ext: {len(cats['sensitive'])} | "
               f"Static: {len(cats['static'])} | Other: {len(cats['other'])}")

        findings: list[dict] = []

        # Admin panels → high severity
        for url in cats["admin"]:
            path = _up.urlparse(url).path
            findings.append({
                "title":       f"[ZAP Spider] Admin / Management Interface: {path}",
                "severity":    "high",
                "url":         url,
                "description": f"An administrative interface was discovered at {url} during the ZAP spider crawl of {target}.",
                "evidence":    f"Discovered URL: {url}\nPattern matched: admin/management path",
                "remediation": (
                    "Restrict admin panels by IP allowlist, enforce strong authentication, "
                    "add MFA, and audit access logs. Remove if not required."
                ),
            })

        # Sensitive file extensions → medium severity
        for url in cats["sensitive"]:
            ext  = _up.urlparse(url).path.rsplit(".", 1)[-1].lower() if "." in _up.urlparse(url).path else ""
            path = _up.urlparse(url).path
            findings.append({
                "title":       f"[ZAP Spider] Sensitive File Discovered: {path}",
                "severity":    "medium",
                "url":         url,
                "description": (
                    f"A file with a potentially sensitive extension (.{ext}) was discovered "
                    f"at {url}. Such files may contain credentials, configuration data, "
                    "database dumps, or source code."
                ),
                "evidence":    f"Discovered URL: {url}\nExtension: .{ext}",
                "remediation": (
                    "Remove backup/config files from the web root. "
                    "Block access via server config if the file must remain. "
                    "Audit the file content for credential exposure."
                ),
            })

        # API endpoints → info
        for url in cats["api"]:
            path = _up.urlparse(url).path
            findings.append({
                "title":       f"[ZAP Spider] API Endpoint Discovered: {path}",
                "severity":    "info",
                "url":         url,
                "description": f"API endpoint discovered at {url} during spider crawl.",
                "evidence":    f"Discovered URL: {url}",
                "remediation": (
                    "Ensure every API endpoint enforces authentication, authorisation, "
                    "rate-limiting, and input validation. Consider running ZAP-03 Active "
                    "Audit against discovered API paths."
                ),
            })

        # Auth pages → info
        for url in cats["auth"]:
            path = _up.urlparse(url).path
            findings.append({
                "title":       f"[ZAP Spider] Authentication Endpoint Discovered: {path}",
                "severity":    "info",
                "url":         url,
                "description": f"An authentication-related page was found at {url}.",
                "evidence":    f"Discovered URL: {url}",
                "remediation": (
                    "Verify brute-force protections (lockout/CAPTCHA/rate-limit), "
                    "ensure CSRF tokens are present, use secure cookies, "
                    "and enforce HTTPS."
                ),
            })

        # Out-of-scope external links (optional)
        if incl_oos and urls_out:
            ext_hosts = list({_up.urlparse(u).netloc for u in urls_out if _up.urlparse(u).netloc})[:20]
            findings.append({
                "title":       f"[ZAP Spider] External Links Discovered ({len(urls_out)} URLs → {len(ext_hosts)} hosts)",
                "severity":    "info",
                "url":         target,
                "description": (
                    f"Spider crawled to {len(urls_out)} out-of-scope URLs referencing "
                    f"{len(ext_hosts)} external host(s): {', '.join(ext_hosts[:10])}"
                ),
                "evidence":    "\n".join(urls_out[:50]),
                "remediation": "Review external links for open redirect chains or third-party data leakage.",
            })

        # One summary finding with the full in-scope URL list
        url_list_text = "\n".join(urls_in[:300])
        findings.append({
            "title":       f"[ZAP Spider] Site Map: {len(urls_in)} URLs discovered ({len(live_urls)} live)",
            "severity":    "info",
            "url":         target,
            "description": (
                f"ZAP spider completed crawl of {target} at max depth {max_depth}. "
                f"Found {len(urls_in)} in-scope URLs ({len(live_urls)} live, "
                f"{dead_count} returned 4xx/5xx and were excluded from findings)"
                + (f", {len(ajax_new)} via Ajax spider" if use_ajax else "") + "."
            ),
            "evidence":    url_list_text,
            "remediation": "Review all discovered endpoints for unintended exposure. "
                           "Use ZAP-02 for passive analysis or ZAP-03 for active testing.",
        })

        client.remove_replacer_rules()

        sec_count = len([f for f in findings if f["severity"] not in ("info",)])
        stream("success",
               f"[ZAP] Spider complete — {len(urls_in)} URLs mapped ({len(live_urls)} live) | "
               f"{sec_count} security-notable endpoints | "
               f"Admin: {len(cats['admin'])} | Sensitive: {len(cats['sensitive'])}")

        return {
            "status":   "done",
            "findings": findings,
            "raw_output": (
                f"ZAP Spider: {len(urls_in)} in-scope URLs discovered. "
                f"Admin:{len(cats['admin'])} API:{len(cats['api'])} "
                f"Auth:{len(cats['auth'])} SensitiveExt:{len(cats['sensitive'])}"
            ),
            "metadata": {
                "urls_discovered":    len(urls_in),
                "urls_out_of_scope":  len(urls_out),
                "categories":         {k: len(v) for k, v in cats.items()},
                "subdomains":         [],
                "zap_version":        version,
            },
        }


# ─── [ZAP-02] OWASP ZAP — Passive Audit ─────────────────────────────────────

class ZAPPassiveAuditModule(_ZAPBaseModule):
    id          = "ZAP-02"
    name        = "OWASP ZAP — Passive Audit"
    category    = "vuln_scan"
    description = (
        "Spider the target then run a full passive-only security audit — "
        "no attack payloads are ever sent. Analyses HTTP responses in real time "
        "for missing security headers (CSP, HSTS, X-Frame-Options, Referrer-Policy), "
        "insecure cookie flags (Secure/HttpOnly/SameSite), information disclosure "
        "(server banners, stack traces, internal IPs), CORS misconfigurations, "
        "anti-clickjacking controls, and mixed content. Results are grouped by "
        "passive scan rule so you can see exactly which rules triggered and how many "
        "responses were affected."
    )
    risk_level  = "low"
    tags        = ["zap", "owasp", "passive", "headers", "cookies", "csp", "hsts", "cors"]

    PARAMETER_SCHEMA = _ZAPBaseModule._BASE_PARAMS + [
        FieldSchema(
            key="max_depth",
            label="Max Crawl Depth",
            field_type="number",
            default=5,
            help_text="Depth to crawl before starting passive analysis.",
        ),
        FieldSchema(
            key="min_risk",
            label="Minimum Risk Level to Report",
            field_type="select",
            default="0",
            options=[
                {"value": "0", "label": "All (including Informational)"},
                {"value": "1", "label": "Low and above"},
                {"value": "2", "label": "Medium and above"},
                {"value": "3", "label": "High only"},
            ],
            group="advanced",
        ),
    ]

    # Human-readable category labels for well-known passive rule plugin IDs
    _RULE_LABELS: dict[int, str] = {
        10010: "Cookie: Missing Secure Flag",
        10011: "Cookie: Missing HttpOnly Flag",
        10012: "Password Autocomplete",
        10013: "Password in GET",
        10015: "Incomplete/No Cache-Control Header",
        10016: "Web Browser XSS Protection Not Enabled",
        10017: "Cross-Domain JavaScript Source File Inclusion",
        10019: "Content-Type Header Missing",
        10020: "Anti-clickjacking Header",
        10021: "X-Content-Type-Options Header Missing",
        10023: "Information Disclosure — Debug Error Messages",
        10024: "Information Disclosure — Sensitive Info in URL",
        10025: "Information Disclosure — Sensitive Info in HTTP Referrer Header",
        10027: "Information Disclosure — Suspicious Comments",
        10028: "Open Redirect",
        10035: "Strict-Transport-Security Header",
        10036: "Server Leaks Version Info via Server HTTP Response Header",
        10038: "Content Security Policy (CSP) Header Not Set",
        10040: "Secure Pages Include Mixed Content",
        10049: "Non-Storable Content",
        10050: "Retrieved from Cache",
        10054: "Cookie Without SameSite Attribute",
        10055: "CSP Scanner",
        10056: "X-Debug-Token Information Leak",
        10061: "X-AspNet-Version Response Header",
        10062: "PII Disclosure",
        10063: "Feature Policy Header Not Set",
        10094: "Base64 Disclosure",
        10095: "Backup File Disclosure",
        10096: "Timestamp Disclosure",
        10098: "Cross-Domain Misconfiguration (CORS)",
        10105: "Weak Authentication Method",
        10108: "Reverse Tabnabbing",
        10109: "Modern Web Application",
        10110: "Dangerous JS Functions",
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        client, version = self._get_client(params)
        target    = params["target_url"].strip()
        max_depth = int(params.get("max_depth", 5))
        min_risk  = int(params.get("min_risk", 0))

        risk_labels = {0: "Informational", 1: "Low", 2: "Medium", 3: "High"}
        stream("info", f"[ZAP {version}] Starting Passive Audit → {target}")
        stream("info",  "[ZAP] Mode: passive-only analysis — no attack payloads will be sent")
        stream("info",  "[ZAP] Checks: security headers · cookie flags · CSP · HSTS · "
                        "CORS · info-disclosure · clickjacking · mixed content")
        client.new_session(f"passive-{job_id[:8]}")
        self._setup_auth(client, params, target)

        # ── Phase 1: Traditional spider — populates ZAP's response history ──
        stream("info", "[ZAP] Phase 1/2 — Spidering to collect HTTP responses for analysis…")
        scan_id = client.spider_start(target, max_depth=max_depth)
        client.wait_spider(scan_id, timeout=self.time_limit - 600, stream=stream)
        urls = client.spider_results(scan_id)
        stream("success",
               f"[ZAP] Spider done — {len(urls)} responses queued for passive analysis")

        # ── Phase 2: Wait for passive scan queue to drain ────────────────────
        stream("info", "[ZAP] Phase 2/2 — Running passive analysis rules on all captured responses…")
        start_t  = time.time()
        last_rem = None
        deadline = start_t + 600
        while time.time() < deadline:
            remaining = client.passive_scan_records_to_scan()
            elapsed   = int(time.time() - start_t)
            if remaining != last_rem:
                if remaining > 0:
                    stream("info",
                           f"[ZAP] Passive queue: {remaining} responses pending ({elapsed}s)…")
                last_rem = remaining
            if remaining == 0:
                break
            time.sleep(8)

        total_elapsed = int(time.time() - start_t)
        stream("info", f"[ZAP] Passive analysis complete ({total_elapsed}s).")

        # ── Collect and filter alerts ────────────────────────────────────────
        _risk_ord = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3}
        # Plugin IDs that produce excessive noise without actionable findings
        _NOISE_IDS = {
            10104,  # User Agent Fuzzer — fires for every URL per UA variant; not a vulnerability
        }
        all_alerts = client.alerts(base_url=target)
        # Keep only passive-rule alerts (plugin ID < 40000), noise-filtered, min_risk applied
        passive_alerts = [
            a for a in all_alerts
            if client._is_passive_alert(a)
            and int(a.get("pluginId", 0)) not in _NOISE_IDS
            and _risk_ord.get(a.get("risk", "Informational"), 0) >= min_risk
        ]

        stream("info",
               f"[ZAP] {len(passive_alerts)} passive findings "
               f"(≥{risk_labels.get(min_risk, 'All')}) — converting to findings…")
        findings = [client.alert_to_finding(a, target) for a in passive_alerts]

        # ── Rule coverage report ─────────────────────────────────────────────
        rule_counts: dict[str, int] = {}
        for a in passive_alerts:
            pid   = int(a.get("pluginId", 0))
            label = self._RULE_LABELS.get(pid, a.get("name", f"Rule {pid}"))
            rule_counts[label] = rule_counts.get(label, 0) + 1

        if rule_counts:
            top = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
            rules_summary = " | ".join(f"{n}:{c}" for n, c in top[:6])
            stream("info", f"[ZAP] Rules triggered — {rules_summary}")
            stream("info",
                   f"[ZAP] {len(rule_counts)} distinct passive rules found issues "
                   f"across {len(urls)} responses")
        else:
            stream("info", "[ZAP] No passive rule violations found — good baseline security posture.")

        summary = client.alerts_summary()
        stream("success",
               f"[ZAP] Passive audit complete — {len(findings)} findings. "
               f"High:{summary.get('High',0)} "
               f"Med:{summary.get('Medium',0)} "
               f"Low:{summary.get('Low',0)} "
               f"Info:{summary.get('Informational',0)}")

        client.remove_replacer_rules()

        return {
            "status":   "done",
            "findings": findings,
            "raw_output": (
                f"ZAP Passive Audit: {len(urls)} URLs analysed | "
                f"{len(findings)} passive findings | "
                f"{len(rule_counts)} distinct rules triggered"
            ),
            "metadata": {
                "urls_crawled":    len(urls),
                "alerts_summary":  summary,
                "rules_triggered": len(rule_counts),
                "rule_breakdown":  rule_counts,
                "zap_version":     version,
            },
        }


# ─── [ZAP-03] OWASP ZAP — Active Audit ──────────────────────────────────────

class ZAPActiveAuditModule(_ZAPBaseModule):
    id          = "ZAP-03"
    name        = "OWASP ZAP — Active Audit"
    category    = "vuln_scan"
    description = (
        "Full three-phase active vulnerability scan: spider → passive analysis → "
        "active attack. Sends real attack payloads to test for SQLi, XSS, SSRF, "
        "path traversal, command injection, XXE, open redirect, broken auth, and "
        "100+ other OWASP vulnerability classes. Findings are labelled as passive "
        "(observed from response) or active (confirmed via injected payload). "
        "Only run against targets you own or have explicit written authorisation to test."
    )
    risk_level  = "high"
    tags        = ["zap", "owasp", "active", "sqli", "xss", "ssrf", "full-scan", "pentest"]

    PARAMETER_SCHEMA = _ZAPBaseModule._BASE_PARAMS + [
        FieldSchema(
            key="max_depth",
            label="Max Crawl Depth",
            field_type="number",
            default=5,
        ),
        FieldSchema(
            key="scan_policy",
            label="Scan Policy",
            field_type="select",
            default="",
            options=[
                {"value": "",              "label": "Default (all checks)"},
                {"value": "SQL Injection", "label": "SQL Injection only"},
                {"value": "XSS",           "label": "XSS only"},
            ],
            help_text="Leave as Default to run all active rules.",
            group="advanced",
        ),
        FieldSchema(
            key="recurse",
            label="Recurse (scan all discovered URLs)",
            field_type="toggle",
            default=True,
            group="advanced",
        ),
        FieldSchema(
            key="thread_count",
            label="Scanner Threads",
            field_type="range_slider",
            default=2,
            min_value=1,
            max_value=10,
            step=1,
            help_text="Higher = faster but more aggressive. Use 1-2 on fragile targets.",
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        client, version = self._get_client(params)
        target     = params["target_url"].strip()
        max_depth  = int(params.get("max_depth", 5))
        recurse    = bool(params.get("recurse", True))
        threads    = int(params.get("thread_count", 2))

        _raw_policy = (params.get("scan_policy") or "").strip()
        _KNOWN_POLICIES = {"SQL Injection", "XSS"}
        policy = _raw_policy if _raw_policy in _KNOWN_POLICIES else ""

        stream("info", f"[ZAP {version}] Starting Active Audit → {target}")
        stream("warning",
               "[ZAP] Active scan sends real attack payloads (SQLi, XSS, SSRF, …). "
               "Ensure you have written authorisation for this target.")

        client.new_session(f"active-{job_id[:8]}")
        self._setup_auth(client, params, target)

        # ── Phase 1: Spider ──────────────────────────────────────────────────
        stream("info", "[ZAP] Phase 1/3 — Spidering target to build site map…")
        scan_id = client.spider_start(target, max_depth=max_depth)
        client.wait_spider(scan_id, timeout=self.time_limit // 3, stream=stream)
        urls = client.spider_results(scan_id)
        stream("success", f"[ZAP] Spider complete — {len(urls)} URLs discovered")

        # ── Phase 2: Passive analysis ────────────────────────────────────────
        stream("info", "[ZAP] Phase 2/3 — Passive analysis of captured responses…")
        passive_start = time.time()
        client.wait_passive_scan(timeout=300, stream=stream)
        passive_elapsed = int(time.time() - passive_start)

        # Count passive alerts before active scan mutates the state
        passive_count_before = len(client.alerts(base_url=target))
        stream("info",
               f"[ZAP] Passive phase done ({passive_elapsed}s) — "
               f"{passive_count_before} passive issues detected so far")

        # ── Phase 3: Active scan ─────────────────────────────────────────────
        actual_target = client.best_site_for(target)
        if actual_target != target:
            stream("info", f"[ZAP] Canonical target in site tree: {actual_target}")

        policy_label = policy if policy else "Default (all checks)"
        stream("info",
               f"[ZAP] Phase 3/3 — Active scan (policy: {policy_label}, "
               f"threads: {threads}, recurse: {recurse})…")
        stream("info",
               "[ZAP] Attack categories: SQL Injection · XSS · Path Traversal · "
               "Command Injection · SSRF · XXE · Open Redirect · Buffer Overflow · "
               "Parameter Tampering…")

        ascan_id = client.active_scan_start(actual_target, recurse=recurse, policy=policy)
        stream("info", f"[ZAP] Active scanner started (scan ID: {ascan_id})")
        client.wait_active_scan(ascan_id, timeout=self.time_limit - 600, stream=stream)

        # ── Collect all alerts and separate passive from active ──────────────
        # Plugin IDs that are informational noise and add no security value
        _NOISE_IDS = {
            10104,  # User Agent Fuzzer — not a vulnerability finding; fires per URL per UA variant
        }
        all_alerts = [
            a for a in client.alerts(base_url=target)
            if int(a.get("pluginId", 0)) not in _NOISE_IDS
        ]

        passive_alerts = [a for a in all_alerts if client._is_passive_alert(a)]
        active_alerts  = [a for a in all_alerts if not client._is_passive_alert(a)]

        stream("info",
               f"[ZAP] Alert breakdown — "
               f"Active (attack-confirmed): {len(active_alerts)} | "
               f"Passive (response-observed): {len(passive_alerts)}")

        # Convert to findings, labelling each finding source in the title
        findings: list[dict] = []
        for a in active_alerts:
            f = client.alert_to_finding(a, target)
            # Active findings already have rich evidence (attack payload + response)
            findings.append(f)

        for a in passive_alerts:
            f = client.alert_to_finding(a, target)
            findings.append(f)

        # ── Post-scan statistics ─────────────────────────────────────────────
        summary = client.alerts_summary()

        # Summarise which active attack categories found issues
        active_names: dict[str, int] = {}
        for a in active_alerts:
            name = a.get("name", "Unknown")
            active_names[name] = active_names.get(name, 0) + 1

        if active_names:
            top_active = sorted(active_names.items(), key=lambda x: x[1], reverse=True)[:5]
            active_summary = " · ".join(f"{n}" for n, _ in top_active)
            stream("warning", f"[ZAP] Active vulnerabilities confirmed: {active_summary}")

        stream("success",
               f"[ZAP] Active audit complete — {len(findings)} total findings. "
               f"High:{summary.get('High',0)} "
               f"Med:{summary.get('Medium',0)} "
               f"Low:{summary.get('Low',0)} "
               f"Info:{summary.get('Informational',0)}")

        client.remove_replacer_rules()

        return {
            "status":   "done",
            "findings": findings,
            "raw_output": (
                f"ZAP Active Audit: {len(urls)} URLs | "
                f"Active findings: {len(active_alerts)} | "
                f"Passive findings: {len(passive_alerts)}"
            ),
            "metadata": {
                "urls_crawled":         len(urls),
                "alerts_summary":       summary,
                "active_alert_count":   len(active_alerts),
                "passive_alert_count":  len(passive_alerts),
                "active_rule_hits":     active_names,
                "zap_version":          version,
            },
        }


