"""
Recon modules — registered automatically by ModuleRegistry._discover().
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema, ModuleRegistry
from apps.modules.runner import ToolRunner


# ─── [R-01] Port Scanner (naabu) ────────────────────────────────────────────

class PortScannerModule(BaseModule):
    id = "R-01"
    name = "Port Scanner"
    category = "recon"
    description = "Fast TCP port scanner using naabu. Discovers open ports across the target."
    risk_level = "medium"
    tags = ["naabu", "ports", "services", "network"]
    celery_queue = "recon_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_host",
            label="Target Host / IP / CIDR",
            field_type="text",
            required=True,
            placeholder="192.168.1.1 or example.com or 10.0.0.0/24",
            help_text="Single host, hostname, or CIDR range.",
        ),
        FieldSchema(
            key="port_range",
            label="Port Range",
            field_type="text",
            default="80,443,8080,8443,8888,3000,3306,5432,6379,27017",
            placeholder="80,443,8080 or 1-1000",
            help_text="Comma-separated ports or range. Leave blank to use Top Ports preset.",
        ),
        FieldSchema(
            key="top_ports",
            label="Top Ports Preset",
            field_type="select",
            default="",
            options=[
                {"value": "", "label": "Use custom port range above"},
                {"value": "100", "label": "Top 100 ports"},
                {"value": "1000", "label": "Top 1000 ports"},
            ],
            help_text="If selected, overrides the Port Range field.",
        ),
        FieldSchema(
            key="rate",
            label="Scan Rate (packets/sec)",
            field_type="number",
            default=1000,
            min_value=100,
            max_value=10000,
            group="advanced",
            help_text="Higher = faster but noisier. Reduce on rate-limited targets.",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import json as json_lib
        import os

        runner = ToolRunner("naabu")
        output_file = runner.output_file_path(job_id, "json")

        args = ["-host", params["target_host"], "-json", "-o", str(output_file), "-silent"]

        top_ports = params.get("top_ports", "").strip()
        port_range = params.get("port_range", "").strip()
        if top_ports:
            args += ["-top-ports", top_ports]
        elif port_range:
            args += ["-p", port_range]
        else:
            args += ["-top-ports", "100"]

        rate = int(params.get("rate", 1000))
        args += ["-rate", str(rate)]

        stream("info", f"[naabu] Scanning ports on {params['target_host']}...")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        if os.path.exists(str(output_file)):
            findings = _parse_naabu_json(str(output_file), stream)

        return {
            "status": "success" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


def _parse_naabu_json(json_path: str, stream) -> list[dict]:
    """Parse naabu JSON-lines output into Finding dicts."""
    import json as json_lib
    findings = []
    try:
        with open(json_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json_lib.loads(line)
                except json_lib.JSONDecodeError:
                    continue
                ip = entry.get("ip", "")
                port = entry.get("port", "")
                host = entry.get("host", ip)
                proto = entry.get("protocol", "tcp")
                if not port:
                    continue
                severity = "info"
                if int(port) in (21, 22, 23, 25, 110, 143, 445, 3389, 5900):
                    severity = "medium"
                findings.append({
                    "title": f"Open port {port}/{proto} on {host or ip}",
                    "severity": severity,
                    "url": f"{host or ip}:{port}",
                    "description": f"Port {port}/{proto} is open on {host or ip} (IP: {ip}).",
                    "evidence": f"naabu: port={port} proto={proto} host={host}",
                    "remediation": "Review whether this port/service needs to be publicly accessible.",
                })
    except Exception as e:
        stream("warning", f"Failed to parse naabu output: {e}")
    return findings


# ─── [R-02] Subdomain Enumeration (subfinder + amass + alterx + puredns + dnsx + httpx) ───

class SubdomainEnumModule(BaseModule):
    id = "R-02"
    name = "Subdomain Enumeration"
    category = "recon"
    description = (
        "Deep subdomain enumeration pipeline: passive discovery (subfinder + amass) → "
        "permutation expansion (alterx) → DNS bruteforce (puredns/massdns) → "
        "live resolution (dnsx) → HTTP probing (httpx)."
    )
    risk_level = "low"
    tags = ["subfinder", "amass", "alterx", "puredns", "dnsx", "httpx", "recon", "subdomains"]
    celery_queue = "recon_queue"
    time_limit = 1800  # 30 min for deep enum

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="domain",
            label="Root Domain",
            field_type="text",
            required=True,
            placeholder="example.com",
        ),
        FieldSchema(
            key="depth",
            label="Enumeration Depth",
            field_type="select",
            default="standard",
            options=[
                {"value": "passive",  "label": "Passive only (subfinder — fast, ~2 min)"},
                {"value": "standard", "label": "Standard (subfinder + amass passive, ~5 min)"},
                {"value": "deep",     "label": "Deep (+ alterx permutations + puredns bruteforce, ~20 min)"},
            ],
            help_text="'Deep' runs DNS bruteforce — generates significant DNS traffic.",
        ),
        FieldSchema(
            key="resolve_dns",
            label="Resolve DNS (dnsx)",
            field_type="toggle",
            default=True,
        ),
        FieldSchema(
            key="probe_http",
            label="Probe HTTP/HTTPS (httpx)",
            field_type="toggle",
            default=True,
        ),
        FieldSchema(
            key="threads",
            label="Threads",
            field_type="range_slider",
            default=50,
            min_value=1,
            max_value=200,
            step=10,
        ),
        FieldSchema(
            key="wordlist",
            label="Bruteforce Wordlist (deep mode only)",
            field_type="wordlist_select",
            required=False,
            show_if={"depth": "deep"},
            help_text="Used by puredns for DNS bruteforce. Leave blank for built-in list.",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os, json, shutil
        from pathlib import Path

        domain = params["domain"].strip().lower()
        threads = str(params.get("threads", 50))
        depth = params.get("depth", "standard")

        # Working dir for temp files
        work_dir = Path(f"/tmp/pentools/{job_id}")
        work_dir.mkdir(parents=True, exist_ok=True)

        # Collect all discovered subdomains in a set to deduplicate
        all_subs: set[str] = set()

        # ── Step 1: subfinder (passive) ──────────────────────────────────────
        stream("info", f"[1/6] subfinder — passive DNS sources against {domain}...")
        sf_out = work_dir / "subfinder.txt"
        sf_runner = ToolRunner("subfinder")
        sf_runner.run(
            args=["-d", domain, "-t", threads, "-o", str(sf_out), "-silent"],
            stream=stream, timeout=300,
        )
        if sf_out.exists():
            subs = {l.strip() for l in sf_out.read_text().splitlines() if l.strip()}
            all_subs |= subs
            stream("success", f"subfinder: {len(subs)} subdomains found.")
        else:
            stream("warning", "subfinder produced no output.")

        # ── Step 2: amass (passive, standard+deep) ──────────────────────────
        if depth in ("standard", "deep") and shutil.which("/opt/tools/bin/amass") or \
                os.path.isfile("/opt/tools/bin/amass"):
            stream("info", "[2/6] amass — OSINT passive subdomain intel...")
            amass_out = work_dir / "amass.txt"
            amass_runner = ToolRunner("amass")
            amass_runner.run(
                args=["enum", "-passive", "-d", domain, "-o", str(amass_out), "-silent"],
                stream=stream, timeout=300,
            )
            if amass_out.exists():
                subs = {l.strip() for l in amass_out.read_text().splitlines() if l.strip()}
                new = subs - all_subs
                all_subs |= subs
                stream("success", f"amass: {len(subs)} subdomains ({len(new)} new).")
            else:
                stream("warning", "amass produced no output (may not be installed yet).")
        else:
            stream("info", "[2/6] amass not available — skipping.")

        # ── Step 3: alterx + puredns (deep only) ────────────────────────────
        if depth == "deep" and all_subs:
            # 3a. alterx: generate permutations from known subdomains
            alterx_bin = "/opt/tools/bin/alterx"
            if os.path.isfile(alterx_bin):
                stream("info", f"[3/6] alterx — generating permutations from {len(all_subs)} subdomains...")
                subs_file = work_dir / "known_subs.txt"
                subs_file.write_text("\n".join(sorted(all_subs)))
                alterx_out = work_dir / "alterx.txt"
                alterx_runner = ToolRunner("alterx")
                alterx_runner.run(
                    args=["-l", str(subs_file), "-o", str(alterx_out), "-silent"],
                    stream=stream, timeout=120,
                )
                if alterx_out.exists():
                    perms = {l.strip() for l in alterx_out.read_text().splitlines() if l.strip()}
                    stream("success", f"alterx: {len(perms)} permutations generated.")

                    # 3b. puredns: resolve permutations against public resolvers
                    massdns_bin = "/opt/tools/bin/massdns"
                    puredns_bin = "/opt/tools/bin/puredns"
                    if os.path.isfile(puredns_bin) and os.path.isfile(massdns_bin):
                        stream("info", f"[4/6] puredns — bruteforcing {len(perms)} permutations via massdns...")
                        # Write public resolvers list
                        resolvers_file = work_dir / "resolvers.txt"
                        resolvers_file.write_text(
                            "8.8.8.8\n8.8.4.4\n1.1.1.1\n1.0.0.1\n9.9.9.9\n"
                            "208.67.222.222\n208.67.220.220\n"
                        )
                        puredns_out = work_dir / "puredns.txt"
                        puredns_runner = ToolRunner("puredns")
                        puredns_runner.run(
                            args=["resolve", str(alterx_out),
                                  "-r", str(resolvers_file),
                                  "--resolvers-trusted", str(resolvers_file),
                                  "-w", str(puredns_out), "--quiet"],
                            stream=stream, timeout=600,
                        )
                        if puredns_out.exists():
                            resolved = {l.strip() for l in puredns_out.read_text().splitlines() if l.strip()}
                            new = resolved - all_subs
                            all_subs |= resolved
                            stream("success", f"puredns: {len(new)} new subdomains resolved.")
                    else:
                        stream("info", "[4/6] puredns/massdns not available — skipping bruteforce.")
                else:
                    stream("info", "[3/6] alterx produced no permutations.")
            else:
                stream("info", "[3/6] alterx not available — skipping permutations.")
        else:
            stream("info", "[3/6][4/6] Permutation + bruteforce skipped (depth != deep).")

        if not all_subs:
            stream("error", "No subdomains discovered.")
            return {"status": "failed", "findings": [], "raw_output": ""}

        stream("success", f"Total unique subdomains before DNS validation: {len(all_subs)}")

        # Write merged list for dnsx / httpx
        merged_file = work_dir / "all_subs.txt"
        merged_file.write_text("\n".join(sorted(all_subs)))

        # ── Step 4 (5): dnsx — live DNS resolution ──────────────────────────
        live_subs: list[str] = []
        if params.get("resolve_dns", True):
            stream("info", f"[5/6] dnsx — resolving {len(all_subs)} subdomains...")
            dnsx_out = work_dir / "dnsx.txt"
            dnsx_runner = ToolRunner("dnsx")
            dnsx_runner.run(
                args=["-l", str(merged_file), "-o", str(dnsx_out),
                      "-t", threads, "-silent", "-resp"],
                stream=stream, timeout=300,
            )
            if dnsx_out.exists():
                live_subs = [l.strip() for l in dnsx_out.read_text().splitlines() if l.strip()]
                stream("success", f"dnsx: {len(live_subs)} live A records.")
                # Extract just the hostname part (dnsx -resp adds IP)
                resolved_file = work_dir / "live_hosts.txt"
                resolved_file.write_text("\n".join(
                    line.split()[0] for line in live_subs if line
                ))
                merged_file = resolved_file
            else:
                stream("warning", "dnsx produced no output — using unresolved list.")
        else:
            stream("info", "[5/6] DNS resolution skipped.")

        # ── Step 5 (6): httpx — HTTP/HTTPS probing ──────────────────────────
        findings = []
        if params.get("probe_http", True):
            stream("info", f"[6/6] httpx — probing HTTP/HTTPS on live hosts...")
            httpx_runner = ToolRunner("httpx")
            httpx_out = work_dir / "httpx.json"
            httpx_runner.run(
                args=["-l", str(merged_file),
                      "-json", "-o", str(httpx_out),
                      "-threads", threads, "-silent",
                      "-status-code", "-title", "-tech-detect",
                      "-follow-redirects", "-no-color"],
                stream=stream, timeout=300,
            )

            if httpx_out.exists():
                for line in httpx_out.read_text().splitlines():
                    if not line.strip():
                        continue
                    try:
                        entry = json.loads(line)
                        url = entry.get("url", "")
                        sc = entry.get("status-code", "")
                        title = entry.get("title", "")
                        tech = ", ".join(
                            t.get("name", t) if isinstance(t, dict) else str(t)
                            for t in (entry.get("technologies") or entry.get("tech") or [])
                        )
                        desc = f"HTTP {sc} — {title}"
                        if tech:
                            desc += f" | Tech: {tech}"
                        findings.append({
                            "title": f"Live subdomain: {url}",
                            "severity": "info",
                            "url": url,
                            "description": desc,
                            "evidence": line.strip(),
                            "remediation": "Review exposed subdomains and their attack surface.",
                            "metadata": {"technologies": tech, "status_code": sc, "title": title},
                        })
                    except Exception:
                        pass
                stream("success", f"httpx: {len(findings)} live HTTP endpoints.")
            else:
                stream("warning", "httpx produced no output.")
        else:
            # Return raw subdomain list as findings
            for sub in sorted(all_subs):
                findings.append({
                    "title": f"Subdomain: {sub}",
                    "severity": "info",
                    "url": sub,
                    "description": f"Subdomain discovered (not HTTP-probed): {sub}",
                    "evidence": "",
                    "remediation": "Review exposed subdomains.",
                })

        stream("success", f"R-02 complete. {len(all_subs)} subdomains discovered, {len(findings)} findings.")
        return {
            "status": "done",
            "findings": findings,
            "raw_output": "\n".join(sorted(all_subs)),
            "metadata": {
                "total_subdomains": len(all_subs),
                "live_http_endpoints": len(findings),
                # Pass subdomain list for scan chaining (downstream modules can read this)
                "subdomains": sorted(all_subs),
            },
        }


# ─── [R-03] SSL/TLS Deep Audit ────────────────────────────────────────────────

class SSLTLSAuditModule(BaseModule):
    id = "R-03"
    name = "SSL/TLS Deep Audit"
    category = "recon"
    description = (
        "Deep SSL/TLS analysis using testssl.sh: cipher suites, protocol versions, "
        "certificate chain, HSTS, and known vulnerabilities (POODLE, BEAST, Heartbleed)."
    )
    risk_level = "medium"
    tags = ["ssl", "tls", "testssl", "certificates", "ciphers"]
    celery_queue = "recon_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_host",
            label="Target Host:Port",
            field_type="text",
            required=True,
            placeholder="example.com:443",
        ),
        FieldSchema(
            key="check_vulns",
            label="Check Known TLS Vulnerabilities",
            field_type="toggle",
            default=True,
            help_text="POODLE, BEAST, CRIME, BREACH, Heartbleed, etc.",
        ),
        FieldSchema(
            key="check_ciphers",
            label="Enumerate Cipher Suites",
            field_type="toggle",
            default=True,
        ),
        FieldSchema(
            key="checks",
            label="Additional Checks",
            field_type="checkbox_group",
            default=["hsts", "cert"],
            options=[
                {"value": "hsts",    "label": "HSTS / HPKP checks"},
                {"value": "cert",    "label": "Certificate chain / expiry"},
                {"value": "http2",   "label": "HTTP/2 support"},
                {"value": "caa",     "label": "DNS CAA records"},
            ],
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os, json
        runner = ToolRunner("testssl.sh")
        target = params["target_host"]
        output_file = runner.output_file_path(job_id, "json")

        args = ["--jsonfile", str(output_file), "--quiet", "--color", "0"]
        if params.get("check_vulns"):
            args.append("--vulnerable")
        if params.get("check_ciphers"):
            args.append("--cipher-per-proto")
        args.append(target)

        stream("info", f"Running testssl.sh against {target}...")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)
                for entry in data:
                    severity_map = {
                        "CRITICAL": "critical", "HIGH": "high",
                        "MEDIUM": "medium", "LOW": "low",
                        "WARN": "medium", "OK": "info", "INFO": "info",
                    }
                    sev_raw = entry.get("severity", "INFO").upper()
                    sev = severity_map.get(sev_raw, "info")
                    if sev in ("info",):
                        continue  # skip info-level
                    findings.append({
                        "title": f"TLS issue: {entry.get('id', '')}",
                        "severity": sev,
                        "url": target,
                        "description": entry.get("finding", ""),
                        "evidence": json.dumps(entry)[:400],
                        "remediation": "Disable vulnerable protocol versions and weak cipher suites.",
                    })
        except Exception as e:
            stream("warning", f"Parse error: {e}")

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [R-04] WAF & CDN Fingerprint ────────────────────────────────────────────

class WAFCDNFingerprintModule(BaseModule):
    id = "R-04"
    name = "WAF & CDN Fingerprint"
    category = "recon"
    description = (
        "Detect web application firewalls and CDN providers using wafw00f "
        "and HTTP header analysis."
    )
    risk_level = "low"
    tags = ["waf", "cdn", "wafw00f", "fingerprint", "recon"]
    celery_queue = "recon_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com",
        ),
        FieldSchema(
            key="detect_all",
            label="Test all WAF signatures (--findall)",
            field_type="toggle",
            default=False,
            help_text="Slower but more thorough.",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os
        runner = ToolRunner("wafw00f")
        url = params["target_url"]
        output_file = runner.output_file_path(job_id, "txt")

        args = [url, "-o", str(output_file), "-f", "json"]
        if params.get("detect_all"):
            args.append("-a")

        stream("info", f"WAF/CDN fingerprinting: {url}...")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        raw = result.get("stdout", "")
        if "is behind" in raw.lower() or "is protected by" in raw.lower():
            for line in raw.splitlines():
                if "behind" in line.lower() or "protected" in line.lower():
                    findings.append({
                        "title": f"WAF/CDN detected",
                        "severity": "info",
                        "url": url,
                        "description": line.strip(),
                        "evidence": raw[:500],
                        "remediation": "Document WAF/CDN for bypass consideration during testing.",
                    })
                    break

        return {
            "status": "done",
            "findings": findings,
            "raw_output": raw,
        }


# ─── [R-05] Tech Stack Fingerprint ───────────────────────────────────────────

class TechStackFingerprintModule(BaseModule):
    id = "R-05"
    name = "Tech Stack Fingerprint"
    category = "recon"
    description = (
        "Identify web technologies, frameworks, CMS, CDN, and server software "
        "using whatweb and favicon hash lookup."
    )
    risk_level = "low"
    tags = ["whatweb", "fingerprint", "tech-detection", "recon"]
    celery_queue = "recon_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",
            required=True,
            placeholder="https://example.com",
        ),
        FieldSchema(
            key="aggression",
            label="Aggression Level",
            field_type="select",
            default="1",
            options=[
                {"value": "1", "label": "1 — Passive (single request)"},
                {"value": "2", "label": "2 — Polite"},
                {"value": "3", "label": "3 — Aggressive (multiple requests)"},
            ],
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os
        runner = ToolRunner("whatweb")
        url = params["target_url"]
        aggression = str(params.get("aggression", "1"))
        output_file = runner.output_file_path(job_id, "json")

        args = [url, f"-a{aggression}", "--log-json", str(output_file), "--quiet"]
        stream("info", f"Tech stack fingerprint: {url}...")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        raw = result.get("stdout", "")

        # Version-based severity
        version_keywords = ["WordPress", "Drupal", "Joomla", "Apache", "nginx", "PHP", "jQuery"]
        for kw in version_keywords:
            if kw.lower() in raw.lower():
                findings.append({
                    "title": f"Technology detected: {kw}",
                    "severity": "info",
                    "url": url,
                    "description": f"WhatWeb detected {kw} on the target.",
                    "evidence": raw[:500],
                    "remediation": "Verify that detected software is up-to-date. Remove version disclosure headers.",
                })

        return {
            "status": "done",
            "findings": findings,
            "raw_output": raw,
        }


# ─── [R-06] DNS Full Enumeration ─────────────────────────────────────────────

class DNSEnumerationModule(BaseModule):
    id = "R-06"
    name = "DNS Full Enumeration"
    category = "recon"
    description = (
        "Enumerate DNS records (A, AAAA, MX, NS, TXT, SRV, SOA, CAA) "
        "and attempt zone transfer using dnsx."
    )
    risk_level = "low"
    tags = ["dns", "dnsx", "zone-transfer", "records", "recon"]
    celery_queue = "recon_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="domain",
            label="Domain",
            field_type="text",
            required=True,
            placeholder="example.com",
        ),
        FieldSchema(
            key="record_types",
            label="Record Types",
            field_type="checkbox_group",
            default=["A", "AAAA", "MX", "NS", "TXT", "SOA"],
            options=[
                {"value": "A",    "label": "A — IPv4"},
                {"value": "AAAA", "label": "AAAA — IPv6"},
                {"value": "MX",   "label": "MX — Mail"},
                {"value": "NS",   "label": "NS — Nameserver"},
                {"value": "TXT",  "label": "TXT — Text/SPF/DKIM"},
                {"value": "SOA",  "label": "SOA — Start of Authority"},
                {"value": "CAA",  "label": "CAA — CA Authorization"},
                {"value": "SRV",  "label": "SRV — Service"},
                {"value": "PTR",  "label": "PTR — Reverse lookup"},
            ],
        ),
        FieldSchema(
            key="attempt_axfr",
            label="Attempt Zone Transfer (AXFR)",
            field_type="toggle",
            default=True,
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os
        runner = ToolRunner("dnsx")
        domain = params["domain"]
        rtypes = params.get("record_types", ["A", "MX", "NS", "TXT"])
        output_file = runner.output_file_path(job_id, "json")

        # dnsx record query via -resp
        rtype_flags = []
        for rt in rtypes:
            rtype_flags += [f"-{rt.lower()}"]

        args = ["-d", domain, "-json", "-o", str(output_file), "-resp"] + rtype_flags
        stream("info", f"DNS enumeration: {domain} ({', '.join(rtypes)})")
        result = runner.run(args=args, stream=stream, timeout=60)

        findings = []
        import json as json_mod
        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json_mod.loads(line)
                        # Look for SPF / DMARC issues in TXT
                        txt = str(entry)
                        if "v=spf1" in txt and "~all" in txt and "-all" not in txt:
                            findings.append({
                                "title": "Weak SPF policy (softfail ~all instead of -all)",
                                "severity": "medium",
                                "url": domain,
                                "description": "SPF uses ~all (softfail) instead of -all. Allows email spoofing.",
                                "evidence": txt[:200],
                                "remediation": "Change SPF record to end with '-all' for strict enforcement.",
                            })
        except Exception as e:
            stream("warning", f"Parse error: {e}")

        # Attempt zone transfer
        if params.get("attempt_axfr"):
            dig_runner = ToolRunner("dig")
            stream("info", f"Attempting zone transfer (AXFR) for {domain}...")
            axfr_result = dig_runner.run(
                args=[f"axfr", domain, f"@{domain}"],
                stream=stream,
                timeout=15,
            )
            if "Transfer failed" not in axfr_result.get("stdout", "") and \
               len(axfr_result.get("stdout", "")) > 100:
                findings.append({
                    "title": f"DNS Zone Transfer (AXFR) succeeded!",
                    "severity": "critical",
                    "url": domain,
                    "description": "Zone transfer is enabled — full zone data readable by any host.",
                    "evidence": axfr_result.get("stdout", "")[:1000],
                    "remediation": "Restrict AXFR to authorised secondary nameservers only.",
                })

        return {
            "status": "done",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [R-07] Certificate Transparency ─────────────────────────────────────────

class CertTransparencyModule(BaseModule):
    id = "R-07"
    name = "Certificate Transparency"
    category = "recon"
    description = (
        "Query crt.sh certificate transparency logs to discover subdomains "
        "passively without touching the target."
    )
    risk_level = "low"
    tags = ["crt.sh", "certificate-transparency", "passive-recon", "subdomains"]
    celery_queue = "recon_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="domain",
            label="Domain",
            field_type="text",
            required=True,
            placeholder="example.com",
        ),
        FieldSchema(
            key="include_expired",
            label="Include expired certificates",
            field_type="toggle",
            default=False,
        ),
        FieldSchema(
            key="deduplicate",
            label="Deduplicate results",
            field_type="toggle",
            default=True,
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import urllib.request
        import json as json_mod
        import time

        domain = params["domain"]
        include_expired = params.get("include_expired", False)
        deduplicate = params.get("deduplicate", True)

        stream("info", f"Querying crt.sh for {domain}...")

        url = f"https://crt.sh/?q=%.{domain}&output=json"
        if include_expired:
            url += "&exclude=expired"

        try:
            req = urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0 crt.sh-query"})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json_mod.loads(resp.read().decode())
        except Exception as e:
            stream("error", f"crt.sh query failed: {e}")
            return {"status": "failed", "findings": [], "raw_output": str(e)}

        subdomains = set()
        for entry in data:
            name = entry.get("name_value", "")
            for sub in name.split("\n"):
                sub = sub.strip().lstrip("*.")
                if sub and sub.endswith(domain):
                    subdomains.add(sub)

        stream("success", f"Found {len(subdomains)} unique subdomains via Certificate Transparency.")

        findings = []
        for sub in sorted(subdomains):
            findings.append({
                "title": f"CT subdomain: {sub}",
                "severity": "info",
                "url": sub,
                "description": f"Subdomain '{sub}' found in certificate transparency logs for {domain}.",
                "evidence": f"crt.sh query: %.{domain}",
                "remediation": "Review all discovered subdomains for exposed services.",
            })

        return {
            "status": "done",
            "findings": findings,
            "raw_output": f"crt.sh returned {len(data)} certificates, {len(subdomains)} unique subdomains.",
        }


# ─── [R-08] Web Crawler & Sitemap ────────────────────────────────────────────

class WebCrawlerModule(BaseModule):
    id = "R-08"
    name = "Web Crawler & Sitemap"
    category = "recon"
    description = (
        "Crawl the target using katana to discover endpoints, parameters, "
        "JS files, and forms. Supports JavaScript rendering mode."
    )
    risk_level = "low"
    tags = ["katana", "crawler", "sitemap", "spider", "recon"]
    celery_queue = "recon_queue"
    time_limit = 600

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
            default=2,
            min_value=1,
            max_value=5,
            step=1,
        ),
        FieldSchema(
            key="js_crawl",
            label="Crawl JavaScript (fetch inline JS URLs)",
            field_type="toggle",
            default=True,
        ),
        FieldSchema(
            key="scope",
            label="Scope Regex",
            field_type="text",
            required=False,
            placeholder=".*example\\.com.*",
            help_text="Restrict crawl to URLs matching this pattern.",
        ),
        FieldSchema(
            key="headers",
            label="Custom Request Headers",
            field_type="header_list",
            required=False,
            group="advanced",
        ),
        FieldSchema(
            key="parallelism",
            label="Parallelism",
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
        runner = ToolRunner("katana")
        url = params["target_url"]
        depth = str(int(params.get("depth", 2)))
        parallelism = str(int(params.get("parallelism", 10)))
        output_file = runner.output_file_path(job_id, "txt")

        args = [
            "-u", url,
            "-d", depth,
            "-c", parallelism,
            "-o", str(output_file),
            "-silent",
        ]
        if params.get("js_crawl"):
            args.append("-jc")
        if params.get("scope"):
            args += ["-fs", params["scope"]]

        headers = params.get("headers", [])
        if isinstance(headers, list):
            for h in headers:
                if isinstance(h, dict):
                    k, v = h.get("key", ""), h.get("value", "")
                    if k and v:
                        args += ["-H", f"{k}: {v}"]

        stream("info", f"Crawling {url} (depth={depth})...")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        if os.path.exists(output_file):
            with open(output_file) as f:
                urls = [l.strip() for l in f if l.strip()]
            stream("success", f"Crawled {len(urls)} URLs.")

            for crawled_url in urls[:500]:  # cap findings at 500
                sev = "info"
                if any(kw in crawled_url for kw in ["admin", "api/", "/v1/", "/v2/", "token", "key", "secret"]):
                    sev = "low"
                findings.append({
                    "title": f"Endpoint discovered: {crawled_url[:80]}",
                    "severity": sev,
                    "url": crawled_url,
                    "description": f"URL crawled from {url}.",
                    "evidence": "",
                    "remediation": "Review discovered endpoints for access control gaps.",
                })

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [R-09] HTTP Probing ──────────────────────────────────────────────────────

class HTTPProbingModule(BaseModule):
    id = "R-09"
    name = "HTTP Probing"
    category = "recon"
    description = (
        "Probe HTTP/HTTPS on a list of hosts with httpx: "
        "status codes, titles, redirect chains, and tech detection headers."
    )
    risk_level = "low"
    tags = ["httpx", "http-probe", "status", "redirect", "recon"]
    celery_queue = "recon_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="targets",
            label="Targets (one per line)",
            field_type="textarea",
            required=True,
            placeholder="example.com\napi.example.com\nhttps://admin.example.com",
        ),
        FieldSchema(
            key="ports",
            label="Ports to Probe",
            field_type="text",
            default="80,443",
            help_text="Comma-separated port list.",
        ),
        FieldSchema(
            key="follow_redirects",
            label="Follow Redirects",
            field_type="toggle",
            default=True,
        ),
        FieldSchema(
            key="tech_detect",
            label="Technology Detection",
            field_type="toggle",
            default=True,
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
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os
        import json as json_mod
        import tempfile

        runner = ToolRunner("httpx")
        targets = params["targets"]
        ports = params.get("ports", "80,443")
        threads = str(int(params.get("threads", 50)))
        output_file = runner.output_file_path(job_id, "json")

        # Write targets to temp file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
            for line in targets.splitlines():
                line = line.strip()
                if line:
                    tf.write(line + "\n")
            target_file = tf.name

        args = [
            "-l", target_file,
            "-ports", ports,
            "-json",
            "-o", str(output_file),
            "-t", threads,
            "-silent",
            "-status-code",
            "-title",
            "-web-server",
        ]
        if params.get("follow_redirects"):
            args.append("-follow-redirects")
        if params.get("tech_detect"):
            args.append("-tech-detect")

        stream("info", f"HTTP probing {len(targets.splitlines())} targets...")
        result = runner.run(args=args, stream=stream, timeout=self.time_limit)

        findings = []
        try:
            if os.path.exists(output_file):
                with open(output_file) as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        entry = json_mod.loads(line)
                        url = entry.get("url", "")
                        status = entry.get("status-code", 0)
                        title = entry.get("title", "")
                        server = entry.get("webserver", "")
                        findings.append({
                            "title": f"Live host: {url}",
                            "severity": "info",
                            "url": url,
                            "description": f"HTTP {status} — {title} | Server: {server}",
                            "evidence": line[:300],
                            "remediation": "Review all live hosts for exposed services and attack surface.",
                        })
        except Exception as e:
            stream("warning", f"Parse error: {e}")
        finally:
            try:
                os.unlink(target_file)
            except Exception:
                pass

        return {
            "status": "done" if result["returncode"] == 0 else "failed",
            "findings": findings,
            "raw_output": result.get("stdout", ""),
        }


# ─── [R-10] ASN & IP Intelligence ────────────────────────────────────────────

class ASNIntelligenceModule(BaseModule):
    id = "R-10"
    name = "ASN & IP Intelligence"
    category = "recon"
    description = (
        "Retrieve ASN, BGP prefix, organisation, and geolocation data for one or "
        "more IP addresses or domain names. Optionally query Shodan for open ports "
        "and CVEs on the target IP."
    )
    risk_level = "info"
    tags = ["asn", "ip", "bgp", "whois", "geolocation", "shodan", "recon"]
    celery_queue = "recon_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="targets",
            label="IP Addresses / Domains",
            field_type="textarea",
            required=True,
            placeholder="8.8.8.8\n1.1.1.1\nexample.com",
            help_text="One IP or domain per line.",
        ),
        FieldSchema(
            key="shodan_api_key",
            label="Shodan API Key (optional)",
            field_type="text",
            required=False,
            placeholder="YOUR_SHODAN_API_KEY",
            help_text="If provided, Shodan host data (ports, CVEs) will be included.",
            group="credentials",
        ),
        FieldSchema(
            key="resolve_rdns",
            label="Resolve reverse DNS",
            field_type="toggle",
            default=True,
        ),
    ]

    def _ipinfo(self, ip: str) -> dict:
        import urllib.request, json as j
        try:
            with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=10) as r:
                return j.loads(r.read())
        except Exception:
            return {}

    def _rdns(self, ip: str) -> str:
        import socket
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return ""

    def _resolve_host(self, host: str) -> str:
        import socket
        try:
            return socket.gethostbyname(host)
        except Exception:
            return host

    def _shodan(self, ip: str, api_key: str, stream) -> list:
        import urllib.request, json as j
        results = []
        try:
            url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
            with urllib.request.urlopen(url, timeout=15) as r:
                data = j.loads(r.read())
            ports = data.get("ports", [])
            vulns = data.get("vulns", [])
            if ports:
                results.append({
                    "title": f"Shodan: {ip} has {len(ports)} open port(s)",
                    "severity": "medium",
                    "url": f"https://www.shodan.io/host/{ip}",
                    "description": f"Open ports: {', '.join(str(p) for p in ports[:30])}",
                    "evidence": str(ports),
                    "remediation": "Close unnecessary ports and firewall services not intended for public access.",
                })
            if vulns:
                results.append({
                    "title": f"Shodan: {len(vulns)} CVE(s) associated with {ip}",
                    "severity": "high",
                    "url": f"https://www.shodan.io/host/{ip}",
                    "description": f"CVEs: {', '.join(list(vulns)[:20])}",
                    "evidence": str(list(vulns)),
                    "remediation": "Patch identified vulnerabilities and update all exposed software.",
                    "cve_id": list(vulns)[0] if vulns else "",
                })
        except Exception as e:
            stream("warning", f"Shodan query failed for {ip}: {e}")
        return results

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os as _os
        raw_targets = [t.strip() for t in params["targets"].splitlines() if t.strip()]
        shodan_key = (params.get("shodan_api_key") or "").strip() or _os.environ.get("SHODAN_API_KEY", "").strip()
        resolve_rdns = params.get("resolve_rdns", True)
        findings = []
        raw_lines = []

        for target in raw_targets:
            ip = self._resolve_host(target)
            stream("info", f"Querying IP intelligence for {target} ({ip})...")
            info = self._ipinfo(ip)
            org = info.get("org", "Unknown")
            country = info.get("country", "?")
            city = info.get("city", "?")
            region = info.get("region", "?")
            summary = f"{ip} | {org} | {city}, {region}, {country}"
            raw_lines.append(summary)
            stream("info", summary)

            rdns = ""
            if resolve_rdns:
                rdns = self._rdns(ip)
                if rdns:
                    stream("info", f"  rDNS: {rdns}")

            findings.append({
                "title": f"IP intelligence: {ip} ({org})",
                "severity": "info",
                "url": f"https://ipinfo.io/{ip}",
                "description": (
                    f"IP: {ip}\nOrg/ASN: {org}\nCountry: {country}\n"
                    f"City: {city}, {region}\nReverse DNS: {rdns or 'N/A'}"
                ),
                "evidence": str(info),
                "remediation": "No direct remediation required. Use for attack-surface mapping.",
            })
            if shodan_key:
                findings.extend(self._shodan(ip, shodan_key, stream))

        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [R-11] Email Harvesting ──────────────────────────────────────────────────

class EmailHarvestingModule(BaseModule):
    id = "R-11"
    name = "Email Harvesting"
    category = "recon"
    description = (
        "Harvest email addresses for a target domain using theHarvester (if installed), "
        "Hunter.io API, and/or pattern-based regex scraping."
    )
    risk_level = "medium"
    tags = ["email", "harvesting", "osint", "phishing", "theharvester", "hunter"]
    celery_queue = "recon_queue"
    time_limit = 180

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="domain",
            label="Target Domain",
            field_type="text",
            required=True,
            placeholder="example.com",
        ),
        FieldSchema(
            key="sources",
            label="Sources",
            field_type="checkbox_group",
            default=["theharvester", "duckduckgo"],
            options=[
                {"value": "theharvester", "label": "theHarvester binary"},
                {"value": "duckduckgo",   "label": "DuckDuckGo (scraped)"},
                {"value": "hunter_io",    "label": "Hunter.io API"},
            ],
        ),
        FieldSchema(
            key="hunter_api_key",
            label="Hunter.io API Key",
            field_type="text",
            required=False,
            group="credentials",
        ),
        FieldSchema(key="limit", label="Max results", field_type="number", default=200),
    ]

    EMAIL_RE = r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import re, json as j, tempfile, os, urllib.request
        from apps.modules.runner import ToolRunner

        domain = params["domain"].strip().lower()
        sources = params.get("sources", ["theharvester"])
        hunter_key = params.get("hunter_api_key", "").strip()
        limit = int(params.get("limit", 200))
        emails: set = set()
        raw_lines = []

        if "theharvester" in sources:
            stream("info", "Running theHarvester...")
            runner = ToolRunner("theHarvester")
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
                out_base = tf.name.replace(".json", "")
            try:
                result = runner.run(
                    args=["-d", domain, "-b", "google,bing,duckduckgo",
                          "-l", str(limit), "-f", out_base],
                    stream=stream, timeout=120,
                )
                out_file = out_base + ".json"
                if os.path.exists(out_file):
                    with open(out_file) as f:
                        data = j.load(f)
                    for e in data.get("emails", []):
                        emails.add(e.lower())
                else:
                    for e in re.findall(self.EMAIL_RE, result.get("stdout", "")):
                        emails.add(e.lower())
            finally:
                for ext in (".json", ".xml"):
                    p = out_base + ext
                    if os.path.exists(p):
                        os.unlink(p)

        if "hunter_io" in sources and hunter_key:
            stream("info", "Querying Hunter.io...")
            try:
                from urllib.parse import urlencode
                url = (f"https://api.hunter.io/v2/domain-search?"
                       f"domain={domain}&api_key={hunter_key}&limit={min(limit,100)}")
                with urllib.request.urlopen(url, timeout=15) as r:
                    data = j.loads(r.read())
                for entry in data.get("data", {}).get("emails", []):
                    emails.add(entry["value"].lower())
            except Exception as e:
                stream("warning", f"Hunter.io error: {e}")

        if "duckduckgo" in sources:
            stream("info", "Scraping DuckDuckGo for emails...")
            try:
                from urllib.parse import quote
                url = f"https://html.duckduckgo.com/html/?q={quote(domain+' email site:'+domain)}"
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=15) as r:
                    body = r.read(65536).decode("utf-8", errors="replace")
                domain_emails = [e.lower() for e in re.findall(self.EMAIL_RE, body)
                                 if domain.lower() in e.lower()]
                emails.update(domain_emails)
            except Exception as e:
                stream("warning", f"DuckDuckGo scrape error: {e}")

        unique_emails = sorted(emails)[:limit]
        stream("info", f"Total unique emails: {len(unique_emails)}")
        findings = []
        if unique_emails:
            findings.append({
                "title": f"{len(unique_emails)} email address(es) harvested for {domain}",
                "severity": "medium",
                "url": f"https://{domain}",
                "description": (
                    f"Harvested {len(unique_emails)} email addresses associated with {domain}. "
                    "These can be used in phishing simulations or credential spray testing."
                ),
                "evidence": "\n".join(unique_emails[:100]),
                "remediation": (
                    "Obfuscate email addresses on public pages. "
                    "Add reCAPTCHA to contact forms. "
                    "Monitor for credential spray attacks."
                ),
            })
        return {
            "status": "done",
            "findings": findings,
            "raw_output": "\n".join(raw_lines) + "\n\nEmails:\n" + "\n".join(unique_emails),
        }


# ─── [R-12] Google Dork Automation ───────────────────────────────────────────

class GoogleDorkModule(BaseModule):
    id = "R-12"
    name = "Google Dork Automation"
    category = "recon"
    description = (
        "Generate a curated set of Google dork search queries for a target domain. "
        "Covers exposed files, login panels, vulnerable parameters, config leaks, and more."
    )
    risk_level = "medium"
    tags = ["google", "dork", "osint", "recon", "information disclosure"]
    celery_queue = "recon_queue"
    time_limit = 30

    DORK_LIBRARY = {
        "Exposed Files & Backups": [
            'site:{domain} ext:sql OR ext:bak OR ext:backup OR ext:dump',
            'site:{domain} ext:env OR ext:cfg OR ext:conf OR ext:config',
            'site:{domain} "index of" (backup OR db OR sql OR log)',
            'site:{domain} ext:log filetype:log',
            'site:{domain} ext:pem OR ext:key OR ext:p12 OR ext:pfx',
        ],
        "Login Panels": [
            'site:{domain} inurl:login OR inurl:admin OR inurl:signin',
            'site:{domain} inurl:wp-login OR inurl:wp-admin',
            'site:{domain} inurl:"adminpanel" OR inurl:"controlpanel"',
            'site:{domain} intitle:"Login" OR intitle:"Admin Login"',
        ],
        "Sensitive Information": [
            'site:{domain} "password" OR "passwd" OR "secret" filetype:txt',
            'site:{domain} "api_key" OR "api-key" OR "apikey"',
            'site:{domain} "access_token" OR "bearer" OR "Authorization:"',
            'site:{domain} intext:"DB_PASSWORD" OR intext:"DB_USER"',
        ],
        "Vulnerable Parameters": [
            'site:{domain} inurl:"?id=" OR inurl:"?page=" OR inurl:"?cat="',
            'site:{domain} inurl:"?redirect=" OR inurl:"?url=" OR inurl:"?next="',
            'site:{domain} inurl:"?file=" OR inurl:"?path=" OR inurl:"?dir="',
        ],
        "Error Pages & Debug Info": [
            'site:{domain} "Fatal error" OR "Warning:" OR "Undefined variable"',
            'site:{domain} "stack trace" OR "Traceback (most recent call last)"',
            'site:{domain} intitle:"Error" intext:"MySQL" OR "ORA-" OR "MSSQL"',
        ],
        "Cloud & Infrastructure": [
            'site:{domain} "amazonaws.com" OR "storage.googleapis.com"',
            'site:{domain} "github.com" OR "gitlab.com" OR "bitbucket.org"',
            'site:{domain} ".git/config" OR "/.git/" OR "gitconfig"',
        ],
    }

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="domain",
            label="Target Domain",
            field_type="text",
            required=True,
            placeholder="example.com",
        ),
        FieldSchema(
            key="categories",
            label="Dork Categories",
            field_type="checkbox_group",
            default=["Exposed Files & Backups", "Login Panels", "Sensitive Information",
                     "Vulnerable Parameters", "Error Pages & Debug Info", "Cloud & Infrastructure"],
            options=[{"value": k, "label": k} for k in DORK_LIBRARY],
        ),
        FieldSchema(
            key="custom_dorks",
            label="Custom Dorks (one per line, use {domain})",
            field_type="textarea",
            required=False,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        from urllib.parse import quote

        domain = params["domain"].strip().lower()
        categories = params.get("categories", list(self.DORK_LIBRARY.keys()))
        custom_raw = params.get("custom_dorks", "").strip()

        findings = []
        all_dorks = []
        raw_lines = [f"Google dorks for: {domain}", ""]

        for cat in categories:
            dorks = self.DORK_LIBRARY.get(cat, [])
            cat_dorks = [d.replace("{domain}", domain) for d in dorks]
            all_dorks.extend(cat_dorks)
            if cat_dorks:
                findings.append({
                    "title": f"Google Dorks — {cat}",
                    "severity": "info",
                    "url": "",
                    "description": f"Category: {cat}\n{len(cat_dorks)} dork(s) generated.",
                    "evidence": "\n".join(
                        f"https://www.google.com/search?q={quote(d)}  →  {d}"
                        for d in cat_dorks
                    ),
                    "remediation": (
                        "Review all returned results and remove or protect exposed resources. "
                        "Submit removal requests to Google for sensitive cached pages."
                    ),
                })
                raw_lines.append(f"[{cat}]")
                raw_lines.extend(f"  {d}" for d in cat_dorks)
                raw_lines.append("")
            stream("info", f"{cat}: {len(cat_dorks)} dork(s)")

        if custom_raw:
            custom_dorks = [
                d.strip().replace("{domain}", domain)
                for d in custom_raw.splitlines() if d.strip()
            ]
            all_dorks.extend(custom_dorks)
            findings.append({
                "title": f"Custom Google Dorks ({len(custom_dorks)} dork(s))",
                "severity": "info",
                "url": "",
                "description": "User-supplied custom dorks.",
                "evidence": "\n".join(
                    f"https://www.google.com/search?q={quote(d)}"
                    for d in custom_dorks
                ),
                "remediation": "Review all results manually.",
            })

        stream("success", f"Generated {len(all_dorks)} dorks across {len(categories)} categories")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [R-13] GitHub Recon ─────────────────────────────────────────────────────

class GitHubReconModule(BaseModule):
    id = "R-13"
    name = "GitHub Recon"
    category = "recon"
    description = (
        "Search GitHub for secrets, sensitive files, and exposed credentials "
        "belonging to a target organisation. Uses trufflehog for deep secret scanning "
        "and GitHub Search API for targeted dork queries."
    )
    risk_level = "high"
    tags = ["github", "secrets", "trufflehog", "recon", "osint", "leak"]
    celery_queue = "recon_queue"
    time_limit = 300

    SEARCH_DORKS = {
        "Credentials": [
            'org:{org} password',
            'org:{org} secret key',
            'org:{org} "BEGIN RSA PRIVATE KEY"',
            'org:{org} "api_key" OR "api-key" OR "apikey"',
        ],
        "Config Files": [
            'org:{org} filename:.env',
            'org:{org} filename:docker-compose.yml password',
            'org:{org} filename:.htpasswd',
        ],
        "AWS": [
            'org:{org} AKIA language:python OR language:javascript',
            'org:{org} aws_secret_access_key',
        ],
        "Database": [
            'org:{org} filename:*.sql password',
            'org:{org} DB_PASSWORD',
        ],
    }

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target",
            label="GitHub Organisation or User",
            field_type="text",
            required=True,
            placeholder="acme-corp",
        ),
        FieldSchema(
            key="github_token",
            label="GitHub Personal Access Token",
            field_type="text",
            required=False,
            placeholder="ghp_...",
            help_text="Required for GitHub Search API. Leave blank for trufflehog only.",
            group="credentials",
        ),
        FieldSchema(
            key="scan_mode",
            label="Scan Mode",
            field_type="checkbox_group",
            default=["trufflehog", "search_api"],
            options=[
                {"value": "trufflehog",  "label": "trufflehog (deep secret scan)"},
                {"value": "search_api",  "label": "GitHub Search API dorks"},
            ],
        ),
        FieldSchema(
            key="dork_categories",
            label="Dork Categories",
            field_type="checkbox_group",
            default=["Credentials", "Config Files", "AWS", "Database"],
            options=[{"value": k, "label": k} for k in SEARCH_DORKS],
        ),
        FieldSchema(
            key="repo_url",
            label="Specific Repo URL (trufflehog override)",
            field_type="url",
            required=False,
            group="advanced",
        ),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import json as j, urllib.request, urllib.error
        from apps.modules.runner import ToolRunner

        target = params["target"].strip()
        token = params.get("github_token", "").strip()
        scan_modes = params.get("scan_mode", ["trufflehog"])
        dork_cats = params.get("dork_categories", list(self.SEARCH_DORKS.keys()))
        repo_url = params.get("repo_url", "").strip()

        findings = []
        raw_lines = [f"Target: {target}"]

        if "trufflehog" in scan_modes:
            stream("info", "Running trufflehog...")
            runner = ToolRunner("trufflehog")
            scan_target = repo_url if repo_url else f"https://github.com/{target}"
            args = [
                "github",
                "--repo" if repo_url else "--org", scan_target,
                "--json", "--no-update",
            ]
            if token:
                args += ["--token", token]
            result = runner.run(args=args, stream=stream, timeout=240)
            raw = result.get("stdout", "")
            secret_count = 0
            for line in raw.splitlines():
                try:
                    entry = j.loads(line)
                except Exception:
                    continue
                detector = entry.get("DetectorName", "Unknown")
                source = entry.get("SourceMetadata", {}).get("Data", {})
                repo = source.get("Github", {}).get("repository", "")
                commit = source.get("Github", {}).get("commit", "")
                raw_secret = entry.get("Raw", "")[:200]
                secret_count += 1
                findings.append({
                    "title": f"trufflehog: {detector} secret in {repo}",
                    "severity": "critical",
                    "url": f"https://github.com/{repo}/commit/{commit}" if repo and commit else "",
                    "description": (
                        f"trufflehog detected a {detector} secret.\n"
                        f"Repository: {repo}\nCommit: {commit}"
                    ),
                    "evidence": raw_secret,
                    "remediation": (
                        "Immediately invalidate the exposed secret. "
                        "Remove from git history using git-filter-repo or BFG Repo-Cleaner."
                    ),
                    "cvss_score": 9.5,
                })
            if not secret_count:
                stream("info", "trufflehog: no secrets detected")
            else:
                stream("success", f"trufflehog: {secret_count} secret(s) found!")

        if "search_api" in scan_modes and token:
            headers = {
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "PenTools/1.0",
            }
            for cat in dork_cats:
                dorks = self.SEARCH_DORKS.get(cat, [])
                for dork_tpl in dorks:
                    query = dork_tpl.replace("{org}", target)
                    stream("info", f"GitHub search: {query}")
                    try:
                        from urllib.parse import quote
                        url = f"https://api.github.com/search/code?q={quote(query)}&per_page=10"
                        req = urllib.request.Request(url, headers=headers)
                        with urllib.request.urlopen(req, timeout=10) as r:
                            data = j.loads(r.read())
                        total = data.get("total_count", 0)
                        if total > 0:
                            items = data.get("items", [])
                            findings.append({
                                "title": f"GitHub [{cat}]: '{query}' — {total} result(s)",
                                "severity": "high",
                                "url": f"https://github.com/search?q={quote(query)}&type=code",
                                "description": (
                                    f"Query: {query}\nResults: {total}\nTop files:\n" +
                                    "\n".join(
                                        f"  - {i.get('repository',{}).get('full_name','')}: {i.get('path','')}"
                                        for i in items[:5]
                                    )
                                ),
                                "evidence": str([i.get("html_url") for i in items[:5]]),
                                "remediation": (
                                    "Review each match for secrets or sensitive data. "
                                    "Rotate exposed credentials and remove from history."
                                ),
                            })
                            stream("success", f"  Hit: {total} result(s)")
                    except urllib.error.HTTPError as e:
                        if e.code == 403:
                            stream("warning", "GitHub API rate limit hit")
                    except Exception as e:
                        stream("warning", f"Search error: {e}")
        elif "search_api" in scan_modes and not token:
            stream("warning", "GitHub Search API requires a token — skipped")

        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [R-15] Cloud Asset Discovery ────────────────────────────────────────────

class CloudAssetDiscoveryModule(BaseModule):
    id = "R-15"
    name = "Cloud Asset Discovery"
    category = "recon"
    description = (
        "Enumerate cloud storage buckets (AWS S3, GCP, Azure Blob) using permutation-based "
        "name generation from a company name. Probes each for public access."
    )
    risk_level = "high"
    tags = ["cloud", "s3", "gcp", "azure", "bucket", "recon", "enumeration"]
    celery_queue = "recon_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="company_name",
            label="Company / Brand Name",
            field_type="text",
            required=True,
            placeholder="acme",
        ),
        FieldSchema(
            key="extra_keywords",
            label="Additional Keywords (one per line)",
            field_type="textarea",
            required=False,
            placeholder="backup\ndev\nstaging",
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
    ]

    _SUFFIXES = [
        "", "-backup", "-prod", "-dev", "-staging", "-test", "-data",
        "-files", "-assets", "-uploads", "-media", "-cdn", "-static",
        "-logs", "-archive", "-db", "-config",
    ]
    _PREFIXES = ["", "backup-", "dev-", "staging-", "prod-", "data-", "assets-"]

    def _gen_names(self, base: str, extras: list) -> list:
        import re
        clean = re.sub(r"[^a-z0-9]", "-", base.lower())
        names: set = set()
        words = [clean] + [re.sub(r"[^a-z0-9]", "-", e.lower()) for e in extras if e.strip()]
        for w in words:
            for pre in self._PREFIXES:
                for suf in self._SUFFIXES:
                    name = f"{pre}{w}{suf}"
                    if 3 <= len(name) <= 63:
                        names.add(name)
        return sorted(names)

    def _probe(self, url: str) -> tuple:
        import urllib.request, urllib.error
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0"}), timeout=8
            ) as r:
                body = r.read(2048).decode("utf-8", errors="replace")
                return r.status, body
        except urllib.error.HTTPError as e:
            return e.code, e.read(512).decode("utf-8", errors="replace")
        except Exception:
            return 0, ""

    def execute(self, params: dict, job_id: str, stream) -> dict:
        company = params["company_name"].strip()
        extras = [e.strip() for e in params.get("extra_keywords", "").splitlines() if e.strip()]
        providers = params.get("providers", ["aws"])

        names = self._gen_names(company, extras)
        stream("info", f"Generated {len(names)} permutations")

        findings = []
        raw_lines = [f"Permutations: {len(names)}"]

        for name in names:
            if "aws" in providers:
                code, body = self._probe(f"https://{name}.s3.amazonaws.com/?max-keys=5")
                if code in (200, 403) and "NoSuchBucket" not in body:
                    readable = code == 200 and "<ListBucketResult" in body
                    sev = "critical" if readable else "medium"
                    stream("info" if not readable else "success",
                           f"S3: {name} (readable={readable})")
                    findings.append({
                        "title": f"S3 bucket: {name}" + (" [PUBLIC READ]" if readable else " [exists]"),
                        "severity": sev,
                        "url": f"https://{name}.s3.amazonaws.com/",
                        "description": (
                            f"S3 bucket '{name}' exists. "
                            f"Public read: {'YES' if readable else 'No'}"
                        ),
                        "evidence": body[:1000],
                        "remediation": "Enable S3 Block Public Access. Review ACLs and bucket policies.",
                    })

            if "gcp" in providers:
                code, body = self._probe(f"https://storage.googleapis.com/{name}/")
                if code in (200, 403, 400) and "NoSuchBucket" not in body and code != 0:
                    readable = code == 200 and len(body) > 0
                    findings.append({
                        "title": f"GCS bucket: {name}" + (" [PUBLIC]" if readable else " [exists]"),
                        "severity": "critical" if readable else "medium",
                        "url": f"https://storage.googleapis.com/{name}/",
                        "description": f"GCS bucket '{name}' exists. Public: {readable}",
                        "evidence": body[:500],
                        "remediation": "Disable allUsers IAM bindings on the bucket.",
                    })
                    if readable:
                        stream("success", f"GCS: {name} [PUBLIC]")

            if "azure" in providers:
                import re as _re
                safe = _re.sub(r"[^a-z0-9]", "", name.lower())[:24]
                if len(safe) >= 3:
                    code, body = self._probe(f"https://{safe}.blob.core.windows.net/")
                    if code in (400, 403, 409) and "StorageAccountNotFound" not in body:
                        findings.append({
                            "title": f"Azure Blob storage: {safe} [exists]",
                            "severity": "medium",
                            "url": f"https://{safe}.blob.core.windows.net/",
                            "description": f"Azure storage account '{safe}' exists.",
                            "evidence": body[:300],
                            "remediation": "Disable anonymous blob access. Enable Defender for Storage.",
                        })

        if not findings:
            findings.append({
                "title": f"No cloud assets found for '{company}'",
                "severity": "info", "url": "", "description": "No public buckets found.",
                "evidence": "", "remediation": "N/A",
            })

        stream("success", f"Cloud discovery complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [R-16] Virtual Host Discovery ───────────────────────────────────────────

class VirtualHostDiscoveryModule(BaseModule):
    id = "R-16"
    name = "Virtual Host Discovery"
    category = "recon"
    description = (
        "Fuzz HTTP Host header to discover virtual hosts served by a single IP. "
        "Uses ffuf with built-in or custom wordlist."
    )
    risk_level = "medium"
    tags = ["vhost", "ffuf", "fuzzing", "recon", "subdomain"]
    celery_queue = "recon_queue"
    time_limit = 300

    _BUILTIN_WORDLIST = [
        "admin", "api", "app", "auth", "backend", "beta", "blog", "cdn",
        "cms", "console", "dashboard", "data", "db", "dev", "demo", "docs",
        "email", "ftp", "git", "help", "internal", "intranet", "jenkins",
        "jira", "kibana", "ldap", "legacy", "login", "mail", "manage",
        "metrics", "monitoring", "noc", "old", "ops", "portal", "preprod",
        "proxy", "remote", "sandbox", "smtp", "staff", "staging", "static",
        "support", "test", "vpn", "webapp", "wiki", "www", "www2",
    ]

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_ip",   label="Target IP / Host",  field_type="text",   required=True,  placeholder="10.10.10.10"),
        FieldSchema(key="domain",      label="Base Domain",        field_type="text",   required=True,  placeholder="example.com"),
        FieldSchema(key="port",        label="Port",               field_type="number", default=80),
        FieldSchema(key="scheme",      label="Scheme",             field_type="radio",  default="http",
                    options=[{"value": "http", "label": "HTTP"}, {"value": "https", "label": "HTTPS"}]),
        FieldSchema(key="wordlist",    label="Wordlist",           field_type="wordlist_select", default="subdomains-top1million-5000.txt"),
        FieldSchema(key="filter_status", label="Filter Status Codes (exclude)", field_type="text", default="404", group="advanced"),
        FieldSchema(key="threads",     label="Threads",            field_type="number", default=50, group="advanced"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os, tempfile, json as j
        from apps.modules.runner import ToolRunner

        target_ip = params["target_ip"].strip()
        domain = params["domain"].strip().lower()
        port = int(params.get("port", 80))
        scheme = params.get("scheme", "http")
        wordlist_name = params.get("wordlist", "subdomains-top1million-5000.txt")
        filter_status = params.get("filter_status", "404")
        threads = int(params.get("threads", 50))

        target_url = (target_ip if target_ip.startswith("http")
                      else f"{scheme}://{target_ip}:{port}")

        wl_paths = [
            f"/opt/tools/wordlists/{wordlist_name}",
            f"/usr/share/wordlists/{wordlist_name}",
            f"/usr/share/seclists/Discovery/DNS/{wordlist_name}",
        ]
        wl_file = next((p for p in wl_paths if os.path.exists(p)), None)
        tmp_wl = None
        if not wl_file:
            stream("warning", "Wordlist not found — using built-in list")
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(self._BUILTIN_WORDLIST))
                wl_file = tmp_wl = tf.name

        findings = []
        raw_lines = [f"Target: {target_url}", f"Domain: {domain}"]

        try:
            runner = ToolRunner("ffuf")
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as out_f:
                out_json = out_f.name

            result = runner.run(
                args=[
                    "-w", f"{wl_file}:FUZZ",
                    "-u", target_url + "/",
                    "-H", f"Host: FUZZ.{domain}",
                    "-fc", filter_status,
                    "-t", str(threads),
                    "-o", out_json, "-of", "json",
                    "-timeout", "5", "-s",
                ],
                stream=stream, timeout=240,
            )
            raw_lines.append(result.get("stdout", ""))

            if os.path.exists(out_json):
                with open(out_json) as f:
                    data = j.load(f)
                for item in data.get("results", []):
                    vhost = item.get("input", {}).get("FUZZ", "")
                    status = item.get("status", 0)
                    length = item.get("length", 0)
                    stream("success", f"Found vhost: {vhost}.{domain} (HTTP {status})")
                    findings.append({
                        "title": f"Virtual host: {vhost}.{domain}",
                        "severity": "medium",
                        "url": f"{scheme}://{target_ip}/",
                        "description": (
                            f"Virtual host '{vhost}.{domain}' responds differently.\n"
                            f"HTTP {status} | {length} bytes"
                        ),
                        "evidence": f"Host: {vhost}.{domain} → HTTP {status} / {length}B",
                        "remediation": "Ensure all vhosts have proper access controls.",
                    })
                os.unlink(out_json)
        finally:
            if tmp_wl:
                try:
                    os.unlink(tmp_wl)
                except Exception:
                    pass

        if not findings:
            findings.append({
                "title": f"No virtual hosts discovered on {target_ip}",
                "severity": "info", "url": target_url,
                "description": "No vhosts responded differently from baseline.",
                "evidence": "", "remediation": "N/A",
            })

        stream("success", f"Vhost discovery complete — {len(findings)} host(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [R-17] Screenshot Capture ───────────────────────────────────────────────

class ScreenshotCaptureModule(BaseModule):
    id = "R-17"
    name = "Screenshot Capture"
    category = "recon"
    description = (
        "Capture screenshots of web services using gowitness. Supports single URL, "
        "URL list, or CIDR range scan."
    )
    risk_level = "info"
    tags = ["screenshot", "gowitness", "visual", "recon", "web"]
    celery_queue = "recon_queue"
    time_limit = 300

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="input_mode",
            label="Input Mode",
            field_type="radio",
            default="single",
            options=[
                {"value": "single", "label": "Single URL"},
                {"value": "list",   "label": "URL List (one per line)"},
                {"value": "cidr",   "label": "CIDR range"},
            ],
        ),
        FieldSchema(key="target_url", label="Target URL",  field_type="url",      required=False, placeholder="https://example.com", show_if={"input_mode": "single"}),
        FieldSchema(key="url_list",   label="URL List",    field_type="textarea", required=False, show_if={"input_mode": "list"}),
        FieldSchema(key="cidr",       label="CIDR Range",  field_type="text",     required=False, placeholder="192.168.1.0/24", show_if={"input_mode": "cidr"}),
        FieldSchema(key="ports",      label="Ports (CIDR)", field_type="text",    default="80,443,8080,8443", show_if={"input_mode": "cidr"}, group="advanced"),
        FieldSchema(key="threads",    label="Threads",     field_type="number",   default=4,  group="advanced"),
        FieldSchema(key="timeout",    label="Per-URL timeout (s)", field_type="number", default=10, group="advanced"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import os, tempfile
        from apps.modules.runner import ToolRunner

        input_mode = params.get("input_mode", "single")
        threads = int(params.get("threads", 4))
        timeout_s = int(params.get("timeout", 10))

        out_dir = f"/app/uploads/screenshots/{job_id}"
        os.makedirs(out_dir, exist_ok=True)
        runner = ToolRunner("gowitness")
        raw_lines = [f"Output directory: {out_dir}"]

        if input_mode == "single":
            target = params.get("target_url", "").strip()
            if not target:
                return {"status": "failed", "findings": [], "raw_output": "No URL provided"}
            stream("info", f"Screenshotting: {target}")
            result = runner.run(
                args=["single", "-u", target, "--screenshot-path", out_dir,
                      "--timeout", str(timeout_s)],
                stream=stream, timeout=60,
            )
            raw_lines.append(result.get("stdout", ""))

        elif input_mode == "list":
            url_list = params.get("url_list", "").strip()
            if not url_list:
                return {"status": "failed", "findings": [], "raw_output": "No URLs provided"}
            urls = [u.strip() for u in url_list.splitlines() if u.strip()]
            stream("info", f"Screenshotting {len(urls)} URL(s)...")
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
                tf.write("\n".join(urls))
                url_file = tf.name
            try:
                result = runner.run(
                    args=["file", "-f", url_file, "--screenshot-path", out_dir,
                          "--threads", str(threads), "--timeout", str(timeout_s)],
                    stream=stream, timeout=240,
                )
                raw_lines.append(result.get("stdout", ""))
            finally:
                os.unlink(url_file)

        elif input_mode == "cidr":
            cidr = params.get("cidr", "").strip()
            if not cidr:
                return {"status": "failed", "findings": [], "raw_output": "No CIDR provided"}
            ports = params.get("ports", "80,443,8080,8443")
            stream("info", f"Scanning CIDR {cidr} on ports {ports}...")
            result = runner.run(
                args=["cidr", cidr, "--ports", ports, "--screenshot-path", out_dir,
                      "--threads", str(threads), "--timeout", str(timeout_s)],
                stream=stream, timeout=240,
            )
            raw_lines.append(result.get("stdout", ""))

        screenshots = [f for f in os.listdir(out_dir) if f.endswith(".png")] if os.path.exists(out_dir) else []
        stream("success", f"Captured {len(screenshots)} screenshot(s)")

        findings = [{
            "title": (f"{len(screenshots)} screenshot(s) captured" if screenshots
                      else "No screenshots captured"),
            "severity": "info",
            "url": "",
            "description": (
                f"Screenshots saved to {out_dir}.\nFiles: {', '.join(screenshots[:20])}"
                if screenshots else "gowitness produced no screenshots."
            ),
            "evidence": "\n".join(screenshots[:50]),
            "remediation": "Review screenshots for exposed admin panels or sensitive pages.",
        }]

        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}


# ─── [R-14] Shodan / Censys Query ────────────────────────────────────────────

class ShodanCensysQueryModule(BaseModule):
    id = "R-14"
    name = "Shodan / Censys Intelligence Query"
    category = "recon"
    description = (
        "Query Shodan and Censys APIs for target host intelligence: open ports, "
        "running services, CVEs, geographic location, and ASN data. "
        "Supports both IP lookups and dork-style searches."
    )
    risk_level = "info"
    tags = ["shodan", "censys", "recon", "osint", "ports", "services", "intelligence"]
    celery_queue = "recon_queue"
    time_limit = 90

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="query",
            label="Search Query or IP",
            field_type="text",
            required=True,
            placeholder='hostname:"example.com" OR 93.184.216.34',
            help_text="IP address, hostname, or search query (Shodan/Censys dork syntax).",
        ),
        FieldSchema(
            key="providers",
            label="Providers to query",
            field_type="checkbox_group",
            default=["shodan"],
            options=[
                {"value": "shodan",  "label": "Shodan (requires API key)"},
                {"value": "censys",  "label": "Censys (requires API ID + secret)"},
            ],
        ),
        FieldSchema(key="shodan_api_key",     label="Shodan API Key",        field_type="text", required=False, group="credentials"),
        FieldSchema(key="censys_api_id",      label="Censys API ID",         field_type="text", required=False, group="credentials"),
        FieldSchema(key="censys_api_secret",  label="Censys API Secret",     field_type="text", required=False, group="credentials"),
        FieldSchema(
            key="facets",
            label="Result Facets",
            field_type="checkbox_group",
            default=["ports", "org", "country"],
            options=[
                {"value": "ports",   "label": "Open ports"},
                {"value": "org",     "label": "Organization / ASN"},
                {"value": "country", "label": "Country"},
                {"value": "product", "label": "Product / Service"},
                {"value": "cves",    "label": "Known CVEs (Shodan)"},
                {"value": "hostnames", "label": "Hostnames"},
            ],
        ),
        FieldSchema(key="max_results", label="Max results per provider", field_type="number", default=20),
    ]

    def _shodan_host(self, ip: str, api_key: str, timeout: int = 15) -> dict:
        import urllib.request, urllib.error, json
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0"}),
                timeout=timeout
            ) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.read(200).decode('utf-8', errors='replace')}"}
        except Exception as ex:
            return {"error": str(ex)}

    def _shodan_search(self, query: str, api_key: str, max_results: int, timeout: int = 15) -> dict:
        import urllib.request, urllib.error, json, urllib.parse
        params = urllib.parse.urlencode({"key": api_key, "query": query, "minify": "false"})
        url = f"https://api.shodan.io/shodan/host/search?{params}"
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers={"User-Agent": "PenTools/1.0"}),
                timeout=timeout
            ) as r:
                data = json.loads(r.read())
                data["matches"] = data.get("matches", [])[:max_results]
                return data
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.read(200).decode('utf-8', errors='replace')}"}
        except Exception as ex:
            return {"error": str(ex)}

    def _censys_search(self, query: str, api_id: str, api_secret: str, max_results: int, timeout: int = 15) -> dict:
        import urllib.request, urllib.error, json, base64, urllib.parse
        url = "https://search.censys.io/api/v2/hosts/search"
        payload = json.dumps({"q": query, "per_page": min(max_results, 100)}).encode()
        credentials = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        req = urllib.request.Request(url, data=payload, headers={
            "Authorization": f"Basic {credentials}",
            "Content-Type": "application/json",
            "User-Agent": "PenTools/1.0",
        }, method="GET")
        # Censys v2 uses GET with query params
        params = urllib.parse.urlencode({"q": query, "per_page": min(max_results, 100)})
        get_url = f"https://search.censys.io/api/v2/hosts/search?{params}"
        get_req = urllib.request.Request(get_url, headers={
            "Authorization": f"Basic {credentials}",
            "User-Agent": "PenTools/1.0",
        })
        try:
            with urllib.request.urlopen(get_req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.read(200).decode('utf-8', errors='replace')}"}
        except Exception as ex:
            return {"error": str(ex)}

    def _censys_host(self, ip: str, api_id: str, api_secret: str, timeout: int = 15) -> dict:
        import urllib.request, urllib.error, json, base64
        url = f"https://search.censys.io/api/v2/hosts/{ip}"
        credentials = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        req = urllib.request.Request(url, headers={
            "Authorization": f"Basic {credentials}",
            "User-Agent": "PenTools/1.0",
        })
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}: {e.read(200).decode('utf-8', errors='replace')}"}
        except Exception as ex:
            return {"error": str(ex)}

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import re

        query = params["query"].strip()
        import os as _os
        providers = params.get("providers", ["shodan"])
        shodan_key = (params.get("shodan_api_key") or "").strip() or _os.environ.get("SHODAN_API_KEY", "").strip()
        censys_id = (params.get("censys_api_id") or "").strip()
        censys_secret = params.get("censys_api_secret", "").strip()
        facets = params.get("facets", ["ports", "org", "country"])
        max_results = int(params.get("max_results", 20))

        findings = []
        raw_lines = [f"Query: {query}", f"Providers: {providers}"]

        # Detect if query is an IP address
        is_ip = bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", query))

        # ── Shodan ──
        if "shodan" in providers:
            if not shodan_key:
                findings.append({
                    "title": "Shodan query — API key missing",
                    "severity": "info", "url": "",
                    "description": "No Shodan API key provided. Configure in credentials.",
                    "evidence": "",
                    "remediation": "Add Shodan API key from https://account.shodan.io",
                })
            else:
                stream("info", f"Querying Shodan for: {query}")
                if is_ip:
                    data = self._shodan_host(query, shodan_key)
                else:
                    data = self._shodan_search(query, shodan_key, max_results)

                if "error" in data:
                    stream("warning", f"Shodan error: {data['error']}")
                    findings.append({
                        "title": "Shodan query error",
                        "severity": "info", "url": "",
                        "description": f"Shodan API returned: {data['error']}",
                        "evidence": data["error"],
                        "remediation": "Verify API key and query syntax.",
                    })
                else:
                    # Process host data
                    if is_ip:
                        ports = [s.get("port") for s in data.get("data", [])]
                        services = [f"{s.get('port')}/{s.get('transport','tcp')} {s.get('product','')} {s.get('version','')}" 
                                    for s in data.get("data", [])[:20]]
                        vulns = list(data.get("vulns", {}).keys())
                        hostnames = data.get("hostnames", [])
                        org = data.get("org", "")
                        country = data.get("country_name", "")
                        raw_lines.append(f"Shodan host: {ports} ports, {len(vulns)} CVEs")

                        sev = "critical" if vulns else ("high" if len(ports) > 10 else "medium")
                        findings.append({
                            "title": f"Shodan host intel: {query} — {len(ports)} open ports",
                            "severity": sev,
                            "url": f"https://www.shodan.io/host/{query}",
                            "description": (
                                f"Shodan reports {len(ports)} open port(s) on {query}.\n"
                                f"Org: {org} | Country: {country}\n"
                                f"Hostnames: {', '.join(hostnames[:5])}\n"
                                + (f"CVEs: {', '.join(vulns[:10])}" if vulns else "No CVEs reported by Shodan.")
                            ),
                            "evidence": (
                                f"Open ports: {ports}\n"
                                f"Services: {chr(10).join(services[:15])}\n"
                                + (f"Vulns: {vulns}" if vulns else "")
                            ),
                            "remediation": (
                                "Close unnecessary ports. Patch CVEs listed above. "
                                "Enable firewall rules for non-public services."
                            ),
                        })

                        if "cves" in facets and vulns:
                            for cve in vulns[:10]:
                                findings.append({
                                    "title": f"Shodan CVE: {cve} on {query}",
                                    "severity": "high",
                                    "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                                    "description": f"Shodan flags {cve} for {query}.",
                                    "evidence": f"Shodan /shodan/host/{query} vulns field",
                                    "remediation": f"See https://nvd.nist.gov/vuln/detail/{cve} for patch details.",
                                    "cve_id": cve,
                                })
                    else:
                        # Search results
                        total = data.get("total", 0)
                        matches = data.get("matches", [])
                        stream("info", f"Shodan search: {total} total results, {len(matches)} fetched")
                        raw_lines.append(f"Shodan total: {total}")

                        findings.append({
                            "title": f"Shodan search: {total} hosts match '{query}'",
                            "severity": "medium" if total > 0 else "info",
                            "url": f"https://www.shodan.io/search?query={query}",
                            "description": f"{total} hosts on Shodan match the query '{query}'.",
                            "evidence": "\n".join(
                                f"{m.get('ip_str','')}:{m.get('port','')} [{m.get('org','')}] {m.get('product','')} {m.get('version','')}"
                                for m in matches[:20]
                            ),
                            "remediation": "Review exposed hosts. Reduce attack surface by limiting internet-facing services.",
                        })

        # ── Censys ──
        if "censys" in providers:
            if not censys_id or not censys_secret:
                findings.append({
                    "title": "Censys query — API credentials missing",
                    "severity": "info", "url": "",
                    "description": "No Censys API ID/secret provided.",
                    "evidence": "",
                    "remediation": "Add Censys credentials from https://search.censys.io/account/api",
                })
            else:
                stream("info", f"Querying Censys for: {query}")
                if is_ip:
                    data = self._censys_host(query, censys_id, censys_secret)
                else:
                    data = self._censys_search(query, censys_id, censys_secret, max_results)

                if "error" in data:
                    stream("warning", f"Censys error: {data['error']}")
                    findings.append({
                        "title": "Censys query error",
                        "severity": "info", "url": "",
                        "description": f"Censys API returned: {data['error']}",
                        "evidence": data["error"],
                        "remediation": "Verify Censys API credentials and query syntax.",
                    })
                else:
                    result = data.get("result", {})
                    if is_ip:
                        services = result.get("services", [])
                        ports = [s.get("port") for s in services]
                        raw_lines.append(f"Censys host: {ports}")
                        findings.append({
                            "title": f"Censys host intel: {query} — {len(ports)} services",
                            "severity": "medium" if ports else "info",
                            "url": f"https://search.censys.io/hosts/{query}",
                            "description": f"Censys reports {len(ports)} service(s) on {query}.",
                            "evidence": "\n".join(
                                f"{s.get('port')}/{s.get('transport_protocol','tcp')} {s.get('service_name','')} {s.get('software',[{'product':''}])[0].get('product','') if s.get('software') else ''}"
                                for s in services[:20]
                            ),
                            "remediation": "Review exposed services and close those not required.",
                        })
                    else:
                        hits = result.get("hits", [])
                        total = result.get("total", 0)
                        raw_lines.append(f"Censys total: {total}")
                        findings.append({
                            "title": f"Censys search: {total} hosts match '{query}'",
                            "severity": "medium" if total > 0 else "info",
                            "url": f"https://search.censys.io/search?resource=hosts&q={query}",
                            "description": f"{total} hosts on Censys match '{query}'.",
                            "evidence": "\n".join(
                                f"{h.get('ip','')}: {', '.join(str(s.get('port')) for s in h.get('services',[])[:5])}"
                                for h in hits[:20]
                            ),
                            "remediation": "Review the exposed attack surface from search results.",
                        })

        if not findings:
            findings.append({
                "title": "Shodan/Censys query — no results",
                "severity": "info", "url": "",
                "description": f"Query '{query}' returned no results from the selected providers.",
                "evidence": "\n".join(raw_lines),
                "remediation": "Try different query syntax or ensure API keys are valid.",
            })

        stream("success", f"Shodan/Censys query complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}
