"""
OWASP ZAP REST API helper for PenTools.

Wraps ZAP's JSON API endpoints so modules don't have to deal with
HTTP plumbing directly.  All network calls are plain urllib (no extra
dependencies) and run synchronously inside Celery workers.

Architecture:
  ┌─────────────────────────────────────────────┐
  │  Celery worker (web container)              │
  │  ZAPClient ──► http://zap:8080 (ZAP daemon) │
  └─────────────────────────────────────────────┘

Environment variables (set in .env):
  ZAP_API_URL  — default http://zap:8080
  ZAP_API_KEY  — must match the key ZAP was started with
"""
from __future__ import annotations

import json
import re
import time
import urllib.parse
import urllib.request
from django.conf import settings


# ── Exceptions ────────────────────────────────────────────────────────────────

class ZAPNotAvailableError(Exception):
    """Raised when ZAP daemon cannot be reached."""


class ZAPAPIError(Exception):
    """Raised when ZAP returns an error response."""


# ── Client ────────────────────────────────────────────────────────────────────

class ZAPClient:
    """
    Thin synchronous wrapper around the ZAP JSON REST API.

    Instantiate once per task execution::

        zap = ZAPClient()
        zap.ping()
    """

    def __init__(self, api_url: str | None = None, api_key: str | None = None):
        self.base_url = (
            (api_url or "").rstrip("/")
            or getattr(settings, "ZAP_API_URL", None)
            or "http://zap:8080"
        )
        self.api_key = (
            api_key
            or getattr(settings, "ZAP_API_KEY", None)
            or "changeme"  # last resort — must match ZAP container default
        )
        if not self.api_key:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                "ZAPClient: ZAP_API_KEY is not set — API calls will fail 403. "
                "Set ZAP_API_KEY in .env and ensure it matches the ZAP daemon."
            )

    # ── Low-level HTTP ────────────────────────────────────────────────────────

    def _get(self, path: str, params: dict | None = None, timeout: int = 30) -> dict:
        qs = dict(params or {})
        qs["apikey"] = self.api_key
        url = f"{self.base_url}{path}?{urllib.parse.urlencode(qs)}"
        try:
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise ZAPAPIError(
                f"ZAP API error {exc.code} on {path}: {body}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ZAPNotAvailableError(
                f"Could not reach ZAP at {self.base_url}: {exc}"
            ) from exc

    def _post(self, path: str, data: dict | None = None, timeout: int = 30) -> dict:
        payload = dict(data or {})
        payload["apikey"] = self.api_key
        encoded = urllib.parse.urlencode(payload).encode()
        url = f"{self.base_url}{path}"
        try:
            req = urllib.request.Request(
                url, data=encoded,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            raise ZAPAPIError(
                f"ZAP API error {exc.code} on {path}: {body}"
            ) from exc
        except urllib.error.URLError as exc:
            raise ZAPNotAvailableError(
                f"Could not reach ZAP at {self.base_url}: {exc}"
            ) from exc

    # ── Health ────────────────────────────────────────────────────────────────

    def ping(self) -> dict:
        """Return ZAP version info or raise ZAPNotAvailableError."""
        return self._get("/JSON/core/view/version/")

    # ── Session management ────────────────────────────────────────────────────

    def new_session(self, name: str = "pentools") -> None:
        self._post("/JSON/core/action/newSession/", {"name": name, "overwrite": "true"})

    # ── Context ───────────────────────────────────────────────────────────────

    def create_context(self, name: str, target_url: str) -> str:
        """Create a context scoped to target_url. Returns context ID."""
        resp = self._post("/JSON/context/action/newContext/", {"contextName": name})
        ctx_id = str(resp.get("contextId", "1"))
        # Include everything under the target domain
        parsed = urllib.parse.urlparse(target_url)
        scheme_host = f"{parsed.scheme}://{parsed.netloc}"
        self._post("/JSON/context/action/includeInContext/", {
            "contextName": name,
            "regex": f"{re.escape(scheme_host)}.*",
        })
        return ctx_id

    # ── Spider (traditional recursive spider) ─────────────────────────────────

    def spider_start(self, target_url: str, max_depth: int = 5) -> str:
        """Start the traditional spider. Returns scan ID."""
        resp = self._post("/JSON/spider/action/scan/", {
            "url": target_url,
            "maxChildren": "0",
            "recurse": "true",
            "contextName": "",
            "subtreeOnly": "false",
        })
        return str(resp.get("scan", "0"))

    def spider_status(self, scan_id: str) -> int:
        """Return spider progress 0-100."""
        resp = self._get("/JSON/spider/view/status/", {"scanId": scan_id})
        return int(resp.get("status", 0))

    def spider_results(self, scan_id: str) -> list[str]:
        """Return list of URLs discovered by the spider."""
        resp = self._get("/JSON/spider/view/results/", {"scanId": scan_id})
        return resp.get("results", [])

    def sites(self) -> list[str]:
        """Return all sites currently in ZAP's site tree."""
        resp = self._get("/JSON/core/view/sites/")
        return resp.get("sites", [])

    def best_site_for(self, target_url: str) -> str:
        """
        Return the URL from ZAP's site tree that best matches target_url.
        ZAP normalises URLs (e.g. strips trailing slashes, follows redirects),
        so the exact URL we submitted may not appear in the tree.
        Falls back to target_url if no match is found.
        """
        parsed = urllib.parse.urlparse(target_url)
        target_host = parsed.netloc.lower().lstrip("www.")
        target_scheme = parsed.scheme

        # Exact match first
        site_list = self.sites()
        for site in site_list:
            if site.rstrip("/") == target_url.rstrip("/"):
                return site

        # Match by scheme + host (handles www redirect)
        for site in site_list:
            p = urllib.parse.urlparse(site)
            if p.scheme == target_scheme and p.netloc.lower().lstrip("www.") == target_host:
                return site

        # Any site containing the host
        for site in site_list:
            if target_host in site.lower():
                return site

        # Nothing matched — return original (let ZAP error naturally)
        return target_url

    def spider_full_results(self, scan_id: str) -> dict:
        resp = self._get("/JSON/spider/view/fullResults/", {"scanId": scan_id})
        return resp

    # ── Ajax Spider ───────────────────────────────────────────────────────────

    def ajax_spider_start(self, target_url: str) -> None:
        """Start the Ajax spider (no scan ID — status polled differently)."""
        self._post("/JSON/ajaxSpider/action/scan/", {
            "url": target_url,
            "inScope": "false",
            "contextName": "",
            "subtreeOnly": "false",
        })

    def ajax_spider_status(self) -> str:
        resp = self._get("/JSON/ajaxSpider/view/status/")
        return resp.get("status", "stopped")

    def ajax_spider_results(self) -> list[str]:
        resp = self._get("/JSON/ajaxSpider/view/results/")
        return [r.get("requestHeader", "").split("\n")[0].split(" ")[1]
                for r in resp.get("results", []) if "requestHeader" in r]

    # ── Passive scan ──────────────────────────────────────────────────────────

    def passive_scan_records_to_scan(self) -> int:
        """Return the number of records still waiting for passive analysis."""
        resp = self._get("/JSON/pscan/view/recordsToScan/")
        return int(resp.get("recordsToScan", 0))

    def wait_passive_scan(self, timeout: int = 300, stream=None) -> None:
        """Block until passive scan queue drains (or timeout reached)."""
        start = time.time()
        while time.time() - start < timeout:
            remaining = self.passive_scan_records_to_scan()
            if remaining == 0:
                break
            if stream:
                stream("info", f"[ZAP] Passive scan: {remaining} records to analyse…")
            time.sleep(10)

    # ── Active scan ───────────────────────────────────────────────────────────

    def active_scan_start(self, target_url: str, recurse: bool = True, policy: str = "") -> str:
        """Start the active scanner. Returns scan ID."""
        data: dict = {
            "url": target_url,
            "recurse": "true" if recurse else "false",
            "inScopeOnly": "false",
        }
        # Only send scanPolicyName when it is non-empty AND is a real ZAP policy
        # name (ZAP returns 400/does_not_exist if the name doesn't exist).
        # An empty string means "use ZAP's default policy".
        if policy and policy.strip():
            data["scanPolicyName"] = policy.strip()
        resp = self._post("/JSON/ascan/action/scan/", data)
        return str(resp.get("scan", "0"))

    def active_scan_status(self, scan_id: str) -> int:
        """Return active scan progress 0-100."""
        resp = self._get("/JSON/ascan/view/status/", {"scanId": scan_id})
        return int(resp.get("status", 0))

    # ── Alerts ────────────────────────────────────────────────────────────────

    def alerts(self, base_url: str = "", risk: str = "") -> list[dict]:
        """Return all recorded alerts (optionally filtered)."""
        params: dict = {}
        if base_url:
            params["baseurl"] = base_url
        if risk:
            params["riskId"] = risk
        resp = self._get("/JSON/core/view/alerts/", params)
        return resp.get("alerts", [])

    def alerts_summary(self) -> dict:
        """Return counts by risk level."""
        resp = self._get("/JSON/alert/view/alertsSummary/")
        return resp.get("alertsSummary", {})

    # ── Auth helpers ──────────────────────────────────────────────────────────

    def set_custom_header(self, name: str, value: str) -> None:
        """
        Add a persistent request header (e.g. Authorization or Cookie)
        to all outbound requests via the replacer rule API.
        """
        self._post("/JSON/replacer/action/addRule/", {
            "description": f"pentools-{name}",
            "enabled": "true",
            "matchType": "REQ_HEADER",
            "matchRegex": "false",
            "matchString": name,
            "replacement": value,
            "initiators": "",
        })

    # ── Session cookie ────────────────────────────────────────────────────────

    def add_session_cookie(self, target_url: str, cookie_value: str) -> None:
        """
        Inject a cookie into ZAP's HTTP sessions / httpSend interceptor.
        Uses the replacer API so it applies regardless of domain.
        """
        self.set_custom_header("Cookie", cookie_value)

    # ── Cleanup ───────────────────────────────────────────────────────────────

    def remove_replacer_rules(self) -> None:
        try:
            rules = self._get("/JSON/replacer/view/rules/").get("rules", [])
            for r in rules:
                if str(r.get("description", "")).startswith("pentools-"):
                    self._post("/JSON/replacer/action/removeRule/",
                               {"description": r["description"]})
        except Exception:
            pass

    # ── HTTP message retrieval ────────────────────────────────────────────────

    def message(self, msg_id: str) -> dict:
        """
        Fetch a single HTTP message from ZAP's history by ID.
        Returns a dict with requestHeader, requestBody, responseHeader, responseBody.
        """
        try:
            resp = self._get("/JSON/core/view/message/", {"id": str(msg_id)})
            return resp.get("message", {})
        except (ZAPAPIError, ZAPNotAvailableError):
            return {}

    @staticmethod
    def _strip_nul(s: str) -> str:
        """Remove NUL bytes that PostgreSQL rejects in text columns."""
        return s.replace("\x00", "") if isinstance(s, str) else s

    def format_http_evidence(self, alert: dict) -> str:
        """
        Build a human-readable evidence block from a ZAP alert.

        Priority:
          1. Fetch full request + response from ZAP history (messageId)
          2. Fall back to alert.evidence + alert.attack + alert.param fields
        """
        lines: list[str] = []

        # ── Section: matched parameter / attack payload ──
        param   = self._strip_nul(alert.get("param", ""))
        attack  = self._strip_nul(alert.get("attack", ""))
        raw_ev  = self._strip_nul(alert.get("evidence", ""))
        conf    = alert.get("confidence", "")
        risk    = alert.get("riskdesc", alert.get("risk", ""))

        if risk:
            lines.append(f"Risk: {risk}")
        if conf:
            lines.append(f"Confidence: {conf}")
        if param:
            lines.append(f"Parameter: {param}")
        if attack and attack != raw_ev:
            lines.append(f"Attack payload: {attack}")
        if raw_ev:
            lines.append(f"Evidence match: {raw_ev}")

        # ── Section: full HTTP request / response from ZAP history ──
        msg_id = alert.get("messageId") or alert.get("id")
        if msg_id:
            msg = self.message(str(msg_id))
            req_hdr  = self._strip_nul((msg.get("requestHeader")  or "").strip())
            req_body = self._strip_nul((msg.get("requestBody")    or "").strip())
            resp_hdr = self._strip_nul((msg.get("responseHeader") or "").strip())
            resp_body = self._strip_nul((msg.get("responseBody")  or "").strip())

            if req_hdr:
                lines.append("")
                lines.append("─── HTTP Request ───────────────────────────────")
                lines.append(req_hdr)
                if req_body:
                    lines.append("")
                    lines.append(req_body[:1000])

            if resp_hdr:
                lines.append("")
                lines.append("─── HTTP Response ──────────────────────────────")
                lines.append(resp_hdr[:500])
                if resp_body:
                    lines.append("")
                    # Show a window around the evidence match if possible
                    body_text = resp_body
                    if raw_ev and raw_ev in resp_body:
                        idx = resp_body.find(raw_ev)
                        start = max(0, idx - 200)
                        end   = min(len(resp_body), idx + len(raw_ev) + 200)
                        body_text = ""
                        if start > 0:
                            body_text += "…"
                        body_text += resp_body[start:end]
                        if end < len(resp_body):
                            body_text += "…"
                    else:
                        body_text = resp_body[:500]
                    lines.append(body_text)

        return "\n".join(lines).strip()

    # ── Alert → Finding conversion ────────────────────────────────────────────

    def alert_to_finding(self, alert: dict, target_url: str) -> dict:
        """Convert a ZAP alert dict into a PenTools finding dict."""
        risk_map = {
            "3": "high",
            "2": "medium",
            "1": "low",
            "0": "info",
            "High":          "high",
            "Medium":        "medium",
            "Low":           "low",
            "Informational": "info",
        }
        risk_raw = str(alert.get("risk", "0"))
        severity = risk_map.get(risk_raw, "info")

        name   = alert.get("name", "Unknown Alert")
        url    = alert.get("url", target_url)
        desc   = alert.get("description", "")
        soln   = alert.get("solution", "")
        ref    = alert.get("reference", "")
        cweid  = alert.get("cweid", "")
        cvss   = None
        try:
            cs = float(alert.get("riskdesc", "").split("(")[-1].rstrip(")").strip())
            cvss = cs
        except Exception:
            pass

        # Build rich evidence block: param, attack payload, full request/response
        evidence = self.format_http_evidence(alert)

        # Fetch raw HTTP message for raw_data too
        msg_id = alert.get("messageId") or alert.get("id")
        http_msg: dict = self.message(str(msg_id)) if msg_id else {}

        return {
            "title":       f"[ZAP] {name}",
            "severity":    severity,
            "url":         url,
            "description": self._strip_nul(desc),
            "evidence":    evidence,
            "remediation": self._strip_nul(soln),
            "cwe_id":      f"CWE-{cweid}" if cweid else "",
            "cvss_score":  cvss,
            "raw_data": {
                "alert_id":        alert.get("alertRef", ""),
                "risk":            risk_raw,
                "confidence":      alert.get("confidence", ""),
                "param":           self._strip_nul(alert.get("param", "")),
                "attack":          self._strip_nul(alert.get("attack", "")),
                "evidence":        self._strip_nul(alert.get("evidence", "")),
                "reference":       self._strip_nul(ref),
                "solution":        self._strip_nul(soln),
                "request_header":  self._strip_nul(http_msg.get("requestHeader", "")),
                "request_body":    self._strip_nul(http_msg.get("requestBody", "")),
                "response_header": self._strip_nul(http_msg.get("responseHeader", "")),
                "response_body":   self._strip_nul((http_msg.get("responseBody", "") or "")[:2000]),
                "zap_alert":       alert,
            },
        }

    def alerts_as_findings(self, target_url: str = "") -> list[dict]:
        """Return all alerts converted to PenTools finding dicts."""
        return [
            self.alert_to_finding(a, target_url)
            for a in self.alerts(base_url=target_url)
        ]

    # ── Polling helpers ───────────────────────────────────────────────────────

    def passive_scan_scanners(self) -> list[dict]:
        """Return list of enabled passive scan rules with their names and IDs."""
        resp = self._get("/JSON/pscan/view/scanners/")
        return resp.get("scanners", [])

    def active_scan_messages_sent(self, scan_id: str) -> int:
        """Return total number of HTTP requests sent by the active scanner so far."""
        try:
            resp = self._get("/JSON/ascan/view/numberOfRecordsToScan/")
            # ZAP returns records still pending; approximation only
            return int(resp.get("numberOfRecordsToScan", 0))
        except Exception:
            return 0

    def active_scan_scanners(self) -> list[dict]:
        """Return list of active scan rules (plugins) with their IDs and names."""
        resp = self._get("/JSON/ascan/view/scanners/")
        return resp.get("scanners", [])

    @staticmethod
    def _is_passive_alert(alert: dict) -> bool:
        """
        Classify an alert as passive (observed from response analysis) or active
        (injected attack payload).

        ZAP passive rule plugin IDs are generally < 40000;
        active rule IDs are >= 40000. However, a few rules have low IDs but are
        triggered by the active scanner — these are listed explicitly.
        """
        # Rules with IDs < 40000 that are actually fired by the active scanner
        _ACTIVE_DESPITE_LOW_ID = {
            10104,  # User Agent Fuzzer
        }
        try:
            pid = int(alert.get("pluginId", 0))
            if pid in _ACTIVE_DESPITE_LOW_ID:
                return False
            return pid < 40000
        except (TypeError, ValueError):
            return True

    # ── Polling helpers ───────────────────────────────────────────────────────

    def wait_spider(
        self,
        scan_id: str,
        timeout: int = 600,
        stream=None,
    ) -> None:
        """Block until spider reaches 100% or timeout. Logs only on progress change."""
        start = time.time()
        last_pct = -1
        while time.time() - start < timeout:
            pct = self.spider_status(scan_id)
            if pct != last_pct:
                if stream:
                    stream("info", f"[ZAP] Spider progress: {pct}%")
                last_pct = pct
            if pct >= 100:
                break
            time.sleep(5)

    def wait_active_scan(
        self,
        scan_id: str,
        timeout: int = 3600,
        stream=None,
    ) -> None:
        """Block until active scan reaches 100% or timeout. Logs on change + every 60s."""
        start = time.time()
        last_pct = -1
        last_log_time = start
        while time.time() - start < timeout:
            pct = self.active_scan_status(scan_id)
            now = time.time()
            # Log if percentage changed or 60 seconds have passed (heartbeat)
            if pct != last_pct or (now - last_log_time) >= 60:
                elapsed = int(now - start)
                if stream:
                    stream("info", f"[ZAP] Active scan progress: {pct}% ({elapsed}s elapsed)")
                last_pct = pct
                last_log_time = now
            if pct >= 100:
                break
            time.sleep(15)


