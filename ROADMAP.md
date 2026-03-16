# PenTools — Development Roadmap
## Dynamic Web Pentest Engine + Professional Graph UI

> Filosofi inti: **User drives the attack, engine executes it.**  
> platform interaktif di mana pentest expert mengkonfigurasi setiap parameter serangan, engine menjalankan, dan hasilnya divisualisasikan sebagai graph.

---

## Daftar Isi

1. [Visi Produk](#visi-produk)
2. [Model Interaksi User (Dynamic Input)](#model-interaksi-user-dynamic-input)
3. [Attack Module Registry](#attack-module-registry)
4. [Graph UI Architecture](#graph-ui-architecture)
5. [Sprint Roadmap](#sprint-roadmap)
6. [Cara Memulai Development](#cara-memulai-development)

---

## Visi Produk

```
╔══════════════════════════════════════════════════════════════════════╗
║  BUKAN ini:  "Masukkan domain → klik scan → tunggu hasil"           ║
║                                                                      ║
║  INI:        User memilih modul attack                              ║
║              → Sistem menampilkan form parameter dinamis            ║
║              → User isi: endpoint, auth, payload, options           ║
║              → Engine eksekusi + stream live result                 ║
║              → Hasil divisualisasikan sebagai interactive graph     ║
║              → User bisa drill-down, annotate, re-run per node      ║
╚══════════════════════════════════════════════════════════════════════╝

Dua mode penggunaan:
  AUTO MODE   ──► Orchestrated full scan (seperti reNgine)
  MANUAL MODE ──► User pilih modul → isi form → eksekusi manual
```

---

## Model Interaksi User (Dynamic Input)

### Konsep: Attack Module dengan Form Dinamis

Setiap modul serangan punya **schema parameter** yang di-render sebagai form interaktif. User tidak perlu tahu command line — tapi expert bisa set semua opsi lanjutan.

### Contoh — Race Condition Module

```
┌─────────────────────────────────────────────────────────────────┐
│  MODULE: Race Condition Attack                                   │
│  Category: Business Logic / Timing                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  TARGET ENDPOINT                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  https://api.example.com/checkout/apply-coupon             │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  HTTP METHOD          REQUEST PATH                              │
│  [POST ▼]             /checkout/apply-coupon                    │
│                                                                  │
│  AUTHENTICATION TYPE                                            │
│  ◉ Bearer JWT Token                                             │
│  ○ Basic Auth (username/password)                               │
│  ○ Cookie                                                       │
│  ○ API Key Header                                               │
│  ○ None                                                         │
│                                                                  │
│  JWT Token                                                       │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...                  │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  REQUEST BODY (JSON)                                            │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │  {"coupon_code": "DISCOUNT50", "cart_id": "abc123"}        │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                  │
│  CONCURRENCY OPTIONS                    ADVANCED ▼              │
│  Parallel Requests:  [50  ]             ┌───────────────────┐   │
│  Request Delay (ms): [0   ]             │ HTTP/2 mode: [ON] │   │
│  Timeout (ms):       [5000]             │ TLS Bypass: [ ]   │   │
│  Repeat Rounds:      [3   ]             │ Proxy:      [ ]   │   │
│                                         └───────────────────┘   │
│                                                                  │
│  [▶ Run Attack]   [Save Config]   [Export cURL]                  │
└─────────────────────────────────────────────────────────────────┘
```

### Contoh — SQL Injection Module

```
┌─────────────────────────────────────────────────────────────────┐
│  MODULE: SQL Injection                                           │
├─────────────────────────────────────────────────────────────────┤
│  TARGET URL                                                      │
│  https://example.com/products?id=1                              │
│                                                                  │
│  INJECTION POINT                                                 │
│  ◉ GET Parameter    ○ POST Body    ○ Header    ○ Cookie         │
│                                                                  │
│  Parameter Name:  [id]                                          │
│                                                                  │
│  TECHNIQUE                                                       │
│  ☑ Boolean-based blind    ☑ Time-based blind                   │
│  ☑ Error-based            ☐ Stacked queries                     │
│  ☐ UNION-based                                                  │
│                                                                  │
│  DATABASE TYPE                                                   │
│  ◉ Auto-detect   ○ MySQL   ○ PostgreSQL   ○ MSSQL   ○ Oracle   │
│                                                                  │
│  EXTRACTION GOAL                                                 │
│  ☑ Detect & confirm only                                        │
│  ☐ Extract database names (--dbs)                              │
│  ☐ Extract tables (--tables -D dbname)                         │
│  ☐ Extract data (--dump)                                       │
│                                                                  │
│  AUTHENTICATION                                                  │
│  Cookie: [session=abc123; csrf=xyz]                             │
│                                                                  │
│  [▶ Run]   [Load from Burp]   [Export Report]                   │
└─────────────────────────────────────────────────────────────────┘
```

### Contoh — XSS Module

```
┌─────────────────────────────────────────────────────────────────┐
│  MODULE: XSS Scanner                                            │
├─────────────────────────────────────────────────────────────────┤
│  TARGET URL                                                      │
│  https://example.com/search?q=test                             │
│                                                                  │
│  SCAN MODE                                                       │
│  ◉ Reflected XSS     ○ Stored XSS     ○ DOM-based XSS          │
│                                                                  │
│  PARAMETER                                                       │
│  ◉ Auto-discover all params    ○ Specific: [q          ]       │
│                                                                  │
│  PAYLOAD CATEGORY                                               │
│  ☑ Basic       ☑ HTML5      ☑ PolyGlot                         │
│  ☑ SVG-based   ☐ WAF Bypass specific: [CloudFlare ▼]           │
│                                                                  │
│  BLIND XSS (OOB)                                                │
│  ○ Disabled                                                     │
│  ◉ Use callback URL: [https://your-xss-hunter.com/...]         │
│                                                                  │
│  [▶ Run]   [View Payloads]   [Export Findings]                  │
└─────────────────────────────────────────────────────────────────┘
```

### Contoh — SSRF Module

```
┌─────────────────────────────────────────────────────────────────┐
│  MODULE: SSRF (Server-Side Request Forgery)                     │
├─────────────────────────────────────────────────────────────────┤
│  TARGET URL                                                      │
│  https://api.example.com/fetch?url=                            │
│                                                                  │
│  INJECTION PARAMETER     METHOD                                 │
│  [url              ]     [GET ▼]                                │
│                                                                  │
│  PROBE TARGETS                                                  │
│  ☑ Internal: 169.254.169.254 (AWS metadata)                    │
│  ☑ Internal: 192.168.x.x range                                 │
│  ☑ Internal: 127.0.0.1 + common ports                          │
│  ☑ Burp Collaborator / Interactsh (OOB detection)              │
│  ☐ Custom internal range: [10.0.0.0/8              ]           │
│                                                                  │
│  BYPASS TECHNIQUES                                              │
│  ☑ URL encoding    ☑ IP octal    ☑ IPv6    ☑ DNS rebinding     │
│                                                                  │
│  OAST CALLBACK DOMAIN                                           │
│  [xxxxx.oast.fun                                    ]           │
│                                                                  │
│  [▶ Run]   [View Payloads]                                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## Attack Module Registry

### Cara Kerja Module System

```python
# Setiap modul adalah class dengan schema yang di-render jadi form

class RaceConditionModule:
    id = "race_condition"
    name = "Race Condition Attack"
    category = "Business Logic"
    risk_level = "High"
    tags = ["timing", "concurrency", "business-logic"]
    
    # Schema ini di-render otomatis jadi form di frontend
    PARAMETER_SCHEMA = [
        {
            "key": "target_url",
            "label": "Target Endpoint",
            "type": "url",
            "required": True,
            "placeholder": "https://api.example.com/endpoint"
        },
        {
            "key": "method",
            "label": "HTTP Method",
            "type": "select",
            "options": ["GET", "POST", "PUT", "PATCH", "DELETE"],
            "default": "POST"
        },
        {
            "key": "auth_type",
            "label": "Authentication Type",
            "type": "radio",
            "options": ["none", "bearer_jwt", "basic_auth", "cookie", "api_key"],
            "default": "none"
        },
        {
            "key": "auth_token",
            "label": "Bearer JWT Token",
            "type": "textarea",
            "sensitive": True,           # Nilai ini tidak di-log
            "show_if": {"auth_type": "bearer_jwt"}
        },
        {
            "key": "request_body",
            "label": "Request Body (JSON)",
            "type": "json_editor",
            "required": False
        },
        {
            "key": "concurrency",
            "label": "Parallel Requests",
            "type": "number",
            "default": 50,
            "min": 1,
            "max": 500,
            "group": "advanced"
        },
        {
            "key": "rounds",
            "label": "Repeat Rounds",
            "type": "number",
            "default": 3,
            "group": "advanced"
        },
    ]
    
    def execute(self, params: dict, scan_id: str):
        """Engine eksekusi — dipanggil oleh Celery task"""
        ...
```

### Katalog Modul — Master Registry (68 Modules)

> Setiap modul = class Python + PARAMETER_SCHEMA + Celery task.
> Label Phase menunjukkan kapan modul dibangun (lihat Sprint Roadmap).

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 1]  STATIC ANALYSIS & UTILITY TOOLS                 Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [S-01] HTTP Request Analyzer       Parse & dissect HTTP request/response   P1
 [S-02] JWT Decoder & Attacker      Decode, alg:none, weak secret brute,    P1
                                    kid inject, jwks spoofing, exp tamper
 [S-03] Security Header Auditor     Paste response headers → full audit      P1
                                    (CSP, HSTS, X-Frame, Permissions-Policy)
 [S-04] JS Secret Scanner           Paste/URL JS → extract keys, tokens,    P1
                                    API keys, AWS creds, hardcoded passwords
 [S-05] Regex / Payload Lab         Test & craft payloads, WAF bypass regex  P1
 [S-06] Encoding / Decoding Studio  Base64, URL, HTML, Unicode, Hex, Gzip   P1
 [S-07] Hash Analyzer               Detect hash type, crack via wordlist     P2
 [S-08] TLS Certificate Inspector   Parse cert chain, detect weak config     P1
 [S-09] HTTP Diff Comparator        Compare two responses → detect changes   P2

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 2]  RECONNAISSANCE & OSINT                          Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [R-01] Subdomain Discovery         subfinder + amass + dnsx + alterations  P1
 [R-02] Port & Service Scanner      nmap + rustscan, banner grab, NSE        P1
 [R-03] SSL/TLS Deep Audit          testssl.sh + sslyze (ciphers, versions)  P1
 [R-04] WAF & CDN Fingerprint       wafw00f + identywaf + CDN detect         P1
 [R-05] Tech Stack Fingerprint      whatweb + wappalyzer + favicon hash      P1
 [R-06] DNS Full Enumeration        dnsx, zone transfer, DNSSEC check        P1
 [R-07] Certificate Transparency    crt.sh + censys passive cert lookup      P1
 [R-08] Web Crawler & Sitemap       katana — scope, depth, JS rendering      P1
 [R-09] HTTP Probing                httpx — status, title, redirect chain    P1
 [R-10] ASN & IP Intelligence       BGP lookup, WHOIS, ASN neighbors         P2
 [R-11] Email Harvesting            theHarvester — Google, Bing, Hunter.io   P2
 [R-12] Google Dork Automation      Pre-built dorks: admin panels, errors,   P2
                                    open dirs, config leaks, camera feeds
 [R-13] GitHub Recon                trufflehog on repos, search API dorks    P2
 [R-14] Shodan / Censys Query       Host intel via API key user provides     P3
 [R-15] Cloud Asset Discovery       S3, GCS, Azure Blob enumeration          P2
 [R-16] Virtual Host Discovery      ffuf + Host header fuzzing               P2
 [R-17] Screenshot Capture          gowitness — visual reconnaissance        P2

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 3]  INJECTION ATTACKS                               Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [I-01] SQL Injection                sqlmap + custom: technique, DB type,    P1
                                     auth, extraction goal (detect→dump)
 [I-02] NoSQL Injection              MongoDB, CouchDB operator inject         P2
                                     ($where, $ne, $regex payloads)
 [I-03] LDAP Injection               Authentication bypass & data extract     P2
 [I-04] XPath Injection              Blind & error-based XPath payloads       P2
 [I-05] Command Injection            OS command inject, chaining, blind OOB   P2
                                     (ping, curl to callback, time-based)
 [I-06] SSTI — Template Injection    Auto-detect engine (Jinja2, Twig,        P1
                                     Freemarker, ERB, Velocity), RCE path
 [I-07] HTML Injection               Form manipulation, meta refresh, iFrame  P2
 [I-08] Email Header Injection       CC/BCC inject via contact forms          P2
 [I-09] HTTP Parameter Pollution     Duplicate param, override logic          P2
 [I-10] XML/SOAP Injection           Entity inject in SOAP body/headers       P2

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 4]  CROSS-SITE SCRIPTING (XSS)                     Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [X-01] Reflected XSS               dalfox: param discovery + payload fire   P1
 [X-02] Stored XSS                  Submit → retrieve → detect injection      P1
 [X-03] DOM-Based XSS               Analyze JS source: sinks & sources        P2
 [X-04] Blind XSS (OOB)             XSS Hunter / interactsh callback          P1
 [X-05] mXSS — Mutation XSS         Browser parsing edge-case payloads        P2
 [X-06] CSS Injection                Style attribute leak, data exfil via CSS  P2
 [X-07] XSS via File Upload          SVG, HTML, XML file upload → XSS         P2
 [X-08] XSS WAF Bypass Lab           Craft bypass payloads per WAF vendor      P2
 [X-09] DOM Clobbering               Overwrite DOM globals via HTML injection  P3
 [X-10] Prototype Pollution → XSS    Object proto injection path to XSS        P3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 5]  SERVER-SIDE VULNERABILITIES                     Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [SS-01] SSRF                        ssrfmap + nuclei + OAST; bypass modes    P1
                                     (URL encode, IP forms, DNS rebind)
 [SS-02] XXE Injection               Classic, blind (OOB/SSRF), XInclude      P2
                                     error-based; user pastes XML body
 [SS-03] File Upload — RCE           Extension bypass, polyglot, MIME spoof,  P2
                                     .htaccess, double ext, path traversal
 [SS-04] Insecure Deserialization    Java (ysoserial), PHP (phpggc),           P3
                                     Python pickle, .NET (ysoserial.net)
 [SS-05] Path Traversal / LFI        ffuf + dotdot wordlist; PHP wrapper       P1
                                     (php://filter, expect://, data://)
 [SS-06] Remote File Inclusion        RFI via PHP + custom payload server      P3
 [SS-07] Open Redirect               302 chaining, token theft, phishing      P1
 [SS-08] Server-Side Template RCE    Jinja2 {{7*7}} → RCE chain               P1
 [SS-09] Log Poisoning               LFI + writable log → code execution      P3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 6]  ACCESS CONTROL & AUTHORIZATION                  Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [AC-01] IDOR / BOLA                 ID fuzzing (sequential, GUID, hash)      P1
                                     per endpoint; user provides auth tokens
 [AC-02] BFLA — Function-Level       Access admin/privileged actions as       P2
          Auth Bypass                low-priv user (horizontal + vertical)
 [AC-03] Privilege Escalation        Role parameter tampering, admin flags     P2
 [AC-04] Directory Traversal         Path normalization bypass + OS-specific  P1
 [AC-05] Forced Browsing             Access unlinked resources / admin paths  P1
 [AC-06] HTTP Method Override        Add X-HTTP-Method-Override: DELETE etc.  P2
 [AC-07] Missing Function Auth       Skip auth via direct URL access          P2
 [AC-08] JWT Privilege Escalation    Modify role/isAdmin claim, re-sign       P1

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 7]  AUTHENTICATION ATTACKS                          Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [AUTH-01] JWT Full Attack Suite     alg:none, weak secret (wordlist),        P1
                                     kid SQLi/path traversal, jwks spoof,
                                     exp tamper, claim injection
 [AUTH-02] OAuth2 Vulnerability      state param bypass (CSRF), open          P2
                                     redirect_uri, token leakage, PKCE bypass
 [AUTH-03] SAML Attacks              Signature bypass, XML wrap, XXE in       P3
                                     assertion, entity expansion (Billion Laughs)
 [AUTH-04] Password Brute Force      ffuf + credential wordlist, lockout      P1
                                     detection, account enum via timing
 [AUTH-05] Credential Stuffing       Bulk cred test with proxy rotation       P2
 [AUTH-06] MFA/2FA Bypass            Code brute, response manipulation,       P2
                                     backup code abuse, race condition
 [AUTH-07] Session Management Audit  Cookie flags (Secure/HttpOnly/SameSite), P1
                                     fixation, predictable tokens, timeout
 [AUTH-08] Password Reset Flaws      Host header inject, token in Referer,    P1
                                     predictable reset token, reset poisoning
 [AUTH-09] Account Takeover Chain    Combine: reset + CSRF + XSS → full ATO  P2
 [AUTH-10] SSO / OIDC Abuse          nonce skip, sub claim override,          P3
                                     token substitution, silent auth bypass

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 8]  CLIENT-SIDE ATTACKS                             Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [CS-01] CSRF                        Token absence, SameSite bypass,          P2
                                     JSON CSRF, multipart CSRF
 [CS-02] Clickjacking                X-Frame-Options absent, UI Redressing    P1
 [CS-03] CORS Misconfiguration       Null origin, wildcard + creds,           P1
                                     subdomain trust exploitation
 [CS-04] Prototype Pollution         __proto__, constructor.prototype inject  P3
 [CS-05] DOM Clobbering              Overwrite window.x via named anchors     P3
 [CS-06] PostMessage Exploitation    Weak origin check → data leak / XSS      P3
 [CS-07] WebSocket Hijacking         CSWSH: cross-site WS abuse               P3
 [CS-08] Subdomain Takeover          CNAME → dangling cloud resource          P2
 [CS-09] Tabnabbing                  window.opener abuse via target=_blank    P2
 [CS-10] Content Injection           Inject into pages lacking output encode  P2
 [CS-11] CSS Exfiltration            Leak attribute values via CSS selectors  P3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 9]  API SECURITY                                    Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [API-01] REST API Fuzzer            ffuf + OpenAPI / Swagger spec import;    P1
                                     endpoint + method + param fuzzing
 [API-02] API Version Enumeration    /v1/ /v2/ /api/ /internal/ /private/     P1
 [API-03] Mass Assignment            Inject extra JSON fields (isAdmin, role) P1
 [API-04] Rate Limit Bypass          X-Forwarded-For rotate, race, verb swap  P2
 [API-05] API Key Leak Scanner       JS files, error pages, response headers  P1
 [API-06] GraphQL Security Suite     Introspection, batching DoS, injection,  P2
                                     field suggestion abuse, aliases, CSRF
 [API-07] SOAP / WSDL Audit          Parse WSDL → auto-fuzz all operations    P3
 [API-08] WebSocket Fuzzer           Message injection, auth bypass, flood    P3
 [API-09] gRPC Audit                 Reflection enumeration + method fuzz     P3
 [API-10] JSON Web API Injection     JSON path traversal, deeply nested keys  P2
 [API-11] API Object-Level Auth      BOLA per object ID across all endpoints  P2
 [API-12] Swagger/OpenAPI Parser     Auto-map all endpoints from spec file    P2

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 10] BUSINESS LOGIC & RACE CONDITIONS                Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [BL-01] Race Condition Engine       HTTP/2 parallel burst: coupon, balance,  P1
                                     vote, transfer, OTP — user configures
                                     endpoint, auth, body, concurrency
 [BL-02] Price / Value Manipulation  Negative amount, float overflow,         P2
                                     currency decode, discount stacking
 [BL-03] Workflow Step Bypass        Skip payment, skip verification, jump    P2
                                     state without completing prerequisites
 [BL-04] Limit Bypass                Exceed per user/account limits via       P2
                                     param manipulation or race condition
 [BL-05] Coupon / Promo Abuse        Reuse single-use codes, race condition   P1
                                     simultaneous redemption
 [BL-06] File Upload Logic Bypass    Extension whitelist bypass, MIME spoof,  P2
                                     polyglot files, zip slip, path traversal
 [BL-07] 2FA Race Condition          Parallel 2FA code submission             P2
 [BL-08] Account / Balance Exploit   Double spend, negative transfer, rollback P3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 11] HTTP-LEVEL ATTACKS                              Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [H-01] HTTP Request Smuggling       CL.TE / TE.CL / TE.TE — smuggler tool    P3
 [H-02] HTTP Response Splitting      CRLF in response headers                 P2
 [H-03] Cache Poisoning              Unkeyed header → poison cache:           P2
                                     X-Forwarded-Host, X-Forwarded-For
 [H-04] Web Cache Deception          Path confusion: /account/..%2Fstatic/    P3
 [H-05] Host Header Injection        Password reset, middleware bypass,       P1
                                     SSRF via Host header
 [H-06] HTTP Method Fuzzer           Test allowed verbs (TRACE, OPTIONS, PUT) P1
 [H-07] CRLF Injection               crlfuzz: header inject, set-cookie,      P1
                                     log injection, XSS via CRLF
 [H-08] Redirect Chain Analysis      Analyze multi-hop redirects for leakage  P2

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 12] INFORMATION DISCLOSURE                          Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [D-01] Sensitive File Discovery     /.git /.env /.DS_Store /backup /config   P1
                                     /phpinfo.php /server-status wordlists
 [D-02] Error Message Mining         Trigger errors → extract stack trace,    P1
                                     DB names, source paths, versions
 [D-03] Source Code Disclosure       .git exposure (gitdumper), .svn, .hg     P2
 [D-04] Backup & Archive Finder      .bak .old .zip .tar.gz filename fuzz     P2
 [D-05] Debug / Admin Panel Finder   /admin /debug /console /actuator         P1
 [D-06] API Key / Token in Response  Scan all responses for credentials       P2
 [D-07] Cloud Metadata Exposure      169.254.169.254 SSRF pivot to metadata   P2
 [D-08] EXIF / Metadata Extractor    Analyze uploaded images for GPS, author  P2

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 13] CLOUD & INFRASTRUCTURE                          Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [C-01] S3 Bucket Audit              s3scanner: enum, public read/write,      P2
                                     ACL misconfiguration, object listing
 [C-02] AWS Metadata Exploit         SSRF → 169.254.169.254 → IAM creds       P2
 [C-03] Azure Blob / Storage Audit   Public container enum + access check     P3
 [C-04] GCP Metadata Exploit         SSRF → metadata.google.internal          P3
 [C-05] Docker & K8s API Exposure    Port 2375/2376, K8s dashboard : 8001     P3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [KATEGORI 14] VULNERABILITY SCAN (Template-Based)            Phase
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
 [V-01] Nuclei — CVE Templates       User pilih severity + tag filter         P1
 [V-02] Nuclei — Misconfiguration    Exposed panels, default creds, debug     P1
 [V-03] Nuclei — Web Templates       Injection, SSRF, takeover patterns       P1
 [V-04] Nuclei — API Templates       REST + GraphQL + JWT vulnerability       P2
 [V-05] Nuclei — Network Templates   Protocols, services, ports               P2
 [V-06] Nuclei — Custom Template     User upload/write custom YAML template   P2
 [V-07] CMS Scanner                  wpscan (WordPress), droopescan           P2
                                     (Drupal/Joomla), CMSeeK
 [V-08] Dependency Vulnerability     retire.js (frontend), trivy (container)  P2
 [V-09] Default Credentials Tester   Admin panels: predefined cred list       P2
 [V-10] CVE PoC Auto-Matcher         Match detected version → known CVE PoC   P3

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUMMARY
  Phase 1 (MVP)     : 28 modules  — core pentest flow operational
  Phase 2 (Advanced): 28 modules  — full OWASP Top 10 + API + Logic
  Phase 3 (Deep)    : 12 modules  — advanced binary-level & protocol
  ─────────────────────────────────────────────────────────────────
  Total             : 68 modules
```

---

## Graph UI Architecture

### Konsep: Everything is a Graph

```
                    ┌──────────────────────────────────────────────┐
                    │            ATTACK GRAPH VIEW                  │
                    │                                               │
                    │   [example.com] ──────────────────────────┐   │
                    │       │                                   │   │
                    │   [Subdomain Discovery]              [Port Scan]│
                    │   ┌───┴──────────────────┐         ┌──┴──────┐│
                    │   │                      │         │         ││
                    │ [api.example.com]  [admin.example.com]  [443] ││
                    │   │ ⚠️ SSL weak           │ 🔴 XSS  │ nginx   ││
                    │   │                      │         │ CVE-XXXX││
                    │ [XSS Scan]          [Dir Fuzz]     └─────────┘│
                    │   │                      │                     │
                    │ [3 Vulns] ◄── user clicks drill-down           │
                    │                                               │
                    │  Nodes bisa di-klik → buka detail panel       │
                    │  Edges = relationships / attack chain         │
                    │  Color coding: 🔴 Critical 🟠 High 🟡 Med 🟢 Low│
                    └──────────────────────────────────────────────┘
```

### UI Layout

```
╔═══════════════════════════════════════════════════════════════════════════╗
║  PenTools                         [Workspace: HackerOne Target] [+New]   ║
╠══════════╦═══════════════════════════════════════╦════════════════════════╣
║          ║                                       ║                        ║
║ SIDEBAR  ║           MAIN CANVAS (Graph)         ║   DETAIL PANEL        ║
║          ║                                       ║                        ║
║ Modules: ║   [Target: api.example.com]           ║  Node: api.example.com ║
║ ▸ Recon  ║           │                           ║  ────────────────────  ║
║ ▸ Web    ║     ┌─────┴──────┐                    ║  IP: 93.184.216.34    ║
║ ▸ Auth   ║     │            │                    ║  Status: 200 OK       ║
║ ▸ API    ║  [XSS]      [SQLi]                    ║  Server: nginx/1.24   ║
║ ▸ Logic  ║   ⚠️3         🔴1                      ║  Tech: React, JWT     ║
║ ▸ Vuln   ║                                       ║                        ║
║          ║                                       ║  [▶ Run Module]       ║
╠══════════║                                       ║  [+ Add Note]         ║
║          ║                                       ║  [Export Node]        ║
║ Active:  ║                                       ║                        ║
║ Scan #12 ║                [+Add Module]          ║  ────────────────────  ║
║ 78% ████║                                       ║  Sub-findings:        ║
║         ║                                       ║  • /admin → 403 bypass ║
║ History  ║                                       ║  • XSS in ?q= param   ║
║ Scan #11 ║                                       ║  • JWT alg:none       ║
║ Scan #10 ║                                       ║                        ║
╚══════════╩═══════════════════════════════════════╩════════════════════════╝
```

### Graph Engine

Menggunakan **Cytoscape.js** atau **React Flow** di frontend:
- Nodes = target, subdomain, endpoint, finding
- Edges = scan relationship, attack chain, dependency
- Filter by severity, module type, status
- Export graph sebagai PNG atau JSON (shareable)

```javascript
// Contoh node data structure
{
  "id": "node-api-example-com",
  "type": "subdomain",
  "data": {
    "label": "api.example.com",
    "ip": "93.184.216.34",
    "http_status": 200,
    "risk": "high",
    "findings_count": 3,
    "modules_run": ["xss", "sqli", "header_audit"]
  },
  "position": { "x": 300, "y": 200 }
}

// Edge = hasil module/serangan
{
  "id": "edge-xss-finding-1",
  "source": "node-api-example-com",
  "target": "node-finding-xss-1",
  "label": "XSS Found",
  "data": {
    "severity": "high",
    "module": "xss_scanner"
  }
}
```

---

## Sprint Roadmap

```
OVERVIEW — 68 Modules across 4 Phases
─────────────────────────────────────────────────────────────────
Phase 1 (Sprint 0-3)  : Foundation + Engine + 28 core modules
Phase 2 (Sprint 4-6)  : 28 advanced modules + Graph UI
Phase 3 (Sprint 7-9)  : 12 deep/protocol modules + Reports
Phase 4 (Sprint 10)   : Production hardening + Polish

Total estimated duration: ~14-16 weeks
─────────────────────────────────────────────────────────────────
```

---

### Sprint 0 — Foundation (1 minggu)
*Tujuan: Docker stack jalan, Django scaffolding siap, bisa login*

```
INFRASTRUCTURE
[ ] docker-compose.yml — services: db, redis, web, celery, celery_beat,
                         flower, nginx, tools (shared binary volume)
[ ] web/Dockerfile — Python 3.12, multi-stage build
[ ] tools/Dockerfile — Alpine + semua pentest binary P1
[ ] nginx/nginx.conf — reverse proxy, static files, WS upgrade
[ ] scripts/entrypoint.sh — migrate + collectstatic + gunicorn
[ ] scripts/celery-entrypoint.sh — worker startup per queue
[ ] .env.example + .env (gitignored)
[ ] Makefile — shortcuts: up, down, shell, worker, logs, migrate, test

DJANGO SCAFFOLDING
[ ] pentools/ project init (Django 5.1)
[ ] settings/base.py, development.py, production.py
[ ] apps/ structure: accounts, targets, scans, modules, results,
                     recon, injection, xss, access_control, auth_attacks,
                     server_side, client_side, api_audit, business_logic,
                     http_attacks, disclosure, cloud, vuln_scan, reports
[ ] pentools/celery.py — app + queue definitions
[ ] pentools/asgi.py — channels routing

AUTH & USER
[ ] User model + login, logout, register views
[ ] API key generation (per user)
[ ] Login required middleware
[ ] Base templates: base.html, sidebar, topbar (Tailwind CSS dark theme)
[ ] Health check endpoint: GET /health/ → 200 OK
[ ] Flower monitor: accessible /flower/ (auth protected)
```

**Deliverable**: `make up` → buka browser → bisa login → sidebar tampil

---

### Sprint 1 — Module Engine Core (2 minggu)
*Tujuan: Infrastruktur module system bekerja end-to-end*

```
MODULE REGISTRY ENGINE
[ ] BaseModule class — id, name, category, tags, PARAMETER_SCHEMA, execute()
[ ] Module auto-discovery — scan semua apps/*/modules.py saat startup
[ ] ModuleRegistry singleton — getall(), getby_id(), getby_category()
[ ] PARAMETER_SCHEMA field types: url, text, textarea, number, select,
    radio, checkbox, json_editor, file_upload, wordlist_select
[ ] show_if logic resolver — Alpine.js di frontend

DYNAMIC FORM RENDERING
[ ] Schema → HTMX-rendered form (server-side template rendering)
[ ] Sensitive field masking — type="password", tidak di-log & tidak di-store plain
[ ] Auth context widget — Bearer JWT / Basic / Cookie / API Key / None
    dengan conditional field show/hide
[ ] Wordlist picker — built-in catalog + upload custom
[ ] Form validation — per field type (URL format, JSON valid, required)
[ ] Save Config button — simpan params as JSON ke ScanJobTemplate
[ ] Export cURL button — generate cURL command dari params yang diisi

SCAN JOB SYSTEM
[ ] ScanJob model — UUID, module_id, params (JSONField, encrypted),
    status (pending/running/paused/done/failed/cancelled),
    progress 0-100, created_by (FK), target (optional FK)
[ ] execute_module Celery task — load module class → call execute(params)
[ ] ToolRunner class — subprocess.Popen list args (NO shell=True),
    timeout enforcement, output size cap, stream per-line to WS
[ ] ScanLog model + WebSocket push per log line
[ ] Job cancel / retry endpoint

REAL-TIME UI
[ ] Django Channels WebSocket consumer — /ws/scan/{job_id}/
[ ] Auth check in consumer connect() — user must own the scan
[ ] Live log panel — auto-scroll, ANSI color strip, level badge
    (INFO=blue, WARN=yellow, ERROR=red, SUCCESS=green)
[ ] Progress bar update via WS messages
[ ] Job status indicator (running spinner, done checkmark, error X)

PROOF OF CONCEPT MODULES (2 modules to validate engine)
[ ] [R-02] Port Scanner (nmap) — basic form: target host, port range, timing
[ ] [X-01] Reflected XSS (dalfox) — target URL, auth type, param config

Deliverable: User pilih XSS modul → isi form → run → live log stream →
             hasil tersimpan di DB → bisa lihat di result page
```

---

### Sprint 2 — Phase 1 Static & Recon Modules 
*28 modules total — dimulai dari yang paling banyak dipakai*

```
STATIC ANALYSIS (no network needed)
[ ] [S-01] HTTP Request Analyzer — paste raw HTTP req/resp → parse headers,
           cookies, params, security issues
[ ] [S-02] JWT Decoder & Attacker — decode all parts, detect alg:none,
           brute weak secret (rockyou subset), kid SQLi/path traversal
[ ] [S-03] Security Header Auditor — grade CSP, HSTS, X-Frame-Options,
           Permissions-Policy, Referrer-Policy, COEP, CORP
[ ] [S-04] JS Secret Scanner — fetch URL or paste JS → grep for API keys,
           AWS, GCP, Stripe, tokens (trufflehog patterns)
[ ] [S-05] Regex / Payload Lab — test regex against custom strings,
           preview WAF bypass payload variations
[ ] [S-06] Encoding / Decoding Studio — Base64, URL, HTML entity,
           Unicode, Hex, Gzip, JWT decode (client-side only)
[ ] [S-08] TLS Certificate Inspector — parse cert, check expiry, CN/SAN,
           issuer, key size, weak cipher warning

RECONNAISSANCE
[ ] [R-01] Subdomain Discovery — subfinder, dnsx resolve, alterations flag
[ ] [R-03] SSL/TLS Deep Audit — testssl.sh, output structured to DB
[ ] [R-04] WAF & CDN Fingerprint — wafw00f, CDN detect via headers/CNAME
[ ] [R-05] Tech Stack Fingerprint — whatweb + favicon hash lookup
[ ] [R-06] DNS Full Enumeration — dnsx, AXFR attempt, record types
[ ] [R-07] Certificate Transparency — crt.sh API query (passive, no noise)
[ ] [R-08] Web Crawler & Sitemap — katana, scope regex, JS-rendering mode
[ ] [R-09] HTTP Probing — httpx: status, title, redirect chain, tech headers

INJECTION — PHASE 1 SUBSET
[ ] [I-01] SQL Injection — sqlmap wrapper: technique checkboxes,
           DB type radio, auth config, extraction goal (detect only default)
[ ] [I-06] SSTI — template engine auto-detect, RCE payload chain

ACCESS CONTROL — PHASE 1
[ ] [AC-01] IDOR / BOLA — endpoint + ID range fuzzer + auth context
[ ] [AC-04] Directory Traversal — ffuf + traversal wordlist
[ ] [AC-05] Forced Browsing — ffuf + admin path wordlist
[ ] [AC-08] JWT Privilege Escalation — modify claim + re-sign options

AUTH ATTACKS — PHASE 1
[ ] [AUTH-01] JWT Full Attack Suite — all 6 attack vectors in one module
[ ] [AUTH-04] Password Brute Force — ffuf + credential wordlist,
              lockout detection, account enum via timing diff
[ ] [AUTH-07] Session Management Audit — cookie flag grader
[ ] [AUTH-08] Password Reset Flaws — Host header inject test

HTTP LEVEL — PHASE 1
[ ] [H-05] Host Header Injection — detected via redirect/email/SSRF
[ ] [H-06] HTTP Method Fuzzer — allowed verb enumeration
[ ] [H-07] CRLF Injection — crlfuzz wrapper

DISCLOSURE — PHASE 1
[ ] [D-01] Sensitive File Discovery — ffuf + sensitive files wordlist
[ ] [D-02] Error Message Mining — trigger 404/500 variants, parse output
[ ] [D-05] Debug / Admin Panel Finder — ffuf + admin paths wordlist

VULNERABILITY SCAN
[ ] [V-01] Nuclei — CVE scan — severity + tag filter + template count
[ ] [V-02] Nuclei — Misconfiguration scan
[ ] [V-03] Nuclei — Web Templates scan

Result model: generic Finding(scan_job, title, severity, url, evidence,
              description, remediation, cvss_score, cve_id, raw_output)
```

---

### Sprint 3 — Graph UI 
*Tujuan: Semua findings divisualisasikan sebagai interactive graph*

```
GRAPH ENGINE
[ ] Cytoscape.js integration — bundled via npm/CDN in base template
[ ] GraphDataBuilder — Django view yang return JSON dari DB findings
    untuk dirender Cytoscape
[ ] Node types dengan distinct styling:
    - target (hexagon, dark)
    - subdomain (circle, blue)
    - port (diamond, gray)
    - endpoint (rectangle, teal)
    - finding (circle, color by severity)
    - module_run (small dot, purple)
[ ] Edge types: discovered_by, has_port, found_at, ran_on
[ ] Layout options: breadthfirst (default), concentric, dagre (hierarchy)

REAL-TIME GRAPH UPDATES
[ ] WebSocket graph_update event — saat scan selesai, push new nodes/edges
[ ] Node merge logic — deduplicate jika subdomain/port sudah ada

INTERACTION
[ ] Click node → slide-in right panel (detail + raw finding)
[ ] Right-click node → context menu:
    "Run Module on This" → buka module form pre-filled dengan node data
    "Mark as Confirmed"
    "Add Note"
    "Copy Value"
[ ] Double-click group node → expand children
[ ] Drag & drop node repositioning (layout lock/unlock)
[ ] Multi-select → bulk action (export, mark all)

FILTER & SEARCH
[ ] Filter sidebar: by node type, severity, module, status
[ ] Search bar: highlight matching nodes
[ ] Minimap (Cytoscape.js navigator extension)
[ ] Zoom controls + fit-to-screen

EXPORT
[ ] Export graph as PNG (high-res)
[ ] Export graph as JSON (shareable, importable)
[ ] Export findings as CSV
[ ] Print-friendly view

WORKSPACE / PROJECT SYSTEM
[ ] Project model (group multiple scans per target/engagement)
[ ] Project graph = merged graph dari semua scan dalam project
[ ] Project switcher di topbar
```

---

### Sprint 4 — Phase 2 Attack Modules Batch A
*XSS full suite + Injection expansion + Server-Side*

```
XSS FULL SUITE
[x] [X-02] Stored XSS — submit → fetch stored → detect
[x] [X-03] DOM-Based XSS — URL fragment, document.write, innerHTML sinks
[x] [X-04] Blind XSS (OOB) — interactsh callback integration
[x] [X-05] mXSS — mutation-based payload list
[x] [X-06] CSS Injection — data exfil via CSS attribute selectors
[x] [X-07] XSS via File Upload — SVG/HTML/XML upload vector
[x] [X-08] XSS WAF Bypass Lab — vendor-specific bypass payload library

INJECTION EXPANSION
[x] [I-02] NoSQL Injection — MongoDB/CouchDB operator payloads
[x] [I-03] LDAP Injection — auth bypass & data extract payloads
[x] [I-04] XPath Injection — blind + error-based
[x] [I-05] Command Injection — OS command + OOB (ping/curl to interactsh)
[x] [I-07] HTML Injection — form manipulation, meta refresh, pixel track
[x] [I-08] Email Header Injection — CC/BCC inject, newline in SMTP
[x] [I-09] HTTP Parameter Pollution — duplicate param logic check
[x] [I-10] XML/SOAP Injection — entity injection in SOAP body

SERVER-SIDE FULL
[x] [SS-01] SSRF — full config (probe targets, bypass techniques, OAST)
[x] [SS-02] XXE Injection — classic + blind OOB + XInclude + error-based
[x] [SS-03] File Upload RCE — extension bypass, MIME spoof, .htaccess,
            double ext, path traversal, image polyglot
[x] [SS-05] Path Traversal / LFI — PHP wrappers (filter, expect, data)
[x] [SS-07] Open Redirect — 302 chain for token theft
[x] [SS-08] SSTI → RCE — Jinja2, Twig, Freemarker payload chains

ACCESS CONTROL EXPANSION
[x] [AC-02] BFLA — access privileged functions as low-priv
[x] [AC-03] Privilege Escalation — role param tamper
[x] [AC-06] HTTP Method Override — X-HTTP-Method-Override header
[x] [AC-07] Missing Function Auth — direct URL access audit
```

---

### Sprint 5 — Phase 2 Attack Modules Batch B
*Auth expansion + API Security + Business Logic + Client-Side*

```
AUTH ATTACKS EXPANSION
[ ] [AUTH-02] OAuth2 Vulnerability — state bypass, open redirect_uri,
              PKCE bypass, token leakage in Referer
[ ] [AUTH-05] Credential Stuffing — bulk cred test with proxy rotation
[ ] [AUTH-06] MFA/2FA Bypass — OTP brute, response manipulation,
              backup code abuse, race condition
[ ] [AUTH-09] Account Takeover Chain — multi-step ATO module
[ ] Multi-session support — user saves multiple auth contexts per project
    → quick-switch between "user role", "admin role", "unauthenticated"

API SECURITY
[ ] [API-01] REST API Fuzzer — OpenAPI/Swagger spec import + auto-fuzz
[ ] [API-02] API Version Enumeration — /v1/ /v2/ /internal/ bruteforce
[ ] [API-03] Mass Assignment — extra JSON field inject per endpoint
[ ] [API-04] Rate Limit Bypass — X-Forwarded-For rotate, verb swap, race
[ ] [API-05] API Key Leak Scanner — scan JS files + error responses
[ ] [API-06] GraphQL Security Suite — introspection, batching DoS,
             field suggestion abuse, CSRF, alias overload
[ ] [API-10] JSON Web API Injection — path traversal in nested JSON keys
[ ] [API-11] API Object-Level Auth — BOLA per object across endpoints
[ ] [API-12] Swagger/OpenAPI Parser — import spec → auto-map all endpoints

BUSINESS LOGIC
[ ] [BL-01] Race Condition Engine — HTTP/2 parallel burst (turbo intruder style)
[ ] [BL-02] Price / Value Manipulation
[ ] [BL-03] Workflow Step Bypass
[ ] [BL-04] Limit Bypass
[ ] [BL-05] Coupon / Promo Abuse
[ ] [BL-06] File Upload Logic Bypass — zip slip, extension bypass
[ ] [BL-07] 2FA Race Condition

CLIENT-SIDE
[ ] [CS-01] CSRF — token absence, SameSite bypass, JSON CSRF
[ ] [CS-02] Clickjacking — iframe embed test + remediation check
[ ] [CS-03] CORS Misconfiguration — null origin, wildcard + creds
[ ] [CS-08] Subdomain Takeover — CNAME dangling check (subjack wrapper)
[ ] [CS-09] Tabnabbing — window.opener audit

HTTP LEVEL
[ ] [H-02] HTTP Response Splitting — CRLF in header values
[ ] [H-03] Cache Poisoning — unkeyed headers probe
[ ] [H-08] Redirect Chain Analysis — multi-hop redirect tracker

DISCLOSURE
[ ] [D-03] Source Code Disclosure — git dumper, .svn, .hg
[ ] [D-04] Backup & Archive Finder — .bak .old .zip .tar.gz fuzz
[ ] [D-06] API Key / Token in Response — scan all response bodies
[ ] [D-07] Cloud Metadata Exposure — SSRF to metadata endpoints
[ ] [D-08] EXIF / Metadata Extractor — exiftool on uploaded images

VULNERABILITY SCAN
[ ] [V-04] Nuclei — API Templates
[ ] [V-05] Nuclei — Network Templates
[ ] [V-06] Nuclei — Custom Template (user uploads YAML)
[ ] [V-07] CMS Scanner — wpscan, droopescan, CMSeeK
[ ] [V-08] Dependency Vulnerability — retire.js, trivy
[ ] [V-09] Default Credentials Tester
```

---

### Sprint 6 — Reporting & Export  COMPLETED

```
FINDING MANAGEMENT
[x] Finding model — title, severity (critical/high/medium/low/info),
    cvss_score, cvss_vector, cve_id, cwe_id, description, evidence
    (screenshot/raw), remediation, status (open/confirmed/FP/fixed)
[x] Manual finding entry — user tambah temuan manual dari graph atau form
[x] Finding status workflow — open → confirmed → mitigated → closed
[x] Duplicate detection — SHA-256 hash evidence untuk detect duplikat
[x] CVSS 3.1 calculator widget — interaktif, compute score dari vector

REPORTS
[x] HTML report generator — executive summary + technical detail
    per finding, severity chart, risk matrix
[x] JSON export — machine-readable, tool-importable format
[x] PDF export — WeasyPrint: professional layout, logo, cover page
[x] Markdown export — for GitLab/GitHub issue creation
[x] Report builder — user pilih findings yang di-include, drag reorder
[x] Risk matrix heatmap — severity × likelihood visual
[ ] Attack graph embed — static PNG dalam report (deferred to Sprint 8)

NOTIFICATION
[x] Telegram bot — finding alert on critical/high
[x] Slack webhook — scan complete + summary
[x] Email SMTP — configurable per project
```

---

### Sprint 7 — Recon Expansion + OSINT (1 minggu)  COMPLETED

```
RECONNAISSANCE EXPANSION
[x] [R-10] ASN & IP Intelligence — BGP.he.net lookup, WHOIS, neighbors
[x] [R-11] Email Harvesting — theHarvester, Hunter.io API (user provides key)
[x] [R-12] Google Dork Automation — pre-built dork library per category
            (admin panels, error messages, config files, cameras)
[x] [R-13] GitHub Recon — trufflehog on org repos + GitHub search API dorks
[x] [R-15] Cloud Asset Discovery — s3scanner, GCS enum, Azure blob
[x] [R-16] Virtual Host Discovery — ffuf + Host header wordlist
[x] [R-17] Screenshot Capture — gowitness for visual recon batch

STATIC TOOLS REMAINING
[x] [S-07] Hash Analyzer — hashid detect + hashcat mode + wordlist crack
[x] [S-09] HTTP Diff Comparator — A/B response diff view

CLOUD MODULES
[x] [C-01] S3 Bucket Audit — s3scanner: ACL check, object listing, takeover
[x] [C-02] AWS Metadata Exploit — SSRF to 169.254.169.254, IAM cred extract
```

---

### Sprint 8 — Phase 3 Deep / Protocol Modules (2 minggu)  COMPLETED

```
ADVANCED AUTH
[x] [AUTH-03] SAML Attacks — signature bypass, XML wrap, XXE in assertion
[x] [AUTH-10] SSO / OIDC Abuse — nonce skip, sub claim override

ADVANCED CLIENT-SIDE
[x] [CS-04] Prototype Pollution — __proto__ / constructor.prototype inject
[x] [CS-05] DOM Clobbering — named anchor / form element overwrite window.x
[x] [CS-06] PostMessage Exploitation — weak origin check → data leak
[x] [CS-07] WebSocket Hijacking — CSWSH: cross-site WebSocket abuse
[x] [CS-11] CSS Exfiltration — attribute value leak via CSS attribute selectors

ADVANCED SERVER-SIDE
[x] [SS-04] Insecure Deserialization — Java (ysoserial), PHP (phpggc),
            Python pickle, .NET (ysoserial.net) — gadget chain selector
[x] [SS-06] Remote File Inclusion — RFI + custom payload server helper
[x] [SS-09] Log Poisoning — LFI + writable log → code execution chain

ADVANCED HTTP
[x] [H-01] HTTP Request Smuggling — smuggler.py wrapper (CL.TE / TE.CL / TE.TE)
[x] [H-04] Web Cache Deception — path confusion: /account/..%2Fstatic/

ADVANCED API
[x] [API-07] SOAP / WSDL Audit — parse WSDL → auto-fuzz all operations
[x] [API-08] WebSocket Fuzzer — message injection, auth bypass, flood test
[x] [API-09] gRPC Audit — reflection enumeration + method fuzzing

ADVANCED CLOUD
[x] [C-03] Azure Blob / Storage Audit
[x] [C-04] GCP Metadata Exploit — SSRF to metadata.google.internal
[x] [C-05] Docker & K8s API Exposure — port 2375/2376, K8s dashboard

ADVANCED BUSINESS LOGIC
[x] [BL-08] Account / Balance Exploit — double spend, negative transfer

VULNERABILITY SCAN
[x] [V-10] CVE PoC Auto-Matcher — match detected version → known CVE PoC

RECON FINAL
[x] [R-14] Shodan / Censys Query — user provides API key, host intel
```

Docker verification: 21/21 modules loaded 

---

### Sprint 9 — Polish, RBAC & Production Hardening (1.5 minggu)

```
PLATFORM HARDENING
[ ] RBAC — roles: viewer (read-only), operator (run modules), admin (all)
[ ] Audit log — semua aksi user (create/run/delete/export) di-log
[ ] Rate limiting — API endpoints: 60 req/min per user, 10 req/min unauth
[ ] Input sanitization audit — review semua form inputs, URL validation
[ ] Sensitive data — encrypt params JSONField (cryptography.fernet)
[ ] Docker production config — resource limits, healthchecks, restart policy
[ ] Celery task timeout enforcement — global + per-module override
[ ] Log rotation — prevent disk fill from verbose tool output

UX POLISH
[ ] Dark theme — full Tailwind dark mode, sidebar icon tooltips
[ ] Keyboard shortcuts — j/k navigate graph, / focus search, r run module
[ ] Module search & filter — category tree, search by name/tag, favorites
[ ] Scan history — timeline per project, diff dua scan results
[ ] Scan scheduling — Celery Beat: cron periodic rescan
[ ] Workspace onboarding — empty state guide for new users
[ ] Mobile-responsive — minimal but functional on tablet

DOCUMENTATION
[ ] In-app help per module — collapsible "How to use this module" panel
[ ] User guide (Markdown rendered in /docs/)
[ ] API reference — DRF auto-generated + swagger-ui
[ ] Self-pentest — run PenTools against itself before release

CI/CD
[ ] GitHub Actions / GitLab CI — lint, test, docker build on push
[ ] pytest coverage — unit tests for module engine, ToolRunner, form schema
[ ] Docker image publish to registry
```

---

## Cara Memulai Development

### Step 1 — Buat Struktur Direktori (Hari 1)

```bash
cd /home/h3llo/Documents/Project/Vulnx/PenTools

# Infrastructure directories
mkdir -p nginx ssl scripts tools

# Django project
mkdir -p web/pentools/settings
mkdir -p web/apps/{accounts,targets,scans,modules,results}
mkdir -p web/apps/{recon,injection,xss,server_side,access_control}
mkdir -p web/apps/{auth_attacks,client_side,api_audit,business_logic}
mkdir -p web/apps/{http_attacks,disclosure,cloud,vuln_scan,reports,notifications}
mkdir -p web/templates/{base,dashboard,modules,scans,graph,reports}
mkdir -p web/static/{css,js,img}
mkdir -p web/wordlists/{common,api,lfi,sqli,xss,fuzz}

# Tools container
mkdir -p tools
```

### Step 2 — Tech Stack Final

```
Backend:
  Django 5.1 + Python 3.12
  Django REST Framework 3.15
  Django Channels 4.x (WebSocket/ASGI)
  Celery 5.x + Redis 7 (broker + result backend)
  PostgreSQL 16 (JSONField untuk params + findings)
  cryptography (Fernet) — enkripsi sensitive params di DB

Frontend:
  Django Templates (server-rendered HTML)
  HTMX 2.x — dynamic partial page updates, form submit async
  Alpine.js 3.x — show_if logic, UI state (no heavy SPA)
  Tailwind CSS 3.x — dark theme utility-first styling
  Cytoscape.js 3.x — graph canvas (Sprint 3)

Container:
  Docker + Docker Compose v2
  Gunicorn + Uvicorn workers (ASGI mode untuk Channels)
  Nginx — reverse proxy, SSL termination, WS upstream

Pentest Tools (tools container, Alpine Linux):
  Go tools: subfinder, dnsx, httpx, nuclei, ffuf, katana, dalfox,
            crlfuzz, trufflehog, rustscan, amass, gobuster, naabu
  System: nmap, masscan, sqlmap, wafw00f, whatweb, testssl.sh,
          gowitness, theHarvester, exiftool, wpscan
```

### Step 3 — File Build Order (Sprint 0)

```
Urutan pembuatan file (dari paling foundational):

1.  .env.example                  → template semua secrets
2.  docker-compose.yml            → seluruh service stack
3.  tools/Dockerfile              → pentest binary container
4.  web/Dockerfile                → Django container
5.  nginx/nginx.conf              → reverse proxy + WS
6.  scripts/entrypoint.sh         → Django startup script
7.  scripts/celery-entrypoint.sh  → Celery worker startup
8.  Makefile                      → developer shortcuts
9.  web/requirements.txt          → Python dependencies
10. web/pentools/settings/base.py → Django config
11. web/pentools/celery.py        → Celery config + queues
12. web/pentools/asgi.py          → ASGI + Channels routing
13. web/apps/accounts/            → User model + auth views
14. web/templates/base.html       → sidebar + topbar skeleton
15. web/manage.py                 → Django entry point
```

---

## Key Design Decisions

### Mengapa "Dynamic Form Schema"?

```
Problem:  Setiap modul punya parameter berbeda.
          Race condition perlu concurrency, JWT assault perlu secret wordlist,
          SQLi perlu technique flag, SSRF perlu OAST callback.
          
Solution: Setiap modul punya PARAMETER_SCHEMA (list of dicts).
          Frontend merender schema ini jadi form dinamis dengan HTMX.
          Logika show_if dihandle Alpine.js.
          
Benefit:  Tambah modul baru = hanya tulis class + schema.
          Tidak perlu buat template form baru.
          Form bisa di-serialize jadi JSON → disimpan as ScanJob config.
          Bisa di-replay: load config → jalankan ulang scan.
```

### Mengapa Graph, bukan Tabel?

```
Problem:  Hasil pentest punya relasi kompleks.
          api.example.com → port 443 → CVE-XXXX + XSS
          Tabel tidak bisa menggambarkan attack chain.
          
Solution: Graph di mana setiap entitas adalah node,
          dan hubungannya adalah edge.
          
Benefit:  - User bisa lihat attack surface secara visual
          - Klik node → jalankan modul selanjutnya (chaining)
          - Mudah identify "high value target" (node dengan banyak edge)
          - Export graph = shareable attack map untuk report
```

### Mengapa Tidak Auto-Run Semua?

```
Filosofi: Platform ini untuk EXPERT, bukan script kiddie.
          User yang memutuskan kapan dan modul apa yang dijalankan.
          Auto mode tetap ada (untuk full reconnaissance),
          tapi attack modules SELALU butuh user confirmation + parameter.
          
Practical: SQLi, RCE potential, brute force — tidak boleh jalan tanpa
           user explicitly set parameter dan klik "Run".
           Ini juga mencegah accidental damage ke target.
```

---

*Roadmap ini akan di-update setelah setiap sprint selesai.*
