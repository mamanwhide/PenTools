# PenTools — Web-Based Penetration Testing Platform

A professional, self-hosted penetration testing platform built with Django 5.1, Celery, Django Channels, and PostgreSQL. Provides 132 security testing modules covering every major OWASP category, with a real-time scan console, structured finding management, and automated report generation.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Default Credentials](#default-credentials)
- [Project Structure](#project-structure)
- [Module System](#module-system)
- [All Modules (132 total)](#all-modules)
- [Sprint History](#sprint-history)
- [User Workflow](#user-workflow)
- [REST API Reference](#rest-api-reference)
- [Environment Variables](#environment-variables)
- [Running Tests](#running-tests)
- [Production Deployment](#production-deployment)

---

## Overview

PenTools is a platform for running structured penetration tests against web applications, APIs, and infrastructure. The test engine is fully asynchronous — every scan is dispatched as a Celery task and streamed back to the browser via WebSocket in real time.

Key capabilities:

- 132 attack modules across 14 categories (auth, injection, XSS, recon, API, cloud, etc.)
- Real-time scan output streamed over WebSocket to a live console
- Per-finding status tracking with CVSS 3.1 scoring and duplicate detection
- Drag-and-drop report builder that exports to HTML/PDF
- Telegram and Slack notifications on scan completion and critical findings
- Interactive attack graph per project (Cytoscape.js)
- REST API and API key authentication for CI/CD integration
- Celery Flower dashboard for worker monitoring

---

## Architecture

```
Browser                     Django (ASGI / Uvicorn)
  |                              |
  |-- HTTP (HTMX, forms) ------> |-- pentools/urls.py
  |-- WebSocket (live logs) ---> |-- apps/scans/consumers.py
                                 |
                                 |-- PostgreSQL  (main DB)
                                 |-- Redis       (broker + cache + channel layer)
                                 |-- Celery      (async task execution)
                                 |-- Nginx       (TLS termination + static files)
```

Services defined in `docker-compose.yml`:

| Service       | Image / Build           | Purpose                                 |
|---------------|-------------------------|-----------------------------------------|
| `web`         | `./web/Dockerfile`      | Django ASGI server (Uvicorn + Gunicorn) |
| `db`          | `postgres:16-alpine`    | Primary PostgreSQL database             |
| `redis`       | `redis:7-alpine`        | Celery broker, cache, channel layer     |
| `celery`      | `./web/Dockerfile`      | Scan task worker                        |
| `celery_beat` | `./web/Dockerfile`      | Periodic task scheduler                 |
| `flower`      | `./web/Dockerfile`      | Celery monitor (port 5555)              |
| `tools`       | `./tools/Dockerfile`    | Installs pentest binaries into a volume |
| `nginx`       | `nginx:1.26-alpine`     | Reverse proxy (ports 80 / 443)          |

---

## Prerequisites

- Docker 24+
- Docker Compose v2 (`docker compose` command, not `docker-compose`)
- A domain or IP address pointing to the host (for HTTPS in production)

---

## Quick Start

### 1. Clone and configure

```bash
git clone https://github.com/vulnx/pentools.git
cd pentools

cp .env.example .env
# Edit .env and set at minimum:
#   DJANGO_SECRET_KEY — generate with: python -c "import secrets; print(secrets.token_urlsafe(50))"
#   POSTGRES_PASSWORD
#   FIELD_ENCRYPTION_KEY — generate with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

### 2. Build and start

```bash
docker compose up --build -d
```

The first run builds all images and installs pentest tool binaries. This takes 5–15 minutes on first launch.

### 3. Run database migrations and create a superuser

```bash
docker compose exec web python manage.py migrate
docker compose exec web python manage.py createsuperuser
```

### 4. Open the app

Navigate to `http://localhost` (or your configured hostname). Log in with the superuser credentials you just created.

---

## Default Credentials

No default credentials are shipped. You create the first superuser with `createsuperuser` as shown above.

The admin site is available at `/admin-panel/`. Only users with `is_staff=True` can access it.

---

## Project Structure

```
PenTools/
  docker-compose.yml          # All services
  .env.example                # Environment variable template
  nginx/
    nginx.conf                # Nginx reverse proxy configuration
  tools/
    Dockerfile                # Builds pentest tool binaries
  web/                        # Django application root
    manage.py
    Dockerfile
    requirements.txt
    pentools/                 # Django project package
      settings/
        base.py               # Shared settings
        development.py        # Dev overrides (DEBUG=True, console email)
        production.py         # Production overrides (HTTPS, HSTS)
      urls.py                 # Root URL configuration + dashboard view
      celery.py               # Celery app initialisation
      asgi.py                 # ASGI entry point (HTTP + WebSocket)
    apps/
      accounts/               # Custom User model, login/logout, API key auth
      targets/                # Projects and Targets
      modules/                # Module registry, BaseModule, FieldSchema
      scans/                  # ScanJob, ScanLog, Celery task executor, WebSocket consumer
      results/                # Finding, FindingStatusHistory, CVSS calculator
      reports/                # Report, report builder, PDF/HTML export
      notifications/          # NotificationChannel, Telegram / Slack dispatch
      graph/                  # Attack graph (Cytoscape.js + WebSocket)
      recon/                  # R-* modules
      injection/              # I-* modules
      xss_modules/            # X-* modules
      server_side/            # SS-* modules
      access_control/         # AC-* modules
      auth_attacks/           # AUTH-* modules
      client_side/            # CS-* modules
      api_audit/              # API-* modules
      business_logic/         # BL-* modules
      http_attacks/           # H-* modules
      disclosure/             # D-* modules
      cloud/                  # C-* modules
      vuln_scan/              # V-* modules (Nuclei-based)
      static_tools/           # S-* modules (offline analysis tools)
    templates/                # Django templates
      base/                   # base.html (layout, sidebar, nav)
      dashboard/
      scans/
      modules/
      targets/
      results/                # findings, CVSS calculator
      reports/
      notifications/
    tests/
      test_integration_flow.py  # Full integration test suite (14 test classes)
```

---

## Module System

### BaseModule

All attack modules inherit from `apps.modules.engine.BaseModule`. The minimum required implementation is:

```python
from apps.modules.engine import BaseModule, FieldSchema

class MyModule(BaseModule):
    id         = "CATEGORY-NN"       # Unique module ID in registry
    name       = "Human-Readable Name"
    category   = "injection"         # Maps to sidebar category filter
    risk_level = "high"              # critical | high | medium | low | info
    description = "What this module does."

    PARAMETER_SCHEMA = [
        FieldSchema(
            key="target_url",
            label="Target URL",
            field_type="url",       # text | url | password | number | select |
                                    # multiselect | checkbox | file_upload | textarea
            required=True,
            help_text="The URL to test.",
        ),
    ]

    def run(self, params: dict, logger) -> None:
        url = params["target_url"]
        with self.new_session() as session:
            resp = session.get(url, timeout=30)
            if "<script>" in resp.text:
                self.add_finding(
                    title="Reflected XSS",
                    severity="high",
                    url=url,
                    evidence=resp.text[:500],
                    remediation="Encode output context-appropriately.",
                )
```

The `run()` method receives validated `params` (a dict mapping field keys to values) and a `logger` object with `.info()`, `.warn()`, `.error()` methods. Output is streamed via WebSocket and persisted as `ScanLog` rows.

### Module Auto-Discovery

The `ModuleRegistry` singleton discovers all modules at startup by importing every `apps/*/modules.py` file. No registration call is needed — defining a class that inherits `BaseModule` with a valid `id` is sufficient.

### FieldSchema

| Property      | Default  | Description                                          |
|---------------|----------|------------------------------------------------------|
| `key`         | required | URL-safe parameter name                              |
| `label`       | required | Human-readable field label                           |
| `field_type`  | `"text"` | Input type (see list above)                          |
| `required`    | `False`  | Whether the field must have a non-empty value        |
| `default`     | `None`   | Default value pre-populated in the form              |
| `placeholder` | `""`     | Placeholder text shown in empty inputs               |
| `help_text`   | `""`     | Small description shown below the field              |
| `choices`     | `[]`     | List of `{"value": ..., "label": ...}` for selects   |
| `advanced`    | `False`  | Show only when the user expands the advanced section |

### Module Categories

| Category        | Prefix  | Description                                |
|-----------------|---------|--------------------------------------------|
| Authentication  | AUTH    | JWT, OAuth2, SAML, session, brute force    |
| Injection       | I       | SQL, NoSQL, LDAP, command, SSTI            |
| XSS             | X       | Reflected, Stored, DOM, Blind, WAF bypass  |
| Server-Side     | SS      | SSRF, XXE, deserialization, LFI, RFI       |
| Access Control  | AC      | IDOR, BFLA, privilege escalation           |
| Recon           | R       | Port scan, subdomain enum, fingerprinting  |
| Client-Side     | CS      | CSRF, CORS, clickjacking, prototype pollut |
| API / Web Svcs  | API     | REST fuzzing, GraphQL, SOAP, gRPC          |
| Business Logic  | BL      | Race conditions, price manipulation        |
| HTTP Attacks    | H       | Request smuggling, cache poisoning, CRLF   |
| Disclosure      | D       | Sensitive files, error leakage, EXIF       |
| Cloud           | C       | S3, Azure, GCP, AWS metadata, K8s          |
| Vulnerability   | V       | Nuclei CVE/misconfiguration scans          |
| Static Tools    | S       | Offline analyzers (JWT decoder, headers)   |

---

## All Modules

### Authentication (10 modules)

| ID      | Name                         |
|---------|------------------------------|
| AUTH-01 | JWT Full Attack Suite        |
| AUTH-02 | OAuth2 Vulnerability         |
| AUTH-03 | SAML Attacks                 |
| AUTH-04 | Password Brute Force         |
| AUTH-05 | Credential Stuffing          |
| AUTH-06 | MFA/2FA Bypass               |
| AUTH-07 | Session Management Audit     |
| AUTH-08 | Password Reset Flaws         |
| AUTH-09 | Account Takeover Chain       |
| AUTH-10 | SSO / OIDC Abuse             |

### Injection (10 modules)

| ID   | Name                         |
|------|------------------------------|
| I-01 | SQL Injection                |
| I-02 | NoSQL Injection              |
| I-03 | LDAP Injection               |
| I-04 | XPath Injection              |
| I-05 | Command Injection            |
| I-06 | SSTI — Template Injection    |
| I-07 | HTML Injection               |
| I-08 | Email Header Injection       |
| I-09 | HTTP Parameter Pollution     |
| I-10 | XML/SOAP Injection           |

### XSS (8 modules)

| ID   | Name                         |
|------|------------------------------|
| X-01 | Reflected XSS Scanner        |
| X-02 | Stored XSS                   |
| X-03 | DOM XSS Finder               |
| X-04 | Blind XSS (OOB)              |
| X-05 | mXSS — Mutation XSS          |
| X-06 | CSS Injection                |
| X-07 | XSS via File Upload          |
| X-08 | XSS WAF Bypass Lab           |

### Server-Side (9 modules)

| ID    | Name                          |
|-------|-------------------------------|
| SS-01 | SSRF                          |
| SS-02 | XXE Injection                 |
| SS-03 | File Upload — RCE             |
| SS-04 | Insecure Deserialization      |
| SS-05 | Path Traversal / LFI          |
| SS-06 | Remote File Inclusion (RFI)   |
| SS-07 | Open Redirect                 |
| SS-08 | SSTI to RCE                   |
| SS-09 | Log Poisoning                 |

### Access Control (8 modules)

| ID    | Name                               |
|-------|------------------------------------|
| AC-01 | IDOR / BOLA                        |
| AC-02 | BFLA — Function-Level Auth Bypass  |
| AC-03 | Privilege Escalation               |
| AC-04 | Directory Traversal                |
| AC-05 | Forced Browsing                    |
| AC-06 | HTTP Method Override               |
| AC-07 | Missing Function-Level Auth        |
| AC-08 | JWT Privilege Escalation           |

### Recon (17 modules)

| ID    | Name                             |
|-------|----------------------------------|
| R-01  | Port Scanner                     |
| R-02  | Subdomain Enumeration            |
| R-03  | SSL/TLS Deep Audit               |
| R-04  | WAF & CDN Fingerprint            |
| R-05  | Tech Stack Fingerprint           |
| R-06  | DNS Full Enumeration             |
| R-07  | Certificate Transparency         |
| R-08  | Web Crawler & Sitemap            |
| R-09  | HTTP Probing                     |
| R-10  | ASN & IP Intelligence            |
| R-11  | Email Harvesting                 |
| R-12  | Google Dork Automation           |
| R-13  | GitHub Recon                     |
| R-14  | Shodan / Censys Intelligence     |
| R-15  | Cloud Asset Discovery            |
| R-16  | Virtual Host Discovery           |
| R-17  | Screenshot Capture               |

### Client-Side (10 modules)

| ID    | Name                              |
|-------|-----------------------------------|
| CS-01 | CSRF — Cross-Site Request Forgery |
| CS-02 | Clickjacking                      |
| CS-03 | CORS Misconfiguration             |
| CS-04 | Prototype Pollution               |
| CS-05 | DOM Clobbering                    |
| CS-06 | PostMessage Exploitation          |
| CS-07 | WebSocket Hijacking (CSWSH)       |
| CS-08 | Subdomain Takeover                |
| CS-09 | Tabnabbing — window.opener Audit  |
| CS-11 | CSS Exfiltration                  |

### API / Web Services (12 modules)

| ID     | Name                                    |
|--------|-----------------------------------------|
| API-01 | REST API Fuzzer                         |
| API-02 | API Version Enumeration                 |
| API-03 | Mass Assignment                         |
| API-04 | Rate Limit Bypass                       |
| API-05 | API Key Leak Scanner                    |
| API-06 | GraphQL Security Suite                  |
| API-07 | SOAP / WSDL Audit                       |
| API-08 | WebSocket Fuzzer                        |
| API-09 | gRPC Security Audit                     |
| API-10 | JSON Web API Injection                  |
| API-11 | API Object-Level Authorization (BOLA)   |
| API-12 | Swagger/OpenAPI Parser                  |

### Business Logic (8 modules)

| ID    | Name                          |
|-------|-------------------------------|
| BL-01 | Race Condition Engine         |
| BL-02 | Price / Value Manipulation    |
| BL-03 | Workflow Step Bypass          |
| BL-04 | Limit Bypass                  |
| BL-05 | Coupon / Promo Abuse          |
| BL-06 | File Upload Logic Bypass      |
| BL-07 | 2FA Race Condition            |
| BL-08 | Account & Balance Exploit     |

### HTTP Attacks (8 modules)

| ID   | Name                          |
|------|-------------------------------|
| H-01 | HTTP Request Smuggling        |
| H-02 | HTTP Response Splitting       |
| H-03 | Cache Poisoning               |
| H-04 | Web Cache Deception           |
| H-05 | Host Header Injection         |
| H-06 | HTTP Method Fuzzer            |
| H-07 | CRLF Injection                |
| H-08 | Redirect Chain Analysis       |

### Information Disclosure (8 modules)

| ID   | Name                          |
|------|-------------------------------|
| D-01 | Sensitive File Discovery      |
| D-02 | Error Message Mining          |
| D-03 | Source Code Disclosure        |
| D-04 | Backup & Archive Finder       |
| D-05 | Debug / Admin Panel Finder    |
| D-06 | API Key / Token in Response   |
| D-07 | Cloud Metadata Exposure       |
| D-08 | EXIF / Metadata Extractor     |

### Cloud (5 modules)

| ID   | Name                              |
|------|-----------------------------------|
| C-01 | S3 Bucket Audit                   |
| C-02 | AWS Metadata Exploit (SSRF)       |
| C-03 | Azure Blob Storage Audit          |
| C-04 | GCP Metadata Service Exploit      |
| C-05 | Docker & Kubernetes API Exposure  |

### Vulnerability Scanning — Nuclei (10 modules)

| ID   | Name                                |
|------|-------------------------------------|
| V-01 | Nuclei — CVE Scan                   |
| V-02 | Nuclei — Misconfiguration Scan      |
| V-03 | Nuclei — Web Templates Scan         |
| V-04 | Nuclei — API Security Scan          |
| V-05 | Nuclei — Network & Service Scan     |
| V-06 | Nuclei — Custom YAML Template       |
| V-07 | CMS Vulnerability Scanner           |
| V-08 | Dependency Vulnerability Scanner    |
| V-09 | Default Credentials Tester          |
| V-10 | CVE PoC Auto-Matcher                |

### Static / Offline Tools (9 modules)

| ID   | Name                          |
|------|-------------------------------|
| S-01 | HTTP Request Analyzer         |
| S-02 | JWT Decoder & Attacker        |
| S-03 | Security Header Auditor       |
| S-04 | JS Secret Scanner             |
| S-05 | Regex / Payload Lab           |
| S-06 | Encoding / Decoding Studio    |
| S-07 | Hash Analyzer                 |
| S-08 | TLS Certificate Inspector     |
| S-09 | HTTP Diff Comparator          |

---

## Sprint History

| Sprint | Focus                                      | Modules delivered                                              |
|--------|--------------------------------------------|----------------------------------------------------------------|
| 1      | Platform foundation                        | Django project, Celery, WebSocket, User model, module registry |
| 2      | Authentication attacks                     | AUTH-01 to AUTH-09                                             |
| 3      | Injection and XSS                          | I-01..I-10, X-01..X-08                                        |
| 4      | Server-side and access control             | SS-01..SS-09, AC-01..AC-08                                     |
| 5      | Recon and client-side                      | R-01..R-17, CS-01..CS-11                                       |
| 6      | Findings, Reports, Notifications           | Full Finding model, CVSS 3.1, Report builder, Telegram/Slack   |
| 7      | API, Business Logic, HTTP, Disclosure      | API-01..API-12, BL-01..BL-08, H-01..H-08, D-01..D-08          |
| 8      | Cloud, Vuln Scan, Static Tools, completion | C-01..C-05, V-01..V-10, S-01..S-09, AUTH-10, CS-04..CS-11,    |
|        |                                            | SS-04/SS-06/SS-09, H-01/H-04, API-07..API-09, BL-08, R-14     |

Total modules: 132

---

## User Workflow

### 1. Create a Project

Navigate to **Targets** in the sidebar and click **New Project**. Enter a project name and optional description. Every scan, finding, and report is scoped to a project.

### 2. Add Targets

Inside the project, click **Add Target**. Provide a name, type (URL, domain, IP, or CIDR), and value. Targets are optionally attached to scans for correlation.

### 3. Browse Modules

Navigate to **Modules** in the sidebar. Filter by category (e.g., "auth", "injection") or search by module name or ID. Each module card shows the risk level, a brief description, and a **Launch** button.

### 4. Configure and Launch a Scan

Clicking **Launch** on a module card opens the scan configuration form. Fill in required parameters (such as the target URL), expand **Advanced Options** for optional parameters, and optionally save the configuration as a named template for reuse. Click **Launch Scan**.

### 5. Monitor Scan Progress

The scan detail page shows a live console that receives log lines via WebSocket as the scan runs. A progress bar and status badge update in real time. The cancel button is available while the scan is `pending` or `running`.

### 6. Review Findings

After the scan completes, findings appear in the **Findings** tab on the scan detail page and in the global **Findings** list (sidebar). Each finding shows severity, CVSS score, URL, evidence, and remediation. Update the finding status (open, confirmed, false positive, fixed) to manage triage workflow.

### 7. Generate a Report

Navigate to **Reports** and click **New Report**. Select the project, add an executive summary, and choose the minimum severity to include. Use the drag-and-drop builder to arrange sections. Export as HTML or PDF.

### 8. Set Up Notifications

Navigate to **Notifications** and create a channel (Telegram or Slack). Link it to a project and choose which events trigger alerts (scan complete, critical finding). Notifications are dispatched asynchronously via Celery.

---

## REST API Reference

### Authentication

The API supports two authentication methods:

**Session authentication** (browser): standard Django session cookie set after logging in through the web UI.

**API key authentication** (programmatic): include the header `X-API-Key: <your-key>` on every request. Regenerate your key from the profile page.

All API endpoints require authentication. Unauthenticated requests receive `302 Redirect` to the login page (session) or `403 Forbidden` (API key).

### Scan Endpoints

| Method | Path                                      | Description                                      |
|--------|-------------------------------------------|--------------------------------------------------|
| GET    | `/api/v1/scans/<job-id>/status/`          | Job status, progress, finding counts             |
| GET    | `/api/v1/scans/<job-id>/logs/`            | Log lines (supports `?since=<log-id>` cursor)    |
| GET    | `/api/v1/scans/<job-id>/findings/`        | Findings attached to this scan job               |
| GET    | `/api/v1/scans/configs/<module-id>/`      | List saved parameter configs for a module        |
| POST   | `/api/v1/scans/configs/<module-id>/save/` | Save or overwrite a named config                 |
| POST   | `/api/v1/scans/configs/delete/<id>/`      | Delete a saved config                            |

**Job status response example:**

```json
{
  "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
  "status": "done",
  "progress": 100,
  "finding_count": 3,
  "critical_count": 1,
  "high_count": 2,
  "duration": 47
}
```

**Log lines response example:**

```json
{
  "logs": [
    { "id": 1001, "level": "info",  "message": "Starting JWT attack suite against https://example.com", "ts": "2025-01-01T12:00:00Z" },
    { "id": 1002, "level": "warn",  "message": "alg:none accepted — token forgeable", "ts": "2025-01-01T12:00:01Z" }
  ]
}
```

### Module Endpoints

| Method | Path              | Description                                         |
|--------|-------------------|-----------------------------------------------------|
| GET    | `/api/v1/modules/` | List all registered modules with schema             |

**Module list response example:**

```json
{
  "modules": [
    {
      "id": "AUTH-01",
      "name": "JWT Full Attack Suite",
      "category": "auth",
      "risk_level": "high",
      "description": "Tests JWT for alg:none, weak secret, key confusion, and claim forgery.",
      "schema": [...]
    }
  ]
}
```

### WebSocket Channels

| Path                            | Protocol | Description                                 |
|---------------------------------|----------|---------------------------------------------|
| `ws://<host>/ws/scan/<job-id>/` | WS       | Live scan log stream for a specific job     |
| `ws://<host>/ws/graph/<proj-id>/` | WS     | Real-time attack graph updates              |

---

## Environment Variables

Copy `.env.example` to `.env` and set each value before running:

| Variable                  | Required | Default                    | Description                                      |
|---------------------------|----------|----------------------------|--------------------------------------------------|
| `DJANGO_SECRET_KEY`       | Yes      | —                          | Django secret key (50+ chars random string)      |
| `DJANGO_DEBUG`            | No       | `False`                    | Set `True` for local development only            |
| `DJANGO_ALLOWED_HOSTS`    | No       | `localhost,127.0.0.1`      | Comma-separated allowed hostnames                |
| `CSRF_TRUSTED_ORIGINS`    | No       | auto-derived               | Comma-separated trusted CSRF origins             |
| `POSTGRES_DB`             | Yes      | `pentools`                 | PostgreSQL database name                         |
| `POSTGRES_USER`           | Yes      | `pentools`                 | PostgreSQL username                              |
| `POSTGRES_PASSWORD`       | Yes      | —                          | PostgreSQL password                              |
| `POSTGRES_HOST`           | No       | `db`                       | PostgreSQL host (Docker service name)            |
| `POSTGRES_PORT`           | No       | `5432`                     | PostgreSQL port                                  |
| `REDIS_URL`               | No       | `redis://redis:6379/0`     | Redis connection URL                             |
| `CELERY_BROKER_URL`       | No       | `redis://redis:6379/0`     | Celery broker URL                                |
| `CELERY_RESULT_BACKEND`   | No       | `redis://redis:6379/1`     | Celery result backend URL                        |
| `CELERY_MAX_CONCURRENCY`  | No       | `20`                       | Maximum Celery worker concurrency                |
| `FIELD_ENCRYPTION_KEY`    | Yes      | —                          | Fernet key for encrypting sensitive scan params  |
| `FLOWER_USER`             | No       | `admin`                    | Basic auth username for Flower                   |
| `FLOWER_PASSWORD`         | Yes      | —                          | Basic auth password for Flower                   |
| `TELEGRAM_BOT_TOKEN`      | No       | —                          | Telegram bot token for notifications             |
| `SLACK_WEBHOOK_URL`       | No       | —                          | Slack incoming webhook URL for notifications     |
| `INTERACTSH_SERVER`       | No       | —                          | Self-hosted OOB/OAST callback server hostname    |
| `INTERACTSH_TOKEN`        | No       | —                          | Auth token for the interactsh server             |
| `SHODAN_API_KEY`          | No       | —                          | Shodan API key (used by R-14)                    |
| `HUNTER_IO_API_KEY`       | No       | —                          | Hunter.io API key (used by R-11)                 |
| `GITHUB_TOKEN`            | No       | —                          | GitHub token (used by R-13)                      |

### Generating required key values

```bash
# DJANGO_SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(50))"

# FIELD_ENCRYPTION_KEY
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

---

## Running Tests

### Inside the container (recommended)

```bash
# Run the full integration test suite
docker compose exec web python manage.py test tests.test_integration_flow --verbosity=2

# Run all tests
docker compose exec web python manage.py test --verbosity=2

# Run Django system check
docker compose exec web python manage.py check
```

### Test classes

| Class                          | Coverage area                                                    |
|--------------------------------|------------------------------------------------------------------|
| `HealthCheckTestCase`          | `/health/` endpoint returns `{"status": "ok"}`                  |
| `AuthenticationTestCase`       | Login, logout, profile, API key regeneration, redirect rules     |
| `ProjectTargetTestCase`        | Project and target CRUD, uniqueness constraints                  |
| `ModuleRegistryTestCase`       | Module list/detail/filter, required field validation, field types|
| `ScanLifecycleTestCase`        | Scan create/detail/list/cancel/retry, access control             |
| `ScanAPITestCase`              | Status, logs, findings APIs, saved config CRUD                   |
| `FindingsTestCase`             | Finding CRUD, status update, CVSS calc, duplicate dedup          |
| `ReportsTestCase`              | Report create/detail/builder                                     |
| `NotificationsTestCase`        | Notification channel creation                                    |
| `DashboardTestCase`            | Stats accuracy, isolation (own data only), root redirect         |
| `ContextProcessorTestCase`     | `user_all_projects` includes owned and member projects           |
| `ScanParamValidationTestCase`  | Schema serialisation, form handling without required fields      |
| `ScanTaskUnitTestCase`         | Celery task marks job failed for non-existent module             |
| `FindingModelTestCase`         | evidence_hash computation, severity badge, project inheritance   |

---

## Production Deployment

### TLS / HTTPS

Place fullchain and private key PEM files at `./ssl/fullchain.pem` and `./ssl/privkey.pem`. The provided `nginx/nginx.conf` serves them on port 443. Alternatively, use Certbot with the Nginx container.

### Environment

Set the following in `.env` for production:

```
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=your.domain.com
CSRF_TRUSTED_ORIGINS=https://your.domain.com
```

### Collect static files

```bash
docker compose exec web python manage.py collectstatic --noinput
```

The `./staticfiles/` directory is bind-mounted into the Nginx container and served directly.

### Database backups

```bash
# Dump
docker compose exec db pg_dump -U pentools pentools > backup_$(date +%Y%m%d).sql

# Restore
cat backup_YYYYMMDD.sql | docker compose exec -T db psql -U pentools -d pentools
```

### Scaling Celery workers

To increase scan parallelism, start more Celery worker replicas:

```bash
docker compose up --scale celery=4 -d
```

Each event in `CELERY_TASK_ROUTES` maps a task namespace to a named queue. Run specialised workers for specific queues to keep scan types isolated:

```bash
celery -A pentools worker -Q recon_queue,api_queue --concurrency=8
```

### Flower monitor

Flower is available at `http://localhost:5555` (bound to `127.0.0.1` only). Expose it behind Nginx with authentication if remote access is needed.
