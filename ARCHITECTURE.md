# PenTools — Advanced Web Pentest Platform
## Arsitektur Sistem & Blueprint Teknis

> Platform pentest berbasis Django + Docker untuk melakukan server-side dan client-side vulnerability assessment secara mendalam, terinspirasi dari arsitektur reNgine.

---

## Daftar Isi

1. [Gambaran Umum](#gambaran-umum)
2. [Stack Teknologi](#stack-teknologi)
3. [Arsitektur Container (Docker)](#arsitektur-container-docker)
4. [Struktur Direktori Proyek](#struktur-direktori-proyek)
5. [Modul Fitur](#modul-fitur)
6. [Alur Kerja Scan](#alur-kerja-scan)
7. [Database Schema](#database-schema)
8. [Task Queue & Worker](#task-queue--worker)
9. [Real-time WebSocket](#real-time-websocket)
10. [Tools yang Diintegrasikan](#tools-yang-diintegrasikan)
11. [API Design](#api-design)
12. [Security Model](#security-model)
13. [Roadmap Implementasi](#roadmap-implementasi)

---

## Gambaran Umum

```
╔═══════════════════════════════════════════════════════════════════╗
║                     P E N T O O L S                               ║
║           Advanced Server-Side & Client-Side Pentest              ║
║                  Web Application Platform                         ║
╚═══════════════════════════════════════════════════════════════════╝

Target yang bisa di-scan:
  Server-Side  ──►  Domains, IPs, Subdomains, APIs, Services
  Client-Side  ──►  Web Apps, JavaScript, SPA, Headers, Forms
```

### Filosofi Desain

| Prinsip           | Implementasi                                   |
|-------------------|------------------------------------------------|
| **Async First**   | Semua scan dijalankan via Celery (non-blocking) |
| **Modular**       | Setiap kategori scan = Django App tersendiri   |
| **Scalable**      | Worker bisa di-scale horizontal via Docker     |
| **Observable**    | Real-time log stream via WebSocket             |
| **Reproducible**  | Semua tool di-containerize, versi terkunci     |

---

## Stack Teknologi

```
┌─────────────────────────────────────────────────────────────┐
│  FRONTEND                                                    │
│  ├── Django Templates (Jinja2/DTL)                          │
│  ├── HTMX  ──► Real-time partial updates tanpa full SPA     │
│  ├── Alpine.js ──► Interaktivitas ringan di frontend        │
│  └── Tailwind CSS ──► Styling komponen                      │
├─────────────────────────────────────────────────────────────┤
│  BACKEND                                                     │
│  ├── Django 5.x ──► Core framework                          │
│  ├── Django REST Framework ──► API layer                    │
│  ├── Django Channels ──► WebSocket / async I/O              │
│  ├── Celery 5.x ──► Distributed task queue                  │
│  └── Celery Beat ──► Scheduled/periodic scans               │
├─────────────────────────────────────────────────────────────┤
│  DATA LAYER                                                  │
│  ├── PostgreSQL 16 ──► Primary database                     │
│  ├── Redis 7 ──► Broker + Result backend + Cache            │
│  └── MinIO (opsional) ──► Object storage untuk laporan/screenshot │
├─────────────────────────────────────────────────────────────┤
│  INFRASTRUCTURE                                              │
│  ├── Docker + Docker Compose ──► Container orchestration    │
│  ├── Nginx ──► Reverse proxy + SSL termination              │
│  └── Gunicorn + Uvicorn ──► WSGI/ASGI server                │
└─────────────────────────────────────────────────────────────┘
```

---

## Arsitektur Container (Docker)

### Diagram Keseluruhan

```
                        ┌─────────────────────┐
                        │    USER BROWSER      │
                        │   (Port 80 / 443)    │
                        └──────────┬──────────┘
                                   │ HTTPS
                                   ▼
                   ┌───────────────────────────────┐
                   │        NGINX CONTAINER         │
                   │  (Reverse Proxy + SSL)          │
                   │  Port 80 → 443 redirect         │
                   │  /static/ → serve direct        │
                   │  /media/  → serve direct        │
                   │  /ws/     → proxy to Django Channels │
                   └───────────────┬───────────────┘
                                   │
                    ┌──────────────▼──────────────┐
                    │    DJANGO / GUNICORN (ASGI)  │
                    │         web container         │
                    │  Port 8000                    │
                    │                               │
                    │  ┌─────────┐  ┌───────────┐  │
                    │  │  Views  │  │    API    │  │
                    │  │  HTMX   │  │   (DRF)   │  │
                    │  └─────────┘  └───────────┘  │
                    │  ┌──────────────────────────┐ │
                    │  │  Django Channels (ASGI)  │ │
                    │  │  WebSocket consumers     │ │
                    │  └──────────────────────────┘ │
                    └──────┬─────────────────┬──────┘
                           │                 │
           ┌───────────────▼──┐         ┌────▼────────────┐
           │   PostgreSQL 16   │         │    Redis 7       │
           │   db container    │         │  redis container │
           │   Port 5432       │         │  Port 6379       │
           └───────────────────┘         └────┬────────────┘
                                              │ Task Broker
                           ┌──────────────────┼──────────────────┐
                           │                  │                  │
                    ┌──────▼──────┐   ┌──────▼──────┐   ┌──────▼──────┐
                    │  celery     │   │ celery_beat  │   │  flower     │
                    │  worker     │   │ (Scheduler)  │   │ (Monitor)   │
                    │             │   │              │   │ Port 5555   │
                    │ Queues:     │   │ Cron Jobs:   │   │             │
                    │ scan_queue  │   │ - Auto re-scan│  │ Web UI      │
                    │ recon_queue │   │ - Report gen │   │ Task Stats  │
                    │ exploit_q   │   │ - Cleanup    │   │             │
                    │ report_queue│   │              │   └─────────────┘
                    └─────────────┘   └──────────────┘
                    
           ┌─────────────────────────────────────────────────────┐
           │              PENTEST TOOLS CONTAINER                  │
           │  tools container — Alpine Linux + semua binary tool  │
           │                                                       │
           │  Server-Side Tools:   Client-Side Tools:             │
           │  ├── nmap             ├── nuclei (web templates)     │
           │  ├── masscan          ├── dalfox (XSS)               │
           │  ├── subfinder        ├── nikto                      │
           │  ├── httpx            ├── whatweb                    │
           │  ├── nuclei           ├── testssl.sh                  │
           │  ├── ffuf             ├── trufflehog (secrets)        │
           │  ├── feroxbuster      ├── retire.js (JS vuln)        │
           │  ├── gobuster         ├── wapiti (web scanner)        │
           │  ├── amass            └── zap-api (OWASP ZAP)        │
           │  ├── wafw00f                                          │
           │  ├── sqlmap                                           │
           │  └── rustscan                                         │
           └─────────────────────────────────────────────────────┘
```

### docker-compose.yml Services

```yaml
version: "3.9"

services:
  db:          # PostgreSQL 16
  redis:       # Redis 7 (broker + cache)
  web:         # Django + Gunicorn/Uvicorn (ASGI)
  celery:      # Celery worker (semua queues)
  celery_beat: # Celery periodic scheduler
  flower:      # Celery monitoring dashboard
  nginx:       # Reverse proxy
  tools:       # Shared volume dengan semua pentest binary
  
  # Opsional / Phase 2:
  minio:       # S3-compatible object storage
  prometheus:  # Metrics collection
  grafana:     # Metrics visualization
```

---

## Struktur Direktori Proyek

```
PenTools/
│
├── docker-compose.yml
├── docker-compose.prod.yml
├── .env.example
├── Makefile                    ◄── Shortcut commands (make up, make scan, dll)
│
├── nginx/
│   ├── nginx.conf
│   └── ssl/                    ◄── Self-signed atau cert Let's Encrypt
│
├── scripts/
│   ├── entrypoint.sh           ◄── Django startup (migrate + collectstatic)
│   ├── celery-entrypoint.sh    ◄── Celery startup
│   └── install-tools.sh        ◄── Install semua pentest binary
│
├── tools/
│   └── Dockerfile              ◄── Container khusus pentest tools
│
└── web/                        ◄── Django Project Root
    │
    ├── manage.py
    ├── requirements.txt
    ├── Dockerfile
    │
    ├── pentools/               ◄── Django Project Config
    │   ├── settings/
    │   │   ├── base.py
    │   │   ├── development.py
    │   │   └── production.py
    │   ├── urls.py
    │   ├── asgi.py             ◄── ASGI (WebSocket support)
    │   ├── wsgi.py
    │   └── celery.py           ◄── Celery app config
    │
    ├── apps/
    │   │
    │   ├── accounts/           ◄── Auth, Users, API keys
    │   │   ├── models.py
    │   │   ├── views.py
    │   │   └── serializers.py
    │   │
    │   ├── targets/            ◄── Manajemen target (domain, IP, URL)
    │   │   ├── models.py
    │   │   ├── views.py
    │   │   └── forms.py
    │   │
    │   ├── scans/              ◄── Orchestration: buat & monitor scan jobs
    │   │   ├── models.py       ◄── ScanJob, ScanResult, ScanLog
    │   │   ├── tasks.py        ◄── Celery tasks (scan entry points)
    │   │   ├── views.py
    │   │   ├── consumers.py    ◄── WebSocket consumers (live logs)
    │   │   └── routing.py
    │   │
    │   ├── recon/              ◄── Server-Side: Reconnaissance
    │   │   ├── tasks/
    │   │   │   ├── subdomain.py    ◄── subfinder, amass, dnsx
    │   │   │   ├── port_scan.py    ◄── nmap, masscan, rustscan
    │   │   │   └── http_probe.py   ◄── httpx, whatweb
    │   │   └── models.py
    │   │
    │   ├── server_audit/       ◄── Server-Side: Deep Vulnerability
    │   │   ├── tasks/
    │   │   │   ├── vuln_scan.py    ◄── nuclei (network templates)
    │   │   │   ├── ssl_audit.py    ◄── testssl.sh, sslyze
    │   │   │   ├── service_enum.py ◄── banner grab, version detect
    │   │   │   └── waf_detect.py   ◄── wafw00f, identywaf
    │   │   └── models.py
    │   │
    │   ├── web_audit/          ◄── Client-Side: Web App Audit
    │   │   ├── tasks/
    │   │   │   ├── crawler.py      ◄── katana, gospider
    │   │   │   ├── dir_fuzz.py     ◄── ffuf, feroxbuster, gobuster
    │   │   │   ├── xss_scan.py     ◄── dalfox, XSStrike
    │   │   │   ├── sqli_scan.py    ◄── sqlmap
    │   │   │   ├── lfi_scan.py     ◄── ffuf + LFI wordlist
    │   │   │   ├── ssrf_scan.py    ◄── ssrfmap, nuclei
    │   │   │   ├── header_audit.py ◄── security headers check
    │   │   │   ├── js_scan.py      ◄── trufflehog, retire.js, linkfinder
    │   │   │   ├── cms_scan.py     ◄── wpscan, droopescan
    │   │   │   └── api_scan.py     ◄── nuclei (API templates)
    │   │   └── models.py
    │   │
    │   ├── osint/              ◄── OSINT & Passive Recon
    │   │   ├── tasks/
    │   │   │   ├── email_harvest.py  ◄── theHarvester
    │   │   │   ├── dns_enum.py       ◄── dnsx, dnsrecon
    │   │   │   ├── whois_lookup.py
    │   │   │   ├── google_dorks.py
    │   │   │   └── cert_enum.py      ◄── crt.sh, certsh
    │   │   └── models.py
    │   │
    │   ├── reports/            ◄── Report generation & export
    │   │   ├── generators/
    │   │   │   ├── html_report.py
    │   │   │   ├── pdf_report.py   ◄── WeasyPrint / xhtml2pdf
    │   │   │   └── json_export.py
    │   │   └── templates/
    │   │       └── report/
    │   │
    │   └── notifications/      ◄── Notifikasi (Slack, Telegram, Email)
    │       └── tasks.py
    │
    ├── templates/              ◄── Django HTML templates
    │   ├── base.html
    │   ├── dashboard/
    │   ├── scans/
    │   ├── targets/
    │   └── reports/
    │
    └── static/
        ├── css/
        ├── js/
        └── img/
```

---

## Modul Fitur

### Feature Matrix — Phase 1 (MVP)

```
╔═══════════════╦══════════════════════════════════════════════════════╗
║   KATEGORI    ║   FITUR                                              ║
╠═══════════════╬══════════════════════════════════════════════════════╣
║               ║  ✦ Subdomain enumeration (subfinder + amass + dnsx) ║
║  SERVER-SIDE  ║  ✦ Port scanning (nmap + masscan + rustscan)        ║
║  RECON        ║  ✦ HTTP probing (httpx)                             ║
║               ║  ✦ Technology fingerprinting (whatweb, wappalyzer)  ║
╠═══════════════╬══════════════════════════════════════════════════════╣
║               ║  ✦ Vulnerability scan (nuclei — network templates)  ║
║  SERVER-SIDE  ║  ✦ SSL/TLS audit (testssl.sh)                       ║
║  AUDIT        ║  ✦ WAF detection (wafw00f)                          ║
║               ║  ✦ Service banner grabbing                          ║
╠═══════════════╬══════════════════════════════════════════════════════╣
║               ║  ✦ Web crawler (katana)                             ║
║  CLIENT-SIDE  ║  ✦ Directory fuzzing (ffuf)                         ║
║  AUDIT        ║  ✦ XSS scan (dalfox)                                ║
║               ║  ✦ Security header audit                            ║
║               ║  ✦ JS secrets scan (trufflehog, linkfinder)         ║
╠═══════════════╬══════════════════════════════════════════════════════╣
║               ║  ✦ Scan management (create, pause, cancel, retry)  ║
║  PLATFORM     ║  ✦ Real-time log stream (WebSocket)                 ║
║               ║  ✦ HTML + JSON report export                        ║
║               ║  ✦ User auth + API key                              ║
╚═══════════════╩══════════════════════════════════════════════════════╝
```

### Feature Matrix — Phase 2 (Advanced)

```
╔═══════════════╦══════════════════════════════════════════════════════╗
║   KATEGORI    ║   FITUR                                              ║
╠═══════════════╬══════════════════════════════════════════════════════╣
║   WEB APP     ║  ✦ SQLi scan (sqlmap integration)                   ║
║   DEEP AUDIT  ║  ✦ SSRF detection (nuclei + ssrfmap)                ║
║               ║  ✦ LFI/RFI fuzzing (ffuf + wordlist)                ║
║               ║  ✦ CORS misconfiguration                            ║
║               ║  ✦ OAuth/Auth bypass testing                        ║
║               ║  ✦ API endpoint bruteforce                          ║
╠═══════════════╬══════════════════════════════════════════════════════╣
║  OSINT        ║  ✦ Email harvesting (theHarvester)                  ║
║               ║  ✦ Google Dork automation                           ║
║               ║  ✦ Cert transparency (crt.sh)                       ║
║               ║  ✦ WHOIS + ASN lookup                               ║
╠═══════════════╬══════════════════════════════════════════════════════╣
║  CMS SCAN     ║  ✦ WordPress (wpscan)                               ║
║               ║  ✦ Drupal (droopescan)                              ║
║               ║  ✦ Joomla, Magento                                  ║
╠═══════════════╬══════════════════════════════════════════════════════╣
║  REPORTING    ║  ✦ PDF report (WeasyPrint)                          ║
║               ║  ✦ Executive summary generator                      ║
║               ║  ✦ CVSS score calculator                            ║
║               ║  ✦ Risk matrix visualization                        ║
╠═══════════════╬══════════════════════════════════════════════════════╣
║  INTEGRATIONS ║  ✦ Slack / Telegram notification                    ║
║               ║  ✦ Jira/GitLab issue creation                       ║
║               ║  ✦ Nuclei template auto-update                      ║
╚═══════════════╩══════════════════════════════════════════════════════╝
```

---

## Alur Kerja Scan

### End-to-End Scan Flow

```
User di Dashboard
       │
       │  [Buat Scan Baru]
       │  Target: example.com
       │  Mode: Full Scan (Server + Client)
       │
       ▼
┌─────────────────────────────────────────────────────┐
│              Django View (scans/views.py)            │
│  1. Validasi input (domain/IP/URL)                   │
│  2. Buat ScanJob object di PostgreSQL                │
│  3. Kirim task ke Celery:                            │
│     orchestrate_scan.apply_async(scan_id=123,        │
│                                   queue='scan_q')    │
└─────────────────────┬───────────────────────────────┘
                      │ Task → Redis Queue
                      ▼
┌─────────────────────────────────────────────────────┐
│          Celery Worker: orchestrate_scan()           │
│                                                      │
│  Phase 0: OSINT & Passive Recon                      │
│    ├── whois_lookup.delay()                          │
│    ├── dns_enum.delay()                              │
│    └── cert_enum.delay()                             │
│                      ↓                               │
│  Phase 1: Asset Discovery                            │
│    ├── subdomain_enum.delay()  ─── subfinder, amass  │
│    └── http_probe.delay()      ─── httpx             │
│                      ↓                               │
│  Phase 2: Server-Side Analysis                       │
│    ├── port_scan.delay()       ─── nmap, rustscan    │
│    ├── ssl_audit.delay()       ─── testssl.sh        │
│    ├── waf_detect.delay()      ─── wafw00f           │
│    └── vuln_scan_server.delay()─── nuclei (network)  │
│                      ↓                               │
│  Phase 3: Client-Side / Web Analysis                 │
│    ├── web_crawl.delay()       ─── katana            │
│    ├── dir_fuzz.delay()        ─── ffuf              │
│    ├── xss_scan.delay()        ─── dalfox            │
│    ├── header_audit.delay()    ─── custom checks     │
│    ├── js_secrets.delay()      ─── trufflehog        │
│    └── vuln_scan_web.delay()   ─── nuclei (web tmpl) │
│                      ↓                               │
│  Phase 4: Aggregation & Reporting                    │
│    ├── aggregate_results()                           │
│    ├── calculate_risk_score()                        │
│    └── generate_report.delay()                       │
└─────────────────────────────────────────────────────┘
       │ Real-time progress via WebSocket
       ▼
┌─────────────────────────────────────────────────────┐
│              User Browser (Live View)                │
│  Dashboard menampilkan:                              │
│  [████████░░] 80% — Running XSS scan...              │
│                                                      │
│  Live Log Stream:                                    │
│  [10:42:01] ✓ Subdomain: api.example.com            │
│  [10:42:05] ✓ Port 443 open: nginx/1.24.0           │
│  [10:42:09] ⚠ CVE-2023-XXXX found at /api/v1       │
│  [10:42:15] ✗ XSS: /search?q=<payload> → Reflected  │
└─────────────────────────────────────────────────────┘
```

---

## Database Schema

### Diagram Entity Relationship

```
┌──────────────┐       ┌───────────────────┐
│    User      │       │      Target        │
│──────────────│       │───────────────────│
│ id           │       │ id                │
│ username     │       │ name              │
│ email        │  1:N  │ type (domain/ip/url│
│ api_key      │◄──────│ value             │
│ role         │       │ description       │
└──────────────┘       │ created_by (FK)   │
                       └─────────┬─────────┘
                                 │ 1:N
                                 ▼
                       ┌─────────────────────┐
                       │      ScanJob         │
                       │─────────────────────│
                       │ id (UUID)            │
                       │ target (FK)          │
                       │ mode (full/server/   │
                       │       client/custom) │
                       │ status (pending/     │
                       │  running/done/fail)  │
                       │ progress (0-100)     │
                       │ config (JSON)        │
                       │ started_at           │
                       │ finished_at          │
                       │ initiated_by (FK)    │
                       └──────────┬──────────┘
                                  │ 1:N
              ┌───────────────────┼───────────────────┐
              │                   │                   │
              ▼                   ▼                   ▼
   ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
   │    Subdomain     │  │      Port        │  │  Vulnerability  │
   │─────────────────│  │─────────────────│  │─────────────────│
   │ id              │  │ id              │  │ id              │
   │ scan (FK)       │  │ scan (FK)       │  │ scan (FK)       │
   │ fqdn            │  │ target (FK)     │  │ title           │
   │ ip              │  │ port_number     │  │ severity        │
   │ http_status     │  │ protocol (tcp/  │  │ (crit/high/med/ │
   │ http_url        │  │          udp)   │  │  low/info)      │
   │ page_title      │  │ service         │  │ cve_id          │
   │ web_server      │  │ version         │  │ cvss_score      │
   │ technologies    │  │ banner          │  │ affected_url    │
   │ is_cdn          │  │ state (open/    │  │ template_id     │
   │ screenshot      │  │  filtered)      │  │ description     │
   └────────┬────────┘  └─────────────────┘  │ proof (curl)    │
            │ 1:N                             │ remediation     │
            ▼                                 └─────────────────┘
   ┌─────────────────┐
   │    Endpoint      │     ┌──────────────────┐
   │─────────────────│     │    ScanLog        │
   │ id              │     │──────────────────│
   │ subdomain (FK)  │     │ id               │
   │ url             │     │ scan (FK)        │
   │ method          │     │ level (info/warn/│
   │ status_code     │     │        error)    │
   │ content_type    │     │ message          │
   │ response_time   │     │ timestamp        │
   │ content_length  │     └──────────────────┘
   │ technologies    │
   └─────────────────┘
```

---

## Task Queue & Worker

### Queue Architecture

```python
# pentools/celery.py

CELERY_TASK_QUEUES = {
    'scan_orchestration': {   # Koordinator utama scan jobs
        'priority': 10,
    },
    'recon_queue': {          # Subdomain, DNS, OSINT
        'priority': 8,
    },
    'server_audit_queue': {   # Port scan, SSL, WAF, Nuclei network
        'priority': 7,
    },
    'web_audit_queue': {      # Web crawl, fuzzing, XSS, SQLi
        'priority': 7,
    },
    'report_queue': {         # Report generation, export
        'priority': 5,
    },
    'notification_queue': {   # Slack, Telegram, email
        'priority': 3,
    },
}

# Celery worker startup:
# celery -A pentools worker
#   --queues=scan_orchestration,recon_queue,server_audit_queue,
#            web_audit_queue,report_queue,notification_queue
#   --concurrency=20
#   --pool=prefork
#   --max-tasks-per-child=4
```

### Tool Execution Model

```python
# apps/scans/utils/tool_runner.py

class ToolRunner:
    """
    Universal subprocess wrapper untuk menjalankan pentest tools.
    - Output di-stream ke WebSocket secara real-time
    - Semua output di-sanitize sebelum dikirim ke DB
    - Timeout enforcement per tool
    """

    def run(self, cmd: list[str], timeout: int = 3600) -> dict:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # SECURITY: Tidak menggunakan shell=True
            # Semua argument sebagai list, bukan string
        )
        stdout, stderr = process.communicate(timeout=timeout)
        return {
            'returncode': process.returncode,
            'stdout': stdout.decode(errors='replace'),
            'stderr': stderr.decode(errors='replace'),
        }

    def stream_run(self, cmd: list[str], scan_id: str):
        """Real-time output streaming ke WebSocket channel"""
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, ...)
        for line in iter(process.stdout.readline, b''):
            self.send_to_ws(scan_id, line.decode().strip())
```

---

## Real-time WebSocket

### Architecture

```
Browser                    Django Channels              Redis
   │                           │                         │
   │──── ws://host/ws/scan/{id}►│                         │
   │                           │── join group "scan_{id}"►│
   │                           │                         │
   │           Celery Task Running...                     │
   │                           │◄── group_send() ─────────│
   │◄──── JSON message ─────────│                         │
   │  {                        │                         │
   │    "type": "log",         │                         │
   │    "level": "info",       │                         │
   │    "message": "...",      │                         │
   │    "progress": 45         │                         │
   │  }                        │                         │
```

### Consumer Implementation (Ringkas)

```python
# apps/scans/consumers.py

class ScanLogConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        scan_id = self.scope['url_route']['kwargs']['scan_id']
        
        # Auth check: user harus punya akses ke scan ini
        if not await self.user_can_access_scan(scan_id):
            await self.close(code=4003)   # Forbidden
            return
        
        self.group_name = f'scan_{scan_id}'
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def scan_log(self, event):
        await self.send(text_data=json.dumps(event['payload']))
```

---

## Tools yang Diintegrasikan

### Phase 1 — Wajib

| Tool           | Kategori          | Sumber         | Bahasa  |
|----------------|-------------------|----------------|---------|
| `subfinder`    | Subdomain enum    | ProjectDiscovery | Go    |
| `amass`        | Subdomain OSINT   | OWASP          | Go      |
| `dnsx`         | DNS resolver      | ProjectDiscovery | Go    |
| `httpx`        | HTTP probe        | ProjectDiscovery | Go    |
| `nmap`         | Port scan         | nmap.org       | C       |
| `rustscan`     | Fast port scan    | RustScan       | Rust    |
| `nuclei`       | Vuln templates    | ProjectDiscovery | Go    |
| `testssl.sh`   | SSL/TLS audit     | testssl.sh     | Bash    |
| `wafw00f`      | WAF detection     | EnableSecurity | Python  |
| `katana`       | Web crawler       | ProjectDiscovery | Go    |
| `ffuf`         | Dir fuzzing       | ffuf           | Go      |
| `dalfox`       | XSS scan          | hahwul         | Go      |
| `trufflehog`   | Secrets in JS     | TruffleHog     | Go      |
| `whatweb`      | Tech fingerprint  | urbanadventurer | Ruby   |

### Phase 2 — Advanced

| Tool           | Kategori          | Sumber         |
|----------------|-------------------|----------------|
| `sqlmap`       | SQLi              | sqlmap.org     |
| `feroxbuster`  | Recursive fuzz    | epi052         |
| `wpscan`       | WordPress audit   | WPScan         |
| `theHarvester` | Email OSINT       | laramies       |
| `gobuster`     | DNS/dir brute     | OJ Reeves      |
| `masscan`      | Ultra-fast portscan | Robert David Graham |
| `ssrfmap`      | SSRF testing      | swisskyrepo    |

---

## API Design

### REST API Endpoints (DRF)

```
Authentication:
  POST   /api/auth/login/
  POST   /api/auth/logout/
  POST   /api/auth/token/refresh/

Targets:
  GET    /api/targets/
  POST   /api/targets/
  GET    /api/targets/{id}/
  PUT    /api/targets/{id}/
  DELETE /api/targets/{id}/

Scans:
  GET    /api/scans/
  POST   /api/scans/                    ◄── Buat & jalankan scan
  GET    /api/scans/{id}/
  POST   /api/scans/{id}/cancel/
  POST   /api/scans/{id}/retry/
  GET    /api/scans/{id}/logs/          ◄── Paginated logs
  GET    /api/scans/{id}/results/       ◄── Full results aggregasi

Results:
  GET    /api/scans/{id}/subdomains/
  GET    /api/scans/{id}/ports/
  GET    /api/scans/{id}/vulnerabilities/
  GET    /api/scans/{id}/endpoints/

Reports:
  GET    /api/reports/{scan_id}/html/   ◄── HTML report
  GET    /api/reports/{scan_id}/json/   ◄── JSON export
  GET    /api/reports/{scan_id}/pdf/    ◄── PDF (Phase 2)

WebSocket:
  WS     /ws/scan/{scan_id}/            ◄── Live log stream
```

---

## Security Model

### Prinsip Keamanan

```
1. AUTHENTICATION
   ├── Django session auth (dashboard)
   └── JWT / API key (REST API)

2. AUTHORIZATION
   ├── User hanya bisa lihat scan miliknya sendiri
   ├── Admin bisa lihat semua
   └── Role-based: viewer, operator, admin

3. INPUT VALIDATION
   ├── Target domain/IP divalidasi dengan regex + DNS check
   ├── Semua tool argument sebagai list[] (bukan string)
   │   → Mencegah command injection
   └── Output tool di-sanitize sebelum disimpan ke DB

4. TOOL EXECUTION SECURITY
   ├── Tools berjalan di container terpisah (tools container)
   ├── Network namespace terisolasi
   ├── Timeout enforcement (prevent hangs)
   └── Output size limit (prevent log flooding)

5. DATA SECURITY
   ├── Semua secrets di .env (tidak di-commit ke git)
   ├── DB credentials + API keys via environment variables
   └── Scan results hanya accessible oleh owner

6. NETWORK SECURITY
   ├── Nginx SSL termination
   ├── Internal services tidak expose ke host (internal network)
   └── Rate limiting pada API endpoints
```

---

## Roadmap Implementasi

### Sprint Plan

```
PHASE 1 — Foundation (2-3 minggu)
├── [Week 1] Core Infrastructure
│   ├── Docker Compose setup (db, redis, web, celery, nginx)
│   ├── Django project scaffolding
│   ├── User auth (login, logout, API key)
│   ├── Target management (CRUD)
│   └── Basic database models
│
├── [Week 2] Server-Side Scan Engine
│   ├── Celery + Redis integration
│   ├── ScanJob model + orchestrator task
│   ├── Subdomain enumeration (subfinder)
│   ├── Port scanning (nmap)
│   ├── HTTP probing (httpx)
│   └── WebSocket real-time log stream
│
└── [Week 3] Client-Side Scan + UI
    ├── Web crawler (katana)
    ├── Directory fuzzing (ffuf)
    ├── XSS scan (dalfox)
    ├── Security header audit
    ├── Dashboard UI (HTMX + Tailwind)
    └── HTML report generation

PHASE 2 — Advanced (3-4 minggu)
├── SSL audit (testssl.sh)
├── Nuclei integration (full template set)
├── SQLi scan (sqlmap)
├── JS secrets scan (trufflehog)
├── OSINT module
├── PDF report export
├── Notification (Telegram + Slack)
├── Scan scheduling (Celery Beat)
└── Flower dashboard

PHASE 3 — Production Hardening
├── Multi-user support
├── RBAC (Role-Based Access Control)
├── Prometheus + Grafana monitoring
├── Horizontal Celery scaling
├── CI/CD pipeline
└── Security audit + penetration testing diri sendiri
```

---

## Keputusan Arsitektur Kunci

| Keputusan | Pilihan | Alasan |
|-----------|---------|--------|
| Frontend stack | Django Templates + HTMX | Tidak butuh full SPA, HTMX cukup untuk interaktivitas. Lebih simple dari React. |
| Task execution | Celery + Redis | Battle-tested, scalable, familiar di ekosistem Django |
| Database | PostgreSQL | JSONB support untuk menyimpan tool output yang fleksibel |
| Real-time | Django Channels | Native Django solution untuk WebSocket |
| Tool isolation | Shared volume dari tools container | Satu image tools, dipakai semua worker |
| Scan config | JSON field di model | Fleksibel tanpa schema migration tiap tambah option |
| Auth API | API Key (simple) + JWT | API key untuk CLI/automation, JWT untuk web session |

---

*Dokumen ini adalah blueprint hidup — akan diperbarui seiring implementasi.*
